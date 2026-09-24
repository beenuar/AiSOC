"""Post-action verification (Phase B3).

A real SOC doesn't trust "the API returned 200" as proof an action took effect —
it re-queries the vendor. This module adds that read-back step. After an action
executes (and especially when the autonomy decision set
``requires_verification``), :class:`PostActionVerifier.verify` re-queries the
vendor to confirm the effect is actually present and returns a
:class:`VerificationOutcome`:

* ``VERIFIED``   — a real confirming query ran and the effect is present.
* ``FAILED``     — a real query ran and the effect is **absent** (the action
                   silently didn't take, or was undone) — a genuine alarm.
* ``UNVERIFIED`` — no read-back probe exists for this action/vendor yet, so we
                   say so honestly rather than claim success we can't prove.

Verifiers are pluggable async callables keyed by :class:`ActionType`; a probe
receives ``(target, params)`` and returns ``True`` (present) / ``False``
(absent) / ``None`` (couldn't determine). Builtin probes use the same vendor
clients as the forward actions and skip cleanly (→ ``UNVERIFIED``) when
credentials are absent. This keeps the honest default: we never fabricate a
``VERIFIED`` we didn't earn with a real query.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

from app.clients.factories import _entra_client, _mde_client, _okta_client
from app.executors.endpoint import INVESTIGATION_PACKAGE_ACTION, _cs_client
from app.executors.siem import _ack_vendor, _qradar_client, _splunk_client
from app.models.action import ActionType
from app.services.disposition_writeback import WritebackAction, plan_writeback

logger = structlog.get_logger()


class VerificationOutcome(str, Enum):
    VERIFIED = "verified"
    FAILED = "failed"
    UNVERIFIED = "unverified"


@dataclass(frozen=True)
class VerificationResult:
    outcome: VerificationOutcome
    action_type: ActionType
    target: str
    reason: str
    vendor: str | None = None


# A probe returns True (effect present), False (absent), or None (indeterminate).
Probe = Callable[[str, dict[str, Any]], Awaitable[bool | None]]


#: CrowdStrike device states that mean containment is actually in force.
#: ``containment_pending`` is deliberately excluded: the request was accepted
#: but the host is not contained yet, which is precisely the "the API returned
#: 200" condition this module exists to distinguish from a real effect.
_CONTAINED_STATES = {"contained"}


async def _probe_isolate(target: str, params: dict[str, Any]) -> bool | None:
    """Confirm host isolation by reading the EDR's containment state.

    This previously returned ``bool(device_id)`` — i.e. "does this hostname
    resolve to a device". That is true of every host in the fleet, contained or
    not, so it would have certified an uncontained host as VERIFIED. Now it
    reads the device's actual ``status``.

    Absent CrowdStrike credentials we return None → UNVERIFIED (honest).
    """
    cs = _cs_client(params)
    if cs is None:
        return None
    device_id = await cs.get_device_id(target)
    if not device_id:
        # The host cannot be found at all, so containment cannot be confirmed.
        # Indeterminate rather than FAILED: a renamed or decommissioned host is
        # not the same fact as "containment did not take".
        return None
    status = await cs.get_containment_status(device_id)
    if status is None:
        return None
    return status.lower() in _CONTAINED_STATES


async def _probe_block_ip(target: str, params: dict[str, Any]) -> bool | None:
    """Confirm an IP block by re-reading the enforcing rule set.

    Only AWS security groups are readable today; every other vendor arm of
    ``BlockIPExecutor`` has no read-back, so this reports indeterminate rather
    than inventing a confirmation.
    """
    from app.executors.network import read_back_blocked_ip  # noqa: PLC0415

    return await read_back_blocked_ip(target, params)


#: Okta lifecycle states that mean sign-in is actually blocked. ACTIVE,
#: PROVISIONED and RECOVERY all permit sign-in and must not count.
_OKTA_BLOCKED_STATES = {"SUSPENDED", "DEPROVISIONED", "LOCKED_OUT"}


async def _probe_disable_user(target: str, params: dict[str, Any]) -> bool | None:
    """Confirm an account is actually blocked by re-reading the directory.

    Both vendors return success on an accepted request, which says nothing
    about whether sign-in is blocked — and for Entra, directory replication
    means the two genuinely differ for a short window. That window is exactly
    what a responder needs told rather than guessed at.

    Vendor is chosen by which credentials are present, in the same order the
    executor uses. Absent both, this is indeterminate rather than a failure:
    "we cannot check" and "the disable did not take" are different facts and
    the dispatcher treats them differently.
    """
    okta = _okta_client(params)
    if okta is not None:
        status = await okta.get_user_status(target)
        if status is None:
            return None
        return status.upper() in _OKTA_BLOCKED_STATES

    entra = _entra_client(params)
    if entra is not None:
        enabled = await entra.get_user_enabled(target)
        if enabled is None:
            return None
        return not enabled

    return None


async def _probe_enable_user(target: str, params: dict[str, Any]) -> bool | None:
    """Confirm an account is usable again. The inverse of the above.

    Worth verifying in its own right: a rollback that silently fails leaves
    someone locked out after the incident is closed, and nobody is watching
    for that.
    """
    blocked = await _probe_disable_user(target, params)
    return None if blocked is None else not blocked


#: MDE machine-action states. Only one means the work finished; three mean it
#: definitively did not; the rest mean it is still going.
_MDE_ACTION_SUCCEEDED = "succeeded"
_MDE_ACTION_TERMINAL_FAILURES = {"failed", "timeout", "cancelled"}


async def _probe_capture_forensics(target: str, params: dict[str, Any]) -> bool | None:
    """Confirm a forensic package actually exists and can be fetched.

    This is the verb where "the API returned 200" is furthest from the truth.
    Collection is asynchronous: MDE queues a machine action, replies
    immediately with ``Pending``, and the package appears minutes later or
    never. An executor reporting that as success tells an analyst the evidence
    is preserved at exactly the moment they stop looking for it.

    So VERIFIED requires two things, not one: the machine action reached
    ``Succeeded`` *and* Defender will hand over a download URI for it. A
    collection that claims to have finished and has nothing to download is a
    failure, not a success — reading only the status would certify it.

    Three outcomes, all of them real:

    * ``Succeeded`` with a package URI → True.
    * ``Failed`` / ``TimeOut`` / ``Cancelled`` → False. A genuine alarm: the
      responder believes they hold evidence and they do not.
    * ``Pending`` / ``InProgress`` → None. Not finished is not the same fact
      as not happening, and the immediate post-dispatch probe will almost
      always land here.

    Which action it reads
    ---------------------
    ``mde_action_id`` in params is used when present and is exact — the
    executor returns it, so a later re-verification can name the acquisition
    it means. Without one the probe falls back to the newest
    ``CollectInvestigationPackage`` action against that machine, which is this
    one unless a second collection was started on the same host in the same
    window. That ambiguity is narrow but real, so the action id is not
    swallowed: it is logged, and a caller who needs certainty passes it in.
    """
    mde = _mde_client(params)
    if mde is None:
        return None

    action_id = params.get("mde_action_id")
    if not action_id:
        machine = await mde.find_machine(target)
        if not machine or not machine.get("id"):
            # The host cannot be resolved, so nothing can be read back. Not a
            # failed acquisition — a host we cannot look at.
            return None
        actions = await mde.list_machine_actions(str(machine["id"]), INVESTIGATION_PACKAGE_ACTION, limit=5)
        if not actions:
            return None
        action_id = actions[0].get("id")
        if not action_id:
            return None

    action = await mde.get_machine_action(str(action_id))
    if not action:
        return None

    status = str(action.get("status") or "").lower()
    logger.info("verification.capture_forensics.read", target=target, mde_action_id=str(action_id), mde_status=status)

    if status in _MDE_ACTION_TERMINAL_FAILURES:
        return False
    if status != _MDE_ACTION_SUCCEEDED:
        return None

    # Succeeded. Now the part that makes this a check rather than a restatement
    # of the vendor's own optimism: ask for the artefact.
    return bool(await mde.get_investigation_package_uri(str(action_id)))


async def _probe_allow_ip(target: str, params: dict[str, Any]) -> bool | None:
    """Confirm an IP block was actually removed.

    The inverse of the block probe, against the same read-back. Worth having
    in its own right: a rollback that silently fails leaves a production
    address blocked after the incident closes, and nobody is watching for
    that the way they watch a containment.
    """
    from app.executors.network import read_back_blocked_ip  # noqa: PLC0415

    still_blocked = await read_back_blocked_ip(target, params)
    return None if still_blocked is None else not still_blocked


#: Splunk ES notable status codes. A new notable is 0 ("unassigned"), so
#: reading 1 back is evidence an acknowledgement landed; 5 is closed.
_SPLUNK_STATUS_IN_PROGRESS = "1"
_SPLUNK_STATUS_CLOSED = "5"


async def _read_back_finding_state(target: str, params: dict[str, Any], *, expect_closed: bool) -> bool | None:
    """Re-read a vendor finding and say whether it reached the expected state.

    Shared by the three verbs that move a finding through its lifecycle:
    acknowledge, suppress, and the disposition writeback that does one or the
    other depending on the verdict.

    Two of the five vendor arms expose a read-back and three do not, so this
    answers ``None`` for the rest rather than inventing a confirmation. That
    is the same shape as ``_probe_block_ip``, where only AWS security groups
    are readable.
    """
    vendor = _ack_vendor(params)

    if vendor == "splunk":
        splunk = _splunk_client(params)
        if splunk is None:
            return None
        state = await splunk.get_notable_event_state(target)
        if state is None or state.get("status") is None:
            return None
        status = str(state["status"])
        if expect_closed:
            # Unambiguous: a notable nobody closed is not status 5.
            return status == _SPLUNK_STATUS_CLOSED
        # An acknowledgement sets status to "in progress" *and* assigns an
        # owner. Status alone would be weak — a notable an analyst had already
        # picked up reads the same — so the owner has to match too. An analyst
        # who takes the notable over afterwards makes this report FAILED,
        # which is the safe direction to be wrong in.
        expected_owner = str(params.get("owner") or "aisoc")
        return status == _SPLUNK_STATUS_IN_PROGRESS and str(state.get("owner") or "") == expected_owner

    if vendor == "qradar":
        qradar = _qradar_client(params)
        if qradar is None:
            return None
        offense = await qradar.get_offense(target)
        status = str(offense.get("status") or "").upper()
        if not status:
            return None
        if expect_closed:
            return status == "CLOSED"
        # An escalation annotates the offense and leaves it OPEN — which is
        # also the state it was in beforehand. Returning True for "still OPEN"
        # would certify a write that never happened, which is exactly what the
        # isolation probe did when it returned bool(device_id). Indeterminate
        # is the honest answer, and QRadar exposes nothing better: the note
        # that carries the verdict is not on the offense record.
        return None

    # Elastic, Sentinel and Defender: their clients expose no read of a
    # finding's current state, so there is nothing to compare against.
    return None


async def _probe_alert_disposition(target: str, params: dict[str, Any]) -> bool | None:
    """Confirm an AiSOC verdict actually reached the finding that produced it.

    The writeback shipped claiming no probe, which was honest — a declared
    probe that does not run is the defect the contract gate exists to catch —
    but the standing rule is that an unverifiable action is not an autonomous
    one, and this one is automatic. So it gets a real read-back.

    The expected state is re-derived from the same ``disposition`` through the
    same :func:`plan_writeback` the executor used, rather than passed in
    alongside it. A probe told separately what to expect can be told wrong.
    """
    plan = plan_writeback(params.get("disposition"), confidence=params.get("confidence"))
    if plan.action is WritebackAction.REFUSE:
        # The executor deliberately wrote nothing, so there is no effect to
        # confirm. Reporting VERIFIED here would mean "the refusal worked",
        # which is not what a verification outcome is read as.
        return None
    return await _read_back_finding_state(target, params, expect_closed=plan.action is WritebackAction.CLOSE)


async def _probe_ack_alert(target: str, params: dict[str, Any]) -> bool | None:
    """Confirm an acknowledgement moved the finding to in-progress and owned."""
    return await _read_back_finding_state(target, params, expect_closed=False)


async def _probe_suppress_alert(target: str, params: dict[str, Any]) -> bool | None:
    """Confirm a suppression actually closed the finding.

    Worth having in its own right: a close that silently fails leaves the
    alert in the analyst queue while AiSOC reports it handled, and the two
    views of the same finding then disagree with nobody watching.
    """
    return await _read_back_finding_state(target, params, expect_closed=True)


_DEFAULT_PROBES: dict[ActionType, Probe] = {
    ActionType.ISOLATE_HOST: _probe_isolate,
    ActionType.BLOCK_IP: _probe_block_ip,
    ActionType.DISABLE_USER: _probe_disable_user,
    ActionType.ALLOW_IP: _probe_allow_ip,
    ActionType.CAPTURE_FORENSICS: _probe_capture_forensics,
    ActionType.UPDATE_ALERT_DISPOSITION: _probe_alert_disposition,
    ActionType.ACK_ALERT: _probe_ack_alert,
    ActionType.SUPPRESS_ALERT: _probe_suppress_alert,
}


@dataclass
class PostActionVerifier:
    probes: dict[ActionType, Probe] = field(default_factory=lambda: dict(_DEFAULT_PROBES))

    def register(self, action_type: ActionType, probe: Probe) -> None:
        self.probes[action_type] = probe

    async def verify(self, action_type: ActionType, target: str, params: dict[str, Any] | None = None) -> VerificationResult:
        probe = self.probes.get(action_type)
        if probe is None:
            return VerificationResult(
                VerificationOutcome.UNVERIFIED,
                action_type,
                target,
                reason=f"no read-back verifier for {action_type.value}",
            )
        params = params or {}
        try:
            present = await probe(target, params)
        except Exception as exc:  # noqa: BLE001 — a probe error is UNVERIFIED, never a false VERIFIED
            logger.warning("verification.probe_error", action=action_type.value, target=target, error=str(exc))
            return VerificationResult(VerificationOutcome.UNVERIFIED, action_type, target, reason=f"probe error: {exc}")

        if present is None:
            return VerificationResult(
                VerificationOutcome.UNVERIFIED,
                action_type,
                target,
                reason="probe could not determine effect (likely no credentials)",
            )
        outcome = VerificationOutcome.VERIFIED if present else VerificationOutcome.FAILED
        reason = "effect confirmed present" if present else "effect NOT present on re-query"
        logger.info("verification.result", action=action_type.value, target=target, outcome=outcome.value)
        return VerificationResult(outcome, action_type, target, reason=reason)
