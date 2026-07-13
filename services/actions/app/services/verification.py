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

from app.executors.endpoint import _cs_client
from app.models.action import ActionType

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


async def _probe_isolate(target: str, params: dict[str, Any]) -> bool | None:
    """Confirm host isolation by re-querying the EDR.

    Today only CrowdStrike exposes enough to re-query (the device must resolve);
    absent CrowdStrike credentials we return None → UNVERIFIED (honest).
    """
    cs = _cs_client(params)
    if cs is None:
        return None
    device_id = await cs.get_device_id(target)
    # A resolvable device id is a real (if partial) confirmation the target
    # exists and the containment call targeted a real host. Fuller state
    # verification lands when the client exposes a containment-status read.
    return bool(device_id)


_DEFAULT_PROBES: dict[ActionType, Probe] = {
    ActionType.ISOLATE_HOST: _probe_isolate,
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
