"""Dispatch the reversal of a completed action, under the same governance as
the forward dispatch that produced it.

Every executor's ``rollback()`` was reachable only from tests. The capability
contracts advertise ``reverse_capability`` for each platform-reversible verb
and the executors capture ``rollback_data`` on every destructive one, but no
route or worker ever invoked a reversal — a promise the docs made and the
product could not keep. This module is the missing dispatch, shaped like the
forward one so an undo can never be a governance bypass:

* **The record decides what is being reversed.** The action id names a stored
  record; its ``rollback_data`` (prior state, never credentials) and the
  vendor it executed against come from that record, never from the caller.
* **Credentials arrive per call.** The executors' own docstrings state that
  credentials are never stored in ``rollback_data``; they reach the reversal
  through ``auth_config`` — connector-schema fields the API resolves from the
  tenant's stored integration — translated at this boundary exactly as
  forward dispatch translates them.
* **The reverse capability's contract grades the undo.** The same
  ``evaluate_contract`` every forward door calls, applied to the
  ``reverse_capability``'s own entry: an undo whose reversal is declared
  analyst-tier waits for a distinct approver, one whose reversal is
  prohibited never runs, and confidence below the floor queues exactly as a
  forward dispatch would.
* **One conditional UPDATE claims the reversal.** ``completed →
  rolling_back`` before the vendor is contacted, so two undo requests elect
  one executor — the same durable-claim discipline as forward execution.
* **The executor's boolean is reported honestly.** ``False`` is a failed
  undo naming the vendor refusal, and the action stays ``completed`` — still
  in force, still retryable. Only a reversal that really ran moves the
  record to ``rolled_back``.
"""

from __future__ import annotations

import inspect
import os
import socket
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import structlog

from app.live_actions import registry
from app.live_actions.capability_contracts import CAPABILITY_CONTRACTS, contract_for_action_type
from app.live_actions.contract import ApprovalRequirement, Reversal
from app.live_actions.models import LiveActionResult, LiveActionStatus
from app.models.action import ActionPrincipal, ActionRequest, ActionStatus, ActionType
from app.security.authz import SOD_UNEVALUATED, ActionAuthzError, authorize_action, authorize_approver
from app.services import action_store
from app.services.action_store import ActionIntentConflict, ActionStoreUnavailable, ClaimOutcome
from app.services.approval_gate import _resolve_tier
from app.services.approval_matrix import evaluate_contract
from app.services.asset_lookup import asset_criticality_for_target
from app.services.credential_resolver import resolve_params
from app.services.response_schedule_store import resolve_response_schedule

logger = structlog.get_logger(__name__)

#: Which replica claimed the reversal — same provenance the dispatch claim
#: records, for the same operator holding a stuck ``rolling_back`` record.
_WORKER_ID = f"{socket.gethostname()}/{os.getpid()}"


class UndoRefused(Exception):
    """The undo request itself is refusable, with an HTTP status and a reason.

    Raised for caller errors — an action that never executed, one already
    rolled back, a verb the platform cannot reverse — and translated by the
    route into the matching 4xx/5xx. Governance outcomes (pending approval, a
    prohibited reversal, a vendor refusal) are *not* refusals: they are
    reported in an :class:`UndoReport` so the caller has one shape to read,
    the same split the forward dispatch report draws.
    """

    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


@dataclass(frozen=True)
class UndoReport:
    """What actually happened to one undo request.

    ``reversed_`` is the single field that means the vendor's state was
    restored. Every other outcome — queued for approval, refused by contract,
    refused by the vendor — is ``False`` and ``status`` names which one.
    """

    action_id: str
    status: str  # rolled_back | undo_failed | pending_approval | refused
    reversed_: bool
    vendor_id: str = ""
    requirement: str = ""
    reason: str = ""
    summary: str = ""
    error: str = ""
    rolled_back_at: str = ""
    rolled_back_by: str = ""

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "action_id": self.action_id,
            "status": self.status,
            "reversed": self.reversed_,
            "summary": self.summary,
        }
        for key in ("vendor_id", "requirement", "reason", "error", "rolled_back_at", "rolled_back_by"):
            value = getattr(self, key)
            if value:
                out[key] = value
        return out


def _status_text(record: dict[str, Any]) -> str:
    return str(getattr(record.get("status"), "value", record.get("status")))


def _state_guard(action_id: str, record: dict[str, Any]) -> None:
    """Refuse, with the reason, any record not in a reversible state.

    A friendly pre-read: the durable claim below re-evaluates the same
    predicate, so a race between two undo requests is settled by Postgres,
    not by this check.
    """
    current = _status_text(record)
    if current == ActionStatus.COMPLETED.value:
        return
    if current == ActionStatus.ROLLED_BACK.value:
        rolled_back_at = record.get("rolled_back_at") or "an earlier time"
        rolled_back_by = record.get("rolled_back_by") or "an unrecorded identity"
        raise UndoRefused(
            409,
            f"this action was already rolled back at {rolled_back_at} by {rolled_back_by}; there is nothing left to undo",
        )
    if current == ActionStatus.ROLLING_BACK.value:
        raise UndoRefused(409, "another worker is already rolling this action back")
    if current in (ActionStatus.RUNNING.value, ActionStatus.RECONCILIATION_REQUIRED.value):
        raise UndoRefused(
            409,
            f"this action's outcome is not settled (current: {current}); reconcile it before deciding whether to undo it",
        )
    raise UndoRefused(
        409,
        f"only a completed action can be rolled back (current: {current}); this one never executed, so there is no effect to undo",
    )


def _reversal_route(action_id: str, record: dict[str, Any]) -> tuple[ActionType, str, str, dict[str, Any], Any]:
    """Resolve what would be reversed and who can reverse it, or refuse.

    Returns ``(action_type, reverse_capability, vendor_id, rollback_data,
    adapter)``. Everything here is derived from the stored record and the
    registry — the caller chooses none of it, which is what keeps an undo
    aimed at the vendor the action actually ran against.
    """
    raw_type = str(record.get("action_type") or "")
    try:
        action_type = ActionType(raw_type)
    except ValueError as exc:
        raise UndoRefused(422, f"the record names a verb this service does not know ({raw_type!r})") from exc

    contract = contract_for_action_type(action_type.value)
    if contract is None:
        raise UndoRefused(
            422,
            f"'{action_type.value}' has no capability contract, so its reversal cannot be graded; nothing ungradable is dispatched",
        )
    if contract.reversal is not Reversal.PLATFORM or not contract.reverse_capability:
        raise UndoRefused(
            422,
            f"the platform cannot undo '{action_type.value}': its contract declares reversal '{contract.reversal.value}'",
        )
    if contract.reverse_capability not in CAPABILITY_CONTRACTS:
        raise UndoRefused(
            422,
            f"'{action_type.value}' names reverse capability '{contract.reverse_capability}', which has no contract to grade against",
        )

    rollback_data = dict(record.get("rollback_data") or {})
    if not rollback_data:
        raise UndoRefused(
            422,
            "the action captured no reversal state (it may have run in simulation mode); there is nothing to restore",
        )

    output = record.get("output") or {}
    vendor_id = str(rollback_data.get("vendor") or (output.get("vendor") if isinstance(output, dict) else "") or "")
    if not vendor_id:
        raise UndoRefused(
            422,
            "the record does not name the vendor it executed against, so credentials cannot be resolved for the reversal",
        )

    adapter = registry.get_executor(vendor_id, action_type.value)
    if adapter is None:
        raise UndoRefused(422, f"no executor is registered for {vendor_id}/{action_type.value}")

    # Can per-call credentials reach this reversal at all? The adapter widens
    # ``rollback`` to take ``params`` only when the wrapped executor does; a
    # one-argument reversal would run with no way to connect and could only
    # simulate or fail. Refused before grading, because queueing an approval
    # for an undo that can never run is a trap for the approver.
    legacy = getattr(adapter, "_legacy_executor", None)
    rollback_fn = getattr(legacy, "rollback", None) if legacy is not None else getattr(adapter, "rollback", None)
    if not callable(rollback_fn):
        raise UndoRefused(422, f"{vendor_id}/{action_type.value} declares no reversal")
    if "params" not in inspect.signature(rollback_fn).parameters:
        raise UndoRefused(
            422,
            f"the {vendor_id}/{action_type.value} reversal cannot accept per-call credentials yet, so it cannot be dispatched",
        )

    return action_type, contract.reverse_capability, vendor_id, rollback_data, adapter


async def undo_action(
    action_id: str,
    *,
    tenant_id: str,
    auth_config: dict[str, Any] | None = None,
    principal: ActionPrincipal | None = None,
    approver: ActionPrincipal | None = None,
    requester: ActionPrincipal | None = None,
    confidence: float | None = None,
    requested_by: str = "aisoc-api",
) -> UndoReport:
    """Reverse one completed action through its executor's ``rollback``.

    The order below is the control, mirroring forward dispatch: a
    tenant-narrowed authoritative read, the state and reversal-route guards,
    the invoking principal's authorization, the reverse capability's grading,
    an approver bound under separation of duties when the grading demands
    one, the durable claim, and only then the vendor.
    """
    try:
        record = await action_store.get(action_id, tenant_id=tenant_id, authoritative=True)
    except ActionStoreUnavailable as exc:
        raise UndoRefused(503, "the action store is unavailable; nothing was reversed") from exc
    if not record:
        raise UndoRefused(404, "Action not found")

    _state_guard(action_id, record)
    action_type, reverse_capability, vendor_id, rollback_data, adapter = _reversal_route(action_id, record)

    log = logger.bind(
        action_id=action_id,
        tenant_id=tenant_id,
        action_type=action_type.value,
        reverse_capability=reverse_capability,
        vendor_id=vendor_id,
    )

    # The invoking principal needs the same execution-tier permission the
    # forward verb demanded: undoing a containment-grade act is itself a
    # containment-grade act. Same check, same code, same settings-driven
    # principal requirement as ``POST /actions``.
    probe = ActionRequest(
        id=UUID(action_id),
        incident_id=UUID(str(record.get("incident_id") or uuid4())),
        tenant_id=UUID(str(tenant_id)),
        action_type=action_type,
        target=str(record.get("target") or ""),
        rationale="",
        parameters={},
        principal=principal,
        requested_by=requested_by,
    )
    try:
        authorize_action(probe)
    except ActionAuthzError as exc:
        log.warning("action_undo.principal_refused", reason=str(exc))
        raise UndoRefused(403, str(exc)) from exc

    decision = evaluate_contract(
        contract=CAPABILITY_CONTRACTS[reverse_capability],
        confidence=confidence,
        tier=await _resolve_tier(tenant_id),
        asset_criticality=await asset_criticality_for_target(tenant_id, record.get("target")),
        schedule=await resolve_response_schedule(tenant_id),
    )

    if decision.is_blocked:
        log.info("action_undo.refused_by_contract", reason=decision.reason)
        return UndoReport(
            action_id=action_id,
            status="refused",
            reversed_=False,
            vendor_id=vendor_id,
            requirement=decision.requirement.value,
            reason=decision.reason,
            summary=f"'{action_type.value}' on {record.get('target')}: the reversal is refused by contract — {decision.reason}",
        )

    sod = SOD_UNEVALUATED
    if decision.requirement is not ApprovalRequirement.AUTOMATIC:
        if approver is None:
            log.info("action_undo.pending_approval", reason=decision.reason)
            return UndoReport(
                action_id=action_id,
                status="pending_approval",
                reversed_=False,
                vendor_id=vendor_id,
                requirement=decision.requirement.value,
                reason=decision.reason,
                summary=(
                    f"'{action_type.value}' on {record.get('target')}: the reversal needs "
                    f"{decision.requirement.value} approval before it runs — {decision.reason}"
                ),
            )
        # The approver must hold the verb's permission, belong to the
        # record's tenant, and not be the undo's own requester. Reused from
        # the approve door rather than restated, so the two cannot drift —
        # with the requester being the *undo's* requester: the forward
        # action's requester already got their action, and comparing against
        # them would let the person who asked for the undo wave it through.
        undo_requester_id = (requester.user_id if requester else None) or (principal.user_id if principal else None)
        sod_context = {
            "action_type": action_type.value,
            "tenant_id": str(record.get("tenant_id") or tenant_id),
            "requested_by_user_id": undo_requester_id,
        }
        try:
            sod = authorize_approver(sod_context, approver)
        except ActionAuthzError as exc:
            log.warning("action_undo.approver_refused", reason=str(exc))
            raise UndoRefused(403, str(exc)) from exc

    claim = await action_store.claim_rollback(action_id, tenant_id=tenant_id, claimed_by=_WORKER_ID)
    if not claim.ok:
        if claim.outcome is ClaimOutcome.STORE_UNAVAILABLE:
            raise UndoRefused(503, "the action store is unavailable, so the reversal was not authorized; nothing was sent to the vendor")
        if claim.outcome is ClaimOutcome.NOT_FOUND:
            raise UndoRefused(404, "Action not found")
        current = claim.current_status or "unknown"
        if current == ActionStatus.ROLLED_BACK.value:
            raise UndoRefused(409, "this action was already rolled back; there is nothing left to undo")
        raise UndoRefused(409, f"the reversal was not claimed: the action is no longer in a reversible state (current: {current})")

    params = resolve_params(vendor_id, dict(auth_config or {})) if auth_config else {}
    live_result = LiveActionResult(
        request_id=UUID(action_id),
        status=LiveActionStatus.SUCCEEDED,
        capability=action_type.value,
        vendor_id=vendor_id,
        summary=f"recorded execution of {action_type.value} on {record.get('target')}",
        details={**(record.get("output") or {}), "rollback_data": rollback_data},
    )

    error = ""
    try:
        reversed_ok = bool(await adapter.rollback(live_result, params=params))
        if not reversed_ok:
            error = "the executor reported the reversal did not run (vendor refusal or missing reversal state)"
    except Exception as exc:  # noqa: BLE001 — a claimed reversal must always settle
        # Logged in full, echoed by type only: vendor exceptions carry
        # internal hostnames, same reasoning as the forward dispatch.
        log.error("action_undo.executor_crashed", error=str(exc), exc_info=True)
        reversed_ok = False
        error = f"the reversal raised {type(exc).__name__}"

    now = datetime.now(UTC).isoformat()
    settled = claim.record or record
    acted_by = (approver.user_id if approver else None) or (principal.user_id if principal else None) or requested_by
    provenance: dict[str, Any] = {
        "state": "reversed" if reversed_ok else "failed",
        "requested_by": requested_by,
        "approved_by": approver.user_id if approver else None,
        "separation_of_duties": sod,
        "vendor_id": vendor_id,
        "reverse_capability": reverse_capability,
        "requirement": decision.requirement.value,
        "reason": decision.reason,
        "claimed_by": _WORKER_ID,
        "settled_at": now,
    }
    if reversed_ok:
        settled["status"] = ActionStatus.ROLLED_BACK
        settled["rolled_back_at"] = now
        settled["rolled_back_by"] = acted_by
    else:
        # The effect is still in force. ``completed`` is the honest state and
        # keeps the undo retryable; the provenance says what was attempted
        # and why it did not take.
        settled["status"] = ActionStatus.COMPLETED
        provenance["error"] = error
    settled["rollback"] = provenance

    try:
        await action_store.save(settled)
    except ActionIntentConflict:  # pragma: no cover - a reversal changes no intent
        log.error("action_undo.settle_write_refused")

    log.info(
        "action_undo.settled",
        reversed=reversed_ok,
        requirement=decision.requirement.value,
        acted_by=acted_by,
        error=error or None,
    )

    if reversed_ok:
        return UndoReport(
            action_id=action_id,
            status="rolled_back",
            reversed_=True,
            vendor_id=vendor_id,
            requirement=decision.requirement.value,
            reason=decision.reason,
            summary=f"'{action_type.value}' on {record.get('target')} was reversed on {vendor_id}",
            rolled_back_at=now,
            rolled_back_by=acted_by,
        )
    return UndoReport(
        action_id=action_id,
        status="undo_failed",
        reversed_=False,
        vendor_id=vendor_id,
        requirement=decision.requirement.value,
        reason=decision.reason,
        error=error,
        summary=f"'{action_type.value}' on {record.get('target')}: the reversal did not take — {error}",
    )
