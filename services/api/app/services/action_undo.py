"""Drive the reversal of a completed action through the actions service.

The executors capture ``rollback_data`` on every destructive verb and the
capability contracts name a ``reverse_capability`` for each platform-reversible
one, but nothing in production could dispatch a reversal. This module is the
API's half of the undo path, and it decides the same two things the
playbook-step dispatch decides for a forward action — **which connector** and
**which credentials** — because those are tenant facts and this is the only
service that can read them. Whether the undo may run is decided where the
contract lives: ``services/actions`` grades the reverse capability and claims
the reversal durably before any vendor is contacted.

Two hard rules, inherited from the forward hop:

* Credentials are resolved from the tenant's stored integration through the
  vault, per call, at the moment of dispatch — never from the caller's
  request (the route's body cannot carry them) and never from the stored
  action record (the executors never put them there).
* The vendor is a fact of the record, not a choice. The reversal goes to the
  vendor the action executed against; a record that does not name one is
  refused rather than guessed at.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app._vendor.action_contracts.capability_contracts import contract_for_action_type
from app.security.credential_vault import CredentialVaultError, get_vault
from app.services import actions_client
from app.services.playbook_step_dispatch import _operational_config, _pick_connector

logger = structlog.get_logger(__name__)

#: Upstream refusals whose status and reason are the caller's to see. These
#: are statements about the undo request itself — the action never executed,
#: it was already rolled back, the verb has no platform reverse — and
#: flattening them into a 502 would hide exactly the sentence the operator
#: needs.
_PASSTHROUGH_STATUSES: frozenset[int] = frozenset({400, 403, 404, 409, 422})


class UndoNotPossible(Exception):
    """This undo request cannot be served, with the HTTP status naming why."""

    def __init__(self, status_code: int, detail: str, *, indeterminate: bool = False) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail
        #: True when the actions service may have acted and never answered.
        #: A decide path records this as "unknown" rather than "failed",
        #: because the reversal is claimed durably upstream and the answer
        #: exists there to be read.
        self.indeterminate = indeterminate


@dataclass(frozen=True)
class UndoDispatchReport:
    """What actually happened to one undo request, in one shape.

    ``reversed_`` is the single field that means the vendor's state was
    restored. A queued approval, a contract refusal and a vendor refusal are
    all ``False``, each naming which one it was — the same honesty contract
    the playbook-step report keeps for forward actions.
    """

    action_id: str
    status: str  # rolled_back | undo_failed | pending_approval | refused
    reversed_: bool
    action_type: str = ""
    target: str = ""
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
        for key in ("action_type", "target", "vendor_id", "requirement", "reason", "error", "rolled_back_at", "rolled_back_by"):
            value = getattr(self, key)
            if value:
                out[key] = value
        return out


async def _load_record(action_id: str, tenant_id: str) -> dict[str, Any]:
    try:
        return await actions_client.get_action(action_id=action_id, tenant_id=tenant_id)
    except actions_client.ActionsServiceError as exc:
        raise _translated(exc) from exc


def _translated(exc: actions_client.ActionsServiceError) -> UndoNotPossible:
    if exc.status_code in _PASSTHROUGH_STATUSES:
        return UndoNotPossible(exc.status_code or 502, exc.upstream_detail, indeterminate=exc.indeterminate)
    return UndoNotPossible(
        502,
        exc.upstream_detail
        if exc.status_code
        else "The action service is unreachable. It runs in the `full` and `chatops` compose profiles.",
        indeterminate=exc.indeterminate,
    )


async def _resolve_reversal_credentials(
    db: AsyncSession,
    *,
    tenant_id: Any,
    record: dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    """``(vendor_id, auth_config)`` for the vendor this record executed against.

    The vendor comes from the record's own ``rollback_data`` (stamped by the
    executor at capture time) with the execution output as fallback. The
    connector lookup is the forward hop's own: enabled, owned by this tenant,
    not downscoped away from the reverse verb.
    """
    rollback_data = record.get("rollback_data") or {}
    output = record.get("output") or {}
    vendor_id = str(
        (rollback_data.get("vendor") if isinstance(rollback_data, dict) else "")
        or (output.get("vendor") if isinstance(output, dict) else "")
        or ""
    )
    if not vendor_id:
        raise UndoNotPossible(
            422,
            "the action record does not name the vendor it executed against, so no stored integration can be resolved for the reversal",
        )

    # The verb being performed now is the reverse capability; a tenant that
    # downscoped it off this connector has said "not this verb here", and an
    # undo does not outrank that any more than a playbook step does.
    contract = contract_for_action_type(str(record.get("action_type") or ""))
    reverse_capability = (contract.reverse_capability if contract else "") or str(record.get("action_type") or "")

    connector = await _pick_connector(
        db,
        tenant_id=tenant_id,
        capability=reverse_capability,
        implementers=[vendor_id],
        pinned="",
    )
    if connector is None:
        raise UndoNotPossible(
            422,
            f"this tenant has no enabled {vendor_id} connector that may perform "
            f"'{reverse_capability}', so the reversal has no credentials to run with",
        )

    try:
        auth_config = get_vault().decrypt_dict(connector.auth_config or {})
    except CredentialVaultError as exc:
        # Reported, never downgraded: an undo that silently ran without
        # credentials would be recorded as a vendor refusal, which sends the
        # operator to the wrong console. Same rule as the forward hop.
        logger.warning("action_undo.credentials_undecryptable", vendor_id=vendor_id)
        raise UndoNotPossible(
            503,
            f"credentials for {vendor_id} could not be decrypted, so the reversal did not run",
        ) from exc
    auth_config.update(_operational_config(connector))
    return vendor_id, auth_config


def _interpret(action_id: str, record: dict[str, Any], body: dict[str, Any]) -> UndoDispatchReport:
    """Translate the actions service's answer into the report shape.

    An unrecognised status is a failure, not a success — the actions service
    owns this vocabulary, and a new member arriving here means this reader
    is behind.
    """
    status = str(body.get("status") or "")
    common = {
        "action_id": action_id,
        "action_type": str(record.get("action_type") or ""),
        "target": str(record.get("target") or ""),
        "vendor_id": str(body.get("vendor_id") or ""),
        "requirement": str(body.get("requirement") or ""),
        "reason": str(body.get("reason") or ""),
        "summary": str(body.get("summary") or ""),
    }
    if status == "rolled_back":
        return UndoDispatchReport(
            **common,
            status="rolled_back",
            reversed_=bool(body.get("reversed")),
            rolled_back_at=str(body.get("rolled_back_at") or ""),
            rolled_back_by=str(body.get("rolled_back_by") or ""),
        )
    if status in ("undo_failed", "pending_approval", "refused"):
        return UndoDispatchReport(
            **common,
            status=status,
            reversed_=False,
            error=str(body.get("error") or ""),
        )
    logger.warning("action_undo.unrecognised_status", status=status, action_id=action_id)
    return UndoDispatchReport(
        **common,
        status="undo_failed",
        reversed_=False,
        error=f"the action service answered an unrecognised status {status!r}; treated as not reversed",
    )


async def drive_undo(
    db: AsyncSession,
    *,
    tenant_id: Any,
    action_id: str,
    principal: dict[str, Any],
    requested_by: str,
    confidence: float | None = None,
    approver: dict[str, Any] | None = None,
    requester: dict[str, Any] | None = None,
) -> UndoDispatchReport:
    """Load the record, resolve the tenant's credentials, and dispatch the reversal.

    Called from two places with the same body and different identities: the
    undo route (no ``approver`` — a reversal the grading queues comes back
    ``pending_approval``) and the approval decide path (``approver`` is the
    deciding principal, ``requester`` the stamped originator, so separation
    of duties upstream has two identities to compare).
    """
    record = await _load_record(action_id, str(tenant_id))
    vendor_id, auth_config = await _resolve_reversal_credentials(db, tenant_id=tenant_id, record=record)

    try:
        body = await actions_client.undo_action(
            action_id=action_id,
            tenant_id=str(tenant_id),
            auth_config=auth_config,
            principal=principal,
            approver=approver,
            requester=requester,
            confidence=confidence,
            requested_by=requested_by,
        )
    except actions_client.ActionsServiceError as exc:
        raise _translated(exc) from exc

    report = _interpret(action_id, record, body)
    logger.info(
        "action_undo.dispatched",
        action_id=action_id,
        vendor_id=vendor_id,
        status=report.status,
        reversed=report.reversed_,
    )
    return report
