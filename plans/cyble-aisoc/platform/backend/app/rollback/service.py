"""Core rollback service.

This module is the **only** sanctioned entrypoint for reversing a
previously-executed ``WRITE-*`` action. Direct calls into the reverse
tools (e.g. ``edr.release_host``) bypass the audit pairing and the
tenant guard, so the rollback API and any background SLA watcher route
through here instead.

Design notes
------------
* The forward tool's :class:`~app.tools.registry.ToolDef` carries both
  ``reverse_tool`` (name) and ``reverse_params_builder`` (pure function
  ``(forward_params, forward_result) -> reverse_params``). This module
  resolves both, then dispatches through
  :meth:`app.agents.base.BaseAgent.call_tool` with ``rollback_of_id``
  set. The base agent atomically stamps the forward row's
  ``rolled_back_at`` / ``rolled_back_by`` fields on success, so the
  paired audit is a single transaction from the caller's perspective.
* The executor is :class:`~app.agents.responder.ResponderAgent` because
  rollbacks of containment actions are themselves containment actions
  (they change the live environment) and the Responder already owns
  the HITL gating / risk-class plumbing.
* We deliberately surface ``RollbackNotEligible`` as a distinct
  exception class. The API layer maps it to ``409 Conflict`` so that
  retries are explicit and idempotent — re-rolling-back an already
  reversed action never silently no-ops.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy import desc
from sqlmodel import Session, select

from app.agents.responder import ResponderAgent
from app.models.tool_call import RiskClass, ToolCall
from app.tools.registry import ToolDef, registry


class RollbackError(Exception):
    """Base class for all rollback-service failures."""


class RollbackNotEligible(RollbackError):
    """The requested ``ToolCall`` cannot be rolled back.

    Reasons include: forward call did not succeed, the tool has no
    registered reverse, the call was already rolled back, the call IS
    itself a rollback row, or the integration handler refused to
    materialize inverse parameters (e.g. missing fields).
    """

    def __init__(self, reason: str, *, code: str) -> None:
        super().__init__(reason)
        self.code = code
        self.reason = reason


# Risk classes that participate in the reverse-action pairing. ``READ``
# never mutates state so it is excluded; ``DESTRUCTIVE`` is intentionally
# excluded because true destructives (data wipe, password rotation that
# invalidates 2FA recovery secrets) cannot be reversed safely.
_REVERSIBLE_RISK_CLASSES = frozenset(
    {RiskClass.WRITE_REVERSIBLE, RiskClass.WRITE_SIGNIFICANT}
)


# ──────────────────────────────────────────────────────────────────────
# Eligibility
# ──────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class RollbackEligibility:
    """Eligibility verdict for a single ``ToolCall`` row.

    Returned by :func:`rollback_eligibility` and embedded in the list
    response so the UI can disable the "Undo" button with an actionable
    reason instead of a generic 409.
    """

    tool_call_id: int
    eligible: bool
    reason: str
    reverse_tool: str | None
    # Pre-built reverse params (deterministic given forward params +
    # result). We expose them so the analyst console can show "Will
    # call edr.release_host(host_id=…)" *before* clicking undo. Empty
    # dict if ineligible.
    reverse_params_preview: dict[str, Any]


def _classify(tc: ToolCall, td: ToolDef | None) -> RollbackEligibility:
    if td is None:
        return RollbackEligibility(
            tool_call_id=tc.id or 0,
            eligible=False,
            reason="tool no longer registered",
            reverse_tool=None,
            reverse_params_preview={},
        )
    if tc.rollback_of_id is not None:
        return RollbackEligibility(
            tool_call_id=tc.id or 0,
            eligible=False,
            reason="this row is itself a rollback",
            reverse_tool=None,
            reverse_params_preview={},
        )
    if tc.rolled_back_at is not None:
        return RollbackEligibility(
            tool_call_id=tc.id or 0,
            eligible=False,
            reason="already rolled back",
            reverse_tool=td.reverse_tool,
            reverse_params_preview={},
        )
    if not tc.success:
        return RollbackEligibility(
            tool_call_id=tc.id or 0,
            eligible=False,
            reason="forward call did not succeed; nothing to undo",
            reverse_tool=td.reverse_tool,
            reverse_params_preview={},
        )
    if tc.risk_class not in _REVERSIBLE_RISK_CLASSES:
        return RollbackEligibility(
            tool_call_id=tc.id or 0,
            eligible=False,
            reason=f"risk_class={tc.risk_class.value} is not reversible by policy",
            reverse_tool=None,
            reverse_params_preview={},
        )
    if not td.is_reversible or td.reverse_params_builder is None:
        # Distinguish documented forward-only opt-outs from genuine
        # gaps. The former is a deliberate product decision the UI
        # should explain verbatim ("re-granting requires fresh user
        # consent"); the latter is a coverage bug the structural
        # test catches in CI.
        if td.forward_only_reason is not None:
            reason = f"forward-only by design: {td.forward_only_reason}"
        else:
            reason = "tool has no registered reverse handler"
        return RollbackEligibility(
            tool_call_id=tc.id or 0,
            eligible=False,
            reason=reason,
            reverse_tool=None,
            reverse_params_preview={},
        )

    # Materialize the reverse params upfront so an unrecoverable builder
    # error (e.g. forward result missing required fields) is surfaced as
    # an eligibility failure rather than a runtime crash mid-rollback.
    try:
        reverse_params = td.reverse_params_builder(
            dict(tc.params or {}), dict(tc.result or {})
        )
    except Exception as exc:  # noqa: BLE001  (we want any builder failure)
        return RollbackEligibility(
            tool_call_id=tc.id or 0,
            eligible=False,
            reason=f"reverse param builder failed: {exc}",
            reverse_tool=td.reverse_tool,
            reverse_params_preview={},
        )

    return RollbackEligibility(
        tool_call_id=tc.id or 0,
        eligible=True,
        reason="ok",
        reverse_tool=td.reverse_tool,
        reverse_params_preview=reverse_params,
    )


def rollback_eligibility(db: Session, tool_call_id: int) -> RollbackEligibility:
    """Inspect a single ``ToolCall`` without mutating anything."""
    tc = db.get(ToolCall, tool_call_id)
    if tc is None:
        return RollbackEligibility(
            tool_call_id=tool_call_id,
            eligible=False,
            reason="tool_call not found",
            reverse_tool=None,
            reverse_params_preview={},
        )
    td = registry.get(tc.tool_name)
    return _classify(tc, td)


def list_rollback_eligible(
    db: Session,
    *,
    tenant_ids: list[str] | None,
    case_id: int | None = None,
    limit: int = 100,
    include_ineligible: bool = False,
) -> list[tuple[ToolCall, RollbackEligibility]]:
    """Return recent ``ToolCall`` rows visible to the caller.

    ``tenant_ids`` MUST be the set of tenants the caller is allowed to
    view (see :class:`app.security.tenant.TenantContext`). Passing
    ``None`` is reserved for system / background workers and disables
    the tenant filter — never wire user-facing endpoints that way.
    """
    stmt = select(ToolCall)
    if tenant_ids is not None:
        # Empty list => zero rows. That is the correct behaviour for a
        # principal with no viewable tenants; do NOT collapse it to
        # "no filter".
        stmt = stmt.where(ToolCall.tenant_id.in_(tenant_ids))  # type: ignore[attr-defined]
    if case_id is not None:
        stmt = stmt.where(ToolCall.case_id == case_id)
    # Show forward rows only — rollback rows themselves are not
    # candidates for further rollback.
    stmt = stmt.where(ToolCall.rollback_of_id.is_(None))  # type: ignore[union-attr]
    stmt = stmt.order_by(desc(ToolCall.created_at)).limit(limit)

    rows = db.exec(stmt).all()
    out: list[tuple[ToolCall, RollbackEligibility]] = []
    for tc in rows:
        td = registry.get(tc.tool_name)
        verdict = _classify(tc, td)
        if not verdict.eligible and not include_ineligible:
            continue
        out.append((tc, verdict))
    return out


# ──────────────────────────────────────────────────────────────────────
# Execution
# ──────────────────────────────────────────────────────────────────────


async def execute_rollback(
    db: Session,
    *,
    tool_call_id: int,
    actor: str,
    rationale: str = "",
) -> dict[str, Any]:
    """Reverse the named forward action.

    The caller MUST have already enforced tenant visibility on
    ``tool_call_id`` (see :func:`app.security.tenant.ensure_row_visible`
    in the API route). This function trusts that the row is the
    caller's to undo.

    Parameters
    ----------
    db:
        Active SQLModel session. Will be passed to the spawned
        :class:`ResponderAgent`.
    tool_call_id:
        Primary key of the forward ``ToolCall`` row to reverse.
    actor:
        Free-form actor identifier. Used as a soft override for the
        ``rolled_back_by`` field; the base agent currently stamps
        ``agent:<name>`` automatically. We surface ``actor`` here so
        callers (HTTP handler, SLA watcher) can pass through richer
        principal info on the resulting trace + rollback row.
    rationale:
        Operator rationale, recorded on the rollback ``ToolCall`` row.

    Raises
    ------
    RollbackNotEligible:
        Whenever :func:`rollback_eligibility` returns ineligible. The
        ``code`` attribute on the exception lets the API map to a
        specific HTTP status — currently always 409.
    """
    tc = db.get(ToolCall, tool_call_id)
    if tc is None:
        raise RollbackNotEligible(
            "tool_call not found", code="NOT_FOUND"
        )

    td = registry.get(tc.tool_name)
    verdict = _classify(tc, td)
    if not verdict.eligible:
        raise RollbackNotEligible(verdict.reason, code="INELIGIBLE")

    # `td` is guaranteed non-None when verdict.eligible is True.
    assert td is not None
    assert td.reverse_tool is not None
    reverse_params = dict(verdict.reverse_params_preview)

    # Resolve the *reverse* tool definition. The reverse tool is also a
    # registered tool — that is the contract for symmetric audit — and
    # it must itself be allowed for the forward call's tenant.
    reverse_td = registry.get(td.reverse_tool)
    if reverse_td is None:
        raise RollbackNotEligible(
            f"reverse tool {td.reverse_tool} not registered",
            code="REVERSE_MISSING",
        )
    if not registry.is_allowed_for_tenant(reverse_td.name, tc.tenant_id):
        raise RollbackNotEligible(
            f"reverse tool {reverse_td.name} not allowed for tenant {tc.tenant_id}",
            code="REVERSE_DENIED_BY_TENANT",
        )

    # Dispatch through the Responder so the resulting row gets the same
    # HITL gating, prompt-injection defense, and tool-output audit as a
    # forward action. We bind to the same case_id and tenant_id; the
    # base agent stamps `rollback_of_id` and the forward row.
    responder = ResponderAgent(
        db=db, case_id=tc.case_id, tenant_id=tc.tenant_id
    )

    # The base agent automatically stamps `rolled_back_by` as
    # `agent:<responder>`. We want the human actor visible too, so we
    # take a "best effort" pass: if the call succeeds AND the forward
    # row was stamped, we append the human-actor suffix. This keeps the
    # default machine-friendly while letting analysts trace back to a
    # specific user.
    result = await responder.call_tool(
        reverse_td.name,
        reverse_params,
        rationale=rationale or f"rollback of tool_call={tool_call_id}",
        blast_radius={
            "rollback_of_id": tool_call_id,
            "forward_tool": tc.tool_name,
            "actor": actor,
        },
        rollback_of_id=tool_call_id,
    )

    # Augment `rolled_back_by` with the human actor if the forward row
    # was indeed stamped by call_tool. We DO NOT overwrite — the agent
    # name is preserved as the primary attribution.
    db.refresh(tc)
    if tc.rolled_back_at is not None and tc.rolled_back_by and actor:
        if actor not in tc.rolled_back_by:
            tc.rolled_back_by = f"{tc.rolled_back_by} via {actor}"
            db.add(tc)
            db.commit()
            db.refresh(tc)

    return {
        "rollback_of_id": tool_call_id,
        "reverse_tool": reverse_td.name,
        "reverse_params": reverse_params,
        "result": result,
        "rolled_back_at": tc.rolled_back_at.isoformat()
        if tc.rolled_back_at
        else None,
        "rolled_back_by": tc.rolled_back_by,
    }
