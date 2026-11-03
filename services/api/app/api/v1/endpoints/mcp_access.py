"""The authority behind AiSOC's own MCP server, once it is on the network.

Depth plan 9.1 (parity 6.6).

Five routes:

* ``POST /mcp/tool-calls/authorize`` — called by ``services/mcp`` before it
  dispatches a tool. Answers allow / deny / approval_required and writes the
  audit row. This is the only route the MCP process needs to be able to call.
* ``POST /mcp/tool-calls/{call_id}/complete`` — called after, with the
  outcome and latency. Fire-and-forget from the MCP side.
* ``GET  /mcp/tools`` — the catalogue with this tenant's effective switches.
* ``PUT  /mcp/tools/{tool_name}`` — a tenant administrator flips one.
* ``GET  /mcp/approvals`` and ``POST /mcp/approvals/{id}/decide`` — the queue
  for anything that is not a read, and the human decision on it.

Why the audit row is written here and not in the MCP process
------------------------------------------------------------
``audit_log`` is append-only and hash-chained per tenant, and the chain's
appender holds a row lock. A second writer outside this service would either
need the database directly — a second place that can write a customer's
audit history — or would fork the chain. More to the point: the MCP process
is the thing being accounted for, and a subject that writes its own record
is not an account of it. ``services/mcp`` emits telemetry about itself as
well, and that is a different artefact with a different trust level.

Why a call produces two rows
----------------------------
``mcp:tool_call`` is written at the decision, carrying the decision. The
``audit_log`` immutability trigger refuses UPDATE, which is deliberate and
correct, so the outcome cannot be filled in later on the same row;
``mcp:tool_result`` is the second row and carries the outcome and latency.
Both carry the same ``resource_id``, which is the call id, so they join.

The first row alone satisfies "an audit row for every call, reads included":
it is written *before* the tool runs, so a call that crashes the process
still has a record. The second is the part a reader wants and the part that
can legitimately be missing.

The tenant is never read from the request
-----------------------------------------
Every route here takes it from the authenticated principal. The MCP server
presents the caller's own credential, forwarded verbatim, rather than a
service token plus a tenant it names — so there is no tenant parameter to
get wrong, and a compromised MCP deployment cannot ask on behalf of a tenant
whose credential it does not hold.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select, update

from app.api.v1.deps import AuthUser, require_permission
from app.db.rls import TenantDBSession
from app.models.audit import AuditLog
from app.models.mcp_access import McpToolApproval, McpToolGrant
from app.services.audit import emit_audit
from app.services.mcp_access import (
    Decision,
    authorize,
    effective_tools,
    tool_catalogue,
)

logger = structlog.get_logger()

router = APIRouter(prefix="/mcp", tags=["mcp"])

#: Outcomes the MCP server may report. Closed on purpose: a free-text
#: outcome column is one nobody can aggregate, and "success" spelled three
#: ways is how a usage meter reads zero.
COMPLETION_OUTCOMES: frozenset[str] = frozenset({"success", "error", "invalid_arguments", "unknown_tool", "denied"})


# ---------------------------------------------------------------------------
# Wire models
# ---------------------------------------------------------------------------


class McpAuthorizeRequest(BaseModel):
    """What ``services/mcp`` asks before dispatching.

    ``arguments`` is sent in full rather than as key names because the
    approval fingerprint has to bind to the specific call. It is hashed on
    arrival and never stored, and the audit row records the argument *names*
    only — the values routinely carry hostnames and lake queries.
    """

    tool_name: str = Field(min_length=1, max_length=120)
    arguments: dict[str, Any] = Field(default_factory=dict)


class McpAuthorizeResponse(BaseModel):
    call_id: str
    outcome: str
    reason: str
    approval_id: str | None = None
    required_permission: str = ""


class McpCompleteRequest(BaseModel):
    outcome: str
    latency_ms: int = Field(ge=0, le=86_400_000)
    error_kind: str | None = Field(default=None, max_length=120)


class McpToolStateModel(BaseModel):
    name: str
    read_only: bool
    enabled: bool
    #: ``tenant`` when somebody decided, ``default`` when nobody has. The
    #: console renders the two differently; collapsing them would let an
    #: operator read "nobody has thought about this" as "we chose this".
    source: str
    required_permission: str
    requires_approval: bool
    decided_by: str


class McpToolGrantRequest(BaseModel):
    enabled: bool


class McpApprovalModel(BaseModel):
    id: str
    tool_name: str
    argument_fingerprint: str
    requested_by: str
    state: str
    decided_by: str | None
    decision_note: str
    expires_at: datetime
    created_at: datetime


class McpApprovalDecisionRequest(BaseModel):
    approve: bool
    note: str = Field(default="", max_length=500)


# ---------------------------------------------------------------------------
# The two routes services/mcp calls
# ---------------------------------------------------------------------------


@router.post("/tool-calls/authorize", response_model=McpAuthorizeResponse)
async def authorize_tool_call(
    body: McpAuthorizeRequest,
    request: Request,
    db: TenantDBSession,
    current_user: AuthUser,
) -> McpAuthorizeResponse:
    """Decide one tool call and record the decision.

    No ``require_permission`` dependency: the permission a call needs depends
    on the tool, and :func:`app.services.mcp_access.authorize` resolves it
    from the catalogue and checks it through the principal's own path. A
    blanket dependency here would be a second, coarser authority in front of
    the specific one.
    """
    call_id = uuid.uuid4()

    def permits(permission: str) -> bool:
        """The principal's own check, turned into a predicate.

        Deliberately ``require_permission`` and not a set membership test.
        That method *is* the one permission path — scopes, then the RBAC
        tables widened by live elevation, then the static map, then any
        attribute condition the tenant configured. Reimplementing any part
        of it here would be a second authority that can disagree with the
        first, which is the shape that produced GHSA-pm3f-h6gc-rvgp.
        """
        try:
            current_user.require_permission(permission)
        except HTTPException:
            return False
        return True

    decision: Decision = await authorize(
        db=db,
        tenant_id=current_user.tenant_id,
        tool_name=body.tool_name,
        arguments=body.arguments,
        has_permission=permits,
        requested_by=current_user.api_key_prefix or current_user.email,
        # The person, beside the label. `user_id` is the key's *owning* user
        # on the API-key path, so one human is one id whichever credential
        # they present -- which is what separation of duties needs and what
        # the label could never give it (GHSA-xhmc-69rh-h3rr, F10).
        requested_by_user_id=current_user.user_id,
    )

    await emit_audit(
        db=db,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        actor_email=current_user.email,
        api_key_prefix=getattr(current_user, "api_key_prefix", None),
        action="mcp:tool_call",
        resource="mcp_tool_call",
        resource_id=str(call_id),
        changes={
            "tool_name": body.tool_name,
            # Names, never values. Which parameters a call carried is the
            # signal an investigator needs; the values are the sensitive half
            # and this row is read by anyone with audit access.
            "argument_keys": sorted(body.arguments),
            "decision": decision.outcome,
            "reason": decision.reason,
            "required_permission": decision.required_permission,
            **({"approval_id": str(decision.approval_id)} if decision.approval_id else {}),
        },
        request=request,
    )
    await db.commit()

    return McpAuthorizeResponse(
        call_id=str(call_id),
        outcome=decision.outcome,
        reason=decision.reason,
        approval_id=str(decision.approval_id) if decision.approval_id else None,
        required_permission=decision.required_permission,
    )


@router.post("/tool-calls/{call_id}/complete", status_code=status.HTTP_204_NO_CONTENT)
async def complete_tool_call(
    call_id: uuid.UUID,
    body: McpCompleteRequest,
    request: Request,
    db: TenantDBSession,
    current_user: AuthUser,
) -> None:
    """Record how a call that was allowed turned out.

    Authorized against the call being reported on, not by a blanket
    permission. There is no single permission every MCP caller holds — a key
    minted for ``alerts:read`` is a legitimate caller — so a blanket
    dependency here would either be wider than the call it describes or
    exclude the callers it exists for.

    Instead this resolves the ``mcp:tool_call`` row the authorize step wrote
    for this id in this tenant, and requires the principal to still hold the
    permission *that call* needed. Two consequences, both wanted: a caller
    cannot write an outcome for a call nobody authorized here, and a key
    whose scopes were narrowed between the call and the report is refused
    rather than quietly accepted.
    """
    if body.outcome not in COMPLETION_OUTCOMES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unknown outcome: {body.outcome}. Expected one of {sorted(COMPLETION_OUTCOMES)}.",
        )

    decision = (
        await db.execute(
            select(AuditLog)
            .where(
                AuditLog.tenant_id == current_user.tenant_id,
                AuditLog.action == "mcp:tool_call",
                AuditLog.resource_id == str(call_id),
            )
            .limit(1)
        )
    ).scalar_one_or_none()
    if decision is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No authorize decision was recorded for call {call_id} in this tenant.",
        )
    required = str((decision.changes or {}).get("required_permission") or "").strip()
    if required:
        # The principal's own path, which is also what `authorize` used. A
        # second copy of the logic here would be a second authority that can
        # disagree with the first.
        current_user.require_permission(required)
    await emit_audit(
        db=db,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        actor_email=current_user.email,
        api_key_prefix=getattr(current_user, "api_key_prefix", None),
        action="mcp:tool_result",
        resource="mcp_tool_call",
        resource_id=str(call_id),
        changes={
            "outcome": body.outcome,
            "latency_ms": body.latency_ms,
            **({"error_kind": body.error_kind} if body.error_kind else {}),
        },
        request=request,
    )
    await db.commit()


# ---------------------------------------------------------------------------
# Administration
# ---------------------------------------------------------------------------


@router.get("/tools", response_model=list[McpToolStateModel])
async def list_tools(
    db: TenantDBSession,
    current_user: AuthUser,
    _: Annotated[None, Depends(require_permission("settings:read"))],
) -> list[McpToolStateModel]:
    return [McpToolStateModel(**row) for row in await effective_tools(db, current_user.tenant_id)]


@router.put("/tools/{tool_name}", response_model=McpToolStateModel)
async def set_tool_grant(
    tool_name: str,
    body: McpToolGrantRequest,
    request: Request,
    db: TenantDBSession,
    current_user: AuthUser,
    _: Annotated[None, Depends(require_permission("settings:write"))],
) -> McpToolStateModel:
    if tool_name not in tool_catalogue():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown tool: {tool_name}. GET /api/v1/mcp/tools lists what this deployment serves.",
        )
    actor = current_user.api_key_prefix or current_user.email
    row = (
        await db.execute(
            select(McpToolGrant).where(
                McpToolGrant.tenant_id == current_user.tenant_id,
                McpToolGrant.tool_name == tool_name,
            )
        )
    ).scalar_one_or_none()
    if row is None:
        row = McpToolGrant(
            tenant_id=current_user.tenant_id,
            tool_name=tool_name,
            enabled=body.enabled,
            decided_by=actor,
        )
        db.add(row)
    else:
        row.enabled = body.enabled
        row.decided_by = actor
        row.updated_at = datetime.now(UTC)

    await emit_audit(
        db=db,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        actor_email=current_user.email,
        api_key_prefix=getattr(current_user, "api_key_prefix", None),
        action="mcp:tool_grant",
        resource="mcp_tool_grant",
        resource_id=tool_name,
        changes={"enabled": body.enabled},
        request=request,
    )
    await db.commit()

    states = {entry["name"]: entry for entry in await effective_tools(db, current_user.tenant_id)}
    return McpToolStateModel(**states[tool_name])


@router.get("/approvals", response_model=list[McpApprovalModel])
async def list_approvals(
    db: TenantDBSession,
    current_user: AuthUser,
    _: Annotated[None, Depends(require_permission("settings:read"))],
    state: str = "pending",
) -> list[McpApprovalModel]:
    stmt = (
        select(McpToolApproval)
        .where(McpToolApproval.tenant_id == current_user.tenant_id)
        .order_by(McpToolApproval.created_at.desc())
        .limit(200)
    )
    if state != "all":
        stmt = stmt.where(McpToolApproval.state == state)
    rows = (await db.execute(stmt)).scalars().all()
    return [
        McpApprovalModel(
            id=str(row.id),
            tool_name=row.tool_name,
            argument_fingerprint=row.argument_fingerprint,
            requested_by=row.requested_by,
            state=row.state,
            decided_by=row.decided_by,
            decision_note=row.decision_note,
            expires_at=row.expires_at,
            created_at=row.created_at,
        )
        for row in rows
    ]


async def claim_decision(
    db: Any,
    *,
    approval_id: uuid.UUID,
    tenant_id: uuid.UUID,
    state: str,
    actor: str,
    note: str,
) -> uuid.UUID | None:
    """Write a decision onto a still-pending approval. ``None`` if it moved.

    One conditional ``UPDATE``, not a read-then-write (GHSA-xhmc-69rh-h3rr,
    F11). The decision used to be a ``SELECT``, a ``row.state != "pending"``
    test in Python, and an ORM write. The read took no lock, so two concurrent
    decisions both passed the guard and both committed -- an approve and a
    deny were each accepted on one request, and the row kept whichever landed
    last. Narrowing the statement by the state it expects means the loser
    matches no row and is told so.

    ``rowcount`` rather than ``RETURNING``: this is the same statement on
    SQLite, which the offline suite runs on, and the count is the portable
    answer to the only question here -- did this caller take the decision.
    """
    result = await db.execute(
        update(McpToolApproval)
        .where(
            McpToolApproval.id == approval_id,
            McpToolApproval.tenant_id == tenant_id,
            McpToolApproval.state == "pending",
        )
        .values(state=state, decided_by=actor, decided_at=datetime.now(UTC), decision_note=note)
        .execution_options(synchronize_session=False)
    )
    return approval_id if result.rowcount == 1 else None


@router.post("/approvals/{approval_id}/decide", response_model=McpApprovalModel)
async def decide_approval(
    approval_id: uuid.UUID,
    body: McpApprovalDecisionRequest,
    request: Request,
    db: TenantDBSession,
    current_user: AuthUser,
    _: Annotated[None, Depends(require_permission("settings:write"))],
) -> McpApprovalModel:
    row = (
        await db.execute(
            select(McpToolApproval).where(
                McpToolApproval.id == approval_id,
                McpToolApproval.tenant_id == current_user.tenant_id,
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such approval")
    if row.state != "pending":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Approval {approval_id} is already {row.state}.",
        )

    # Separation of duties, the same rule the response-action queue follows:
    # the caller who asked cannot be the caller who agrees.
    #
    # Compared on the **person**, not on `requested_by`. That column holds
    # `api_key_prefix or email` -- whichever credential authenticated the
    # request -- so a single human who requested a call through their own API
    # key and then opened the console appeared as two different strings and
    # the check passed (GHSA-xhmc-69rh-h3rr, F10). `user_id` is the key's
    # owning user on the key path and the signed-in user on the session path,
    # so it is one id for one human either way.
    actor = current_user.api_key_prefix or current_user.email
    if row.requested_by_user_id is not None:
        if row.requested_by_user_id == current_user.user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    "The principal that requested this call cannot approve it, whichever credential they present (separation of duties)."
                ),
            )
    elif row.requested_by and row.requested_by == actor:
        # Pre-158 rows carry no requester id. The label comparison is all
        # there is, and it is kept rather than dropped: it catches the
        # same-credential case, which is better than nothing. Recorded as
        # unevaluated below so the row does not read as a check that passed.
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The principal that requested this call cannot approve it.",
        )

    decided_state = "approved" if body.approve else "denied"
    claimed = await claim_decision(
        db,
        approval_id=approval_id,
        tenant_id=current_user.tenant_id,
        state=decided_state,
        actor=actor,
        note=body.note or "",
    )
    if claimed is None:
        # Somebody decided it between the read above and this statement.
        # Re-read so the conflict names the decision that won rather than the
        # one this caller tried to take.
        await db.rollback()
        current = (
            await db.execute(
                select(McpToolApproval).where(
                    McpToolApproval.id == approval_id,
                    McpToolApproval.tenant_id == current_user.tenant_id,
                )
            )
        ).scalar_one_or_none()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(f"Approval {approval_id} was decided concurrently and is now {current.state if current else 'gone'}."),
        )
    await db.refresh(row)

    await emit_audit(
        db=db,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        actor_email=current_user.email,
        api_key_prefix=getattr(current_user, "api_key_prefix", None),
        action="mcp:approval_decision",
        resource="mcp_tool_approval",
        resource_id=str(approval_id),
        changes={"tool_name": row.tool_name, "state": row.state},
        request=request,
    )
    await db.commit()
    await db.refresh(row)

    return McpApprovalModel(
        id=str(row.id),
        tool_name=row.tool_name,
        argument_fingerprint=row.argument_fingerprint,
        requested_by=row.requested_by,
        state=row.state,
        decided_by=row.decided_by,
        decision_note=row.decision_note,
        expires_at=row.expires_at,
        created_at=row.created_at,
    )
