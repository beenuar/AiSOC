"""The stop button for autonomous closure and action dispatch.

Parity plan 2.2.

Why it is separate from the closure policy
------------------------------------------
A closure policy is a considered edit to how a tenant wants to run, made on
a Tuesday afternoon with a class in mind. A kill switch is what somebody
reaches for at 3am when the agent is doing something they did not expect,
and it must work without reasoning about per-class rows, without a deploy
and without a restart.

So it is one boolean with a mandatory reason, checked first and separately
by the two things that act without a human.

What it stops
-------------
1. **Automatic closure**, in the triage worker. ``closure.decide()`` checks
   the switch before the per-class policy, so an engaged switch withholds
   auto-close whatever the confidence.
2. **Action dispatch**, at ``services/actions`` ``live_actions.dispatch()``
   — before the executor is looked up, so no vendor is contacted. That is
   the single chokepoint every route to a customer's estate passes through:
   ``POST /live-actions/dispatch``, the ``/dry-run`` sibling, the agent
   loop, and **playbook steps**, which reach it through
   ``action_bridge`` → ``POST /playbook-steps/dispatch`` →
   ``actions_client``. A blocked request comes back ``blocked``, never
   ``failed``: failed invites a retry, and the retry is refused too.

Dry runs are stopped as well. A preview is only credentials-free while the
strip list matches what each client factory reads, and
``services/actions/app/executors/siem.py`` records a release where it did
not and a "dry run" reached the customer's production SIEM. An operator who
pressed the stop button did not mean "stop, except for previews".

What it does not stop
---------------------
Anything a human does. Analysts keep triaging, the console keeps working,
and an operator can still act directly at the vendor — the switch governs
what the platform does on its own, and is not an outage.

This paragraph used to name "the MCP write tools" as a third enforcement
point. There are no MCP write tools. ``services/mcp`` exposes one tool that
touches the response surface, ``aisoc_preview_action``, it is dry-run only,
and ``services/mcp/tests/actions.test.ts`` asserts that the path performing
an action appears nowhere in its source. Naming it here was worse than an
unenforced claim: it told a reader the MCP server could perform actions,
which was the more alarming half and was never true either.

Two scopes
----------
Global (``tenant_id IS NULL``) is the platform operator's, and a tenant can
read that it is engaged: a platform-wide stop that a tenant cannot see reads
to them as an unexplained outage. Tenant scope is their own. Either being
engaged is enough to refuse, and neither needs the other's agreement.

The reason is NOT optional. A switch with no reason is one nobody can safely
disengage, because the next operator cannot tell a deliberate freeze from a
forgotten test.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import text

from app.api.v1.deps import AuthUser, DBSession, require_permission
from app.db.rls import TenantDBSession

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/kill-switch", tags=["autonomy"])


class KillSwitchState(BaseModel):
    engaged: bool
    scope: str | None = Field(None, description="global | tenant, when engaged")
    reason: str | None = None
    engaged_by: str | None = None
    engaged_at: datetime | None = None


class EngageRequest(BaseModel):
    reason: str = Field(
        ...,
        min_length=8,
        max_length=500,
        description="Why. Required: the next operator has to be able to tell a deliberate freeze from a forgotten test.",
    )


class ReleaseRequest(BaseModel):
    reason: str = Field(..., min_length=8, max_length=500)


def _sanitize(value: object, limit: int = 200) -> str:
    """Flatten for the log. Newlines in an operator-supplied reason would
    otherwise forge log lines."""
    return str(value).replace("\r", "").replace("\n", " ")[:limit]


@router.get("", response_model=KillSwitchState, summary="Is autonomous action frozen")
async def read_kill_switch(db: DBSession, user: AuthUser) -> KillSwitchState:
    """Readable by any authenticated user in the tenant.

    Deliberately not behind a write permission: an analyst watching the
    queue stop moving needs to be able to find out why without asking an
    administrator.
    """
    rows = (
        await db.execute(
            text("""
            SELECT tenant_id, reason, engaged_by, engaged_at
              FROM aisoc_kill_switch
             WHERE engaged = TRUE
               AND (tenant_id IS NULL OR tenant_id = :t)
             ORDER BY tenant_id NULLS FIRST
            """).bindparams(t=user.tenant_id)
        )
    ).fetchall()

    if not rows:
        return KillSwitchState(engaged=False)
    row = rows[0]
    return KillSwitchState(
        engaged=True,
        scope="global" if row.tenant_id is None else "tenant",
        reason=row.reason,
        engaged_by=row.engaged_by,
        engaged_at=row.engaged_at,
    )


@router.post(
    "/engage",
    response_model=KillSwitchState,
    status_code=status.HTTP_200_OK,
    summary="Freeze autonomous closure and action dispatch for this tenant",
)
async def engage(
    body: EngageRequest,
    # Tenant-scoped on purpose: aisoc_kill_switch and aisoc_kill_switch_audit
    # carry the strict RLS policy `WITH CHECK (tenant_id = current_tenant_id())`,
    # so these INSERTs through a session that never sets app.current_tenant_id
    # were refused for every tenant — the emergency stop answered HTTP 500 on
    # every deployment (same defect class as GHSA-898c-wxrw-hx6c, reproduced
    # live against real Postgres as the aisoc_app runtime role).
    db: TenantDBSession,
    user: Annotated[AuthUser, Depends(require_permission("settings:write"))],
) -> KillSwitchState:
    actor = getattr(user, "email", None) or str(getattr(user, "user_id", "unknown"))
    now = datetime.now(UTC)

    await db.execute(
        text("""
            INSERT INTO aisoc_kill_switch
                (id, tenant_id, engaged, reason, engaged_by, engaged_at, updated_at)
            VALUES (:id, :t, TRUE, :reason, :actor, :now, :now)
            ON CONFLICT (tenant_id) WHERE tenant_id IS NOT NULL
            DO UPDATE SET engaged = TRUE,
                          reason = EXCLUDED.reason,
                          engaged_by = EXCLUDED.engaged_by,
                          engaged_at = EXCLUDED.engaged_at,
                          released_by = NULL,
                          released_at = NULL,
                          updated_at = EXCLUDED.updated_at
        """).bindparams(id=uuid.uuid4(), t=user.tenant_id, reason=body.reason, actor=actor, now=now)
    )
    await db.execute(
        text("""
            INSERT INTO aisoc_kill_switch_audit (id, tenant_id, action, reason, actor, scope)
            VALUES (:id, :t, 'engage', :reason, :actor, 'tenant')
        """).bindparams(id=uuid.uuid4(), t=user.tenant_id, reason=body.reason, actor=actor)
    )
    await db.commit()

    logger.warning(
        "kill_switch.engaged tenant=%s actor=%s reason=%s",
        _sanitize(user.tenant_id, 64),
        _sanitize(actor, 64),
        _sanitize(body.reason),
    )
    return KillSwitchState(engaged=True, scope="tenant", reason=body.reason, engaged_by=actor, engaged_at=now)


@router.post(
    "/release",
    response_model=KillSwitchState,
    summary="Resume autonomous closure and action dispatch",
)
async def release(
    body: ReleaseRequest,
    # Tenant-scoped for the same reason as engage: the UPDATE's new row and
    # the audit INSERT are judged by the strict WITH CHECK. The global-switch
    # read below still works — the table's USING clause admits tenant_id IS
    # NULL rows to every session.
    db: TenantDBSession,
    user: Annotated[AuthUser, Depends(require_permission("settings:write"))],
) -> KillSwitchState:
    actor = getattr(user, "email", None) or str(getattr(user, "user_id", "unknown"))
    now = datetime.now(UTC)

    result = await db.execute(
        text("""
            UPDATE aisoc_kill_switch
               SET engaged = FALSE, released_by = :actor, released_at = :now, updated_at = :now
             WHERE tenant_id = :t AND engaged = TRUE
         RETURNING id
        """).bindparams(t=user.tenant_id, actor=actor, now=now)
    )
    if result.first() is None:
        # A global switch is not a tenant's to release, and saying so is
        # better than reporting success over a switch that stays engaged.
        globally = (await db.execute(text("SELECT 1 FROM aisoc_kill_switch WHERE tenant_id IS NULL AND engaged = TRUE"))).first()
        if globally is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="A platform-wide kill switch is engaged. It can only be released by the "
                "platform operator, and releasing this tenant's switch would not resume anything.",
            )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No kill switch is engaged for this tenant.",
        )

    await db.execute(
        text("""
            INSERT INTO aisoc_kill_switch_audit (id, tenant_id, action, reason, actor, scope)
            VALUES (:id, :t, 'release', :reason, :actor, 'tenant')
        """).bindparams(id=uuid.uuid4(), t=user.tenant_id, reason=body.reason, actor=actor)
    )
    await db.commit()

    logger.warning(
        "kill_switch.released tenant=%s actor=%s reason=%s",
        _sanitize(user.tenant_id, 64),
        _sanitize(actor, 64),
        _sanitize(body.reason),
    )
    return KillSwitchState(engaged=False)
