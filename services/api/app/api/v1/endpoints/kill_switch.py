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
by everything that acts: closure in the triage worker, the actions
dispatcher, playbook dispatch and the MCP write tools.

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

#: Deployment-wide authority, so deliberately **not** ``settings:write``.
#: A tenant administrator holds that one, and the platform switch stops every
#: other tenant on the deployment too. No tenant-scoped role in
#: ``ROLE_PERMISSIONS`` is granted this; only the wildcard roles hold it, which
#: is the same decision ``workload_identities:*`` records for the same reason.
#: Migration 123 seeds it into the permission catalog.
PLATFORM_KILL_SWITCH_PERMISSION = "platform_kill_switch:write"


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


# ── The platform-wide switch ────────────────────────────────────────────────
#
# These two are the surface that did not exist. The table has carried a global
# row since 078 and two readers consult it — the GET above and
# `kill_switch_engaged` in services/agents, on every alert — but every write in
# this module bound the caller's own tenant, so no endpoint, console control,
# CLI or script could set `tenant_id IS NULL`. The platform-wide stop was
# readable, documented, and reachable only from a psql prompt; and migration
# 078's WITH CHECK refused it even there for the role the services connect as.
#
# Both routes take the **unbound** `DBSession`, which is the inverse of the two
# tenant routes above and is load-bearing rather than an oversight: migration
# 123 admits the global row only when `current_tenant_id()` IS NULL, so a
# tenant-scoped session is precisely the one that cannot write it. Moving these
# onto `TenantDBSession` — the repair the tenant routes needed — would break the
# global switch again, so `test_they_run_on_an_unbound_session` asserts the
# resolved dependency rather than leaving it to a comment.


@router.post(
    "/global/engage",
    response_model=KillSwitchState,
    status_code=status.HTTP_200_OK,
    summary="Freeze autonomous closure and action dispatch for every tenant",
)
async def engage_global(
    body: EngageRequest,
    db: DBSession,
    user: Annotated[AuthUser, Depends(require_permission(PLATFORM_KILL_SWITCH_PERMISSION))],
) -> KillSwitchState:
    """Stop autonomous closure and dispatch across the whole deployment.

    One row, upserted. The conflict target is the expression index
    `aisoc_kill_switch_global_idx ON aisoc_kill_switch ((TRUE)) WHERE tenant_id
    IS NULL`, which is what keeps the global switch a singleton rather than a
    pile of rows a reader would have to reconcile at 3am.
    """
    actor = getattr(user, "email", None) or str(getattr(user, "user_id", "unknown"))
    now = datetime.now(UTC)

    await db.execute(
        text("""
            INSERT INTO aisoc_kill_switch
                (id, tenant_id, engaged, reason, engaged_by, engaged_at, updated_at)
            VALUES (:id, NULL, TRUE, :reason, :actor, :now, :now)
            ON CONFLICT ((TRUE)) WHERE tenant_id IS NULL
            DO UPDATE SET engaged = TRUE,
                          reason = EXCLUDED.reason,
                          engaged_by = EXCLUDED.engaged_by,
                          engaged_at = EXCLUDED.engaged_at,
                          released_by = NULL,
                          released_at = NULL,
                          updated_at = EXCLUDED.updated_at
        """).bindparams(id=uuid.uuid4(), reason=body.reason, actor=actor, now=now)
    )
    await db.execute(
        text("""
            INSERT INTO aisoc_kill_switch_audit (id, tenant_id, action, reason, actor, scope)
            VALUES (:id, NULL, 'engage', :reason, :actor, 'global')
        """).bindparams(id=uuid.uuid4(), reason=body.reason, actor=actor)
    )
    await db.commit()

    logger.warning(
        "kill_switch.engaged scope=global actor=%s reason=%s",
        _sanitize(actor, 64),
        _sanitize(body.reason),
    )
    return KillSwitchState(engaged=True, scope="global", reason=body.reason, engaged_by=actor, engaged_at=now)


@router.post(
    "/global/release",
    response_model=KillSwitchState,
    summary="Resume autonomous closure and action dispatch across every tenant",
)
async def release_global(
    body: ReleaseRequest,
    db: DBSession,
    user: Annotated[AuthUser, Depends(require_permission(PLATFORM_KILL_SWITCH_PERMISSION))],
) -> KillSwitchState:
    """Release the platform-wide stop.

    A tenant that engaged its own switch keeps it: the two scopes are
    independent and neither needs the other's agreement, so releasing globally
    must not silently resume a tenant that asked to stay stopped.
    """
    actor = getattr(user, "email", None) or str(getattr(user, "user_id", "unknown"))
    now = datetime.now(UTC)

    result = await db.execute(
        text("""
            UPDATE aisoc_kill_switch
               SET engaged = FALSE, released_by = :actor, released_at = :now, updated_at = :now
             WHERE tenant_id IS NULL AND engaged = TRUE
         RETURNING id
        """).bindparams(actor=actor, now=now)
    )
    if result.first() is None:
        # Saying so beats reporting success over a switch that was never
        # engaged: an operator who believes they released a stop that is not
        # there stops looking for the one that is.
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No platform-wide kill switch is engaged.",
        )

    await db.execute(
        text("""
            INSERT INTO aisoc_kill_switch_audit (id, tenant_id, action, reason, actor, scope)
            VALUES (:id, NULL, 'release', :reason, :actor, 'global')
        """).bindparams(id=uuid.uuid4(), reason=body.reason, actor=actor)
    )
    await db.commit()

    logger.warning(
        "kill_switch.released scope=global actor=%s reason=%s",
        _sanitize(actor, 64),
        _sanitize(body.reason),
    )
    return KillSwitchState(engaged=False)
