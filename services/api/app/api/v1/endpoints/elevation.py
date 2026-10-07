"""Time-boxed privilege elevation: request, approve, expire.

Depth plan item 8.2. ``privilege_grants`` was created by migration 087 and
read by nothing, so there was no elevation at all: a role was held
permanently or not at all, and an analyst who needed to isolate a host once
either held that power every day or waited for somebody who did.

The three properties that make this least privilege rather than paperwork
-------------------------------------------------------------------------

**Permissions, not roles.** Elevating to ``admin`` to isolate one host
confers the wildcard. A grant names the permissions it confers and nothing
else.

**The approver must already hold what they confer.** Enforced by
:func:`app.core.role_grants.authorize_permission_grant`, the same function
that guards role assignment and API-key scopes — scoped to the granter
rather than enumerated per call site, because an allow-list per route means
the next route written is a new advisory (GHSA-pm3f-h6gc-rvgp).

**Nobody approves their own.** Otherwise a request is a grant with extra
steps, and the whole control is a log line.

Expiry needs no worker
----------------------
``expires_at`` is checked where the grant is *used*, in
``CurrentUser.elevated_permissions``. A sweep job is a job that can be
down, and a grant outliving its window because a worker crashed is the
failure mode this exists to remove. Revocation writes ``revoked_at`` and
bumps the RBAC version so every replica drops the grant on its next
request rather than when its TTL happens to lapse.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.api.v1.deps import AuthUser, require_permission
from app.core.permission_cache import bump_version
from app.core.rbac_catalog import PERMISSIONS
from app.core.role_grants import RoleGrantDenied, authorize_permission_grant
from app.db.rls import TenantDBSession
from app.models.enterprise_iam import PrivilegeGrant
from app.models.tenant import User
from app.services.audit import emit_audit

router = APIRouter(prefix="/elevation", tags=["elevation"])

#: The longest a single elevation may run. Eight hours is one shift: long
#: enough to work an incident, short enough that it cannot quietly become
#: standing access. A grant that outlives the reason for it is the state
#: this feature exists to avoid, and "the requester asked for a year" is
#: not a reason the server should accept.
MAX_DURATION = timedelta(hours=8)

#: Permission strings a grant may name. Derived from the seeded catalog
#: rather than written down again, so a permission added there is
#: elevatable without anyone remembering this list exists — and a typo is
#: refused instead of being stored as a grant that confers nothing while
#: reading in the console as though it does.
_KNOWN_PERMISSIONS = frozenset(name for name, _desc, _cat in PERMISSIONS)


class ElevationRequest(BaseModel):
    permissions: list[str] = Field(..., min_length=1, max_length=20)
    justification: str = Field(..., min_length=10, max_length=2000)
    duration_minutes: int = Field(60, ge=5, le=int(MAX_DURATION.total_seconds() // 60))
    case_id: uuid.UUID | None = None
    alert_id: uuid.UUID | None = None


class ElevationOut(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID
    user_email: str | None = None
    permissions: list[str]
    justification: str
    approved_by_id: uuid.UUID | None
    granted_at: datetime
    expires_at: datetime
    revoked_at: datetime | None
    case_id: uuid.UUID | None
    alert_id: uuid.UUID | None
    state: str


def _state(row: PrivilegeGrant, *, now: datetime) -> str:
    """One word for what this row is, so a console does not re-derive it.

    Four columns describe the lifecycle and a surface that reads three of
    them shows a revoked grant as live.
    """
    if row.revoked_at is not None:
        return "revoked"
    if row.approved_by_id is None:
        return "pending"
    expires = row.expires_at if row.expires_at.tzinfo else row.expires_at.replace(tzinfo=UTC)
    return "active" if expires > now else "expired"


def _out(row: PrivilegeGrant, *, now: datetime, email: str | None = None) -> ElevationOut:
    return ElevationOut(
        id=row.id,
        user_id=row.user_id,
        user_email=email,
        permissions=list(row.permissions or []),
        justification=row.justification,
        approved_by_id=row.approved_by_id,
        granted_at=row.granted_at,
        expires_at=row.expires_at,
        revoked_at=row.revoked_at,
        case_id=row.case_id,
        alert_id=row.alert_id,
        state=_state(row, now=now),
    )


def _reject_unknown(permissions: list[str]) -> None:
    unknown = sorted(set(permissions) - _KNOWN_PERMISSIONS)
    if unknown:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unknown permission(s): {', '.join(unknown)}",
        )


@router.post("/requests", response_model=ElevationOut, status_code=status.HTTP_201_CREATED)
async def request_elevation(
    body: ElevationRequest,
    request: Request,
    db: TenantDBSession,
    current_user: Annotated[AuthUser, Depends(require_permission("elevation:request"))],
) -> ElevationOut:
    """Ask for a permission for a while. Confers nothing until approved.

    The row is written with ``approved_by_id`` NULL, and
    ``resolve_elevation`` requires that column to be set, so a request is
    inert by construction rather than by a flag somebody could forget to
    check.

    The tenant and the requesting user come from the authenticated
    principal. Neither is a body field: a caller that can name the subject
    of an elevation can elevate somebody else, and a caller that can name
    the tenant can elevate inside another one.
    """
    _reject_unknown(body.permissions)

    row = PrivilegeGrant(
        tenant_id=current_user.tenant_id,
        user_id=current_user.user_id,
        permissions=sorted(set(body.permissions)),
        justification=body.justification,
        approved_by_id=None,
        granted_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(minutes=body.duration_minutes),
        case_id=body.case_id,
        alert_id=body.alert_id,
    )
    db.add(row)
    await db.flush()

    await emit_audit(
        db=db,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        actor_email=current_user.email,
        action="elevation:request",
        resource="privilege_grant",
        resource_id=str(row.id),
        changes={"permissions": row.permissions, "justification": body.justification},
        request=request,
    )
    await db.commit()
    return _out(row, now=datetime.now(UTC), email=current_user.email)


@router.post("/requests/{grant_id}/approve", response_model=ElevationOut)
async def approve_elevation(
    grant_id: uuid.UUID,
    request: Request,
    db: TenantDBSession,
    current_user: Annotated[AuthUser, Depends(require_permission("elevation:approve"))],
) -> ElevationOut:
    """Approve a pending request, if you hold what it confers.

    Two refusals, and they are different questions:

    * **separation of duties** — an approver who is the requester is a
      requester, and the control would be a log line;
    * **no escalation through the approval door** — the approver must
      already hold every permission the grant confers, checked by the same
      function that guards role assignment and key scopes. Without it,
      ``elevation:approve`` would be a permission that confers every other
      permission, which is the wildcard by another name.
    """
    row = await _load(db, grant_id, current_user.tenant_id)

    if row.approved_by_id is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="This request has already been approved")
    if row.revoked_at is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="This request was revoked")
    if row.user_id == current_user.user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You cannot approve your own elevation request",
        )

    expires = row.expires_at if row.expires_at.tzinfo else row.expires_at.replace(tzinfo=UTC)
    if expires <= datetime.now(UTC):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This request's window has already passed; ask for a new one",
        )

    try:
        authorize_permission_grant(
            granter_role=current_user.role,
            granter_scopes=current_user.scopes,
            granter_permissions=current_user.resolved_permissions,
            requested=list(row.permissions or []),
            subject="elevated permission(s)",
        )
    except RoleGrantDenied as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=exc.reason) from exc

    row.approved_by_id = current_user.user_id
    await emit_audit(
        db=db,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        actor_email=current_user.email,
        action="elevation:approve",
        resource="privilege_grant",
        resource_id=str(row.id),
        changes={"permissions": list(row.permissions or []), "expires_at": row.expires_at.isoformat()},
        request=request,
    )
    await db.commit()
    # After the commit: a cache invalidated before the write lands can be
    # repopulated with the old answer by a concurrent request on another
    # replica, which for a *grant* is a delay and for a revoke is a hole.
    await bump_version(str(current_user.tenant_id))
    return _out(row, now=datetime.now(UTC))


@router.post("/requests/{grant_id}/revoke", response_model=ElevationOut)
async def revoke_elevation(
    grant_id: uuid.UUID,
    request: Request,
    db: TenantDBSession,
    current_user: Annotated[AuthUser, Depends(require_permission("elevation:approve"))],
) -> ElevationOut:
    """End an elevation now, rather than at its expiry.

    Gated on ``elevation:approve`` rather than a permission of its own:
    whoever may confer this authority may take it back, and a separate
    ``elevation:revoke`` that somebody forgot to grant would mean an
    elevation nobody present can end.
    """
    row = await _load(db, grant_id, current_user.tenant_id)
    if row.revoked_at is None:
        row.revoked_at = datetime.now(UTC)
        await emit_audit(
            db=db,
            tenant_id=current_user.tenant_id,
            actor_id=current_user.user_id,
            actor_email=current_user.email,
            action="elevation:revoke",
            resource="privilege_grant",
            resource_id=str(row.id),
            changes={"permissions": list(row.permissions or [])},
            request=request,
        )
        await db.commit()
        await bump_version(str(current_user.tenant_id))
    return _out(row, now=datetime.now(UTC))


@router.get("/requests", response_model=list[ElevationOut])
async def list_elevations(
    db: TenantDBSession,
    current_user: Annotated[AuthUser, Depends(require_permission("elevation:read"))],
    state: str | None = None,
) -> list[ElevationOut]:
    """Every elevation in this tenant, newest first.

    Scoped on the authenticated tenant in the ``WHERE`` clause as well as
    by row-level security, because query-layer scoping is the control that
    holds when a session is opened without the RLS context.
    """
    rows = (
        await db.execute(
            select(PrivilegeGrant)
            .where(PrivilegeGrant.tenant_id == current_user.tenant_id)
            .order_by(PrivilegeGrant.granted_at.desc())
            .limit(200)
        )
    ).scalars()

    now = datetime.now(UTC)
    emails = await _emails(db, current_user.tenant_id)
    out = [_out(row, now=now, email=emails.get(row.user_id)) for row in rows]
    return [item for item in out if state is None or item.state == state]


@router.get("/mine", response_model=list[ElevationOut])
async def my_elevations(
    db: TenantDBSession,
    current_user: Annotated[AuthUser, Depends(require_permission("elevation:request"))],
) -> list[ElevationOut]:
    """This principal's own elevations.

    Gated on ``elevation:request`` rather than left identity-only: a
    principal who may not request one has nothing to read here, and an
    identity-only route is how "is this a valid session?" quietly becomes
    the whole authorization decision.
    """
    rows = (
        await db.execute(
            select(PrivilegeGrant)
            .where(
                PrivilegeGrant.tenant_id == current_user.tenant_id,
                PrivilegeGrant.user_id == current_user.user_id,
            )
            .order_by(PrivilegeGrant.granted_at.desc())
            .limit(100)
        )
    ).scalars()
    now = datetime.now(UTC)
    return [_out(row, now=now, email=current_user.email) for row in rows]


async def _load(db: Any, grant_id: uuid.UUID, tenant_id: uuid.UUID) -> PrivilegeGrant:
    """One grant, or 404 — and never another tenant's.

    The tenant predicate is in the query rather than checked after the
    fetch. A read that loads the row first and compares afterwards still
    answers a different 404 for "exists elsewhere" than for "does not
    exist", which enumerates ids across tenants.
    """
    row = (
        await db.execute(select(PrivilegeGrant).where(PrivilegeGrant.id == grant_id, PrivilegeGrant.tenant_id == tenant_id))
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Elevation request not found")
    return row


async def _emails(db: Any, tenant_id: uuid.UUID) -> dict[uuid.UUID, str]:
    rows = await db.execute(select(User.id, User.email).where(User.tenant_id == tenant_id))
    return dict(rows.all())
