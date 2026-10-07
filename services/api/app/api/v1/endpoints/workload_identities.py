"""Per-service credentials for internal callers.

Depth plan item 8.2. ``workload_identities`` was created by migration 087
and read by nothing, leaving ``AISOC_SERVICE_TOKEN`` — one string every
internal caller presents — as the only internal credential.

Deployment-wide, and therefore not tenant-scoped
-------------------------------------------------
A service authenticates *before* any tenant is known; the agents container
triages alerts for every tenant on the deployment and names the one it is
acting for on a header, per request. So these rows carry no ``tenant_id``,
and the table has no row-level security policy — the migration says so and
means it.

That makes minting one a platform act rather than a tenant act, which is
why the permissions below are held only by the wildcard roles
(``admin`` and ``platform_admin``). That is deliberate and is the one case
where "no non-wildcard role holds this" is the right answer rather than
the bug it usually is: a tenant administrator minting a credential that
every tenant's data flows through would be precisely the cross-tenant
authority this feature exists to remove.

Scopes are still bounded by the minter
---------------------------------------
``authorize_permission_grant`` refuses a scope the caller does not hold,
the same function that guards role assignment and API-key scopes. A
wildcard principal may mint a wildcard workload — it confers nothing they
do not already have — and anybody else is held to what they hold.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select

from app.api.v1.deps import AuthUser, DBSession, require_permission
from app.api.v1.endpoints.api_keys import VALID_SCOPES
from app.core.role_grants import RoleGrantDenied, authorize_permission_grant
from app.models.enterprise_iam import WorkloadIdentity
from app.services import workload_identity as service
from app.services.audit import emit_audit

router = APIRouter(prefix="/workload-identities", tags=["workload-identities"])

#: Service names a credential may be minted for. A closed vocabulary
#: because the point of the row is attribution: a free-text service name
#: lets two deployments disagree about what "agents" is called, and an
#: audit trail that cannot be grouped is not much better than one that
#: says "a service".
KNOWN_SERVICES = (
    "agents",
    "actions",
    "connectors",
    "fusion",
    "ingest",
    "realtime",
    "threatintel",
    "ueba",
    "mcp",
)


class WorkloadIn(BaseModel):
    service: str
    description: str | None = Field(None, max_length=500)
    scopes: list[str] = Field(default_factory=list, max_length=40)
    expires_in_days: int | None = Field(None, ge=1, le=3650)

    @field_validator("service")
    @classmethod
    def _known_service(cls, value: str) -> str:
        if value not in KNOWN_SERVICES:
            raise ValueError(f"unknown service {value!r}; known: {', '.join(KNOWN_SERVICES)}")
        return value


class WorkloadCreated(BaseModel):
    """The one response that carries secret material, and only on create."""

    identity: dict[str, Any]
    secret: str
    warning: str = "Store this now. It is shown once and is not recoverable."


def _validate_scopes(scopes: list[str], current_user: AuthUser) -> None:
    """Two refusals: unknown scopes, and scopes the minter does not hold.

    The second is the one that matters. A credential is a bearer
    credential, so its scopes are authority conferred on whoever holds it —
    and ``workload_identities:write`` must not be a door that mints
    authority its holder lacks.
    """
    invalid = sorted(set(scopes) - VALID_SCOPES)
    if invalid:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid scope(s): {', '.join(invalid)}. Valid scopes: {sorted(VALID_SCOPES)}",
        )
    try:
        authorize_permission_grant(
            granter_role=current_user.role,
            granter_scopes=current_user.scopes,
            granter_permissions=current_user.resolved_permissions,
            requested=scopes,
            subject="workload scope(s)",
        )
    except RoleGrantDenied as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=exc.reason) from exc


@router.get("", response_model=list[dict])
async def list_workload_identities(
    db: DBSession,
    _user: Annotated[AuthUser, Depends(require_permission("workload_identities:read"))],
) -> list[dict[str, Any]]:
    """Every workload credential, with no secret material.

    ``last_used_at`` is the column that matters operationally: it is what
    tells an operator a credential they are about to revoke is dead.
    """
    rows = (await db.execute(select(WorkloadIdentity).order_by(WorkloadIdentity.service, WorkloadIdentity.created_at))).scalars()
    return [service.describe(row) for row in rows]


@router.post("", response_model=WorkloadCreated, status_code=status.HTTP_201_CREATED)
async def create_workload_identity(
    body: WorkloadIn,
    request: Request,
    db: DBSession,
    current_user: Annotated[AuthUser, Depends(require_permission("workload_identities:write"))],
) -> WorkloadCreated:
    """Mint a credential for one internal service."""
    _validate_scopes(body.scopes, current_user)

    secret, prefix, digest = service.mint_workload_secret()
    row = WorkloadIdentity(
        service=body.service,
        description=body.description,
        scopes=sorted(set(body.scopes)),
        secret_hash=digest,
        secret_prefix=prefix,
        expires_at=(datetime.now(UTC) + timedelta(days=body.expires_in_days)) if body.expires_in_days else None,
    )
    db.add(row)
    await db.flush()

    await emit_audit(
        db=db,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        actor_email=current_user.email,
        action="workload_identity:create",
        resource="workload_identity",
        resource_id=str(row.id),
        # The prefix, never the secret. `emit_audit` redacts on key names
        # and would not know this one.
        changes={"service": body.service, "scopes": row.scopes, "secret_prefix": prefix},
        request=request,
    )
    await db.commit()
    return WorkloadCreated(identity=service.describe(row), secret=secret)


@router.post("/{identity_id}/rotate", response_model=WorkloadCreated)
async def rotate_workload_identity(
    identity_id: uuid.UUID,
    request: Request,
    db: DBSession,
    current_user: Annotated[AuthUser, Depends(require_permission("workload_identities:write"))],
) -> WorkloadCreated:
    """Issue a new secret and keep the old one alive for a grace window.

    Rotation in place is the whole reason the ``previous_*`` columns exist.
    The only path before was create, update every caller, delete — which is
    downtime, so most deployments never rotated at all, which is how one
    leaked log line became permanent internal access.
    """
    row = await _load(db, identity_id)
    if row.revoked_at is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="This credential is revoked; mint a new one")

    secret = await service.rotate(db, row)
    await emit_audit(
        db=db,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        actor_email=current_user.email,
        action="workload_identity:rotate",
        resource="workload_identity",
        resource_id=str(row.id),
        changes={"service": row.service, "secret_prefix": row.secret_prefix},
        request=request,
    )
    await db.commit()
    return WorkloadCreated(
        identity=service.describe(row),
        secret=secret,
        warning=(
            "Store this now. The previous secret keeps working until "
            f"{row.previous_expires_at.isoformat() if row.previous_expires_at else 'the grace window ends'}."
        ),
    )


@router.delete("/{identity_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_workload_identity(
    identity_id: uuid.UUID,
    request: Request,
    db: DBSession,
    current_user: Annotated[AuthUser, Depends(require_permission("workload_identities:write"))],
) -> None:
    """Revoke immediately, including the superseded secret.

    Clearing ``previous_hash`` is the half that is easy to miss: a
    revocation that left a rotation's grace window intact would leave the
    credential working for up to a day after an operator believed they had
    killed it.
    """
    row = await _load(db, identity_id)
    if row.revoked_at is None:
        row.revoked_at = datetime.now(UTC)
        row.previous_hash = None
        row.previous_expires_at = None
        await emit_audit(
            db=db,
            tenant_id=current_user.tenant_id,
            actor_id=current_user.user_id,
            actor_email=current_user.email,
            action="workload_identity:revoke",
            resource="workload_identity",
            resource_id=str(row.id),
            changes={"service": row.service, "secret_prefix": row.secret_prefix},
            request=request,
        )
        await db.commit()


async def _load(db: Any, identity_id: uuid.UUID) -> WorkloadIdentity:
    row = (await db.execute(select(WorkloadIdentity).where(WorkloadIdentity.id == identity_id))).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Workload identity not found")
    return row
