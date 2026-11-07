"""Tenant and user management endpoints."""

import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr
from sqlalchemy import select, text, update

from app.api.v1.deps import AuthUser, DBSession, require_permission
from app.api.v1.limits import refuse_if_over_limit
from app.core import role_grants
from app.core.permission_cache import bump_version, tenant_uses_rbac
from app.core.role_grants import RoleGrantDenied, authorize_role_change, authorize_role_grant
from app.core.security import get_password_hash
from app.models.tenant import Tenant, User
from app.services.audit import emit_audit
from app.services.tenant_deletion import delete_tenant

router = APIRouter(prefix="/tenants", tags=["tenants"])


def _refuse(exc: RoleGrantDenied) -> HTTPException:
    """Map a refused grant onto a status code.

    422 when the role is not in the vocabulary at all (the request is
    malformed), 403 when it exists and this caller may not confer it.
    """
    code = status.HTTP_422_UNPROCESSABLE_ENTITY if exc.unknown else status.HTTP_403_FORBIDDEN
    return HTTPException(status_code=code, detail=exc.reason)


class TenantHeaderResponse(BaseModel):
    """Minimal tenant identity payload — safe for *any* authenticated user.

    Used by the SOC console TopBar to render the tenant switcher and role
    badge (Workstream 5). Intentionally excludes `plan`, `settings`, and
    `limits` so it does not leak privileged config to viewer/analyst roles.
    """

    id: uuid.UUID
    name: str
    mssp_role: str | None
    parent_tenant_id: uuid.UUID | None

    model_config = {"from_attributes": True}


class TenantResponse(BaseModel):
    id: uuid.UUID
    name: str
    slug: str
    plan: str
    is_active: bool
    settings: dict
    limits: dict
    mssp_role: str | None = None
    parent_tenant_id: uuid.UUID | None = None
    created_at: datetime

    model_config = {"from_attributes": True}


class UserResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    email: str
    username: str
    role: str
    is_active: bool
    last_login: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


class CreateUserRequest(BaseModel):
    email: EmailStr
    username: str
    password: str
    #: Refused unless the caller already holds everything it confers, and
    #: refused outright for the wildcard roles. See ``app.core.role_grants``.
    #: Not a Literal: the enforced vocabulary lives in ``ROLE_PERMISSIONS``,
    #: and a second copy in the schema would be a second thing to keep true.
    role: str = "soc_analyst"


class UpdateUserRequest(BaseModel):
    username: str | None = None
    role: str | None = None
    is_active: bool | None = None
    reason: str | None = None  # required-by-convention context for role changes, audited


class UpdateTenantSettingsRequest(BaseModel):
    settings: dict = {}


@router.get("/me/identity", response_model=TenantHeaderResponse)
async def get_my_tenant_identity(
    current_user: AuthUser,
    db: DBSession,
) -> TenantHeaderResponse:
    """Get minimal tenant identity for the current user.

    Returns only `id`, `name`, `mssp_role`, and `parent_tenant_id`. This is
    safe for **any** authenticated user (analyst, viewer, responder, etc.)
    because it does not expose plan, settings, or limits. Used by the SOC
    console TopBar to render the tenant switcher pill and role badge.
    """
    result = await db.execute(select(Tenant).where(Tenant.id == current_user.tenant_id))
    tenant = result.scalar_one_or_none()
    if tenant is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found")
    return TenantHeaderResponse.model_validate(tenant)


@router.get("/me", response_model=TenantResponse)
async def get_my_tenant(
    current_user: Annotated[AuthUser, Depends(require_permission("settings:read"))],
    db: DBSession,
) -> TenantResponse:
    """Get the current user's tenant details (full config — requires settings:read)."""
    result = await db.execute(select(Tenant).where(Tenant.id == current_user.tenant_id))
    tenant = result.scalar_one_or_none()
    if tenant is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found")
    return TenantResponse.model_validate(tenant)


@router.patch("/me/settings", response_model=TenantResponse)
async def update_tenant_settings(
    request: UpdateTenantSettingsRequest,
    current_user: Annotated[AuthUser, Depends(require_permission("settings:write"))],
    db: DBSession,
) -> TenantResponse:
    """Update tenant settings."""
    await db.execute(
        update(Tenant)
        .where(Tenant.id == current_user.tenant_id)
        .values(
            settings=request.settings,
            updated_at=datetime.now(UTC),
        )
    )
    await db.commit()

    result = await db.execute(select(Tenant).where(Tenant.id == current_user.tenant_id))
    return TenantResponse.model_validate(result.scalar_one())


class TenantDeletionRequest(BaseModel):
    """Offboarding request.

    ``confirm_tenant_id`` must equal the tenant being erased. Typing the id is
    the only thing standing between "preview the erase" and "erase", and this
    endpoint has no undo.
    """

    dry_run: bool = True
    confirm_tenant_id: uuid.UUID | None = None


@router.post("/me/delete", response_model=dict)
async def delete_my_tenant(
    request: TenantDeletionRequest,
    current_user: Annotated[AuthUser, Depends(require_permission("settings:write"))],
    db: DBSession,
) -> dict:
    """Erase this tenant from Postgres, ClickHouse, Neo4j, Qdrant and Redis.

    Defaults to a dry run, which counts what would be removed per store
    without deleting. A live run requires ``confirm_tenant_id`` to match, and
    reports per-store results: if any store fails, the Postgres transaction is
    rolled back so the tenant record still names whatever data survived
    elsewhere, and ``complete`` is false.
    """
    tenant_id = current_user.tenant_id

    if not request.dry_run and request.confirm_tenant_id != tenant_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=("confirm_tenant_id must match the tenant being deleted. This operation is irreversible; run with dry_run=true first."),
        )

    report = await delete_tenant(db, tenant_id, dry_run=request.dry_run)

    if not request.dry_run and not report.complete:
        # 207: Postgres rolled back, but a satellite store may have deleted
        # before another failed. Reporting 200 would tell an operator the
        # erase succeeded when it partially did.
        raise HTTPException(
            status_code=status.HTTP_207_MULTI_STATUS,
            detail=report.as_dict(),
        )

    return report.as_dict()


@router.get("/me/users", response_model=list[UserResponse])
async def list_users(
    current_user: Annotated[AuthUser, Depends(require_permission("users:read"))],
    db: DBSession,
) -> list[UserResponse]:
    """List all users in the current tenant."""
    result = await db.execute(select(User).where(User.tenant_id == current_user.tenant_id).order_by(User.created_at))
    users = result.scalars().all()
    return [UserResponse.model_validate(u) for u in users]


@router.post("/me/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    request: CreateUserRequest,
    current_user: Annotated[AuthUser, Depends(require_permission("users:write"))],
    db: DBSession,
) -> UserResponse:
    """Create a new user in the current tenant.

    The role must be one the caller could hold itself. `platform_admin` and
    `admin` cannot be assigned through the API at all.
    """
    # Authorized before anything is read or written, so a refused request
    # touches no row and reveals nothing about which addresses exist.
    try:
        granted_role = authorize_role_grant(
            granter_role=current_user.role,
            granter_scopes=current_user.scopes,
            granter_permissions=current_user.resolved_permissions,
            requested_role=request.role,
        )
    except RoleGrantDenied as exc:
        raise _refuse(exc) from exc

    # After the role grant is authorized and before any row is read. An
    # unauthorized caller is refused for being unauthorized, not told how
    # full somebody else's tenant is.
    await refuse_if_over_limit(db, current_user.tenant_id, "seats")

    # Check email uniqueness
    existing = await db.execute(select(User).where(User.email == request.email))
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User with this email already exists",
        )

    user = User(
        tenant_id=current_user.tenant_id,
        email=request.email,
        username=request.username,
        hashed_password=get_password_hash(request.password),
        role=granted_role,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return UserResponse.model_validate(user)


@router.patch("/me/users/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: uuid.UUID,
    request: UpdateUserRequest,
    current_user: Annotated[AuthUser, Depends(require_permission("users:write"))],
    db: DBSession,
) -> UserResponse:
    """Update a user.

    A role change is bounded the same way creation is, and a principal
    already holding `platform_admin` or `admin` cannot be re-roled here.
    """
    # Promotion is the same grant as creation and goes through the same check.
    # An allow-list on `create_user` alone would have left `role: "admin"`
    # here as a one-request escalation. Rationale kept out of the docstring
    # because FastAPI publishes that verbatim in docs/openapi.yaml.
    result = await db.execute(select(User).where(User.id == user_id, User.tenant_id == current_user.tenant_id))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # Captured before anything is written. `db.execute(update(...))` below
    # synchronises the loaded object, so reading `user.role` afterwards
    # returns the *new* value — which is how the audit trail came to record
    # `{"from": "viewer", "to": "viewer"}` and tell an auditor nothing about
    # what was removed.
    previous_role = str(user.role)

    updates: dict = {}
    for field in ["username", "role", "is_active"]:
        val = getattr(request, field, None)
        if val is not None:
            updates[field] = val

    if "role" in updates:
        # Authorized first, before the tenant is counted. A caller who may not
        # make this change is refused for that reason and is not told how many
        # administrators somebody else's tenant has — the same ordering
        # `create_user` uses above, for the same reason.
        try:
            updates["role"] = authorize_role_change(
                granter_role=current_user.role,
                granter_scopes=current_user.scopes,
                granter_permissions=current_user.resolved_permissions,
                current_role=previous_role,
                requested_role=updates["role"],
            )
        except RoleGrantDenied as exc:
            # Raised before the UPDATE, so a refused promotion leaves the
            # username and is_active fields in the same request unwritten too.
            raise _refuse(exc) from exc

    if "role" in updates or "is_active" in updates:
        # Last-administrator lockout guard, evaluated against the live table
        # before anything is written — this endpoint is one of the few doors
        # that can empty a tenant of administrators.
        #
        # It counts the roles that can *restore* access rather than the
        # wildcard roles. Those are refused to every API caller by
        # `never_grantable`, so a tenant created through the product has none
        # and this guard could never fire for it: one `tenant_admin` could
        # demote every peer and then itself, leaving nobody able to promote
        # anyone back and no route to recovery short of database credentials
        # (GHSA-hrc5-w9r3-2g8r).
        administrative = sorted(role_grants.administrative_roles())
        losing_authority = "role" in updates and updates["role"] not in administrative
        deactivating = updates.get("is_active") is False
        if previous_role in administrative and (losing_authority or deactivating):
            # Every bind is cast explicitly. The previous spelling compared a
            # bare `:t` against a `uuid` column, which asyncpg answers with
            # `operator does not exist: uuid = character varying` — so this
            # guard raised a 500 on every deployment the moment it fired,
            # instead of the 409 it exists to return. It was never noticed
            # because the only branch that could reach it needed a wildcard
            # role, and those are refused to API callers anyway.
            remaining = (
                await db.execute(
                    text(
                        "SELECT count(*) FROM users "
                        "WHERE tenant_id = CAST(:t AS uuid) AND is_active = TRUE "
                        "AND role = ANY(CAST(:admins AS text[])) AND id <> CAST(:keep AS uuid)"
                    ).bindparams(
                        t=str(current_user.tenant_id),
                        admins=administrative,
                        keep=str(user_id),
                    )
                )
            ).scalar()
            if not remaining:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="this is the last active administrator in the tenant; promote another admin before removing this one",
                )

    if updates:
        updates["updated_at"] = datetime.now(UTC)
        await db.execute(update(User).where(User.id == user_id).values(**updates))
        # Role changes are auditable events with their reason; every admin
        # mutation is logged, and nothing that reaches this line does so
        # silently.
        if "role" in updates:
            await emit_audit(
                db=db,
                tenant_id=current_user.tenant_id,
                actor_id=current_user.user_id,
                actor_email=current_user.email,
                api_key_prefix=getattr(current_user, "api_key_prefix", None),
                action="users:role_changed",
                resource="user",
                resource_id=str(user_id),
                changes={
                    "from": previous_role,
                    "to": updates["role"],
                    "reason": (request.reason or "")[:500],
                    # Whether this changed any access, which is not the same
                    # question as whether it changed the row. A tenant running
                    # database-backed RBAC resolves permissions from
                    # `user_roles`, so `users.role` is not what any check
                    # reads and the demotion withdraws nothing. Recording the
                    # row change alone let an audit log assert a withdrawal
                    # that never happened.
                    "effective_permissions_follow_role": not await tenant_uses_rbac(db, current_user.tenant_id),
                },
            )
        await db.commit()
        # After the commit, so a rolled-back change does not invalidate a set
        # that is still correct. Without it the old permissions stayed cached
        # on every replica until the fallback TTL lapsed, and for a
        # revocation that is the wrong direction.
        if "role" in updates or "is_active" in updates:
            await bump_version(str(current_user.tenant_id))
        await db.refresh(user)

    return UserResponse.model_validate(user)
