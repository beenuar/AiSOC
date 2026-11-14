"""RBAC endpoints — role & permission management.

Roles are tenant-scoped.  Permissions are platform-wide and read-only.

Requires:
  - ``roles:read``  to list / inspect roles and permissions
  - ``roles:write`` to create / update / delete roles and assign users
  - ``users:write`` to assign / revoke roles from users
"""

import re
import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Body, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import delete, func, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.v1.deps import AuthUser, require_permission
from app.core import role_grants
from app.core.permission_cache import bump_version
from app.core.rbac_catalog import SSO_DEFAULT_ROLE, seed_tenant_catalog
from app.core.role_grants import RoleGrantDenied, authorize_permission_grant
from app.db.rls import TenantDBSession
from app.models.rbac import Permission, Role, RolePermission, UserRole
from app.models.tenant import User
from app.services.audit import emit_audit

router = APIRouter(prefix="/rbac", tags=["rbac"])


def _authorize_permission_grant(permissions: list[Permission], current_user: AuthUser, *, subject: str) -> None:
    """Refuse a database-backed role that confers more than its author holds.

    These rows are a second authorization path, not documentation:
    ``CurrentUser.has_permission_db`` resolves ``user_roles`` →
    ``role_permissions`` → ``permissions`` and prefers it over the static
    ``ROLE_PERMISSIONS`` map whenever the principal has any row at all. So a
    role assembled here and attached below is exactly as load-bearing as
    ``users.role``, and the same property has to hold for it.
    """
    try:
        authorize_permission_grant(
            granter_role=current_user.role,
            granter_scopes=current_user.scopes,
            granter_permissions=current_user.resolved_permissions,
            requested=[p.name for p in permissions],
            subject=subject,
        )
    except RoleGrantDenied as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=exc.reason) from exc


# ──────────────────────────────────────────────
# Pydantic schemas
# ──────────────────────────────────────────────


class PermissionOut(BaseModel):
    id: uuid.UUID
    name: str
    description: str | None
    category: str | None

    model_config = {"from_attributes": True}


#: Machine-safe slug, immutable after create. The name reaches users.role,
#: JWT static-map resolution, audit resource strings and URL segments; the
#: human-facing text lives in `label`.
ROLE_NAME_RE = re.compile(r"^[a-z][a-z0-9]*(-[a-z0-9]+)*$")

#: Names the platform owns. Creating one shadows a seeded role or the
#: static-map path; renaming into one is blocked by immutability anyway.
RESERVED_ROLE_NAMES = frozenset({"admin", "platform_admin", "viewer", "infosec", "user", "operator", "api_client"})


class RoleIn(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    label: str | None = Field(default=None, max_length=200)
    description: str | None = None
    permission_ids: list[uuid.UUID] = []
    permission_names: list[str] = []

    @field_validator("name")
    @classmethod
    def _validate_slug(cls, v: str) -> str:
        v = v.strip().lower()
        if not ROLE_NAME_RE.match(v):
            raise ValueError("role name must be a lowercase slug: letters/numbers, single hyphens, starting with a letter")
        if v in RESERVED_ROLE_NAMES:
            raise ValueError(f"{v!r} is a reserved platform role name")
        return v


class RoleUpdate(BaseModel):
    """The machine `name` is immutable after create: it is mirrored into
    users.role, resolved against the JWT static map, and written into audit
    resource strings; renaming a live role would strand all three. The field
    stays on the wire (SDK clients generated against earlier releases send
    it) and is validated as a no-op: omit it, or send the role's current
    name — an actual rename is a 400 that says why. Edit `label` and
    `description` for the human-facing text."""

    name: str | None = Field(default=None, max_length=100)
    label: str | None = Field(default=None, max_length=200)
    description: str | None = None
    permission_ids: list[uuid.UUID] | None = None
    permission_names: list[str] | None = None


class PermissionNamesIn(BaseModel):
    """Body for `PUT /roles/{id}/permissions`.

    The console sends `{"permissions": ["alerts:read", ...]}` and the
    route additionally accepts the bare list shape (see the endpoint);
    either way every key is validated against the platform vocabulary
    before anything is deleted, so an unknown key is a 400 that names the
    valid set instead of a silent partial update.
    """

    permissions: list[str] = Field(min_length=0)

    @field_validator("permissions")
    @classmethod
    def _dedupe(cls, v: list[str]) -> list[str]:
        seen: set[str] = set()
        out: list[str] = []
        for name in v:
            if name not in seen:
                seen.add(name)
                out.append(name)
        return out


class PermissionNameIn(BaseModel):
    permission: str = Field(min_length=1, max_length=200)


class RoleOut(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    name: str
    label: str | None = None
    description: str | None
    is_system: bool
    permissions: list[PermissionOut] = []
    user_count: int = 0
    is_sso_default: bool = False

    model_config = {"from_attributes": True}


class UserRoleAssignment(BaseModel):
    user_id: uuid.UUID
    role_id: uuid.UUID
    reason: str | None = Field(default=None, max_length=500)


class PrimaryRoleAssignment(BaseModel):
    """Body for `PUT /rbac/users/{id}/role` — replaces the primary role.

    `role_name` names a seeded catalog role (`viewer` | `infosec` | `admin`
    or a tenant custom role); the server resolves it against this tenant's
    catalog and refuses anything it does not recognize with a 400 naming the
    valid set — a 500 would leak the schema, and a silent 404 would make a
    typo look like an outage.
    """

    role_name: str = Field(min_length=1, max_length=100)
    reason: str | None = Field(default=None, max_length=500)


class UserRoleOut(BaseModel):
    user_id: uuid.UUID
    role_id: uuid.UUID
    role_name: str

    model_config = {"from_attributes": True}


# ──────────────────────────────────────────────
# Permissions (platform-wide, read-only)
# ──────────────────────────────────────────────


@router.get("/permissions", response_model=list[PermissionOut])
async def list_permissions(
    current_user: Annotated[AuthUser, Depends(require_permission("roles:read"))],
    db: TenantDBSession,
    category: str | None = None,
) -> list[PermissionOut]:
    """List all available permissions."""
    q = select(Permission).order_by(Permission.category, Permission.name)
    if category:
        q = q.where(Permission.category == category)
    result = await db.execute(q)
    return [PermissionOut.model_validate(p) for p in result.scalars().all()]


# ──────────────────────────────────────────────
# Roles (tenant-scoped)
# ──────────────────────────────────────────────


@router.get("/roles", response_model=list[RoleOut])
async def list_roles(
    current_user: Annotated[AuthUser, Depends(require_permission("roles:read"))],
    db: TenantDBSession,
) -> list[RoleOut]:
    """List all roles for the current tenant, with permissions and headcount.

    `user_count` counts this tenant's users holding each role — the Roles
    screen shows it so an operator can see who would move when a role's
    grants change, not just what the grants are.
    """
    result = await db.execute(
        select(Role)
        .where(Role.tenant_id == current_user.tenant_id)
        .options(selectinload(Role.role_permissions).selectinload(RolePermission.permission))
        .order_by(Role.name)
    )
    roles = result.scalars().all()

    counts = dict(
        (
            await db.execute(
                select(UserRole.role_id, func.count())
                .join(User, User.id == UserRole.user_id)
                .join(Role, Role.id == UserRole.role_id)
                .where(Role.tenant_id == current_user.tenant_id)
                .group_by(UserRole.role_id)
            )
        ).all()
    )

    out: list[RoleOut] = []
    for role in roles:
        perms = [PermissionOut.model_validate(rp.permission) for rp in role.role_permissions]
        out.append(
            RoleOut(
                id=role.id,
                tenant_id=role.tenant_id,
                name=role.name,
                label=role.label,
                description=role.description,
                is_system=role.is_system,
                permissions=perms,
                user_count=int(counts.get(role.id, 0)),
                is_sso_default=role.name == SSO_DEFAULT_ROLE,
            )
        )
    return out


@router.post("/roles/seed", response_model=dict)
async def seed_roles(
    current_user: Annotated[AuthUser, Depends(require_permission("roles:write"))],
    db: TenantDBSession,
) -> dict:
    """Seed this tenant's catalog from `app.core.rbac_catalog`.

    Idempotent — safe to call from the Roles screen's empty state ("Seed
    roles") as often as you like. Catalog rows and the membership backfill
    land in one transaction, so a half-seeded tenant (roles with no
    members, every member resolving to zero permissions) is not a state this
    endpoint can leave behind.
    """
    counts = await seed_tenant_catalog(db, current_user.tenant_id)
    await db.commit()
    await bump_version(str(current_user.tenant_id))
    await emit_audit(
        db=db,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        actor_email=current_user.email,
        api_key_prefix=getattr(current_user, "api_key_prefix", None),
        action="rbac.catalog_seeded",
        resource="tenant",
        resource_id=str(current_user.tenant_id),
        changes={"counts": counts},
    )
    await db.commit()
    return {"seeded": True, **counts}


@router.post("/roles", response_model=RoleOut, status_code=status.HTTP_201_CREATED)
async def create_role(
    body: RoleIn,
    request: Request,
    current_user: Annotated[AuthUser, Depends(require_permission("roles:write"))],
    db: TenantDBSession,
) -> RoleOut:
    """Create a custom role for the current tenant.

    `permission_names` (validated against the platform vocabulary, unknown
    keys → 400 naming them) is the console-facing shape; `permission_ids`
    stays for API clients. Both may be sent; they merge.
    """
    existing = await db.execute(select(Role).where(Role.tenant_id == current_user.tenant_id, Role.name == body.name))
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Role '{body.name}' already exists")

    named = await _resolve_permission_names(db, body.permission_names)
    by_id = await _resolve_permissions(db, body.permission_ids)
    seen_ids = {p.id for p in by_id}
    perms_to_attach = by_id + [p for p in named if p.id not in seen_ids]
    _authorize_permission_grant(perms_to_attach, current_user, subject="permission(s)")

    role = Role(
        tenant_id=current_user.tenant_id,
        name=body.name,
        label=(body.label or body.name),
        description=body.description,
        is_system=False,
    )
    db.add(role)
    await db.flush()

    for perm in perms_to_attach:
        db.add(RolePermission(role_id=role.id, permission_id=perm.id))

    await emit_audit(
        db=db,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        actor_email=current_user.email,
        api_key_prefix=getattr(current_user, "api_key_prefix", None),
        action="rbac.role_created",
        resource="role",
        resource_id=str(role.id),
        changes={"label": role.label, "permissions_after": sorted(p.name for p in perms_to_attach)},
        request=request,
    )
    await db.commit()
    await bump_version(str(current_user.tenant_id))
    await db.refresh(role)

    return RoleOut(
        id=role.id,
        tenant_id=role.tenant_id,
        name=role.name,
        label=role.label,
        description=role.description,
        is_system=role.is_system,
        permissions=[PermissionOut.model_validate(p) for p in perms_to_attach],
    )


@router.get("/roles/{role_id}", response_model=RoleOut)
async def get_role(
    role_id: uuid.UUID,
    current_user: Annotated[AuthUser, Depends(require_permission("roles:read"))],
    db: TenantDBSession,
) -> RoleOut:
    role = await _get_role_or_404(db, role_id, current_user.tenant_id)
    perms = await _load_role_permissions(db, role.id)
    count = await db.scalar(select(func.count()).select_from(UserRole).where(UserRole.role_id == role.id))
    return RoleOut(
        id=role.id,
        tenant_id=role.tenant_id,
        name=role.name,
        label=role.label,
        description=role.description,
        is_system=role.is_system,
        permissions=perms,
        user_count=int(count or 0),
        is_sso_default=role.name == SSO_DEFAULT_ROLE,
    )


@router.patch("/roles/{role_id}", response_model=RoleOut)
async def update_role(
    role_id: uuid.UUID,
    body: RoleUpdate,
    request: Request,
    current_user: Annotated[AuthUser, Depends(require_permission("roles:write"))],
    db: TenantDBSession,
) -> RoleOut:
    """Edit label/description (and, optionally, replace the permission set).

    System roles are refused with an explanatory 403 body that names the
    role: the lock is a server rule, not a hidden button. `name` cannot be
    edited — see RoleUpdate."""
    role = await _get_role_or_404(db, role_id, current_user.tenant_id)

    if body.name is not None and body.name != role.name:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Role name is immutable after create (current name '{role.name}'): "
                "it is mirrored into users.role, the JWT role map, and audit "
                "resource strings. Edit label/description, or create a new role."
            ),
        )

    if role.is_system:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Role '{role.name}' is a system role: its name and permission set are protected. "
                "Duplicate it to create an editable custom role."
            ),
        )

    perms: list[Permission] | None = None
    if body.permission_ids is not None or body.permission_names is not None:
        named = await _resolve_permission_names(db, body.permission_names or [])
        by_id = await _resolve_permissions(db, body.permission_ids or [])
        seen_ids = {p.id for p in by_id}
        perms = by_id + [p for p in named if p.id not in seen_ids]
        _authorize_permission_grant(perms, current_user, subject="permission(s)")

    before = sorted(p.name for p in await _load_role_models(db, role.id))
    if body.label is not None:
        role.label = body.label
    if body.description is not None:
        role.description = body.description

    if perms is not None:
        # Replace permissions — same transaction as the audit row below;
        # a crash between DELETE and INSERT rolls both back, never partial.
        await db.execute(delete(RolePermission).where(RolePermission.role_id == role.id))
        for perm in perms:
            db.add(RolePermission(role_id=role.id, permission_id=perm.id))

    after = sorted(p.name for p in (perms if perms is not None else await _load_role_models(db, role.id)))
    await emit_audit(
        db=db,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        actor_email=current_user.email,
        api_key_prefix=getattr(current_user, "api_key_prefix", None),
        action="rbac.role_updated",
        resource="role",
        resource_id=str(role.id),
        changes={
            "label": role.label,
            "permissions_before": before,
            "permissions_after": after,
            "removed": sorted(set(before) - set(after)),
            "added": sorted(set(after) - set(before)),
            "affected_users": await _permission_affected_users(db, role.id),
        },
        request=request,
    )
    await db.commit()
    await bump_version(str(current_user.tenant_id))
    await db.refresh(role)
    perms_out = await _load_role_permissions(db, role.id)
    return RoleOut(
        id=role.id,
        tenant_id=role.tenant_id,
        name=role.name,
        label=role.label,
        description=role.description,
        is_system=role.is_system,
        permissions=perms_out,
        user_count=await _permission_affected_users(db, role.id),
        is_sso_default=role.name == SSO_DEFAULT_ROLE,
    )


@router.put("/roles/{role_id}/permissions", response_model=RoleOut)
async def replace_role_permissions(
    role_id: uuid.UUID,
    request: Request,
    current_user: Annotated[AuthUser, Depends(require_permission("roles:write"))],
    db: TenantDBSession,
    body: Annotated[PermissionNamesIn | None, Body()] = None,
    raw: Annotated[Any, Body(embed=False)] = None,
) -> RoleOut:
    """Replace the role's full permission set (atomic, audited, before/after).

    Accepts `{"permissions": ["alerts:read", ...]}` or a bare list
    `["alerts:read", ...]` — both shapes validate every key against the
    vocabulary first, so an unknown key is a 400 that names it, never a
    silently dropped grant.
    """
    names: list[str] = []
    if body is not None:
        names = body.permissions
    elif isinstance(raw, list):
        names = [str(x) for x in raw]
    elif isinstance(raw, dict) and isinstance(raw.get("permissions"), list):
        names = [str(x) for x in raw["permissions"]]

    role = await _get_role_or_404(db, role_id, current_user.tenant_id)
    if role.is_system:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Role '{role.name}' is a system role: its permission set is protected and cannot be edited.",
        )

    perms = await _resolve_permission_names(db, names)
    _authorize_permission_grant(perms, current_user, subject="permission(s)")

    before = sorted(p.name for p in await _load_role_models(db, role.id))
    await db.execute(delete(RolePermission).where(RolePermission.role_id == role.id))
    for perm in perms:
        db.add(RolePermission(role_id=role.id, permission_id=perm.id))

    after = sorted(p.name for p in perms)
    await emit_audit(
        db=db,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        actor_email=current_user.email,
        api_key_prefix=getattr(current_user, "api_key_prefix", None),
        action="rbac.role_permissions_replaced",
        resource="role",
        resource_id=str(role.id),
        changes={
            "permissions_before": before,
            "permissions_after": after,
            "removed": sorted(set(before) - set(after)),
            "added": sorted(set(after) - set(before)),
            "affected_users": await _permission_affected_users(db, role.id),
        },
        request=request,
    )
    await db.commit()
    await bump_version(str(current_user.tenant_id))
    return RoleOut(
        id=role.id,
        tenant_id=role.tenant_id,
        name=role.name,
        label=role.label,
        description=role.description,
        is_system=role.is_system,
        permissions=[PermissionOut.model_validate(p) for p in perms],
        user_count=await _permission_affected_users(db, role.id),
        is_sso_default=role.name == SSO_DEFAULT_ROLE,
    )


@router.post("/roles/{role_id}/permissions", response_model=RoleOut, status_code=status.HTTP_201_CREATED)
async def add_role_permission(
    role_id: uuid.UUID,
    body: PermissionNameIn,
    request: Request,
    current_user: Annotated[AuthUser, Depends(require_permission("roles:write"))],
    db: TenantDBSession,
) -> RoleOut:
    role = await _get_role_or_404(db, role_id, current_user.tenant_id)
    if role.is_system:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Role '{role.name}' is a system role: its permission set is protected and cannot be edited.",
        )
    [perm] = await _resolve_permission_names(db, [body.permission])
    _authorize_permission_grant([perm], current_user, subject=f"permission {perm.name!r}")

    existing = await db.execute(select(RolePermission).where(RolePermission.role_id == role.id, RolePermission.permission_id == perm.id))
    if existing.scalar_one_or_none() is None:
        db.add(RolePermission(role_id=role.id, permission_id=perm.id))
        await emit_audit(
            db=db,
            tenant_id=current_user.tenant_id,
            actor_id=current_user.user_id,
            actor_email=current_user.email,
            api_key_prefix=getattr(current_user, "api_key_prefix", None),
            action="rbac.role_permission_added",
            resource="role",
            resource_id=str(role.id),
            changes={"added": perm.name, "affected_users": await _permission_affected_users(db, role.id)},
            request=request,
        )
        await db.commit()
        await bump_version(str(current_user.tenant_id))
    perms_out = await _load_role_permissions(db, role.id)
    return RoleOut(
        id=role.id,
        tenant_id=role.tenant_id,
        name=role.name,
        label=role.label,
        description=role.description,
        is_system=role.is_system,
        permissions=perms_out,
        user_count=await _permission_affected_users(db, role.id),
        is_sso_default=role.name == SSO_DEFAULT_ROLE,
    )


@router.delete("/roles/{role_id}/permissions/{permission_name}", response_model=RoleOut)
async def remove_role_permission(
    role_id: uuid.UUID,
    permission_name: str,
    request: Request,
    current_user: Annotated[AuthUser, Depends(require_permission("roles:write"))],
    db: TenantDBSession,
) -> RoleOut:
    role = await _get_role_or_404(db, role_id, current_user.tenant_id)
    if role.is_system:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Role '{role.name}' is a system role: its permission set is protected and cannot be edited.",
        )
    [perm] = await _resolve_permission_names(db, [permission_name])

    existing = await db.execute(select(RolePermission).where(RolePermission.role_id == role.id, RolePermission.permission_id == perm.id))
    if existing.scalar_one_or_none() is not None:
        await db.execute(delete(RolePermission).where(RolePermission.role_id == role.id, RolePermission.permission_id == perm.id))
        await emit_audit(
            db=db,
            tenant_id=current_user.tenant_id,
            actor_id=current_user.user_id,
            actor_email=current_user.email,
            api_key_prefix=getattr(current_user, "api_key_prefix", None),
            action="rbac.role_permission_removed",
            resource="role",
            resource_id=str(role.id),
            changes={"removed": perm.name, "affected_users": await _permission_affected_users(db, role.id)},
            request=request,
        )
        await db.commit()
        await bump_version(str(current_user.tenant_id))
    perms_out = await _load_role_permissions(db, role.id)
    return RoleOut(
        id=role.id,
        tenant_id=role.tenant_id,
        name=role.name,
        label=role.label,
        description=role.description,
        is_system=role.is_system,
        permissions=perms_out,
        user_count=await _permission_affected_users(db, role.id),
        is_sso_default=role.name == SSO_DEFAULT_ROLE,
    )


@router.delete("/roles/{role_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def delete_role(
    role_id: uuid.UUID,
    request: Request,
    current_user: Annotated[AuthUser, Depends(require_permission("roles:write"))],
    db: TenantDBSession,
) -> None:
    role = await _get_role_or_404(db, role_id, current_user.tenant_id)
    if role.is_system:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Role '{role.name}' is a system role and cannot be deleted.",
        )
    # FK CASCADE would silently detach members; the product rule is: refuse,
    # with the count, until the operator reassigns them explicitly.
    users = await _permission_affected_users(db, role.id)
    if users:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Role is assigned to {users} user(s). Remove the role from those users first.",
        )
    perms_before = sorted(p.name for p in await _load_role_models(db, role.id))
    role_name = role.name
    await db.delete(role)
    await emit_audit(
        db=db,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        actor_email=current_user.email,
        api_key_prefix=getattr(current_user, "api_key_prefix", None),
        action="rbac.role_deleted",
        resource="role",
        resource_id=str(role_id),
        changes={"name": role_name, "permissions_before": perms_before},
        request=request,
    )
    await db.commit()
    await bump_version(str(current_user.tenant_id))


# ──────────────────────────────────────────────
# User ↔ Role assignments
# ──────────────────────────────────────────────


@router.get("/users/{user_id}/roles", response_model=list[UserRoleOut])
async def get_user_roles(
    user_id: uuid.UUID,
    current_user: Annotated[AuthUser, Depends(require_permission("users:read"))],
    db: TenantDBSession,
) -> list[UserRoleOut]:
    """List roles assigned to a user within the current tenant."""
    result = await db.execute(
        select(UserRole, Role.name)
        .join(Role, Role.id == UserRole.role_id)
        .where(
            UserRole.user_id == user_id,
            Role.tenant_id == current_user.tenant_id,
        )
    )
    rows = result.all()
    return [UserRoleOut(user_id=row.UserRole.user_id, role_id=row.UserRole.role_id, role_name=row.name) for row in rows]


@router.put("/users/{user_id}/role", response_model=UserRoleOut)
async def set_primary_role(
    user_id: uuid.UUID,
    body: PrimaryRoleAssignment,
    current_user: Annotated[AuthUser, Depends(require_permission("roles:write"))],
    db: TenantDBSession,
) -> UserRoleOut:
    """Replace the user's primary role — the console's `Assign role` action.

    Multi-role storage, single-role product: the assignment set becomes the
    one chosen role, and `users.role` — the string the JWT/static path
    reads — is mirrored to match, so the two authorization paths cannot
    disagree after this call. Takes effect on the target's next request:
    the permission cache version bumps, and the verifier re-reads
    `users.role` from the database. No re-login required.

    Refusals, all before any write:
      * 404 target not in tenant; 400 unknown role name (naming the valid
        set) or disabled target; 403 this caller may not confer the role's
        permissions; 409 this would empty the tenant of active admins.
    """
    target = (await db.execute(select(User).where(User.id == user_id, User.tenant_id == current_user.tenant_id))).scalar_one_or_none()
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found in tenant")
    if not target.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot assign roles to a disabled user")

    role = (
        await db.execute(select(Role).where(Role.tenant_id == current_user.tenant_id, Role.name == body.role_name))
    ).scalar_one_or_none()
    if role is None:
        valid = sorted((await db.execute(select(Role.name).where(Role.tenant_id == current_user.tenant_id))).scalars().all())
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Unknown role {body.role_name!r}. Valid roles for this tenant: "
                f"{', '.join(valid) or '(none seeded — seed the catalog first)'}"
            ),
        )

    # The granter may only confer what they hold (GHSA lineage: a scoped
    # caller minting unscoped authority).
    _authorize_permission_grant(
        await _load_role_models(db, role.id),
        current_user,
        subject=f"permission(s) carried by role {role.name!r}",
    )

    old_role = str(target.role)
    wildcard = sorted(role_grants.wildcard_roles())
    demoting_admin = old_role in wildcard and role.name not in wildcard
    if demoting_admin or (current_user.user_id == user_id and demoting_admin):
        remaining = await db.scalar(
            text("SELECT count(*) FROM users WHERE tenant_id = :t AND is_active = TRUE AND role = ANY(:wild) AND id <> :keep").bindparams(
                t=str(current_user.tenant_id), wild=wildcard, keep=str(user_id)
            )
        )
        if not remaining:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="this is the last active administrator in the tenant; promote another admin before demoting this one",
            )

    now = datetime.now(UTC)
    await db.execute(delete(UserRole).where(UserRole.user_id == user_id))
    db.add(UserRole(user_id=user_id, role_id=role.id, assigned_by=current_user.user_id))
    await db.execute(update(User).where(User.id == user_id).values(role=role.name, updated_at=now))
    await emit_audit(
        db=db,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        actor_email=current_user.email,
        api_key_prefix=getattr(current_user, "api_key_prefix", None),
        action="rbac.role_assigned",
        resource="user",
        resource_id=str(user_id),
        changes={"old_role": old_role, "new_role": role.name, "reason": (body.reason or "")[:500]},
    )
    await db.commit()
    # After commit: the cache bump must not be able to strand a half-apply
    # (a bumped version pointing at uncommitted rows would be self-healing
    # anyway, but ordering it last keeps the invariant obvious).
    await bump_version(str(current_user.tenant_id))

    return UserRoleOut(user_id=user_id, role_id=role.id, role_name=role.name)


@router.post("/users/{user_id}/roles", response_model=UserRoleOut, status_code=status.HTTP_201_CREATED)
async def assign_role(
    user_id: uuid.UUID,
    body: UserRoleAssignment,
    current_user: Annotated[AuthUser, Depends(require_permission("roles:write"))],
    db: TenantDBSession,
) -> UserRoleOut:
    """Assign a role to a user."""
    if body.user_id != user_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="user_id mismatch")

    role = await _get_role_or_404(db, body.role_id, current_user.tenant_id)

    # `users:write` is the gate on this route and `roles:write` is the gate on
    # role *authorship*, so without this a caller holding only the former
    # could attach whatever the latter had already built — including
    # `roles:write` itself, from which the rest follows.
    _authorize_permission_grant(
        await _load_role_models(db, role.id),
        current_user,
        subject=f"permission(s) carried by role {role.name!r}",
    )

    # Ensure the target user belongs to this tenant
    user_res = await db.execute(select(User).where(User.id == user_id, User.tenant_id == current_user.tenant_id))
    if user_res.scalar_one_or_none() is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found in tenant")

    # Upsert
    existing = await db.execute(select(UserRole).where(UserRole.user_id == user_id, UserRole.role_id == role.id))
    if existing.scalar_one_or_none() is not None:
        return UserRoleOut(user_id=user_id, role_id=role.id, role_name=role.name)

    assignment = UserRole(user_id=user_id, role_id=role.id, assigned_by=current_user.user_id)
    db.add(assignment)
    await emit_audit(
        db=db,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        actor_email=current_user.email,
        api_key_prefix=getattr(current_user, "api_key_prefix", None),
        action="rbac.role_added",
        resource="user",
        resource_id=str(user_id),
        changes={"new_role": role.name, "reason": (body.reason or "")[:500]},
    )
    await db.commit()
    await bump_version(str(current_user.tenant_id))
    return UserRoleOut(user_id=user_id, role_id=role.id, role_name=role.name)


@router.delete("/users/{user_id}/roles/{role_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def revoke_role(
    user_id: uuid.UUID,
    role_id: uuid.UUID,
    current_user: Annotated[AuthUser, Depends(require_permission("roles:write"))],
    db: TenantDBSession,
) -> None:
    """Revoke a role from a user.

    Last-admin lockout guard: revoking the role that IS the tenant's admin
    role from the last active holder is refused with 409, same rule as
    `PUT /users/{id}/role` and `PATCH /tenants/me/users/{id}` — every door
    that removes management authority checks it, because "one of the doors
    remembers" is no control at all.
    """
    role = await _get_role_or_404(db, role_id, current_user.tenant_id)
    wildcard = sorted(role_grants.wildcard_roles())
    if role.name in wildcard:
        remaining = await db.scalar(
            text("SELECT count(*) FROM users WHERE tenant_id = :t AND is_active = TRUE AND role = ANY(:wild) AND id <> :keep").bindparams(
                t=str(current_user.tenant_id), wild=wildcard, keep=str(user_id)
            )
        )
        if not remaining:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="this is the last active administrator in the tenant; promote another admin before revoking this role",
            )

    await db.execute(delete(UserRole).where(UserRole.user_id == user_id, UserRole.role_id == role_id))
    await emit_audit(
        db=db,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        actor_email=current_user.email,
        api_key_prefix=getattr(current_user, "api_key_prefix", None),
        action="rbac.role_revoked",
        resource="user",
        resource_id=str(user_id),
        changes={"revoked_role": role.name},
    )
    await db.commit()
    await bump_version(str(current_user.tenant_id))


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────


async def _get_role_or_404(db: AsyncSession, role_id: uuid.UUID, tenant_id: uuid.UUID) -> Role:
    result = await db.execute(select(Role).where(Role.id == role_id, Role.tenant_id == tenant_id))
    role = result.scalar_one_or_none()
    if role is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found")
    return role


async def _resolve_permission_names(db: AsyncSession, names: list[str]) -> list[Permission]:
    """Resolve permission *keys* against the platform vocabulary.

    Unknown keys → 400 listing the valid set (sorted, capped so a typo in
    front of a 61-row vocabulary still fits comfortably in the body). A
    silent skip would be the worst failure mode here: the operator would
    believe the grant landed.
    """
    if not names:
        return []
    uniq = sorted(set(names))
    result = await db.execute(select(Permission).where(Permission.name.in_(uniq)))
    found = list(result.scalars().all())
    found_names = {p.name for p in found}
    missing = [n for n in uniq if n not in found_names]
    if missing:
        valid = sorted((await db.execute(select(Permission.name))).scalars().all())
        preview = ", ".join(valid[:80]) + (" …" if len(valid) > 80 else "")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown permission key(s): {', '.join(missing)}. Valid keys: {preview}",
        )
    return found


async def _permission_affected_users(db: AsyncSession, role_id: uuid.UUID) -> int:
    return int(await db.scalar(text("SELECT count(*) FROM user_roles WHERE role_id = CAST(:r AS uuid)").bindparams(r=str(role_id))) or 0)


async def _resolve_permissions(db: AsyncSession, permission_ids: list[uuid.UUID]) -> list[Permission]:
    if not permission_ids:
        return []
    result = await db.execute(select(Permission).where(Permission.id.in_(permission_ids)))
    found = result.scalars().all()
    if len(found) != len(permission_ids):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="One or more permission IDs are invalid")
    return list(found)


async def _load_role_models(db: AsyncSession, role_id: uuid.UUID) -> list[Permission]:
    result = await db.execute(
        select(Permission)
        .join(RolePermission, RolePermission.permission_id == Permission.id)
        .where(RolePermission.role_id == role_id)
        .order_by(Permission.category, Permission.name)
    )
    return list(result.scalars().all())


async def _load_role_permissions(db: AsyncSession, role_id: uuid.UUID) -> list[PermissionOut]:
    return [PermissionOut.model_validate(p) for p in await _load_role_models(db, role_id)]
