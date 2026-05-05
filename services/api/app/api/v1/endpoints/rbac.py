"""RBAC endpoints — role & permission management.

Roles are tenant-scoped.  Permissions are platform-wide and read-only.

Requires:
  - ``roles:read``  to list / inspect roles and permissions
  - ``roles:write`` to create / update / delete roles and assign users
  - ``users:write`` to assign / revoke roles from users
"""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.v1.deps import AuthUser, require_permission
from app.db.rls import TenantDBSession
from app.models.rbac import Permission, Role, RolePermission, UserRole
from app.models.tenant import User

router = APIRouter(prefix="/rbac", tags=["rbac"])


# ──────────────────────────────────────────────
# Pydantic schemas
# ──────────────────────────────────────────────


class PermissionOut(BaseModel):
    id: uuid.UUID
    name: str
    description: str | None
    category: str | None

    model_config = {"from_attributes": True}


class RoleIn(BaseModel):
    name: str
    description: str | None = None
    permission_ids: list[uuid.UUID] = []


class RoleUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    permission_ids: list[uuid.UUID] | None = None


class RoleOut(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    name: str
    description: str | None
    is_system: bool
    permissions: list[PermissionOut] = []

    model_config = {"from_attributes": True}


class UserRoleAssignment(BaseModel):
    user_id: uuid.UUID
    role_id: uuid.UUID


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
    """List all roles for the current tenant."""
    result = await db.execute(
        select(Role)
        .where(Role.tenant_id == current_user.tenant_id)
        .options(selectinload(Role.role_permissions).selectinload(RolePermission.permission))
        .order_by(Role.name)
    )
    roles = result.scalars().all()
    out: list[RoleOut] = []
    for role in roles:
        perms = [PermissionOut.model_validate(rp.permission) for rp in role.role_permissions]
        out.append(
            RoleOut(
                id=role.id,
                tenant_id=role.tenant_id,
                name=role.name,
                description=role.description,
                is_system=role.is_system,
                permissions=perms,
            )
        )
    return out


@router.post("/roles", response_model=RoleOut, status_code=status.HTTP_201_CREATED)
async def create_role(
    body: RoleIn,
    current_user: Annotated[AuthUser, Depends(require_permission("roles:write"))],
    db: TenantDBSession,
) -> RoleOut:
    """Create a custom role for the current tenant."""
    # Check name uniqueness
    existing = await db.execute(select(Role).where(Role.tenant_id == current_user.tenant_id, Role.name == body.name))
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Role '{body.name}' already exists")

    role = Role(
        tenant_id=current_user.tenant_id,
        name=body.name,
        description=body.description,
        is_system=False,
    )
    db.add(role)
    await db.flush()  # get role.id

    # Attach permissions
    perms_to_attach = await _resolve_permissions(db, body.permission_ids)
    for perm in perms_to_attach:
        db.add(RolePermission(role_id=role.id, permission_id=perm.id))

    await db.commit()
    await db.refresh(role)

    return RoleOut(
        id=role.id,
        tenant_id=role.tenant_id,
        name=role.name,
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
    return RoleOut(
        id=role.id,
        tenant_id=role.tenant_id,
        name=role.name,
        description=role.description,
        is_system=role.is_system,
        permissions=perms,
    )


@router.patch("/roles/{role_id}", response_model=RoleOut)
async def update_role(
    role_id: uuid.UUID,
    body: RoleUpdate,
    current_user: Annotated[AuthUser, Depends(require_permission("roles:write"))],
    db: TenantDBSession,
) -> RoleOut:
    role = await _get_role_or_404(db, role_id, current_user.tenant_id)

    if role.is_system:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="System roles cannot be modified")

    if body.name is not None:
        role.name = body.name
    if body.description is not None:
        role.description = body.description

    if body.permission_ids is not None:
        # Replace permissions
        await db.execute(delete(RolePermission).where(RolePermission.role_id == role.id))
        perms = await _resolve_permissions(db, body.permission_ids)
        for perm in perms:
            db.add(RolePermission(role_id=role.id, permission_id=perm.id))

    await db.commit()
    await db.refresh(role)
    perms_out = await _load_role_permissions(db, role.id)
    return RoleOut(
        id=role.id,
        tenant_id=role.tenant_id,
        name=role.name,
        description=role.description,
        is_system=role.is_system,
        permissions=perms_out,
    )


@router.delete("/roles/{role_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def delete_role(
    role_id: uuid.UUID,
    current_user: Annotated[AuthUser, Depends(require_permission("roles:write"))],
    db: TenantDBSession,
) -> None:
    role = await _get_role_or_404(db, role_id, current_user.tenant_id)
    if role.is_system:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="System roles cannot be deleted")
    await db.delete(role)
    await db.commit()


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


@router.post("/users/{user_id}/roles", response_model=UserRoleOut, status_code=status.HTTP_201_CREATED)
async def assign_role(
    user_id: uuid.UUID,
    body: UserRoleAssignment,
    current_user: Annotated[AuthUser, Depends(require_permission("users:write"))],
    db: TenantDBSession,
) -> UserRoleOut:
    """Assign a role to a user."""
    if body.user_id != user_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="user_id mismatch")

    role = await _get_role_or_404(db, body.role_id, current_user.tenant_id)

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
    await db.commit()
    return UserRoleOut(user_id=user_id, role_id=role.id, role_name=role.name)


@router.delete("/users/{user_id}/roles/{role_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def revoke_role(
    user_id: uuid.UUID,
    role_id: uuid.UUID,
    current_user: Annotated[AuthUser, Depends(require_permission("users:write"))],
    db: TenantDBSession,
) -> None:
    """Revoke a role from a user."""
    await db.execute(delete(UserRole).where(UserRole.user_id == user_id, UserRole.role_id == role_id))
    await db.commit()


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────


async def _get_role_or_404(db: AsyncSession, role_id: uuid.UUID, tenant_id: uuid.UUID) -> Role:
    result = await db.execute(select(Role).where(Role.id == role_id, Role.tenant_id == tenant_id))
    role = result.scalar_one_or_none()
    if role is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found")
    return role


async def _resolve_permissions(db: AsyncSession, permission_ids: list[uuid.UUID]) -> list[Permission]:
    if not permission_ids:
        return []
    result = await db.execute(select(Permission).where(Permission.id.in_(permission_ids)))
    found = result.scalars().all()
    if len(found) != len(permission_ids):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="One or more permission IDs are invalid")
    return list(found)


async def _load_role_permissions(db: AsyncSession, role_id: uuid.UUID) -> list[PermissionOut]:
    result = await db.execute(
        select(Permission)
        .join(RolePermission, RolePermission.permission_id == Permission.id)
        .where(RolePermission.role_id == role_id)
        .order_by(Permission.category, Permission.name)
    )
    return [PermissionOut.model_validate(p) for p in result.scalars().all()]
