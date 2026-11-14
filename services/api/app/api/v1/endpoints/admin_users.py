"""Admin user-management endpoints — the console's `Users` screen.

All routes here gate on `roles:write`, which only the `admin` wildcard role
holds: viewer and infosec get 403 at the dependency before any query runs.
(The static map and the catalog both withhold `roles:write` from non-admin
roles, and `CurrentUser.require_permission` prefers the catalog once a
tenant has one — so the gate cannot be walked around by editing
`users.role` alone.)

Design notes carried over from `rbac.py`, where they matter most:

* Multi-role is real here. `user_roles` is a join table and the console
  assigns a *set*; `users.role` — the string the JWT/static path reads —
  mirrors the highest-ranked held role after every write so the two
  authorization paths never disagree about who someone is.
* Every write ends the target's active sessions (`sessions_revoked_at`)
  and bumps the permission-cache version. New permissions are live on the
  next request; old tokens die immediately. No waiting for token expiry.
* The last active admin cannot be demoted, stripped, or disabled through
  any of these doors — each counts before it writes and answers 409.
* Disabled users cannot receive role assignments (fixes the old ordering
  hole where a disabled account could be quietly re-scoped).
* Unknown role names → 400 naming the tenant's valid set. Self-service
  profile endpoints never touched roles; nothing on this router accepts a
  role except the explicit role routes.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import AuthUser, require_permission
from app.core import role_grants
from app.core.permission_cache import bump_version
from app.db.rls import TenantDBSession
from app.models.rbac import Permission, Role, RolePermission, UserRole
from app.models.tenant import User
from app.services.audit import emit_audit

router = APIRouter(prefix="/admin/users", tags=["admin-users"])

#: Rank for the `users.role` mirror: the highest held role wins. Roles
#: outside this list rank below every listed one.
ROLE_RANK: dict[str, int] = {"viewer": 0, "infosec": 1, "admin": 2, "platform_admin": 3}

_SORTABLE = {
    "name": User.username,
    "email": User.email,
    "status": User.is_active,
    "created": User.created_at,
    "last_login": User.last_login,
}


class AdminUserOut(BaseModel):
    id: uuid.UUID
    email: str
    username: str
    is_active: bool
    role: str
    roles: list[str] = []
    provider: str = "local"
    last_login: datetime | None = None
    created_at: datetime | None = None
    effective_permissions: list[str] = []


class UserPage(BaseModel):
    items: list[AdminUserOut]
    total: int
    limit: int
    offset: int


class UserPatch(BaseModel):
    """Body for PATCH /admin/users/{id} — status changes only.

    Roles deliberately do not live on this body: a status patch that can
    also carry roles turns every future "toggle" feature into a privilege
    escalation vector. Roles move through the explicit role routes.
    """

    is_active: bool
    reason: str | None = Field(default=None, max_length=500)


class RoleSetIn(BaseModel):
    role_names: list[str] = Field(min_length=1)
    reason: str = Field(min_length=1, max_length=500)


class RoleAddIn(BaseModel):
    role_name: str = Field(min_length=1, max_length=100)
    reason: str = Field(min_length=1, max_length=500)


# ──────────────────────────────────────────────
# Reads
# ──────────────────────────────────────────────


@router.get("", response_model=UserPage)
async def list_users(
    current_user: Annotated[AuthUser, Depends(require_permission("roles:write"))],
    db: TenantDBSession,
    search: str | None = Query(default=None, max_length=200),
    role: str | None = Query(default=None, max_length=100),
    status_filter: str | None = Query(default=None, alias="status", pattern="^(active|disabled)$"),
    sort: str = Query(default="created", pattern="^(name|email|status|created|last_login)$"),
    order: str = Query(default="desc", pattern="^(asc|desc)$"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> UserPage:
    """Paginated member list with live roles, provider, and headcounts."""
    conds = [User.tenant_id == current_user.tenant_id]
    if search:
        like = f"%{search.strip()}%"
        conds.append(User.email.ilike(like) | User.username.ilike(like))
    if status_filter == "active":
        conds.append(User.is_active.is_(True))
    elif status_filter == "disabled":
        conds.append(User.is_active.is_(False))

    params: dict[str, Any] = {
        "search": f"%{search.strip()}%" if search else None,
        "active": True if status_filter == "active" else (False if status_filter == "disabled" else None),
    }

    if role:
        conds.append(
            text(
                "EXISTS (SELECT 1 FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = users.id AND r.name = :role_name)"
            )
            .bindparams(role_name=role)
            .bindparams(role_name=role)
        )
        params["role_name"] = role

    # `status` sorts active-first asc / disabled-first desc; NULL last_login
    # sorts last either way so never-logged-in accounts don't cluster on top.
    order_col = _SORTABLE[sort]
    order_by = order_col.asc().nulls_last() if order == "asc" else order_col.desc().nulls_last()

    total = await db.scalar(select(func.count()).select_from(User).where(*conds))
    rows = (await db.execute(select(User).where(*conds).order_by(order_by, User.id).limit(limit).offset(offset))).scalars().all()

    # One join for every listed user's roles; provider from the password
    # hash prefix (`!sso-no-pass` marks SSO-JIT accounts with no local
    # credential); effective permissions resolved from the catalog once per
    # user via a single aggregate query.
    user_ids = [u.id for u in rows]
    roles_by_user: dict[uuid.UUID, list[str]] = {uid: [] for uid in user_ids}
    perms_by_user: dict[uuid.UUID, list[str]] = {uid: [] for uid in user_ids}
    if user_ids:
        role_rows = await db.execute(
            text(
                "SELECT ur.user_id, r.name FROM user_roles ur JOIN roles r ON r.id = ur.role_id "
                "WHERE ur.user_id = ANY(CAST(:ids AS uuid[])) AND r.tenant_id = CAST(:t AS uuid)"
            ).bindparams(ids=[str(u) for u in user_ids], t=str(current_user.tenant_id))
        )
        for uid, rname in role_rows.all():
            roles_by_user[uuid.UUID(str(uid))].append(rname)
        perm_rows = await db.execute(
            text(
                "SELECT DISTINCT ur.user_id, p.name FROM user_roles ur "
                "JOIN roles r ON r.id = ur.role_id "
                "JOIN role_permissions rp ON rp.role_id = r.id "
                "JOIN permissions p ON p.id = rp.permission_id "
                "WHERE ur.user_id = ANY(CAST(:ids AS uuid[])) AND r.tenant_id = CAST(:t AS uuid) "
                "ORDER BY 2"
            ).bindparams(ids=[str(u) for u in user_ids], t=str(current_user.tenant_id))
        )
        for uid, pname in perm_rows.all():
            perms_by_user[uuid.UUID(str(uid))].append(pname)

    items = []
    for u in rows:
        held = roles_by_user.get(u.id) or ([u.role] if u.role else [])
        items.append(
            AdminUserOut(
                id=u.id,
                email=u.email,
                username=u.username,
                is_active=u.is_active,
                role=u.role,
                roles=sorted(set(held)),
                provider="local" if (u.hashed_password or "").startswith("$2") else "sso",
                last_login=u.last_login,
                created_at=u.created_at,
                effective_permissions=perms_by_user.get(u.id, []),
            )
        )
    return UserPage(items=items, total=int(total or 0), limit=limit, offset=offset)


@router.get("/{user_id}", response_model=AdminUserOut)
async def get_user(
    user_id: uuid.UUID,
    current_user: Annotated[AuthUser, Depends(require_permission("roles:write"))],
    db: TenantDBSession,
) -> AdminUserOut:
    target = await _get_target(db, user_id, current_user.tenant_id)
    roles = await _roles_of(db, target.id, current_user.tenant_id)
    perms = await _effective_perms(db, target.id, current_user.tenant_id)
    return AdminUserOut(
        id=target.id,
        email=target.email,
        username=target.username,
        is_active=target.is_active,
        role=target.role,
        roles=sorted(set(roles)),
        provider="local" if (target.hashed_password or "").startswith("$2") else "sso",
        last_login=target.last_login,
        created_at=target.created_at,
        effective_permissions=perms,
    )


@router.get("/{user_id}/effective-permissions", response_model=list[str])
async def effective_permissions(
    user_id: uuid.UUID,
    current_user: Annotated[AuthUser, Depends(require_permission("roles:write"))],
    db: TenantDBSession,
) -> list[str]:
    """Merged permission set for one user — the modal's read-only preview.

    Answers from `user_roles` only (the catalog), not the static map: what
    the modal shows is what the enforcement layer will check once the
    tenant is catalog-backed.
    """
    await _get_target(db, user_id, current_user.tenant_id)
    return await _effective_perms(db, user_id, current_user.tenant_id)


# ──────────────────────────────────────────────
# Role writes
# ──────────────────────────────────────────────


@router.put("/{user_id}/roles", response_model=AdminUserOut)
async def set_roles(
    user_id: uuid.UUID,
    body: RoleSetIn,
    request: Request,
    current_user: Annotated[AuthUser, Depends(require_permission("roles:write"))],
    db: TenantDBSession,
) -> AdminUserOut:
    """Replace the user's full role set (multi-role replace semantics)."""
    target = await _get_target(db, user_id, current_user.tenant_id)
    if not target.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This member is disabled — enable them before changing roles (the role is preserved either way)",
        )

    roles = await _resolve_roles(db, current_user.tenant_id, body.role_names)
    await _authorize_roles(db, roles, current_user)
    await _guard_last_admin(db, current_user.tenant_id, target, roles)

    old_roles = await _roles_of(db, target.id, current_user.tenant_id)
    now = datetime.now(UTC)
    await db.execute(text("DELETE FROM user_roles WHERE user_id = CAST(:u AS uuid)").bindparams(u=str(target.id)))
    for role in roles:
        db.add(UserRole(user_id=target.id, role_id=role.id, assigned_by=current_user.user_id))
    mirrored = _mirror_role(roles)
    await db.execute(update(User).where(User.id == target.id).values(role=mirrored, updated_at=now))
    await _end_sessions(db, target.id, now)

    await emit_audit(
        db=db,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        actor_email=current_user.email,
        api_key_prefix=getattr(current_user, "api_key_prefix", None),
        action="admin.users.roles_replaced",
        resource="user",
        resource_id=str(target.id),
        changes={
            "old_roles": sorted(set(old_roles)),
            "new_roles": sorted(r.name for r in roles),
            "reason": (body.reason or "")[:500],
        },
        request=request,
    )
    await db.commit()
    await bump_version(str(current_user.tenant_id))

    return await _read_out(db, target, current_user.tenant_id)


@router.post("/{user_id}/roles", response_model=AdminUserOut, status_code=status.HTTP_201_CREATED)
async def add_role(
    user_id: uuid.UUID,
    body: RoleAddIn,
    request: Request,
    current_user: Annotated[AuthUser, Depends(require_permission("roles:write"))],
    db: TenantDBSession,
) -> AdminUserOut:
    target = await _get_target(db, user_id, current_user.tenant_id)
    if not target.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="This member is disabled — enable them before changing roles")
    role = await _resolve_role_or_400(db, current_user.tenant_id, body.role_name)
    await _authorize_roles(db, [role], current_user)

    existing = await db.execute(select(UserRole).where(UserRole.user_id == target.id, UserRole.role_id == role.id))
    if existing.scalar_one_or_none() is None:
        old_roles = await _roles_of(db, target.id, current_user.tenant_id)
        db.add(UserRole(user_id=target.id, role_id=role.id, assigned_by=current_user.user_id))
        rows = await _role_rows(db, target.id, current_user.tenant_id)
        mirrored = _mirror_role(list(rows) + [role])
        now = datetime.now(UTC)
        await db.execute(update(User).where(User.id == target.id).values(role=mirrored, updated_at=now))
        await _end_sessions(db, target.id, now)
        await emit_audit(
            db=db,
            tenant_id=current_user.tenant_id,
            actor_id=current_user.user_id,
            actor_email=current_user.email,
            api_key_prefix=getattr(current_user, "api_key_prefix", None),
            action="admin.users.role_added",
            resource="user",
            resource_id=str(target.id),
            changes={"old_roles": sorted(set(old_roles)), "added_role": role.name, "reason": (body.reason or "")[:500]},
            request=request,
        )
        await db.commit()
        await bump_version(str(current_user.tenant_id))
    return await _read_out(db, target, current_user.tenant_id)


@router.delete("/{user_id}/roles/{role_name}", response_model=AdminUserOut)
async def remove_role(
    user_id: uuid.UUID,
    role_name: str,
    request: Request,
    current_user: Annotated[AuthUser, Depends(require_permission("roles:write"))],
    db: TenantDBSession,
) -> AdminUserOut:
    target = await _get_target(db, user_id, current_user.tenant_id)
    role = await _resolve_role_or_400(db, current_user.tenant_id, role_name)

    held = [r for r in await _role_rows(db, target.id, current_user.tenant_id) if r.id != role.id]
    if not held:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot remove the member's only role — assign another role first (spec: no NULL-role users)",
        )
    await _guard_last_admin(db, current_user.tenant_id, target, held)

    now = datetime.now(UTC)
    await db.execute(
        text("DELETE FROM user_roles WHERE user_id = CAST(:u AS uuid) AND role_id = CAST(:r AS uuid)").bindparams(
            u=str(target.id), r=str(role.id)
        )
    )
    mirrored = _mirror_role(held)
    await db.execute(update(User).where(User.id == target.id).values(role=mirrored, updated_at=now))
    await _end_sessions(db, target.id, now)
    await emit_audit(
        db=db,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        actor_email=current_user.email,
        api_key_prefix=getattr(current_user, "api_key_prefix", None),
        action="admin.users.role_removed",
        resource="user",
        resource_id=str(target.id),
        changes={
            "removed_role": role.name,
            "new_roles": sorted(r.name for r in held),
            "reason": (request.query_params.get("reason") or "")[:500],
        },
        request=request,
    )
    await db.commit()
    await bump_version(str(current_user.tenant_id))
    return await _read_out(db, target, current_user.tenant_id)


# ──────────────────────────────────────────────
# Status writes
# ──────────────────────────────────────────────


@router.patch("/{user_id}", response_model=AdminUserOut)
async def patch_status(
    user_id: uuid.UUID,
    body: UserPatch,
    request: Request,
    current_user: Annotated[AuthUser, Depends(require_permission("roles:write"))],
    db: TenantDBSession,
) -> AdminUserOut:
    """Enable / disable a member. Disabling ends their sessions immediately;
    the role assignment is preserved untouched."""
    target = await _get_target(db, user_id, current_user.tenant_id)
    if not body.is_active:
        await _guard_last_admin(
            db, current_user.tenant_id, target, await _role_rows(db, target.id, current_user.tenant_id), deactivating=True
        )

    now = datetime.now(UTC)
    await db.execute(update(User).where(User.id == target.id).values(is_active=body.is_active, updated_at=now))
    if not body.is_active:
        await _end_sessions(db, target.id, now)
    await emit_audit(
        db=db,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        actor_email=current_user.email,
        api_key_prefix=getattr(current_user, "api_key_prefix", None),
        action="admin.users.disabled" if not body.is_active else "admin.users.enabled",
        resource="user",
        resource_id=str(target.id),
        changes={"is_active": body.is_active, "reason": (body.reason or "")[:500]},
        request=request,
    )
    await db.commit()
    return await _read_out(db, target, current_user.tenant_id)


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: uuid.UUID,
    request: Request,
    current_user: Annotated[AuthUser, Depends(require_permission("roles:write"))],
    reason: Annotated[str, Query(min_length=1, max_length=500)],
    db: TenantDBSession,
) -> None:
    """Permanently delete a member.

    Hard delete, deliberately: `audit_log.actor_id` and every other
    attribution column SET NULL on delete, so the audit trail keeps each
    action with the name attributed in the audit payload below — the
    history survives, the identity row does not. Ownership rows
    (`user_roles`, `aisoc_sso_identities`, `saved_views`, …) cascade.

    Guards, in order:
    * a member cannot delete their own account (disable yourself instead);
    * the last active admin cannot be deleted (`_guard_last_admin`);
    * sessions are ended before the row goes, so any in-flight token dies
      at the next request even if a race briefly revives the row.

    An SSO-provisioned account that is deleted will be re-created as a
    `viewer` by JIT on the next successful login — deletion removes the
    account, not the IdP's right to provision it. Say so in the reason if
    that matters for the case.
    """
    target = await _get_target(db, user_id, current_user.tenant_id)
    if str(target.id) == str(current_user.user_id):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="you cannot delete your own account; disable it instead",
        )
    await _guard_last_admin(db, current_user.tenant_id, target, await _role_rows(db, target.id, current_user.tenant_id), deactivating=True)

    now = datetime.now(UTC)
    snapshot = {
        "email": target.email,
        "username": target.username,
        "role": target.role,
        "roles": await _roles_of(db, target.id, current_user.tenant_id),
        "provider": "local" if (target.hashed_password or "").startswith("$2") else "sso",
        "reason": reason[:500],
    }
    # End sessions first: a token mid-flight must fail closed the moment
    # the row disappears, not at expiry.
    await _end_sessions(db, target.id, now)
    await db.execute(text("DELETE FROM user_roles WHERE user_id = CAST(:u AS uuid)").bindparams(u=str(target.id)))
    await db.delete(target)
    await emit_audit(
        db=db,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        actor_email=current_user.email,
        api_key_prefix=getattr(current_user, "api_key_prefix", None),
        action="admin.users.deleted",
        resource="user",
        resource_id=str(user_id),
        changes=snapshot,
        request=request,
    )
    await db.commit()


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────


async def _get_target(db: AsyncSession, user_id: uuid.UUID, tenant_id: uuid.UUID) -> User:
    target = (await db.execute(select(User).where(User.id == user_id, User.tenant_id == tenant_id))).scalar_one_or_none()
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found in tenant")
    return target


async def _resolve_role_or_400(db: AsyncSession, tenant_id: uuid.UUID, name: str) -> Role:
    role = (await db.execute(select(Role).where(Role.tenant_id == tenant_id, Role.name == name))).scalar_one_or_none()
    if role is None:
        valid = sorted((await db.execute(select(Role.name).where(Role.tenant_id == tenant_id))).scalars().all())
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown role {name!r}. Valid roles for this tenant: {', '.join(valid) or '(none seeded — seed the catalog first)'}",
        )
    return role


async def _resolve_roles(db: AsyncSession, tenant_id: uuid.UUID, names: list[str]) -> list[Role]:
    uniq = []
    seen = set()
    for n in names:
        if n in seen:
            continue
        seen.add(n)
        uniq.append(await _resolve_role_or_400(db, tenant_id, n))
    if not uniq:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="A user must hold at least one role")
    return uniq


async def _authorize_roles(db: AsyncSession, roles: list[Role], granter: AuthUser) -> None:
    """The granter may only confer what they hold (privilege-escalation gate)."""
    from app.core.role_grants import RoleGrantDenied, authorize_permission_grant

    names = sorted({p.name for r in roles for p in (await _role_perm_models(db, r.id))})
    if "*" in names:
        names = sorted(await _all_perm_names(db))
    try:
        authorize_permission_grant(
            granter_role=granter.role,
            granter_scopes=granter.scopes,
            granter_permissions=granter.resolved_permissions,
            requested=names,
            subject=f"permission(s) carried by role(s) {[r.name for r in roles]}",
        )
    except RoleGrantDenied as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=exc.reason) from exc


async def _role_perm_models(db: AsyncSession, role_id: uuid.UUID) -> list[Permission]:
    result = await db.execute(
        select(Permission).join(RolePermission, RolePermission.permission_id == Permission.id).where(RolePermission.role_id == role_id)
    )
    return list(result.scalars().all())


async def _all_perm_names(db: AsyncSession) -> list[str]:
    result = await db.execute(select(Permission.name))
    return sorted(result.scalars().all())


async def _guard_last_admin(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    target: User,
    resulting_roles: list[Role],
    *,
    deactivating: bool = False,
) -> None:
    """Refuse any write that would empty the tenant of active admins."""
    wildcard = sorted(role_grants.wildcard_roles())
    keeps_admin = any(r.name in wildcard for r in resulting_roles) and not deactivating
    if keeps_admin:
        return  # target keeps admin and stays active — nothing lost
    losing = target.role in wildcard or deactivating
    if not losing:
        # admin may be held only through a role row being replaced/stripped
        held_admin = await db.scalar(
            text(
                "SELECT count(*) FROM user_roles ur JOIN roles r ON r.id = ur.role_id "
                "WHERE ur.user_id = CAST(:u AS uuid) AND r.name = ANY(:w)"
            ).bindparams(u=str(target.id), w=wildcard)
        )
        losing = bool(held_admin)
    if not losing:
        return
    remaining = await db.scalar(
        text(
            "SELECT count(*) FROM users WHERE tenant_id = CAST(:t AS uuid) AND is_active = TRUE "
            "AND (role = ANY(:w) OR EXISTS (SELECT 1 FROM user_roles ur JOIN roles r ON r.id = ur.role_id "
            "WHERE ur.user_id = users.id AND r.name = ANY(:w))) AND id <> CAST(:keep AS uuid)"
        ).bindparams(t=str(tenant_id), w=wildcard, keep=str(target.id))
    )
    if not remaining:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="this is the last active administrator in the tenant; promote another admin before removing this one's authority",
        )


async def _roles_of(db: AsyncSession, user_id: uuid.UUID, tenant_id: uuid.UUID) -> list[str]:
    rows = await db.execute(
        text(
            "SELECT r.name FROM user_roles ur JOIN roles r ON r.id = ur.role_id "
            "WHERE ur.user_id = CAST(:u AS uuid) AND r.tenant_id = CAST(:t AS uuid)"
        ).bindparams(u=str(user_id), t=str(tenant_id))
    )
    return [r for (r,) in rows.all()]


async def _role_rows(db: AsyncSession, user_id: uuid.UUID, tenant_id: uuid.UUID) -> list[Role]:
    result = await db.execute(
        select(Role).join(UserRole, UserRole.role_id == Role.id).where(UserRole.user_id == user_id, Role.tenant_id == tenant_id)
    )
    return list(result.scalars().all())


async def _effective_perms(db: AsyncSession, user_id: uuid.UUID, tenant_id: uuid.UUID) -> list[str]:
    rows = await db.execute(
        text(
            "SELECT DISTINCT p.name FROM user_roles ur JOIN roles r ON r.id = ur.role_id "
            "JOIN role_permissions rp ON rp.role_id = r.id JOIN permissions p ON p.id = rp.permission_id "
            "WHERE ur.user_id = CAST(:u AS uuid) AND r.tenant_id = CAST(:t AS uuid) ORDER BY 1"
        ).bindparams(u=str(user_id), t=str(tenant_id))
    )
    return [p for (p,) in rows.all()]


def _mirror_role(roles: list[Role]) -> str:
    return max(roles, key=lambda r: ROLE_RANK.get(r.name, -1)).name


async def _end_sessions(db: AsyncSession, user_id: uuid.UUID, now: datetime) -> None:
    await db.execute(update(User).where(User.id == user_id).values(sessions_revoked_at=now))


async def _read_out(db: AsyncSession, target: User, tenant_id: uuid.UUID) -> AdminUserOut:
    await db.refresh(target)
    roles = await _roles_of(db, target.id, tenant_id)
    perms = await _effective_perms(db, target.id, tenant_id)
    return AdminUserOut(
        id=target.id,
        email=target.email,
        username=target.username,
        is_active=target.is_active,
        role=target.role,
        roles=sorted(set(roles)),
        provider="local" if (target.hashed_password or "").startswith("$2") else "sso",
        last_login=target.last_login,
        created_at=target.created_at,
        effective_permissions=perms,
    )
