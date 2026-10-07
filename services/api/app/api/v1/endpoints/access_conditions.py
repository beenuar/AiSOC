"""Attribute conditions that narrow a permission.

Depth plan item 8.2. ``permission_conditions`` was created by migration 087
and read by nothing, so ``cases:write`` was true everywhere, always, from
any address: there was no way to say "from the corporate network" or "during
this incident".

Enforcement does not live here
------------------------------
These routes administer rows. The rows are applied by
``CurrentUser.require_permission`` in ``app/api/v1/deps.py``, inside the one
permission path, after whichever branch allowed. That placement is the
design, not an implementation detail: a condition evaluated *beside* the
permission check would be a second authorization system, and two authorities
that can disagree is the shape that produced GHSA-pm3f-h6gc-rvgp here.

Why the operator set is narrower than the evaluator's
------------------------------------------------------
``app.security.abac`` implements eight operators. This surface accepts the
subset whose attributes the API actually puts in the evaluation context
today. The rest are refused at write time with the reason, rather than
stored and silently denied at read time: a condition the deployment cannot
evaluate is indeterminate, indeterminate denies, and an operator who
configured one would see a permanent 403 with nothing explaining it.

``mfa_satisfied`` is the one that matters. Console MFA is being built
separately; until the authenticated principal carries that fact, a condition
naming it would be a control the tree does not have.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select

from app.api.v1.deps import AuthUser, require_permission
from app.core.permission_cache import bump_version
from app.core.rbac_catalog import PERMISSIONS
from app.core.role_grants import GRANTABLE_ROLES, RoleGrantDenied, authorize_permission_grant, permissions_for
from app.db.rls import TenantDBSession
from app.models.enterprise_iam import PermissionCondition
from app.security.abac import OPERATORS
from app.services.audit import emit_audit

router = APIRouter(prefix="/access-conditions", tags=["access-conditions"])

#: Operators this deployment can evaluate, mapped to the attribute each
#: needs. ``app/api/v1/deps.py::CurrentUser.bind_connection_attributes`` is
#: what puts those attributes in the context, and these two must agree —
#: ``test_access_conditions.py`` asserts every attribute named here is one
#: the binding actually produces, so adding an operator without the fact it
#: judges fails rather than ships.
SUPPORTED: dict[str, str] = {
    "ip_in_cidr": "source_ip",
    "ip_not_in_cidr": "source_ip",
    "time_between_utc": "now",
    "weekday_in": "now",
    "attribute_equals": "role / auth_method",
    "attribute_in": "role / auth_method",
}

#: Attributes an ``attribute_equals`` / ``attribute_in`` condition may name.
#: A closed set because the context is a closed set: a condition on an
#: attribute nothing supplies is indeterminate, and indeterminate denies.
ADDRESSABLE_ATTRIBUTES = frozenset({"role", "auth_method", "source_ip"})

#: Why each unsupported operator is refused, so the message names the thing
#: that would have to exist rather than saying "unsupported".
_UNSUPPORTED_REASON: dict[str, str] = {
    "mfa_satisfied": (
        "the authenticated principal does not yet carry whether MFA was satisfied, so this "
        "condition could only ever be indeterminate — and indeterminate denies"
    ),
}

_KNOWN_PERMISSIONS = frozenset(name for name, _desc, _cat in PERMISSIONS)


class ConditionIn(BaseModel):
    permission: str = Field(..., min_length=3, max_length=200)
    operator: str
    value: Any
    role: str | None = None
    description: str | None = Field(None, max_length=500)
    enabled: bool = True

    @field_validator("operator")
    @classmethod
    def _known_operator(cls, value: str) -> str:
        if value not in OPERATORS:
            raise ValueError(f"unknown operator {value!r}; known: {sorted(OPERATORS)}")
        if value not in SUPPORTED:
            raise ValueError(f"{value!r} cannot be enforced on this deployment: {_UNSUPPORTED_REASON.get(value, 'unsupported')}")
        return value


class ConditionOut(BaseModel):
    id: uuid.UUID
    permission: str
    role: str | None
    operator: str
    value: Any
    description: str | None
    enabled: bool
    created_at: datetime


def _out(row: PermissionCondition) -> ConditionOut:
    condition = row.condition or {}
    return ConditionOut(
        id=row.id,
        permission=row.permission,
        role=row.role,
        operator=str(condition.get("operator") or ""),
        value=condition.get("value"),
        description=row.description,
        enabled=row.enabled,
        created_at=row.created_at,
    )


def _validate(permission: str, operator: str, value: Any, role: str | None) -> None:
    """Refuse a row that could not narrow anything, or could narrow everything.

    Each refusal is a condition that would otherwise be stored, read as
    configured in the console, and behave differently from what it says.

    Takes the fields rather than the request model because it decides
    nothing about authority -- that decision belongs beside
    ``require_permission`` in the handler, and binding the model here
    would say otherwise both to a reader and to
    `scripts/check_role_grant_scope.py`.
    """
    if permission != "*" and permission not in _KNOWN_PERMISSIONS:
        resource = permission.split(":")[0]
        if not (permission.endswith(":*") and any(p.startswith(f"{resource}:") for p in _KNOWN_PERMISSIONS)):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Unknown permission {permission!r}. Use a seeded permission name or a 'resource:*' form.",
            )

    if role is not None and role not in GRANTABLE_ROLES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unknown role {role!r}. Assignable roles: {', '.join(GRANTABLE_ROLES)}",
        )

    if operator in {"attribute_equals", "attribute_in"}:
        named = value.get("attribute") if isinstance(value, dict) else None
        if named not in ADDRESSABLE_ATTRIBUTES:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=(
                    f"attribute conditions must name one of {sorted(ADDRESSABLE_ATTRIBUTES)}; "
                    f"got {named!r}. An attribute the request does not carry is indeterminate, and indeterminate denies."
                ),
            )


@router.get("/operators", response_model=dict)
async def supported_operators(
    _user: Annotated[AuthUser, Depends(require_permission("access_conditions:read"))],
) -> dict[str, Any]:
    """What this deployment can enforce, and why the rest is refused.

    A console that offered every operator the evaluator implements would
    let an operator configure a permanent, unexplained denial.
    """
    return {
        "supported": [{"operator": name, "attribute": attribute} for name, attribute in sorted(SUPPORTED.items())],
        "unsupported": [{"operator": name, "reason": reason} for name, reason in sorted(_UNSUPPORTED_REASON.items())],
        "attributes": sorted(ADDRESSABLE_ATTRIBUTES),
    }


@router.get("", response_model=list[ConditionOut])
async def list_conditions(
    db: TenantDBSession,
    current_user: Annotated[AuthUser, Depends(require_permission("access_conditions:read"))],
) -> list[ConditionOut]:
    rows = (
        await db.execute(
            select(PermissionCondition)
            .where(PermissionCondition.tenant_id == current_user.tenant_id)
            .order_by(PermissionCondition.permission, PermissionCondition.created_at)
        )
    ).scalars()
    return [_out(row) for row in rows]


@router.post("", response_model=ConditionOut, status_code=status.HTTP_201_CREATED)
async def create_condition(
    body: ConditionIn,
    request: Request,
    db: TenantDBSession,
    current_user: Annotated[AuthUser, Depends(require_permission("access_conditions:write"))],
) -> ConditionOut:
    """Add a condition to this tenant.

    The tenant comes from the authenticated principal. A condition is a
    denial, so a caller able to name the tenant could refuse another
    tenant's work — the same shape as the MSSP override that let any
    authenticated user delete a critical detection from any other tenant.

    `role` is the same argument one level down, and it was unguarded.
    Scoping a condition to a role is legislating over that role's
    exercise of a permission, so the rule is the one the rest of this
    tree already applies to conferral, turned around: you may not
    constrain authority you do not yourself hold. Without it a
    `soc_analyst` holding `access_conditions:write` could store a
    condition denying `admin` a permission outright, and the only
    symptom an administrator would see is their own access failing for
    a reason the console attributes to a rule they cannot edit.

    Measured against `resolved_permissions`, never the static role map:
    `require_permission` admitted this caller on the database-backed set,
    and judging the grant against the broader static one is how six call
    sites passed this gate while still escalating.
    """
    if body.role is not None:
        try:
            authorize_permission_grant(
                granter_role=current_user.role,
                granter_scopes=current_user.scopes,
                granter_permissions=current_user.resolved_permissions,
                requested=sorted(permissions_for(body.role)),
                subject=f"a condition scoped to role {body.role!r}",
            )
        except RoleGrantDenied as exc:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=exc.reason) from exc

    _validate(body.permission, body.operator, body.value, body.role)

    row = PermissionCondition(
        tenant_id=current_user.tenant_id,
        permission=body.permission,
        role=body.role,
        condition={"operator": body.operator, "value": body.value},
        description=body.description,
        enabled=body.enabled,
    )
    db.add(row)
    await db.flush()

    await emit_audit(
        db=db,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        actor_email=current_user.email,
        action="access_condition:create",
        resource="permission_condition",
        resource_id=str(row.id),
        changes={"permission": body.permission, "operator": body.operator, "enabled": body.enabled},
        request=request,
    )
    await db.commit()
    await bump_version(str(current_user.tenant_id))
    return _out(row)


@router.patch("/{condition_id}", response_model=ConditionOut)
async def set_condition_enabled(
    condition_id: uuid.UUID,
    enabled: bool,
    request: Request,
    db: TenantDBSession,
    current_user: Annotated[AuthUser, Depends(require_permission("access_conditions:write"))],
) -> ConditionOut:
    """Turn a condition on or off without deleting it.

    Only ``enabled`` is mutable. Editing a stored condition's operator or
    value in place would change what an audit entry referring to it meant;
    a replaced rule is a new row.
    """
    row = await _load(db, condition_id, current_user.tenant_id)
    row.enabled = enabled
    await emit_audit(
        db=db,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        actor_email=current_user.email,
        action="access_condition:update",
        resource="permission_condition",
        resource_id=str(row.id),
        changes={"enabled": enabled},
        request=request,
    )
    await db.commit()
    await bump_version(str(current_user.tenant_id))
    return _out(row)


@router.delete("/{condition_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_condition(
    condition_id: uuid.UUID,
    request: Request,
    db: TenantDBSession,
    current_user: Annotated[AuthUser, Depends(require_permission("access_conditions:write"))],
) -> None:
    row = await _load(db, condition_id, current_user.tenant_id)
    await emit_audit(
        db=db,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        actor_email=current_user.email,
        action="access_condition:delete",
        resource="permission_condition",
        resource_id=str(row.id),
        changes={"permission": row.permission},
        request=request,
    )
    await db.delete(row)
    await db.commit()
    await bump_version(str(current_user.tenant_id))


async def _load(db: Any, condition_id: uuid.UUID, tenant_id: uuid.UUID) -> PermissionCondition:
    row = (
        await db.execute(
            select(PermissionCondition).where(
                PermissionCondition.id == condition_id,
                PermissionCondition.tenant_id == tenant_id,
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Condition not found")
    return row
