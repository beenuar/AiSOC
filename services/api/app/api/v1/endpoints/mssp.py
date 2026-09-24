"""MSSP console endpoints.

Two generations of model live here side by side, deliberately.

`/mssp/children`, `/mssp/notes`, `/mssp/delegations` and the rule-pack routes
read `tenants.parent_tenant_id` (migration 012), which makes the managing
provider a tenant. Existing deployments have data in those tables, so they
keep working unchanged — with the consent and ownership checks that sit
alongside them.

Everything under `/mssp/portfolio` and `/mssp/organizations` reads the
organisation model (migration 058), where the operator is its own object
with members, per-member roles, and per-member tenant grants. Cross-tenant
reads resolve their tenant list through
`app.services.org_scope.resolve_portfolio_scope` and nothing else.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.endpoints.auth import get_current_user
from app.db.database import get_db
from app.models.mssp import MSSPDelegation, MSSPTenantMetrics, MSSPTenantNote
from app.models.organization import (
    ORG_ROLES,
    Organization,
    OrganizationMember,
    OrganizationMemberTenant,
    OrganizationTenant,
)
from app.models.tenant import Tenant, User
from app.services import mssp_portfolio
from app.services.org_scope import PortfolioScope, narrow, resolve_portfolio_scope

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/mssp", tags=["mssp"])


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class ChildTenantOut(BaseModel):
    id: uuid.UUID
    name: str
    mssp_role: str
    created_at: str

    model_config = ConfigDict(from_attributes=True)


class TenantNoteCreate(BaseModel):
    child_id: uuid.UUID
    body: str


class TenantNoteOut(TenantNoteCreate):
    id: uuid.UUID
    parent_id: uuid.UUID
    author_id: uuid.UUID | None
    created_at: str

    model_config = ConfigDict(from_attributes=True)


class DelegationCreate(BaseModel):
    child_tenant_id: uuid.UUID
    granted_role: str = "soc_analyst"
    expires_at: datetime | None = None


class DelegationOut(DelegationCreate):
    id: uuid.UUID
    parent_tenant_id: uuid.UUID
    granted_by_user: uuid.UUID | None
    revoked_at: datetime | None
    created_at: str

    model_config = ConfigDict(from_attributes=True)


class MetricsOut(BaseModel):
    tenant_id: uuid.UUID
    snapshot_at: str
    open_alerts: int
    critical_alerts: int
    open_cases: int
    mttr_minutes: float | None
    sla_breaches: int
    connector_count: int
    health_score: float | None

    model_config = ConfigDict(from_attributes=True)


# ---------------------------------------------------------------------------
# Child-tenant management
# ---------------------------------------------------------------------------


@router.get("/children", response_model=list[ChildTenantOut])
async def list_child_tenants(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[Tenant]:
    """Return all child tenants of the current parent tenant."""
    result = await db.execute(select(Tenant).where(Tenant.parent_tenant_id == current_user.tenant_id))
    return list(result.scalars().all())


@router.post("/children/{child_id}/onboard", status_code=status.HTTP_200_OK)
async def onboard_child_tenant(
    child_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict[str, str]:
    """Link an existing tenant as a child, if that tenant invited the caller.

    Adoption previously required nothing but an authenticated session and a
    tenant UUID: the only check was a 409 when the target already had a
    parent, so **every standalone tenant on the deployment was adoptable by
    any user**, and adoption is what makes the child-scoped write routes below
    accept you. That is the root of the escalation ``_require_own_child``
    describes — closing those routes alone would not have helped, because an
    attacker could simply adopt the victim first.

    Consent is now required and comes from the child's own side: an admin of
    the tenant being adopted sets ``settings["mssp_parent_invite"]`` to the
    parent's UUID through ``PATCH /api/v1/tenants/me/settings``. The invite is
    single-use — it is cleared here — so a stale value cannot re-adopt a
    tenant that later left.
    """
    child = await db.get(Tenant, child_id)
    if not child:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found")
    if child.id == current_user.tenant_id:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="A tenant cannot be its own parent")
    if child.parent_tenant_id == current_user.tenant_id:
        # Already ours — idempotent, and it must not consume a fresh invite.
        return {"status": "ok", "child_id": str(child_id)}
    if child.parent_tenant_id:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Tenant already has a parent")

    child_settings = dict(child.settings or {})
    invited = str(child_settings.get(_MSSP_INVITE_SETTING) or "")
    if invited != str(current_user.tenant_id):
        # Deliberately does not say whether an invite exists for someone else.
        logger.warning(
            "mssp.onboard.refused_without_invite parent=%s child=%s",
            str(current_user.tenant_id).replace("\r", "").replace("\n", " ")[:64],
            str(child_id).replace("\r", "").replace("\n", " ")[:64],
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "That tenant has not invited you to manage it. An admin of the tenant must set "
                f"settings.{_MSSP_INVITE_SETTING} to your tenant id first."
            ),
        )

    child_settings.pop(_MSSP_INVITE_SETTING, None)
    child.settings = child_settings  # type: ignore[assignment]
    child.parent_tenant_id = current_user.tenant_id  # type: ignore[assignment]
    child.mssp_role = "child"  # type: ignore[assignment]
    parent = await db.get(Tenant, current_user.tenant_id)
    if parent:
        parent.mssp_role = "parent"  # type: ignore[assignment]
    await db.commit()
    return {"status": "ok", "child_id": str(child_id)}


# ---------------------------------------------------------------------------
# Cross-tenant notes
# ---------------------------------------------------------------------------


@router.get("/notes", response_model=list[TenantNoteOut])
async def list_notes(
    child_id: uuid.UUID | None = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[MSSPTenantNote]:
    q = select(MSSPTenantNote).where(MSSPTenantNote.parent_id == current_user.tenant_id)
    if child_id:
        q = q.where(MSSPTenantNote.child_id == child_id)
    q = q.order_by(MSSPTenantNote.created_at.desc())
    result = await db.execute(q)
    return list(result.scalars().all())


@router.post("/notes", response_model=TenantNoteOut, status_code=status.HTTP_201_CREATED)
async def create_note(
    body: TenantNoteCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> MSSPTenantNote:
    await _require_own_child(db, current_user, body.child_id)
    note = MSSPTenantNote(
        parent_id=current_user.tenant_id,
        child_id=body.child_id,
        body=body.body,
        author_id=current_user.id,
    )
    db.add(note)
    await db.commit()
    await db.refresh(note)
    return note


# ---------------------------------------------------------------------------
# Cross-tenant delegations
# ---------------------------------------------------------------------------


@router.get("/delegations", response_model=list[DelegationOut])
async def list_delegations(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[MSSPDelegation]:
    result = await db.execute(
        select(MSSPDelegation)
        .where(
            MSSPDelegation.parent_tenant_id == current_user.tenant_id,
            MSSPDelegation.revoked_at.is_(None),
        )
        .order_by(MSSPDelegation.created_at.desc())
    )
    return list(result.scalars().all())


@router.post("/delegations", response_model=DelegationOut, status_code=status.HTTP_201_CREATED)
async def create_delegation(
    body: DelegationCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> MSSPDelegation:
    await _require_own_child(db, current_user, body.child_tenant_id)
    delegation = MSSPDelegation(
        parent_tenant_id=current_user.tenant_id,
        child_tenant_id=body.child_tenant_id,
        granted_role=body.granted_role,
        granted_by_user=current_user.id,
        expires_at=body.expires_at,
    )
    db.add(delegation)
    await db.commit()
    await db.refresh(delegation)
    return delegation


@router.delete("/delegations/{delegation_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def revoke_delegation(
    delegation_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> None:
    delegation = await db.get(MSSPDelegation, delegation_id)
    if not delegation or delegation.parent_tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="Delegation not found")
    delegation.revoked_at = datetime.now(UTC)  # type: ignore[assignment]
    await db.commit()


# ---------------------------------------------------------------------------
# Tenant rollup metrics
# ---------------------------------------------------------------------------


@router.get("/metrics", response_model=list[MetricsOut])
async def list_metrics(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[MSSPTenantMetrics]:
    """Return the latest metrics snapshot for every child tenant."""
    # Get child tenant ids
    children_result = await db.execute(select(Tenant.id).where(Tenant.parent_tenant_id == current_user.tenant_id))
    child_ids = list(children_result.scalars().all())
    if not child_ids:
        return []

    # Subquery: most recent snapshot per tenant
    subq = (
        select(
            MSSPTenantMetrics.tenant_id,
            MSSPTenantMetrics.snapshot_at,
        )
        .where(MSSPTenantMetrics.tenant_id.in_(child_ids))
        .order_by(MSSPTenantMetrics.tenant_id, MSSPTenantMetrics.snapshot_at.desc())
        .distinct(MSSPTenantMetrics.tenant_id)
        .subquery()
    )

    result = await db.execute(
        select(MSSPTenantMetrics).join(
            subq,
            (MSSPTenantMetrics.tenant_id == subq.c.tenant_id) & (MSSPTenantMetrics.snapshot_at == subq.c.snapshot_at),
        )
    )
    return list(result.scalars().all())


# ---------------------------------------------------------------------------
# MSSP Rule Pack management (parent-only)
# ---------------------------------------------------------------------------

from app.models.detection_rule import DetectionRule  # noqa: E402
from app.models.mssp import (  # noqa: E402
    MSSPRuleOverride,
    MSSPRulePack,
    MSSPRulePackAssignment,
    MSSPRulePackRule,
)
from app.services.mssp_rule_resolver import count_effective_rules, resolve_effective_rules  # noqa: E402


class RulePackCreate(BaseModel):
    name: str
    description: str | None = None
    category: str | None = None
    is_default: bool = False


class RulePackUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    category: str | None = None
    is_default: bool | None = None


class RulePackOut(BaseModel):
    id: uuid.UUID
    name: str
    description: str | None
    category: str | None
    is_default: bool
    created_at: str
    updated_at: str

    model_config = ConfigDict(from_attributes=True)


class RulePackRuleAdd(BaseModel):
    rule_id: uuid.UUID


class PackAssignmentCreate(BaseModel):
    child_tenant_id: uuid.UUID
    enabled: bool = True
    parameter_overrides: dict = {}


class PackAssignmentOut(BaseModel):
    id: uuid.UUID
    pack_id: uuid.UUID
    child_tenant_id: uuid.UUID
    enabled: bool
    parameter_overrides: dict
    created_at: str

    model_config = ConfigDict(from_attributes=True)


class RuleOverrideCreate(BaseModel):
    child_tenant_id: uuid.UUID
    rule_id: uuid.UUID
    action: str  # "exclude" | "customize"
    note: str | None = None
    severity_override: str | None = None
    parameter_overrides: dict = {}


class RuleOverrideOut(BaseModel):
    id: uuid.UUID
    parent_tenant_id: uuid.UUID
    child_tenant_id: uuid.UUID
    rule_id: uuid.UUID
    action: str
    note: str | None
    severity_override: str | None
    parameter_overrides: dict
    created_at: str

    model_config = ConfigDict(from_attributes=True)


class EffectiveRuleOut(BaseModel):
    id: uuid.UUID
    name: str
    rule_language: str
    severity: str
    category: str | None
    status: str
    is_builtin: bool
    source: str
    pack_ids: list[uuid.UUID]
    severity_overridden: bool
    original_severity: str | None
    override_note: str | None
    parameter_overrides: dict

    model_config = ConfigDict(from_attributes=True)


class EffectiveRuleCountOut(BaseModel):
    total: int
    tenant: int
    builtin: int
    pack: int
    excluded: int


#: Key a child tenant's own admin sets in ``tenants.settings`` to consent to
#: being managed, holding the UUID of the parent they are inviting.
#:
#: Consent lives in the child's settings rather than in a new table because
#: ``PATCH /api/v1/tenants/me/settings`` already writes only the caller's own
#: row and is gated on ``settings:write``. That makes the invite unforgeable by
#: construction: the only principal who can name a parent is an admin of the
#: tenant being adopted.
_MSSP_INVITE_SETTING = "mssp_parent_invite"


async def _require_own_child(
    db: AsyncSession,
    current_user: User,
    child_id: uuid.UUID,
) -> Tenant:
    """Return ``child_id`` only if it is a child of the caller's tenant.

    Raises 404 — not 403 — for both "no such tenant" and "not yours", so the
    endpoint cannot be used to enumerate which tenant UUIDs exist.

    This replaces ``_ensure_mssp_parent``, whose body was ``pass``. Four write
    routes took a caller-supplied ``child_tenant_id`` and wrote it straight
    onto a row. The one that mattered was ``create_rule_override``: an override
    with ``action="exclude"`` is read back by
    :func:`app.services.mssp_rule_resolver.resolve_effective_rules`, filtered on
    ``child_tenant_id == <the victim's tenant>``, and pops the rule out of the
    ruleset that `POST /rules/hunt` runs. Any authenticated user of any tenant
    could therefore disable a named detection rule inside any other tenant, and
    the victim's only symptom was a hunt that stopped matching.
    """
    child = await db.get(Tenant, child_id)
    if child is None or child.parent_tenant_id != current_user.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Child tenant not found",
        )
    return child


@router.get("/rule-packs", response_model=list[RulePackOut])
async def list_rule_packs(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[MSSPRulePack]:
    """List all rule packs owned by the current parent tenant."""
    result = await db.execute(
        select(MSSPRulePack).where(MSSPRulePack.parent_tenant_id == current_user.tenant_id).order_by(MSSPRulePack.created_at.desc())
    )
    return list(result.scalars().all())


@router.post("/rule-packs", response_model=RulePackOut, status_code=status.HTTP_201_CREATED)
async def create_rule_pack(
    body: RulePackCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> MSSPRulePack:
    """Create a new rule pack (parent tenant only)."""
    pack = MSSPRulePack(
        parent_tenant_id=current_user.tenant_id,
        name=body.name,
        description=body.description,
        category=body.category,
        is_default=body.is_default,
        created_by_user=current_user.id,
    )
    db.add(pack)
    await db.commit()
    await db.refresh(pack)
    return pack


@router.get("/rule-packs/{pack_id}", response_model=RulePackOut)
async def get_rule_pack(
    pack_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> MSSPRulePack:
    pack = await db.get(MSSPRulePack, pack_id)
    if not pack or pack.parent_tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="Rule pack not found")
    return pack


@router.put("/rule-packs/{pack_id}", response_model=RulePackOut)
async def update_rule_pack(
    pack_id: uuid.UUID,
    body: RulePackUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> MSSPRulePack:
    pack = await db.get(MSSPRulePack, pack_id)
    if not pack or pack.parent_tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="Rule pack not found")
    if body.name is not None:
        pack.name = body.name
    if body.description is not None:
        pack.description = body.description
    if body.category is not None:
        pack.category = body.category
    if body.is_default is not None:
        pack.is_default = body.is_default
    await db.commit()
    await db.refresh(pack)
    return pack


@router.delete("/rule-packs/{pack_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def delete_rule_pack(
    pack_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> None:
    pack = await db.get(MSSPRulePack, pack_id)
    if not pack or pack.parent_tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="Rule pack not found")
    await db.delete(pack)
    await db.commit()


@router.post("/rule-packs/{pack_id}/rules", status_code=status.HTTP_201_CREATED)
async def add_rule_to_pack(
    pack_id: uuid.UUID,
    body: RulePackRuleAdd,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict[str, str]:
    pack = await db.get(MSSPRulePack, pack_id)
    if not pack or pack.parent_tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="Rule pack not found")

    rule = await db.get(DetectionRule, body.rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Detection rule not found")

    link = MSSPRulePackRule(pack_id=pack_id, rule_id=body.rule_id)
    db.add(link)
    await db.commit()
    return {"status": "ok", "pack_id": str(pack_id), "rule_id": str(body.rule_id)}


@router.delete("/rule-packs/{pack_id}/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def remove_rule_from_pack(
    pack_id: uuid.UUID,
    rule_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> None:
    pack = await db.get(MSSPRulePack, pack_id)
    if not pack or pack.parent_tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="Rule pack not found")
    link = await db.get(MSSPRulePackRule, (pack_id, rule_id))
    if link:
        await db.delete(link)
        await db.commit()


@router.post("/rule-packs/{pack_id}/assign", response_model=PackAssignmentOut, status_code=status.HTTP_201_CREATED)
async def assign_pack_to_child(
    pack_id: uuid.UUID,
    body: PackAssignmentCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> MSSPRulePackAssignment:
    pack = await db.get(MSSPRulePack, pack_id)
    if not pack or pack.parent_tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="Rule pack not found")
    # Pack ownership was checked; the assignment target was not, so a pack the
    # caller legitimately owns could be pushed into a tenant they do not.
    await _require_own_child(db, current_user, body.child_tenant_id)

    assignment = MSSPRulePackAssignment(
        pack_id=pack_id,
        child_tenant_id=body.child_tenant_id,
        enabled=body.enabled,
        parameter_overrides=body.parameter_overrides,
    )
    db.add(assignment)
    await db.commit()
    await db.refresh(assignment)
    return assignment


@router.post("/overrides", response_model=RuleOverrideOut, status_code=status.HTTP_201_CREATED)
async def create_rule_override(
    body: RuleOverrideCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> MSSPRuleOverride:
    if body.action not in ("exclude", "customize"):
        raise HTTPException(status_code=422, detail="action must be 'exclude' or 'customize'")
    # The severe one. An "exclude" override is read back by the effective-rule
    # resolver keyed on the *child's* tenant id and removes the rule from the
    # ruleset `POST /rules/hunt` runs for them.
    await _require_own_child(db, current_user, body.child_tenant_id)
    override = MSSPRuleOverride(
        parent_tenant_id=current_user.tenant_id,
        child_tenant_id=body.child_tenant_id,
        rule_id=body.rule_id,
        action=body.action,
        note=body.note,
        severity_override=body.severity_override,
        parameter_overrides=body.parameter_overrides,
        created_by_user=current_user.id,
    )
    db.add(override)
    await db.commit()
    await db.refresh(override)
    return override


@router.get("/overrides", response_model=list[RuleOverrideOut])
async def list_overrides(
    child_id: uuid.UUID | None = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[MSSPRuleOverride]:
    q = select(MSSPRuleOverride).where(
        MSSPRuleOverride.child_tenant_id.in_(select(Tenant.id).where(Tenant.parent_tenant_id == current_user.tenant_id))
    )
    if child_id:
        q = q.where(MSSPRuleOverride.child_tenant_id == child_id)
    result = await db.execute(q.order_by(MSSPRuleOverride.created_at.desc()))
    return list(result.scalars().all())


@router.delete("/overrides/{override_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def delete_override(
    override_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> None:
    override = await db.get(MSSPRuleOverride, override_id)
    if not override:
        raise HTTPException(status_code=404, detail="Override not found")
    child = await db.get(Tenant, override.child_tenant_id)
    if not child or child.parent_tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="Override not found")
    await db.delete(override)
    await db.commit()


# ---------------------------------------------------------------------------
# Effective rules preview (parent views what a child tenant gets)
# ---------------------------------------------------------------------------


@router.get("/children/{child_id}/effective-rules", response_model=list[EffectiveRuleOut])
async def list_effective_rules_for_child(
    child_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    category: str | None = Query(None),
    rule_language: str | None = Query(None),
) -> list[EffectiveRuleOut]:
    """Preview the resolved rule set for a child tenant (parent-only)."""
    child = await db.get(Tenant, child_id)
    if not child or child.parent_tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="Child tenant not found")

    resolved = await resolve_effective_rules(
        db,
        child_id,
        include_builtin=True,
        include_packs=True,
        rule_language=rule_language,
        category=category,
        only_active=False,
    )

    return [
        EffectiveRuleOut(
            id=r.id,
            name=r.name,
            rule_language=r.rule_language,
            severity=r.severity,
            category=r.category,
            status=r.status,
            is_builtin=r.is_builtin,
            source=r.source,
            pack_ids=r.pack_ids,
            severity_overridden=r.severity_overridden,
            original_severity=r.original_severity,
            override_note=r.override_note,
            parameter_overrides=r.parameter_overrides,
        )
        for r in resolved
    ]


@router.get("/children/{child_id}/effective-rules/count", response_model=EffectiveRuleCountOut)
async def count_effective_rules_for_child(
    child_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> EffectiveRuleCountOut:
    """Return source-breakdown counts for a child tenant's effective ruleset."""
    child = await db.get(Tenant, child_id)
    if not child or child.parent_tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="Child tenant not found")

    counts = await count_effective_rules(db, child_id)
    return EffectiveRuleCountOut(**counts)


# ---------------------------------------------------------------------------
# Cross-tenant portfolio surfaces (organisation model, migration 058)
# ---------------------------------------------------------------------------
#
# These three routes used to return five hardcoded companies — "Acme Corp,
# health 92.4, 12 open alerts", "Wayne Enterprises", a list of invented
# incidents with invented assignees — to any authenticated caller. The
# aggregation query behind them was never written. A later change stopped
# short of deleting the sample and instead gated it behind demo mode, which
# removed the lie but left the feature unimplemented: outside demo mode the
# MSSP console showed zeros forever.
#
# They are now computed from real rows in `app.services.mssp_portfolio`. The
# sample is gone from the file rather than gated, because a fabricated
# portfolio has no honest use — an operator evaluating the product needs to
# see their own empty portfolio, not somebody else's fictional one.


async def _scope(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> PortfolioScope:
    """Resolve the caller's managed portfolio, or refuse the surface.

    A principal who belongs to no organisation gets 403 rather than an empty
    list: an empty list would read as "you manage nothing", when the truth
    is that cross-tenant reads are not theirs to make. A member whose
    portfolio is genuinely empty does get empty results, and the payload
    says so explicitly.
    """
    scope = await resolve_portfolio_scope(db, current_user)
    if not scope.is_member:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not a member of an operator organisation",
        )
    return scope


async def _admin_scope(scope: PortfolioScope = Depends(_scope)) -> PortfolioScope:
    if not scope.can_administer:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Organisation owner or admin role required",
        )
    return scope


class LimitHeadroomOut(BaseModel):
    key: str
    label: str
    used: int
    # `None` means uncapped. AiSOC ships with no limits, and a tenant that
    # has none reports `unlimited` rather than a ceiling nobody configured.
    limit: int | None
    remaining: int | None
    pct_used: float | None
    state: str = Field(description="unlimited | ok | warning | exhausted")


class ConnectorHealthOut(BaseModel):
    total: int
    healthy: int
    stale: int
    error: int


class PortfolioTenantOut(BaseModel):
    tenant_id: uuid.UUID
    name: str
    slug: str
    relationship: str
    is_active: bool
    open_alerts: int
    critical_alerts: int
    high_alerts: int
    untriaged_alerts: int
    synthetic_alerts: int = Field(description="Seeded demo rows, counted apart from the figures above.")
    open_cases: int
    sla_breached_cases: int
    mttr_minutes: float | None = Field(
        description="Mean minutes to close, over cases this tenant closed in the trailing 30 days. Null when it closed none."
    )
    connectors: ConnectorHealthOut
    last_event_at: str | None
    limits: list[LimitHeadroomOut]
    limits_exhausted: int
    limits_warning: int


class PortfolioSummaryOut(BaseModel):
    tenants: int
    tenants_active: int
    open_alerts: int
    critical_alerts: int
    high_alerts: int
    untriaged_alerts: int
    synthetic_alerts: int
    open_cases: int
    sla_breached_cases: int
    mttr_minutes: float | None = Field(
        description="Mean of the per-tenant figures, over tenants that closed something. Null when the portfolio closed nothing."
    )
    connectors_total: int
    connectors_healthy: int
    connectors_stale: int
    connectors_error: int
    tenants_with_exhausted_limits: int
    tenants_with_limit_warnings: int
    tenants_without_connectors: int


class PortfolioOut(BaseModel):
    org_id: uuid.UUID | None
    org_slug: str | None
    org_name: str | None
    org_role: str | None
    portfolio_wide: bool = Field(
        description="True when the caller's role reaches the whole portfolio rather than a set of explicit tenant grants."
    )
    # Present so an empty console can explain itself. "You have no tenant
    # grants" and "your organisation manages no tenants" are different
    # problems with different fixes, and a bare zero distinguishes neither.
    scoped_tenants: int
    summary: PortfolioSummaryOut
    tenants: list[PortfolioTenantOut]


class PortfolioAlertOut(BaseModel):
    alert_id: uuid.UUID
    tenant_id: uuid.UUID
    tenant_name: str
    title: str
    severity: str
    status: str
    category: str | None
    created_at: str | None
    event_time: str | None
    case_id: uuid.UUID | None
    is_synthetic: bool


@router.get("/portfolio", response_model=PortfolioOut)
async def get_portfolio(
    tenant_id: list[uuid.UUID] | None = Query(None, description="Restrict to these tenants; ignored if outside the portfolio."),
    scope: PortfolioScope = Depends(_scope),
    db: AsyncSession = Depends(get_db),
) -> PortfolioOut:
    """Managed portfolio: per-tenant posture plus derived totals.

    Every figure is counted from that tenant's own rows. A portfolio with no
    tenants returns zeros and an empty list.
    """
    effective = narrow(scope, tenant_id) if tenant_id else scope

    if effective.is_empty:
        return PortfolioOut(
            org_id=scope.org_id,
            org_slug=scope.org_slug,
            org_name=scope.org_name,
            org_role=scope.org_role,
            portfolio_wide=scope.portfolio_wide,
            scoped_tenants=0,
            summary=PortfolioSummaryOut(**mssp_portfolio.EMPTY_SUMMARY),
            tenants=[],
        )

    rollups = await mssp_portfolio.tenant_rollups(db, effective)
    return PortfolioOut(
        org_id=scope.org_id,
        org_slug=scope.org_slug,
        org_name=scope.org_name,
        org_role=scope.org_role,
        portfolio_wide=scope.portfolio_wide,
        scoped_tenants=len(effective.tenant_ids),
        summary=PortfolioSummaryOut(**mssp_portfolio.summarise(rollups)),
        tenants=[PortfolioTenantOut(**r.as_dict()) for r in rollups],
    )


@router.get("/portfolio/alerts", response_model=list[PortfolioAlertOut])
async def list_portfolio_alerts(
    severity: str | None = Query(None, description="critical | high | medium | low | info"),
    alert_status: str | None = Query(None, alias="status"),
    include_synthetic: bool = Query(False, description="Include seeded demo rows, labelled as such."),
    limit: int = Query(50, ge=1, le=500),
    tenant_id: list[uuid.UUID] | None = Query(None),
    scope: PortfolioScope = Depends(_scope),
    db: AsyncSession = Depends(get_db),
) -> list[PortfolioAlertOut]:
    """Open alerts across the portfolio, newest first."""
    effective = narrow(scope, tenant_id) if tenant_id else scope
    if effective.is_empty:
        return []

    rows = await mssp_portfolio.portfolio_alerts(
        db,
        effective,
        severity=severity,
        status=alert_status,
        include_synthetic=include_synthetic,
        limit=limit,
    )
    return [PortfolioAlertOut(**row) for row in rows]


# The original three paths, kept so existing callers keep working, now
# reading the same real rows as `/portfolio`. Their payloads changed with
# their honesty: `health_score` is gone because it was an undefined
# composite nobody could reproduce, and `avg_mttr_minutes` is now measured
# from cases the tenant actually closed and is null when it closed none.


@router.get("/overview", response_model=PortfolioSummaryOut)
async def mssp_overview(
    scope: PortfolioScope = Depends(_scope),
    db: AsyncSession = Depends(get_db),
) -> PortfolioSummaryOut:
    """Portfolio totals for the operator dashboard."""
    if scope.is_empty:
        return PortfolioSummaryOut(**mssp_portfolio.EMPTY_SUMMARY)
    rollups = await mssp_portfolio.tenant_rollups(db, scope)
    return PortfolioSummaryOut(**mssp_portfolio.summarise(rollups))


@router.get("/tenants", response_model=list[PortfolioTenantOut])
async def list_managed_tenants(
    scope: PortfolioScope = Depends(_scope),
    db: AsyncSession = Depends(get_db),
) -> list[PortfolioTenantOut]:
    """Managed tenants with their measured posture."""
    if scope.is_empty:
        return []
    rollups = await mssp_portfolio.tenant_rollups(db, scope)
    return [PortfolioTenantOut(**r.as_dict()) for r in rollups]


@router.get("/incidents", response_model=list[PortfolioAlertOut])
async def list_cross_tenant_incidents(
    severity: str | None = Query(None, description="critical | high | medium | low | info"),
    limit: int = Query(50, ge=1, le=500),
    scope: PortfolioScope = Depends(_scope),
    db: AsyncSession = Depends(get_db),
) -> list[PortfolioAlertOut]:
    """Open alerts across the portfolio."""
    if scope.is_empty:
        return []
    rows = await mssp_portfolio.portfolio_alerts(db, scope, severity=severity, limit=limit)
    return [PortfolioAlertOut(**row) for row in rows]


# ---------------------------------------------------------------------------
# Organisation administration
# ---------------------------------------------------------------------------


class OrganizationOut(BaseModel):
    id: uuid.UUID
    slug: str
    name: str
    kind: str
    home_tenant_id: uuid.UUID | None
    is_active: bool

    model_config = ConfigDict(from_attributes=True)


class OrganizationCreate(BaseModel):
    slug: str = Field(min_length=2, max_length=64, pattern=r"^[a-z0-9][a-z0-9-]*$")
    name: str = Field(min_length=1, max_length=255)
    kind: str = Field(default="mssp", pattern="^(mssp|enterprise)$")


class MemberOut(BaseModel):
    user_id: uuid.UUID
    email: str
    org_role: str
    granted_tenants: list[uuid.UUID]


class MemberUpsert(BaseModel):
    user_id: uuid.UUID
    org_role: str = Field(default="viewer")


class TenantGrant(BaseModel):
    tenant_ids: list[uuid.UUID]


@router.post("/organizations", response_model=OrganizationOut, status_code=status.HTTP_201_CREATED)
async def create_organization(
    body: OrganizationCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Organization:
    """Create an operator organisation around the caller's own tenant.

    The creator becomes its owner. Available to any authenticated user
    because there is no organisation to be a member of yet — the
    home tenant is taken from the caller's session rather than the body, so
    nobody can found an organisation on top of somebody else's tenant.
    """
    existing = (await db.execute(select(Organization).where(Organization.slug == body.slug))).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(status_code=409, detail="Organisation slug already taken")

    already_home = (
        await db.execute(select(Organization).where(Organization.home_tenant_id == current_user.tenant_id))
    ).scalar_one_or_none()
    if already_home is not None:
        raise HTTPException(status_code=409, detail="This tenant already hosts an organisation")

    org = Organization(
        slug=body.slug,
        name=body.name,
        kind=body.kind,
        home_tenant_id=current_user.tenant_id,
    )
    db.add(org)
    await db.flush()
    db.add(OrganizationMember(org_id=org.id, user_id=current_user.id, org_role="owner"))
    # The operator's own tenant joins its own portfolio, so a provider that
    # also runs an estate sees it in the same rollup as its customers.
    db.add(OrganizationTenant(org_id=org.id, tenant_id=current_user.tenant_id, relationship="own"))
    await db.commit()
    await db.refresh(org)
    return org


@router.get("/organizations/current", response_model=OrganizationOut)
async def get_current_organization(
    scope: PortfolioScope = Depends(_scope),
    db: AsyncSession = Depends(get_db),
) -> Organization:
    org = await db.get(Organization, scope.org_id)
    if org is None:  # pragma: no cover - scope resolution just read this row
        raise HTTPException(status_code=404, detail="Organisation not found")
    return org


@router.post("/organizations/current/tenants", status_code=status.HTTP_200_OK)
async def add_tenants_to_portfolio(
    body: TenantGrant,
    scope: PortfolioScope = Depends(_admin_scope),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict[str, object]:
    """Bring tenants under management.

    A tenant already managed by another organisation is rejected rather than
    reassigned: `organization_tenants` carries a unique constraint on
    `tenant_id` precisely so a customer cannot end up in two portfolios, and
    silently moving one would be a cross-tenant transfer performed by
    whoever asked last.
    """
    added: list[str] = []
    rejected: dict[str, str] = {}

    for tenant_id in body.tenant_ids:
        tenant = await db.get(Tenant, tenant_id)
        if tenant is None:
            rejected[str(tenant_id)] = "tenant not found"
            continue
        claim = (await db.execute(select(OrganizationTenant).where(OrganizationTenant.tenant_id == tenant_id))).scalar_one_or_none()
        if claim is not None:
            rejected[str(tenant_id)] = "already in this portfolio" if claim.org_id == scope.org_id else "managed by another organisation"
            continue
        db.add(
            OrganizationTenant(
                org_id=scope.org_id,
                tenant_id=tenant_id,
                relationship="managed",
                onboarded_by=current_user.id,
            )
        )
        added.append(str(tenant_id))

    await db.commit()
    return {"added": added, "rejected": rejected}


@router.delete("/organizations/current/tenants/{tenant_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def remove_tenant_from_portfolio(
    tenant_id: uuid.UUID,
    scope: PortfolioScope = Depends(_admin_scope),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Release a tenant from management.

    Deletes the portfolio link only. The tenant and all of its data survive
    as a standalone tenant — offboarding a customer from a provider is not
    the same request as erasing them, and conflating the two would make this
    button destructive in a way its label does not say.
    """
    link = (
        await db.execute(
            select(OrganizationTenant).where(
                OrganizationTenant.org_id == scope.org_id,
                OrganizationTenant.tenant_id == tenant_id,
            )
        )
    ).scalar_one_or_none()
    if link is None:
        raise HTTPException(status_code=404, detail="Tenant is not in this portfolio")
    # Per-member grants over this tenant go with it, by foreign key cascade.
    await db.delete(link)
    await db.commit()


@router.get("/organizations/current/members", response_model=list[MemberOut])
async def list_members(
    scope: PortfolioScope = Depends(_admin_scope),
    db: AsyncSession = Depends(get_db),
) -> list[MemberOut]:
    rows = (
        await db.execute(
            select(OrganizationMember, User)
            .join(User, User.id == OrganizationMember.user_id)
            .where(OrganizationMember.org_id == scope.org_id)
            .order_by(User.email)
        )
    ).all()

    grants: dict[uuid.UUID, list[uuid.UUID]] = {}
    for user_id, tenant_id in (
        await db.execute(
            select(OrganizationMemberTenant.user_id, OrganizationMemberTenant.tenant_id).where(
                OrganizationMemberTenant.org_id == scope.org_id
            )
        )
    ).all():
        grants.setdefault(uuid.UUID(str(user_id)), []).append(uuid.UUID(str(tenant_id)))

    return [
        MemberOut(
            user_id=uuid.UUID(str(member.user_id)),
            email=str(user.email),
            org_role=str(member.org_role),
            granted_tenants=sorted(grants.get(uuid.UUID(str(member.user_id)), [])),
        )
        for member, user in rows
    ]


@router.put("/organizations/current/members", response_model=MemberOut)
async def upsert_member(
    body: MemberUpsert,
    scope: PortfolioScope = Depends(_admin_scope),
    db: AsyncSession = Depends(get_db),
) -> MemberOut:
    if body.org_role not in ORG_ROLES:
        raise HTTPException(status_code=422, detail=f"org_role must be one of {', '.join(ORG_ROLES)}")

    user = await db.get(User, body.user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    member = (
        await db.execute(
            select(OrganizationMember).where(
                OrganizationMember.org_id == scope.org_id,
                OrganizationMember.user_id == body.user_id,
            )
        )
    ).scalar_one_or_none()

    if member is None:
        member = OrganizationMember(org_id=scope.org_id, user_id=body.user_id, org_role=body.org_role)
        db.add(member)
    else:
        member.org_role = body.org_role
    await db.commit()

    return MemberOut(
        user_id=uuid.UUID(str(body.user_id)),
        email=str(user.email),
        org_role=body.org_role,
        granted_tenants=[],
    )


@router.put("/organizations/current/members/{user_id}/tenants", response_model=MemberOut)
async def set_member_tenant_grants(
    user_id: uuid.UUID,
    body: TenantGrant,
    scope: PortfolioScope = Depends(_admin_scope),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> MemberOut:
    """Replace which portfolio tenants one member may reach.

    Tenants outside the portfolio are refused here *and* would be refused by
    the database: `organization_member_tenants` has a composite foreign key
    onto `organization_tenants`, so a grant cannot name a tenant the
    organisation does not manage even if this check were removed.
    """
    member = (
        await db.execute(
            select(OrganizationMember).where(
                OrganizationMember.org_id == scope.org_id,
                OrganizationMember.user_id == user_id,
            )
        )
    ).scalar_one_or_none()
    if member is None:
        raise HTTPException(status_code=404, detail="Not a member of this organisation")

    portfolio = {
        uuid.UUID(str(t))
        for t in (await db.execute(select(OrganizationTenant.tenant_id).where(OrganizationTenant.org_id == scope.org_id))).scalars()
    }
    requested = {uuid.UUID(str(t)) for t in body.tenant_ids}
    outside = requested - portfolio
    if outside:
        raise HTTPException(
            status_code=422,
            detail=f"not in this portfolio: {', '.join(sorted(str(t) for t in outside))}",
        )

    existing = (
        await db.execute(
            select(OrganizationMemberTenant).where(
                OrganizationMemberTenant.org_id == scope.org_id,
                OrganizationMemberTenant.user_id == user_id,
            )
        )
    ).scalars()
    for row in existing:
        if uuid.UUID(str(row.tenant_id)) not in requested:
            await db.delete(row)

    held = {
        uuid.UUID(str(t))
        for t in (
            await db.execute(
                select(OrganizationMemberTenant.tenant_id).where(
                    OrganizationMemberTenant.org_id == scope.org_id,
                    OrganizationMemberTenant.user_id == user_id,
                )
            )
        ).scalars()
    }
    for tenant_id in requested - held:
        db.add(
            OrganizationMemberTenant(
                org_id=scope.org_id,
                user_id=user_id,
                tenant_id=tenant_id,
                granted_by=current_user.id,
            )
        )

    await db.commit()

    user = await db.get(User, user_id)
    return MemberOut(
        user_id=user_id,
        email=str(user.email) if user else "",
        org_role=str(member.org_role),
        granted_tenants=sorted(requested),
    )
