"""MSSP parent-tenant console endpoints."""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.endpoints.auth import get_current_user
from app.core.config import settings
from app.db.database import get_db
from app.models.mssp import MSSPDelegation, MSSPTenantMetrics, MSSPTenantNote
from app.models.tenant import Tenant, User

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
# Cross-tenant dashboard rollups (mock data for UI)
# ---------------------------------------------------------------------------


class MSSPKpiOverview(BaseModel):
    total_tenants: int
    total_open_alerts: int
    total_critical_incidents: int
    avg_health_score: float
    avg_mttr_minutes: float
    sla_breach_count: int
    connectors_online: int
    connectors_degraded: int

    model_config = ConfigDict(from_attributes=True)


class ManagedTenantRow(BaseModel):
    tenant_id: str
    name: str
    health_score: float
    open_alerts: int
    critical_alerts: int
    sla_breaches: int
    connector_status: str
    last_event_at: str

    model_config = ConfigDict(from_attributes=True)


class CrossTenantIncident(BaseModel):
    incident_id: str
    tenant_name: str
    title: str
    severity: str
    status: str
    created_at: str
    assignee: str | None = None

    model_config = ConfigDict(from_attributes=True)


_MSSP_TENANTS_MOCK = [
    ManagedTenantRow(
        tenant_id="t-acme",
        name="Acme Corp",
        health_score=92.4,
        open_alerts=12,
        critical_alerts=1,
        sla_breaches=0,
        connector_status="healthy",
        last_event_at="2026-05-07T20:31:00Z",
    ),
    ManagedTenantRow(
        tenant_id="t-globex",
        name="Globex Industries",
        health_score=78.1,
        open_alerts=34,
        critical_alerts=3,
        sla_breaches=2,
        connector_status="degraded",
        last_event_at="2026-05-07T20:28:00Z",
    ),
    ManagedTenantRow(
        tenant_id="t-initech",
        name="Initech LLC",
        health_score=95.7,
        open_alerts=5,
        critical_alerts=0,
        sla_breaches=0,
        connector_status="healthy",
        last_event_at="2026-05-07T20:30:00Z",
    ),
    ManagedTenantRow(
        tenant_id="t-wayne",
        name="Wayne Enterprises",
        health_score=64.3,
        open_alerts=58,
        critical_alerts=7,
        sla_breaches=4,
        connector_status="degraded",
        last_event_at="2026-05-07T20:25:00Z",
    ),
    ManagedTenantRow(
        tenant_id="t-stark",
        name="Stark Solutions",
        health_score=88.9,
        open_alerts=9,
        critical_alerts=1,
        sla_breaches=0,
        connector_status="healthy",
        last_event_at="2026-05-07T20:29:00Z",
    ),
]

_MSSP_INCIDENTS_MOCK = [
    CrossTenantIncident(
        incident_id="INC-4201",
        tenant_name="Wayne Enterprises",
        title="Ransomware lateral movement detected",
        severity="high",
        status="investigating",
        created_at="2026-05-07T19:45:00Z",
        assignee="Jordan Lee",
    ),
    CrossTenantIncident(
        incident_id="INC-4198",
        tenant_name="Globex Industries",
        title="Suspicious OAuth token abuse in Azure AD",
        severity="high",
        status="investigating",
        created_at="2026-05-07T18:12:00Z",
        assignee="Morgan Chen",
    ),
    CrossTenantIncident(
        incident_id="INC-4195",
        tenant_name="Wayne Enterprises",
        title="Data exfiltration via DNS tunneling",
        severity="high",
        status="contained",
        created_at="2026-05-07T16:30:00Z",
        assignee="Alex Rivera",
    ),
    CrossTenantIncident(
        incident_id="INC-4192",
        tenant_name="Acme Corp",
        title="Brute-force against VPN gateway",
        severity="medium",
        status="resolved",
        created_at="2026-05-07T14:20:00Z",
        assignee="Taylor Kim",
    ),
    CrossTenantIncident(
        incident_id="INC-4189",
        tenant_name="Globex Industries",
        title="Compromised service account in GCP",
        severity="high",
        status="investigating",
        created_at="2026-05-07T12:55:00Z",
        assignee=None,
    ),
]


# The three rollup routes below have no implementation behind them — the
# cross-tenant aggregation query was never written. They returned the
# hardcoded rows above to *authenticated* callers with no demo check and no
# marker, so "Acme Corp, health 92.4, 12 open alerts" was indistinguishable
# from a measurement. Fabricated security posture presented as real is the one
# thing this project will not ship.
#
# They now serve that sample only in demo mode, and return empty outside it.
# An empty rollup is the truthful answer: nothing has been aggregated.


def _mssp_sample_allowed() -> bool:
    return bool(settings.AISOC_DEMO_MODE)


@router.get("/overview", response_model=MSSPKpiOverview)
async def mssp_overview(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> MSSPKpiOverview:
    """Cross-tenant KPI summary for the MSSP parent dashboard.

    Not yet implemented against real data. Returns zeros outside demo mode
    rather than the sample figures, because a dashboard reading 23.4 minutes
    MTTR that nobody measured is worse than one reading nothing.
    """
    if not _mssp_sample_allowed():
        return MSSPKpiOverview(
            total_tenants=0,
            total_open_alerts=0,
            total_critical_incidents=0,
            avg_health_score=0.0,
            avg_mttr_minutes=0.0,
            sla_breach_count=0,
            connectors_online=0,
            connectors_degraded=0,
        )
    tenants = _MSSP_TENANTS_MOCK
    return MSSPKpiOverview(
        total_tenants=len(tenants),
        total_open_alerts=sum(t.open_alerts for t in tenants),
        total_critical_incidents=sum(t.critical_alerts for t in tenants),
        avg_health_score=round(sum(t.health_score for t in tenants) / len(tenants), 1),
        avg_mttr_minutes=23.4,
        sla_breach_count=sum(t.sla_breaches for t in tenants),
        connectors_online=3,
        connectors_degraded=2,
    )


@router.get("/tenants", response_model=list[ManagedTenantRow])
async def list_managed_tenants(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[ManagedTenantRow]:
    """List managed tenants with health scores for the parent dashboard.

    Empty outside demo mode. `GET /api/v1/mssp/children` is the route backed
    by real rows.
    """
    if not _mssp_sample_allowed():
        return []
    return _MSSP_TENANTS_MOCK


@router.get("/incidents", response_model=list[CrossTenantIncident])
async def list_cross_tenant_incidents(
    severity: str | None = Query(None, description="Filter: high | medium | low"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[CrossTenantIncident]:
    """Critical incidents across all managed tenants. Empty outside demo mode."""
    if not _mssp_sample_allowed():
        return []
    incidents = _MSSP_INCIDENTS_MOCK
    if severity:
        incidents = [i for i in incidents if i.severity == severity]
    return incidents
