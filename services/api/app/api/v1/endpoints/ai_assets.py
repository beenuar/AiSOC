"""Read the observed AI estate, and record an operator's judgement about it.

Depth plan 6.1.

Three routes: list, one asset, and a sanction decision. The list is what the
console page renders; the sanction route is the only write, and it writes one
tri-state field.

Why reads require a permission here when most reads in this service do not
--------------------------------------------------------------------------
This inventory names which coding agent on which laptop belongs to which
person and which provider key it holds. That is a target list, and a session
that can read alerts should not automatically get it. ``ai_estate:read`` is
held by the five working roles; ``ai_estate:write`` by the two that govern.

Why there is no create route
----------------------------
Rows arrive from observation — the fusion recorder writes them from AI
runtime, endpoint and provider-audit telemetry. A create route would let the
inventory be populated by hand, and an inventory a human can type into stops
answering the question it exists to answer, which is "what is running that
nobody told us about". The declaration surface already exists and is
``/api/v1/mcp-servers``.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select, update

from app.api.v1.deps import CurrentUser, require_permission
from app.db.rls import TenantDBSession
from app.models.ai_asset import AI_ASSET_KINDS, AiAsset
from app.services.ai_estate_collectors import collect_hosted_agents, scan_repositories_for_ai_config
from app.services.ai_inventory import score_risk

logger = structlog.get_logger()

router = APIRouter(prefix="/ai-assets", tags=["ai-estate"])

_MAX_PAGE = 200


class AiAssetModel(BaseModel):
    """One asset as the console sees it."""

    id: str
    kind: str
    externalId: str
    displayName: str | None = None
    vendor: str | None = None
    discoverySource: str
    # Null means "not learned", and the console must render that differently
    # from a blank: an asset nobody is accountable for is the finding.
    principal: str | None = None
    device: str | None = None
    effectivePermissions: dict[str, Any] | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)
    risk: int
    riskReasons: list[str] = Field(default_factory=list)
    sanctioned: bool | None = None
    firstSeen: str
    lastSeen: str
    observationCount: int


class AiAssetListResponse(BaseModel):
    items: list[AiAssetModel]
    total: int
    # Stated rather than inferred from an empty list. A tenant with no AI
    # telemetry and a tenant whose AI estate is genuinely empty look
    # identical in the rows, and only one of them is a reason to go looking.
    observedSources: list[str] = Field(default_factory=list)


class SanctionRequest(BaseModel):
    sanctioned: bool | None = Field(
        ...,
        description="true = approved, false = reviewed and refused, null = back to undecided. The three are distinct.",
    )
    note: str | None = Field(None, max_length=500)


def _to_model(row: AiAsset) -> AiAssetModel:
    return AiAssetModel(
        id=str(row.id),
        kind=row.kind,
        externalId=row.external_id,
        displayName=row.display_name,
        vendor=row.vendor,
        discoverySource=row.discovery_source,
        principal=row.principal,
        device=row.device,
        effectivePermissions=row.effective_permissions,
        attributes=row.attributes or {},
        risk=row.risk_score,
        riskReasons=list(row.risk_reasons or []),
        sanctioned=row.sanctioned,
        firstSeen=row.first_seen_at.isoformat(),
        lastSeen=row.last_seen_at.isoformat(),
        observationCount=row.observation_count,
    )


@router.get("", response_model=AiAssetListResponse)
async def list_ai_assets(
    db: TenantDBSession,
    current_user: Annotated[CurrentUser, Depends(require_permission("ai_estate:read"))],
    kind: Annotated[str | None, Query(description="Filter to one asset kind.")] = None,
    unlinked: Annotated[bool, Query(description="Only assets with no person linked.")] = False,
    limit: Annotated[int, Query(ge=1, le=_MAX_PAGE)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> AiAssetListResponse:
    """The estate, newest sighting first."""
    if kind is not None and kind not in AI_ASSET_KINDS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unknown kind {kind!r}. Known kinds: {', '.join(AI_ASSET_KINDS)}.",
        )

    stmt = select(AiAsset).where(AiAsset.tenant_id == current_user.tenant_id)
    if kind is not None:
        stmt = stmt.where(AiAsset.kind == kind)
    if unlinked:
        stmt = stmt.where(AiAsset.principal.is_(None))

    rows = (await db.execute(stmt.order_by(AiAsset.last_seen_at.desc()).limit(limit).offset(offset))).scalars().all()

    # Counted independently of the page rather than from len(rows), which
    # would report the page size as the total on every page but the last.
    count_stmt = select(AiAsset.id).where(AiAsset.tenant_id == current_user.tenant_id)
    if kind is not None:
        count_stmt = count_stmt.where(AiAsset.kind == kind)
    if unlinked:
        count_stmt = count_stmt.where(AiAsset.principal.is_(None))
    total = len((await db.execute(count_stmt)).scalars().all())

    source_rows = await db.execute(select(AiAsset.discovery_source).where(AiAsset.tenant_id == current_user.tenant_id).distinct())
    sources = sorted(set(source_rows.scalars().all()))

    return AiAssetListResponse(items=[_to_model(r) for r in rows], total=total, observedSources=sources)


@router.get("/{asset_id}", response_model=AiAssetModel)
async def get_ai_asset(
    asset_id: uuid.UUID,
    db: TenantDBSession,
    current_user: Annotated[CurrentUser, Depends(require_permission("ai_estate:read"))],
) -> AiAssetModel:
    row = (
        await db.execute(select(AiAsset).where(AiAsset.id == asset_id, AiAsset.tenant_id == current_user.tenant_id))
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="AI asset not found")
    return _to_model(row)


@router.post("/{asset_id}/sanction", response_model=AiAssetModel)
async def sanction_ai_asset(
    asset_id: uuid.UUID,
    payload: SanctionRequest,
    db: TenantDBSession,
    current_user: Annotated[CurrentUser, Depends(require_permission("ai_estate:write"))],
) -> AiAssetModel:
    """Approve an asset, refuse it, or put it back to undecided.

    The risk score is recomputed here rather than left stale, through the
    same `score_risk` the recorder calls, because the sanction decision is
    one of its inputs: an asset that has just been refused and is still
    running is a different exposure from one nobody had looked at.
    """
    row = (
        await db.execute(select(AiAsset).where(AiAsset.id == asset_id, AiAsset.tenant_id == current_user.tenant_id))
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="AI asset not found")

    score, reasons = score_risk(
        kind=row.kind,
        principal=row.principal,
        device=row.device,
        sanctioned=payload.sanctioned,
        attributes=row.attributes or {},
        effective_permissions=row.effective_permissions,
    )
    attributes = dict(row.attributes or {})
    if payload.note:
        attributes["sanction_note"] = payload.note

    await db.execute(
        update(AiAsset)
        .where(AiAsset.id == asset_id, AiAsset.tenant_id == current_user.tenant_id)
        .values(sanctioned=payload.sanctioned, risk_score=score, risk_reasons=reasons, attributes=attributes)
    )
    await db.commit()

    logger.info(
        "ai_asset.sanctioned",
        asset_id=str(asset_id),
        kind=row.kind,
        sanctioned=payload.sanctioned,
        actor=str(current_user.user_id),
    )

    row.sanctioned = payload.sanctioned
    row.risk_score = score
    row.risk_reasons = reasons
    row.attributes = attributes
    return _to_model(row)


# ---------------------------------------------------------------------------
# Discovery (wave-2 7.2)
#
# Both routes are read-only against the vendor — the plan's rule for this
# phase — and both write their findings through the one `score_risk`.
# Explicit rather than scheduled, for the same reason the chat-compliance
# collector is: each reaches a third party with the tenant's own
# credential.
# ---------------------------------------------------------------------------


class HostedAgentScanRequest(BaseModel):
    adminKey: str = Field(..., min_length=8, description="Provider admin key. Used for this call and not stored.")


class RepositoryScanRequest(BaseModel):
    """Files a code-platform connector has already fetched.

    The console passes what the connector read rather than this service
    cloning anything: the connector already holds the tenant's code-platform
    credential and the governed read path, and a second fetcher here would
    be a second place that credential has to live.
    """

    repositories: dict[str, dict[str, str]] = Field(
        ...,
        description="repository -> {path: content}. Only recognised AI artefact paths are read.",
    )


class ScanResponse(BaseModel):
    assets: int
    errors: list[str] = Field(default_factory=list)
    skipped: dict[str, str] = Field(default_factory=dict)


@router.post("/scan/hosted-agents", response_model=ScanResponse)
async def scan_hosted_agents(
    payload: HostedAgentScanRequest,
    db: TenantDBSession,
    current_user: Annotated[CurrentUser, Depends(require_permission("ai_estate:write"))],
) -> ScanResponse:
    """Inventory the agents configured in a provider's control plane.

    These are invisible to every other discovery path: endpoint telemetry
    never sees them, and gateway telemetry sees their traffic without
    knowing what they were configured to do.
    """
    result = await collect_hosted_agents(db, current_user.tenant_id, payload.adminKey)
    logger.info(
        "ai_estate.hosted_agent_scan",
        tenant_id=str(current_user.tenant_id),
        actor=str(current_user.user_id),
        assets=result.assets,
    )
    return ScanResponse(assets=result.assets, errors=result.errors, skipped=result.skipped)


@router.post("/scan/repositories", response_model=ScanResponse)
async def scan_repositories(
    payload: RepositoryScanRequest,
    db: TenantDBSession,
    current_user: Annotated[CurrentUser, Depends(require_permission("ai_estate:write"))],
) -> ScanResponse:
    """Record the agent instructions, skills and MCP config a repository carries.

    Everything read here is attacker-controlled: these files are checked
    in, editable by anyone who can land a pull request, and read by an
    agent verbatim as instructions. `ai_repo_scan` sanitises and caps every
    excerpt and runs the prompt-injection patterns over the content at
    capture, storing matched pattern *names* and never the matching text —
    see that module's header.
    """
    result = await scan_repositories_for_ai_config(db, current_user.tenant_id, payload.repositories)
    logger.info(
        "ai_estate.repository_scan",
        tenant_id=str(current_user.tenant_id),
        actor=str(current_user.user_id),
        repositories=len(payload.repositories),
        assets=result.assets,
    )
    return ScanResponse(assets=result.assets, errors=result.errors, skipped=result.skipped)
