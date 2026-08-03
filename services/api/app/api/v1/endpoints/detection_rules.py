"""Detection rule management endpoints."""

import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import and_, or_, select, update

from app.api.v1.deps import AuthUser, DBSession, require_permission
from app.models.detection_rule import DetectionRule
from app.services.backtest import backtest_rule, build_backtest_sql, rows_to_events
from app.services.mssp_rule_resolver import resolve_effective_rules
from app.services.rule_engine import execute_rule, run_hunt

router = APIRouter(prefix="/rules", tags=["detection_rules"])


class BacktestRequest(BaseModel):
    """Backtest a rule over historical lake events."""

    window_days: int = Field(30, ge=1, le=365, description="How many days of history to scan.")
    limit: int = Field(5000, ge=1, le=100_000, description="Max events to scan.")
    source: str | None = Field(None, description="Optional connector_type filter (e.g. 'okta_system_log').")


class BacktestResponse(BaseModel):
    rule_id: uuid.UUID
    rule_language: str
    window_days: int
    events_scanned: int
    would_fire: int
    hit_rate: float
    sample_matches: list[dict[str, Any]]
    error: str | None = None


async def _fetch_lake_events(tenant_id: uuid.UUID, *, window_days: int, limit: int, source: str | None) -> list[dict[str, Any]]:
    """Fetch tenant-scoped historical events from the ClickHouse lake."""
    from app.db.clickhouse import execute_lake_query  # noqa: PLC0415 — optional lake backend
    from app.services.lake_sql import rewrite_for_tenant  # noqa: PLC0415

    sql = build_backtest_sql(window_days=window_days, limit=limit, source=source)
    rewrite = rewrite_for_tenant(sql, tenant_id, row_cap=limit)
    result = await execute_lake_query(rewrite.sql, timeout_seconds=30)
    return rows_to_events(result.columns, result.rows)


class DetectionRuleResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID | None
    name: str
    description: str | None
    rule_language: str
    rule_body: str
    category: str
    status: str
    severity: str
    confidence: int
    mitre_tactics: list
    mitre_techniques: list
    fp_rate: float
    total_hits: int
    last_triggered: datetime | None
    tags: list
    is_builtin: bool
    version: int
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class CreateRuleRequest(BaseModel):
    name: str
    description: str | None = None
    rule_language: str
    rule_body: str
    category: str
    severity: str = "medium"
    confidence: int = 50
    mitre_tactics: list[str] = []
    mitre_techniques: list[str] = []
    tags: list[str] = []


class UpdateRuleRequest(BaseModel):
    name: str | None = None
    description: str | None = None
    rule_body: str | None = None
    status: str | None = None
    severity: str | None = None
    confidence: int | None = None
    tags: list[str] | None = None


@router.get("", response_model=list[DetectionRuleResponse])
async def list_rules(
    current_user: Annotated[AuthUser, Depends(require_permission("rules:read"))],
    db: DBSession,
    category: str | None = Query(default=None),
    rule_language: str | None = Query(default=None),
    include_builtin: bool = Query(default=True),
    include_packs: bool = Query(default=True),
) -> list[DetectionRuleResponse]:
    """List detection rules for the tenant.

    Returns the tenant's own rules, plus optionally platform-wide built-in
    rules and rules sourced from MSSP-assigned rule packs (with excluded
    overrides removed).
    """
    from app.models.mssp import (
        MSSPRuleOverride,
        MSSPRulePackAssignment,
        MSSPRulePackRule,
    )

    tid = current_user.tenant_id

    conditions = [DetectionRule.tenant_id == tid]

    if include_builtin:
        conditions = [
            or_(
                DetectionRule.tenant_id == tid,
                and_(DetectionRule.tenant_id.is_(None), DetectionRule.is_builtin.is_(True)),
            )
        ]

    if include_packs:
        pack_rule_ids = (
            select(MSSPRulePackRule.rule_id)
            .join(MSSPRulePackAssignment, MSSPRulePackAssignment.pack_id == MSSPRulePackRule.pack_id)
            .where(
                MSSPRulePackAssignment.child_tenant_id == tid,
                MSSPRulePackAssignment.enabled.is_(True),
            )
        )
        conditions = [
            or_(
                *conditions,
                DetectionRule.id.in_(pack_rule_ids),
            )
        ]

    excluded_ids = select(MSSPRuleOverride.rule_id).where(MSSPRuleOverride.child_tenant_id == tid, MSSPRuleOverride.action == "exclude")
    filters = [and_(*conditions), DetectionRule.id.notin_(excluded_ids)]

    if category:
        filters.append(DetectionRule.category == category)
    if rule_language:
        filters.append(DetectionRule.rule_language == rule_language)

    result = await db.execute(select(DetectionRule).where(and_(*filters)).order_by(DetectionRule.name))
    rules = result.scalars().all()
    return [DetectionRuleResponse.model_validate(r) for r in rules]


@router.post("", response_model=DetectionRuleResponse, status_code=status.HTTP_201_CREATED)
async def create_rule(
    request: CreateRuleRequest,
    current_user: Annotated[AuthUser, Depends(require_permission("rules:write"))],
    db: DBSession,
) -> DetectionRuleResponse:
    """Create a new detection rule."""
    rule = DetectionRule(
        tenant_id=current_user.tenant_id,
        name=request.name,
        description=request.description,
        rule_language=request.rule_language,
        rule_body=request.rule_body,
        category=request.category,
        severity=request.severity,
        confidence=request.confidence,
        mitre_tactics=request.mitre_tactics,
        mitre_techniques=request.mitre_techniques,
        tags=request.tags,
        created_by_id=current_user.user_id,
    )
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    return DetectionRuleResponse.model_validate(rule)


@router.get("/{rule_id}", response_model=DetectionRuleResponse)
async def get_rule(
    rule_id: uuid.UUID,
    current_user: Annotated[AuthUser, Depends(require_permission("rules:read"))],
    db: DBSession,
) -> DetectionRuleResponse:
    """Get a detection rule by ID."""
    result = await db.execute(
        select(DetectionRule).where(
            DetectionRule.id == rule_id,
            or_(
                DetectionRule.tenant_id == current_user.tenant_id,
                DetectionRule.tenant_id.is_(None),
            ),
        )
    )
    rule = result.scalar_one_or_none()
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")
    return DetectionRuleResponse.model_validate(rule)


@router.patch("/{rule_id}", response_model=DetectionRuleResponse)
async def update_rule(
    rule_id: uuid.UUID,
    request: UpdateRuleRequest,
    current_user: Annotated[AuthUser, Depends(require_permission("rules:write"))],
    db: DBSession,
) -> DetectionRuleResponse:
    """Update a detection rule (only tenant-owned rules)."""
    result = await db.execute(
        select(DetectionRule).where(
            DetectionRule.id == rule_id,
            DetectionRule.tenant_id == current_user.tenant_id,
        )
    )
    rule = result.scalar_one_or_none()
    if rule is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rule not found or cannot be modified",
        )

    updates: dict = {}
    for field in ["name", "description", "rule_body", "status", "severity", "confidence", "tags"]:
        val = getattr(request, field, None)
        if val is not None:
            updates[field] = val

    if updates:
        updates["updated_at"] = datetime.now(UTC)
        updates["version"] = rule.version + 1
        await db.execute(update(DetectionRule).where(DetectionRule.id == rule_id).values(**updates))
        await db.commit()
        await db.refresh(rule)

    return DetectionRuleResponse.model_validate(rule)


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def delete_rule(
    rule_id: uuid.UUID,
    current_user: Annotated[AuthUser, Depends(require_permission("rules:write"))],
    db: DBSession,
) -> None:
    """Delete a tenant-owned detection rule."""
    result = await db.execute(
        select(DetectionRule).where(
            DetectionRule.id == rule_id,
            DetectionRule.tenant_id == current_user.tenant_id,
        )
    )
    rule = result.scalar_one_or_none()
    if rule is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rule not found or cannot be deleted",
        )
    await db.delete(rule)
    await db.commit()


# ─── Rule Execution Endpoint ──────────────────────────────────────────────────


class ExecuteRuleRequest(BaseModel):
    """Payload for ad-hoc rule execution."""

    events: list[dict[str, Any]] = Field(..., description="Events to test the rule against", max_length=1000)


class ExecuteRuleResponse(BaseModel):
    rule_id: str
    rule_name: str
    rule_language: str
    severity: str
    matched: bool
    match_count: int
    matched_events: list[dict[str, Any]]
    score: float
    error: str | None
    execution_time_ms: float


@router.post(
    "/{rule_id}/execute",
    response_model=ExecuteRuleResponse,
    summary="Execute a detection rule against provided events",
)
async def execute_detection_rule(
    rule_id: uuid.UUID,
    request: ExecuteRuleRequest,
    current_user: Annotated[AuthUser, Depends(require_permission("rules:read"))],
    db: DBSession,
) -> ExecuteRuleResponse:
    """
    Execute a single detection rule against a set of events and return matches.
    Useful for testing rules in the detection IDE before enabling them.
    """
    result = await db.execute(
        select(DetectionRule).where(
            DetectionRule.id == rule_id,
            or_(
                DetectionRule.tenant_id == current_user.tenant_id,
                DetectionRule.tenant_id.is_(None),
            ),
        )
    )
    rule = result.scalar_one_or_none()
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")

    match = execute_rule(
        rule_id=str(rule.id),
        rule_name=rule.name,
        rule_language=rule.rule_language,
        rule_body=rule.rule_body,
        severity=rule.severity,
        events=request.events,
    )

    # Update hit stats if matched
    if match.matched:
        await db.execute(
            update(DetectionRule)
            .where(DetectionRule.id == rule_id)
            .values(
                total_hits=DetectionRule.total_hits + len(match.match_details.get("matched_events", [])),
                last_triggered=datetime.now(UTC),
            )
        )
        await db.commit()

    matched_events = match.match_details.get("matched_events", [])
    return ExecuteRuleResponse(
        rule_id=str(rule.id),
        rule_name=rule.name,
        rule_language=rule.rule_language,
        severity=rule.severity,
        matched=match.matched,
        match_count=len(matched_events),
        matched_events=matched_events,
        score=match.score,
        error=match.error,
        execution_time_ms=match.execution_time_ms,
    )


# ─── Hunt Endpoint ────────────────────────────────────────────────────────────


class HuntRequest(BaseModel):
    """Payload for threat hunting across events."""

    rule_ids: list[uuid.UUID] | None = Field(None, description="Specific rule IDs to hunt with; omit to use all active rules")
    rule_language: str | None = Field(None, description="Filter rules by language (sigma, yara, kql, eql)")
    events: list[dict[str, Any]] = Field(..., description="Events to hunt through", max_length=5000)


class HuntResponse(BaseModel):
    hunt_id: str
    rules_evaluated: int
    rules_matched: int
    total_events_scanned: int
    matched_events: list[dict[str, Any]]
    match_summary: list[dict[str, Any]]
    execution_time_ms: float
    errors: list[str]


@router.post(
    "/hunt",
    response_model=HuntResponse,
    summary="Threat hunt: run detection rules against a set of events",
)
async def hunt(
    request: HuntRequest,
    current_user: Annotated[AuthUser, Depends(require_permission("rules:read"))],
    db: DBSession,
) -> HuntResponse:
    """
    Run multiple detection rules against provided events (threat hunting).

    The effective rule set is resolved through
    :func:`app.services.mssp_rule_resolver.resolve_effective_rules`, which layers:

      1. Tenant-owned rules
      2. Platform-wide built-in rules
      3. Rules sourced from MSSP-assigned rule packs
      4. Per-tenant exclude / customize overrides

    If ``rule_ids`` is omitted, all active rules in the resolved set are used.
    """
    resolved = await resolve_effective_rules(
        db,
        current_user.tenant_id,
        rule_ids=request.rule_ids,
        rule_language=request.rule_language,
        only_active=True,
    )

    if not resolved:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No active detection rules found matching the criteria",
        )

    rule_dicts = [r.to_engine_dict() for r in resolved]

    hunt_result = await run_hunt(
        tenant_id=str(current_user.tenant_id),
        rules=rule_dicts,
        events=request.events,
    )

    return HuntResponse(
        hunt_id=hunt_result.hunt_id,
        rules_evaluated=hunt_result.rules_evaluated,
        rules_matched=hunt_result.rules_matched,
        total_events_scanned=hunt_result.total_events_scanned,
        matched_events=hunt_result.matched_events,
        match_summary=hunt_result.match_summary,
        execution_time_ms=hunt_result.execution_time_ms,
        errors=hunt_result.errors,
    )


@router.post(
    "/{rule_id}/backtest",
    response_model=BacktestResponse,
    summary="Backtest a detection rule against historical lake events",
)
async def backtest_detection_rule(
    rule_id: uuid.UUID,
    request: BacktestRequest,
    current_user: Annotated[AuthUser, Depends(require_permission("rules:read"))],
    db: DBSession,
) -> BacktestResponse:
    """Run a rule over the last N days of REAL events in the ClickHouse lake and
    report exactly how many would have fired (Wave 2). Tenant-scoped via
    ``lake_sql.rewrite_for_tenant``. Read-only."""
    from app.db.clickhouse import LakeQueryNotConfiguredError  # noqa: PLC0415

    rule = (
        await db.execute(
            select(DetectionRule).where(
                and_(
                    DetectionRule.id == rule_id,
                    or_(DetectionRule.tenant_id == current_user.tenant_id, DetectionRule.tenant_id.is_(None)),
                )
            )
        )
    ).scalar_one_or_none()
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Detection rule not found")

    try:
        events = await _fetch_lake_events(
            current_user.tenant_id,
            window_days=request.window_days,
            limit=request.limit,
            source=request.source,
        )
    except LakeQueryNotConfiguredError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="lake backend not configured") from exc
    except Exception as exc:  # noqa: BLE001 — surface a lake failure as 502, not 500
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=f"lake query failed: {exc}") from exc

    summary = backtest_rule(rule_language=rule.rule_language, rule_body=rule.rule_body, events=events)
    return BacktestResponse(
        rule_id=rule_id,
        rule_language=rule.rule_language,
        window_days=request.window_days,
        **summary,
    )
