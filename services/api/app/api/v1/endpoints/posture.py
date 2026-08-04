"""Cloud Security Posture Management (CSPM/KSPM) endpoints."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.endpoints.auth import get_current_user
from app.db.database import get_db
from app.models.posture import PostureFinding, PostureScanRun
from app.models.tenant import User
from app.services.compliance_mapping import evidence_for_cspm_finding
from app.services.cspm import scan_resources, summarize
from app.services.destinations import (
    build_email_payload,
    build_opsgenie_payload,
    build_soar_handoff_payload,
)

router = APIRouter(prefix="/posture", tags=["posture"])


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class FindingCreate(BaseModel):
    cloud_provider: str
    cloud_account: str | None = None
    cloud_region: str | None = None
    resource_type: str
    resource_id: str
    resource_name: str | None = None
    rule_id: str
    rule_title: str
    description: str | None = None
    severity: str = "medium"
    frameworks: list[str] | None = None
    control_ids: list[str] | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    remediation_guide: str | None = None


class FindingOut(FindingCreate):
    id: uuid.UUID
    tenant_id: uuid.UUID
    status: str
    auto_remediated: bool
    first_detected_at: str
    last_evaluated_at: str
    resolved_at: str | None = None

    model_config = ConfigDict(from_attributes=True)


class ScanRunOut(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    cloud_provider: str
    cloud_account: str | None
    started_at: str
    completed_at: str | None
    status: str
    findings_total: int
    findings_new: int
    findings_closed: int
    error_message: str | None

    model_config = ConfigDict(from_attributes=True)


class SuppressRequest(BaseModel):
    reason: str


class PostureSummary(BaseModel):
    total: int
    critical: int
    high: int
    medium: int
    low: int
    open: int
    resolved: int
    suppressed: int


# ---------------------------------------------------------------------------
# Findings endpoints
# ---------------------------------------------------------------------------


@router.get("/findings", response_model=list[FindingOut])
async def list_findings(
    cloud_provider: str | None = Query(None),
    severity: str | None = Query(None),
    status_filter: str | None = Query(None, alias="status"),
    rule_id: str | None = Query(None),
    limit: int = Query(50, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[PostureFinding]:
    q = select(PostureFinding).where(PostureFinding.tenant_id == current_user.tenant_id)
    if cloud_provider:
        q = q.where(PostureFinding.cloud_provider == cloud_provider)
    if severity:
        q = q.where(PostureFinding.severity == severity)
    if status_filter:
        q = q.where(PostureFinding.status == status_filter)
    if rule_id:
        q = q.where(PostureFinding.rule_id == rule_id)
    q = q.order_by(PostureFinding.last_evaluated_at.desc()).offset(offset).limit(limit)
    result = await db.execute(q)
    return list(result.scalars().all())


@router.post("/findings", response_model=FindingOut, status_code=status.HTTP_201_CREATED)
async def ingest_finding(
    body: FindingCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> PostureFinding:
    finding = PostureFinding(**body.model_dump(), tenant_id=current_user.tenant_id)
    db.add(finding)
    await db.commit()
    await db.refresh(finding)
    return finding


@router.get("/findings/{finding_id}", response_model=FindingOut)
async def get_finding(
    finding_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> PostureFinding:
    f = await db.get(PostureFinding, finding_id)
    if not f or f.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="Finding not found")
    return f


@router.post("/findings/{finding_id}/suppress", response_model=FindingOut)
async def suppress_finding(
    finding_id: uuid.UUID,
    body: SuppressRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> PostureFinding:
    f = await db.get(PostureFinding, finding_id)
    if not f or f.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="Finding not found")
    f.status = "suppressed"  # type: ignore[assignment]
    f.suppressed_at = datetime.now(UTC)  # type: ignore[assignment]
    f.suppressed_by = current_user.id  # type: ignore[assignment]
    f.suppress_reason = body.reason  # type: ignore[assignment]
    await db.commit()
    await db.refresh(f)
    return f


@router.post("/findings/{finding_id}/resolve", response_model=FindingOut)
async def resolve_finding(
    finding_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> PostureFinding:
    f = await db.get(PostureFinding, finding_id)
    if not f or f.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="Finding not found")
    f.status = "resolved"  # type: ignore[assignment]
    f.resolved_at = datetime.now(UTC)  # type: ignore[assignment]
    await db.commit()
    await db.refresh(f)
    return f


@router.get("/summary", response_model=PostureSummary)
async def get_summary(
    cloud_provider: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> PostureSummary:
    q = select(PostureFinding).where(PostureFinding.tenant_id == current_user.tenant_id)
    if cloud_provider:
        q = q.where(PostureFinding.cloud_provider == cloud_provider)
    result = await db.execute(q)
    findings = list(result.scalars().all())

    return PostureSummary(
        total=len(findings),
        critical=sum(1 for f in findings if f.severity == "critical"),
        high=sum(1 for f in findings if f.severity == "high"),
        medium=sum(1 for f in findings if f.severity == "medium"),
        low=sum(1 for f in findings if f.severity == "low"),
        open=sum(1 for f in findings if f.status == "open"),
        resolved=sum(1 for f in findings if f.status == "resolved"),
        suppressed=sum(1 for f in findings if f.status == "suppressed"),
    )


# ---------------------------------------------------------------------------
# Scan runs
# ---------------------------------------------------------------------------


@router.get("/scans", response_model=list[ScanRunOut])
async def list_scans(
    limit: int = Query(20, le=100),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[PostureScanRun]:
    result = await db.execute(
        select(PostureScanRun)
        .where(PostureScanRun.tenant_id == current_user.tenant_id)
        .order_by(PostureScanRun.started_at.desc())
        .offset(offset)
        .limit(limit)
    )
    return list(result.scalars().all())


# ---------------------------------------------------------------------------
# Wave 6 — agentless CSPM scan engine (W6.2) + auto-evidence (W6.1)
# + destination payload preview (W6.3)
# ---------------------------------------------------------------------------


class CspmScanRequest(BaseModel):
    resources: list[dict[str, Any]] = Field(default_factory=list, description="Normalised cloud-resource snapshot.")


class CspmScanResponse(BaseModel):
    findings: list[dict[str, Any]]
    summary: dict[str, int]
    evidence: list[dict[str, Any]]


@router.post("/scan", response_model=CspmScanResponse)
async def cspm_scan(
    body: CspmScanRequest,
    current_user: User = Depends(get_current_user),
) -> CspmScanResponse:
    """Agentless CSPM MVP (W6.2): evaluate a cloud-resource snapshot against the
    misconfiguration checks, returning findings + a severity summary + the
    auto-generated compliance evidence (W6.1). Stateless — the findings store
    endpoints above persist what an operator chooses to keep."""
    findings = scan_resources(body.resources)
    finding_dicts = [f.as_dict() for f in findings]
    evidence: list[dict[str, Any]] = []
    for fd in finding_dicts:
        evidence.extend(r.as_dict() for r in evidence_for_cspm_finding(fd))
    return CspmScanResponse(findings=finding_dicts, summary=summarize(findings), evidence=evidence)


class DestinationPreviewRequest(BaseModel):
    kind: str = Field(..., description="opsgenie | email | webhook")
    alert: dict[str, Any]
    recipients: list[str] = Field(default_factory=list)


@router.post("/destinations/preview")
async def destination_preview(
    body: DestinationPreviewRequest,
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Preview the exact payload a destination would send (W6.3) — no send."""
    if body.kind == "opsgenie":
        return {"kind": "opsgenie", "payload": build_opsgenie_payload(body.alert)}
    if body.kind == "email":
        return {"kind": "email", "payload": build_email_payload(body.alert, body.recipients)}
    if body.kind == "webhook":
        return {"kind": "webhook", "payload": build_soar_handoff_payload(body.alert)}
    raise HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail=f"unknown destination kind: {body.kind}",
    )
