"""Cloud Security Posture Management (CSPM/KSPM) endpoints.

Authorization
-------------
Posture is cloud configuration hygiene, so the writes take ``settings:write``
and the stateless previews take ``settings:read``.

``suppress_finding`` is the one that matters. It writes ``status`` =
``suppressed`` with a reason and stands the finding down, which is a policy
exception over the tenant's own cloud estate — the CSPM equivalent of the
pre-approval GHSA-wj5c-88hg-5926 let a ``viewer`` install. Before this, a
read-only account could suppress every finding in the tenant one id at a
time, and the dashboard would go green.

``cspm_scan`` and ``destination_preview`` persist nothing: one evaluates a
resource snapshot supplied in the request, the other renders the payload a
destination would send. ``settings:read`` rather than the write because
nothing changes, and rather than nothing because they are still features of
an administrative surface that an API key should have to be scoped for.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import CurrentUser, require_permission
from app.api.v1.endpoints.alert_writeback import service_token_valid
from app.api.v1.endpoints.auth import get_current_user
from app.db.database import get_db
from app.models.posture import PostureFinding, PostureScanRun
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
    """Counts, and whether they mean anything.

    Until depth-2 item 8.1 this model was eight bare integers over a table
    whose only writer was the hand-called route above, so every deployment
    that had never POSTed a finding by hand read a confident
    ``total: 0, critical: 0`` — which says "your cloud estate is clean" about
    an estate nobody has looked at.

    ``collected`` is the discriminator. It is derived from
    ``posture_scan_runs``, which a collector writes on every poll including a
    poll that found nothing, so "nobody has collected" and "collected, and the
    estate is clean" stop being the same answer. When it is false the counts
    are ``None`` rather than ``0``: a renderer cannot accidentally display an
    absent measurement as a reassuring number.
    """

    collected: bool
    last_collected_at: str | None = None
    sources: list[str] = Field(default_factory=list)
    total: int | None = None
    critical: int | None = None
    high: int | None = None
    medium: int | None = None
    low: int | None = None
    open: int | None = None
    resolved: int | None = None
    suppressed: int | None = None


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
    current_user: CurrentUser = Depends(get_current_user),
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
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(require_permission("settings:write"))],
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
    current_user: CurrentUser = Depends(get_current_user),
) -> PostureFinding:
    f = await db.get(PostureFinding, finding_id)
    if not f or f.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="Finding not found")
    return f


@router.post("/findings/{finding_id}/suppress", response_model=FindingOut)
async def suppress_finding(
    finding_id: uuid.UUID,
    body: SuppressRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(require_permission("settings:write"))],
) -> PostureFinding:
    f = await db.get(PostureFinding, finding_id)
    if not f or f.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="Finding not found")
    f.status = "suppressed"  # type: ignore[assignment]
    f.suppressed_at = datetime.now(UTC)  # type: ignore[assignment]
    f.suppressed_by = current_user.user_id  # type: ignore[assignment]
    f.suppress_reason = body.reason  # type: ignore[assignment]
    await db.commit()
    await db.refresh(f)
    return f


@router.post("/findings/{finding_id}/resolve", response_model=FindingOut)
async def resolve_finding(
    finding_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(require_permission("settings:write"))],
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
    current_user: CurrentUser = Depends(get_current_user),
) -> PostureSummary:
    runs = (
        (
            await db.execute(
                select(PostureScanRun)
                .where(PostureScanRun.tenant_id == current_user.tenant_id)
                .order_by(PostureScanRun.started_at.desc())
                .limit(50)
            )
        )
        .scalars()
        .all()
    )

    q = select(PostureFinding).where(PostureFinding.tenant_id == current_user.tenant_id)
    if cloud_provider:
        q = q.where(PostureFinding.cloud_provider == cloud_provider)
    result = await db.execute(q)
    findings = list(result.scalars().all())

    # A hand-POSTed finding is evidence that somebody collected, even though
    # no run row exists for it. Without this an operator who uses the REST
    # route — the only writer this table had for its whole life — would be
    # told their own findings do not count as a measurement.
    if not runs and not findings:
        return PostureSummary(collected=False)

    last = max((r.started_at for r in runs), default=None)
    return PostureSummary(
        collected=True,
        last_collected_at=last.isoformat() if last else None,
        sources=sorted({str(r.source) for r in runs}),
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
# Internal: posture context for a verdict
# ---------------------------------------------------------------------------


class ResourceFinding(BaseModel):
    finding_class: str
    severity: str
    rule_title: str
    resource_name: str | None
    resource_type: str
    source: str
    cloud_provider: str
    first_detected_at: str
    matched_key: str


class ResourceFindingsResponse(BaseModel):
    """What is already known to be wrong with the resources an alert touched.

    ``collected`` carries the same discriminator as the summary, for the same
    reason: an empty ``findings`` list on a tenant with no CNAPP connected
    means "nobody has looked", and a prompt that renders that as "no findings
    on this resource" has told the model something false.
    """

    collected: bool
    findings: list[ResourceFinding] = Field(default_factory=list)
    matched_resources: int = 0


@router.get(
    "/resource-findings",
    response_model=ResourceFindingsResponse,
    include_in_schema=False,
    summary="Cloud-security findings on these resources, for the agents service",
)
async def resource_findings_for_triage(
    tenant_id: uuid.UUID,
    resources: Annotated[list[str], Query()],
    db: Annotated[AsyncSession, Depends(get_db)],
    limit: Annotated[int, Query(ge=1, le=25)] = 5,
    x_aisoc_service_token: Annotated[str | None, Header()] = None,
) -> ResourceFindingsResponse:
    """Posture context keyed on the resource, for triage.

    Depth-2 item 8.1. Distinct from ``/findings`` above, which is the console's
    tenant-wide list: this answers the one question a verdict has, which is
    whether the resource in front of it is already known to be misconfigured
    or already carrying a runtime detection.

    Service-token only, and ``tenant_id`` is the scope rather than a narrowing
    of one, for the same reasons as the sibling internal routes. The resource
    keys come from the alert, which is attacker-influenced text, so they are
    only ever bound as parameters and are matched against a stored array —
    never interpolated, and never used to widen the tenant predicate.
    """
    if not service_token_valid(x_aisoc_service_token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="this route is reachable only by an AiSOC service holding the shared service token",
        )

    keys = sorted({r.strip().lower() for r in resources if r and r.strip()})[:25]

    collected = bool((await db.execute(select(PostureScanRun.id).where(PostureScanRun.tenant_id == tenant_id).limit(1))).first())
    if not keys:
        return ResourceFindingsResponse(collected=collected)

    rows = (
        (
            await db.execute(
                select(PostureFinding)
                .where(
                    PostureFinding.tenant_id == tenant_id,
                    PostureFinding.status == "open",
                    PostureFinding.resource_keys.overlap(keys),
                )
                .order_by(PostureFinding.last_seen_at.desc())
                .limit(limit)
            )
        )
        .scalars()
        .all()
    )

    findings: list[ResourceFinding] = []
    for row in rows:
        stored = [str(k) for k in (row.resource_keys or [])]
        matched = next((k for k in stored if k in keys), "")
        findings.append(
            ResourceFinding(
                finding_class=str(row.finding_class),
                severity=str(row.severity),
                rule_title=str(row.rule_title),
                resource_name=row.resource_name,
                resource_type=str(row.resource_type),
                source=str(row.source),
                cloud_provider=str(row.cloud_provider),
                first_detected_at=row.first_detected_at.isoformat(),
                matched_key=matched,
            )
        )

    return ResourceFindingsResponse(
        collected=collected or bool(findings),
        findings=findings,
        matched_resources=len({f.matched_key for f in findings if f.matched_key}),
    )


# ---------------------------------------------------------------------------
# Scan runs
# ---------------------------------------------------------------------------


@router.get("/scans", response_model=list[ScanRunOut])
async def list_scans(
    limit: int = Query(20, le=100),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
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
    current_user: Annotated[CurrentUser, Depends(require_permission("settings:read"))],
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
    current_user: Annotated[CurrentUser, Depends(require_permission("settings:read"))],
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
