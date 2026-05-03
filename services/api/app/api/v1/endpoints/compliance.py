"""Compliance API endpoints.

GET  /api/v1/compliance/soc2                      — SOC 2 summary + control list with evidence
POST /api/v1/compliance/soc2/collect              — Trigger auto-evidence collection
GET  /api/v1/compliance/soc2/export               — PDF-ready JSON export
GET  /api/v1/compliance/{framework}               — Generic framework dashboard
GET  /api/v1/compliance/{framework}/heatmap       — Heatmap data (category × status)
POST /api/v1/compliance/{framework}/collect       — Auto-collect evidence for any framework
GET  /api/v1/compliance/{framework}/export        — PDF-ready export for any framework
GET  /api/v1/compliance/frameworks                — List all available frameworks
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import func, select

from app.api.v1.deps import AuthUser, require_permission
from app.db.rls import TenantDBSession
from app.models.compliance import ComplianceControl, ComplianceEvidence
from app.services.compliance import auto_collect_evidence, get_soc2_summary

router = APIRouter(prefix="/compliance", tags=["compliance"])

# ---------------------------------------------------------------------------
# Supported frameworks
# ---------------------------------------------------------------------------

SUPPORTED_FRAMEWORKS: dict[str, str] = {
    "soc2": "SOC 2 Type II",
    "iso27001": "ISO/IEC 27001:2022",
    "nist_csf": "NIST Cybersecurity Framework 2.0",
    "pci_dss": "PCI DSS v4.0",
    "hipaa": "HIPAA Security Rule",
    "dora": "DORA (Digital Operational Resilience Act)",
}

# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class ControlOut(BaseModel):
    id: str
    framework: str
    control_id: str
    category: str
    title: str
    description: str | None


class EvidenceOut(BaseModel):
    id: str
    control_id: str
    evidence_type: str
    title: str
    description: str | None
    status: str
    collected_at: str


class ControlWithEvidence(BaseModel):
    control: ControlOut
    evidence: list[EvidenceOut]
    latest_status: str


class FrameworkSummary(BaseModel):
    total: int
    collected: int
    review: int
    approved: int
    rejected: int
    missing: int
    pct: int


class FrameworkResponse(BaseModel):
    framework: str
    framework_name: str
    summary: FrameworkSummary
    controls: list[ControlWithEvidence]


class SOC2Summary(BaseModel):
    total: int
    collected: int
    review: int
    approved: int
    rejected: int
    pct: int


class SOC2Response(BaseModel):
    summary: SOC2Summary
    controls: list[ControlWithEvidence]


class HeatmapCell(BaseModel):
    category: str
    status: str
    count: int


class HeatmapResponse(BaseModel):
    framework: str
    framework_name: str
    categories: list[str]
    statuses: list[str]
    cells: list[HeatmapCell]


class FrameworkInfo(BaseModel):
    id: str
    name: str
    control_count: int


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


async def _get_framework_data(
    db: TenantDBSession,
    tenant_id: uuid.UUID,
    framework: str,
) -> tuple[list[ComplianceControl], dict[uuid.UUID, list[ComplianceEvidence]]]:
    """Fetch controls and grouped evidence for a framework."""
    ctrl_result = await db.execute(
        select(ComplianceControl)
        .where(ComplianceControl.framework == framework)
        .order_by(ComplianceControl.control_id)
    )
    controls = ctrl_result.scalars().all()

    ev_result = await db.execute(
        select(ComplianceEvidence)
        .where(
            ComplianceEvidence.tenant_id == tenant_id,
        )
        .join(ComplianceControl, ComplianceEvidence.control_id == ComplianceControl.id)
        .where(ComplianceControl.framework == framework)
        .order_by(ComplianceEvidence.collected_at.desc())
    )
    all_evidence = ev_result.scalars().all()

    ev_by_control: dict[uuid.UUID, list[ComplianceEvidence]] = {}
    for ev in all_evidence:
        ev_by_control.setdefault(ev.control_id, []).append(ev)

    return controls, ev_by_control


def _build_controls_with_evidence(
    controls: list[ComplianceControl],
    ev_by_control: dict[uuid.UUID, list[ComplianceEvidence]],
    max_evidence: int = 5,
) -> list[ControlWithEvidence]:
    result = []
    for ctrl in controls:
        evs = ev_by_control.get(ctrl.id, [])
        latest_status = evs[0].status if evs else "missing"
        result.append(
            ControlWithEvidence(
                control=ControlOut(
                    id=str(ctrl.id),
                    framework=ctrl.framework,
                    control_id=ctrl.control_id,
                    category=ctrl.category,
                    title=ctrl.title,
                    description=ctrl.description,
                ),
                evidence=[
                    EvidenceOut(
                        id=str(e.id),
                        control_id=str(e.control_id),
                        evidence_type=e.evidence_type,
                        title=e.title,
                        description=e.description,
                        status=e.status,
                        collected_at=e.collected_at.isoformat(),
                    )
                    for e in evs[:max_evidence]
                ],
                latest_status=latest_status,
            )
        )
    return result


def _compute_summary(controls_with_ev: list[ControlWithEvidence]) -> dict:
    total = len(controls_with_ev)
    status_counts: dict[str, int] = {}
    for cwev in controls_with_ev:
        s = cwev.latest_status
        status_counts[s] = status_counts.get(s, 0) + 1
    collected = sum(status_counts.get(s, 0) for s in ("collected", "approved"))
    return {
        "total": total,
        "collected": collected,
        "review": status_counts.get("review", 0),
        "approved": status_counts.get("approved", 0),
        "rejected": status_counts.get("rejected", 0),
        "missing": status_counts.get("missing", 0),
        "pct": int(collected / total * 100) if total else 0,
    }


# ---------------------------------------------------------------------------
# Utility: list all frameworks
# ---------------------------------------------------------------------------


@router.get("/frameworks", response_model=list[FrameworkInfo])
async def list_frameworks(
    current_user: Annotated[AuthUser, Depends(require_permission("compliance:read"))],
    db: TenantDBSession,
) -> list[FrameworkInfo]:
    """Return all supported compliance frameworks with control counts."""
    result = await db.execute(
        select(ComplianceControl.framework, func.count(ComplianceControl.id).label("cnt"))
        .group_by(ComplianceControl.framework)
    )
    counts = {row.framework: row.cnt for row in result}

    return [
        FrameworkInfo(
            id=fw_id,
            name=fw_name,
            control_count=counts.get(fw_id, 0),
        )
        for fw_id, fw_name in SUPPORTED_FRAMEWORKS.items()
        if counts.get(fw_id, 0) > 0 or fw_id in counts
    ]


# ---------------------------------------------------------------------------
# SOC 2 dedicated routes (kept for backward-compat)
# ---------------------------------------------------------------------------


@router.get("/soc2", response_model=SOC2Response)
async def get_soc2_dashboard(
    current_user: Annotated[AuthUser, Depends(require_permission("compliance:read"))],
    db: TenantDBSession,
) -> SOC2Response:
    """Return SOC 2 evidence dashboard for the current tenant."""
    controls, ev_by_control = await _get_framework_data(
        db, current_user.tenant_id, "soc2"
    )
    controls_with_evidence = _build_controls_with_evidence(controls, ev_by_control)
    summary = await get_soc2_summary(db, current_user.tenant_id)

    return SOC2Response(
        summary=SOC2Summary(**summary),
        controls=controls_with_evidence,
    )


@router.post("/soc2/collect", status_code=202)
async def collect_soc2_evidence(
    current_user: Annotated[AuthUser, Depends(require_permission("compliance:write"))],
    db: TenantDBSession,
) -> dict:
    """Trigger automatic evidence collection for all SOC 2 controls."""
    collected = await auto_collect_evidence(db, current_user.tenant_id, framework="soc2")
    await db.commit()

    return {
        "message": f"Collected {len(collected)} evidence items",
        "count": len(collected),
        "collected_at": datetime.utcnow().isoformat(),
    }


@router.get("/soc2/export")
async def export_soc2_evidence(
    current_user: Annotated[AuthUser, Depends(require_permission("compliance:read"))],
    db: TenantDBSession,
) -> dict:
    """Export SOC 2 evidence as structured JSON for PDF generation."""
    controls, ev_by_control = await _get_framework_data(
        db, current_user.tenant_id, "soc2"
    )
    controls_with_evidence = _build_controls_with_evidence(controls, ev_by_control, max_evidence=3)
    summary = await get_soc2_summary(db, current_user.tenant_id)

    return {
        "report_type": "SOC 2 Type I Evidence Report",
        "generated_at": datetime.utcnow().isoformat(),
        "tenant_id": str(current_user.tenant_id),
        "summary": summary,
        "controls": [
            {
                "control_id": cwev.control.control_id,
                "category": cwev.control.category,
                "title": cwev.control.title,
                "description": cwev.control.description,
                "evidence": [
                    {
                        "type": e.evidence_type,
                        "title": e.title,
                        "description": e.description,
                        "status": e.status,
                        "collected_at": e.collected_at,
                    }
                    for e in cwev.evidence
                ],
                "latest_status": cwev.latest_status,
            }
            for cwev in controls_with_evidence
        ],
    }


# ---------------------------------------------------------------------------
# Generic framework routes
# ---------------------------------------------------------------------------


def _validate_framework(framework: str) -> None:
    if framework not in SUPPORTED_FRAMEWORKS:
        raise HTTPException(
            status_code=404,
            detail=f"Framework '{framework}' not found. Supported: {list(SUPPORTED_FRAMEWORKS.keys())}",
        )


@router.get("/{framework}", response_model=FrameworkResponse)
async def get_framework_dashboard(
    framework: str,
    current_user: Annotated[AuthUser, Depends(require_permission("compliance:read"))],
    db: TenantDBSession,
) -> FrameworkResponse:
    """Return compliance dashboard for the given framework."""
    _validate_framework(framework)

    controls, ev_by_control = await _get_framework_data(
        db, current_user.tenant_id, framework
    )
    controls_with_evidence = _build_controls_with_evidence(controls, ev_by_control)
    summary_dict = _compute_summary(controls_with_evidence)

    return FrameworkResponse(
        framework=framework,
        framework_name=SUPPORTED_FRAMEWORKS[framework],
        summary=FrameworkSummary(**summary_dict),
        controls=controls_with_evidence,
    )


@router.get("/{framework}/heatmap", response_model=HeatmapResponse)
async def get_framework_heatmap(
    framework: str,
    current_user: Annotated[AuthUser, Depends(require_permission("compliance:read"))],
    db: TenantDBSession,
) -> HeatmapResponse:
    """Return heatmap data (category × status counts) for the given framework."""
    _validate_framework(framework)

    controls, ev_by_control = await _get_framework_data(
        db, current_user.tenant_id, framework
    )
    controls_with_evidence = _build_controls_with_evidence(controls, ev_by_control)

    # Build category × status matrix
    cell_map: dict[tuple[str, str], int] = {}
    categories_ordered: list[str] = []
    for cwev in controls_with_evidence:
        cat = cwev.control.category
        st = cwev.latest_status
        cell_map[(cat, st)] = cell_map.get((cat, st), 0) + 1
        if cat not in categories_ordered:
            categories_ordered.append(cat)

    statuses = ["approved", "collected", "review", "rejected", "missing"]

    cells = [
        HeatmapCell(category=cat, status=st, count=cell_map.get((cat, st), 0))
        for cat in categories_ordered
        for st in statuses
    ]

    return HeatmapResponse(
        framework=framework,
        framework_name=SUPPORTED_FRAMEWORKS[framework],
        categories=categories_ordered,
        statuses=statuses,
        cells=cells,
    )


@router.post("/{framework}/collect", status_code=202)
async def collect_framework_evidence(
    framework: str,
    current_user: Annotated[AuthUser, Depends(require_permission("compliance:write"))],
    db: TenantDBSession,
) -> dict:
    """Trigger automatic evidence collection for the given framework."""
    _validate_framework(framework)

    collected = await auto_collect_evidence(
        db, current_user.tenant_id, framework=framework
    )
    await db.commit()

    return {
        "framework": framework,
        "message": f"Collected {len(collected)} evidence items",
        "count": len(collected),
        "collected_at": datetime.utcnow().isoformat(),
    }


@router.get("/{framework}/export")
async def export_framework_evidence(
    framework: str,
    current_user: Annotated[AuthUser, Depends(require_permission("compliance:read"))],
    db: TenantDBSession,
) -> dict:
    """Export compliance evidence for the given framework as structured JSON."""
    _validate_framework(framework)

    controls, ev_by_control = await _get_framework_data(
        db, current_user.tenant_id, framework
    )
    controls_with_evidence = _build_controls_with_evidence(controls, ev_by_control, max_evidence=3)
    summary_dict = _compute_summary(controls_with_evidence)

    return {
        "report_type": f"{SUPPORTED_FRAMEWORKS[framework]} Evidence Report",
        "framework": framework,
        "framework_name": SUPPORTED_FRAMEWORKS[framework],
        "generated_at": datetime.utcnow().isoformat(),
        "tenant_id": str(current_user.tenant_id),
        "summary": summary_dict,
        "controls": [
            {
                "control_id": cwev.control.control_id,
                "category": cwev.control.category,
                "title": cwev.control.title,
                "description": cwev.control.description,
                "evidence": [
                    {
                        "type": e.evidence_type,
                        "title": e.title,
                        "description": e.description,
                        "status": e.status,
                        "collected_at": e.collected_at,
                    }
                    for e in cwev.evidence
                ],
                "latest_status": cwev.latest_status,
            }
            for cwev in controls_with_evidence
        ],
    }
