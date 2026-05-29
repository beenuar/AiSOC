"""Compliance evidence trails (tier2-compliance).

Collects, hashes, and reviews audit-grade evidence records for regulatory
frameworks (SOC 2, PCI-DSS, HIPAA, ISO 27001, NIST CSF, …).  Evidence items
form a tamper-evident hash chain — each record's ``payload_hash`` is a
SHA-256 digest of ``prev_hash || summary || raw_payload``.

Endpoints
---------
* ``GET  /compliance/frameworks``          List known frameworks & controls.
* ``POST /compliance/evidence``            Collect a new evidence item.
* ``GET  /compliance/evidence``            List evidence (filter by framework/control/case).
* ``GET  /compliance/evidence/{id}``       Get single evidence item.
* ``POST /compliance/evidence/{id}/review`` Accept or reject an evidence item.
* ``GET  /compliance/report``              Generate a compliance posture report.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import text

from app.api.v1.deps import AuthUser, DBSession

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/compliance", tags=["compliance"])

# ────────────────────────────────────────────────────────────────────────────
# Known frameworks + sampled controls (extendable via DB or config)
# ────────────────────────────────────────────────────────────────────────────

FRAMEWORKS: dict[str, dict[str, str]] = {
    "SOC2": {
        "CC1.1": "Common Criteria — Commitment to Competence",
        "CC6.1": "Logical and Physical Access Controls",
        "CC6.2": "Access Provisioning",
        "CC6.3": "Access Removal",
        "CC7.2": "System Monitoring",
        "CC8.1": "Change Management",
        "A1.1": "Availability — Capacity Management",
    },
    "PCI-DSS": {
        "Req-1": "Install and maintain network security controls",
        "Req-6": "Develop and maintain secure systems",
        "Req-8": "Identify users and authenticate access",
        "Req-10": "Log and monitor all access to system components",
        "Req-11": "Test security of systems and networks regularly",
    },
    "HIPAA": {
        "164.308(a)(1)": "Security Management Process",
        "164.308(a)(5)": "Security Awareness and Training",
        "164.312(b)": "Audit Controls",
        "164.312(d)": "Person or Entity Authentication",
    },
    "ISO27001": {
        "A.12.4.1": "Event Logging",
        "A.12.4.2": "Protection of Log Information",
        "A.16.1.2": "Reporting Information Security Events",
        "A.9.2.1": "User Registration and De-Registration",
    },
    "NIST-CSF": {
        "DE.AE-1": "Baseline of network operations established",
        "DE.CM-1": "Network monitored for potential events",
        "RS.AN-1": "Investigations are performed",
        "RS.MI-2": "Incidents are mitigated",
    },
}

# ────────────────────────────────────────────────────────────────────────────
# Pydantic schemas
# ────────────────────────────────────────────────────────────────────────────

EvidenceKind = Literal["alert", "log", "screenshot", "attestation", "policy", "runbook", "other"]
EvidenceStatus = Literal["pending", "accepted", "rejected"]


class CollectEvidenceRequest(BaseModel):
    framework: str = Field(..., description="Compliance framework key e.g. 'SOC2'.")
    control_id: str = Field(..., description="Control identifier e.g. 'CC7.2'.")
    control_title: str | None = None
    evidence_kind: EvidenceKind = "alert"
    summary: str = Field(..., min_length=5)
    raw_payload: dict[str, Any] = Field(default_factory=dict)
    case_id: uuid.UUID | None = None


class ReviewEvidenceRequest(BaseModel):
    decision: Literal["accepted", "rejected"]
    reviewer: str | None = None


class EvidenceResponse(BaseModel):
    id: uuid.UUID
    case_id: uuid.UUID | None
    framework: str
    control_id: str
    control_title: str | None
    evidence_kind: str
    summary: str
    raw_payload: dict[str, Any]
    payload_hash: str | None
    prev_hash: str | None
    collected_at: datetime
    reviewed_by: str | None
    reviewed_at: datetime | None
    status: str
    created_at: datetime


class FrameworksResponse(BaseModel):
    frameworks: dict[str, dict[str, str]]


class ControlItem(BaseModel):
    control_id: str
    title: str


class ControlsResponse(BaseModel):
    framework_id: str
    controls: list[ControlItem]


class CollectJobRequest(BaseModel):
    framework: str = Field(..., description="Compliance framework key e.g. 'SOC2'.")
    scope: str = Field("full", description="Collection scope: 'full' or 'delta'.")


class CollectJobResponse(BaseModel):
    job_id: uuid.UUID
    framework: str
    scope: str
    status: str
    queued_at: datetime


class CompliancePosture(BaseModel):
    framework: str
    total_evidence: int
    accepted: int
    pending: int
    rejected: int
    coverage_pct: float  # accepted / known controls * 100
    controls_covered: list[str]
    controls_missing: list[str]
    generated_at: datetime


# ────────────────────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────────────────────


def _compute_hash(prev_hash: str | None, summary: str, payload: dict[str, Any]) -> str:
    raw = (prev_hash or "") + summary + json.dumps(payload, sort_keys=True)
    return hashlib.sha256(raw.encode()).hexdigest()


async def _latest_hash(db: DBSession, framework: str, tenant_id: uuid.UUID) -> str | None:
    row = (
        await db.execute(
            text(
                "SELECT payload_hash FROM aisoc_compliance_evidence"
                " WHERE framework = :f AND tenant_id = :tenant_id"
                " ORDER BY created_at DESC LIMIT 1"
            ).bindparams(f=framework, tenant_id=tenant_id)
        )
    ).fetchone()
    return row.payload_hash if row else None


def _row_to_evidence(row: Any) -> EvidenceResponse:
    return EvidenceResponse(
        id=row.id,
        case_id=row.case_id,
        framework=row.framework,
        control_id=row.control_id,
        control_title=row.control_title,
        evidence_kind=row.evidence_kind,
        summary=row.summary,
        raw_payload=dict(row.raw_payload or {}),
        payload_hash=row.payload_hash,
        prev_hash=row.prev_hash,
        collected_at=row.collected_at,
        reviewed_by=row.reviewed_by,
        reviewed_at=row.reviewed_at,
        status=row.status,
        created_at=row.created_at,
    )


# ────────────────────────────────────────────────────────────────────────────
# Endpoints
# ────────────────────────────────────────────────────────────────────────────


@router.get("/frameworks", response_model=FrameworksResponse, summary="List frameworks and controls")
async def list_frameworks() -> FrameworksResponse:
    return FrameworksResponse(frameworks=FRAMEWORKS)


@router.get(
    "/frameworks/{framework_id}/controls",
    response_model=ControlsResponse,
    summary="List controls for a framework",
)
async def list_framework_controls(framework_id: str) -> ControlsResponse:
    controls = FRAMEWORKS.get(framework_id)
    if controls is None:
        raise HTTPException(status_code=404, detail=f"Framework '{framework_id}' not found.")
    return ControlsResponse(
        framework_id=framework_id,
        controls=[ControlItem(control_id=cid, title=title) for cid, title in controls.items()],
    )


@router.post(
    "/evidence/collect",
    response_model=CollectJobResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Trigger evidence collection job",
)
async def trigger_evidence_collection(body: CollectJobRequest) -> CollectJobResponse:
    if body.framework not in FRAMEWORKS:
        raise HTTPException(status_code=404, detail=f"Framework '{body.framework}' not found.")
    return CollectJobResponse(
        job_id=uuid.uuid4(),
        framework=body.framework,
        scope=body.scope,
        status="queued",
        queued_at=datetime.now(UTC),
    )


@router.post("/evidence", response_model=EvidenceResponse, status_code=status.HTTP_201_CREATED, summary="Collect evidence item")
async def collect_evidence(body: CollectEvidenceRequest, db: DBSession, user: AuthUser) -> EvidenceResponse:
    prev_hash = await _latest_hash(db, body.framework, user.tenant_id)
    new_hash = _compute_hash(prev_hash, body.summary, body.raw_payload)
    now = datetime.now(UTC)
    evidence_id = uuid.uuid4()

    q = text("""
        INSERT INTO aisoc_compliance_evidence (
            id, tenant_id, case_id, framework, control_id, control_title,
            evidence_kind, summary, raw_payload, payload_hash, prev_hash,
            collected_at, status, created_at
        ) VALUES (
            :id, :tenant_id, :case_id, :fw, :ctrl, :title,
            :kind, :summary, :payload::jsonb, :hash, :prev,
            :now, 'pending', :now
        ) RETURNING *
    """).bindparams(
        id=evidence_id,
        tenant_id=user.tenant_id,
        case_id=body.case_id,
        fw=body.framework,
        ctrl=body.control_id,
        title=body.control_title or FRAMEWORKS.get(body.framework, {}).get(body.control_id),
        kind=body.evidence_kind,
        summary=body.summary,
        payload=json.dumps(body.raw_payload),
        hash=new_hash,
        prev=prev_hash,
        now=now,
    )
    try:
        row = (await db.execute(q)).fetchone()
        await db.commit()
        return _row_to_evidence(row)
    except Exception as exc:
        await db.rollback()
        logger.exception("Database error in compliance endpoint")
        raise HTTPException(status_code=503, detail="Database error") from exc


@router.get("/evidence", response_model=list[EvidenceResponse], summary="List evidence items")
async def list_evidence(
    db: DBSession,
    user: AuthUser,
    framework: str | None = Query(None),
    control_id: str | None = Query(None),
    case_id: uuid.UUID | None = Query(None),
    ev_status: str | None = Query(None, alias="status"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> list[EvidenceResponse]:
    wheres = ["tenant_id = :tenant_id"]
    params: dict[str, Any] = {"tenant_id": user.tenant_id, "limit": limit, "offset": offset}
    if framework:
        wheres.append("framework = :fw")
        params["fw"] = framework
    if control_id:
        wheres.append("control_id = :ctrl")
        params["ctrl"] = control_id
    if case_id:
        wheres.append("case_id = :case_id")
        params["case_id"] = case_id
    if ev_status:
        wheres.append("status = :ev_status")
        params["ev_status"] = ev_status

    q = text(
        f"SELECT * FROM aisoc_compliance_evidence WHERE {' AND '.join(wheres)} ORDER BY collected_at DESC LIMIT :limit OFFSET :offset"
    ).bindparams(**params)
    try:
        rows = (await db.execute(q)).fetchall()
        return [_row_to_evidence(r) for r in rows]
    except Exception as exc:
        logger.exception("Database error in compliance endpoint")
        raise HTTPException(status_code=503, detail="Database error") from exc


@router.get("/evidence/{evidence_id}", response_model=EvidenceResponse, summary="Get evidence item")
async def get_evidence(evidence_id: uuid.UUID, db: DBSession, user: AuthUser) -> EvidenceResponse:
    row = (
        await db.execute(
            text("SELECT * FROM aisoc_compliance_evidence WHERE id = :id AND tenant_id = :tenant_id").bindparams(
                id=evidence_id, tenant_id=user.tenant_id
            )
        )
    ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Evidence item not found.")
    return _row_to_evidence(row)


@router.post("/evidence/{evidence_id}/review", response_model=EvidenceResponse, summary="Accept or reject evidence")
async def review_evidence(evidence_id: uuid.UUID, body: ReviewEvidenceRequest, db: DBSession, user: AuthUser) -> EvidenceResponse:
    now = datetime.now(UTC)
    q = text("""
        UPDATE aisoc_compliance_evidence
        SET status = :decision, reviewed_by = :reviewer, reviewed_at = :now
        WHERE id = :id AND tenant_id = :tenant_id RETURNING *
    """).bindparams(id=evidence_id, tenant_id=user.tenant_id, decision=body.decision, reviewer=body.reviewer or str(user), now=now)
    try:
        row = (await db.execute(q)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Evidence item not found.")
        await db.commit()
        return _row_to_evidence(row)
    except HTTPException:
        raise
    except Exception as exc:
        await db.rollback()
        logger.exception("Database error in compliance endpoint")
        raise HTTPException(status_code=503, detail="Database error") from exc


@router.get("/report", response_model=list[CompliancePosture], summary="Generate compliance posture report")
async def compliance_report(
    db: DBSession,
    user: AuthUser,
    framework: str | None = Query(None, description="Filter to a single framework."),
) -> list[CompliancePosture]:
    wheres = ["tenant_id = :tenant_id"]
    params: dict[str, Any] = {"tenant_id": user.tenant_id}
    if framework:
        wheres.append("framework = :fw")
        params["fw"] = framework

    q = text(f"""
        SELECT framework, control_id,
               COUNT(*) AS total,
               COUNT(*) FILTER (WHERE status = 'accepted') AS accepted,
               COUNT(*) FILTER (WHERE status = 'pending')  AS pending,
               COUNT(*) FILTER (WHERE status = 'rejected') AS rejected
        FROM aisoc_compliance_evidence
        WHERE {" AND ".join(wheres)}
        GROUP BY framework, control_id
        ORDER BY framework, control_id
    """).bindparams(**params)

    try:
        rows = (await db.execute(q)).fetchall()
    except Exception as exc:
        logger.exception("Database error in compliance endpoint")
        raise HTTPException(status_code=503, detail="Database error") from exc

    # Aggregate by framework
    by_fw: dict[str, Any] = {}
    for r in rows:
        fw = r.framework
        if fw not in by_fw:
            by_fw[fw] = {"total": 0, "accepted": 0, "pending": 0, "rejected": 0, "covered": set()}
        by_fw[fw]["total"] += r.total
        by_fw[fw]["accepted"] += r.accepted
        by_fw[fw]["pending"] += r.pending
        by_fw[fw]["rejected"] += r.rejected
        if r.accepted > 0:
            by_fw[fw]["covered"].add(r.control_id)

    report = []
    target_fws = [framework] if framework else list(by_fw.keys()) + [f for f in FRAMEWORKS if f not in by_fw]
    for fw in dict.fromkeys(target_fws):
        known = FRAMEWORKS.get(fw, {})
        data = by_fw.get(fw, {"total": 0, "accepted": 0, "pending": 0, "rejected": 0, "covered": set()})
        covered = data["covered"]
        missing = [c for c in known if c not in covered]
        pct = (len(covered) / len(known) * 100) if known else 0.0
        report.append(
            CompliancePosture(
                framework=fw,
                total_evidence=data["total"],
                accepted=data["accepted"],
                pending=data["pending"],
                rejected=data["rejected"],
                coverage_pct=round(pct, 1),
                controls_covered=sorted(covered),
                controls_missing=sorted(missing),
                generated_at=datetime.now(UTC),
            )
        )
    return report
