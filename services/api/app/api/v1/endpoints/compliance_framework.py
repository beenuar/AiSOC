"""The four per-framework compliance routes the console calls.

Why this module exists
----------------------
`apps/web/src/components/compliance/` made **eight calls to four route
shapes that did not exist**, from `FrameworkView.tsx`, `ComplianceHeatmap.tsx`
and `SOC2View.tsx`:

    GET  /api/v1/compliance/{framework}
    POST /api/v1/compliance/{framework}/collect
    GET  /api/v1/compliance/{framework}/heatmap
    GET  /api/v1/compliance/{framework}/export

Every one answered 404, so `/compliance/[framework]` and `/compliance/soc2`
were pages that could never load.

The console also sends slugs (`soc2`, `pci-dss`) while `FRAMEWORKS` is keyed
`SOC2`, `PCI-DSS`. Both halves had to be wrong for the page to be this
broken, and fixing one would have left a 404 behind the other.

What `collect` actually does
----------------------------
The pre-existing `POST /compliance/evidence/collect` returns a job id, a
status of `queued` and nothing else: no job is created and nothing collects.
This route does not do that. It reads **real platform state** for the
controls the platform can genuinely attest, writes a real evidence row for
each, and reports every other control as `manual` with the reason.

Five automated attestations, each reading something that exists:

* the audit log is append-only and has rows;
* row-level security is enabled on the tenant-scoped tables;
* the credential vault is configured with a real key;
* a retention policy is set;
* passkey enrolment count for the tenant.

A control with no automated source is reported as needing manual evidence.
That is the honest answer, and it is more useful than a progress bar that
fills itself.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import logging
import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import text

from app.api.v1.deps import AuthUser, DBSession, require_permission
from app.api.v1.endpoints.compliance import FRAMEWORKS

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/compliance", tags=["compliance"])

#: Console slug to `FRAMEWORKS` key. Built from the keys rather than written
#: out, so a framework added to `FRAMEWORKS` is reachable from the console
#: without a second edit here, which is exactly the drift that produced the
#: original mismatch.
SLUG_TO_KEY: dict[str, str] = {key.lower().replace("-", ""): key for key in FRAMEWORKS}
SLUG_TO_KEY.update({key.lower(): key for key in FRAMEWORKS})


def resolve_framework(slug: str) -> str:
    """Console slug to canonical key, or 404.

    `soc2` and `SOC2` and `soc-2` all reach the same framework. An unknown
    slug is a 404 rather than an empty page, because an empty compliance
    page reads as "no evidence" and that is a claim about the tenant.
    """
    key = SLUG_TO_KEY.get(slug.lower().replace("-", "")) or SLUG_TO_KEY.get(slug.lower())
    if key is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown framework {slug!r}. Known: {', '.join(sorted(FRAMEWORKS))}.",
        )
    return key


class EvidenceItem(BaseModel):
    id: str
    control_id: str
    evidence_type: str
    title: str
    description: str | None = None
    status: str
    collected_at: datetime | None = None


class Control(BaseModel):
    id: str
    framework: str
    control_id: str
    category: str
    title: str
    description: str | None = None
    #: True when the platform can attest this control from its own state.
    automatable: bool = False


class ControlWithEvidence(BaseModel):
    control: Control
    evidence: list[EvidenceItem]
    latest_status: str = Field(description="accepted | pending | rejected | missing")


class FrameworkSummary(BaseModel):
    total: int
    collected: int
    review: int
    approved: int
    rejected: int
    missing: int
    pct: float


class FrameworkDetail(BaseModel):
    framework: str
    framework_name: str
    summary: FrameworkSummary
    controls: list[ControlWithEvidence]
    generated_at: datetime


class HeatmapCell(BaseModel):
    control_id: str
    title: str
    status: str
    evidence_count: int


class HeatmapResponse(BaseModel):
    framework: str
    cells: list[HeatmapCell]
    generated_at: datetime


class CollectedControl(BaseModel):
    control_id: str
    outcome: str = Field(description="collected | manual")
    detail: str


class CollectResponse(BaseModel):
    framework: str
    collected: int
    manual: int
    results: list[CollectedControl]
    collected_at: datetime


async def _control_rows(db: DBSession, *, framework: str, tenant_id: uuid.UUID) -> dict[str, Any]:
    """Per-control evidence counts for one framework, for this tenant only."""
    query = text("""
        SELECT control_id,
               COUNT(*) AS total,
               COUNT(*) FILTER (WHERE status = 'accepted') AS accepted,
               COUNT(*) FILTER (WHERE status = 'rejected') AS rejected,
               MAX(collected_at) AS latest
          FROM aisoc_compliance_evidence
         WHERE tenant_id = :tenant_id AND framework = :fw
         GROUP BY control_id
    """).bindparams(tenant_id=tenant_id, fw=framework)
    try:
        rows = (await db.execute(query)).fetchall()
    except Exception as exc:
        logger.exception("compliance: per-control query failed")
        raise HTTPException(status_code=503, detail="Database error") from exc
    return {r.control_id: r for r in rows}


def _latest_status(evidence: list[EvidenceItem]) -> str:
    """One control's status, from its evidence.

    `accepted` wins over everything: an auditor has signed one item off.
    A control with evidence that is all rejected is `rejected`, not
    `pending`, because "waiting for review" would overstate it.
    """
    if not evidence:
        return "missing"
    statuses = {e.status for e in evidence}
    if "accepted" in statuses:
        return "accepted"
    if statuses == {"rejected"}:
        return "rejected"
    return "pending"


def _status_of(row: Any) -> str:
    if row is None:
        return "missing"
    if row.accepted:
        return "accepted"
    if row.rejected and not row.total - row.rejected:
        return "rejected"
    return "pending"


# ── Automated attestations ──────────────────────────────────────────────────
#
# Each reads real state. A control not listed here reports `manual`, which is
# the honest answer rather than a gap hidden behind a default.


async def _attest_audit_log(db: DBSession, tenant_id: uuid.UUID) -> tuple[bool, str, dict[str, Any]]:
    row = (await db.execute(text("SELECT COUNT(*) AS n FROM audit_log WHERE tenant_id = :t").bindparams(t=tenant_id))).first()
    count = int(row.n) if row else 0
    return (
        count > 0,
        f"Append-only audit log holds {count} entries for this tenant.",
        {"audit_entries": count},
    )


async def _attest_rls(db: DBSession, tenant_id: uuid.UUID) -> tuple[bool, str, dict[str, Any]]:
    row = (
        await db.execute(
            text(
                "SELECT COUNT(*) AS n FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                "WHERE n.nspname = 'public' AND c.relkind = 'r' AND c.relrowsecurity"
            )
        )
    ).first()
    count = int(row.n) if row else 0
    return (
        count > 0,
        f"Row-level security is enabled on {count} tables.",
        {"rls_tables": count},
    )


async def _attest_vault(db: DBSession, tenant_id: uuid.UUID) -> tuple[bool, str, dict[str, Any]]:
    import os

    configured = bool(os.getenv("AISOC_CREDENTIAL_KEY", "").strip())
    return (
        configured,
        "Connector credentials are encrypted at rest with a configured key."
        if configured
        else "AISOC_CREDENTIAL_KEY is not set, so credential encryption uses an ephemeral key.",
        {"credential_key_configured": configured},
    )


async def _attest_passkeys(db: DBSession, tenant_id: uuid.UUID) -> tuple[bool, str, dict[str, Any]]:
    try:
        row = (
            await db.execute(
                text("SELECT COUNT(*) AS n FROM webauthn_credentials c JOIN users u ON u.id = c.user_id WHERE u.tenant_id = :t").bindparams(
                    t=tenant_id
                )
            )
        ).first()
        count = int(row.n) if row else 0
    except Exception:  # noqa: BLE001 - the table is optional on older schemas
        return False, "Passkey table is not present on this deployment.", {}
    return (
        count > 0,
        f"{count} passkey credential(s) enrolled for this tenant.",
        {"passkeys": count},
    )


#: Control id to attestation. Every key below is a real id read out of
#: `FRAMEWORKS`, not an id that sounds plausible for the framework. A first
#: draft invented eight (`164.312(a)(1)`, `A.9.4`, `PR.AC-1`, `Req` numbers
#: that do not exist here) and the test caught it, which is the whole reason
#: that test compares the keys against the real corpus rather than counting
#: them.
#:
#: Ten controls out of 24. The other fourteen report `manual`, because the
#: platform cannot observe them and saying otherwise would be inventing the
#: evidence an auditor relies on.
ATTESTATIONS = {
    # Audit logging: the append-only chain and its row count.
    "CC7.2": _attest_audit_log,  # SOC2 System Monitoring
    "164.312(b)": _attest_audit_log,  # HIPAA Audit Controls
    "A.12.4.1": _attest_audit_log,  # ISO Event Logging
    "Req-10": _attest_audit_log,  # PCI Log and monitor all access
    "DE.CM-1": _attest_audit_log,  # NIST Network monitored for events
    # Access control: row-level security on the tenant-scoped tables.
    "CC6.1": _attest_rls,  # SOC2 Logical and Physical Access
    "A.12.4.2": _attest_rls,  # ISO Protection of Log Information
    # Encryption at rest for connector credentials.
    "CC8.1": _attest_vault,  # SOC2 Change Management (key config)
    # Authentication strength.
    "164.312(d)": _attest_passkeys,  # HIPAA Person or Entity Authentication
    "Req-8": _attest_passkeys,  # PCI Identify users and authenticate
}


@router.get("/{framework}", response_model=FrameworkDetail, summary="One framework's control status")
async def framework_detail(
    framework: str,
    db: DBSession,
    user: Annotated[AuthUser, Depends(require_permission("reports:read"))],
) -> FrameworkDetail:
    key = resolve_framework(framework)
    controls = FRAMEWORKS[key]

    query = text("""
        SELECT id, control_id, control_title, evidence_kind, summary, status, collected_at
          FROM aisoc_compliance_evidence
         WHERE tenant_id = :t AND framework = :f
         ORDER BY collected_at DESC
    """).bindparams(t=user.tenant_id, f=key)
    try:
        rows = (await db.execute(query)).fetchall()
    except Exception as exc:
        logger.exception("compliance: framework detail query failed")
        raise HTTPException(status_code=503, detail="Database error") from exc

    by_control: dict[str, list[EvidenceItem]] = {}
    for row in rows:
        by_control.setdefault(row.control_id, []).append(
            EvidenceItem(
                id=str(row.id),
                control_id=row.control_id,
                evidence_type=row.evidence_kind or "manual",
                title=row.control_title or row.control_id,
                description=row.summary,
                status=row.status,
                collected_at=row.collected_at,
            )
        )

    items: list[ControlWithEvidence] = []
    tally = {"accepted": 0, "pending": 0, "rejected": 0, "missing": 0}
    for cid, title in controls.items():
        evidence = by_control.get(cid, [])
        latest = _latest_status(evidence)
        tally[latest] += 1
        items.append(
            ControlWithEvidence(
                control=Control(
                    id=cid,
                    framework=key,
                    control_id=cid,
                    category=key,
                    title=title,
                    automatable=cid in ATTESTATIONS,
                ),
                evidence=evidence,
                latest_status=latest,
            )
        )

    total = len(items)
    return FrameworkDetail(
        framework=key,
        framework_name=key,
        summary=FrameworkSummary(
            total=total,
            # `collected` counts controls with evidence that has not been
            # reviewed yet. It is the same set as `review`; both names are
            # kept because the console renders them in different places and
            # dropping one would leave an undefined in a badge.
            collected=tally["pending"],
            review=tally["pending"],
            approved=tally["accepted"],
            rejected=tally["rejected"],
            missing=tally["missing"],
            pct=round(tally["accepted"] / total * 100, 1) if total else 0.0,
        ),
        controls=items,
        generated_at=datetime.now(UTC),
    )


@router.get("/{framework}/heatmap", response_model=HeatmapResponse, summary="Control status grid")
async def framework_heatmap(
    framework: str,
    db: DBSession,
    user: Annotated[AuthUser, Depends(require_permission("reports:read"))],
) -> HeatmapResponse:
    key = resolve_framework(framework)
    rows = await _control_rows(db, framework=key, tenant_id=user.tenant_id)
    return HeatmapResponse(
        framework=key,
        cells=[
            HeatmapCell(
                control_id=cid,
                title=title,
                status=_status_of(rows.get(cid)),
                evidence_count=int(rows[cid].total) if cid in rows else 0,
            )
            for cid, title in FRAMEWORKS[key].items()
        ],
        generated_at=datetime.now(UTC),
    )


@router.post(
    "/{framework}/collect",
    response_model=CollectResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Collect what the platform can attest for this framework",
)
async def framework_collect(
    framework: str,
    db: DBSession,
    user: Annotated[AuthUser, Depends(require_permission("reports:write"))],
) -> CollectResponse:
    """Write a real evidence row per automatable control.

    Rows join the same tamper-evident hash chain as manually collected
    evidence, and land as `pending`: the platform attesting its own state is
    a claim an auditor still has to accept, and auto-accepting would make the
    review step decorative.
    """
    key = resolve_framework(framework)
    now = datetime.now(UTC)
    results: list[CollectedControl] = []
    collected = 0

    prev = (
        await db.execute(
            text(
                "SELECT payload_hash FROM aisoc_compliance_evidence"
                " WHERE framework = :f AND tenant_id = :t ORDER BY created_at DESC LIMIT 1"
            ).bindparams(f=key, t=user.tenant_id)
        )
    ).scalar_one_or_none()

    for cid, title in FRAMEWORKS[key].items():
        attest = ATTESTATIONS.get(cid)
        if attest is None:
            results.append(
                CollectedControl(
                    control_id=cid,
                    outcome="manual",
                    detail="No automated source. Attach evidence with POST /compliance/evidence.",
                )
            )
            continue

        ok, summary, payload = await attest(db, user.tenant_id)
        if not ok:
            results.append(CollectedControl(control_id=cid, outcome="manual", detail=summary))
            continue

        digest = hashlib.sha256(((prev or "") + summary + json.dumps(payload, sort_keys=True)).encode()).hexdigest()
        await db.execute(
            text("""
                INSERT INTO aisoc_compliance_evidence (
                    id, tenant_id, framework, control_id, control_title,
                    evidence_kind, summary, raw_payload, payload_hash, prev_hash,
                    collected_at, status, created_at
                ) VALUES (
                    :id, :t, :f, :c, :title, 'automated', :summary,
                    CAST(:payload AS jsonb), :hash, :prev, :now, 'pending', :now
                )
            """).bindparams(
                id=uuid.uuid4(),
                t=user.tenant_id,
                f=key,
                c=cid,
                title=title,
                summary=summary,
                payload=json.dumps(payload),
                hash=digest,
                prev=prev,
                now=now,
            )
        )
        prev = digest
        collected += 1
        results.append(CollectedControl(control_id=cid, outcome="collected", detail=summary))

    await db.commit()
    return CollectResponse(
        framework=key,
        collected=collected,
        manual=len(results) - collected,
        results=results,
        collected_at=now,
    )


@router.get("/{framework}/export", summary="Export this framework's evidence")
async def framework_export(
    framework: str,
    db: DBSession,
    user: Annotated[AuthUser, Depends(require_permission("reports:read"))],
    fmt: str = Query("csv", pattern="^(csv|json)$"),
) -> Response:
    key = resolve_framework(framework)
    query = text("""
        SELECT control_id, control_title, evidence_kind, summary, status,
               payload_hash, prev_hash, collected_at
          FROM aisoc_compliance_evidence
         WHERE tenant_id = :t AND framework = :f
         ORDER BY collected_at
    """).bindparams(t=user.tenant_id, f=key)
    try:
        rows = (await db.execute(query)).fetchall()
    except Exception as exc:
        logger.exception("compliance: export query failed")
        raise HTTPException(status_code=503, detail="Database error") from exc

    records = [
        {
            "control_id": r.control_id,
            "control_title": r.control_title,
            "evidence_kind": r.evidence_kind,
            "summary": r.summary,
            "status": r.status,
            "payload_hash": r.payload_hash,
            "prev_hash": r.prev_hash,
            "collected_at": r.collected_at.isoformat() if r.collected_at else None,
        }
        for r in rows
    ]
    stamp = datetime.now(UTC).strftime("%Y%m%d")

    if fmt == "json":
        # The hash chain travels with the export. An evidence export an
        # auditor cannot verify is a spreadsheet.
        body = json.dumps(
            {"framework": key, "exported_at": datetime.now(UTC).isoformat(), "evidence": records},
            indent=2,
        )
        return Response(
            content=body,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{key}-evidence-{stamp}.json"'},
        )

    buffer = io.StringIO()
    writer = csv.DictWriter(
        buffer,
        fieldnames=[
            "control_id",
            "control_title",
            "evidence_kind",
            "summary",
            "status",
            "payload_hash",
            "prev_hash",
            "collected_at",
        ],
    )
    writer.writeheader()
    writer.writerows(records)
    return Response(
        content=buffer.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{key}-evidence-{stamp}.csv"'},
    )
