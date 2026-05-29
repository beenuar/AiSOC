"""Email-security + phishing-triage workflow (tier3-phishing).

Analysts or automated ingestion submit raw email text, URLs, attachments, or
domain names for LLM-powered triage.  The endpoint extracts indicators of
compromise (IOCs), assigns a verdict, and optionally opens a case.

Endpoints
---------
* ``POST /phishing/submit``       Submit an artifact for triage.
* ``GET  /phishing/submissions``  List submissions.
* ``GET  /phishing/{id}``         Get a submission.
* ``POST /phishing/{id}/retriage`` Re-run triage (e.g. after analyst correction).
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import UTC, datetime
from typing import Any, Literal

import httpx
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import text

from app.api.v1.deps import AuthUser, DBSession
from app.core.airgap import AirgapViolation, enforce_airgap_for_url

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/phishing", tags=["phishing"])

# ────────────────────────────────────────────────────────────────────────────
# Schemas
# ────────────────────────────────────────────────────────────────────────────

ArtifactKind = Literal["email", "url", "attachment", "domain"]
Verdict = Literal["pending", "benign", "phishing", "spam", "malware", "unknown"]


class SubmitRequest(BaseModel):
    artifact_kind: ArtifactKind = "email"
    raw_content: str | None = Field(None, description="Raw email source or URL to analyse.")
    sender: str | None = None
    subject: str | None = None
    urls: list[str] = Field(default_factory=list)


class TriageResult(BaseModel):
    verdict: Verdict
    confidence: float
    indicators: list[dict[str, Any]]
    mitre_technique: str | None
    summary: str


class SubmissionResponse(BaseModel):
    id: uuid.UUID
    artifact_kind: str
    sender: str | None
    subject: str | None
    urls: list[str]
    verdict: str
    confidence: float | None
    indicators: list[dict[str, Any]]
    mitre_technique: str | None
    case_id: uuid.UUID | None
    submitted_at: datetime
    triaged_at: datetime | None


# ────────────────────────────────────────────────────────────────────────────
# LLM triage helper
# ────────────────────────────────────────────────────────────────────────────

_SYSTEM = """You are a phishing and email-security analyst.
Analyse the submitted artifact and return ONLY valid JSON with:
{
  "verdict": "benign|phishing|spam|malware|unknown",
  "confidence": 0.0-1.0,
  "indicators": [{"kind": "url|domain|ip|hash|email|header", "value": "...", "note": "..."}],
  "mitre_technique": "T1566.001 or null",
  "summary": "one-sentence explanation"
}"""


async def _triage(artifact_kind: str, content: str, urls: list[str]) -> TriageResult | None:
    api_key = os.getenv("OPENAI_API_KEY") or os.getenv("LLM_API_KEY")
    if not api_key:
        return None
    base_url = os.getenv("LLM_BASE_URL", "https://api.openai.com/v1")
    model = os.getenv("LLM_MODEL", "gpt-4o-mini")
    user_msg = f"ARTIFACT TYPE: {artifact_kind}\n"
    if urls:
        user_msg += f"URLS: {', '.join(urls[:10])}\n"
    if content:
        user_msg += f"CONTENT (first 2000 chars):\n{content[:2000]}"
    completions_url = f"{base_url}/chat/completions"
    # Air-gap enforcement: refuse the call rather than letting httpx fan out.
    # AirgapViolation propagates to the caller so the endpoint can surface 503.
    enforce_airgap_for_url(completions_url)
    try:
        async with httpx.AsyncClient(timeout=45) as client:
            resp = await client.post(
                completions_url,
                headers={"Authorization": f"Bearer {api_key}"},
                json={
                    "model": model,
                    "messages": [
                        {"role": "system", "content": _SYSTEM},
                        {"role": "user", "content": user_msg},
                    ],
                    "temperature": 0.1,
                    "response_format": {"type": "json_object"},
                },
            )
        resp.raise_for_status()
        data = json.loads(resp.json()["choices"][0]["message"]["content"])
        return TriageResult(
            verdict=data.get("verdict", "unknown"),
            confidence=float(data.get("confidence", 0.5)),
            indicators=data.get("indicators", []),
            mitre_technique=data.get("mitre_technique"),
            summary=data.get("summary", ""),
        )
    except Exception:
        return None


def _heuristic_triage(content: str | None, urls: list[str]) -> TriageResult:
    """Fallback rule-based triage when no LLM key is configured."""
    indicators: list[dict[str, Any]] = []
    score = 0.0
    phishing_words = ["verify your account", "click here", "urgent", "suspended", "password reset", "login immediately"]
    if content:
        for kw in phishing_words:
            if kw.lower() in (content or "").lower():
                score += 0.15
                indicators.append({"kind": "keyword", "value": kw, "note": "phishing keyword"})
    for url in urls:
        if any(x in url for x in ["bit.ly", "tinyurl", "goo.gl", "ow.ly"]):
            score += 0.2
            indicators.append({"kind": "url", "value": url, "note": "URL shortener"})
    score = min(score, 1.0)
    verdict: Verdict = "phishing" if score > 0.4 else "benign" if score < 0.1 else "unknown"
    return TriageResult(
        verdict=verdict,
        confidence=round(score, 2),
        indicators=indicators,
        mitre_technique=None,
        summary="Heuristic triage — LLM not configured.",
    )


def _row_to_submission(row: Any) -> SubmissionResponse:
    return SubmissionResponse(
        id=row.id,
        artifact_kind=row.artifact_kind,
        sender=row.sender,
        subject=row.subject,
        urls=list(row.urls or []),
        verdict=row.verdict,
        confidence=row.confidence,
        indicators=list(row.indicators or []),
        mitre_technique=row.mitre_technique,
        case_id=row.case_id,
        submitted_at=row.submitted_at,
        triaged_at=row.triaged_at,
    )


# ────────────────────────────────────────────────────────────────────────────
# Endpoints
# ────────────────────────────────────────────────────────────────────────────


@router.post(
    "/submit", response_model=SubmissionResponse, status_code=status.HTTP_201_CREATED, summary="Submit artifact for phishing triage"
)
async def submit(body: SubmitRequest, db: DBSession, user: AuthUser) -> SubmissionResponse:
    try:
        result = await _triage(body.artifact_kind, body.raw_content or "", body.urls)
    except AirgapViolation:
        # Air-gapped mode is on but the configured LLM endpoint isn't on the
        # allowlist — fall through to heuristic triage rather than 503-ing
        # the user. Phishing triage degrades gracefully; the heuristic path
        # still produces a usable verdict.
        result = None
    if not result:
        result = _heuristic_triage(body.raw_content, body.urls)

    now = datetime.now(UTC)
    sub_id = uuid.uuid4()
    q = text("""
        INSERT INTO aisoc_phishing_submissions (
            id, tenant_id, submitted_by, artifact_kind, raw_content, sender, subject,
            urls, verdict, confidence, indicators, mitre_technique,
            submitted_at, triaged_at, created_at
        ) VALUES (
            :id, :tenant_id, :by, :kind, :content, :sender, :subject,
            :urls::text[], :verdict, :conf, :iocs::jsonb, :mitre,
            :now, :now, :now
        ) RETURNING *
    """).bindparams(
        id=sub_id,
        tenant_id=user.tenant_id,
        by=str(user) if user else "system",
        kind=body.artifact_kind,
        content=body.raw_content,
        sender=body.sender,
        subject=body.subject,
        urls=body.urls or [],
        verdict=result.verdict,
        conf=result.confidence,
        iocs=json.dumps(result.indicators),
        mitre=result.mitre_technique,
        now=now,
    )
    try:
        row = (await db.execute(q)).fetchone()
        await db.commit()
        return _row_to_submission(row)
    except Exception as exc:
        await db.rollback()
        logger.exception("Database error in phishing endpoint")
        raise HTTPException(status_code=503, detail="Database error") from exc


@router.get("/submissions", response_model=list[SubmissionResponse], summary="List phishing submissions")
async def list_submissions(
    db: DBSession,
    user: AuthUser,
    verdict: str | None = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> list[SubmissionResponse]:
    wheres = ["tenant_id = :tenant_id"]
    params: dict[str, Any] = {"tenant_id": user.tenant_id, "limit": limit, "offset": offset}
    if verdict:
        wheres.append("verdict = :verdict")
        params["verdict"] = verdict
    q = text(
        f"SELECT * FROM aisoc_phishing_submissions WHERE {' AND '.join(wheres)} ORDER BY submitted_at DESC LIMIT :limit OFFSET :offset"
    ).bindparams(**params)
    try:
        rows = (await db.execute(q)).fetchall()
        return [_row_to_submission(r) for r in rows]
    except Exception as exc:
        logger.exception("Database error in phishing endpoint")
        raise HTTPException(status_code=503, detail="Database error") from exc


@router.get("/{submission_id}", response_model=SubmissionResponse, summary="Get submission")
async def get_submission(submission_id: uuid.UUID, db: DBSession, user: AuthUser) -> SubmissionResponse:
    row = (
        await db.execute(
            text("SELECT * FROM aisoc_phishing_submissions WHERE id = :id AND tenant_id = :tenant_id").bindparams(
                id=submission_id, tenant_id=user.tenant_id
            )
        )
    ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Submission not found.")
    return _row_to_submission(row)


@router.post("/{submission_id}/retriage", response_model=SubmissionResponse, summary="Re-run triage on submission")
async def retriage(submission_id: uuid.UUID, db: DBSession, user: AuthUser) -> SubmissionResponse:
    existing = (
        await db.execute(
            text("SELECT * FROM aisoc_phishing_submissions WHERE id = :id AND tenant_id = :tenant_id").bindparams(
                id=submission_id, tenant_id=user.tenant_id
            )
        )
    ).fetchone()
    if not existing:
        raise HTTPException(status_code=404, detail="Submission not found.")

    try:
        result = await _triage(existing.artifact_kind, existing.raw_content or "", list(existing.urls or []))
    except AirgapViolation:
        result = None
    if not result:
        result = _heuristic_triage(existing.raw_content, list(existing.urls or []))

    now = datetime.now(UTC)
    q = text("""
        UPDATE aisoc_phishing_submissions
        SET verdict = :verdict, confidence = :conf, indicators = :iocs::jsonb,
            mitre_technique = :mitre, triaged_at = :now
        WHERE id = :id AND tenant_id = :tenant_id RETURNING *
    """).bindparams(
        id=submission_id,
        tenant_id=user.tenant_id,
        verdict=result.verdict,
        conf=result.confidence,
        iocs=json.dumps(result.indicators),
        mitre=result.mitre_technique,
        now=now,
    )
    try:
        row = (await db.execute(q)).fetchone()
        await db.commit()
        return _row_to_submission(row)
    except Exception as exc:
        await db.rollback()
        logger.exception("Database error in phishing endpoint")
        raise HTTPException(status_code=503, detail="Database error") from exc
