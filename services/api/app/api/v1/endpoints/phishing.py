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

Authorization
-------------
Both writes require ``cases:write``. A submission is investigative working
material that can open a case — the module does exactly that — so it is the
same entitlement as working one, and it is held by ``api_service`` too, which
the summary above needs: automated ingestion submits here with a scoped API
key.

``viewer`` is refused, which is the point. Each submission runs LLM triage on
attacker-supplied email text and persists a verdict and extracted IOCs, so an
ungated route was both an unmetered spend and a way to seed indicators from
an account entitled to read only.
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import text

from app.api.v1.deps import AuthUser, DBSession, require_permission
from app.core.airgap import AirgapViolation, enforce_airgap_for_url
from app.services.llm_safety import LLMContractViolation, safe_chat_completions_request
from app.services.model_aliases import chat_completions_url, resolve_api_key, resolve_model_alias
from app.services.sandbox.enrichment import enrich_file_hash

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
    attachment_hashes: list[str] = Field(
        default_factory=list,
        description=(
            "SHA-256 digests of the message's attachments. Digests only: the attachment itself is never "
            "accepted here, because this route runs unattended on submitted mail and an unattended path "
            "that can upload is one misconfiguration away from disclosing every attachment a tenant receives. "
            "To have a file analysed, POST it to /sandbox/files, which enforces the tenant's upload policy."
        ),
    )


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
    model = os.getenv("LLM_MODEL") or resolve_model_alias("investigation")
    # Resolved together with the route: when the call goes to the bundled
    # gateway the bearer is the gateway's master key, not a provider key.
    api_key = resolve_api_key(model)
    if not api_key:
        return None
    user_msg = f"ARTIFACT TYPE: {artifact_kind}\n"
    if urls:
        user_msg += f"URLS: {', '.join(urls[:10])}\n"
    if content:
        user_msg += f"CONTENT (first 2000 chars):\n{content[:2000]}"
    completions_url = chat_completions_url(model)
    # Air-gap enforcement: refuse the call rather than letting httpx fan out.
    # AirgapViolation propagates to the caller so the endpoint can surface 503.
    enforce_airgap_for_url(completions_url)
    try:
        # T2.3 — the contract runs before the request. This body is a
        # submitted email, so it is attacker-authored by definition and is
        # the single most likely place in the product to ship a raw log or a
        # secret to a third party.
        body = await safe_chat_completions_request(
            api_key=api_key,
            model=model,
            messages=[
                {"role": "system", "content": _SYSTEM},
                {"role": "user", "content": user_msg},
            ],
            url=completions_url,
            timeout=45.0,
            temperature=0.1,
            response_format={"type": "json_object"},
        )
        data = json.loads(body["choices"][0]["message"]["content"])
        return TriageResult(
            verdict=data.get("verdict", "unknown"),
            confidence=float(data.get("confidence", 0.5)),
            indicators=data.get("indicators", []),
            mitre_technique=data.get("mitre_technique"),
            summary=data.get("summary", ""),
        )
    except LLMContractViolation as exc:
        # Degrading to heuristic triage is the right outcome, but it must be
        # visible: this `except` used to swallow everything, so a refused
        # prompt was indistinguishable from a missing API key.
        # %-style: `logger` is the stdlib one, which raises TypeError on an
        # unknown keyword — and a raise inside an `except` is not caught by
        # the sibling handler below. The line added to stop this path
        # degrading silently was itself throwing.
        logger.warning("phishing.llm_contract_violation reason=%s", exc.reason)
        return None
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


async def _attachment_indicators(hashes: list[str]) -> list[dict[str, Any]]:
    """Look each attachment digest up through the sandbox provider contract.

    Hash lookup only, and never an upload: see ``attachment_hashes`` above.

    A provider that could not be reached produces an indicator saying so rather
    than nothing. The distinction matters most here, because an analyst reading
    a phishing verdict with no attachment indicator would otherwise conclude
    the attachments were checked and found clean.
    """
    indicators: list[dict[str, Any]] = []
    for digest in hashes[:10]:
        try:
            block = (await enrich_file_hash(digest)).get("file_analysis") or {}
        except Exception:  # noqa: BLE001 - a sandbox outage must not fail triage
            logger.warning("phishing.attachment_lookup_failed hash=%s", str(digest)[:64].replace("\n", " "))
            indicators.append({"kind": "hash", "value": digest, "note": "attachment could not be checked: analysis provider unavailable"})
            continue
        if not block:
            # An empty analysis block means no provider answered -- which on a
            # deployment with nothing configured is every attachment. Skipping
            # produced a phishing verdict carrying no attachment indicator at
            # all, and a reader takes the absence of a finding for a clean one.
            # "Not checked" is not a verdict, and has to be said.
            indicators.append(
                {
                    "kind": "hash",
                    "value": digest,
                    "note": (
                        "attachment was not analysed: no file-analysis provider is configured "
                        "for this deployment. This is not a clean verdict."
                    ),
                }
            )
            continue
        for unchecked in block.get("could_not_check") or []:
            indicators.append(
                {
                    "kind": "hash",
                    "value": digest,
                    "note": f"could not be checked by {unchecked.get('provider')}: not a clean result",
                }
            )
        for finding in block.get("findings") or []:
            indicators.append(
                {
                    "kind": "hash",
                    "value": digest,
                    "note": f"{finding.get('provider')} verdict: {finding.get('verdict')}",
                    "score": finding.get("score"),
                    "attack_techniques": finding.get("attack_techniques"),
                }
            )
    return indicators


def _merge_attachment_verdict(result: TriageResult, indicators: list[dict[str, Any]]) -> TriageResult:
    """Fold attachment findings into the triage result.

    A malicious attachment raises the verdict to ``malware`` and the confidence
    floor, because a sandbox verdict on the file itself is stronger evidence
    than any amount of keyword matching on the body. A verdict is never lowered
    here: an attachment nothing recognised says nothing about the message.
    """
    if not indicators:
        return result
    merged = [*result.indicators, *indicators]
    malicious = any("verdict: malicious" in str(i.get("note", "")) for i in indicators)
    if malicious:
        return TriageResult(
            verdict="malware",
            confidence=max(result.confidence, 0.9),
            indicators=merged,
            mitre_technique=result.mitre_technique or "T1566.001",
            summary=f"{result.summary} An attachment was identified as malicious by file analysis.".strip(),
        )
    return TriageResult(
        verdict=result.verdict,
        confidence=result.confidence,
        indicators=merged,
        mitre_technique=result.mitre_technique,
        summary=result.summary,
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
async def submit(
    body: SubmitRequest, db: DBSession, user: Annotated[AuthUser, Depends(require_permission("cases:write"))]
) -> SubmissionResponse:
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
    result = _merge_attachment_verdict(result, await _attachment_indicators(body.attachment_hashes))

    now = datetime.now(UTC)
    sub_id = uuid.uuid4()
    q = text("""
        INSERT INTO aisoc_phishing_submissions (
            id, tenant_id, submitted_by, artifact_kind, raw_content, sender, subject,
            urls, verdict, confidence, indicators, mitre_technique,
            submitted_at, triaged_at, created_at
        ) VALUES (
            :id, :tenant_id, :by, :kind, :content, :sender, :subject,
            CAST(:urls AS text[]), :verdict, :conf, CAST(:iocs AS jsonb), :mitre,
            :now, :now, :now
        ) RETURNING *
    """).bindparams(
        id=sub_id,
        tenant_id=user.tenant_id,
        by=user.email if user else "system",
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
async def retriage(
    submission_id: uuid.UUID, db: DBSession, user: Annotated[AuthUser, Depends(require_permission("cases:write"))]
) -> SubmissionResponse:
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
    # Re-run the attachment lookups too: a retriage exists because something
    # changed, and a provider that had never seen the file may have now.
    prior_hashes = [
        str(i.get("value")) for i in (existing.indicators or []) if isinstance(i, dict) and i.get("kind") == "hash" and i.get("value")
    ]
    result = _merge_attachment_verdict(result, await _attachment_indicators(list(dict.fromkeys(prior_hashes))))

    now = datetime.now(UTC)
    q = text("""
        UPDATE aisoc_phishing_submissions
        SET verdict = :verdict, confidence = :conf, indicators = CAST(:iocs AS jsonb),
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
