"""Headers, URLs and attachments analysed once, and cited where an auditor looks.

Depth 7.2. The three analyses already had homes of a sort — headers nowhere,
URLs nowhere, attachment digests through
:func:`app.services.sandbox.enrichment.enrich_file_hash` — and none of them
left a record anybody could replay. A verdict an analyst cannot trace back to
what produced it is a verdict they have to re-derive, which is most of the
work the product claims to remove.

So this module does two things: it runs the three analyses over one reported
message, and it writes what each one found into the investigation ledger as
``evidence_cited`` rows.

The honesty rule, restated because it is the whole point
---------------------------------------------------------
**An unanalysed artefact must never read as a clean one.** The submit path
already refuses to skip an empty attachment block, and this module extends the
same rule to the other two:

* no sender-authentication header is ``not_evaluated``, three times over, each
  with its own indicator saying no boundary recorded a verdict;
* no configured sandbox is ``not_analysed`` per URL, naming the absence,
  never an empty list;
* a provider that could not be reached is ``could_not_check``, which is not
  ``benign``.

Counting is the discipline that makes it stick: :class:`MessageAnalysis`
carries ``analysed`` and ``unanalysed`` separately, so a caller cannot add
them up by accident and a surface cannot render zero findings as zero risk.

Why URLs are submitted and attachments are not
-----------------------------------------------
A URL is a public address; sending one to a sandbox discloses that somebody
is interested in it, which the upload policy treats as acceptable and
``analyse_url`` does not gate. An attachment is the customer's file, and
sending it is a disclosure the tenant has to have allowed — so this path does
hash lookup only, exactly as ``POST /phishing/submit`` does, and the door for
an actual upload stays ``POST /sandbox/files`` where the policy is enforced.

Nothing here raises
--------------------
A sandbox outage, an unreachable ledger or a provider returning nonsense all
degrade to a recorded "could not check". An analysis that fails loudly in the
middle of phishing triage takes the triage with it.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.phishing.headers import HeaderAnalysis, analyse_headers
from app.services.phishing.intake import ReportedMessage
from app.services.sandbox.enrichment import enrich_file_hash
from app.services.sandbox.registry import build_registry
from app.services.sandbox.service import analyse_url

logger = structlog.get_logger(__name__)

#: How many URLs are submitted per message. A phishing mail routinely carries
#: twenty links, nineteen of which are the sender's footer; submitting all of
#: them spends a provider's quota on an unsubscribe link.
MAX_URLS_ANALYSED = 5

#: Matches the submit path's cap, so the two agree about how much of a
#: message is examined.
MAX_ATTACHMENTS_ANALYSED = 10

#: The ledger `kind` an auditor filters on. Already in migration 008's
#: documented vocabulary, so this reuses it rather than widening the column.
EVIDENCE_KIND = "evidence_cited"

#: The agent name every row here carries. Not an LLM agent — this analysis
#: places no model call — and named so plainly that a reader of the ledger
#: cannot mistake it for one.
ANALYSIS_AGENT = "aisoc-phishing-analysis"


@dataclass
class ArtefactResult:
    """One URL or one attachment, and what came back."""

    kind: str
    value: str
    outcome: str
    detail: str
    provider: str = ""
    verdict: str = ""

    @property
    def analysed(self) -> bool:
        """``True`` only when a provider returned a verdict.

        ``pending`` is deliberately not analysed: a submission accepted is
        not a result, and the same distinction keeps ``awaiting_completion``
        out of the executed set on the action side.
        """
        return self.outcome == "known"


@dataclass
class MessageAnalysis:
    headers: HeaderAnalysis
    urls: list[ArtefactResult] = field(default_factory=list)
    attachments: list[ArtefactResult] = field(default_factory=list)
    #: The ledger run these citations were written to, when one was written.
    run_id: uuid.UUID | None = None

    @property
    def artefacts(self) -> list[ArtefactResult]:
        return [*self.urls, *self.attachments]

    @property
    def analysed_count(self) -> int:
        return sum(1 for a in self.artefacts if a.analysed)

    @property
    def unanalysed_count(self) -> int:
        """Counted separately from the analysed ones, never summed with them.

        Three URLs and two attachments with no provider configured is an
        analysis that examined nothing, and a surface that renders "5
        artefacts, 0 findings" has said the opposite of what happened.
        """
        return sum(1 for a in self.artefacts if not a.analysed)

    @property
    def malicious_count(self) -> int:
        return sum(1 for a in self.artefacts if a.verdict == "malicious")

    def as_indicators(self) -> list[dict[str, Any]]:
        """Everything found, in the shape the submissions table already holds."""
        out = self.headers.as_indicators()
        for artefact in self.artefacts:
            out.append(
                {
                    "kind": artefact.kind,
                    "value": artefact.value,
                    "note": artefact.detail,
                    **({"provider": artefact.provider} if artefact.provider else {}),
                    **({"verdict": artefact.verdict} if artefact.verdict else {}),
                }
            )
        return out

    def summary(self) -> str:
        parts = [self.headers.summary()]
        if self.artefacts:
            parts.append(
                f"{self.analysed_count} of {len(self.artefacts)} artefact(s) were analysed"
                + (f", {self.malicious_count} malicious" if self.malicious_count else "")
                + (f"; {self.unanalysed_count} could not be" if self.unanalysed_count else "")
            )
        return ". ".join(parts)


async def _analyse_urls(urls: tuple[str, ...]) -> list[ArtefactResult]:
    results: list[ArtefactResult] = []
    try:
        registry = build_registry()
        usable = registry.usable_names()
    except Exception as exc:  # noqa: BLE001 - a registry failure is "could not check"
        logger.warning("phishing_analysis.registry_failed", error=str(exc)[:300])
        usable = []
        registry = None  # type: ignore[assignment]

    for url in urls[:MAX_URLS_ANALYSED]:
        if not usable or registry is None:
            results.append(
                ArtefactResult(
                    kind="url",
                    value=url,
                    outcome="no_provider",
                    detail=(
                        "This URL was not analysed: no file-and-URL analysis provider is configured "
                        "for this deployment. This is not a clean verdict."
                    ),
                )
            )
            continue
        for name in usable:
            provider = registry.get(name)
            if provider is None:  # pragma: no cover - usable_names said otherwise
                continue
            try:
                result = await analyse_url(provider, url, registry=registry)
            except Exception as exc:  # noqa: BLE001
                logger.warning("phishing_analysis.url_failed", provider=name, error=str(exc)[:300])
                results.append(
                    ArtefactResult(
                        kind="url",
                        value=url,
                        outcome="could_not_check",
                        detail=f"{name} could not be reached, so this URL was not checked. This is not a clean verdict.",
                        provider=name,
                    )
                )
                continue
            verdict = ""
            if result.report is not None and not isinstance(result.report.verdict, type(None)):
                raw = getattr(result.report.verdict, "value", None)
                verdict = str(raw) if raw else ""
            results.append(
                ArtefactResult(
                    kind="url",
                    value=url,
                    outcome=result.outcome,
                    detail=result.detail or f"{name}: {result.outcome}",
                    provider=name,
                    verdict=verdict,
                )
            )
    return results


async def _analyse_attachments(hashes: tuple[str, ...]) -> list[ArtefactResult]:
    """Hash lookup only. The same rule and the same wording as the submit path."""
    results: list[ArtefactResult] = []
    for digest in hashes[:MAX_ATTACHMENTS_ANALYSED]:
        try:
            block = (await enrich_file_hash(digest)).get("file_analysis") or {}
        except Exception:  # noqa: BLE001 - a sandbox outage must not fail the analysis
            logger.warning("phishing_analysis.attachment_failed", digest=str(digest)[:64].replace("\n", " "))
            results.append(
                ArtefactResult(
                    kind="hash",
                    value=digest,
                    outcome="could_not_check",
                    detail="attachment could not be checked: analysis provider unavailable. This is not a clean verdict.",
                )
            )
            continue
        if not block:
            results.append(
                ArtefactResult(
                    kind="hash",
                    value=digest,
                    outcome="no_provider",
                    detail=(
                        "attachment was not analysed: no file-analysis provider is configured for this "
                        "deployment. This is not a clean verdict."
                    ),
                )
            )
            continue
        for unchecked in block.get("could_not_check") or []:
            results.append(
                ArtefactResult(
                    kind="hash",
                    value=digest,
                    outcome="could_not_check",
                    detail=f"could not be checked by {unchecked.get('provider')}: not a clean result",
                    provider=str(unchecked.get("provider") or ""),
                )
            )
        for finding in block.get("findings") or []:
            results.append(
                ArtefactResult(
                    kind="hash",
                    value=digest,
                    outcome="known",
                    detail=f"{finding.get('provider')} verdict: {finding.get('verdict')}",
                    provider=str(finding.get("provider") or ""),
                    verdict=str(finding.get("verdict") or ""),
                )
            )
    return results


async def analyse_message(message: ReportedMessage) -> MessageAnalysis:
    """Headers, URLs and attachments. No database, no ledger, no model."""
    return MessageAnalysis(
        headers=analyse_headers(message.headers, reported_sender=message.sender),
        urls=await _analyse_urls(message.urls),
        attachments=await _analyse_attachments(message.attachment_hashes),
    )


async def cite_to_ledger(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    submission_id: uuid.UUID,
    message: ReportedMessage,
    analysis: MessageAnalysis,
) -> uuid.UUID | None:
    """Write the analysis into the investigation ledger as cited evidence.

    One run per analysed message and one ``evidence_cited`` event per
    component, because that is the grain an auditor asks at: "what did the
    header check say", not "what did the phishing path do".

    ``seq`` is assigned densely from one, and the table's unique constraint on
    ``(run_id, seq)`` makes a gap or a collision a write failure rather than a
    silently reordered timeline.

    Returns the run id, or ``None`` when the write failed. A ledger that could
    not be written is logged at ``warning`` and does not fail the analysis:
    the finding is still worth having, and the caller is told it is uncited by
    the ``None``. It is deliberately not swallowed at ``debug`` — a citation
    nobody can find is the defect this function exists to close.
    """
    run_id = uuid.uuid4()
    now = datetime.now(UTC)
    try:
        await db.execute(
            text("""
                INSERT INTO investigation_runs
                    (id, tenant_id, case_id, alert_summary, raw_alert, model_used, status,
                     iterations, started_at, completed_at, created_at)
                VALUES
                    (:id, :tenant_id, :case_id, :summary, CAST(:raw AS jsonb), NULL, 'completed',
                     1, :now, :now, :now)
            """).bindparams(
                id=run_id,
                tenant_id=tenant_id,
                # The submission is the case this run belongs to. `case_id` is
                # a free-text external reference by design (migration 008), so
                # it is prefixed rather than left as a bare uuid that reads
                # like a case id and is not one.
                case_id=f"phishing-submission:{submission_id}",
                summary=analysis.summary()[:4000],
                raw=_json({"internet_message_id": message.internet_message_id, "sender": message.sender, "subject": message.subject}),
                now=now,
            )
        )

        seq = 0
        for kind, summary, payload in _citations(message, analysis):
            seq += 1
            await db.execute(
                text("""
                    INSERT INTO investigation_events
                        (id, run_id, tenant_id, seq, ts, kind, agent, summary, payload, duration_ms, created_at)
                    VALUES
                        (:id, :run_id, :tenant_id, :seq, :now, :kind, :agent, :summary, CAST(:payload AS jsonb), 0, :now)
                """).bindparams(
                    id=uuid.uuid4(),
                    run_id=run_id,
                    tenant_id=tenant_id,
                    seq=seq,
                    now=now,
                    kind=kind,
                    agent=ANALYSIS_AGENT,
                    summary=summary[:4000],
                    payload=_json(payload),
                )
            )
    except Exception as exc:  # noqa: BLE001 - an uncitable analysis is still an analysis
        logger.warning("phishing_analysis.ledger_write_failed", error=str(exc)[:500], submission_id=str(submission_id))
        return None

    analysis.run_id = run_id
    return run_id


def _citations(message: ReportedMessage, analysis: MessageAnalysis) -> list[tuple[str, str, dict[str, Any]]]:
    """``(kind, summary, payload)`` per ledger row.

    Three rows at minimum, and the third is the one that matters: an analysis
    that examined no artefact still writes a row saying so. A ledger with no
    row for the URL check is indistinguishable from one where the check passed.
    """
    rows: list[tuple[str, str, dict[str, Any]]] = [
        (
            EVIDENCE_KIND,
            f"Sender authentication: {analysis.headers.summary()}",
            {
                "component": "headers",
                "authentication": analysis.headers.authentication,
                "failed": list(analysis.headers.failed_methods),
                "not_evaluated": list(analysis.headers.unevaluated_methods),
                "missing_headers": list(analysis.headers.missing_headers),
                "findings": [{"kind": f.kind, "detail": f.detail, "severity_hint": f.severity_hint} for f in analysis.headers.findings],
                "hop_count": analysis.headers.hop_count,
            },
        )
    ]
    for component, artefacts in (("urls", analysis.urls), ("attachments", analysis.attachments)):
        analysed = sum(1 for a in artefacts if a.analysed)
        if not artefacts:
            summary = f"No {component} were present in this message."
        else:
            summary = f"{analysed} of {len(artefacts)} {component[:-1]}(s) analysed" + (
                f"; {len(artefacts) - analysed} not analysed, which is not a clean verdict" if analysed < len(artefacts) else ""
            )
        rows.append(
            (
                EVIDENCE_KIND,
                summary,
                {
                    "component": component,
                    "analysed": analysed,
                    "unanalysed": len(artefacts) - analysed,
                    "items": [
                        {"value": a.value, "outcome": a.outcome, "provider": a.provider, "verdict": a.verdict, "detail": a.detail}
                        for a in artefacts
                    ],
                },
            )
        )
    return rows


def _json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, default=str)
