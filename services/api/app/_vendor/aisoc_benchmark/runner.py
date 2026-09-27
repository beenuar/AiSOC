"""Load a corpus, run an agent over it, publish the numbers.

The corpus carries **provenance per incident**, not as a footnote. A figure
computed over synthetic incidents is a synthetic figure, and a scoreboard
that omits that is misleading even when every number in it is arithmetically
correct. ``BenchmarkResult.corpus_provenance`` travels with the result so a
downstream consumer cannot drop it, and the runner refuses to emit an
unlabelled corpus.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections import Counter
from pathlib import Path
from typing import Any

from .adapter import AgentVerdict, BenchmarkIncident
from .metrics import BenchmarkResult, aggregate, score_incident

logger = logging.getLogger("aisoc.benchmark")

#: Every incident must declare where it came from. "synthetic" is an honest
#: answer; absent is not, because the reader then assumes the generous one.
VALID_PROVENANCE = frozenset(
    {
        "synthetic",  # generated for this harness
        "public-dataset",  # CICIDS, AIT-LDS, MITRE Engenuity and similar
        "real-anonymised",  # a real incident, scrubbed
        "adversary-emulation",  # Caldera / Atomic Red Team output
    }
)

#: One agent must not be able to hang the whole run.
PER_INCIDENT_TIMEOUT_SECONDS = 300.0


class CorpusError(ValueError):
    pass


def load_corpus(path: Path) -> tuple[list[BenchmarkIncident], list[dict[str, Any]], dict[str, int]]:
    """Read a corpus file. Returns incidents, ground truth, and provenance counts."""
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        raise CorpusError(f"could not read corpus {path}: {exc}") from exc

    records = raw.get("incidents") if isinstance(raw, dict) else raw
    if not isinstance(records, list) or not records:
        raise CorpusError(f"corpus {path} contains no incidents")

    incidents: list[BenchmarkIncident] = []
    truth: list[dict[str, Any]] = []
    provenance: Counter[str] = Counter()

    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise CorpusError(f"corpus entry {index} is not an object")

        source = str(record.get("provenance", "")).strip().lower()
        if source not in VALID_PROVENANCE:
            raise CorpusError(
                f"corpus entry {record.get('id', index)!r} declares provenance "
                f"{source!r}; must be one of {sorted(VALID_PROVENANCE)}. A figure "
                f"computed over synthetic incidents is a synthetic figure, and an "
                f"unlabelled corpus lets a reader assume otherwise."
            )
        provenance[source] += 1

        incidents.append(
            BenchmarkIncident(
                incident_id=str(record.get("id", f"incident-{index}")),
                title=str(record.get("title", "")),
                description=str(record.get("description", "")),
                severity=str(record.get("severity", "medium")),
                raw_alert=record.get("raw_alert") or {},
                telemetry=record.get("telemetry") or [],
            )
        )
        truth.append(
            {
                "disposition": record.get("expected_disposition") or record.get("disposition") or "",
                "techniques": record.get("expected_techniques") or record.get("techniques") or [],
                "actions": record.get("expected_actions") or [],
            }
        )

    return incidents, truth, dict(provenance)


async def run_benchmark(
    agent: Any,
    corpus_path: Path,
    *,
    concurrency: int = 4,
    limit: int | None = None,
) -> BenchmarkResult:
    """Grade ``agent`` over the corpus.

    An exception from the agent is scored as an abstention with the failure
    named, never propagated. A harness that dies on one bad response grades
    nothing, and the entrant will reasonably assume the fault is ours.
    """
    incidents, truth, provenance = load_corpus(corpus_path)
    if limit:
        incidents, truth = incidents[:limit], truth[:limit]
        # Recount over the slice. Reporting the full corpus provenance
        # alongside a truncated run overstates what was actually graded,
        # which is the same class of error the labelling exists to prevent.
        kept = {i.incident_id for i in incidents}
        provenance = dict(
            Counter(r["provenance"] for r in json.loads(Path(corpus_path).read_text(encoding="utf-8"))["incidents"] if r.get("id") in kept)
        )

    semaphore = asyncio.Semaphore(max(1, concurrency))

    async def _one(incident: BenchmarkIncident, expected: dict[str, Any]):
        async with semaphore:
            started = time.monotonic()
            try:
                verdict = await asyncio.wait_for(agent.investigate(incident), timeout=PER_INCIDENT_TIMEOUT_SECONDS)
            except TimeoutError:
                verdict = AgentVerdict(
                    abstained=True,
                    narrative=f"agent exceeded {PER_INCIDENT_TIMEOUT_SECONDS:.0f}s",
                )
            except Exception as exc:
                verdict = AgentVerdict(
                    abstained=True,
                    narrative=f"agent raised {type(exc).__name__}: {exc}",
                )
            # Measured here rather than trusted from the agent: self-reported
            # latency is the one number an entrant has an incentive to shade.
            if not verdict.latency_ms:
                verdict.latency_ms = int((time.monotonic() - started) * 1000)
            return score_incident(incident, verdict, expected)

    scores = await asyncio.gather(*(_one(i, t) for i, t in zip(incidents, truth, strict=True)))

    result = aggregate(
        getattr(agent, "name", "unknown"),
        getattr(agent, "version", "unknown"),
        list(scores),
        corpus_provenance=provenance,
    )
    logger.info(
        "benchmark complete agent=%s incidents=%d accuracy=%.3f hallucination=%.3f abstention=%.3f",
        result.agent_name,
        result.incidents,
        result.disposition_accuracy,
        result.hallucination_rate,
        result.abstention_rate,
    )
    return result


def format_report(result: BenchmarkResult) -> str:
    """Human-readable summary.

    Provenance leads. The temptation is to open with the accuracy figure, and
    a reader who sees 0.94 before they see "synthetic: 200" has already
    formed an impression the caveat will not undo.
    """
    provenance = ", ".join(f"{k}: {v}" for k, v in sorted(result.corpus_provenance.items()))
    lines = [
        f"Agent:   {result.agent_name} {result.agent_version}",
        f"Corpus:  {result.incidents} incidents ({provenance or 'unlabelled'})",
        "",
        "Accuracy (over answered incidents only — abstaining does not raise it)",
        f"  disposition accuracy   {result.disposition_accuracy:.3f}",
        f"  technique recall       {result.technique_recall:.3f}",
        f"  technique precision    {result.technique_precision:.3f}",
    ]
    if result.containment_accuracy is not None:
        lines.append(f"  containment accuracy   {result.containment_accuracy:.3f}")

    lines += [
        "",
        "Honesty",
        f"  abstention rate        {result.abstention_rate:.3f}",
        f"  hallucination rate     {result.hallucination_rate:.3f} "
        f"({result.hallucinated_total}/{result.indicators_checked} cited indicators "
        f"absent from the evidence)",
        f"  calibration gap        {result.calibration_gap:+.3f} "
        f"(confidence when right minus when wrong; near zero means the score "
        f"carries no information)",
        "",
        "Cost",
        f"  mean latency           {result.mean_latency_ms:.0f} ms",
        f"  p95 latency            {result.p95_latency_ms:.0f} ms",
        f"  total tokens           {result.total_tokens}",
        f"  mean USD per incident  {result.mean_usd_per_incident:.6f}",
        f"  mean distinct tools    {result.mean_distinct_tools:.1f}",
    ]
    return "\n".join(lines)
