"""Replay a customer's closed findings through production triage, writing nothing.

Gap-closure Phase 1.2.

The whole point of this module is what it does *not* contain. There is no
triage here. :class:`ReplayRunner` builds the message production builds, hands
it to :meth:`FusedAlertTriageWorker.triage` (the same method the Kafka
consumer calls on every live alert), and records what comes back. Swapping the
persistence sink is the only difference between a replay and a live triage,
and that sink is a constructor argument on the worker rather than a branch
inside it, so there is no "if replay" anywhere on the hot path to drift.

That matters more than it sounds. The measurement a reader cares about is "how
does the product do on my alerts". A second triage implementation would answer
"how does the evaluation harness do on my alerts", and the two diverge the
first time anybody changes a prompt.

The split
---------
Findings are ordered by close time and cut at a fraction (default 0.7). The cut
is by **time**, not by row count, so the test window is a contiguous period
rather than a sample: an operator asking "would this have worked last quarter"
gets an answer about last quarter.

Only the test window is replayed. The train window's job is to fix the split
point and to describe the world triage is allowed to know about, and replaying
it would place 70% more model calls to produce decisions nothing grades.

Priors are not seeded from the train window's labels
----------------------------------------------------
:class:`ContextSnapshot` accepts priors and the runner uses them, but nothing
here manufactures them out of the analyst labels in the train window. It
would be easy and it would inflate the result: an outcome prior authored by a
human suppresses a matching repeat immediately and without re-triage, so
seeding priors from ground truth would score the ground truth. An operator who
wants their real priors passes their real priors.
"""

from __future__ import annotations

import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import structlog

from app.agents.dispositions import normalize_disposition
from app.replay.findings import HistoricalFinding
from app.replay.normalize import ENVELOPE_LIMITS, FindingNormalizer, NormalizerUnavailable, to_fused_envelope
from app.replay.shadow import ContextSnapshot, FrozenTriageContextReader, ShadowTriageWriter
from app.workers.business_context import BusinessContextApplier
from app.workers.fused_alert_consumer import FusedAlertTriageWorker

logger = structlog.get_logger()

__all__ = [
    "DEFAULT_TRAIN_FRACTION",
    "ReplayDecision",
    "ReplayRun",
    "ReplayRunner",
    "TimeSplit",
    "split_by_time",
]

#: 70/30, as the plan specifies. Exposed as a constant so the report can state
#: the value it used rather than the value someone remembers the default being.
DEFAULT_TRAIN_FRACTION = 0.7


@dataclass(frozen=True)
class TimeSplit:
    """Where history was cut, and what fell either side."""

    split_at: datetime
    train: tuple[HistoricalFinding, ...]
    test: tuple[HistoricalFinding, ...]
    train_fraction: float

    def as_method_note(self) -> dict[str, Any]:
        return {
            "split_at": self.split_at.isoformat(),
            "train_fraction": self.train_fraction,
            "train_findings": len(self.train),
            "test_findings": len(self.test),
            "train_window_start": self.train[0].closed_at.isoformat() if self.train else None,
            "test_window_end": self.test[-1].closed_at.isoformat() if self.test else None,
        }


def split_by_time(
    findings: Sequence[HistoricalFinding],
    *,
    train_fraction: float = DEFAULT_TRAIN_FRACTION,
) -> TimeSplit:
    """Order by close time and cut so the test window is the later period.

    Ties at the boundary go to the **train** side. A finding closed at the
    exact split instant is one the frozen context could legitimately have
    known about, and putting it in the test window would ask the agent about
    an alert whose answer is inside its own frozen memory.

    Sorting is by ``(closed_at, finding_id)``. Close times collide routinely
    when an analyst bulk-closes a queue, and a sort that is not total makes
    the split, and therefore the report, depend on input order.
    """
    if not 0.0 < train_fraction < 1.0:
        raise ValueError(f"train_fraction must be strictly between 0 and 1, got {train_fraction}")
    ordered = sorted(findings, key=lambda f: (f.closed_at, f.finding_id))
    if not ordered:
        raise ValueError("cannot split an empty history")

    index = max(1, min(len(ordered) - 1, int(round(len(ordered) * train_fraction))))
    split_at = ordered[index - 1].closed_at
    train = [f for f in ordered if f.closed_at <= split_at]
    test = [f for f in ordered if f.closed_at > split_at]
    return TimeSplit(
        split_at=split_at,
        train=tuple(train),
        test=tuple(test),
        train_fraction=train_fraction,
    )


@dataclass
class ReplayDecision:
    """One shadow triage decision, with everything needed to grade or audit it."""

    finding_id: str
    vendor: str
    rule_id: str | None
    closed_at: str

    #: The analyst's label. ``unlabeled`` means excluded from accuracy.
    expected_disposition: str
    vendor_disposition: str
    labelled: bool

    #: What triage said, mapped onto the canonical taxonomy the analyst label
    #: uses. Deterministic triage speaks a second dialect (``likely_benign``,
    #: ``confirmed_incident``), so a raw comparison would score every
    #: deterministic verdict as wrong against a vendor label that is already
    #: canonical. The mapping is ``app.agents.dispositions``, the same one the
    #: writeback and the memory store use, so replay cannot invent a third.
    verdict: str | None = None

    #: Exactly what triage emitted, before normalisation. Kept because a
    #: verdict the taxonomy does not recognise is a finding about the product
    #: and must not be laundered into a canonical one by the grader.
    verdict_raw: str | None = None

    confidence: float = 0.0
    tier: str = ""

    #: Reasoning, kept verbatim. Hallucination scoring reads indicators out
    #: of this and checks them against the evidence the agent was given.
    findings: list[str] = field(default_factory=list)
    confidence_basis: list[str] = field(default_factory=list)

    #: The evidence handed to triage, so a disputed score can be re-derived.
    evidence: dict[str, Any] = field(default_factory=dict)

    tool_calls: int = 0
    resolved_models: list[str] = field(default_factory=list)
    tokens: int = 0
    measured_usd: float | None = None
    estimated_usd: float | None = None
    unpriced_calls: int = 0
    latency_ms: int = 0

    #: Set when triage refused the finding outright, which is neither a
    #: verdict nor an abstention and must not be scored as either.
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "vendor": self.vendor,
            "rule_id": self.rule_id,
            "closed_at": self.closed_at,
            "expected_disposition": self.expected_disposition,
            "vendor_disposition": self.vendor_disposition,
            "labelled": self.labelled,
            "verdict": self.verdict,
            "verdict_raw": self.verdict_raw,
            "confidence": self.confidence,
            "tier": self.tier,
            "findings": list(self.findings),
            "confidence_basis": list(self.confidence_basis),
            "evidence": self.evidence,
            "tool_calls": self.tool_calls,
            "resolved_models": list(self.resolved_models),
            "tokens": self.tokens,
            "measured_usd": self.measured_usd,
            "estimated_usd": self.estimated_usd,
            "unpriced_calls": self.unpriced_calls,
            "latency_ms": self.latency_ms,
            "error": self.error,
        }


@dataclass
class ReplayRun:
    """A completed replay: the decisions, the split, and how it was produced."""

    decisions: list[ReplayDecision]
    split: TimeSplit
    snapshot: ContextSnapshot
    writes_attempted: dict[str, int]
    tenant_id: str
    connector_id: str

    def method(self) -> dict[str, Any]:
        """Everything a reader needs to decide whether to believe the numbers."""
        return {
            "tenant_id": self.tenant_id,
            "connector_id": self.connector_id,
            "split": self.split.as_method_note(),
            "frozen_context": self.snapshot.as_method_note(),
            "shadow_writes_attempted": dict(self.writes_attempted),
            "envelope_limits": list(ENVELOPE_LIMITS),
        }


class ReplayRunner:
    """Drives the production triage path over a frozen historical window."""

    def __init__(
        self,
        *,
        normalizer: FindingNormalizer,
        tenant_id: str,
        connector_id: str = "",
        business_context: BusinessContextApplier | None = None,
    ) -> None:
        if normalizer is None:  # pragma: no cover - defensive, the type says so
            raise NormalizerUnavailable("replay requires the production connector normalizer")
        self._normalizer = normalizer
        self._tenant_id = tenant_id
        self._connector_id = connector_id or getattr(normalizer, "connector_id", "") or ""
        self._business_context = business_context

    async def run(
        self,
        findings: Sequence[HistoricalFinding],
        *,
        snapshot: ContextSnapshot | None = None,
        train_fraction: float = DEFAULT_TRAIN_FRACTION,
    ) -> ReplayRun:
        """Split, freeze, and replay the test window."""
        split = split_by_time(findings, train_fraction=train_fraction)
        frozen = snapshot or ContextSnapshot(split_at=split.split_at)
        if frozen.split_at != split.split_at:
            raise ValueError(
                f"context snapshot was captured at {frozen.split_at.isoformat()} but the split is at "
                f"{split.split_at.isoformat()}; a snapshot taken at a different instant is not a freeze"
            )

        writer = ShadowTriageWriter()
        reader = FrozenTriageContextReader(frozen)
        # The production worker, constructed exactly as the Kafka consumer
        # constructs it apart from the two sinks. `bootstrap_servers` is
        # required by the signature and unused: `triage()` never touches the
        # consumer, and `start()` is not called.
        worker = FusedAlertTriageWorker(
            bootstrap_servers="",
            business_context=self._business_context,
            writer=writer,
            context_reader=reader,
        )

        decisions: list[ReplayDecision] = []
        for finding in split.test:
            decisions.append(await self._replay_one(worker, finding))

        logger.info(
            "replay.completed",
            tenant_id=self._tenant_id,
            graded=sum(1 for d in decisions if d.labelled and d.error is None),
            decisions=len(decisions),
            writes_attempted=writer.total_writes,
        )
        return ReplayRun(
            decisions=decisions,
            split=split,
            snapshot=frozen,
            writes_attempted=dict(writer.calls),
            tenant_id=self._tenant_id,
            connector_id=self._connector_id,
        )

    async def _replay_one(self, worker: FusedAlertTriageWorker, finding: HistoricalFinding) -> ReplayDecision:
        decision = ReplayDecision(
            finding_id=finding.finding_id,
            vendor=finding.vendor,
            rule_id=finding.rule_id,
            closed_at=finding.closed_at.isoformat(),
            expected_disposition=finding.disposition,
            vendor_disposition=finding.vendor_disposition,
            labelled=finding.is_labelled,
        )

        try:
            normalized = self._normalizer.normalize(dict(finding.raw))
        except Exception as exc:  # noqa: BLE001 — one bad row must not end the run
            decision.error = f"normalize failed: {type(exc).__name__}: {exc}"
            return decision

        envelope = to_fused_envelope(
            finding,
            normalized,
            tenant_id=self._tenant_id,
            connector_id=self._connector_id,
        )
        decision.evidence = dict(envelope.get("alert") or {})

        started = time.monotonic()
        try:
            summary = await worker.triage(envelope)
        except Exception as exc:  # noqa: BLE001 — recorded as a refusal, not a verdict
            decision.error = f"triage failed: {type(exc).__name__}: {exc}"
            decision.latency_ms = int(round((time.monotonic() - started) * 1000))
            return decision
        decision.latency_ms = int(round((time.monotonic() - started) * 1000))

        if not isinstance(summary, dict):
            decision.error = "triage returned no summary for this finding"
            return decision

        raw_verdict = summary.get("verdict")
        decision.verdict_raw = raw_verdict
        # An unrecognised verdict keeps its own spelling rather than falling
        # back to a canonical one. The grader gives it its own confusion-matrix
        # column, which is what makes it visible instead of scored as
        # something the agent did not say.
        decision.verdict = normalize_disposition(raw_verdict, default="") or (str(raw_verdict) if raw_verdict else None)
        decision.confidence = float(summary.get("confidence") or 0.0)
        decision.tier = str(summary.get("tier") or ("suppressed" if summary.get("suppressed") else ""))
        decision.findings = [str(f) for f in (summary.get("findings") or [])]
        decision.confidence_basis = [str(b) for b in (summary.get("confidence_basis") or [])]

        cost = summary.get("cost") or {}
        decision.tokens = int(cost.get("tokens") or 0)
        decision.measured_usd = cost.get("measured_usd")
        decision.estimated_usd = cost.get("estimated_usd")
        decision.unpriced_calls = int(cost.get("unpriced_calls") or 0)
        decision.resolved_models = [str(m) for m in (cost.get("resolved_models") or [])]
        # Structurally zero rather than unmeasured: shadow mode declines
        # escalation, and escalation is the only stage of this path that calls
        # tools. Recorded so a future change that gives triage a tool shows up
        # here as a number moving off zero.
        decision.tool_calls = 0
        return decision
