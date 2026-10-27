"""Demote a verdict whose reasoning cites indicators the evidence does not contain.

Why this module exists
----------------------
`score_groundedness` measures what fraction of the concrete indicators an
output asserts -- IPs, hashes, CVEs, MITRE techniques, domains -- actually
appear in the evidence the agent was given. The gate around it was real,
default-on and demoting, and it lived in exactly one place:
`workers/fused_alert_consumer.py`, the auto-triage path.

The *investigator* path had none. So a verdict reached through
`POST /cases/{id}/investigate` -- the one an analyst launches deliberately,
reads carefully and is most likely to act on -- was never checked, while the
background path that nobody is watching was.

Why it could not simply have been added
---------------------------------------
The gate scores against `json.dumps(state.raw_alert or {})`, and on the
investigator path `raw_alert` was `{}`: the console sent the literal string
`"Investigate alert: <title>"` and no evidence at all. Scoring reasoning
against an empty evidence set does not fail safe -- `_extract` finds no
indicators in the evidence, so every indicator the model mentions is
unsupported, and the gate would have demoted *everything*. Tuning around that
by lowering the floor would have made it certify anything.

So the payload had to flow first. It now does: `services/api` loads the case's
alerts and their `raw_event` payloads and sends them as `raw_alert`.

What is gated, and what deliberately is not
-------------------------------------------
Only verdicts that would close something without a human. Demoting an
escalation because its prose mentioned one extra indicator adds review load
without reducing risk, and a verdict already routed to a person is not making
an unsupervised decision.

Two checks, not one
-------------------
Indicator grounding was the only check here, and it is blind to the failure
that matters most on this path. It asks whether the IPs and hashes the output
names appear in the evidence; it cannot ask whether the *sentence that closes
the alert* rests on anything. A rationale reusing the alert's own source IP to
assert "this is our approved scanner, change CHG0049112" scores a perfect 1.0
and closes, with no scanner and no change record anywhere in the evidence.

So :func:`evaluate` now runs both, reports them separately, and withholds the
closure if either fails. They are different measurements — see
:class:`app.confidence.signals.SignalKind` — and collapsing them into one
number would hide exactly the case each is blind to.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any

import structlog

from app.confidence.claim_support import ClaimSupportResult, score_claim_support
from app.confidence.groundedness import score_groundedness

logger = structlog.get_logger(__name__)

#: Default floor. A verdict citing fewer than this fraction of its indicators
#: in the evidence does not get to close anything unattended.
DEFAULT_FLOOR = 0.6


def _dispositions() -> Any:
    """Load `app.agents.dispositions` lazily, to break a real import cycle.

    Importing it at module scope runs `app/agents/__init__.py`, which pulls in
    `auto_triage_agent` -> `context.knowledge_base` -> ... ->
    `app.prompting.envelope`, which imports `app.investigator` -- whose
    `orchestrator` imports this module. The chain is genuine and predates
    this file; the cycle only closes because this gate is now used from both
    ends of it, which is the point of sharing it.

    Deferred to call time rather than restructured, matching how the tree
    already handles this (see `app/llm/tool_loop.py`, moved for the same
    reason). The import is cached by `sys.modules` after the first call.
    """
    from app.agents import dispositions

    return dispositions


def _truthy(name: str, default: str = "1") -> bool:
    return (os.getenv(name, default) or "").strip().lower() not in ("", "0", "false", "no")


def gate_enabled() -> bool:
    """On by default; disable with `AISOC_AGENT_GROUNDEDNESS_GATE=0`."""
    return _truthy("AISOC_AGENT_GROUNDEDNESS_GATE")


def floor() -> float:
    raw = os.getenv("AISOC_AGENT_GROUNDEDNESS_FLOOR", "")
    try:
        return float(raw) if raw.strip() else DEFAULT_FLOOR
    except ValueError:
        return DEFAULT_FLOOR


@dataclass
class GateOutcome:
    """What the gate decided, and why."""

    verdict: Any
    confidence: float
    #: `None` when the gate did not run -- disabled, not an auto-closing
    #: verdict, no reasoning, or **no evidence to score against**. Distinct
    #: from `0.0`, which means it ran and found nothing supported.
    score: float | None = None
    demoted: bool = False
    reason: str = ""
    hallucinated: tuple[str, ...] = ()
    #: The claim-support measurement, kept whole rather than folded into
    #: `score`. `None` means the check did not run; a result whose own
    #: `scored` is False means it ran and found no decisive claim to trace.
    claim_support: ClaimSupportResult | None = None

    @property
    def skipped(self) -> bool:
        return self.score is None

    @property
    def demoted_for_claims(self) -> bool:
        """Whether the demotion was about an untraceable conclusion, not an indicator."""
        return self.demoted and bool(self.claim_support and self.claim_support.blocks_auto_close)


def evaluate(
    *,
    verdict: Any,
    confidence: float,
    reasoning: str,
    raw_alert: dict[str, Any] | None,
    alert_summary: str | None = None,
    supporting_context: str | None = None,
) -> GateOutcome:
    """Score `reasoning` against the evidence and demote it if it is unsupported.

    Two independent reasons to withhold a closure: indicators the evidence
    does not contain, and decisive claims the evidence cannot support.
    ``supporting_context`` is first-party text that also reached the prompt —
    compiled institutional memory, the tenant's recent analyst decisions —
    which is authoritative for "this is sanctioned here" and is not part of
    the alert payload.

    Pure, so both callers can be tested without a Kafka consumer or an HTTP
    stack behind them.
    """
    unchanged = GateOutcome(verdict=verdict, confidence=confidence)

    if not gate_enabled() or not verdict:
        return unchanged

    dispositions = _dispositions()
    normalized = dispositions.normalize_disposition(str(verdict), default=dispositions.NEEDS_REVIEW)
    if normalized not in dispositions.AUTO_CLOSEABLE_DISPOSITIONS:
        return unchanged
    if not (reasoning or "").strip():
        return unchanged

    # The refusal that makes this safe to wire into a second path.
    #
    # With no evidence, `_extract` finds nothing, every indicator the model
    # mentions is "unsupported", and the gate demotes unconditionally. That is
    # not caution -- it is a measurement of nothing, reported as a finding
    # about the model. Say the gate did not run instead.
    evidence_blob = f"{json.dumps(raw_alert or {}, default=str)}\n{alert_summary or ''}"
    if not (raw_alert or {}):
        logger.debug("groundedness_gate.no_evidence", verdict=str(verdict))
        return GateOutcome(
            verdict=verdict,
            confidence=confidence,
            reason="not scored: the investigation carried no alert payload to score against",
        )

    try:
        result = score_groundedness(reasoning, evidence_blob)
    except Exception as exc:  # noqa: BLE001 - a scoring failure must not change the verdict
        logger.debug("groundedness_gate.failed", error=str(exc))
        return unchanged

    # Runs whatever the indicator score was, because the two are independent:
    # the case this exists for is the one where indicator grounding is 1.0.
    try:
        claims = score_claim_support(reasoning, raw_alert, supporting_context=supporting_context)
    except Exception as exc:  # noqa: BLE001 - same reasoning as above
        logger.debug("claim_support.failed", error=str(exc))
        claims = None

    if result.score >= floor():
        if claims is not None and claims.blocks_auto_close:
            logger.warning(
                "verdict_gate.unsupported_claim",
                verdict=str(verdict),
                groundedness=result.score,
                unsupported=[c.phrase for c in claims.unsupported][:5],
                contradicted=[c.phrase for c in claims.contradicted][:5],
            )
            return GateOutcome(
                verdict=dispositions.NEEDS_REVIEW,
                confidence=min(float(confidence or 0.0), float(claims.score or 0.0)),
                # The indicator score is reported as measured. It passed, and
                # saying otherwise would misname which check withheld this.
                score=result.score,
                demoted=True,
                reason=claims.reason,
                claim_support=claims,
            )
        return GateOutcome(verdict=verdict, confidence=confidence, score=result.score, claim_support=claims)

    hallucinated = tuple(result.hallucinated[:10])
    return GateOutcome(
        verdict=dispositions.NEEDS_REVIEW,
        # Confidence describes the demoted verdict now, not the discarded one.
        confidence=min(float(confidence or 0.0), result.score),
        score=result.score,
        demoted=True,
        reason=(
            f"Verdict demoted to needs_review: only {result.score:.0%} of the indicators cited in "
            f"the reasoning appear in the evidence (unsupported: {', '.join(hallucinated[:5])})."
        ),
        hallucinated=hallucinated,
        claim_support=claims,
    )


__all__ = ["DEFAULT_FLOOR", "GateOutcome", "evaluate", "floor", "gate_enabled"]
