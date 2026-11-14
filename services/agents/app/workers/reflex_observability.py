"""What the reflex path did, stage by stage, and the contract its decision carries.

The reflex path — fused alert in, triage verdict out — was observable only as
a total: the agent logged one latency figure and the summary carried none,
so "triage is slow" could not be split into the queue, the context fetch,
the model, the verification gates or the persistence that actually spent the
time. The stage timer here is deliberately dumb: named monotonic spans,
accumulated per alert, reported in milliseconds on the summary and the log
line that already carries the run id — so a timing joins the outcome it
describes through the ids that exist rather than a new correlation scheme.

The decision contract is the other half. The verdict summary carried a
verdict, a confidence and prose findings; what it did not carry was the
*shape* a reviewer needs: what disposition was actually taken, which
evidence supported the decisive claims, which evidence contradicted them,
what was missing, and why the alert escalated if it did. All of that already
existed as scattered structure — the claim-support review, the groundedness
score, the injection scan, the closure-policy reason — and this assembles
it, inventing nothing: a field whose signal never ran is ``None``, never an
empty list pretending the check happened.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Any

__all__ = ["StageTimer", "decision_contract", "queue_delay_ms"]


class StageTimer:
    """Named monotonic spans, accumulated per alert.

    ``measure`` brackets a stage; repeated stages accumulate, so a retry
    inside one alert shows up as a bigger number rather than a lost one.
    Milliseconds, rounded to one decimal: the reflex path's interesting
    differences are tens of milliseconds, and microsecond noise in a report
    invites diffing two runs on digits that measure the host.
    """

    def __init__(self) -> None:
        self._started = time.monotonic()
        self._stages: dict[str, float] = {}

    def add(self, stage: str, seconds: float) -> None:
        self._stages[stage] = self._stages.get(stage, 0.0) + seconds

    def measure(self, stage: str) -> _Span:
        return _Span(self, stage)

    def as_millis(self) -> dict[str, float]:
        """Every measured stage plus the total since construction."""
        out = {name: round(seconds * 1000.0, 1) for name, seconds in sorted(self._stages.items())}
        out["total"] = round((time.monotonic() - self._started) * 1000.0, 1)
        return out


class _Span:
    def __init__(self, timer: StageTimer, stage: str) -> None:
        self._timer = timer
        self._stage = stage
        self._t0 = 0.0

    def __enter__(self) -> _Span:
        self._t0 = time.monotonic()
        return self

    def __exit__(self, *_: Any) -> None:
        self._timer.add(self._stage, time.monotonic() - self._t0)


def queue_delay_ms(message: dict[str, Any] | None) -> float | None:
    """How long the fused alert waited between fusion and triage, when knowable.

    Read off the envelope's ``fused_at`` against the wall clock. ``None`` when
    the envelope carries no parseable timestamp — a replayed historical
    finding legitimately has none, and inventing a delay for it would put a
    plausible-looking number on a measurement nobody took. A negative delay
    (clock skew between the fusion host and this one) is reported as
    measured, because hiding skew is how two hosts' clocks stay wrong.
    """
    if not isinstance(message, dict):
        return None
    raw = message.get("fused_at")
    if not raw:
        return None
    try:
        if isinstance(raw, datetime):
            fused_at = raw if raw.tzinfo else raw.replace(tzinfo=UTC)
        else:
            fused_at = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
            if fused_at.tzinfo is None:
                fused_at = fused_at.replace(tzinfo=UTC)
    except ValueError:
        return None
    return round((datetime.now(UTC) - fused_at).total_seconds() * 1000.0, 1)


def _operational_disposition(*, auto_closed: bool, suppressed_by_memory: bool, escalated: bool) -> str:
    """What actually happened to the alert, as one word a queue can filter on.

    Distinct from the verdict: a ``false_positive`` verdict below the
    confidence threshold is an *escalation*, and reading the verdict alone
    says the opposite.
    """
    if suppressed_by_memory:
        return "suppressed_repeat"
    if auto_closed:
        return "auto_closed"
    if escalated:
        return "escalated_to_investigation"
    return "queued_for_review"


def decision_contract(
    state: Any,
    *,
    verdict: Any,
    confidence: float,
    tier: str,
    auto_closed: bool,
    suppressed_by_memory: bool = False,
    escalated: bool = False,
) -> dict[str, Any]:
    """The decision as a reviewable shape, assembled from signals that ran.

    Nothing here is computed fresh — every field reads structure the triage
    path already produced, so the contract cannot disagree with the ledger.
    A signal that never ran on this path reports ``None``, which a renderer
    shows as *not evaluated*; an empty list means the signal ran and found
    nothing, and the two must never be collapsed.
    """
    claim_review = getattr(state, "claim_review", None) or {}
    findings = [str(f) for f in (getattr(state, "findings", None) or [])]

    # The gates that demote or block record themselves in findings with
    # fixed lead phrases; the contract surfaces them as the machine-readable
    # reasons they are, pointing back at the prose for the detail.
    blocked = [f for f in findings if f.startswith(("Auto-close blocked", "Auto-close withheld"))]
    demoted = [f for f in findings if "demoted" in f.lower()]

    missing: list[str] = []
    if tier == "deterministic":
        missing.append("no model call was placed; the deterministic scorer answered")
    if getattr(state, "injection_suspected", False):
        missing.append("retrieved context was withheld for suspected prompt injection")

    escalation_reason: str | None = None
    if not auto_closed and not suppressed_by_memory:
        if blocked:
            escalation_reason = blocked[0]
        elif demoted:
            escalation_reason = demoted[0]
        elif str(verdict) == "true_positive":
            escalation_reason = "confirmed threat: a true positive always escalates"
        else:
            escalation_reason = f"verdict {verdict!r} at confidence {confidence:.2f} did not meet the closure policy"

    return {
        "verdict": str(verdict) if verdict else None,
        "operational_disposition": _operational_disposition(
            auto_closed=auto_closed,
            suppressed_by_memory=suppressed_by_memory,
            escalated=escalated,
        ),
        "rationale": next(iter(getattr(state, "confidence_basis", None) or []), None),
        # Supported / unsupported / contradicted decisive claims, when the
        # claim-support gate ran (the LLM path). None elsewhere — the
        # deterministic scorer makes no prose claims to review.
        "supporting_evidence": claim_review.get("supported") if claim_review else None,
        "contradictory_evidence": claim_review.get("contradicted") if claim_review else None,
        "contradicted_by": claim_review.get("contradicted_by") if claim_review else None,
        "groundedness": getattr(state, "groundedness", None),
        "missing_prerequisites": missing,
        "blocked_or_demoted_by": blocked + demoted,
        "escalation_reason": escalation_reason,
    }
