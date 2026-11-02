"""Re-triage an open alert when correlated evidence arrives.

Wave 2, Phase 4.4(b).

The gap, and the trap inside it
--------------------------------
Nothing re-triages. Everything points the other way: `_maybe_suppress_from_memory`
short-circuits triage for a repeat, the sink collapses repeats rather than
re-running them, and `attack_chain_grouper.assign()` writes a chain
assignment that re-publishes nothing.

The trap is that **the obvious implementation writes nothing and reports
success.** The run id is deterministic —

    run_id = uuid5(_NAMESPACE, f"{alert_row_id}:{WORKFLOW_VERSION}")

— and every ledger write is `ON CONFLICT (run_id, seq) DO NOTHING`. That
pairing is what makes a Kafka redelivery idempotent, and it is correct. But
it means a second triage of the same alert resolves to the same run id,
collides on seq 0 and seq 1, and leaves the ledger exactly as it was. The
alert row would be updated, the ledger would still describe the first
verdict, and nothing would say a second one had ever been reached.

So a re-triage needs its own identity, and the plan requires more than that:
the ledger has to show **the diff between verdicts**.

The identity
------------
`uuid5(namespace, f"{alert_row_id}:{WORKFLOW_VERSION}:retriage:{trigger}")`
where `trigger` is a stable fingerprint of the evidence that caused it.

Deterministic, so the same trigger arriving twice — a redelivered chain
assignment, a replayed correlation — resolves to one run and stays
idempotent, which is the property the original design was protecting.
Distinct per trigger, so a genuinely new piece of evidence gets a new run
rather than being swallowed.

Not a counter, deliberately. A counter would need durable state of its own
and would make a redelivery look like new evidence, which is the failure
this is built to avoid.

The diff
--------
`verdict_diff` is a record, not a log line. An escalation an analyst cannot
audit from the alert is the same defect as a story severity whose reason
lives in a log — it is recorded on the run so the question "why did this
change" is answerable from the ledger alone. `changed` is explicit rather
than inferred from comparing two fields, because a re-triage that reached
the *same* verdict is a real and useful outcome (the new evidence did not
move it) and must be tellable from one that moved.

What this does not do
---------------------
It does not close anything. A re-triage reaching a closeable verdict goes
through exactly the same chokepoint every other verdict does —
`authorize_auto_closure` inside `persist_auto_triage` — and that chokepoint
is deliberately at the write, so a re-triage cannot route around it. This
module decides only *whether to run again* and *under what identity*.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from typing import Any

import structlog

logger = structlog.get_logger()

#: Ceiling on re-triages of one alert. Correlated evidence can arrive many
#: times for a noisy entity, and an alert that is re-triaged on every arrival
#: is a model call per arrival on the hot path. A ceiling that is not
#: declared is not a ceiling.
MAX_RETRIAGES_PER_ALERT = 3

#: Verdicts whose alert is still open enough to be worth re-triaging. A
#: resolved alert is not re-opened by new evidence here: re-opening a closed
#: alert is an analyst-visible state change, and doing it automatically on a
#: correlation is a decision nobody has asked for.
_OPEN_VERDICTS = frozenset({"needs_review", "true_positive", "suspicious", "unknown"})


@dataclass(frozen=True)
class RetriageTrigger:
    """Why a re-triage is being considered, and what makes it distinct."""

    #: Short, closed vocabulary. Rendered into the ledger summary.
    kind: str
    #: What arrived. Hashed into the run identity, so two different pieces of
    #: evidence produce two runs and the same one produces one.
    evidence: dict[str, Any]

    def fingerprint(self) -> str:
        try:
            canonical = json.dumps(self.evidence, sort_keys=True, default=str)
        except (TypeError, ValueError):
            canonical = str(self.evidence)
        return hashlib.sha256(f"{self.kind}\x00{canonical}".encode()).hexdigest()[:32]


@dataclass(frozen=True)
class VerdictDiff:
    """What a re-triage changed, as a record rather than a log line."""

    previous_verdict: str
    previous_confidence: float
    new_verdict: str
    new_confidence: float
    trigger_kind: str
    trigger_fingerprint: str
    generation: int

    @property
    def changed(self) -> bool:
        return self.previous_verdict != self.new_verdict

    def as_payload(self) -> dict[str, Any]:
        return {
            "previous_verdict": self.previous_verdict,
            "previous_confidence": round(float(self.previous_confidence or 0.0), 4),
            "new_verdict": self.new_verdict,
            "new_confidence": round(float(self.new_confidence or 0.0), 4),
            # Explicit, never inferred by a reader comparing the two fields
            # above: a re-triage that reached the same verdict is a real
            # outcome — the new evidence did not move it — and must be
            # tellable from one that moved.
            "changed": self.changed,
            "confidence_delta": round(float(self.new_confidence or 0.0) - float(self.previous_confidence or 0.0), 4),
            "trigger": self.trigger_kind,
            "trigger_fingerprint": self.trigger_fingerprint,
            "generation": self.generation,
        }

    def summary(self) -> str:
        if self.changed:
            return (
                f"re-triage #{self.generation} on {self.trigger_kind}: "
                f"{self.previous_verdict} -> {self.new_verdict} "
                f"(confidence {self.previous_confidence:.2f} -> {self.new_confidence:.2f})"
            )
        return (
            f"re-triage #{self.generation} on {self.trigger_kind}: verdict unchanged at "
            f"{self.new_verdict} (confidence {self.previous_confidence:.2f} -> {self.new_confidence:.2f})"
        )


def retriage_run_id(
    namespace: uuid.UUID,
    *,
    alert_row_id: str,
    workflow_version: str,
    trigger: RetriageTrigger,
) -> uuid.UUID:
    """The run identity for a re-triage. Deterministic, and distinct per trigger.

    The whole point: without this, a second triage of one alert resolves to
    the first run's id, collides on `(run_id, seq)` and writes nothing while
    reporting success.
    """
    return uuid.uuid5(
        namespace,
        f"{alert_row_id}:{workflow_version}:retriage:{trigger.fingerprint()}",
    )


def should_retriage(
    *,
    previous_verdict: str | None,
    generation: int,
    trigger: RetriageTrigger,
) -> tuple[bool, str]:
    """Whether this alert should be triaged again, and the reason either way.

    The reason is returned rather than logged because "re-triage declined"
    alone makes a control that has silently stopped working look identical
    to one that is working — the same argument the suppression path already
    records for its own refusals.
    """
    if generation > MAX_RETRIAGES_PER_ALERT:
        return False, f"ceiling reached ({MAX_RETRIAGES_PER_ALERT} re-triages)"
    verdict = (previous_verdict or "").strip().lower()
    if not verdict:
        return False, "no previous verdict to re-examine"
    if verdict not in _OPEN_VERDICTS:
        # Re-opening a closed alert is an analyst-visible state change, and
        # doing it automatically on a correlation is a decision nobody asked
        # for. Recorded as a refusal rather than silently skipped.
        return False, f"previous verdict {verdict!r} is not an open state"
    if not trigger.evidence:
        return False, "trigger carried no evidence"
    return True, f"{trigger.kind} arrived on an alert still at {verdict}"


def chain_escalation_trigger(assignment: dict[str, Any] | None) -> RetriageTrigger | None:
    """A story that escalated its members is correlated evidence arriving.

    Phase 3.2 computes a story severity above its highest member when the
    story spans three or more kill-chain stages, and records the reason. An
    alert that was benign on its own and now sits inside such a story is
    precisely the case 4.4(b) exists for.

    Returns None when the assignment carries no escalation, so an ordinary
    chain join does not re-triage every member of a busy story.
    """
    if not isinstance(assignment, dict):
        return None
    reason = str(assignment.get("escalation_reason") or "").strip()
    if not reason:
        return None
    return RetriageTrigger(
        kind="story_escalation",
        evidence={
            "chain_id": str(assignment.get("chain_id") or ""),
            "story_severity": str(assignment.get("story_severity") or ""),
            "member_count": int(assignment.get("member_count") or 0),
            "stage_span": int(assignment.get("stage_span") or 0),
        },
    )
