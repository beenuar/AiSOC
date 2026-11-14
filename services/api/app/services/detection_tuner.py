"""Self-improving detections — feedback -> rule-tuning suggestions (Wave 4c).

Analyst dispositions already flow into institutional memory, but nothing closed
the loop back to the *detections*: a rule that fires 50 times a week and is
dismissed false-positive every time keeps firing. This module derives
**human-approval-gated** tuning suggestions from disposition history:

* A rule with a high false-positive rate over a window and enough samples is a
  tuning candidate.
* If the false positives cluster on one entity (host/user/ip), suggest an
  *exception* for that entity (surgical) rather than weakening the rule.
* Otherwise suggest *lower_severity* (still fires, less noise) or, only when the
  FP rate is overwhelming and corroborated by multiple human analysts,
  *suppress*.

Suggestions are never auto-applied — they are proposals an engineer reviews
(copilot posture). ``benign_true_positive`` is treated as a VALID detection and
is NOT counted toward the FP rate (#526), so authorized activity never tunes a
good rule into silence.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field

# Dispositions that count as an invalid detection (drives the FP rate). BTP and
# true_positive are excluded on purpose.
_FP_DISPOSITIONS = frozenset({"false_positive"})
_VALID_DETECTION = frozenset({"true_positive", "benign_true_positive"})


@dataclass(frozen=True)
class DispositionRecord:
    rule_id: str
    disposition: str
    entity: str | None = None  # host/user/ip the alert was about
    human_verified: bool = False


@dataclass(frozen=True)
class TuningSuggestion:
    rule_id: str
    action: str  # "add_exception" | "lower_severity" | "suppress"
    fp_rate: float
    sample_count: int
    entity: str | None = None
    human_confirmations: int = 0
    rationale: str = ""
    # Explicitly proposal-only; an engineer must approve before it changes a rule.
    requires_approval: bool = True
    evidence: dict[str, int] = field(default_factory=dict)


def suggest_tuning(
    records: list[DispositionRecord],
    *,
    min_samples: int = 10,
    fp_rate_threshold: float = 0.7,
    suppress_fp_rate: float = 0.95,
    min_human_confirmations: int = 2,
    entity_cluster_fraction: float = 0.6,
) -> list[TuningSuggestion]:
    """Derive tuning suggestions from per-rule disposition history."""
    by_rule: dict[str, list[DispositionRecord]] = defaultdict(list)
    for r in records:
        if r.rule_id:
            by_rule[r.rule_id].append(r)

    suggestions: list[TuningSuggestion] = []
    for rule_id, rows in by_rule.items():
        # Denominator excludes needs_review/unknown; count only decided outcomes.
        _decided_dispositions = _FP_DISPOSITIONS | _VALID_DETECTION | {"benign"}
        decided = [r for r in rows if r.disposition in _decided_dispositions]
        if len(decided) < min_samples:
            continue
        fps = [r for r in decided if r.disposition in _FP_DISPOSITIONS]
        fp_rate = len(fps) / len(decided)
        if fp_rate < fp_rate_threshold:
            continue

        human_confirms = sum(1 for r in fps if r.human_verified)
        # Does the FP cluster on a single entity?
        entity_counts = Counter(r.entity for r in fps if r.entity)
        top_entity, top_count = entity_counts.most_common(1)[0] if entity_counts else (None, 0)
        clusters = bool(top_entity) and (top_count / len(fps)) >= entity_cluster_fraction

        if clusters:
            action, entity = "add_exception", top_entity
            rationale = (
                f"{top_count}/{len(fps)} false positives cluster on entity '{top_entity}' "
                "— propose a scoped exception, not a rule-wide change."
            )
        elif fp_rate >= suppress_fp_rate and human_confirms >= min_human_confirmations:
            action, entity = "suppress", None
            rationale = (
                f"{fp_rate:.0%} false-positive rate over {len(decided)} decided alerts with "
                f"{human_confirms} human confirmations — propose suppression pending review."
            )
        else:
            action, entity = "lower_severity", None
            rationale = (
                f"{fp_rate:.0%} false-positive rate over {len(decided)} decided alerts "
                "— propose lowering severity to reduce noise while keeping visibility."
            )

        suggestions.append(
            TuningSuggestion(
                rule_id=rule_id,
                action=action,
                fp_rate=round(fp_rate, 3),
                sample_count=len(decided),
                entity=entity,
                human_confirmations=human_confirms,
                rationale=rationale,
                evidence={
                    "false_positives": len(fps),
                    "decided": len(decided),
                    "valid_detections": sum(1 for r in decided if r.disposition in _VALID_DETECTION),
                },
            )
        )

    suggestions.sort(key=lambda s: (s.fp_rate, s.sample_count), reverse=True)
    return suggestions
