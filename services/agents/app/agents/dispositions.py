"""Canonical triage disposition taxonomy + normalization layer (#526).

The auto-triage LLM and the deterministic fallback scorer historically spoke
different dialects (``benign`` / ``false_positive`` vs. ``likely_benign`` /
``needs_review`` / ``confirmed_incident``). This module is the single
normalization layer that reconciles them, and it introduces an explicit
``benign_true_positive`` outcome.

The taxonomy separates two *independent* questions:

* **Detection validity** — did the rule correctly detect its intended
  condition?
* **Activity maliciousness** — was the detected activity an actual threat?

  - ``true_positive``        valid detection of malicious / unauthorized
                             activity.
  - ``benign_true_positive`` valid detection of AUTHORIZED, expected, or
                             non-malicious activity (an approved penetration
                             test, a scheduled vulnerability scan, sanctioned
                             admin tooling). The rule was CORRECT, so this must
                             NOT be recorded as a false positive — doing so
                             corrupts per-rule false-positive-rate metrics and
                             unfairly penalizes good detections.
  - ``false_positive``       invalid / noisy detection; the intended condition
                             was not actually present.
  - ``benign``               real but non-threatening activity that is not a
                             detection-validity statement (informational).
                             Retained for backward compatibility — see the
                             migration note below.
  - ``needs_review``         insufficient evidence to decide safely; route to a
                             human / the full pipeline.
  - ``escalate``             analyst-forced escalation.

Compatibility / migration
--------------------------
Existing ``benign`` records remain valid and are intentionally left untouched:
``benign`` and ``benign_true_positive`` are *distinct* outcomes (the former
makes no claim about detection validity), so no data backfill is required.
Consumers that compute false-positive rate already key on the literal
``false_positive`` string, so ``benign_true_positive`` is naturally excluded
from FP metrics and kept separate on dashboards, filters, and exports.
"""

from __future__ import annotations

TRUE_POSITIVE = "true_positive"
BENIGN_TRUE_POSITIVE = "benign_true_positive"
FALSE_POSITIVE = "false_positive"
BENIGN = "benign"
NEEDS_REVIEW = "needs_review"
ESCALATE = "escalate"

#: Every disposition the platform recognises as canonical.
CANONICAL_DISPOSITIONS: frozenset[str] = frozenset(
    {
        TRUE_POSITIVE,
        BENIGN_TRUE_POSITIVE,
        FALSE_POSITIVE,
        BENIGN,
        NEEDS_REVIEW,
        ESCALATE,
    }
)

#: Verdicts the auto-triage LLM is allowed to emit directly.
LLM_VERDICTS: frozenset[str] = frozenset(
    {TRUE_POSITIVE, BENIGN_TRUE_POSITIVE, FALSE_POSITIVE, BENIGN, NEEDS_REVIEW}
)

#: Dispositions that indicate the detection itself was INVALID. Used for
#: false-positive-rate / rule-tuning metrics. Deliberately excludes
#: ``benign_true_positive`` (a valid detection) so BTP never inflates FPR.
INVALID_DETECTION_DISPOSITIONS: frozenset[str] = frozenset({FALSE_POSITIVE})

#: Dispositions safe to auto-close without a human — no active threat and no
#: response action required.
AUTO_CLOSEABLE_DISPOSITIONS: frozenset[str] = frozenset(
    {FALSE_POSITIVE, BENIGN, BENIGN_TRUE_POSITIVE}
)

# Graded / vendor / legacy verdicts → canonical. Keys are compared after
# lower-casing and collapsing separators to ``_``.
_ALIASES: dict[str, str] = {
    # deterministic triage scorer (confidence/scoring.py: score_triage)
    "likely_true_positive": TRUE_POSITIVE,
    "likely_benign": BENIGN,
    # deterministic investigation scorer (confidence/scoring.py: score_investigation)
    "confirmed_incident": TRUE_POSITIVE,
    "probable_incident": TRUE_POSITIVE,
    "needs_human_review": NEEDS_REVIEW,
    "likely_false_positive": FALSE_POSITIVE,
    # common synonyms
    "btp": BENIGN_TRUE_POSITIVE,
    "benign_tp": BENIGN_TRUE_POSITIVE,
    "authorized": BENIGN_TRUE_POSITIVE,
    "tp": TRUE_POSITIVE,
    "fp": FALSE_POSITIVE,
    "true positive": TRUE_POSITIVE,
    "false positive": FALSE_POSITIVE,
    "benign true positive": BENIGN_TRUE_POSITIVE,
}


def normalize_disposition(value: object, *, default: str = TRUE_POSITIVE) -> str:
    """Map any verdict/disposition string to a canonical disposition.

    Unknown / non-string values fall back to ``default`` (``true_positive`` by
    default so the fail-safe is to *not* silently close an alert). This is the
    consistency layer shared by the LLM path and the deterministic fallback.
    """
    if not isinstance(value, str):
        return default
    key = value.strip().lower().replace("-", "_").replace(" ", "_")
    if key in CANONICAL_DISPOSITIONS:
        return key
    return _ALIASES.get(key, _ALIASES.get(value.strip().lower(), default))
