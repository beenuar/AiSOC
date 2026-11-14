"""One definition of "did anyone actually decide about this alert".

Why this module exists
----------------------
``alerts.disposition`` carries two different kinds of value and three
surfaces disagreed about which ones count:

* ``/metrics/funnel`` computed signal-to-noise over ``disposition IN
  ('true_positive', 'false_positive', 'benign', 'duplicate')`` — the
  decided verdicts, which is right.
* ``/metrics/soc`` computed the false-positive rate over ``disposition IS
  NOT NULL``.
* ``/dashboards/soc-insights`` did the same.

The auto-triage worker writes ``needs_review`` on every alert it cannot
decide, so on a live deployment with nine alerts the last two reported a
denominator of five to nine while the first reported zero — three
surfaces answering one question three ways, and the two that included
abstentions were scoring the agent on questions it had explicitly
refused to answer.

``needs_review`` is the abstention this product deliberately publishes
(``/metrics/funnel`` reports ``abstention_rate`` as a trust signal), so
it has to be excluded from verdict arithmetic rather than tidied away.
"""

from __future__ import annotations

from typing import Any, Final

from sqlalchemy.sql.elements import ColumnElement

#: The agent, or an analyst, reached a conclusion. These and only these
#: belong in the denominator of an accuracy figure.
DECIDED_DISPOSITIONS: Final[tuple[str, ...]] = (
    "true_positive",
    "benign_true_positive",
    "false_positive",
    "benign",
    "duplicate",
)

#: Explicitly declining to decide. Mirrors
#: ``app/_vendor/autonomy_evidence_rules.py::ABSTENTION_VERDICTS``, minus
#: the empty string, which is not a value this column holds.
ABSTENTION_DISPOSITIONS: Final[tuple[str, ...]] = ("needs_review", "escalate", "unknown")


def decided_filter(column: Any) -> ColumnElement[bool]:
    """SQL predicate for "a conclusion was reached"."""
    return column.in_(DECIDED_DISPOSITIONS)


def is_decided(disposition: str | None) -> bool:
    """True when the disposition is a conclusion rather than an abstention."""
    if disposition is None:
        return False
    return disposition.strip().lower() in DECIDED_DISPOSITIONS


__all__ = [
    "ABSTENTION_DISPOSITIONS",
    "DECIDED_DISPOSITIONS",
    "decided_filter",
    "is_decided",
]
