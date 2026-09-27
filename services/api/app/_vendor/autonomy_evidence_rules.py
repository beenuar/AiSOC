"""How agreement between the agent and a tenant's analysts is measured, decided once.

Gap-closure Phase 2.2. The promotion gate that reads these numbers arrives in
Phase 2.3 and sits on top of this file rather than beside it.

Two services have to agree about this and neither can import the other.
``services/actions`` enforces autonomy at dispatch, where an over-generous
answer executes something at a customer's vendor. ``services/api`` renders the
track record and decides promotions, owns the tenant session and owns the
hash-chained audit log a transition is written to. Both package their code as
top-level ``app``, so one process holds one of them, and each Docker image is
built with only its own service directory as context.

So this module is pure: standard library only, no database handle, no HTTP
client, no service import. ``services/api`` carries a byte-identical copy at
``app/_vendor/autonomy_evidence_rules.py`` and
``scripts/sync_vendored_autonomy_evidence.py --check`` fails the build when the
two drift. Same arrangement as the LLM input contract and the deterministic
narrative, and used here for a stronger reason: a safety control that two
services define differently is a control that is off in whichever one is more
generous, and nobody finds out until something executes that the other half
would have refused.

The metrics are Phase 1's, not a second set
===========================================

``packages/aisoc-benchmark/aisoc_benchmark/replay.py`` already defines what
"malicious recall" means, which verdicts are abstentions, which dispositions
may be graded, and that a rate with no denominator is ``None`` rather than
zero. Restating any of those differently here would give live measurement a
private definition of accuracy, and the first time the two disagreed the
replay report and the scorecard would be describing different agents while
both looked right. ``scripts/check_replay_contract_parity.py`` compares the
constants below against that module in both directions.

Agreement is computed over answered decisions only
==================================================

This is the one a naive implementation gets wrong, and it is worth stating
where the arithmetic is rather than where it is read. If agreement counted
every decision and scored an abstention as "not a disagreement", an agent that
answered a tenth of its queue confidently and routed the rest to a human would
post a near-perfect record on a population it never attempted. Abstaining
removes a decision from the numerator and the denominator together, so it
cannot move the rate; what it moves is
:attr:`AgreementWindow.abstention_rate`, which is reported beside it.

Malicious recall is the counterweight and runs the other way: its denominator
is every malicious case, abstained or not, so an abstention counts there as a
miss. Phase 1 makes exactly that distinction, for exactly that reason, and an
alert routed to a human was not caught by the agent.

A window and a trailing slice, never just the window
====================================================

A thirty-day window is an average, and an average is where a gradual decline
hides: an agent that agreed 99% of the time for three weeks and 70% of the
time this week still posts about 95% over the window. So the aggregate comes
in two statements, one over the window and one over the most recent
:attr:`PromotionThresholds.drift_sample` decisions, and every surface that
shows one shows both. The trailing slice is a count rather than a date range
so it means the same thing for a tenant with ten alerts a day and for one with
ten thousand.

The thresholds live here even though nothing in this file enforces them
======================================================================

:class:`PromotionThresholds` carries the window length, which this file needs,
and the floors, which it does not. They travel together because the scorecard
shows progress toward them ("47 of the 100 decisions, 12 of the 30 malicious
ones") and because a floor stated in one service and enforced in another is
the pair that drifts.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

__all__ = [
    "ABSTENTION_VERDICTS",
    "AGREEMENT_COUNTS_SQL",
    "DEFAULT_THRESHOLDS",
    "GRADED_DISPOSITIONS",
    "MALICIOUS",
    "RECENT_COUNTS_SQL",
    "UNLABELED",
    "AgreementWindow",
    "PromotionThresholds",
    "scoped_sql",
    "to_named_params",
    "window_from_counts",
]

#: The disposition that means "this was a real threat". One spelling, shared
#: with the writeback taxonomy and the replay grader.
MALICIOUS = "true_positive"

#: What an analyst may close a finding as. Mirrors ``GRADED_DISPOSITIONS`` in
#: the benchmark package and ``CANONICAL_DISPOSITIONS`` in the writeback, both
#: pinned by ``scripts/check_replay_contract_parity.py``.
GRADED_DISPOSITIONS: tuple[str, ...] = (
    MALICIOUS,
    "benign_true_positive",
    "false_positive",
    "benign",
)

#: An analyst who declined to classify. Excluded from agreement entirely,
#: never guessed at.
UNLABELED = "unlabeled"

#: Agent outputs that route the alert to a human rather than deciding it.
#: Counted apart from agreement so the two cannot be traded off invisibly.
ABSTENTION_VERDICTS: frozenset[str] = frozenset({"needs_review", "escalate", "unknown", ""})


@dataclass(frozen=True)
class PromotionThresholds:
    """What a tenant's track record has to show. Every value is configurable.

    Defaults are the plan's: 100 decisions, at least 30 of them malicious.
    The rest are set here rather than left to a caller because a threshold
    with no default is a threshold somebody eventually passes zero for.
    """

    #: Labelled decisions required in the window.
    min_decisions: int = 100
    #: How many of those must have been closed by an analyst as malicious.
    min_malicious: int = 30
    #: Agreement over *answered* decisions required to promote.
    min_agreement: float = 0.95
    #: Recall on malicious required to promote. An abstention is a miss.
    min_malicious_recall: float = 0.90
    #: Share of labelled decisions that may be abstentions.
    max_abstention_rate: float = 0.30
    #: How far back the window reaches.
    window_days: int = 30
    #: Agreement below this demotes an existing grant.
    demotion_agreement: float = 0.90
    #: Malicious recall below this demotes an existing grant.
    demotion_malicious_recall: float = 0.80
    #: Size of the trailing slice scored separately, so gradual drift inside a
    #: passing window is still caught.
    drift_sample: int = 50
    #: The trailing slice needs at least this many answered decisions before
    #: it may demote on its own. Without it a single disagreement in a quiet
    #: week would revoke a grant built on months of evidence.
    drift_min_answered: int = 20

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


DEFAULT_THRESHOLDS = PromotionThresholds()


def _ratio(numerator: int, denominator: int) -> float | None:
    """A rate, or ``None`` when there was nothing to divide by.

    ``None`` renders as "not measured". A ``0.0`` in an agreement column says
    the agent was wrong every time; no denominator says it was never asked,
    and those call for opposite responses.
    """
    return (numerator / denominator) if denominator else None


@dataclass(frozen=True)
class AgreementWindow:
    """Agreement between the agent and the analysts over one slice of history.

    Every rate on this object is accompanied by the count it was computed
    over, and is ``None`` when that count is zero. A caller that renders a
    rate without its count has thrown away the difference between a
    measurement and a coincidence.
    """

    #: Shadow decisions in the slice that an analyst has since closed.
    resolved: int = 0
    #: Of those, the ones carrying a disposition this platform can name.
    labelled: int = 0
    #: Labelled decisions the agent declined to decide.
    abstained: int = 0
    #: Labelled decisions the agent answered. The denominator of agreement.
    answered: int = 0
    #: Answered decisions where the agent's verdict is the analyst's label.
    agreed: int = 0
    #: Labelled decisions an analyst closed as malicious.
    malicious_support: int = 0
    #: Of those, the ones the agent also called malicious.
    malicious_caught: int = 0

    def __post_init__(self) -> None:
        # A window whose parts do not add up is a bug in the aggregate query,
        # and it would show as a plausible-looking rate rather than an error.
        if self.answered + self.abstained != self.labelled:
            raise ValueError(
                f"answered ({self.answered}) + abstained ({self.abstained}) must equal "
                f"labelled ({self.labelled}); the aggregate query and this type disagree"
            )
        if self.labelled > self.resolved:
            raise ValueError(f"labelled ({self.labelled}) cannot exceed resolved ({self.resolved})")
        if self.agreed > self.answered:
            raise ValueError(f"agreed ({self.agreed}) cannot exceed answered ({self.answered})")
        if self.malicious_caught > self.malicious_support:
            raise ValueError(f"malicious_caught ({self.malicious_caught}) cannot exceed malicious_support ({self.malicious_support})")

    @property
    def unlabeled(self) -> int:
        """Closures the analyst left unclassified. Excluded from every rate."""
        return self.resolved - self.labelled

    @property
    def agreement_rate(self) -> float | None:
        """Agreement over answered decisions only.

        Abstentions are absent from both halves of this fraction. That is
        what stops an agent from earning a grant by declining the hard cases:
        declining removes a decision from the numerator and the denominator
        together, so the rate does not move and the abstention rate does.
        """
        return _ratio(self.agreed, self.answered)

    @property
    def malicious_recall(self) -> float | None:
        """Share of the analysts' malicious closures the agent also called malicious.

        The denominator is every malicious case, answered or abstained, so an
        abstention counts as a miss here even though it is excluded from
        agreement. An alert routed to a human was not caught by the agent.
        """
        return _ratio(self.malicious_caught, self.malicious_support)

    @property
    def abstention_rate(self) -> float | None:
        return _ratio(self.abstained, self.labelled)

    def as_dict(self) -> dict[str, Any]:
        """Counts and the rates derived from them, in one payload.

        The derived rates are included rather than left to the reader because
        this dict is what lands in the audit log, and a snapshot that stores
        only counts requires whoever reads it in six months to re-derive the
        arithmetic and hope they used the same definition.
        """
        return {
            "resolved": self.resolved,
            "labelled": self.labelled,
            "unlabeled": self.unlabeled,
            "answered": self.answered,
            "abstained": self.abstained,
            "agreed": self.agreed,
            "malicious_support": self.malicious_support,
            "malicious_caught": self.malicious_caught,
            "agreement_rate": self.agreement_rate,
            "malicious_recall": self.malicious_recall,
            "abstention_rate": self.abstention_rate,
        }


def window_from_counts(counts: dict[str, Any]) -> AgreementWindow:
    """Build a window from the aggregate query's row.

    Takes a mapping rather than keyword arguments because both callers get one
    from their driver, and asyncpg's ``Record`` and SQLAlchemy's ``RowMapping``
    are both mappings while neither is a dict.
    """
    return AgreementWindow(
        resolved=int(counts.get("resolved") or 0),
        labelled=int(counts.get("labelled") or 0),
        abstained=int(counts.get("abstained") or 0),
        answered=int(counts.get("answered") or 0),
        agreed=int(counts.get("agreed") or 0),
        malicious_support=int(counts.get("malicious_support") or 0),
        malicious_caught=int(counts.get("malicious_caught") or 0),
    )


# ---------------------------------------------------------------------------
# The aggregate, written once
# ---------------------------------------------------------------------------
#
# Both services run these two statements verbatim. Aggregating in the database
# rather than fetching rows keeps the dispatch path from pulling a month of
# decisions across the wire to divide two numbers, and writing the statement
# here rather than in each service is what stops one of them from quietly
# counting abstentions into agreement.
#
# The placeholders are numbered (`$1`) for asyncpg. SQLAlchemy callers pass the
# statement through `text()` after `to_named_params()` renames them, because
# the two drivers disagree about placeholder syntax and only about that.

#: Scope filters are applied by the caller as an additional predicate, appended
#: where this marker sits. Written as a marker rather than as string
#: concatenation at the call site so both services splice at the same point.
_SCOPE_MARKER = "/*scope*/"

AGREEMENT_COUNTS_SQL = f"""
SELECT
    COUNT(*)::int AS resolved,
    COUNT(*) FILTER (WHERE d.analyst_disposition = ANY($2::text[]))::int AS labelled,
    COUNT(*) FILTER (
        WHERE d.analyst_disposition = ANY($2::text[])
          AND COALESCE(d.verdict, '') = ANY($3::text[])
    )::int AS abstained,
    COUNT(*) FILTER (
        WHERE d.analyst_disposition = ANY($2::text[])
          AND NOT (COALESCE(d.verdict, '') = ANY($3::text[]))
    )::int AS answered,
    COUNT(*) FILTER (
        WHERE d.analyst_disposition = ANY($2::text[])
          AND NOT (COALESCE(d.verdict, '') = ANY($3::text[]))
          AND d.verdict = d.analyst_disposition
    )::int AS agreed,
    COUNT(*) FILTER (WHERE d.analyst_disposition = $4)::int AS malicious_support,
    COUNT(*) FILTER (WHERE d.analyst_disposition = $4 AND d.verdict = $4)::int AS malicious_caught
FROM aisoc_shadow_decisions d
WHERE d.tenant_id = $1
  AND d.resolved_at IS NOT NULL
  AND d.resolved_at >= $5
  AND d.resolved_at <= $6
  {_SCOPE_MARKER}
"""

#: Same counts over the most recent ``$7`` resolved decisions. The slice is by
#: count rather than by date so it means the same thing at ten alerts a day and
#: at ten thousand, and it is ordered by ``resolved_at`` rather than by
#: ``decided_at`` because a decision only joins the evidence when an analyst
#: closes it.
RECENT_COUNTS_SQL = f"""
WITH recent AS (
    SELECT d.verdict, d.analyst_disposition
    FROM aisoc_shadow_decisions d
    WHERE d.tenant_id = $1
      AND d.resolved_at IS NOT NULL
      AND d.resolved_at >= $5
      AND d.resolved_at <= $6
      {_SCOPE_MARKER}
    ORDER BY d.resolved_at DESC, d.id DESC
    LIMIT $7
)
SELECT
    COUNT(*)::int AS resolved,
    COUNT(*) FILTER (WHERE d.analyst_disposition = ANY($2::text[]))::int AS labelled,
    COUNT(*) FILTER (
        WHERE d.analyst_disposition = ANY($2::text[])
          AND COALESCE(d.verdict, '') = ANY($3::text[])
    )::int AS abstained,
    COUNT(*) FILTER (
        WHERE d.analyst_disposition = ANY($2::text[])
          AND NOT (COALESCE(d.verdict, '') = ANY($3::text[]))
    )::int AS answered,
    COUNT(*) FILTER (
        WHERE d.analyst_disposition = ANY($2::text[])
          AND NOT (COALESCE(d.verdict, '') = ANY($3::text[]))
          AND d.verdict = d.analyst_disposition
    )::int AS agreed,
    COUNT(*) FILTER (WHERE d.analyst_disposition = $4)::int AS malicious_support,
    COUNT(*) FILTER (WHERE d.analyst_disposition = $4 AND d.verdict = $4)::int AS malicious_caught
FROM recent d
"""


def scoped_sql(statement: str, predicate: str = "") -> str:
    """Splice a scope predicate into one of the statements above.

    The predicate is written by the caller from a fixed vocabulary of column
    names and placeholder numbers; nothing derived from a request reaches it.
    Passing an empty predicate scores every class the tenant runs, which is
    the tenant-wide row the scorecard leads with.
    """
    return statement.replace(_SCOPE_MARKER, predicate)


def to_named_params(statement: str, names: list[str]) -> str:
    """Rewrite ``$1 … $n`` into ``:name`` for the SQLAlchemy caller.

    Rewriting beats keeping a second copy of a forty-line aggregate: the copy
    is the thing that drifts, and this way the statement the API runs is
    provably the statement ``services/actions`` runs with the placeholders
    spelled the other way.
    """
    # Highest index first, so `$1` does not match inside `$10`.
    for index in range(len(names), 0, -1):
        statement = statement.replace(f"${index}", f":{names[index - 1]}")
    return statement
