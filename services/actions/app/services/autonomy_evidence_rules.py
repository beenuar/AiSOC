"""How autonomy is earned, and what it takes to keep it, decided once.

Gap-closure Phase 2.2 and 2.3.

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

Four refusals the gate exists to make
=====================================

A promotion gate is only worth the cases where it says no. Each of these is a
separate :class:`Refusal` rather than one "not eligible", because an operator
who is told no needs to know what would change the answer, and a gate that
takes three round trips to explain itself gets overridden out of frustration
rather than on the merits. Every check runs; none is short-circuited.

**Too few decisions.** :attr:`PromotionThresholds.min_decisions`, 100 by
default. Nothing subtle: a handful of agreements is not a track record.

**Enough decisions, too few malicious ones.** A real queue is mostly false
positives, so a tenant reaches 100 decisions with two true positives in them.
Agreement over that sample says the agent can recognise noise, which is not
the question being asked. :attr:`PromotionThresholds.min_malicious`, 30 by
default, is the same floor Phase 1 uses before it will print a headline
accuracy, and for the same reason.

**Agreement that is high only because the agent abstains.** Three independent
guards, described above: agreement's denominator excludes abstentions so they
cannot inflate it, :attr:`PromotionThresholds.max_abstention_rate` caps the
share of decisions that may be abstentions at all, and malicious recall counts
an abstention as a miss.

**Drift that arrives gradually.** The window passes while the last fortnight
falls apart. :func:`evaluate_promotion` scores the same trailing slice that
would demote an existing grant, so a grant is never issued into a decline it
would immediately be revoked for.

Demotion floors sit below promotion thresholds on purpose
=========================================================

If the two were equal a grant would flip on every decision that moved the rate
across the line, and the audit log would fill with churn nobody could read,
which is how a real demotion gets missed.
:attr:`PromotionThresholds.demotion_agreement` and
:attr:`~PromotionThresholds.demotion_malicious_recall` are the floors, and the
gap is deliberate hysteresis.

The snapshot is the point
=========================

:meth:`EvidenceSnapshot.as_dict` is what lands in the audit log beside the
transition. "Auto-close was enabled for the identity class on 3 March" is not
auditable; the same sentence carrying the sample size, the agreement rate, the
recall on malicious, the thresholds in force that day and the window they were
measured over is.

It records the thresholds **by value** rather than by name, because a
threshold retuned next quarter would otherwise rewrite the justification for
every promotion granted under the old one. It records the window as absolute
timestamps rather than "the last 30 days", which stops meaning anything the
moment it is read on a different day. It records the counts each rate was
computed over. And it records :data:`RULES_DIGEST`, a hash of the
decision-relevant constants in this file, so a reader six months later can
tell "the gate was more lenient then" from "the numbers were better".

An override is a different word, not a different number
=======================================================

:class:`GrantSource` has two members and nothing derives which one applies
from a request field. ``EARNED`` is reserved for a grant the evidence
justified on its own; ``OPERATOR_OVERRIDE`` is a human overruling a refusal,
and the refusals that were overruled travel in the snapshot. A caller cannot
ask for its override to be recorded as earned, because the source is decided
from the gate's own verdict.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

__all__ = [
    "ABSTENTION_VERDICTS",
    "AGREEMENT_COUNTS_SQL",
    "CAPABILITIES",
    "DEFAULT_THRESHOLDS",
    "GRADED_DISPOSITIONS",
    "MALICIOUS",
    "RECENT_COUNTS_SQL",
    "RULES_DIGEST",
    "SCOPE_KINDS",
    "UNLABELED",
    "AgreementWindow",
    "EvidenceSnapshot",
    "GrantSource",
    "GrantState",
    "PromotionThresholds",
    "Refusal",
    "TransitionDecision",
    "evaluate_demotion",
    "evaluate_promotion",
    "scoped_sql",
    "to_named_params",
    "window_from_counts",
]


class Refusal(str, Enum):
    """Why a promotion was refused. One member per thing an operator could fix."""

    INSUFFICIENT_SAMPLE = "insufficient_sample"
    INSUFFICIENT_MALICIOUS = "insufficient_malicious"
    EXCESSIVE_ABSTENTION = "excessive_abstention"
    AGREEMENT_BELOW_THRESHOLD = "agreement_below_threshold"
    MALICIOUS_RECALL_BELOW_THRESHOLD = "malicious_recall_below_threshold"
    RECENT_DRIFT = "recent_drift"
    SHADOW_MODE_NOT_ENABLED = "shadow_mode_not_enabled"


class GrantState(str, Enum):
    """Where a scope sits on the ladder from measured to trusted."""

    SHADOW = "shadow"
    GRANTED = "granted"
    DEMOTED = "demoted"


class GrantSource(str, Enum):
    """How a grant came to exist. Never inferred from a request field.

    Two words in the database, two words in the audit log, two words on the
    console, so nothing downstream has to reconstruct which one happened from
    the numbers.
    """

    EARNED = "earned"
    OPERATOR_OVERRIDE = "operator_override"


#: What a grant may be about. ``alert_class`` grants auto-closure for a class
#: of alerts; ``action_verb`` raises one response verb's autonomy tier. Fixed
#: here rather than left open because both halves of the system have to agree
#: what a scope key means before they can agree a grant applies.
SCOPE_KINDS: tuple[str, ...] = ("alert_class", "action_verb")

#: What a grant permits. Listed rather than free text so a capability nobody
#: enforces cannot be granted: a row saying a tenant may do something no code
#: path consults is indistinguishable from autonomy that works.
CAPABILITIES: tuple[str, ...] = ("auto_close", "auto_execute")

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


@dataclass(frozen=True)
class EvidenceSnapshot:
    """The numbers a transition rested on, frozen at the moment it was made."""

    scope_kind: str
    scope_key: str
    capability: str
    window: AgreementWindow
    recent: AgreementWindow
    thresholds: PromotionThresholds
    window_start: datetime
    window_end: datetime
    #: Refusals the evidence raised. Empty on an earned grant, populated on a
    #: demotion, and populated on an override, which is what makes an override
    #: legible as one rather than as a promotion with unusual numbers.
    refusals: tuple[Refusal, ...] = ()
    #: Oldest and newest decision in the window, so the rows behind the
    #: summary can still be found after the window has moved on.
    first_decision_id: str | None = None
    last_decision_id: str | None = None
    #: Which models produced the verdicts. A model change makes every figure
    #: before it a description of something else.
    models: tuple[str, ...] = ()
    #: Where the analyst closures came from: this console, a vendor, or both.
    #: "Our analysts agree with it" and "their SIEM agrees with it" are
    #: different claims and a promotion may rest on either.
    resolution_sources: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "scope_kind": self.scope_kind,
            "scope_key": self.scope_key,
            "capability": self.capability,
            "window": self.window.as_dict(),
            "recent": self.recent.as_dict(),
            # By value, not by name. A threshold retuned next quarter must not
            # silently rewrite what this promotion was measured against.
            "thresholds": self.thresholds.as_dict(),
            "window_start": self.window_start.isoformat(),
            "window_end": self.window_end.isoformat(),
            "refusals": [refusal.value for refusal in self.refusals],
            "first_decision_id": self.first_decision_id,
            "last_decision_id": self.last_decision_id,
            "models": list(self.models),
            "resolution_sources": list(self.resolution_sources),
            # Which version of this file judged it. Lets a later reader tell
            # "the gate was more lenient then" from "the numbers were better".
            "rules_digest": RULES_DIGEST,
        }


@dataclass(frozen=True)
class TransitionDecision:
    """The gate's answer: whether the capability may be held, and why not."""

    allowed: bool
    refusals: tuple[Refusal, ...] = field(default_factory=tuple)

    @property
    def refusal_values(self) -> list[str]:
        return [refusal.value for refusal in self.refusals]


def evaluate_promotion(
    *,
    window: AgreementWindow,
    recent: AgreementWindow,
    thresholds: PromotionThresholds = DEFAULT_THRESHOLDS,
    shadow_enabled: bool = True,
) -> TransitionDecision:
    """Decide whether this track record earns the capability.

    Every check runs; the refusals are not short-circuited. An operator told
    only the first thing wrong fixes it, re-asks, and is told the second.
    """
    refusals: list[Refusal] = []

    if not shadow_enabled:
        # Nothing was being measured, so there is no track record. Without
        # this the refusal would be "too few decisions", which reads as "try
        # again later" rather than "you have not started".
        refusals.append(Refusal.SHADOW_MODE_NOT_ENABLED)

    if window.labelled < thresholds.min_decisions:
        refusals.append(Refusal.INSUFFICIENT_SAMPLE)

    if window.malicious_support < thresholds.min_malicious:
        refusals.append(Refusal.INSUFFICIENT_MALICIOUS)

    abstention = window.abstention_rate
    if abstention is not None and abstention > thresholds.max_abstention_rate:
        refusals.append(Refusal.EXCESSIVE_ABSTENTION)

    agreement = window.agreement_rate
    # `None` is a refusal, not a pass. An agent that answered nothing has an
    # unmeasured agreement rate, and "not measured" must never be read here as
    # "met the threshold".
    if agreement is None or agreement < thresholds.min_agreement:
        refusals.append(Refusal.AGREEMENT_BELOW_THRESHOLD)

    recall = window.malicious_recall
    if recall is None or recall < thresholds.min_malicious_recall:
        refusals.append(Refusal.MALICIOUS_RECALL_BELOW_THRESHOLD)

    # The window can pass while the last fortnight is falling apart. Promotion
    # is refused on the same trailing slice that would demote an existing
    # grant, so a grant is never issued into a decline it would immediately be
    # revoked for.
    if _recent_has_drifted(recent, thresholds):
        refusals.append(Refusal.RECENT_DRIFT)

    return TransitionDecision(allowed=not refusals, refusals=tuple(refusals))


def evaluate_demotion(
    *,
    window: AgreementWindow,
    recent: AgreementWindow,
    thresholds: PromotionThresholds = DEFAULT_THRESHOLDS,
) -> TransitionDecision:
    """Decide whether an existing grant may stand.

    ``allowed`` means "the grant survives". The floors are below the promotion
    thresholds so a rate hovering near the line does not flip the grant on
    every decision, and the trailing slice is checked independently so a
    decline the window's average is still absorbing is still caught.

    Unlike promotion, an unmeasured rate does **not** demote. A week in which
    no malicious alert arrived is not evidence the agent got worse, and
    revoking a grant over an empty denominator would make quiet weeks
    dangerous.
    """
    refusals: list[Refusal] = []

    agreement = window.agreement_rate
    if agreement is not None and agreement < thresholds.demotion_agreement:
        refusals.append(Refusal.AGREEMENT_BELOW_THRESHOLD)

    recall = window.malicious_recall
    if recall is not None and recall < thresholds.demotion_malicious_recall:
        refusals.append(Refusal.MALICIOUS_RECALL_BELOW_THRESHOLD)

    abstention = window.abstention_rate
    if abstention is not None and abstention > thresholds.max_abstention_rate:
        refusals.append(Refusal.EXCESSIVE_ABSTENTION)

    if _recent_has_drifted(recent, thresholds):
        refusals.append(Refusal.RECENT_DRIFT)

    return TransitionDecision(allowed=not refusals, refusals=tuple(refusals))


def _recent_has_drifted(recent: AgreementWindow, thresholds: PromotionThresholds) -> bool:
    """Whether the trailing slice has fallen below the demotion floors.

    Returns ``False`` on a slice too small to judge. A quiet tenant should not
    lose a grant because the three decisions since Friday included one
    disagreement, and ``drift_min_answered`` is where that line is drawn.
    ``False`` here means "the recent slice cannot say", not "the recent slice
    is fine"; the window checks apply either way.
    """
    if recent.answered < thresholds.drift_min_answered:
        return False
    agreement = recent.agreement_rate
    if agreement is not None and agreement < thresholds.demotion_agreement:
        return True
    recall = recent.malicious_recall
    # Only judge recall on a slice that contained malicious cases at all.
    # `None` means none arrived, which is not evidence of a decline.
    return recall is not None and recall < thresholds.demotion_malicious_recall


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
#
# The two array parameters carry no `::text[]` cast. They used to, and it was
# wrong in a way that only shows up on the SQLAlchemy half: `to_named_params`
# turns `$2::text[]` into `:graded::text[]`, and SQLAlchemy's `text()` parser
# reads the second colon pair as the start of another bind parameter, so a
# stray colon reaches Postgres and the statement fails to parse. Both drivers
# infer the array type from the column being compared, so the cast bought
# nothing on either side. The SQLAlchemy caller declares the type with
# `bindparam(..., type_=ARRAY(Text))` instead.

#: Scope filters are applied by the caller as an additional predicate, appended
#: where this marker sits. Written as a marker rather than as string
#: concatenation at the call site so both services splice at the same point.
_SCOPE_MARKER = "/*scope*/"

AGREEMENT_COUNTS_SQL = f"""
SELECT
    COUNT(*)::int AS resolved,
    COUNT(*) FILTER (WHERE d.analyst_disposition = ANY($2))::int AS labelled,
    COUNT(*) FILTER (
        WHERE d.analyst_disposition = ANY($2)
          AND COALESCE(d.verdict, '') = ANY($3)
    )::int AS abstained,
    COUNT(*) FILTER (
        WHERE d.analyst_disposition = ANY($2)
          AND NOT (COALESCE(d.verdict, '') = ANY($3))
    )::int AS answered,
    COUNT(*) FILTER (
        WHERE d.analyst_disposition = ANY($2)
          AND NOT (COALESCE(d.verdict, '') = ANY($3))
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
    COUNT(*) FILTER (WHERE d.analyst_disposition = ANY($2))::int AS labelled,
    COUNT(*) FILTER (
        WHERE d.analyst_disposition = ANY($2)
          AND COALESCE(d.verdict, '') = ANY($3)
    )::int AS abstained,
    COUNT(*) FILTER (
        WHERE d.analyst_disposition = ANY($2)
          AND NOT (COALESCE(d.verdict, '') = ANY($3))
    )::int AS answered,
    COUNT(*) FILTER (
        WHERE d.analyst_disposition = ANY($2)
          AND NOT (COALESCE(d.verdict, '') = ANY($3))
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


def _digest_source() -> dict[str, Any]:
    """The constants a reader would need to reproduce a past decision.

    Deliberately not a hash of the whole file: a docstring edit must not make
    every historical snapshot look like it was judged by different rules,
    because then the digest stops being read.
    """
    return {
        "malicious": MALICIOUS,
        "graded_dispositions": list(GRADED_DISPOSITIONS),
        "unlabeled": UNLABELED,
        "abstention_verdicts": sorted(ABSTENTION_VERDICTS),
        "refusals": [refusal.value for refusal in Refusal],
        "grant_states": [state.value for state in GrantState],
        "grant_sources": [source.value for source in GrantSource],
        "scope_kinds": list(SCOPE_KINDS),
        "capabilities": list(CAPABILITIES),
        "default_thresholds": DEFAULT_THRESHOLDS.as_dict(),
        "agreement_sql": AGREEMENT_COUNTS_SQL,
        "recent_sql": RECENT_COUNTS_SQL,
    }


#: Hash of everything above that can change what the gate decides. Travels in
#: every evidence snapshot.
RULES_DIGEST = hashlib.sha256(json.dumps(_digest_source(), sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
