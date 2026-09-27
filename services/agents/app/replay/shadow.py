"""Shadow mode: the production triage path, writing nothing, reading a frozen world.

Gap-closure Phase 1.2.

These are the two halves of the replay's honesty, and they fail in opposite
directions.

:class:`ShadowTriageWriter` implements every method of
``app.workers.triage_persistence.TriageWriter`` and performs none of them. It
counts each call instead, so "wrote nothing" is a number a test can assert on
rather than an absence a test has to prove. An absence proves nothing: a
replay that never reached the writeback branch and a replay whose writeback
was suppressed look identical from outside.

:class:`FrozenTriageContextReader` implements the read port so that every
source is held at the split. This is the leak the plan cares about. Without it
the sequence is:

    triage alert 140 -> verdict benign -> prior written -> triage alert 141
    -> reads the prior -> auto-suppressed -> graded "correct"

and the evaluation has graded the agent on an answer it supplied itself three
seconds earlier. Freezing the reads closes the second half of that; the shadow
writer closes the first. Both are needed: a frozen reader over a live writer
still pollutes the store for the *next* run, and a null writer over a live
reader still picks up whatever the console wrote while the replay was running.

Two kinds of freeze, because two kinds of store
-----------------------------------------------
Gap-closure Phase 6.3 added context sources that cannot be frozen the way the
first three were, and the difference is size rather than taste.

A **snapshot** source is small enough to capture whole, once, before the test
window runs: a tenant's organisation-memory statements, its outcome priors,
its active skills. :func:`capture_context` filters the captured set against
the split and :meth:`ContextSnapshot.as_method_note` publishes what survived
and what did not.

A **cutoff** source is a per-alert query against a store that can hold
everything a SOC has ever written. There is nothing to capture, so the freeze
is a parameter: :class:`FrozenTriageContextReader` passes ``split_at`` as an
``as_of`` and the store is what refuses the late rows. The reader accumulates
what was served and what was refused across the run, and publishes them
through :meth:`FrozenTriageContextReader.as_method_note` using the same key
names the snapshot half uses, so a report has one vocabulary rather than two.

The refused count is the part worth insisting on. A cutoff that matched
nothing and a cutoff that threw away fifty documents return the same empty
list, so without the count a reader cannot tell a working freeze from an
inert one. ``scripts/check_triage_context_freeze.py`` enforces both halves, in
both directions, and knows which kind each source is because
``CONTEXT_FREEZE_KINDS`` declares it.

On the timestamps that are not there
------------------------------------
:func:`capture_context` drops any statement or prior carrying a recorded time
after the split. Organisation-memory statements as served by
``GET /feedback/context-statements`` carry no creation time at all: the query
in ``app/services/analyst_feedback.py`` selects ``statement``, ``reason_code``,
``scope``, ``scope_value``, ``observations`` and ``expires_at``, and nothing
else. So for those rows the filter has nothing to test and they are kept.

That is a real limit and it is counted rather than hidden:
:attr:`ContextSnapshot.undated_statements` travels into the report, so a reader
sees how much of the frozen context could actually be checked against the
split. Silently dropping them would understate the context production gets;
silently keeping them while claiming a clean point-in-time freeze would
overstate the guarantee.

Tenant skills, and the one thing here that bypasses the split on purpose
------------------------------------------------------------------------
Gap-closure Phase 6.2 added a fourth store. A tenant skill carries
``activated_at``, so unlike an organisation-memory statement it *can* be
tested against the split, and :func:`capture_context` drops one activated
after it exactly as it drops a late statement.

:attr:`ContextSnapshot.skills_under_test` is the deliberate exception, and it
is the honest way to do the one thing a skill backtest has to do. Measuring a
skill authored today against history from last quarter means applying guidance
whose author may have read those very alerts. Freezing it out would make the
backtest measure nothing; applying it silently would publish an accuracy
number an author could raise by writing a skill that restates the labels. So
the candidate travels in its own field, the method note names it and counts it
separately from the frozen set, and
:meth:`ContextSnapshot.as_method_note` publishes the caveat rather than
leaving a reader to work it out. A skill under test is scored, and the reader
is told the score is a statement about this window rather than a forecast.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.context import knowledge_base
from app.context.knowledge_base import RunbookRetrieval

__all__ = [
    "ContextSnapshot",
    "FrozenTriageContextReader",
    "ShadowTriageWriter",
    "capture_context",
]

#: Sources held at the split by a server-side cutoff rather than by capture.
#: Named here because :class:`FrozenTriageContextReader` has to open a counter
#: for each one before the first read, and a store whose counter was created
#: lazily would be absent from the method note precisely when it was never
#: consulted, which is the case worth seeing.
_CUTOFF_STORES: tuple[str, ...] = ("runbooks",)

#: Keys that may carry a row's recorded time, newest-authority first. The
#: outcome-prior shape (``first_seen`` / ``last_seen``), the tenant-skill
#: shape (``activated_at``) and the generic SQL shapes are all covered so one
#: function serves every store.
_TIME_KEYS: tuple[str, ...] = (
    "last_seen",
    "activated_at",
    "updated_at",
    "created_at",
    "first_seen",
    "recorded_at",
)


class ShadowTriageWriter:
    """A :class:`TriageWriter` that records what production would have written.

    Every method returns the "nothing happened" value its live counterpart
    returns on a no-op: ``None`` from :meth:`raise_approval` means no approval
    id, and ``None`` from :meth:`write_back_disposition` means nothing was
    attempted. The worker already handles both, because both occur in
    production whenever the relevant feature is switched off, so shadow mode
    exercises paths the worker takes anyway rather than novel ones.
    """

    def __init__(self) -> None:
        self.calls: Counter[str] = Counter()

    @property
    def escalation_allowed(self) -> bool:
        return False

    @property
    def persists_cost(self) -> bool:
        return False

    @property
    def total_writes(self) -> int:
        """How many writes production would have made. Zero is the claim under test."""
        return sum(self.calls.values())

    async def persist_auto_triage(self, **fields: Any) -> None:
        self.calls["persist_auto_triage"] += 1

    async def record_outcome(
        self,
        tenant_id: str,
        signature: str,
        *,
        disposition: str,
        confidence: float,
        author: str,
        alert_id: Any = None,
    ) -> None:
        self.calls["record_outcome"] += 1

    async def record_suppression(
        self,
        *,
        tenant_ref: str,
        signature: str,
        alert_id: Any,
        disposition: str,
        prior_author: str,
    ) -> None:
        self.calls["record_suppression"] += 1

    async def raise_approval(self, **fields: Any) -> Any:
        self.calls["raise_approval"] += 1
        return None

    async def write_back_disposition(
        self,
        *,
        tenant_id: str,
        alert_id: str,
        disposition: str,
        confidence: float | None = None,
        rationale: str = "",
    ) -> dict[str, Any] | None:
        self.calls["write_back_disposition"] += 1
        return None

    def cache_verdict(
        self,
        governor: Any,
        tenant_id: str,
        fingerprint: str,
        verdict: dict[str, Any],
        *,
        usd: float,
        tokens: int,
    ) -> None:
        # Declining this one is not only about the write. The governor's cache
        # is keyed on the evidence fingerprint, so a cached verdict is served
        # back to the next alert with identical evidence as DEDUPLICATED. In a
        # replay that is the test window answering itself through a third
        # store, and it would not show up as a memory prior or a ledger row.
        self.calls["cache_verdict"] += 1


@dataclass(frozen=True)
class ContextSnapshot:
    """Durable state as it stood at the split point.

    ``priors`` is keyed by evidence signature, which is what
    ``CostGovernor.evidence_fingerprint`` produces and what the worker looks
    up. Capturing by signature rather than by alert means the snapshot answers
    the question the worker actually asks.
    """

    split_at: datetime
    statements: tuple[Mapping[str, Any], ...] = ()
    priors: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)

    #: Tenant skills active as of the split. Filtered on ``activated_at``, so
    #: unlike statements these can be tested against it.
    skills: tuple[Mapping[str, Any], ...] = ()

    #: Skills applied on purpose despite being authored after the split. This
    #: is the skill backtest, and it is the only thing in this class that
    #: bypasses the freeze. See the module docstring.
    skills_under_test: tuple[Mapping[str, Any], ...] = ()

    #: Statements kept because they carry no recorded time to test against the
    #: split. Reported so the freeze is not claimed to be tighter than it is.
    undated_statements: int = 0

    #: The same limit for skills. Should be zero: a skill reaching the
    #: resolver has an activation stamp by construction. Counted anyway,
    #: because "should be zero" is how the statement gap went unnoticed.
    undated_skills: int = 0

    #: Rows dropped for carrying a time after the split. A non-zero value is
    #: the freeze doing its job and is worth seeing.
    dropped_statements: int = 0
    dropped_priors: int = 0
    dropped_skills: int = 0

    def all_skills(self) -> tuple[Mapping[str, Any], ...]:
        """Frozen skills plus anything explicitly under test.

        One accessor rather than two reads at each call site, so a caller
        cannot use the frozen set and quietly forget the candidate, which
        would make every backtest report a delta of zero.
        """
        return (*self.skills, *self.skills_under_test)

    def as_method_note(self) -> dict[str, Any]:
        """The provenance block the replay report publishes about its own context."""
        note: dict[str, Any] = {
            "split_at": self.split_at.isoformat(),
            "statements_frozen": len(self.statements),
            "statements_without_timestamp": self.undated_statements,
            "statements_dropped_after_split": self.dropped_statements,
            "priors_frozen": len(self.priors),
            "priors_dropped_after_split": self.dropped_priors,
            "skills_frozen": len(self.skills),
            "skills_without_timestamp": self.undated_skills,
            "skills_dropped_after_split": self.dropped_skills,
        }
        if self.skills_under_test:
            note["skills_under_test"] = [_skill_ref(s) for s in self.skills_under_test]
            note["skills_under_test_caveat"] = (
                "These skills were authored after this window closed and were applied to it on purpose, "
                "which is what a backtest is. Their author may have seen these alerts, so the result "
                "measures the skill against this window and is not a forecast of its accuracy on new alerts."
            )
        return note


def _recorded_time(row: Mapping[str, Any]) -> datetime | None:
    for key in _TIME_KEYS:
        value = row.get(key)
        if isinstance(value, datetime):
            return value if value.tzinfo else value.replace(tzinfo=UTC)
        if isinstance(value, str) and value.strip():
            try:
                parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
            except ValueError:
                continue
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    return None


def _skill_ref(row: Mapping[str, Any]) -> str:
    """``skill-id@vN``, the pair an investigation records."""
    body = row.get("body") if isinstance(row.get("body"), Mapping) else {}
    skill_id = row.get("skill_id") or (body or {}).get("id") or "unknown"
    return f"{skill_id}@v{row.get('version', '?')}"


def capture_context(
    *,
    split_at: datetime,
    statements: Iterable[Mapping[str, Any]] = (),
    priors: Mapping[str, Mapping[str, Any]] | None = None,
    skills: Iterable[Mapping[str, Any]] = (),
    skills_under_test: Iterable[Mapping[str, Any]] = (),
) -> ContextSnapshot:
    """Freeze organisation memory, outcome priors and tenant skills as of ``split_at``.

    ``skills_under_test`` is passed through unfiltered by design: it is the
    candidate a backtest exists to measure, and it is counted and named
    separately in the method note so the bypass is published rather than
    assumed. See the module docstring.
    """
    kept: list[Mapping[str, Any]] = []
    undated = 0
    dropped_statements = 0
    for row in statements:
        recorded = _recorded_time(row)
        if recorded is None:
            undated += 1
            kept.append(dict(row))
            continue
        if recorded > split_at:
            dropped_statements += 1
            continue
        kept.append(dict(row))

    kept_priors: dict[str, Mapping[str, Any]] = {}
    dropped_priors = 0
    for signature, prior in (priors or {}).items():
        recorded = _recorded_time(prior)
        if recorded is not None and recorded > split_at:
            dropped_priors += 1
            continue
        kept_priors[str(signature)] = dict(prior)

    kept_skills: list[Mapping[str, Any]] = []
    undated_skills = 0
    dropped_skills = 0
    for row in skills:
        recorded = _recorded_time(row)
        if recorded is None:
            undated_skills += 1
            kept_skills.append(dict(row))
            continue
        if recorded > split_at:
            dropped_skills += 1
            continue
        kept_skills.append(dict(row))

    return ContextSnapshot(
        split_at=split_at,
        statements=tuple(kept),
        priors=kept_priors,
        skills=tuple(kept_skills),
        skills_under_test=tuple(dict(row) for row in skills_under_test),
        undated_statements=undated,
        undated_skills=undated_skills,
        dropped_statements=dropped_statements,
        dropped_priors=dropped_priors,
        dropped_skills=dropped_skills,
    )


class FrozenTriageContextReader:
    """A :class:`TriageContextReader` held at the split, by one of two means.

    **Snapshot sources** are served entirely from :class:`ContextSnapshot`.
    For those this object holds no client, no pool and no URL, so there is
    nothing for it to refresh from even if a caller wanted it to. That is
    deliberate: a reader that *could* reach the live store would eventually be
    given a cache TTL, and a TTL is a refresh with a delay on it.

    **Cutoff sources** cannot work that way. A knowledge base is queried per
    alert and can hold every document a SOC has written, so there is nothing
    sensible to capture up front. For those this object does reach the store,
    and the freeze is the ``as_of`` it passes: ``self._snapshot.split_at``,
    never the caller's, never "now". Three things make that auditable rather
    than a claim:

    * the cutoff is read off the snapshot inside the method, so a caller
      cannot supply one and the protocol gives them no way to try;
    * the server echoes the instant it applied, and a reply that echoes
      nothing is recorded as an unhonoured cutoff rather than a clean read;
    * the counts of what the server served and refused accumulate here and are
      published by :meth:`as_method_note`, because a cutoff that matched
      nothing and a cutoff that threw away fifty documents return the same
      empty list.
    """

    def __init__(self, snapshot: ContextSnapshot) -> None:
        self._snapshot = snapshot
        self.reads: Counter[str] = Counter()
        #: Running totals per cutoff source, over the whole test window. The
        #: snapshot's own counters are fixed at capture; these can only be
        #: known once the window has been replayed.
        self.cutoff_totals: dict[str, Counter[str]] = {
            store: Counter({"served": 0, "dropped_after_split": 0, "without_timestamp": 0, "cutoff_not_honoured": 0})
            for store in _CUTOFF_STORES
        }

    @property
    def snapshot(self) -> ContextSnapshot:
        return self._snapshot

    def as_method_note(self) -> dict[str, Any]:
        """The provenance block for the sources a snapshot could not hold.

        Deliberately the same three keys per store that
        :meth:`ContextSnapshot.as_method_note` publishes, so a reader does not
        have to learn two vocabularies to read one report, plus the one fact
        only a cutoff source can report: whether the server ever answered
        without applying the cutoff it was given.
        """
        note: dict[str, Any] = {"cutoff_at": self._snapshot.split_at.isoformat()}
        for store, totals in sorted(self.cutoff_totals.items()):
            note[f"{store}_frozen"] = totals["served"]
            note[f"{store}_dropped_after_split"] = totals["dropped_after_split"]
            note[f"{store}_without_timestamp"] = totals["without_timestamp"]
            if totals["cutoff_not_honoured"]:
                note[f"{store}_cutoff_not_honoured"] = totals["cutoff_not_honoured"]
        return note

    def _account(self, store: str, retrieval: Any, *, served: int) -> None:
        """Fold one cutoff read into the running totals."""
        totals = self.cutoff_totals[store]
        totals["served"] += served
        totals["dropped_after_split"] += int(getattr(retrieval, "excluded_after_cutoff", 0) or 0)
        totals["without_timestamp"] += int(getattr(retrieval, "without_timestamp", 0) or 0)
        if not getattr(retrieval, "as_of", None):
            # The reply did not name the instant it cut off at. Either the
            # store ignored the parameter or the read failed, and both mean
            # these rows were not demonstrably point-in-time. Counted rather
            # than assumed either way, because a silent live read behind a
            # method note that says "frozen" is the exact failure this class
            # exists to prevent.
            totals["cutoff_not_honoured"] += 1

    async def fetch_statements(self, tenant_id: str | None) -> list[dict[str, Any]]:
        self.reads["fetch_statements"] += 1
        # Copied per call. The worker hands these to the prompt builder and
        # a shared mutable list would let one alert's triage edit what the
        # next one sees, which is the same leak by a shorter route.
        return [dict(row) for row in self._snapshot.statements]

    async def lookup_prior(self, tenant_id: str, signature: str) -> dict[str, Any] | None:
        self.reads["lookup_prior"] += 1
        prior = self._snapshot.priors.get(signature)
        return dict(prior) if prior is not None else None

    async def fetch_skills(self, tenant_id: str | None) -> list[dict[str, Any]]:
        self.reads["fetch_skills"] += 1
        # Frozen set plus anything under test, copied per call for the same
        # reason statements are: the resolver reads these per alert and a
        # shared mutable list would let one alert's triage edit the next
        # alert's guidance.
        return [dict(row) for row in self._snapshot.all_skills()]

    async def retrieve_runbooks(self, tenant_id: str | None, *, query: str) -> RunbookRetrieval:
        self.reads["retrieve_runbooks"] += 1
        # The one line that makes this a freeze. ``split_at`` comes off the
        # snapshot, so there is no argument a caller could pass to widen it
        # and no clock this could read instead.
        retrieval = await knowledge_base.fetch_runbooks(
            tenant_id,
            query=query,
            as_of=self._snapshot.split_at,
        )
        self._account("runbooks", retrieval, served=len(retrieval.runbooks))
        return retrieval
