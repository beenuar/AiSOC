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

:class:`FrozenTriageContextReader` implements the read port against a snapshot
captured once, before the test window is replayed, and never refreshed. This is
the leak the plan cares about. Without it the sequence is:

    triage alert 140 -> verdict benign -> prior written -> triage alert 141
    -> reads the prior -> auto-suppressed -> graded "correct"

and the evaluation has graded the agent on an answer it supplied itself three
seconds earlier. Freezing the reads closes the second half of that; the shadow
writer closes the first. Both are needed: a frozen reader over a live writer
still pollutes the store for the *next* run, and a null writer over a live
reader still picks up whatever the console wrote while the replay was running.

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
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

__all__ = [
    "ContextSnapshot",
    "FrozenTriageContextReader",
    "ShadowTriageWriter",
    "capture_context",
]

#: Keys that may carry a row's recorded time, newest-authority first. Both
#: the outcome-prior shape (``first_seen`` / ``last_seen``) and the generic
#: SQL shapes are covered so one function serves both stores.
_TIME_KEYS: tuple[str, ...] = ("last_seen", "updated_at", "created_at", "first_seen", "recorded_at")


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

    #: Statements kept because they carry no recorded time to test against the
    #: split. Reported so the freeze is not claimed to be tighter than it is.
    undated_statements: int = 0

    #: Rows dropped for carrying a time after the split. A non-zero value is
    #: the freeze doing its job and is worth seeing.
    dropped_statements: int = 0
    dropped_priors: int = 0

    def as_method_note(self) -> dict[str, Any]:
        """The provenance block the replay report publishes about its own context."""
        return {
            "split_at": self.split_at.isoformat(),
            "statements_frozen": len(self.statements),
            "statements_without_timestamp": self.undated_statements,
            "statements_dropped_after_split": self.dropped_statements,
            "priors_frozen": len(self.priors),
            "priors_dropped_after_split": self.dropped_priors,
        }


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


def capture_context(
    *,
    split_at: datetime,
    statements: Iterable[Mapping[str, Any]] = (),
    priors: Mapping[str, Mapping[str, Any]] | None = None,
) -> ContextSnapshot:
    """Freeze organisation memory and outcome priors as of ``split_at``."""
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

    return ContextSnapshot(
        split_at=split_at,
        statements=tuple(kept),
        priors=kept_priors,
        undated_statements=undated,
        dropped_statements=dropped_statements,
        dropped_priors=dropped_priors,
    )


class FrozenTriageContextReader:
    """A :class:`TriageContextReader` served entirely from a snapshot.

    Holds no client, no pool and no URL, so there is nothing for it to refresh
    from even if a caller wanted it to. That is deliberate: a reader that
    *could* reach the live store would eventually be given a cache TTL, and a
    TTL is a refresh with a delay on it.
    """

    def __init__(self, snapshot: ContextSnapshot) -> None:
        self._snapshot = snapshot
        self.reads: Counter[str] = Counter()

    @property
    def snapshot(self) -> ContextSnapshot:
        return self._snapshot

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
