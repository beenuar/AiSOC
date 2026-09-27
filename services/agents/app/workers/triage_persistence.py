"""Every durable effect the triage path has, behind one injectable seam.

Gap-closure Phase 1.2.

Why this exists
---------------
Replay evaluation has to run triage against a customer's closed findings and
measure the verdicts, while writing nothing: no ledger rows, no alert rows, no
outcome-memory priors, no approvals, no disposition pushed back into their
SIEM. The plan is explicit that the way to get there is to refactor the
production path so persistence is injected, *not* to write a second triage
implementation. A second implementation would measure itself.

So :class:`FusedAlertTriageWorker` no longer calls the ledger, the memory
store, the approvals queue, the writeback client or the cost governor's
cache directly. It calls them through :class:`TriageWriter`, whose default is
:class:`LiveTriageWriter` and whose default does exactly what the worker used
to do inline. The worker is one object with one code path; only the sink
differs.

The reads are a separate port on purpose
----------------------------------------
:class:`TriageContextReader` covers the two reads that decide a verdict from
durable state: the tenant's compiled organisation memory and the per-signature
outcome prior. They are split from the writes because replay needs opposite
things from the two halves. Writes must not happen at all. Reads must happen,
but must see the world as it stood at the train/test split, or the test window
influences its own triage: a verdict recorded for alert 140 becomes a prior
that suppresses alert 141, and the evaluation grades the agent on answers it
supplied itself.

Keeping them apart means the leakage test can assert each property
independently, which is what makes a failure legible. One combined port would
let "wrote nothing" and "read nothing new" fail as the same assertion.

What is deliberately *not* here
-------------------------------
Business-context rules are the third frozen-at-split input, and they are
already injected: :class:`FusedAlertTriageWorker` takes a
``BusinessContextApplier`` in its constructor. Adding a fourth port for
something the constructor already parameterises would be ceremony.

The cost governor's dedup cache is reached through
:meth:`TriageWriter.cache_verdict` rather than being called on the governor
singleton, because it is a write. The governor's ``check`` and
``evidence_fingerprint`` stay direct calls: both are pure reads, and a shadow
run wants the real fingerprint.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from app.context import organisation_memory
from app.investigator import ledger as ledger_module
from app.investigator import siem_writeback
from app.memory import outcomes as outcomes_module

__all__ = [
    "LiveTriageContextReader",
    "LiveTriageWriter",
    "TriageContextReader",
    "TriageWriter",
]


@runtime_checkable
class TriageWriter(Protocol):
    """Every write :meth:`FusedAlertTriageWorker.triage` performs.

    An implementation that returns without doing anything is a complete
    shadow mode. That is the property the replay runner depends on, and
    ``test_replay_shadow_writes_nothing`` asserts it against the real modules
    rather than against a mock of them.
    """

    @property
    def escalation_allowed(self) -> bool:
        """Whether the full investigation graph may run after the verdict.

        Escalation is a write: :func:`app.graph.runner.run_escalation` records
        every node it executes to the Investigation Ledger. It is also the one
        effect that is not reachable through a method here, because it is a
        whole subsystem rather than a row.

        Declining it does not change what replay measures. ``triage()``
        captures ``verdict`` and ``confidence`` into locals *before* calling
        ``_maybe_escalate`` and returns those locals, so the graph cannot
        alter the verdict being graded. ``test_escalation_cannot_change_the_
        graded_verdict`` pins that rather than leaving it as a reading of the
        code.
        """

    @property
    def persists_cost(self) -> bool:
        """Whether the :class:`CostTracker` bound to this run may flush to the database.

        Cost is still *measured* in shadow mode, because tokens and latency
        are two of the fields the replay report has to record. Only the write
        is declined.
        """

    async def persist_auto_triage(self, **fields: Any) -> None:
        """Write the verdict to the ledger and the ``alerts`` row.

        Keyword-only and untyped by design: this mirrors
        :func:`app.investigator.ledger.persist_auto_triage`, which carries
        eighteen fields and gains more as the funnel does. Restating them
        here would create a second signature to keep in step, and the one
        that drifts is always the copy.
        """

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
        """Write the per-signature outcome prior that lets a repeat alert suppress."""

    async def record_suppression(
        self,
        *,
        tenant_ref: str,
        signature: str,
        alert_id: Any,
        disposition: str,
        prior_author: str,
    ) -> None:
        """Record that a repeat alert was closed from memory without re-triage."""

    async def raise_approval(self, **fields: Any) -> Any:
        """Queue an approval-requiring proposed action. Returns its id, or ``None``."""

    async def write_back_disposition(
        self,
        *,
        tenant_id: str,
        alert_id: str,
        disposition: str,
        confidence: float | None = None,
        rationale: str = "",
    ) -> dict[str, Any] | None:
        """Project this verdict onto the finding in the source SIEM."""

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
        """Cache the verdict for dedup and account the spend against the tenant budget."""


@runtime_checkable
class TriageContextReader(Protocol):
    """The durable state a verdict is allowed to depend on.

    Both methods must be total. Production's implementations already are:
    neither ``fetch_statements`` nor ``lookup_prior`` may take triage down
    when the store behind it is unreachable.
    """

    async def fetch_statements(self, tenant_id: str | None) -> list[dict[str, Any]]:
        """The tenant's active organisation-memory statements."""

    async def lookup_prior(self, tenant_id: str, signature: str) -> dict[str, Any] | None:
        """The durable outcome prior for an evidence signature, or ``None``."""


class LiveTriageWriter:
    """The production sink. Every method is the call the worker used to make inline.

    Kept as a class with no state rather than a module of functions so the
    default is an object the worker holds, and so a reader asking "what does
    production do differently from shadow?" gets the answer by diffing two
    classes that implement one protocol.
    """

    __slots__ = ()

    @property
    def escalation_allowed(self) -> bool:
        return True

    @property
    def persists_cost(self) -> bool:
        return True

    async def persist_auto_triage(self, **fields: Any) -> None:
        await ledger_module.persist_auto_triage(**fields)

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
        await outcomes_module.record_outcome(
            tenant_id,
            signature,
            disposition=disposition,
            confidence=confidence,
            author=author,
            alert_id=alert_id,
        )

    async def record_suppression(
        self,
        *,
        tenant_ref: str,
        signature: str,
        alert_id: Any,
        disposition: str,
        prior_author: str,
    ) -> None:
        await ledger_module.record_suppression(
            tenant_ref=tenant_ref,
            signature=signature,
            alert_id=alert_id,
            disposition=disposition,
            prior_author=prior_author,
        )

    async def raise_approval(self, **fields: Any) -> Any:
        return await ledger_module.raise_approval(**fields)

    async def write_back_disposition(
        self,
        *,
        tenant_id: str,
        alert_id: str,
        disposition: str,
        confidence: float | None = None,
        rationale: str = "",
    ) -> dict[str, Any] | None:
        return await siem_writeback.write_back_disposition(
            tenant_id=tenant_id,
            alert_id=alert_id,
            disposition=disposition,
            confidence=confidence,
            rationale=rationale,
        )

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
        governor.record_verdict(tenant_id, fingerprint, verdict, usd=usd, tokens=tokens)


class LiveTriageContextReader:
    """The production reads: whatever the stores hold right now."""

    __slots__ = ()

    async def fetch_statements(self, tenant_id: str | None) -> list[dict[str, Any]]:
        return await organisation_memory.fetch_statements(tenant_id)

    async def lookup_prior(self, tenant_id: str, signature: str) -> dict[str, Any] | None:
        return await outcomes_module.lookup_prior(tenant_id, signature)
