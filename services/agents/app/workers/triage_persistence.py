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

from app.context import dispositions as dispositions_module
from app.context import identity as identity_module
from app.context import knowledge_base, organisation_memory, tenant_skills
from app.context.dispositions import RecentDispositions
from app.context.identity import IdentityContext
from app.context.knowledge_base import RunbookRetrieval
from app.investigator import ledger as ledger_module
from app.investigator import siem_writeback
from app.memory import outcomes as outcomes_module

__all__ = [
    "CONTEXT_FREEZE_KINDS",
    "CUTOFF",
    "LiveTriageContextReader",
    "LiveTriageWriter",
    "SNAPSHOT",
    "TriageContextReader",
    "TriageWriter",
]

#: The two ways a replay can hold a context source still, and which one each
#: source is subject to. Declared here rather than inferred, and read by
#: ``scripts/check_triage_context_freeze.py`` in both directions: a protocol
#: method missing from this table fails the gate, and a name here that is no
#: longer a protocol method fails it too.
#:
#: ``SNAPSHOT``
#:     The whole set is small enough to capture once, before the test window
#:     runs. ``capture_context`` filters it against the split and
#:     ``ContextSnapshot.as_method_note`` publishes what it kept and dropped.
#:     Organisation memory, outcome priors and tenant skills.
#:
#: ``CUTOFF``
#:     A per-alert query against a store too large to capture: a knowledge
#:     base, a queue's disposition history, a directory. There is nothing to
#:     freeze up front, so the freeze is a parameter the **reader** supplies,
#:     and the server is what refuses the late rows. The reader accumulates
#:     what the server served and refused, and
#:     ``FrozenTriageContextReader.as_method_note`` publishes it.
#:
#: The distinction is not cosmetic. A cutoff source's protocol method must not
#: accept the cutoff from its caller, because a caller that can supply it is a
#: caller that can forget to, and the resulting replay reads live with a
#: method note that still says "frozen". The gate enforces that too.
SNAPSHOT = "snapshot"
CUTOFF = "cutoff"

CONTEXT_FREEZE_KINDS: dict[str, str] = {
    "fetch_statements": SNAPSHOT,
    "lookup_prior": SNAPSHOT,
    "fetch_skills": SNAPSHOT,
    "retrieve_runbooks": CUTOFF,
    "recent_dispositions": CUTOFF,
    "fetch_identity_context": CUTOFF,
}


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

    @property
    def fires_playbooks(self) -> bool:
        """Whether a matched playbook may actually run from this triage.

        `alert_trigger.run_for_alert` was called unconditionally, so a replay
        of last month's alerts would have **fired this month's playbooks** --
        real notifications, real tickets, real containment previews -- against
        rows a grader was only meant to score.
        """

    @property
    def uses_dedup_cache(self) -> bool:
        """Whether a cached production verdict may answer for this alert.

        The cost governor returns `Decision.DEDUPLICATED` with a verdict from
        a live cache. Accepting one during a replay grades the cache rather
        than the agent, and the figure that comes out is a measurement of
        something that already happened.
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
        injection_suspected: bool = False,
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

    Every method must be total. Production's implementations already are: none
    of them may take triage down when the store behind it is unreachable.

    This protocol is the seam the replay freeze acts on, so **a new context
    source belongs here or it is not point-in-time**. A source read directly
    from the worker would be live during a replay no matter what the snapshot
    said, and the report would be measuring a world the split point does not
    describe.

    Every method must also appear in :data:`CONTEXT_FREEZE_KINDS`, which says
    which of the two freezes holds it still. A source with no declared kind is
    a source nobody decided how to freeze.
    """

    async def fetch_statements(self, tenant_id: str | None) -> list[dict[str, Any]]:
        """The tenant's active organisation-memory statements."""

    async def lookup_prior(self, tenant_id: str, signature: str) -> dict[str, Any] | None:
        """The durable outcome prior for an evidence signature, or ``None``."""

    async def fetch_skills(self, tenant_id: str | None) -> list[dict[str, Any]]:
        """The tenant's active, unexpired investigation skills."""

    async def retrieve_runbooks(self, tenant_id: str | None, *, query: str) -> RunbookRetrieval:
        """Knowledge-base runbook chunks relevant to one alert, with citations.

        A ``CUTOFF`` source: the implementation decides the point in time, and
        no caller may pass one. The worker knows the alert and nothing about
        the split, which is exactly the division that keeps a replay honest.
        """

    async def recent_dispositions(
        self,
        tenant_id: str | None,
        *,
        rule_id: str,
        entities: list[str],
    ) -> RecentDispositions:
        """The last few analyst decisions on alerts of this shape, with reasons.

        A ``CUTOFF`` source, and the leakiest of the three by construction: a
        decision recorded inside the test window is literally an analyst's
        answer to an alert in that window.
        """

    async def fetch_identity_context(self, tenant_id: str | None, *, accounts: list[str]) -> IdentityContext:
        """Directory context for the principals this alert names.

        A ``CUTOFF`` source whose freeze is partial and says so: an
        ``Employee`` node carries when it was imported, never when the fact it
        records became true.
        """


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

    @property
    def fires_playbooks(self) -> bool:
        """Whether a matched playbook may actually run from this triage.

        `alert_trigger.run_for_alert` was called unconditionally, so a replay
        of last month's alerts would have **fired this month's playbooks** --
        real notifications, real tickets, real containment previews -- against
        rows a grader was only meant to score.
        """
        return True

    @property
    def uses_dedup_cache(self) -> bool:
        """Whether a cached production verdict may answer for this alert.

        The cost governor returns `Decision.DEDUPLICATED` with a verdict from
        a live cache. Accepting one during a replay grades the cache rather
        than the agent, and the figure that comes out is a measurement of
        something that already happened.
        """
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
        injection_suspected: bool = False,
    ) -> None:
        await outcomes_module.record_outcome(
            tenant_id,
            signature,
            disposition=disposition,
            confidence=confidence,
            author=author,
            alert_id=alert_id,
            injection_suspected=injection_suspected,
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

    async def fetch_skills(self, tenant_id: str | None) -> list[dict[str, Any]]:
        return await tenant_skills.fetch_skills(tenant_id)

    async def retrieve_runbooks(self, tenant_id: str | None, *, query: str) -> RunbookRetrieval:
        # ``as_of=None`` is production: retrieve against the knowledge base as
        # it stands. Stated explicitly rather than left to the default, so the
        # one line that differs from the frozen reader is visible in a diff of
        # the two classes.
        return await knowledge_base.fetch_runbooks(tenant_id, query=query, as_of=None)

    async def recent_dispositions(
        self,
        tenant_id: str | None,
        *,
        rule_id: str,
        entities: list[str],
    ) -> RecentDispositions:
        return await dispositions_module.fetch_recent_dispositions(
            tenant_id,
            rule_id=rule_id,
            entities=entities,
            as_of=None,
        )

    async def fetch_identity_context(self, tenant_id: str | None, *, accounts: list[str]) -> IdentityContext:
        return await identity_module.fetch_identity_context(tenant_id, accounts=accounts, as_of=None)
