"""Shadow mode on the live queue: it records, and it does not act.

Gap-closure Phase 2.1.

The property under test is not "fewer writes happen". It is that the agent
never fills in the answer it is about to be graded against. ``alerts.disposition``
is the analyst's column and the column reconciliation reads, so a shadow
verdict landing there would make every alert an analyst did not explicitly
re-dispose score as perfect agreement, and the scorecard would climb toward a
promotion on nothing at all.

That is the Phase 1 leakage lesson arriving by a different route. Phase 1's
version was a verdict written as an outcome prior that suppressed the next
alert; this one is a verdict written into the field the next measurement
reads. Both are the evaluation answering itself.
"""

from __future__ import annotations

import inspect
import uuid
from typing import Any

import pytest
from app.investigator import ledger as ledger_module
from app.workers import shadow_mode as shadow_module
from app.workers.fused_alert_consumer import FusedAlertTriageWorker
from app.workers.shadow_mode import (
    UNCLASSIFIED,
    LiveShadowModePolicy,
    ShadowDecision,
    ShadowModeTriageWriter,
    alert_class_of,
)
from app.workers.triage_persistence import LiveTriageWriter, TriageWriter


class _RecordingDelegate:
    """A live sink that records rather than performs. Stands in for production."""

    def __init__(self) -> None:
        self.persisted: list[dict[str, Any]] = []
        self.cached: list[tuple[Any, ...]] = []

    @property
    def escalation_allowed(self) -> bool:
        return True

    @property
    def persists_cost(self) -> bool:
        return True

    async def persist_auto_triage(self, **fields: Any) -> None:
        self.persisted.append(fields)

    def cache_verdict(self, governor, tenant_id, fingerprint, verdict, *, usd, tokens) -> None:
        self.cached.append((tenant_id, fingerprint, verdict, usd, tokens))


def _decision(**overrides: Any) -> ShadowDecision:
    fields: dict[str, Any] = {
        "tenant_ref": "11111111-1111-1111-1111-111111111111",
        "alert_class": "identity",
        "alert_id": str(uuid.uuid4()),
    }
    fields.update(overrides)
    return ShadowDecision(**fields)


@pytest.fixture
def _no_decision_writes(monkeypatch: pytest.MonkeyPatch) -> list[ShadowDecision]:
    """Capture decision rows instead of writing them, and fail loudly on a pool."""
    captured: list[ShadowDecision] = []

    async def _record(decision: ShadowDecision) -> bool:
        captured.append(decision)
        return True

    monkeypatch.setattr(shadow_module, "record_shadow_decision", _record)
    return captured


class TestItDoesNotAct:
    @pytest.mark.asyncio
    async def test_every_acting_method_declines(self, _no_decision_writes):
        """Each of these changes something outside the measurement.

        An approval is a proposal put in front of a human; a writeback edits a
        record in the customer's SIEM; an outcome prior closes the *next*
        matching alert without triage. Under measurement none of them may
        happen, and the delegate they wrap is a recorder, so a forwarded call
        would show up as a recorded one.
        """
        delegate = _RecordingDelegate()
        writer = ShadowModeTriageWriter(delegate, _decision())

        assert await writer.raise_approval(tenant_ref="t", run_id=None) is None
        assert await writer.write_back_disposition(tenant_id="t", alert_id="a", disposition="true_positive") is None
        assert await writer.record_outcome("t", "sig", disposition="benign", confidence=0.9, author="ai") is None
        assert (
            await writer.record_suppression(tenant_ref="t", signature="sig", alert_id=None, disposition="benign", prior_author="ai") is None
        )
        assert delegate.persisted == []

    def test_escalation_is_declined(self):
        """The investigation graph enriches, proposes and writes a node per step."""
        writer = ShadowModeTriageWriter(_RecordingDelegate(), _decision())
        assert writer.escalation_allowed is False

    def test_cost_is_still_persisted(self):
        """A shadow run places real model calls against a real key.

        Replay declines this because a replay is a measurement the tenant
        asked for; a shadow run is the product running, and a tenant
        measuring for a month must see the spend.
        """
        writer = ShadowModeTriageWriter(_RecordingDelegate(), _decision())
        assert writer.persists_cost is True

    def test_deduplication_still_happens(self):
        """Production dedups an alert flood, so a shadow run that did not
        would cost more than the thing it is modelling."""
        delegate = _RecordingDelegate()
        writer = ShadowModeTriageWriter(delegate, _decision())
        writer.cache_verdict(object(), "t", "fp", {"verdict": "benign"}, usd=0.0, tokens=10)
        assert len(delegate.cached) == 1


class TestTheVerdictIsRecordedWithoutStandingInForTheAnalysts:
    @pytest.mark.asyncio
    async def test_persist_forces_the_shadow_flag_and_refuses_to_auto_close(self, _no_decision_writes):
        delegate = _RecordingDelegate()
        writer = ShadowModeTriageWriter(delegate, _decision())

        await writer.persist_auto_triage(
            run_id=uuid.uuid4(),
            alert_id=str(uuid.uuid4()),
            tenant_ref="t",
            alert_summary="",
            raw_alert={},
            tier="llm",
            verdict="false_positive",
            confidence=0.97,
            rationale="",
            auto_closed=True,
        )

        written = delegate.persisted[0]
        assert written["shadow"] is True
        assert written["auto_closed"] is False

    @pytest.mark.asyncio
    async def test_the_decision_row_carries_the_verdict_and_its_segments(self, _no_decision_writes):
        delegate = _RecordingDelegate()
        decision = _decision(rule_id=None, source=None)
        writer = ShadowModeTriageWriter(delegate, decision)

        await writer.persist_auto_triage(
            run_id=uuid.uuid4(),
            alert_id=decision.alert_id,
            tenant_ref="t",
            alert_summary="",
            raw_alert={"rule_id": "det-identity-004", "connector_type": "okta", "external_id": "notable-9"},
            tier="llm",
            verdict="true_positive",
            confidence=0.91,
            rationale="",
        )

        recorded = _no_decision_writes[0]
        assert recorded.verdict == "true_positive"
        assert recorded.confidence == pytest.approx(0.91)
        # Per-rule and per-source agreement are two of the four breakdowns the
        # plan asks for, and they are only possible if the keys are captured
        # at decision time. The alert row can be edited afterwards.
        assert recorded.rule_id == "det-identity-004"
        assert recorded.source == "okta"
        assert recorded.external_id == "notable-9"

    @pytest.mark.asyncio
    async def test_an_empty_verdict_is_recorded_as_none_not_as_an_empty_string(self, _no_decision_writes):
        """``None`` and ``''`` both mean "the agent did not decide".

        They must not be two values in the column, because the aggregate
        COALESCEs one into the other and a reader looking at the raw rows
        would otherwise see two abstention spellings and conclude they meant
        different things.
        """
        writer = ShadowModeTriageWriter(_RecordingDelegate(), _decision())
        await writer.persist_auto_triage(
            run_id=uuid.uuid4(),
            alert_id=str(uuid.uuid4()),
            tenant_ref="t",
            alert_summary="",
            raw_alert={},
            tier="llm",
            verdict="",
            confidence=0.0,
            rationale="",
        )
        assert _no_decision_writes[0].verdict is None


class TestTheLedgerLeavesTheAnalystsColumnsAlone:
    """The integrity property, asserted on the statement that carries it.

    There is no Postgres in this suite, so this reads the SQL rather than
    running it: it proves the ``disposition`` assignment and the resolution
    columns are guarded by the shadow parameter and that the parameter is
    bound. What it cannot prove is that Postgres evaluates the CASE the way
    the statement reads, which is what ``tests/isolation`` exists for. Stated
    here rather than left implied, because a test whose limits are not
    written down gets read as proving more than it does.
    """

    def test_the_disposition_write_is_guarded_by_the_shadow_parameter(self):
        source = ledger_module.persist_auto_triage.__doc__ or ""
        assert "shadow" in source

        body = " ".join(inspect.getsource(ledger_module.persist_auto_triage).split())
        assert "SET disposition = CASE WHEN $10 THEN disposition ELSE $3 END" in body
        assert "resolved_at = CASE WHEN $7 AND NOT $10 THEN now() ELSE resolved_at END" in body

        # Check the property rather than one known line. The previous form
        # asserted the exact text of the single status branch that existed when
        # it was written, so adding a branch broke it on layout alone -- it
        # would not have failed had the new branch simply omitted the guard,
        # which is the thing that actually matters.
        status_case = body[body.index("status = CASE") : body.index("END, resolved_at")]
        branches = [b.strip() for b in status_case.split("WHEN")[1:] if "THEN" in b]
        assert branches, f"no status branches found to check in: {status_case!r}"
        for branch in branches:
            assert "NOT $10" in branch, (
                f"status branch {branch!r} writes a status without the shadow guard. A shadow run must never move an alert's status."
            )

    def test_the_guard_does_not_depend_on_the_caller_forcing_auto_closed_off(self):
        """``NOT $10`` is what makes this survive a forgetful future caller.

        The shadow sink already forces ``auto_closed`` false. If the guard
        relied on that alone, a second caller added later would close alerts
        it was only meant to observe, and the symptom would be a tenant's
        queue emptying itself during an evaluation.
        """
        import inspect

        body = inspect.getsource(ledger_module.persist_auto_triage)
        assert "CASE WHEN $7 AND NOT $10" in body


class TestWhichWayThePolicyFails:
    @pytest.mark.asyncio
    async def test_no_database_means_not_shadow(self, monkeypatch: pytest.MonkeyPatch):
        """Nothing could have been enabled and there is nowhere to record."""
        shadow_module.clear_cache()

        async def _no_pool():
            return None

        monkeypatch.setattr(ledger_module, "get_pool", _no_pool)
        assert await LiveShadowModePolicy().is_shadow("tenant", "identity") is False

    @pytest.mark.asyncio
    async def test_an_unreadable_policy_means_shadow(self, monkeypatch: pytest.MonkeyPatch):
        """The conservative direction, and the same call ``tenant_policy`` makes.

        Acting on an alert a tenant asked us only to observe is worse than a
        few seconds of suppressed writeback, and the second one resumes by
        itself on the next read.
        """
        shadow_module.clear_cache()

        class _BrokenPool:
            def acquire(self):
                raise RuntimeError("connection reset")

        async def _pool():
            return _BrokenPool()

        monkeypatch.setattr(ledger_module, "get_pool", _pool)
        assert await LiveShadowModePolicy().is_shadow("tenant", "identity") is True

    @pytest.mark.asyncio
    async def test_a_failure_is_not_cached(self, monkeypatch: pytest.MonkeyPatch):
        """A transient read error must not pin a tenant into shadow for the TTL."""
        shadow_module.clear_cache()
        calls: list[int] = []

        class _BrokenPool:
            def acquire(self):
                calls.append(1)
                raise RuntimeError("connection reset")

        async def _pool():
            return _BrokenPool()

        monkeypatch.setattr(ledger_module, "get_pool", _pool)
        policy = LiveShadowModePolicy()
        await policy.is_shadow("tenant", "identity")
        await policy.is_shadow("tenant", "identity")
        assert len(calls) == 2


class TestTheClassAnAlertIsMeasuredUnder:
    def test_it_is_the_alert_category(self):
        assert alert_class_of({"category": "Identity"}) == "identity"

    def test_an_alert_with_no_category_still_lands_somewhere(self):
        """A null class would drop the alert out of every per-class aggregate.

        A tenant whose detection content sets no category would then appear to
        have no evidence at all, rather than one bucket of it.
        """
        assert alert_class_of({}) == UNCLASSIFIED
        assert alert_class_of(None) == UNCLASSIFIED
        assert alert_class_of({"category": "   "}) == UNCLASSIFIED


class TestTheWorkerPicksTheSinkPerAlert:
    @pytest.mark.asyncio
    async def test_a_tenant_not_measuring_gets_the_live_sink_unchanged(self):
        class _Never:
            async def is_shadow(self, tenant_ref: str, alert_class: str) -> bool:
                return False

        worker = FusedAlertTriageWorker(bootstrap_servers="localhost:9092", shadow_policy=_Never())
        state = _state()
        assert await worker._sink_for(state, "fp") is worker._writer

    @pytest.mark.asyncio
    async def test_a_measured_class_gets_a_wrapper_around_that_same_sink(self):
        """The wrapper delegates rather than replacing.

        A replay passing its own sink keeps it, and a production worker wraps
        the live one. Two separate sinks would be two code paths to keep in
        step, and the one that drifts is always the copy.
        """

        class _Always:
            async def is_shadow(self, tenant_ref: str, alert_class: str) -> bool:
                return True

        worker = FusedAlertTriageWorker(bootstrap_servers="localhost:9092", shadow_policy=_Always())
        sink = await worker._sink_for(_state(), "fp")
        assert isinstance(sink, ShadowModeTriageWriter)
        assert sink._delegate is worker._writer
        assert isinstance(sink, TriageWriter)

    @pytest.mark.asyncio
    async def test_the_class_comes_from_the_alert_being_triaged(self):
        seen: list[str] = []

        class _Recording:
            async def is_shadow(self, tenant_ref: str, alert_class: str) -> bool:
                seen.append(alert_class)
                return False

        worker = FusedAlertTriageWorker(bootstrap_servers="localhost:9092", shadow_policy=_Recording())
        await worker._sink_for(_state(category="cloud"), "fp")
        assert seen == ["cloud"]

    def test_the_default_policy_is_the_live_one(self):
        """A worker built with ``__new__`` still resolves a policy.

        Several tests construct one that way to drive a single method, and a
        policy that existed only as an instance attribute would leave those
        objects raising ``AttributeError`` on the first alert.
        """
        worker = FusedAlertTriageWorker.__new__(FusedAlertTriageWorker)
        assert isinstance(worker._shadow_policy, LiveShadowModePolicy)
        assert isinstance(worker._writer, LiveTriageWriter)


def _state(category: str = "identity"):
    from app.models.state import InvestigationState

    return InvestigationState(
        run_id=uuid.uuid4(),
        incident_id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        alert_summary="",
        raw_alert={"id": str(uuid.uuid4()), "category": category},
    )
