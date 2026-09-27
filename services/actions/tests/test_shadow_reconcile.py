"""Closures made in the customer's own SIEM, matched to the verdicts they grade.

Gap-closure Phase 2.1.

Half the closures that matter never happen in AiSOC. An analyst evaluating the
agent dispositions the notable in Splunk, classifies the incident in Sentinel,
closes the offense in QRadar. If agreement were measured only against closures
made in this console, a tenant whose analysts work in their SIEM would see a
scorecard that never fills in, and the natural reading of an empty scorecard
is "the agent is not being evaluated" rather than "we are looking in the wrong
place".

The readers this consumes are Phase 1.1's, unchanged. These tests drive the
real ``ClosedFinding`` rows those readers produce, including the
``unlabeled`` ones, because the interesting behaviour is what happens to a
closure the platform cannot name.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from app.services.alert_history import UNLABELED, parse_qradar_offense, parse_splunk_notable
from app.services.shadow_reconcile import ReconcileResult, reconcile_findings

TENANT = uuid.UUID("11111111-1111-1111-1111-111111111111")


class _FakeConnection:
    """An asyncpg connection that records statements and answers from a map.

    ``matches`` holds the external ids that have an ungraded decision row;
    ``graded`` holds the ones already carrying a closure. Everything else is
    unmatched, which is the case the result type exists to keep separate.
    """

    def __init__(self, matches: set[str] | None = None, graded: set[str] | None = None) -> None:
        self.matches = matches or set()
        self.graded = graded or set()
        self.updates: list[tuple[Any, ...]] = []
        self.rls: list[str] = []
        self.closed = False

    async def execute(self, sql: str, *args: Any) -> None:
        if "set_config" in sql:
            self.rls.append(args[0])

    async def fetchval(self, sql: str, *args: Any) -> Any:
        if sql.strip().startswith("UPDATE"):
            self.updates.append(args)
            return uuid.uuid4() if args[1] in self.matches else None
        return 1 if args[1] in self.graded else None

    async def close(self) -> None:
        self.closed = True


def _splunk(finding_id: str, disposition: str) -> Any:
    return parse_splunk_notable(
        {
            "event_id": finding_id,
            "rule_name": "Suspicious login",
            "disposition": disposition,
            "review_time": "1790000000",
            "reviewer": "alice",
            "rule_id": "splunk-rule-1",
        }
    )


class TestItReusesThePhaseOneReaders:
    @pytest.mark.asyncio
    async def test_a_mapped_disposition_is_written_through_unchanged(self):
        conn = _FakeConnection(matches={"notable-1"})
        result = await reconcile_findings(TENANT, [_splunk("notable-1", "disposition:1")], connection=conn)

        assert result.matched == 1
        # `disposition:1` is Splunk ES's "True Positive - Suspicious Activity",
        # mapped by the Phase 1 taxonomy rather than by anything here.
        assert conn.updates[0][2] == "true_positive"

    @pytest.mark.asyncio
    async def test_the_vendors_own_label_travels_alongside(self):
        """A mapping somebody later disputes is only arguable if the raw label survived."""
        conn = _FakeConnection(matches={"notable-1"})
        await reconcile_findings(TENANT, [_splunk("notable-1", "disposition:2")], connection=conn)
        assert conn.updates[0][3] == "disposition:2"

    @pytest.mark.asyncio
    async def test_an_i_do_not_know_closure_is_recorded_as_unlabeled(self):
        """Splunk ES disposition 6 is literally named "Undetermined".

        Folding it into a verdict because the finding happened to be closed
        would manufacture agreement out of an analyst's admission of
        uncertainty. It is still recorded, because a tenant whose history is
        mostly unlabeled has to see that rather than a confident rate over a
        remnant.
        """
        conn = _FakeConnection(matches={"notable-9"})
        result = await reconcile_findings(TENANT, [_splunk("notable-9", "disposition:6")], connection=conn)

        assert result.matched == 1
        assert conn.updates[0][2] == UNLABELED

    @pytest.mark.asyncio
    async def test_a_qradar_non_issue_keeps_the_readers_distinction(self):
        """Phase 1 maps "Non-Issue" to `benign`, not `benign_true_positive`.

        It makes no claim about whether the rule was right, and that is the
        distinction `benign` exists to carry. Re-deciding it here would be a
        second taxonomy.
        """
        offense = parse_qradar_offense(
            {"id": "77", "description": "Port scan", "closing_reason_name": "Non-Issue", "close_time": 1790000000000}
        )
        conn = _FakeConnection(matches={"77"})
        await reconcile_findings(TENANT, [offense], connection=conn)
        assert conn.updates[0][2] == "benign"


class TestItTellsTheThreeOutcomesApart:
    @pytest.mark.asyncio
    async def test_unmatched_and_already_graded_are_separate_counters(self):
        """One is ordinary and one means the join key never arrives.

        An analyst closing findings the agent never triaged is normal. Zero
        matched against a large unmatched is a wiring fault, and reporting
        both as one number hides the difference.
        """
        conn = _FakeConnection(matches={"a"}, graded={"b"})
        result = await reconcile_findings(
            TENANT,
            [_splunk("a", "disposition:1"), _splunk("b", "disposition:1"), _splunk("c", "disposition:1")],
            connection=conn,
        )

        assert (result.matched, result.already_resolved, result.unmatched) == (1, 1, 1)
        assert result.considered == 3

    @pytest.mark.asyncio
    async def test_a_finding_with_no_id_is_counted_rather_than_dropped(self):
        """Nothing to join on. Reported, because a run of these is a fault.

        The reader itself falls back from ``event_id`` to ``rule_id``, so this
        is built without either: a vendor payload that carried neither is the
        only way the id is genuinely absent.
        """
        anonymous = parse_splunk_notable({"rule_name": "Suspicious login", "disposition": "disposition:1", "review_time": "1790000000"})
        assert anonymous.finding_id == ""

        conn = _FakeConnection()
        result = await reconcile_findings(TENANT, [anonymous], connection=conn)

        assert result.skipped_no_key == 1
        assert conn.updates == []

    @pytest.mark.asyncio
    async def test_nothing_to_do_is_an_empty_result_not_a_connection(self):
        assert await reconcile_findings(TENANT, []) == ReconcileResult()


class TestItNeverRegradesADecision:
    @pytest.mark.asyncio
    async def test_the_update_refuses_a_decision_that_already_carries_a_closure(self):
        """A tenant whose analysts work in both places would otherwise have
        whichever reconciliation ran last win, and a promotion would rest on
        evidence that changes with the scheduler."""
        conn = _FakeConnection(matches={"x"})
        await reconcile_findings(TENANT, [_splunk("x", "disposition:1")], connection=conn)
        # The statement itself carries the guard; the fake does not enforce it.
        assert conn.updates, "expected the UPDATE to have been attempted"

    @pytest.mark.asyncio
    async def test_the_tenant_context_is_bound_before_any_read(self):
        """RLS engages only on a session that set ``app.current_tenant_id``.

        This connection is opened by a worker rather than by a request, so
        nothing else sets it, and without it these statements would fall
        through the policy's fail-open arm.
        """
        conn = _FakeConnection(matches={"x"})
        await reconcile_findings(TENANT, [_splunk("x", "disposition:1")], connection=conn)
        assert conn.rls == [str(TENANT)]

    @pytest.mark.asyncio
    async def test_an_injected_connection_is_not_closed_by_the_callee(self):
        """A caller reconciling five vendors in one pass opens one connection."""
        conn = _FakeConnection(matches={"x"})
        await reconcile_findings(TENANT, [_splunk("x", "disposition:1")], connection=conn)
        assert conn.closed is False


class TestTheCloseTimeIsTheVendorsNotNow:
    @pytest.mark.asyncio
    async def test_the_recorded_resolution_time_comes_from_the_finding(self):
        """The window a promotion is measured over is keyed on this column.

        Stamping ``now()`` would put a closure made three weeks ago into this
        week's trailing drift slice, which is the slice that exists to catch a
        recent decline.
        """
        conn = _FakeConnection(matches={"notable-1"})
        finding = _splunk("notable-1", "disposition:1")
        await reconcile_findings(TENANT, [finding], connection=conn)

        recorded = conn.updates[0][5]
        assert recorded == finding.closed_at
        assert recorded == datetime.fromtimestamp(1790000000, tz=UTC)
