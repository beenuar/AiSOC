"""Rolling agreement, as the console asks for it.

Gap-closure Phase 2.2.

Two things are worth testing here and they are not the arithmetic, which lives
in the shared rules module and is tested there against the same file this
service vendors.

The first is that a scope cannot widen past the tenant. ``scope_kind`` and
``scope_key`` arrive from a query string, and the shape of this feature -
"show me agreement for one alert class" - is exactly the shape that invites a
column name to be interpolated into a statement. The dimension is looked up in
a fixed table and the key is bound, and both halves are asserted.

The second is that reconciliation never guesses a label. ``alerts.disposition``
holds whatever the closing path wrote, and only four values are gradeable.
Everything else has to become ``unlabeled``, which is counted as resolved and
excluded from every rate. Guessing here would manufacture agreement out of an
analyst's shrug, and it would do it silently and in the flattering direction.

There is no Postgres in this suite. The session is mocked, so what is proven
is the statement that gets built and the parameters bound to it; whether
Postgres evaluates that statement as read is what the isolation suite covers.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from app._vendor.autonomy_evidence_rules import (
    GRADED_DISPOSITIONS,
    MALICIOUS,
    UNLABELED,
    AgreementWindow,
    PromotionThresholds,
)
from app.services.shadow_agreement import (
    SCOPE_COLUMNS,
    _scope_predicate,
    agreement_for,
    breakdown_for,
    reconcile_local_closures,
)

TENANT = uuid.UUID("11111111-1111-1111-1111-111111111111")
NOW = datetime(2026, 9, 26, 12, 0, tzinfo=UTC)

_COUNTS = {
    "resolved": 120,
    "labelled": 100,
    "abstained": 10,
    "answered": 90,
    "agreed": 87,
    "malicious_support": 31,
    "malicious_caught": 29,
}


def _session(rows: list[dict[str, Any]] | None = None, rowcount: int = 0) -> MagicMock:
    """An ``AsyncSession`` that answers every execute with the same rows."""
    db = MagicMock()
    mappings = MagicMock()
    mappings.first.return_value = dict(_COUNTS)
    mappings.all.return_value = rows if rows is not None else []
    result = MagicMock()
    result.mappings.return_value = mappings
    result.rowcount = rowcount
    db.execute = AsyncMock(return_value=result)
    db.commit = AsyncMock()
    return db


class TestAScopeCannotWidenPastTheTenant:
    def test_an_unknown_dimension_is_refused_rather_than_interpolated(self):
        with pytest.raises(ValueError, match="unknown scope kind"):
            _scope_predicate("alert_class; DROP TABLE alerts --", "x")

    def test_the_vocabulary_is_the_four_the_plan_names(self):
        """Per alert class, rule, source and model. Nothing else is a column here."""
        assert set(SCOPE_COLUMNS) == {"alert_class", "rule", "source", "model"}

    def test_the_key_is_bound_and_never_written_into_the_statement(self):
        predicate, params = _scope_predicate("rule", "det-identity-004' OR '1'='1")
        assert predicate == "AND d.rule_id = :scope_key"
        assert params == {"scope_key": "det-identity-004' OR '1'='1"}

    def test_the_tenant_scope_adds_no_predicate_at_all(self):
        assert _scope_predicate("tenant", "*") == ("", {})

    @pytest.mark.asyncio
    async def test_every_statement_binds_the_tenant_from_the_caller(self):
        db = _session()
        await agreement_for(db, TENANT, scope_kind="alert_class", scope_key="identity", now=NOW)

        for call in db.execute.await_args_list:
            statement, params = call.args
            assert params["tenant_id"] == str(TENANT)
            assert "d.tenant_id = :tenant_id" in str(statement)


class TestTheWindowIsAbsolute:
    @pytest.mark.asyncio
    async def test_the_bounds_come_from_the_configured_window_length(self):
        """Reported as timestamps, not as "the last 30 days".

        The second form stops meaning anything the moment somebody reads it
        on a later day, which is precisely when a promotion gets questioned.
        """
        db = _session()
        evidence = await agreement_for(db, TENANT, thresholds=PromotionThresholds(window_days=7), now=NOW)

        assert evidence.window_end == NOW
        assert (evidence.window_end - evidence.window_start).days == 7

    @pytest.mark.asyncio
    async def test_the_trailing_slice_is_bounded_by_the_drift_sample(self):
        db = _session()
        await agreement_for(db, TENANT, thresholds=PromotionThresholds(drift_sample=25), now=NOW)

        _, params = db.execute.await_args_list[-1].args
        assert params["recent_limit"] == 25

    @pytest.mark.asyncio
    async def test_both_the_window_and_its_recent_slice_are_returned(self):
        """A surface handed only the window is being handed the flattering half."""
        evidence = await agreement_for(_session(), TENANT, now=NOW)
        assert isinstance(evidence.window, AgreementWindow)
        assert isinstance(evidence.recent, AgreementWindow)
        assert evidence.window.agreement_rate == pytest.approx(87 / 90)


class TestReconciliationNeverGuessesALabel:
    @pytest.mark.asyncio
    async def test_a_disposition_outside_the_taxonomy_becomes_unlabeled(self):
        db = _session(rowcount=4)
        await reconcile_local_closures(db, TENANT)

        statement, params = db.execute.await_args_list[0].args
        sql = str(statement)
        # The CASE is what refuses to guess: a gradeable value is copied,
        # anything else lands on `unlabeled`.
        assert "WHEN a.disposition = ANY(:graded) THEN a.disposition" in sql
        assert "ELSE :unlabeled" in sql
        assert params["unlabeled"] == UNLABELED
        assert params["graded"] == list(GRADED_DISPOSITIONS)

    @pytest.mark.asyncio
    async def test_it_only_touches_decisions_that_are_not_yet_graded(self):
        """An analyst who later changes their mind must not rewrite evidence.

        A promotion already granted rests on what was known at the time, and
        the audit record of that has to stay true. A correction is a new fact
        and arrives as new decisions.
        """
        db = _session(rowcount=0)
        await reconcile_local_closures(db, TENANT)

        sql = str(db.execute.await_args_list[0].args[0])
        assert "d.resolved_at IS NULL" in sql

    @pytest.mark.asyncio
    async def test_it_only_reads_closed_alerts(self):
        db = _session(rowcount=0)
        await reconcile_local_closures(db, TENANT)
        assert "a.status IN ('resolved', 'closed')" in str(db.execute.await_args_list[0].args[0])

    @pytest.mark.asyncio
    async def test_it_reports_how_many_it_graded(self):
        assert await reconcile_local_closures(_session(rowcount=7), TENANT) == 7

    @pytest.mark.asyncio
    async def test_the_sweep_is_bounded(self):
        """It runs inline on a request, so it cannot be allowed to grow without limit."""
        db = _session(rowcount=0)
        await reconcile_local_closures(db, TENANT, limit=250)
        assert db.execute.await_args_list[0].args[1]["limit"] == 250


class TestTheBreakdownLeadsWithEvidence:
    @pytest.mark.asyncio
    async def test_rows_are_ordered_by_sample_size_not_by_rate(self):
        """A perfect rate over three decisions sorted to the top would be the
        most prominent number on the page and the least informative one."""
        db = _session(rows=[])
        await breakdown_for(db, TENANT, scope_kind="rule", now=NOW)
        assert "ORDER BY labelled DESC" in str(db.execute.await_args_list[0].args[0])

    @pytest.mark.asyncio
    async def test_an_unattributed_key_is_named_rather_than_dropped(self):
        db = _session(rows=[])
        await breakdown_for(db, TENANT, scope_kind="source", now=NOW)
        assert "'unattributed'" in str(db.execute.await_args_list[0].args[0])

    @pytest.mark.asyncio
    async def test_an_unknown_dimension_is_refused(self):
        with pytest.raises(ValueError, match="unknown scope kind"):
            await breakdown_for(_session(), TENANT, scope_kind="tenant_id")

    @pytest.mark.asyncio
    async def test_each_row_carries_the_counts_behind_its_rates(self):
        row = {"key": "okta", **_COUNTS}
        rows = await breakdown_for(_session(rows=[row]), TENANT, scope_kind="source", now=NOW)

        assert rows[0].key == "okta"
        payload = rows[0].as_dict()
        assert payload["answered"] == 90
        assert payload["malicious_support"] == 31
        # A rate without its denominator is a rate a reader cannot weigh.
        assert payload["agreement_rate"] == pytest.approx(87 / 90)

    @pytest.mark.asyncio
    async def test_the_grouped_aggregate_uses_the_same_malicious_spelling(self):
        db = _session(rows=[])
        await breakdown_for(db, TENANT, scope_kind="alert_class", now=NOW)
        assert db.execute.await_args_list[0].args[1]["malicious"] == MALICIOUS


class TestTheVendoredRulesAreTheOnesInUse:
    def test_this_service_computes_no_rate_of_its_own(self):
        """Every rate the API serves comes off the shared window type.

        Recomputing one here would give the console one definition of
        agreement and the dispatch gate another, and the difference would
        surface as a tenant asking why the scorecard says they qualify and
        the gate says they do not.
        """
        import inspect

        import app.services.shadow_agreement as module

        source = inspect.getsource(module)
        assert "def agreement_rate" not in source
        assert "def malicious_recall" not in source

    def test_the_evidence_payload_is_the_window_payload(self):
        evidence = SimpleNamespace(window=AgreementWindow(**_COUNTS))
        payload = evidence.window.as_dict()
        assert set(payload) >= {"agreement_rate", "malicious_recall", "abstention_rate", "answered", "labelled"}
