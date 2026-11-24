"""The co-managed operating model's pure halves.

What this pins
--------------
* **The matrix narrows and never grants** — the enforcement contract's
  whole safety argument. An empty matrix allows; an unreadable matrix
  allows (the overlay degrades to the base authorization, stated in the
  module's own docstring with the kill-switch contrast); a row assigning
  the act to the other party refuses WITH the rule named; `shared` admits
  both; the most specific row wins.
* **Party resolution** reads the tenant tree: home tenant → customer,
  managing parent → provider, anything else → provider (the conservative
  side for a matrix whose point is keeping provider hands off
  customer-reserved acts).
* **Shift occurrence math** survives the two traps: an overnight shift
  belongs to the day it STARTED, and a DST transition changes the
  occurrence's UTC length rather than its local wall-clock.
* **The service review's honesty**: a share with no denominator is None
  with the reason, never zero.

The Postgres truths (RLS, generation idempotence, escalation routing and
dedup) live in ``tests/isolation/test_operating_model_live.py``.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from zoneinfo import ZoneInfo

import app.services.service_review as sr
import pytest
from app.services import responsibility as resp
from app.services.escalation_router import _severity_at_or_above
from app.services.shift_handoff import GENERATION_GRACE, ShiftConfigError, latest_ended_occurrence, validate_timezone

TENANT = uuid.UUID("aaaaaaaa-0000-0000-0000-00000000000a")
PARENT = uuid.UUID("bbbbbbbb-0000-0000-0000-00000000000b")


def _db_with_rows(rows: list[tuple]) -> MagicMock:
    db = MagicMock()
    result = MagicMock()
    result.fetchall.return_value = rows
    db.execute = AsyncMock(return_value=result)
    return db


class TestMatrixNarrowsOnly:
    @pytest.mark.asyncio
    async def test_an_empty_matrix_allows(self) -> None:
        decision = await resp.check(_db_with_rows([]), tenant_id=TENANT, activity="action", party="provider", verb="isolate_host")
        assert decision.allowed is True
        assert decision.rule is None

    @pytest.mark.asyncio
    async def test_an_unreadable_matrix_degrades_to_the_base_not_to_an_outage(self) -> None:
        db = MagicMock()
        db.execute = AsyncMock(side_effect=RuntimeError("matrix table unreachable"))
        decision = await resp.check(db, tenant_id=TENANT, activity="action", party="provider", verb="isolate_host")
        assert decision.allowed is True, (
            "the matrix is a narrowing overlay; unavailable must mean 'no narrowing', never a tenant-wide refusal of every act"
        )

    @pytest.mark.asyncio
    async def test_a_row_for_the_other_party_refuses_naming_the_rule(self) -> None:
        rows = [("action", "*", "*", "isolate_host", "customer")]
        decision = await resp.check(_db_with_rows(rows), tenant_id=TENANT, activity="action", party="provider", verb="isolate_host")
        assert decision.allowed is False
        assert decision.owner == "customer"
        assert "isolate_host" in (decision.rule or "")
        assert "provider" in decision.refusal_detail and "customer" in decision.refusal_detail

    @pytest.mark.asyncio
    async def test_shared_admits_both_parties(self) -> None:
        rows = [("action", "*", "*", "*", "shared")]
        for party in ("provider", "customer"):
            decision = await resp.check(_db_with_rows(rows), tenant_id=TENANT, activity="action", party=party)
            assert decision.allowed is True

    @pytest.mark.asyncio
    async def test_the_most_specific_row_wins(self) -> None:
        rows = [
            ("action", "*", "*", "*", "provider"),
            ("action", "*", "critical", "*", "customer"),
            ("action", "*", "critical", "isolate_host", "shared"),
        ]
        # verb+severity row beats severity row beats wildcard
        d1 = await resp.check(
            _db_with_rows(rows),
            tenant_id=TENANT,
            activity="action",
            party="provider",
            severity="critical",
            verb="isolate_host",
        )
        assert d1.allowed is True and d1.owner == "shared"
        d2 = await resp.check(
            _db_with_rows(rows),
            tenant_id=TENANT,
            activity="action",
            party="provider",
            severity="critical",
            verb="reset_password",
        )
        assert d2.allowed is False and d2.owner == "customer"
        d3 = await resp.check(
            _db_with_rows(rows),
            tenant_id=TENANT,
            activity="action",
            party="customer",
            severity="low",
            verb="reset_password",
        )
        assert d3.allowed is False and d3.owner == "provider"

    @pytest.mark.asyncio
    async def test_an_unknown_activity_is_a_programming_error(self) -> None:
        with pytest.raises(ValueError, match="activity"):
            await resp.check(_db_with_rows([]), tenant_id=TENANT, activity="snack", party="provider")


class TestPartyResolution:
    @pytest.mark.asyncio
    async def test_home_tenant_is_customer(self) -> None:
        db = MagicMock()
        assert await resp.party_for(db, caller_home_tenant=TENANT, target_tenant=TENANT) == "customer"
        db.execute.assert_not_called()

    @pytest.mark.asyncio
    async def test_managing_parent_is_provider(self) -> None:
        db = MagicMock()
        result = MagicMock()
        result.scalar_one_or_none.return_value = PARENT
        db.execute = AsyncMock(return_value=result)
        assert await resp.party_for(db, caller_home_tenant=PARENT, target_tenant=TENANT) == "provider"

    @pytest.mark.asyncio
    async def test_anything_else_is_provider_the_conservative_side(self) -> None:
        db = MagicMock()
        result = MagicMock()
        result.scalar_one_or_none.return_value = None
        db.execute = AsyncMock(return_value=result)
        assert await resp.party_for(db, caller_home_tenant=uuid.uuid4(), target_tenant=TENANT) == "provider"


class TestShiftOccurrences:
    def test_a_daytime_shift_that_just_ended_is_found(self) -> None:
        now = datetime(2026, 11, 20, 18, 30, tzinfo=UTC)  # Friday
        occ = latest_ended_occurrence(tz_name="UTC", start_minute=6 * 60, end_minute=18 * 60, weekdays=[1, 2, 3, 4, 5], now=now)
        assert occ is not None
        assert occ.start == datetime(2026, 11, 20, 6, 0, tzinfo=UTC)
        assert occ.end == datetime(2026, 11, 20, 18, 0, tzinfo=UTC)

    def test_an_overnight_shift_belongs_to_the_day_it_started(self) -> None:
        # Friday 22:00 → Saturday 06:00; Saturday is NOT in weekdays, Friday is.
        now = datetime(2026, 11, 21, 7, 0, tzinfo=UTC)  # Saturday morning
        occ = latest_ended_occurrence(tz_name="UTC", start_minute=22 * 60, end_minute=6 * 60, weekdays=[5], now=now)
        assert occ is not None
        assert occ.start == datetime(2026, 11, 20, 22, 0, tzinfo=UTC)
        assert occ.end == datetime(2026, 11, 21, 6, 0, tzinfo=UTC)

    def test_dst_changes_the_utc_length_not_the_local_clock(self) -> None:
        # Europe/Berlin fall-back (2026-10-25, 03:00 -> 02:00): a 00:00–12:00
        # local shift SPANS the repeated hour, so twelve local hours are
        # thirteen UTC hours. The local wall-clock is what the tenant wrote;
        # the UTC window is what the snapshot queries get.
        now = datetime(2026, 10, 25, 12, 30, tzinfo=ZoneInfo("Europe/Berlin")).astimezone(UTC)
        occ = latest_ended_occurrence(
            tz_name="Europe/Berlin",
            start_minute=0,
            end_minute=12 * 60,
            weekdays=[7],
            now=now,
        )
        assert occ is not None
        assert (occ.end - occ.start).total_seconds() == 13 * 3600

    def test_a_long_dead_occurrence_is_not_generated(self) -> None:
        now = datetime(2026, 11, 20, 18, 0, tzinfo=UTC) + GENERATION_GRACE + timedelta(hours=1)
        occ = latest_ended_occurrence(tz_name="UTC", start_minute=6 * 60, end_minute=18 * 60, weekdays=[5], now=now)
        assert occ is None, "a week-old handoff generated on worker restart is invented diligence"

    def test_a_garbage_timezone_is_refused(self) -> None:
        with pytest.raises(ShiftConfigError, match="IANA"):
            validate_timezone("Mars/Olympus_Mons")


class TestSeverityFloor:
    def test_the_floor_is_inclusive(self) -> None:
        assert _severity_at_or_above("high", "high")
        assert _severity_at_or_above("critical", "high")
        assert not _severity_at_or_above("medium", "high")


class TestServiceReviewHonesty:
    @pytest.mark.asyncio
    async def test_no_denominator_reads_not_measured_never_zero(self) -> None:
        from app.services.service_review import build_service_review

        db = MagicMock()

        async def _execute(stmt: Any, params: dict | None = None) -> MagicMock:
            result = MagicMock()
            text = str(getattr(stmt, "text", stmt))
            if "FROM alerts" in text:
                result.fetchone.return_value = (0, 0, 0)
            elif "aisoc_closure_qa_samples" in text:
                result.fetchone.return_value = (5, 0, 0)  # sampled, none reviewed
            elif "aisoc_cases" in text:
                result.fetchone.return_value = (0, 0)
            elif "aisoc_action_records" in text:
                result.fetchone.return_value = (0, 0, 0)
            elif "aisoc_saved_hunts" in text:
                result.scalar_one.return_value = 0
            return result

        db.execute = AsyncMock(side_effect=_execute)
        start = datetime(2026, 11, 9, tzinfo=UTC)
        end = datetime(2026, 11, 16, tzinfo=UTC)

        async def _sla(*_a: Any, **_k: Any) -> dict:
            return {"per_severity": {}, "targets": {}}

        original = sr.compute_sla_metrics
        sr.compute_sla_metrics = _sla  # type: ignore[assignment]
        try:
            review = await build_service_review(db, TENANT, period_start=start, period_end=end)
        finally:
            sr.compute_sla_metrics = original  # type: ignore[assignment]

        assert review["alert_funnel"]["auto_close_share"] is None
        assert "not measured" in review["alert_funnel"]["note"]
        assert review["closure_qa"]["agreement"] is None
        assert review["closure_qa"]["agreement_denominator"] == 0
        assert "not measured" in review["closure_qa"]["note"]
