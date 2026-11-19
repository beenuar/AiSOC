"""Tests for the SOC Insights aggregator endpoint (T3.1).

The endpoint at ``/api/v1/insights/soc`` shapes a one-shot payload for the
SOC Insights dashboard: 7 tiles, each with a current value, a previous-
window comparison, an optional ``delta_pct``, and a 24-point sparkline.

These unit tests exercise response arithmetic over aggregate result rows.
The live PostgreSQL/HTTP regression suite separately verifies the queries,
authenticated tenant isolation, time bounds and the database query budget.

Coverage targets:

* ``_delta_pct`` — math + the "previous window had no data" branch
  (``None`` rather than ``inf``).
* ``_window_to_timedelta`` — clamping to the {24h, 7d, 30d} allowlist.
* Response shape of ``get_soc_insights`` against aggregate result rows, so a
  schema regression (renamed tile key, missing field, off-by-one in the
  ordering) is caught here and not at runtime in the browser.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from decimal import Decimal
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints.insights import (
    MANUAL_INVESTIGATION_MINUTES,
    SOCInsightsResponse,
    _delta_pct,
    _window_to_timedelta,
    get_soc_insights,
)
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def test_delta_pct_basic() -> None:
    # 5 → 10 is +100%
    assert _delta_pct(10.0, 5.0) == 100.0


def test_delta_pct_negative_change() -> None:
    # 10 → 5 is -50%
    assert _delta_pct(5.0, 10.0) == -50.0


def test_delta_pct_no_previous_data_returns_none() -> None:
    """Previous-window zero must be ``None`` (undefined), not infinity.

    The UI renders ``None`` as an em-dash; an infinity here would
    serialize as ``"Infinity"`` and corrupt JSON parsing on the client.
    """
    assert _delta_pct(7.0, 0.0) is None


def test_delta_pct_no_change_is_zero() -> None:
    assert _delta_pct(4.5, 4.5) == 0.0


def test_window_to_timedelta_accepts_24h() -> None:
    assert _window_to_timedelta("24h").days == 1


def test_window_to_timedelta_accepts_7d() -> None:
    assert _window_to_timedelta("7d").days == 7


def test_window_to_timedelta_accepts_30d() -> None:
    assert _window_to_timedelta("30d").days == 30


def test_window_to_timedelta_rejects_unknown() -> None:
    with pytest.raises(HTTPException) as exc_info:
        _window_to_timedelta("1y")
    assert exc_info.value.status_code == 400


# ---------------------------------------------------------------------------
# Endpoint response arithmetic
# ---------------------------------------------------------------------------


def _stub_user() -> CurrentUser:
    return CurrentUser(
        user_id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        role="admin",
        email="insights@example.com",
    )


def _seeded_db(
    *,
    alerts: list[dict] | None = None,
    cases: list[dict] | None = None,
    costs: list[dict] | None = None,
) -> MagicMock:
    """Aggregate result rows; SQL correctness is covered against PostgreSQL."""
    db = MagicMock(spec=AsyncSession)
    results = []
    for rows in (alerts, cases, costs):
        result = MagicMock()
        result.mappings.return_value = rows or []
        results.append(result)
    db.execute = AsyncMock(side_effect=results)
    transaction = MagicMock()
    transaction.is_active = True
    transaction.commit = AsyncMock()
    transaction.rollback = AsyncMock()
    db.begin_nested = AsyncMock(return_value=transaction)
    return db


@pytest.mark.asyncio
async def test_get_soc_insights_returns_seven_tiles_with_expected_keys() -> None:
    """The dashboard depends on a stable seven-tile shape — lock it in."""
    db = _seeded_db()
    user = _stub_user()

    response = await get_soc_insights(user=user, db=db, window="24h")

    assert isinstance(response, SOCInsightsResponse)
    assert response.window == "24h"
    assert response.manual_investigation_minutes == MANUAL_INVESTIGATION_MINUTES
    assert response.tenant_id == user.tenant_id
    assert isinstance(response.generated_at, datetime)
    assert response.generated_at.tzinfo == UTC

    keys = [tile.key for tile in response.tiles]
    assert keys == [
        "mtta",
        "mttr",
        "fp_rate",
        "alerts_per_day",
        "cases_per_day",
        "agent_cost_per_investigation",
        "analyst_hours_saved",
    ]

    # Every tile must have a sparkline of exactly 24 points so the SVG
    # renderer can rely on the bucket count without a runtime check.
    for tile in response.tiles:
        assert len(tile.sparkline.points) == 24
        # Sparkline points are floats — the frontend formats them with
        # ``Number(...)`` so an int would also pass, but locking the
        # type prevents accidental Decimal leakage.
        for point in tile.sparkline.points:
            assert isinstance(point, int | float)


@pytest.mark.asyncio
async def test_get_soc_insights_hours_saved_uses_named_constant() -> None:
    """The hours-saved tile must derive its value from the named heuristic.

    Operators expect to be able to tune ``MANUAL_INVESTIGATION_MINUTES``
    in one place and have the number ripple through both the JSON
    payload (so the docs/tooltip stay accurate) and the tile value.
    """
    # Four closed cases × 45 min = 180 min = 3.0 h saved.
    db = _seeded_db(cases=[{"bucket": 0, "count": 6, "closed": 4}, {"bucket": -1, "count": 3, "closed": 2}])
    user = _stub_user()

    response = await get_soc_insights(user=user, db=db, window="24h")

    hours_saved_tile = next(t for t in response.tiles if t.key == "analyst_hours_saved")
    expected_hours = round((4 * MANUAL_INVESTIGATION_MINUTES) / 60.0, 2)
    assert hours_saved_tile.value == expected_hours
    assert hours_saved_tile.unit == "hours_saved"
    assert hours_saved_tile.sample_count == 4
    assert hours_saved_tile.previous_value == expected_hours / 2
    assert hours_saved_tile.delta_pct == 100.0


@pytest.mark.asyncio
async def test_get_soc_insights_rejects_unknown_window() -> None:
    """Tenants can't sneak a 365-day scan past us via the query string."""
    db = _seeded_db()
    user = _stub_user()

    with pytest.raises(HTTPException) as exc_info:
        await get_soc_insights(user=user, db=db, window="1y")  # type: ignore[arg-type]
    assert exc_info.value.status_code == 400


@pytest.mark.asyncio
async def test_get_soc_insights_zero_state_renders_without_500() -> None:
    """Fresh tenant: no alerts, no cases — payload should still render.

    The dashboard needs to render the day a tenant onboards, so a 500 or a
    blank page is not acceptable. What *is* rendered changed, and the
    distinction is the point of the test.

    A counting tile with nothing to count is genuinely `0`: zero alerts
    arrived, and that is a measurement. An **averaging** tile with nothing
    to average publishes `0.0` *with a `sample_count` of 0*, and the pair
    is the measurement — the count is what separates "responded instantly"
    from "nobody responded".

    The mean is deliberately not nullable: that is a breaking response
    change for every generated client, and `/metrics/soc` already took
    this decision for `mttd_sample_count`. The openapi-breaking gate
    caught an earlier attempt here to make it null.
    """
    db = _seeded_db()
    user = _stub_user()

    response = await get_soc_insights(user=user, db=db, window="7d")

    assert response.window == "7d"
    assert len(response.tiles) == 7

    by_key = {t.key: t for t in response.tiles}
    for key in ("mtta", "mttr", "fp_rate", "agent_cost_per_investigation", "analyst_hours_saved"):
        tile = by_key[key]
        assert tile.sample_count == 0, f"{key} published no denominator, so a reader cannot tell an empty window from a real zero"

    for tile in response.tiles:
        # Nothing to compare against, so a delta would be invented.
        assert tile.delta_pct is None


@pytest.mark.asyncio
async def test_window_means_weight_each_bucket_by_its_samples() -> None:
    """A sparsely populated bucket must not carry the same weight as a busy one."""
    db = _seeded_db(
        alerts=[
            {
                "bucket": -1,
                "count": 20,
                "mtta_sum": 8,
                "mtta_n": 4,
                "mttr_sum": 6,
                "mttr_n": 1,
                "decided": 4,
                "false_positives": 1,
            },
            {
                "bucket": 0,
                "count": 10,
                "mtta_sum": 2,
                "mtta_n": 1,
                "mttr_sum": 8,
                "mttr_n": 2,
                "decided": 2,
                "false_positives": 1,
            },
            {
                "bucket": 23,
                "count": 3,
                "mtta_sum": 12,
                "mtta_n": 3,
                "mttr_sum": 10,
                "mttr_n": 1,
                "decided": 1,
                "false_positives": 0,
            },
        ],
        costs=[
            {"bucket": -1, "cost": 2.0, "runs": 1},
            {"bucket": 0, "cost": 1.0, "runs": 1},
            {"bucket": 23, "cost": 5.0, "runs": 3},
        ],
    )
    response = await get_soc_insights(user=_stub_user(), db=db, window="7d")
    tiles = {tile.key: tile for tile in response.tiles}

    assert (tiles["mtta"].value, tiles["mtta"].sample_count) == (3.5, 4)
    assert (tiles["mtta"].previous_value, tiles["mtta"].delta_pct) == (2, 75)
    assert (tiles["mttr"].value, tiles["mttr"].sample_count) == (6, 3)
    assert (tiles["mttr"].previous_value, tiles["mttr"].delta_pct) == (6, 0)
    assert (tiles["fp_rate"].value, tiles["fp_rate"].sample_count) == (0.3333, 3)
    assert tiles["fp_rate"].previous_value == 0.25
    assert tiles["alerts_per_day"].value == round(13 / 7, 2)
    assert tiles["alerts_per_day"].sparkline.points == [10.0] + [0.0] * 22 + [3.0]
    cost = tiles["agent_cost_per_investigation"]
    assert (cost.value, cost.sample_count, cost.previous_value, cost.delta_pct) == (1.5, 4, 2, -25)
    assert cost.sparkline.points == [1.0] + [0.0] * 22 + [5.0]


@pytest.mark.asyncio
async def test_unmeasured_durations_do_not_gain_samples_from_alert_volume() -> None:
    db = _seeded_db(
        alerts=[
            {
                "bucket": 3,
                "count": 9,
                "mtta_sum": None,
                "mtta_n": 0,
                "mttr_sum": None,
                "mttr_n": 0,
                "decided": 0,
                "false_positives": 0,
            },
            {
                "bucket": -1,
                "count": 1,
                "mtta_sum": 2,
                "mtta_n": 1,
                "mttr_sum": 4,
                "mttr_n": 1,
                "decided": 1,
                "false_positives": 1,
            },
        ],
    )
    response = await get_soc_insights(user=_stub_user(), db=db, window="24h")
    tiles = {tile.key: tile for tile in response.tiles}
    assert tiles["alerts_per_day"].value == 9
    for key in ("mtta", "mttr", "fp_rate"):
        assert tiles[key].sample_count == 0
        assert tiles[key].value == 0
        assert tiles[key].delta_pct is None


@pytest.mark.asyncio
async def test_duration_rounding_preserves_database_precision_across_buckets() -> None:
    # PostgreSQL's original window-wide AVG yields Decimal('1.675'),
    # which the response rounds to 1.68. Adding bucket sums as binary
    # floats first yields 1.6749999999999998 and incorrectly rounds down.
    db = _seeded_db(
        alerts=[
            {
                "bucket": idx,
                "count": 1,
                "mtta_sum": hours,
                "mtta_n": 1,
                "mttr_sum": hours,
                "mttr_n": 1,
                "decided": 0,
                "false_positives": 0,
            }
            for idx, hours in enumerate((Decimal("3.34"), Decimal("0.01")))
        ],
    )
    response = await get_soc_insights(user=_stub_user(), db=db, window="24h")
    tiles = {tile.key: tile for tile in response.tiles}
    assert tiles["mtta"].value == 1.68
    assert tiles["mttr"].value == 1.68
