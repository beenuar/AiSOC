"""Tests for the SOC Insights aggregator endpoint (T3.1).

The endpoint at ``/api/v1/insights/soc`` shapes a one-shot payload for the
SOC Insights dashboard: 7 tiles, each with a current value, a previous-
window comparison, an optional ``delta_pct``, and a 24-point sparkline.

The aggregation logic is a pure mix of SQLAlchemy aggregates plus the
named ``MANUAL_INVESTIGATION_MINUTES`` heuristic. We test it the same
way the rest of the API service tests its endpoint helpers — using a
``MagicMock`` ``AsyncSession`` whose ``scalar`` / ``execute`` return
canned values per call — so the suite stays fast and deterministic.

Coverage targets:

* ``_delta_pct`` — math + the "previous window had no data" branch
  (``None`` rather than ``inf``).
* ``_window_to_timedelta`` — clamping to the {24h, 7d, 30d} allowlist.
* End-to-end shape of ``get_soc_insights`` against seeded numbers, so a
  schema regression (renamed tile key, missing field, off-by-one in the
  ordering) is caught here and not at runtime in the browser.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.api.v1.endpoints.insights import (
    MANUAL_INVESTIGATION_MINUTES,
    SOCInsightsResponse,
    _delta_pct,
    _window_to_timedelta,
    get_soc_insights,
)
from fastapi import HTTPException

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
# End-to-end endpoint shape
# ---------------------------------------------------------------------------


def _stub_user() -> SimpleNamespace:
    """Minimal ``CurrentUser`` stand-in (only ``tenant_id`` is read)."""
    return SimpleNamespace(tenant_id=uuid.uuid4())


class _FakeMappings:
    """Cursor-shaped object that satisfies ``.first()`` and iteration."""

    def __init__(self, rows: list[dict] | None = None) -> None:
        self._rows = rows or []

    def first(self):  # noqa: D401 - mirror SQLAlchemy
        return self._rows[0] if self._rows else None

    def __iter__(self):
        return iter(self._rows)


class _FakeResult:
    """Stand-in for ``Result`` that exposes both ``.all()`` and ``.mappings()``."""

    def __init__(self, rows: list | None = None, mappings: list[dict] | None = None) -> None:
        self._rows = rows or []
        self._mappings = mappings or []

    def all(self) -> list:
        return self._rows

    def mappings(self) -> _FakeMappings:
        return _FakeMappings(self._mappings)


def _seeded_db(scalar_value: int = 5) -> MagicMock:
    """Build an AsyncSession-shaped mock that returns deterministic numbers.

    The endpoint calls ``db.scalar`` and ``db.execute`` many times. We
    return a *fresh* value each call so we can verify the response
    builds without exception and that every tile is populated.

    Numeric values are deliberately picked so the deltas are easy to
    eyeball when the test fails — e.g. current = 10, previous = 5 →
    +100%.
    """
    db = MagicMock()

    # Scalars (current values, then previous-window comparisons + counts).
    # We return the same value for every call — the goal is to assert
    # the tile shape, not the exact arithmetic. The hours-saved test
    # uses a dedicated seed to exercise the heuristic specifically.
    db.scalar = AsyncMock(return_value=scalar_value)

    # ``execute`` is used three places:
    #   * sparkline alerts query → ``.all()`` of (timestamp,) tuples
    #   * sparkline cases  query → ``.all()`` of (timestamp,) tuples
    #   * cost queries (text SQL) → ``.mappings().first()`` / iteration.
    # Empty rows + empty mappings is the "nothing seeded" baseline.
    async def _execute(*_args, **_kwargs):
        return _FakeResult()

    db.execute = AsyncMock(side_effect=_execute)
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
    # Every scalar — including ``_count(... Case.status == 'resolved')``
    # — returns 4. 4 auto-closed cases × 45 min = 180 min = 3.0 h saved.
    db = _seeded_db(scalar_value=4)
    user = _stub_user()

    response = await get_soc_insights(user=user, db=db, window="24h")

    hours_saved_tile = next(t for t in response.tiles if t.key == "analyst_hours_saved")
    expected_hours = round((4 * MANUAL_INVESTIGATION_MINUTES) / 60.0, 2)
    assert hours_saved_tile.value == expected_hours
    assert hours_saved_tile.unit == "hours_saved"


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

    The dashboard needs to render the day a tenant onboards. Returning
    7 tiles of zero with ``delta_pct == None`` is preferable to a 500
    or a blank page.
    """
    db = _seeded_db(scalar_value=0)
    user = _stub_user()

    response = await get_soc_insights(user=user, db=db, window="7d")

    assert response.window == "7d"
    assert len(response.tiles) == 7
    for tile in response.tiles:
        # Both current and previous are zero, so delta is undefined.
        assert tile.value == 0 or tile.value == 0.0
        assert tile.delta_pct is None
