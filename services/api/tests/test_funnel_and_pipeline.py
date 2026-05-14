"""Unit tests for the v1.5 SOC Console funnel + pipeline-health endpoints.

These two endpoints (``GET /api/v1/metrics/funnel`` and ``GET /api/v1/health/pipeline``)
back the new operator dashboard. They're pure read-side aggregations over
Postgres (and ClickHouse for one column on the funnel), so we test them
the same way the rest of the read-side endpoints in this project are
tested — patch the DB seam, exercise every branch in isolation, and
assert on the shape we hand back to FastAPI.

We deliberately do NOT spin up the TestClient here. The endpoint
functions are thin orchestrators around per-stage / per-metric helpers;
the integration tests in CI exercise the SQL against a real Postgres
fixture. The job of *this* file is to lock the per-cell math down to a
specification you can read in 30 seconds:

* "no data" returns ``unknown``, never ``green`` (mirrors
  ``connector_freshness``);
* deltas are percentage changes, never raw differences;
* p95 latency is reported in milliseconds, not seconds;
* MITRE coverage is computed against a configurable denominator;
* the overall pipeline status is the worst-of across the 5 stages.

If any of those invariants change without a corresponding test update,
the dashboard quietly starts lying — and that's exactly the kind of
regression the v1.5 honest-measurement plan was supposed to prevent.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────


def _user() -> SimpleNamespace:
    """Stand-in for ``CurrentUser`` — only ``tenant_id`` is read."""
    return SimpleNamespace(
        user_id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
    )


def _connector_row(
    *,
    category: str = "edr",
    last_event_at: datetime | None = None,
    health_status: str = "healthy",
    is_enabled: bool = True,
    connector_config: dict | None = None,
) -> SimpleNamespace:
    """Stand-in for a row returned by the ingest-stage query.

    The query selects 5 columns: ``category``, ``last_event_at``,
    ``health_status``, ``is_enabled``, ``connector_config``. We
    expose them as attributes so the production code can keep
    using ``r.category`` style access without mock plumbing.
    """
    return SimpleNamespace(
        category=category,
        last_event_at=last_event_at,
        health_status=health_status,
        is_enabled=is_enabled,
        connector_config=connector_config or {},
    )


def _execute_result_all(rows: list) -> MagicMock:
    """Mock ``await db.execute(...).all()`` returning ``rows``."""
    result = MagicMock()
    result.all = MagicMock(return_value=rows)
    return result


def _scalars_all_result(values: list) -> MagicMock:
    """Mock ``await db.execute(...).scalars().all()`` returning ``values``."""
    scalars = MagicMock()
    scalars.all = MagicMock(return_value=values)
    result = MagicMock()
    result.scalars = MagicMock(return_value=scalars)
    return result


# ──────────────────────────────────────────────────────────────────────────────
# /metrics/funnel — _pct_delta (pure)
# ──────────────────────────────────────────────────────────────────────────────


class TestPctDelta:
    """Period-over-period percentage helper.

    Tiny and pure — the contract is exactly two lines: zero-base
    returns 0.0 (never ``inf``), otherwise round to two decimals.
    """

    def test_zero_previous_returns_zero(self) -> None:
        from app.api.v1.endpoints.metrics import _pct_delta

        # The dashboard cannot render ``inf`` or ``NaN`` — we'd
        # rather show "no change" than a useless ∞ pill.
        assert _pct_delta(10.0, 0.0) == 0.0
        assert _pct_delta(0.0, 0.0) == 0.0

    def test_positive_change(self) -> None:
        from app.api.v1.endpoints.metrics import _pct_delta

        # 100 → 150 ⇒ +50% exactly.
        assert _pct_delta(150.0, 100.0) == 50.0

    def test_negative_change(self) -> None:
        from app.api.v1.endpoints.metrics import _pct_delta

        # 100 → 75 ⇒ −25% exactly.
        assert _pct_delta(75.0, 100.0) == -25.0

    def test_rounds_to_two_decimals(self) -> None:
        from app.api.v1.endpoints.metrics import _pct_delta

        # 3/7 ⇒ 0.4285714… ⇒ 42.86% (2 dp).
        assert _pct_delta(10.0, 7.0) == round(((10 - 7) / 7) * 100.0, 2)


# ──────────────────────────────────────────────────────────────────────────────
# /metrics/funnel — _funnel_window happy path
# ──────────────────────────────────────────────────────────────────────────────


class TestFunnelWindow:
    """Single-window roll-up shared by current + previous windows."""

    @pytest.mark.asyncio
    async def test_returns_full_keyset_with_safe_defaults(self) -> None:
        # Empty tenant: every counter must be a Python ``int``/``float``
        # (never ``None``) and ``mitre_coverage`` must be a populated
        # ``MitreCoverage`` instance — Pydantic 422s otherwise.
        from app.api.v1.endpoints.metrics import MitreCoverage, _funnel_window

        db = MagicMock()
        # 7 scalar() calls in order:
        # 1. correlation_instances
        # 2. alerts_generated
        # 3. sig_total (disposition in the closed set)
        # 4. sig_tp (disposition='true_positive')
        # 5. mttd_seconds_raw
        # 6. analyst_queue_depth
        # _events_of_interest path uses _events_of_interest_from_alerts → 7. EOI sum
        db.scalar = AsyncMock(side_effect=[0, 0, 0, 0, 0, None, 0])
        # _mitre_covered calls db.execute() twice (alert_techs, rule_techs)
        db.execute = AsyncMock(
            side_effect=[
                _scalars_all_result([]),
                _scalars_all_result([]),
            ]
        )

        tenant = uuid.uuid4()
        start = datetime.now(UTC) - timedelta(hours=24)
        end = datetime.now(UTC)

        with patch(
            "app.api.v1.endpoints.metrics.settings",
            SimpleNamespace(AISOC_DISABLE_CLICKHOUSE=True, AISOC_FUNNEL_MITRE_TOTAL=201),
        ):
            result = await _funnel_window(db, tenant, start, end, mitre_total=201)

        assert result["events_of_interest"] == 0
        assert result["correlation_instances"] == 0
        assert result["alerts_generated"] == 0
        assert result["signal_to_noise"] == 0.0
        assert result["mttd_seconds"] == 0.0
        assert result["analyst_queue_depth"] == 0
        assert result["correlation_efficiency"] == 0.0
        assert result["alert_yield"] == 0.0
        assert isinstance(result["mitre_coverage"], MitreCoverage)
        assert result["mitre_coverage"].total == 201
        assert result["mitre_coverage"].covered == 0
        assert result["mitre_coverage"].ratio == 0.0

    @pytest.mark.asyncio
    async def test_signal_to_noise_uses_dispositioned_alerts(self) -> None:
        # 4 dispositioned, 1 true_positive → SNR = 0.25.
        from app.api.v1.endpoints.metrics import _funnel_window

        db = MagicMock()
        # scalar() order in _funnel_window (with ClickHouse disabled):
        # 1. EOI fallback          → 50
        # 2. correlation_instances → 2
        # 3. alerts_generated      → 10
        # 4. sig_total             → 4
        # 5. sig_tp                → 1
        # 6. mttd_seconds_raw      → 60.0
        # 7. analyst_queue_depth   → 3
        db.scalar = AsyncMock(side_effect=[50, 2, 10, 4, 1, 60.0, 3])
        db.execute = AsyncMock(
            side_effect=[
                _scalars_all_result([]),
                _scalars_all_result([]),
            ]
        )

        with patch(
            "app.api.v1.endpoints.metrics.settings",
            SimpleNamespace(AISOC_DISABLE_CLICKHOUSE=True, AISOC_FUNNEL_MITRE_TOTAL=201),
        ):
            result = await _funnel_window(
                db,
                uuid.uuid4(),
                datetime.now(UTC) - timedelta(hours=24),
                datetime.now(UTC),
                mitre_total=201,
            )

        assert result["signal_to_noise"] == 0.25
        # MTTD is in seconds, rounded to 2 dp.
        assert result["mttd_seconds"] == 60.0
        # Correlation efficiency = 2 correlated / 50 EOI = 0.04.
        assert result["correlation_efficiency"] == 0.04
        # Alert yield = 10 / 50 = 0.2.
        assert result["alert_yield"] == 0.2

    @pytest.mark.asyncio
    async def test_efficiency_clamps_to_one(self) -> None:
        # Postgres fallback can under-count EOI vs alerts → ratios > 1
        # are clamped to 1.0 so the UI doesn't render a nonsense "117%
        # alert yield" pill.
        from app.api.v1.endpoints.metrics import _funnel_window

        db = MagicMock()
        # Order: EOI=3, correlation=5, alerts=12, sig_total=0, sig_tp=0,
        # mttd=None, queue=0 → both ratios should clamp to 1.0.
        db.scalar = AsyncMock(side_effect=[3, 5, 12, 0, 0, None, 0])
        db.execute = AsyncMock(
            side_effect=[
                _scalars_all_result([]),
                _scalars_all_result([]),
            ]
        )

        with patch(
            "app.api.v1.endpoints.metrics.settings",
            SimpleNamespace(AISOC_DISABLE_CLICKHOUSE=True, AISOC_FUNNEL_MITRE_TOTAL=201),
        ):
            result = await _funnel_window(
                db,
                uuid.uuid4(),
                datetime.now(UTC) - timedelta(hours=24),
                datetime.now(UTC),
                mitre_total=201,
            )

        assert result["correlation_efficiency"] == 1.0
        assert result["alert_yield"] == 1.0

    @pytest.mark.asyncio
    async def test_mitre_coverage_unions_alerts_and_rules(self) -> None:
        # _mitre_covered unions: alerts techs ∪ enabled-rule techs.
        # The union must deduplicate.
        from app.api.v1.endpoints.metrics import _funnel_window

        db = MagicMock()
        # Minimum viable scalar fixtures.
        db.scalar = AsyncMock(side_effect=[0, 0, 0, 0, None, 0, 0])
        # alert_techs: T1078, T1059
        # rule_techs:  T1059, T1110 → union = {T1078, T1059, T1110} = 3
        db.execute = AsyncMock(
            side_effect=[
                _scalars_all_result(["T1078", "T1059"]),
                _scalars_all_result(["T1059", "T1110"]),
            ]
        )

        with patch(
            "app.api.v1.endpoints.metrics.settings",
            SimpleNamespace(AISOC_DISABLE_CLICKHOUSE=True, AISOC_FUNNEL_MITRE_TOTAL=10),
        ):
            result = await _funnel_window(
                db,
                uuid.uuid4(),
                datetime.now(UTC) - timedelta(hours=24),
                datetime.now(UTC),
                mitre_total=10,
            )

        assert result["mitre_coverage"].covered == 3
        assert result["mitre_coverage"].total == 10
        assert result["mitre_coverage"].ratio == 0.3

    @pytest.mark.asyncio
    async def test_mitre_coverage_ratio_clamps_to_one(self) -> None:
        # If the tenant has more techniques in scope than the configured
        # ATT&CK total (operator misconfigured ``AISOC_FUNNEL_MITRE_TOTAL``),
        # we still clamp to 1.0 — the UI can't render "150% coverage".
        from app.api.v1.endpoints.metrics import _funnel_window

        db = MagicMock()
        db.scalar = AsyncMock(side_effect=[0, 0, 0, 0, None, 0, 0])
        db.execute = AsyncMock(
            side_effect=[
                _scalars_all_result([f"T{i}" for i in range(50)]),
                _scalars_all_result([]),
            ]
        )

        with patch(
            "app.api.v1.endpoints.metrics.settings",
            SimpleNamespace(AISOC_DISABLE_CLICKHOUSE=True, AISOC_FUNNEL_MITRE_TOTAL=10),
        ):
            result = await _funnel_window(
                db,
                uuid.uuid4(),
                datetime.now(UTC) - timedelta(hours=24),
                datetime.now(UTC),
                mitre_total=10,
            )

        assert result["mitre_coverage"].covered == 50
        assert result["mitre_coverage"].ratio == 1.0


# ──────────────────────────────────────────────────────────────────────────────
# /metrics/funnel — endpoint orchestration
# ──────────────────────────────────────────────────────────────────────────────


class TestGetFunnelMetrics:
    """End-to-end assembly: current + previous window, deltas, schema."""

    @pytest.mark.asyncio
    async def test_returns_funnel_metrics_with_deltas(self) -> None:
        from app.api.v1.endpoints.metrics import (
            FunnelMetrics,
            MitreCoverage,
            get_funnel_metrics,
        )

        user = _user()

        # We patch ``_funnel_window`` directly so we don't have to feed
        # the SQL helper 14 mock side_effects in the right order. This
        # keeps the test focused on the orchestrator's job: pulling two
        # windows, computing deltas, packaging into ``FunnelMetrics``.
        current = {
            "events_of_interest": 200,
            "correlation_instances": 30,
            "alerts_generated": 50,
            "signal_to_noise": 0.6,
            "mttd_seconds": 90.0,
            "analyst_queue_depth": 5,
            "correlation_efficiency": 0.15,
            "alert_yield": 0.25,
            "mitre_coverage": MitreCoverage(covered=30, total=201, ratio=0.1493),
        }
        previous = {
            "events_of_interest": 100,
            "correlation_instances": 10,
            "alerts_generated": 25,
            "signal_to_noise": 0.5,
            "mttd_seconds": 100.0,
            "analyst_queue_depth": 8,
            "correlation_efficiency": 0.1,
            "alert_yield": 0.25,
            "mitre_coverage": MitreCoverage(covered=20, total=201, ratio=0.0995),
        }

        with patch(
            "app.api.v1.endpoints.metrics._funnel_window",
            new=AsyncMock(side_effect=[current, previous]),
        ):
            payload = await get_funnel_metrics(user=user, db=MagicMock(), period="24h")

        assert isinstance(payload, FunnelMetrics)
        assert payload.period == "24h"
        assert payload.events_of_interest == 200
        assert payload.correlation_instances == 30
        assert payload.alerts_generated == 50
        assert payload.signal_to_noise == 0.6
        assert payload.mttd_seconds == 90.0
        assert payload.analyst_queue_depth == 5
        assert payload.correlation_efficiency == 0.15
        assert payload.alert_yield == 0.25
        assert payload.mitre_coverage.covered == 30
        # Deltas are percent change vs previous window.
        # EOI: 200 vs 100 → +100%
        assert payload.deltas.events_of_interest == 100.0
        # Correlations: 30 vs 10 → +200%
        assert payload.deltas.correlation_instances == 200.0
        # Alerts: 50 vs 25 → +100%
        assert payload.deltas.alerts_generated == 100.0
        # SNR: 0.6 vs 0.5 → +20%
        assert payload.deltas.signal_to_noise == 20.0
        # MTTD: 90 vs 100 → −10% (faster is better — UI flips sign)
        assert payload.deltas.mttd_seconds == -10.0
        # Queue: 5 vs 8 → −37.5%
        assert payload.deltas.analyst_queue_depth == -37.5

    @pytest.mark.asyncio
    async def test_period_validation_accepts_known_values(self) -> None:
        # The pattern regex on the ``period`` query is the *only* place
        # the API enforces the four allowed windows. Make sure every
        # documented period maps to a non-zero ``timedelta`` so we
        # can't accidentally drop one.
        from app.api.v1.endpoints.metrics import _FUNNEL_PERIOD_MAP

        assert set(_FUNNEL_PERIOD_MAP.keys()) == {"1h", "24h", "7d", "30d"}
        for window in _FUNNEL_PERIOD_MAP.values():
            assert window.total_seconds() > 0


# ──────────────────────────────────────────────────────────────────────────────
# /health/pipeline — pure helpers
# ──────────────────────────────────────────────────────────────────────────────


class TestStatusFromLatency:
    """Latency → status ladder.

    Specification: ``None`` is never ``green``. Below the warn ceiling
    is ``green``; below the down ceiling is ``yellow``; above is
    ``red``. Boundaries are inclusive on the lower side (i.e. exactly
    ``warn_seconds`` is still ``green``).
    """

    def test_none_returns_unknown(self) -> None:
        from app.api.v1.endpoints.health import _status_from_latency

        assert _status_from_latency(p95_seconds=None, warn_seconds=600, down_seconds=1800) == "unknown"

    def test_below_warn_is_green(self) -> None:
        from app.api.v1.endpoints.health import _status_from_latency

        assert _status_from_latency(p95_seconds=0.0, warn_seconds=600, down_seconds=1800) == "green"
        assert _status_from_latency(p95_seconds=599.0, warn_seconds=600, down_seconds=1800) == "green"
        # Exactly at the warn ceiling → still green (≤, not <).
        assert _status_from_latency(p95_seconds=600.0, warn_seconds=600, down_seconds=1800) == "green"

    def test_below_down_is_yellow(self) -> None:
        from app.api.v1.endpoints.health import _status_from_latency

        assert _status_from_latency(p95_seconds=601.0, warn_seconds=600, down_seconds=1800) == "yellow"
        # Exactly at the down ceiling → still yellow.
        assert _status_from_latency(p95_seconds=1800.0, warn_seconds=600, down_seconds=1800) == "yellow"

    def test_above_down_is_red(self) -> None:
        from app.api.v1.endpoints.health import _status_from_latency

        assert _status_from_latency(p95_seconds=1801.0, warn_seconds=600, down_seconds=1800) == "red"


class TestWorstStatus:
    """Aggregator that drives ``overall_status`` and the ingest roll-up."""

    def test_empty_list_returns_unknown(self) -> None:
        from app.api.v1.endpoints.health import _worst_status

        # A tenant with no enabled stages → "we don't know," not "all good".
        assert _worst_status([]) == "unknown"

    def test_returns_worst_entry(self) -> None:
        from app.api.v1.endpoints.health import _worst_status

        assert _worst_status(["green", "green"]) == "green"
        assert _worst_status(["green", "yellow"]) == "yellow"
        assert _worst_status(["green", "yellow", "red"]) == "red"
        assert _worst_status(["yellow", "red"]) == "red"

    def test_unknown_ranks_worse_than_green(self) -> None:
        from app.api.v1.endpoints.health import _worst_status

        # Mirrors connector_freshness: we never paint green over
        # an "unknown" — a brand-new connector with no events yet
        # should not let the tenant's overall_status say "green."
        assert _worst_status(["green", "unknown"]) == "unknown"

    def test_unknown_ranks_better_than_yellow(self) -> None:
        from app.api.v1.endpoints.health import _worst_status

        assert _worst_status(["unknown", "yellow"]) == "yellow"
        assert _worst_status(["unknown", "red"]) == "red"

    def test_unrecognised_status_defaults_to_unknown_rank(self) -> None:
        # Defensive: a typo / drift in status strings must NOT
        # let a stage win the aggregation by accident.
        from app.api.v1.endpoints.health import _worst_status

        # ``"weird"`` resolves to the same rank as "unknown" (1),
        # which is worse than "green" (0) but better than "yellow" (2).
        assert _worst_status(["green", "weird"]) in ("weird", "unknown")
        assert _worst_status(["weird", "yellow"]) == "yellow"


# ──────────────────────────────────────────────────────────────────────────────
# /health/pipeline — per-stage helpers
# ──────────────────────────────────────────────────────────────────────────────


class TestIngestStage:
    """Connector freshness roll-up."""

    @pytest.mark.asyncio
    async def test_no_enabled_connectors_returns_unknown(self) -> None:
        from app.api.v1.endpoints.health import _ingest_stage

        # A fresh tenant with zero connectors should report ``unknown``,
        # NOT ``red`` — they haven't onboarded anything yet and a red
        # pill on the dashboard would page them gratuitously.
        db = MagicMock()
        db.execute = AsyncMock(return_value=_execute_result_all([]))

        stage = await _ingest_stage(db, uuid.uuid4(), now=datetime.now(UTC))
        assert stage.stage == "ingest"
        assert stage.backlog == 0
        assert stage.p95_latency_ms == 0.0
        assert stage.error_rate == 0.0
        assert stage.status == "unknown"

    @pytest.mark.asyncio
    async def test_all_disabled_connectors_returns_unknown(self) -> None:
        from app.api.v1.endpoints.health import _ingest_stage

        db = MagicMock()
        db.execute = AsyncMock(return_value=_execute_result_all([_connector_row(is_enabled=False)]))
        stage = await _ingest_stage(db, uuid.uuid4(), now=datetime.now(UTC))
        assert stage.status == "unknown"
        assert stage.backlog == 0

    @pytest.mark.asyncio
    async def test_all_green_connectors_returns_green(self) -> None:
        from app.api.v1.endpoints.health import _ingest_stage

        now = datetime.now(UTC)
        # EDR cadence is 5 min → 1 min ago is well within green.
        recent = now - timedelta(minutes=1)
        db = MagicMock()
        db.execute = AsyncMock(
            return_value=_execute_result_all(
                [
                    _connector_row(category="edr", last_event_at=recent),
                    _connector_row(category="siem", last_event_at=recent),
                ]
            )
        )

        stage = await _ingest_stage(db, uuid.uuid4(), now=now)
        assert stage.status == "green"
        assert stage.backlog == 0
        assert stage.error_rate == 0.0

    @pytest.mark.asyncio
    async def test_one_stale_connector_pushes_red(self) -> None:
        from app.api.v1.endpoints.health import _ingest_stage

        now = datetime.now(UTC)
        # 1 healthy + 1 way past 2× EDR cadence (5 min × 2 = 10 min).
        db = MagicMock()
        db.execute = AsyncMock(
            return_value=_execute_result_all(
                [
                    _connector_row(category="edr", last_event_at=now - timedelta(minutes=1)),
                    _connector_row(category="edr", last_event_at=now - timedelta(hours=2)),
                ]
            )
        )

        stage = await _ingest_stage(db, uuid.uuid4(), now=now)
        assert stage.status == "red"
        # Exactly one connector in the red band.
        assert stage.backlog == 1

    @pytest.mark.asyncio
    async def test_error_rate_uses_health_status(self) -> None:
        from app.api.v1.endpoints.health import _ingest_stage

        now = datetime.now(UTC)
        recent = now - timedelta(minutes=1)
        db = MagicMock()
        db.execute = AsyncMock(
            return_value=_execute_result_all(
                [
                    _connector_row(
                        category="edr",
                        last_event_at=recent,
                        health_status="healthy",
                    ),
                    _connector_row(
                        category="edr",
                        last_event_at=recent,
                        health_status="unhealthy",
                    ),
                    _connector_row(
                        category="edr",
                        last_event_at=recent,
                        health_status="unhealthy",
                    ),
                    _connector_row(
                        category="edr",
                        last_event_at=recent,
                        health_status="healthy",
                    ),
                ]
            )
        )

        stage = await _ingest_stage(db, uuid.uuid4(), now=now)
        # 2 unhealthy / 4 enabled = 0.5 error rate.
        assert stage.error_rate == 0.5

    @pytest.mark.asyncio
    async def test_per_connector_cadence_override_is_honoured(self) -> None:
        from app.api.v1.endpoints.health import _ingest_stage

        now = datetime.now(UTC)
        # SIEM default is 15 min. Without the override, 30 min ago
        # would be RED (> 2× cadence). With override=3600 (1h), it's
        # still GREEN (≤ cadence).
        db = MagicMock()
        db.execute = AsyncMock(
            return_value=_execute_result_all(
                [
                    _connector_row(
                        category="siem",
                        last_event_at=now - timedelta(minutes=30),
                        connector_config={"expected_cadence_seconds": 3600},
                    )
                ]
            )
        )

        stage = await _ingest_stage(db, uuid.uuid4(), now=now)
        assert stage.status == "green"


class TestNormalizeStage:
    """Normalize p95 from ``created_at - event_time`` (seconds → ms)."""

    @pytest.mark.asyncio
    async def test_no_data_returns_unknown(self) -> None:
        from app.api.v1.endpoints.health import _normalize_stage

        # ``percentile_cont`` returns NULL when no rows match → None
        # → must be ``unknown`` rather than a misleading ``green``.
        db = MagicMock()
        db.scalar = AsyncMock(return_value=None)

        now = datetime.now(UTC)
        stage = await _normalize_stage(
            db,
            uuid.uuid4(),
            warn_seconds=600,
            down_seconds=1800,
            window_start=now - timedelta(hours=1),
            window_end=now,
        )
        assert stage.stage == "normalize"
        assert stage.status == "unknown"
        assert stage.p95_latency_ms == 0.0

    @pytest.mark.asyncio
    async def test_fast_p95_is_green_and_in_milliseconds(self) -> None:
        from app.api.v1.endpoints.health import _normalize_stage

        db = MagicMock()
        # 12.5 seconds end-to-end normalize lag.
        db.scalar = AsyncMock(return_value=12.5)

        now = datetime.now(UTC)
        stage = await _normalize_stage(
            db,
            uuid.uuid4(),
            warn_seconds=600,
            down_seconds=1800,
            window_start=now - timedelta(hours=1),
            window_end=now,
        )
        assert stage.status == "green"
        # 12.5s → 12500.0ms (no rounding loss; the round() to 2dp
        # only matters for fractional ms).
        assert stage.p95_latency_ms == 12500.0

    @pytest.mark.asyncio
    async def test_slow_p95_is_red(self) -> None:
        from app.api.v1.endpoints.health import _normalize_stage

        db = MagicMock()
        # 1h normalize lag → above the default 30-min down ceiling.
        db.scalar = AsyncMock(return_value=3600.0)

        now = datetime.now(UTC)
        stage = await _normalize_stage(
            db,
            uuid.uuid4(),
            warn_seconds=600,
            down_seconds=1800,
            window_start=now - timedelta(hours=1),
            window_end=now,
        )
        assert stage.status == "red"
        assert stage.p95_latency_ms == 3600_000.0

    @pytest.mark.asyncio
    async def test_negative_lag_floors_to_zero(self) -> None:
        # Clock skew can produce a negative p95 lag (event_time later
        # than created_at, e.g. NTP drift on a connector). We clamp
        # to zero rather than reporting a negative ms latency.
        from app.api.v1.endpoints.health import _normalize_stage

        db = MagicMock()
        db.scalar = AsyncMock(return_value=-5.0)

        now = datetime.now(UTC)
        stage = await _normalize_stage(
            db,
            uuid.uuid4(),
            warn_seconds=600,
            down_seconds=1800,
            window_start=now - timedelta(hours=1),
            window_end=now,
        )
        assert stage.p95_latency_ms == 0.0
        assert stage.status == "green"


class TestFuseStage:
    """Fuse p95 mirrors normalize — same shape, different SQL."""

    @pytest.mark.asyncio
    async def test_no_data_returns_unknown(self) -> None:
        from app.api.v1.endpoints.health import _fuse_stage

        db = MagicMock()
        db.scalar = AsyncMock(return_value=None)
        now = datetime.now(UTC)
        stage = await _fuse_stage(
            db,
            uuid.uuid4(),
            warn_seconds=600,
            down_seconds=1800,
            window_start=now - timedelta(hours=1),
            window_end=now,
        )
        assert stage.stage == "fuse"
        assert stage.status == "unknown"
        assert stage.p95_latency_ms == 0.0

    @pytest.mark.asyncio
    async def test_p95_window_in_yellow_band(self) -> None:
        from app.api.v1.endpoints.health import _fuse_stage

        db = MagicMock()
        # 800s ⇒ above warn (600) but below down (1800) → yellow.
        db.scalar = AsyncMock(return_value=800.0)
        now = datetime.now(UTC)
        stage = await _fuse_stage(
            db,
            uuid.uuid4(),
            warn_seconds=600,
            down_seconds=1800,
            window_start=now - timedelta(hours=1),
            window_end=now,
        )
        assert stage.status == "yellow"
        assert stage.p95_latency_ms == 800_000.0


class TestCorrelateStage:
    """Correlation health: backlog = single-event alerts; status by mix."""

    @pytest.mark.asyncio
    async def test_no_alerts_returns_unknown(self) -> None:
        from app.api.v1.endpoints.health import _correlate_stage

        db = MagicMock()
        # single_event=0, multi_event=0.
        db.scalar = AsyncMock(side_effect=[0, 0])
        now = datetime.now(UTC)
        stage = await _correlate_stage(
            db,
            uuid.uuid4(),
            window_start=now - timedelta(hours=1),
            window_end=now,
        )
        assert stage.stage == "correlate"
        assert stage.status == "unknown"
        assert stage.backlog == 0

    @pytest.mark.asyncio
    async def test_only_single_event_alerts_returns_yellow(self) -> None:
        # Correlation engine isn't producing multi-event alerts —
        # backlog = single-event count, status = yellow.
        from app.api.v1.endpoints.health import _correlate_stage

        db = MagicMock()
        # single_event=7, multi_event=0.
        db.scalar = AsyncMock(side_effect=[7, 0])
        now = datetime.now(UTC)
        stage = await _correlate_stage(
            db,
            uuid.uuid4(),
            window_start=now - timedelta(hours=1),
            window_end=now,
        )
        assert stage.status == "yellow"
        assert stage.backlog == 7

    @pytest.mark.asyncio
    async def test_mixed_alerts_returns_green_with_backlog(self) -> None:
        from app.api.v1.endpoints.health import _correlate_stage

        db = MagicMock()
        # 3 still-single + 2 already-correlated → green, backlog=3.
        db.scalar = AsyncMock(side_effect=[3, 2])
        now = datetime.now(UTC)
        stage = await _correlate_stage(
            db,
            uuid.uuid4(),
            window_start=now - timedelta(hours=1),
            window_end=now,
        )
        assert stage.status == "green"
        assert stage.backlog == 3


class TestAlertStage:
    """Alert queue depth + MTTD p95."""

    @pytest.mark.asyncio
    async def test_no_unacked_no_data_is_unknown(self) -> None:
        from app.api.v1.endpoints.health import _alert_stage

        db = MagicMock()
        # unacked=0, p95=None.
        db.scalar = AsyncMock(side_effect=[0, None])
        now = datetime.now(UTC)
        stage = await _alert_stage(
            db,
            uuid.uuid4(),
            warn_seconds=600,
            down_seconds=1800,
            window_start=now - timedelta(hours=1),
            window_end=now,
        )
        assert stage.stage == "alert"
        assert stage.backlog == 0
        assert stage.status == "unknown"
        assert stage.p95_latency_ms == 0.0

    @pytest.mark.asyncio
    async def test_unacked_no_p95_is_yellow(self) -> None:
        # Queue has work but nothing's been seen yet → analyst is
        # behind ⇒ yellow.
        from app.api.v1.endpoints.health import _alert_stage

        db = MagicMock()
        db.scalar = AsyncMock(side_effect=[7, None])
        now = datetime.now(UTC)
        stage = await _alert_stage(
            db,
            uuid.uuid4(),
            warn_seconds=600,
            down_seconds=1800,
            window_start=now - timedelta(hours=1),
            window_end=now,
        )
        assert stage.backlog == 7
        assert stage.status == "yellow"

    @pytest.mark.asyncio
    async def test_fast_mttd_is_green(self) -> None:
        from app.api.v1.endpoints.health import _alert_stage

        db = MagicMock()
        # 0 unacked, 45s MTTD p95.
        db.scalar = AsyncMock(side_effect=[0, 45.0])
        now = datetime.now(UTC)
        stage = await _alert_stage(
            db,
            uuid.uuid4(),
            warn_seconds=600,
            down_seconds=1800,
            window_start=now - timedelta(hours=1),
            window_end=now,
        )
        assert stage.status == "green"
        assert stage.p95_latency_ms == 45000.0
        assert stage.backlog == 0

    @pytest.mark.asyncio
    async def test_slow_mttd_is_red(self) -> None:
        from app.api.v1.endpoints.health import _alert_stage

        db = MagicMock()
        # 2 hours MTTD p95 → well above the down ceiling.
        db.scalar = AsyncMock(side_effect=[3, 7200.0])
        now = datetime.now(UTC)
        stage = await _alert_stage(
            db,
            uuid.uuid4(),
            warn_seconds=600,
            down_seconds=1800,
            window_start=now - timedelta(hours=1),
            window_end=now,
        )
        assert stage.status == "red"
        assert stage.p95_latency_ms == 7_200_000.0
        assert stage.backlog == 3


# ──────────────────────────────────────────────────────────────────────────────
# /health/pipeline — endpoint orchestration
# ──────────────────────────────────────────────────────────────────────────────


class TestGetPipelineHealth:
    """End-to-end assembly: five stages in order, worst-of overall."""

    @pytest.mark.asyncio
    async def test_returns_five_stages_in_canonical_order(self) -> None:
        from app.api.v1.endpoints.health import (
            PipelineHealth,
            PipelineStage,
            get_pipeline_health,
        )

        # Patch each stage helper so we don't have to feed a long
        # AsyncMock side_effect chain. The orchestrator's job is the
        # ordering + overall_status — that's what we lock in here.
        ingest = PipelineStage(stage="ingest", backlog=0, p95_latency_ms=0.0, error_rate=0.0, status="green")
        normalize = PipelineStage(stage="normalize", backlog=0, p95_latency_ms=10.0, error_rate=0.0, status="green")
        fuse = PipelineStage(stage="fuse", backlog=0, p95_latency_ms=20.0, error_rate=0.0, status="green")
        correlate = PipelineStage(stage="correlate", backlog=0, p95_latency_ms=0.0, error_rate=0.0, status="green")
        alert = PipelineStage(stage="alert", backlog=0, p95_latency_ms=30.0, error_rate=0.0, status="green")

        with (
            patch("app.api.v1.endpoints.health._ingest_stage", new=AsyncMock(return_value=ingest)),
            patch(
                "app.api.v1.endpoints.health._normalize_stage",
                new=AsyncMock(return_value=normalize),
            ),
            patch("app.api.v1.endpoints.health._fuse_stage", new=AsyncMock(return_value=fuse)),
            patch(
                "app.api.v1.endpoints.health._correlate_stage",
                new=AsyncMock(return_value=correlate),
            ),
            patch(
                "app.api.v1.endpoints.health._alert_stage",
                new=AsyncMock(return_value=alert),
            ),
        ):
            payload = await get_pipeline_health(user=_user(), db=MagicMock())

        assert isinstance(payload, PipelineHealth)
        assert [s.stage for s in payload.stages] == [
            "ingest",
            "normalize",
            "fuse",
            "correlate",
            "alert",
        ]
        # All green ⇒ overall green.
        assert payload.overall_status == "green"
        # ``generated_at`` should be very close to "now".
        assert (datetime.now(UTC) - payload.generated_at).total_seconds() < 5

    @pytest.mark.asyncio
    async def test_overall_is_worst_of_stages(self) -> None:
        from app.api.v1.endpoints.health import (
            PipelineStage,
            get_pipeline_health,
        )

        # 1 yellow stage among greens ⇒ overall yellow.
        green = PipelineStage(stage="x", backlog=0, p95_latency_ms=0.0, error_rate=0.0, status="green")
        yellow = PipelineStage(stage="alert", backlog=4, p95_latency_ms=900_000.0, error_rate=0.0, status="yellow")

        with (
            patch("app.api.v1.endpoints.health._ingest_stage", new=AsyncMock(return_value=green)),
            patch("app.api.v1.endpoints.health._normalize_stage", new=AsyncMock(return_value=green)),
            patch("app.api.v1.endpoints.health._fuse_stage", new=AsyncMock(return_value=green)),
            patch("app.api.v1.endpoints.health._correlate_stage", new=AsyncMock(return_value=green)),
            patch("app.api.v1.endpoints.health._alert_stage", new=AsyncMock(return_value=yellow)),
        ):
            payload = await get_pipeline_health(user=_user(), db=MagicMock())

        assert payload.overall_status == "yellow"

        # 1 red stage ⇒ overall red, no matter what the others say.
        red = PipelineStage(stage="fuse", backlog=0, p95_latency_ms=99_999_999.0, error_rate=0.0, status="red")

        with (
            patch("app.api.v1.endpoints.health._ingest_stage", new=AsyncMock(return_value=green)),
            patch("app.api.v1.endpoints.health._normalize_stage", new=AsyncMock(return_value=green)),
            patch("app.api.v1.endpoints.health._fuse_stage", new=AsyncMock(return_value=red)),
            patch("app.api.v1.endpoints.health._correlate_stage", new=AsyncMock(return_value=green)),
            patch("app.api.v1.endpoints.health._alert_stage", new=AsyncMock(return_value=yellow)),
        ):
            payload = await get_pipeline_health(user=_user(), db=MagicMock())
        assert payload.overall_status == "red"
