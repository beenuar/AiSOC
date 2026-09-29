"""The storage projection beside the LLM spend (ADR-0005 / 6b).

Two properties carry the honesty rule here and both are asserted below.

A projection is not a bill. The number comes from running the committed model
over one measurement at reference list prices, so it must arrive labelled and
must never be summed into the measured LLM spend.

An absence is not a zero. The lake runs in the ``full`` profile, so on a CORE
deployment there is no ingest volume to measure — and a confident ``$0.00``
for a tenant nobody measured reads as free storage. That is the same contract
``usage_metering.UNMEASURED`` already holds for ``events_ingested``.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest
from app.services.storage_cost import (
    COMPRESSION_RATIO,
    RATE_CARD_USD_PER_GB_MONTH,
    RETENTION_DAYS,
    StorageCostProjection,
    measure_and_project,
    not_measured,
    project,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
COMMITTED_MODEL = REPO_ROOT / "docs" / "decisions" / "storage-cost-model.json"

_BYTES_PER_TB = 1_000_000_000_000


class TestItReproducesTheCommittedModel:
    """The whole point of 6b is that the console quotes *this* model."""

    def test_one_tb_per_day_reproduces_the_committed_worked_example(self) -> None:
        committed = json.loads(COMMITTED_MODEL.read_text(encoding="utf-8"))
        # 30 days at exactly the scenario's 1 TB/day.
        result = project(_BYTES_PER_TB * 30, window_days=30, events=1)

        assert result.monthly_usd == pytest.approx(committed["total_monthly_usd"], abs=0.02)
        assert result.usd_per_raw_tb_ingested == pytest.approx(committed["usd_per_raw_tb_ingested"], abs=0.02)

    def test_each_tier_reproduces_the_committed_tier(self) -> None:
        committed = json.loads(COMMITTED_MODEL.read_text(encoding="utf-8"))
        result = project(_BYTES_PER_TB * 30, window_days=30)

        by_tier = {t.tier: t for t in result.tiers}
        assert set(by_tier) == set(committed["tiers"])
        for name, expected in committed["tiers"].items():
            got = by_tier[name]
            assert got.retention_days == expected["retention_days"]
            assert got.rate_usd_per_gb_month == expected["rate_usd_per_gb_month"]
            assert got.resident_gb == pytest.approx(expected["resident_gb"], rel=0.001)
            assert got.monthly_usd == pytest.approx(expected["monthly_usd"], abs=0.02)

    def test_the_constants_match_the_committed_rate_card(self) -> None:
        """Belt to the drift gate's braces.

        ``scripts/storage_cost_model.py --check`` parses these constants out of
        the module. This asserts the same thing from the other side, so a
        change that somehow satisfied the parser still fails here.
        """
        committed = json.loads(COMMITTED_MODEL.read_text(encoding="utf-8"))
        assert RATE_CARD_USD_PER_GB_MONTH == committed["rate_card_usd_per_gb_month"]
        assert RETENTION_DAYS == committed["scenario"]["retention_days"]
        assert COMPRESSION_RATIO == committed["scenario"]["compression_ratio"]


class TestAbsenceIsNotZero:
    def test_not_measured_carries_the_reason_and_no_money(self) -> None:
        result = not_measured("no lake on this deployment")

        assert result.measured is False
        assert result.unmeasured_reason == "no lake on this deployment"
        # Every money field must be None. A zero here is the defect.
        assert result.monthly_usd is None
        assert result.usd_per_raw_tb_ingested is None
        assert result.raw_bytes_measured is None
        assert result.tiers == []

    @pytest.mark.asyncio
    async def test_an_unconfigured_lake_reports_not_measured_rather_than_zero(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from app.db import clickhouse

        async def _refuse(*_args: object, **_kwargs: object) -> None:
            raise clickhouse.LakeQueryNotConfiguredError("CLICKHOUSE_HOST is not configured")

        monkeypatch.setattr(clickhouse, "execute_lake_query", _refuse)
        result = await measure_and_project(uuid.uuid4(), start=_t(0), end=_t(30), window_days=30)

        assert result.measured is False
        assert result.monthly_usd is None
        assert "full" in (result.unmeasured_reason or "")

    @pytest.mark.asyncio
    async def test_an_unreachable_lake_degrades_rather_than_raising(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A missing storage number must not take the whole cost page with it."""
        from app.db import clickhouse

        async def _fail(*_args: object, **_kwargs: object) -> None:
            raise clickhouse.LakeQueryError("connection refused")

        monkeypatch.setattr(clickhouse, "execute_lake_query", _fail)
        result = await measure_and_project(uuid.uuid4(), start=_t(0), end=_t(30), window_days=30)

        assert result.measured is False
        assert result.monthly_usd is None

    def test_a_tenant_that_ingested_nothing_is_measured_zero_not_unmeasured(self) -> None:
        """The distinction the `measured` flag exists to carry.

        Ingesting nothing is a fact about the tenant. Having no lake is a fact
        about the deployment. Reporting both as ``$0.00`` would lose the only
        difference that matters to someone reading the number.
        """
        result = project(0, window_days=30, events=0)

        assert result.measured is True
        assert result.monthly_usd == 0.0
        assert result.raw_bytes_measured == 0


class TestItIsLabelledAsAModel:
    def test_every_projection_carries_the_disclaimer(self) -> None:
        result = project(_BYTES_PER_TB, window_days=30)

        assert "not your provider's bill" in result.disclaimer
        assert "reference list prices" in result.disclaimer

    def test_no_field_is_named_so_it_reads_as_measured_spend(self) -> None:
        """``check_cost_provenance.py`` reconciles any field ending ``cost_usd``
        against a call count. A projection has no calls, so it deliberately
        does not use that suffix — the naming is the label."""
        fields = set(StorageCostProjection.model_fields)

        assert not any(f.endswith("cost_usd") for f in fields), fields
        assert "measured" in fields and "unmeasured_reason" in fields


class TestItIsNotSummedIntoTheLlmSpend:
    def test_the_dashboard_exposes_storage_as_a_sibling_not_a_total(self) -> None:
        from app.services.cost_dashboard import CostDashboard, CostHeadline

        assert "storage" in CostDashboard.model_fields
        # If a future edit adds storage into the headline, this fails — which
        # is the point. One number cannot be labelled two ways.
        assert not any("storage" in f for f in CostHeadline.model_fields)


def _t(day: int):
    from datetime import UTC, datetime, timedelta

    return datetime(2026, 5, 1, tzinfo=UTC) + timedelta(days=day)
