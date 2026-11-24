"""The archive tier's pure halves. The engine truths live in
``tests/isolation/test_lake_archive_live.py``; this file pins what must not
drift without a container: path and window derivation, destination
validation, the estimate's cost honesty, the scratch-table namespace, the
explorer's rehydrated-table arm, and the hold-exemption SQL composers."""

from __future__ import annotations

import uuid
from datetime import UTC, date, datetime

import pytest
from app.services import lake_archive
from app.services.governance import LegalHold
from app.services.lake_sql import LakeSqlForbiddenError, rewrite_for_tenant
from app.workers.retention_purge import (
    build_alert_hold_exemption,
    build_lake_hold_exemption,
)

TENANT = uuid.UUID("aaaaaaaa-0000-0000-0000-00000000000a")


class TestPathsAndWindows:
    def test_object_path_is_deterministic_and_month_keyed(self) -> None:
        path = lake_archive.object_path(TENANT, date(2026, 9, 1))
        assert path == f"aisoc-archive/tenant={TENANT}/month=2026-09/events.parquet"

    def test_month_bounds_cover_exactly_one_month(self) -> None:
        start, end = lake_archive.month_bounds(date(2026, 12, 1))
        assert start == datetime(2026, 12, 1, tzinfo=UTC)
        assert end == datetime(2027, 1, 1, tzinfo=UTC)

    def test_months_in_range_is_inclusive(self) -> None:
        months = lake_archive.months_in_range(date(2026, 11, 15), date(2027, 1, 2))
        assert months == [date(2026, 11, 1), date(2026, 12, 1), date(2027, 1, 1)]


class TestDestinationValidation:
    def test_a_bare_hostname_is_refused(self) -> None:
        with pytest.raises(lake_archive.ArchiveConfigError, match="s3_endpoint"):
            lake_archive.validate_destination("minio:9000", "bucket")

    def test_a_bad_bucket_is_refused(self) -> None:
        with pytest.raises(lake_archive.ArchiveConfigError, match="s3_bucket"):
            lake_archive.validate_destination("http://minio:9000", "Bad_Bucket!")

    def test_a_sane_destination_passes(self) -> None:
        lake_archive.validate_destination("http://minio:9000", "tenant-archive")


class TestEstimateHonesty:
    def test_cost_is_null_without_a_configured_price(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("AISOC_ARCHIVE_RETRIEVAL_PRICE_PER_GB", raising=False)
        estimate = lake_archive.estimate_from_manifests([{"files": [{"path": "a", "sha256": "x", "bytes": 2_000_000_000}]}])
        assert estimate["bytes"] == 2_000_000_000
        assert estimate["retrieval_cost"] is None
        assert "unknown, not zero" in estimate["retrieval_cost_note"]

    def test_cost_is_computed_only_from_a_configured_price(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AISOC_ARCHIVE_RETRIEVAL_PRICE_PER_GB", "0.02")
        estimate = lake_archive.estimate_from_manifests([{"files": [{"path": "a", "sha256": "x", "bytes": 2_000_000_000}]}])
        assert estimate["retrieval_cost"] == 0.04  # type: ignore[comparison-overlap]  # dict[str, Any] by construction
        assert estimate["retrieval_cost_note"] is None


class TestScratchTableNamespace:
    def test_the_name_is_regex_pinned(self) -> None:
        rid = uuid.UUID("deadbeef-0000-0000-0000-000000000000")
        table = lake_archive.rehydrated_table_name(rid)
        assert table == "aisoc.rehydrated_deadbeef"
        assert lake_archive.REHYDRATED_TABLE_RE.match(table)

    @pytest.mark.asyncio
    async def test_drop_refuses_anything_outside_the_namespace(self) -> None:
        with pytest.raises(lake_archive.ArchiveConfigError, match="refusing to drop"):
            await lake_archive.drop_rehydration_table("aisoc.raw_events")


class TestExplorerRehydratedArm:
    def test_a_rehydrated_table_gets_the_tenant_predicate(self) -> None:
        result = rewrite_for_tenant("SELECT count() FROM aisoc.rehydrated_deadbeef", TENANT)
        assert f"tenant_id = '{TENANT}'" in result.sql

    @pytest.mark.parametrize(
        "table",
        [
            "aisoc.rehydrated_nothex",  # not hex
            "aisoc.rehydrated_deadbeefcafe",  # wrong length
            "aisoc.rehydrated_",  # empty
            "evil.rehydrated_deadbeef",  # wrong schema
        ],
    )
    def test_the_arm_cannot_widen(self, table: str) -> None:
        with pytest.raises(LakeSqlForbiddenError):
            rewrite_for_tenant(f"SELECT 1 FROM {table}", TENANT)


def _hold(kind: str, value: str, **kwargs) -> LegalHold:
    return LegalHold(id="h", subject_kind=kind, subject_value=value, **kwargs)


class TestHoldExemptionComposers:
    def test_only_narrowable_kinds_compose(self) -> None:
        sql, params = build_alert_hold_exemption([_hold("tenant", "whole")])
        assert sql == "" and params == {}

    def test_every_value_is_a_bind_never_a_literal(self) -> None:
        hostile = "x'); DROP TABLE alerts; --"
        sql, params = build_alert_hold_exemption([_hold("user", hostile)])
        assert hostile not in sql
        assert params["hold_v_0"] == hostile

    def test_windows_ride_the_exemption(self) -> None:
        start = datetime(2026, 1, 1, tzinfo=UTC)
        sql, params = build_alert_hold_exemption([_hold("user", "m", covers_from=start)])
        assert "alerts.created_at >= :hold_from_0" in sql
        assert params["hold_from_0"] == start

    def test_the_lake_ip_arm_compares_addresses_not_strings(self) -> None:
        sql, _ = build_lake_hold_exemption([_hold("ip", "10.0.0.9")])
        assert "toIPv6OrDefault" in sql, "IPv6 columns render v4 as ::ffff:...; a string compare would miss every v4 hold"

    def test_covers_respects_the_window(self) -> None:
        hold = _hold(
            "user",
            "m",
            covers_from=datetime(2026, 1, 1, tzinfo=UTC),
            covers_until=datetime(2026, 2, 1, tzinfo=UTC),
        )
        subjects = {"user": "M"}
        assert hold.covers(subjects, at=datetime(2026, 1, 15, tzinfo=UTC))
        assert not hold.covers(subjects, at=datetime(2026, 3, 1, tzinfo=UTC))
        # A caller that cannot date the record gets the over-retaining answer.
        assert hold.covers(subjects, at=None)
