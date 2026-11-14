"""The cold-query estimate and its honesty rules (depth 4.3).

Pure-function tests over ``app.services.lake_cold_query``. The parsing,
the warm/cold split and the "no money figure without a price" rule are
arithmetic and policy, and both are testable without a ClickHouse.

The job lifecycle — where the claim must be atomic and a terminal state
must never be left — is covered against real Postgres in
``tests/isolation/test_lake_query_jobs_live.py``, because a mocked
session answers whatever the test asked it to and would hide exactly
that.
"""

from __future__ import annotations

from typing import Any

import pytest
from app.services.lake_cold_query import (
    COLD_VOLUME_NAMES,
    RETRIEVAL_PRICE_ENV,
    ColdEstimateUnavailable,
    QueryProgress,
    ScanEstimate,
    cold_disk_names_from_policy,
    parse_explain_estimate,
    price_cold_bytes,
    split_bytes_by_volume,
    validate_query_id,
)

_GB = 1024**3


# ---------------------------------------------------------------------------
# EXPLAIN ESTIMATE
# ---------------------------------------------------------------------------


def test_the_planner_output_is_summed_by_column_name():
    columns = ["database", "table", "parts", "rows", "marks"]
    rows = [["aisoc", "raw_events", 12, 4_000_000, 500]]
    total_rows, parts, tables = parse_explain_estimate(columns, rows)
    assert (total_rows, parts, tables) == (4_000_000, 12, ["raw_events"])


def test_a_reordered_column_set_is_read_by_name_not_position():
    # parts and rows are both plausible integers, so a silent reorder
    # would swap them and nobody would notice until an estimate said a
    # 4-million-row scan touched 12 rows.
    columns = ["database", "table", "rows", "parts", "marks"]
    rows = [["aisoc", "raw_events", 4_000_000, 12, 500]]
    total_rows, parts, _ = parse_explain_estimate(columns, rows)
    assert total_rows == 4_000_000
    assert parts == 12


def test_several_tables_are_summed_and_listed_once():
    columns = ["database", "table", "parts", "rows", "marks"]
    rows = [
        ["aisoc", "raw_events", 4, 100, 1],
        ["aisoc", "raw_events", 2, 50, 1],
        ["aisoc", "alerts_archive", 1, 25, 1],
    ]
    total_rows, parts, tables = parse_explain_estimate(columns, rows)
    assert (total_rows, parts) == (175, 7)
    assert tables == ["raw_events", "alerts_archive"]


def test_an_unreadable_column_set_raises_rather_than_returning_zero():
    # Zero and "could not estimate" are opposite answers, and returning
    # the first for the second waves a 400-day cold scan through as free.
    with pytest.raises(ColdEstimateUnavailable):
        parse_explain_estimate(["something", "unexpected"], [["a", "b"]])


def test_no_rows_is_an_empty_estimate_not_a_failure():
    assert parse_explain_estimate(["database", "table", "parts", "rows", "marks"], []) == (0, 0, [])


# ---------------------------------------------------------------------------
# Where the data lives
# ---------------------------------------------------------------------------


def test_cold_disks_are_read_from_the_servers_storage_policy():
    # The volume is named in a mounted XML file an operator owns, so the
    # disk names cannot be hardcoded here.
    disks = cold_disk_names_from_policy([["hot", ["nvme0"]], ["cold", ["s3_disk", "s3_backup"]]])
    assert disks == frozenset({"s3_disk", "s3_backup"})


def test_a_deployment_with_no_cold_volume_has_no_cold_disks():
    assert cold_disk_names_from_policy([["hot", ["nvme0"]]]) == frozenset()


def test_bytes_are_split_by_the_disk_the_part_is_on():
    cold, warm = split_bytes_by_volume(
        [["nvme0", 1_000], ["s3_disk", 9_000]],
        cold_disk_names=frozenset({"s3_disk"}),
    )
    assert (cold, warm) == (9_000, 1_000)


def test_an_unrecognised_disk_counts_as_warm():
    # Deliberate direction. Over-reporting cold would route ordinary
    # queries into the job path and make the feature feel broken;
    # under-reporting sends a cold query down the synchronous path where
    # it fails the way it always did — no worse than before, and visible.
    cold, warm = split_bytes_by_volume([["some_new_disk", 5_000]], cold_disk_names=frozenset({"s3_disk"}))
    assert (cold, warm) == (0, 5_000)


def test_the_fallback_volume_name_matches_the_tiering_migration():
    # services/api/clickhouse/tiering/002_tiering.sql moves to VOLUME 'cold'.
    assert "cold" in COLD_VOLUME_NAMES


# ---------------------------------------------------------------------------
# Money. The rule this repository cares about most.
# ---------------------------------------------------------------------------


def test_no_configured_price_means_no_figure_and_a_reason(monkeypatch):
    monkeypatch.delenv(RETRIEVAL_PRICE_ENV, raising=False)
    usd, basis = price_cold_bytes(10 * _GB)
    assert usd is None, "a figure was produced with no price configured"
    assert "storage rate card" in basis
    assert RETRIEVAL_PRICE_ENV in basis


def test_a_configured_price_produces_a_figure_derived_from_it(monkeypatch):
    monkeypatch.setenv(RETRIEVAL_PRICE_ENV, "0.01")
    usd, basis = price_cold_bytes(10 * _GB)
    assert usd == pytest.approx(0.10)
    assert "0.01" in basis


def test_a_nonsense_price_is_refused_rather_than_coerced(monkeypatch):
    for bad in ("free", "-1"):
        monkeypatch.setenv(RETRIEVAL_PRICE_ENV, bad)
        usd, _ = price_cold_bytes(10 * _GB)
        assert usd is None, f"{bad!r} produced a figure"


def test_zero_cold_bytes_with_a_price_is_zero_not_none(monkeypatch):
    # The distinction the whole design rests on: None means "we do not
    # know what this costs", 0.0 means "this costs nothing".
    monkeypatch.setenv(RETRIEVAL_PRICE_ENV, "0.01")
    usd, _ = price_cold_bytes(0)
    assert usd == 0.0


# ---------------------------------------------------------------------------
# The estimate object
# ---------------------------------------------------------------------------


def _estimate(**overrides) -> ScanEstimate:
    base: dict[str, Any] = {
        "estimated_rows": 1_000,
        "estimated_parts": 3,
        "estimated_bytes": 2_000,
        "cold_bytes": 0,
        "warm_bytes": 2_000,
        "tables": ["raw_events"],
    }
    base.update(overrides)
    return ScanEstimate(**base)


def test_touches_cold_is_what_routes_a_query_to_a_job():
    assert _estimate(cold_bytes=0).touches_cold is False
    assert _estimate(cold_bytes=1).touches_cold is True


def test_the_serialised_estimate_carries_the_routing_field():
    payload = _estimate(cold_bytes=5).as_dict()
    assert payload["touches_cold"] is True
    assert payload["cold_bytes"] == 5
    assert "estimated_usd" in payload


# ---------------------------------------------------------------------------
# Progress
# ---------------------------------------------------------------------------


def test_progress_with_no_denominator_is_unknown_rather_than_complete():
    # ClickHouse publishes total_rows_approx best-effort. A bar that
    # invents 100% because the denominator was zero is worse than one
    # that says it does not know.
    assert QueryProgress(rows_read=500, bytes_read=1, total_rows_approx=0, elapsed_seconds=1.0).ratio is None


def test_progress_is_clamped_when_the_estimate_is_overtaken():
    # total_rows_approx moves while a query runs and can end up below
    # rows_read, which would otherwise render as 140%.
    progress = QueryProgress(rows_read=1_400, bytes_read=1, total_rows_approx=1_000, elapsed_seconds=1.0)
    assert progress.ratio == 1.0


def test_progress_serialises_the_unknown_ratio_as_null():
    payload = QueryProgress(rows_read=1, bytes_read=1, total_rows_approx=0, elapsed_seconds=0.5).as_dict()
    assert payload["ratio"] is None


@pytest.mark.parametrize(
    "bad",
    ["", "a b", "a;DROP", "x" * 65, "../etc", "id'quote"],
)
def test_a_query_id_outside_the_safe_alphabet_is_refused(bad):
    with pytest.raises(ValueError):
        validate_query_id(bad)


def test_a_derived_query_id_is_accepted():
    assert validate_query_id("aisoc-lake-11111111-1111-1111-1111-111111111111")
