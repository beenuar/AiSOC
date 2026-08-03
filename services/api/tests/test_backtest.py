"""Wave 2 - detection backtesting over the lake (pure logic).

The lake-fetch path needs a live ClickHouse and is covered by the integration
gate; these tests pin the pure, deterministic pieces: bounded/allow-listed SQL
construction, row->event mapping (with JSON payload expansion), and the
would-fire count/hit-rate/sample summary.
"""

from __future__ import annotations

from app.services.backtest import (
    backtest_rule,
    build_backtest_sql,
    rows_to_events,
    sanitize_source,
)


def test_build_backtest_sql_bounds_and_source():
    sql = build_backtest_sql(window_days=30, limit=5000, source="okta_system_log")
    assert "FROM aisoc.raw_events" in sql
    assert "INTERVAL 30 DAY" in sql
    assert "connector_type = 'okta_system_log'" in sql
    assert "LIMIT 5000" in sql
    # window + limit are clamped to sane maxima
    assert "INTERVAL 365 DAY" in build_backtest_sql(window_days=9999, limit=1, source=None)
    assert "LIMIT 100000" in build_backtest_sql(window_days=1, limit=10**9, source=None)


def test_source_filter_is_injection_sanitised():
    sql = build_backtest_sql(window_days=1, limit=1, source="okta'; DROP TABLE x;--")
    assert "DROP TABLE" not in sql
    assert sanitize_source("Okta_System-Log.1") == "okta_system-log.1"
    assert sanitize_source("'; drop") == "drop"
    assert sanitize_source("!!!") is None
    assert sanitize_source(None) is None


def test_rows_to_events_zip_and_expand_payload():
    cols = ["event_id", "connector_type", "raw_data"]
    rows = [["e1", "okta", '{"user": "ceo", "action": "login"}']]
    events = rows_to_events(cols, rows)
    assert events[0]["connector_type"] == "okta"
    assert events[0]["user"] == "ceo"  # expanded from the JSON payload column
    assert events[0]["action"] == "login"


def test_backtest_rule_counts_hit_rate_and_samples():
    events = [{"msg": "malware detected"}, {"msg": "benign login"}, {"msg": "more malware here"}]
    result = backtest_rule(rule_language="regex", rule_body="malware", events=events, sample_limit=1)
    assert result["events_scanned"] == 3
    assert result["would_fire"] == 2
    assert result["hit_rate"] == round(2 / 3, 4)
    assert len(result["sample_matches"]) == 1  # capped to sample_limit
    assert result["error"] is None


def test_backtest_unsupported_language_reports_error_no_fire():
    result = backtest_rule(rule_language="esql", rule_body="x", events=[{"a": 1}])
    assert result["would_fire"] == 0
    assert result["error"] is not None


def test_backtest_empty_lake_is_zero_not_crash():
    result = backtest_rule(rule_language="regex", rule_body="anything", events=[])
    assert result["events_scanned"] == 0
    assert result["would_fire"] == 0
    assert result["hit_rate"] == 0.0
