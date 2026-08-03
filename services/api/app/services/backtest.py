"""Detection backtesting over the ClickHouse event lake (Wave 2).

Runs a candidate detection rule against REAL historical events from
``aisoc.raw_events`` (tenant-scoped) so an engineer can see exactly what a rule
would have fired on over the last N days before promoting it — the gap the
audit flagged (rules could only be tested against hand-crafted fixtures).

Honesty: the lake has no ground-truth benign/malicious labels, so this reports
``would_fire`` counts + a ``hit_rate`` (fraction of scanned events that fire),
NOT a fabricated "false-positive rate". A high hit_rate over routine history is
the noise signal an author cares about.
"""

from __future__ import annotations

import json
import re
from typing import Any

from app.services.rule_engine import evaluate_rule_over_events

# Connector types are slugs; sanitise before interpolating into lake SQL.
_SOURCE_RE = re.compile(r"[^a-z0-9_.-]")


def sanitize_source(source: str | None) -> str | None:
    if not source:
        return None
    cleaned = _SOURCE_RE.sub("", source.lower())
    return cleaned or None


def build_backtest_sql(*, window_days: int, limit: int, source: str | None) -> str:
    """Bounded SELECT over the lake for the backtest window (tenant filter is
    injected later by ``lake_sql.rewrite_for_tenant``)."""
    window_days = max(1, min(int(window_days), 365))
    limit = max(1, min(int(limit), 100_000))
    clauses = [f"event_time >= now() - INTERVAL {window_days} DAY"]
    safe_source = sanitize_source(source)
    if safe_source:
        clauses.append(f"connector_type = '{safe_source}'")
    where = " AND ".join(clauses)
    return f"SELECT * FROM aisoc.raw_events WHERE {where} ORDER BY event_time DESC LIMIT {limit}"


def rows_to_events(columns: list[str], rows: list[list[Any]]) -> list[dict[str, Any]]:
    """Zip lake columns+rows into event dicts, expanding any JSON payload column
    (``raw_data`` / ``raw_event``) so rules that match connector-flat fields work."""
    events: list[dict[str, Any]] = []
    for row in rows:
        event = dict(zip(columns, row, strict=False))
        for payload_key in ("raw_data", "raw_event"):
            payload = event.get(payload_key)
            if isinstance(payload, str) and payload.strip():
                try:
                    parsed = json.loads(payload)
                    if isinstance(parsed, dict):
                        # Flat payload fields take precedence for matching, but
                        # keep the OCSF columns available too.
                        event = {**event, **parsed}
                except (ValueError, TypeError):
                    pass
            elif isinstance(payload, dict):
                event = {**event, **payload}
        events.append(event)
    return events


def backtest_rule(
    *,
    rule_language: str,
    rule_body: str,
    events: list[dict[str, Any]],
    sample_limit: int = 20,
) -> dict[str, Any]:
    """Run a rule over historical events; return an exact would-fire summary."""
    matched, error = evaluate_rule_over_events(rule_language, rule_body, events)
    scanned = len(events)
    fired = len(matched)
    return {
        "events_scanned": scanned,
        "would_fire": fired,
        "hit_rate": round(fired / scanned, 4) if scanned else 0.0,
        "sample_matches": matched[:sample_limit],
        "error": error,
    }
