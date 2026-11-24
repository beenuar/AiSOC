"""Bounded projections of linked alert metadata for forensic and report use."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

LINKED_OBSERVATIONS_HEADING = "Timeline of linked alert observations"

_MAX_OBSERVATIONS = 5
_MAX_ALERT_ROWS = 1024
_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_SOURCE = re.compile(r"[a-zA-Z0-9_.-]{1,64}")


@dataclass(frozen=True)
class AlertObservation:
    alert_id: str
    when: datetime
    severity: str
    source: str


def select_alert_observations(
    raw_alert: dict[str, Any],
) -> tuple[list[AlertObservation], int]:
    """Select oldest, newest and highest-severity unique linked observations."""
    rows = raw_alert.get("alerts")
    if not isinstance(rows, list) or len(rows) > _MAX_ALERT_ROWS:
        return [], 0

    observations: set[AlertObservation] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        identifier = row.get("id")
        stamp = row.get("event_time")
        if not isinstance(identifier, str) or len(identifier) > 64 or not isinstance(stamp, str) or len(stamp) > 64:
            continue
        try:
            alert_id = str(UUID(identifier))
            when = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
            if when.tzinfo is None:
                continue
            when = when.astimezone(UTC)
        except (ValueError, OverflowError):
            continue
        value = row.get("severity")
        severity = value.lower() if isinstance(value, str) and len(value) <= 8 else "unknown"
        severity = severity if severity in _SEVERITY_RANK else "unknown"
        value = row.get("source")
        source = value if isinstance(value, str) and _SOURCE.fullmatch(value) else "unknown"
        # Repeat observations compact without treating disagreement in
        # source metadata as interchangeable.
        observations.add(AlertObservation(alert_id, when, severity, source))

    def chronological_key(row: AlertObservation) -> tuple[datetime, str, str, str]:
        return row.when, row.alert_id, row.severity, row.source

    chronological = sorted(observations, key=chronological_key)
    if len(chronological) <= _MAX_OBSERVATIONS:
        return chronological, 0
    selected = [chronological[0], chronological[-1]]
    selected.extend(
        sorted(
            chronological[1:-1],
            key=lambda row: (-_SEVERITY_RANK.get(row.severity, -1), *chronological_key(row)),
        )[: _MAX_OBSERVATIONS - 2]
    )
    selected.sort(key=chronological_key)
    return selected, len(chronological) - len(selected)


def describe_alert_observations(
    rows: list[AlertObservation],
    omitted: int,
) -> str:
    """A bounded prompt projection without free text or raw event payloads."""
    lines = [f"{row.when.isoformat()} | {row.alert_id} | {row.source} | {row.severity}" for row in rows]
    if omitted:
        lines.append(f"{omitted} other timestamped linked alerts omitted.")
    return "\n".join(lines)


def render_alert_observations(raw_alert: dict[str, Any]) -> str:
    """Render metadata, not model-inferred events or proof of causation."""
    lines = [f"## {LINKED_OBSERVATIONS_HEADING}", ""]
    alerts = raw_alert.get("alerts")
    if isinstance(alerts, list) and len(alerts) > _MAX_ALERT_ROWS:
        return "\n".join([*lines, "Too many linked alerts to render a bounded timeline."])
    rows, omitted = select_alert_observations(raw_alert)
    if not rows:
        return "\n".join([*lines, "No usable linked alert observations were available."])
    lines.extend(
        (
            "Times are from linked alert records (UTC), not a confirmed incident chronology.",
            "",
            "| Event time (UTC) | Alert ID | Source | Severity |",
            "| --- | --- | --- | --- |",
        )
    )
    lines.extend(f"| {row.when.isoformat()} | {row.alert_id} | {row.source} | {row.severity} |" for row in rows)
    if omitted:
        lines.extend(("", f"{omitted} other timestamped linked alerts omitted."))
    return "\n".join(lines)
