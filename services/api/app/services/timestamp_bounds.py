"""Bound submitted event timestamps so a misconfigured (or malicious)
connector can't poison the alerts table with timestamps from 1970 or 2099.

The ``POST /alerts/submit`` endpoint accepts arbitrary connector-supplied
timestamps under ``published`` / ``time`` / ``@timestamp`` and propagates
them to ``Alert.first_seen`` / ``last_seen`` / ``event_time``. Those
columns drive:

* SLA timers (MTTD, MTTR) — a 1970 timestamp would mark every alert as
  catastrophically overdue;
* event-time indexes (``ix_alerts_tenant_event_time``) — wildly out-of-band
  values create write hotspots and poison the index histograms;
* the investigation rail's mini-timeline — a 2099 event time renders as
  the most recent event globally and shadows real activity.

This module clamps timestamps into a sane window centred on "now":

* ``MIN_AGE``: how far in the past we accept an event (default 90 days).
  Older timestamps get pinned to the boundary and a ``bounds_clamped``
  marker is emitted in the stats so the endpoint can log it.
* ``MAX_FUTURE``: how far in the future we accept (default 5 minutes).
  This is generous enough for clock skew between a connector and the
  API server, but tight enough to prevent "schedule this alert for next
  Tuesday" abuse.

Caller contract:

* :func:`coerce_with_bounds` takes one event dict and returns
  ``(datetime | None, was_clamped: bool)``. Callers that want the raw
  timestamp (e.g. for forensics) can recover it from ``raw_event``;
  the bounded timestamp is what lands on the alert.
* :func:`now_utc` exists so tests can monkeypatch the wall clock without
  patching ``datetime.now`` globally.

Both knobs are env-driven so an operator running a historical backfill
can widen ``MIN_AGE`` without redeploying:

* ``AISOC_SUBMIT_MAX_TIMESTAMP_AGE_DAYS``  — default 90
* ``AISOC_SUBMIT_MAX_FUTURE_SECONDS``      — default 300

AiSOC — open-source AI Security Operations Center (MIT License)
Author: Beenu Arora <beenu@cyble.com>
"""

from __future__ import annotations

import logging
import os
from datetime import UTC, datetime, timedelta
from typing import Any

logger = logging.getLogger(__name__)


# ─── env-driven knobs ───────────────────────────────────────────────────────

_MAX_AGE_DAYS_ENV = "AISOC_SUBMIT_MAX_TIMESTAMP_AGE_DAYS"
_MAX_FUTURE_SECONDS_ENV = "AISOC_SUBMIT_MAX_FUTURE_SECONDS"

# Default 90 days back is wide enough to ingest a quarter of historical
# events on initial connector setup, but narrow enough to prevent the
# 1970 / epoch-zero footgun from poisoning SLA timers.
_DEFAULT_MAX_AGE_DAYS = 90

# 5 minutes of future clock skew tolerates legitimate drift between a
# connector host and the API server, but rejects "future-dated alerts"
# entirely.
_DEFAULT_MAX_FUTURE_SECONDS = 300

# Hard guardrails so an operator can't accidentally disable bounds by
# typing a huge value. 10 years is wider than any reasonable historical
# ingest; 1 hour is wider than any reasonable clock skew.
_HARD_MAX_AGE_DAYS = 365 * 10
_HARD_MAX_FUTURE_SECONDS = 3600


def _read_positive_int(env_name: str, default: int, hard_max: int) -> int:
    """Read a positive int env var with junk-tolerance + hard clamping."""
    raw = os.getenv(env_name)
    if not raw:
        return default
    try:
        value = int(raw)
    except (TypeError, ValueError):
        logger.warning(
            "timestamp_bounds: invalid %s=%r, falling back to default %d",
            env_name,
            raw,
            default,
        )
        return default
    if value <= 0:
        return default
    return min(value, hard_max)


def max_age_days() -> int:
    """Maximum age of an accepted event timestamp, in days."""
    return _read_positive_int(_MAX_AGE_DAYS_ENV, _DEFAULT_MAX_AGE_DAYS, _HARD_MAX_AGE_DAYS)


def max_future_seconds() -> int:
    """Maximum positive clock skew on an accepted event timestamp."""
    return _read_positive_int(
        _MAX_FUTURE_SECONDS_ENV,
        _DEFAULT_MAX_FUTURE_SECONDS,
        _HARD_MAX_FUTURE_SECONDS,
    )


def now_utc() -> datetime:
    """Wall clock in UTC. Indirection point so tests can freeze time."""
    return datetime.now(UTC)


# ─── timestamp parsing & coercion ───────────────────────────────────────────


_TIMESTAMP_FIELDS = ("published", "time", "@timestamp", "timestamp", "eventTime")


def _parse_one(value: Any) -> datetime | None:
    """Best-effort parse of a single timestamp candidate.

    Accepts:
    * an actual ``datetime`` (naïve datetimes get UTC pinned on);
    * an ISO-8601 string with or without timezone (we map trailing ``Z``
      to ``+00:00`` since ``fromisoformat`` rejected ``Z`` until Python 3.11);
    * an int/float treated as a Unix epoch (seconds or milliseconds —
      values > 1e12 are presumed milliseconds).
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, int | float):
        try:
            if value > 1e12:  # almost certainly milliseconds
                value = value / 1000.0
            return datetime.fromtimestamp(float(value), tz=UTC)
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        # ``fromisoformat`` doesn't accept the ``Z`` suffix prior to 3.11;
        # normalise it to be safe across runtimes.
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(s)
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed
    return None


def coerce_with_bounds(
    event: dict[str, Any],
    *,
    now: datetime | None = None,
    max_age: timedelta | None = None,
    max_future: timedelta | None = None,
) -> tuple[datetime | None, bool]:
    """Extract a timestamp from ``event`` and clamp it into the accepted window.

    Returns ``(datetime | None, was_clamped)``:

    * ``datetime`` — the bounded timestamp, or ``None`` if the event
      carries no recognisable timestamp field.
    * ``was_clamped`` — ``True`` if the timestamp was outside the window
      and got pinned to the boundary. Callers should log/emit metrics
      when this is true so operators can spot misconfigured connectors.

    The bounds are inclusive at both ends.
    """
    if not isinstance(event, dict):
        return None, False

    now_ts = now or now_utc()
    age = max_age or timedelta(days=max_age_days())
    future = max_future or timedelta(seconds=max_future_seconds())

    earliest = now_ts - age
    latest = now_ts + future

    parsed: datetime | None = None
    for field in _TIMESTAMP_FIELDS:
        candidate = _parse_one(event.get(field))
        if candidate is not None:
            parsed = candidate
            break

    if parsed is None:
        return None, False

    if parsed < earliest:
        return earliest, True
    if parsed > latest:
        return latest, True
    return parsed, False
