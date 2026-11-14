"""Which parts of this deployment have quietly stopped working.

Every field this needs was already being written — `last_sync`,
`error_count`, `events_ingested`, `oauth_refresh_failures`,
`last_schema_drift_at` — and nothing read them together. The result is the
failure mode this platform is least able to tolerate: a connector stops
polling, alerts stop arriving from that source, and the console looks calm
because an absence of alerts is indistinguishable from an absence of
threats.

The design decision that shapes everything here is **what counts as
stale**. A connector polling every five minutes is broken after twenty; one
polling daily is fine after twenty hours. A single global threshold would
either page constantly on slow connectors or stay silent on fast ones, so
staleness is measured in *missed poll intervals* against each connector's
own configured cadence.

Two things deliberately not inferred:

**A connector that has never synced is not stale.** It is unproven. Those
are different operator actions — one is "something broke", the other is
"this was never finished" — and collapsing them sends people to debug a
working connector that nobody completed setup for.

**A disabled connector is not unhealthy.** Reporting it as degraded trains
people to ignore the degraded count, which is how a real failure gets
missed.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any

#: Default cadence when a connector declares none. Matches the scheduler's
#: own default, so staleness is judged against what actually runs.
DEFAULT_POLL_SECONDS = 300

#: Missed intervals before a connector is called stale. Three rather than
#: one: a single missed poll is routine (a vendor rate-limit, a redeploy),
#: and alerting on it produces noise that gets the whole surface muted.
STALE_INTERVALS = 3

#: Missed intervals before it is called failed rather than degraded.
FAILED_INTERVALS = 12

#: Consecutive errors before the error count alone is enough, regardless of
#: recency. A connector erroring every poll but still "recent" is broken.
ERROR_THRESHOLD = 5


class HealthState(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    FAILED = "failed"
    #: Enabled but has never completed a poll. Not a failure — setup was
    #: never finished, which is a different action for the operator.
    UNPROVEN = "unproven"
    #: Turned off on purpose. Never counted against fleet health.
    DISABLED = "disabled"


@dataclass
class ConnectorHealth:
    connector_id: str
    name: str
    connector_type: str
    state: HealthState
    #: Why, in words an operator can act on. Never "unhealthy".
    reason: str
    last_sync: datetime | None
    seconds_since_sync: int | None
    poll_interval_seconds: int
    missed_intervals: float | None
    error_count: int
    events_ingested: int
    oauth_refresh_failures: int = 0
    schema_drift_at: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        out = asdict(self)
        out["state"] = self.state.value
        for key in ("last_sync", "schema_drift_at"):
            value = out.get(key)
            out[key] = value.isoformat() if isinstance(value, datetime) else None
        return out


@dataclass
class FleetHealth:
    generated_at: datetime
    connectors: list[ConnectorHealth] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        out = {state.value: 0 for state in HealthState}
        for connector in self.connectors:
            out[connector.state.value] += 1
        return out

    @property
    def worst_state(self) -> HealthState:
        """The fleet is as healthy as its least healthy enabled connector.

        Averaging would let nineteen working connectors hide one that
        stopped — and the one that stopped is the whole question.
        """
        for state in (HealthState.FAILED, HealthState.DEGRADED, HealthState.UNPROVEN):
            if any(c.state is state for c in self.connectors):
                return state
        return HealthState.HEALTHY

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at.isoformat(),
            "state": self.worst_state.value,
            "counts": self.counts,
            "connectors": [c.to_dict() for c in self.connectors],
        }


def _poll_interval(row: Any) -> int:
    config = getattr(row, "connector_config", None) or {}
    raw = config.get("poll_interval_seconds") if isinstance(config, dict) else None
    try:
        interval = int(raw)
    except (TypeError, ValueError):
        return DEFAULT_POLL_SECONDS
    # A zero or negative cadence would make every connector infinitely
    # stale; treat it as unset rather than as a division by zero.
    return interval if interval > 0 else DEFAULT_POLL_SECONDS


def assess_connector(row: Any, *, now: datetime | None = None) -> ConnectorHealth:
    """Judge one connector against its own configured cadence."""
    now = now or datetime.now(UTC)
    interval = _poll_interval(row)
    last_sync = getattr(row, "last_sync", None)
    error_count = int(getattr(row, "error_count", 0) or 0)
    oauth_failures = int(getattr(row, "oauth_refresh_failures", 0) or 0)

    base = {
        "connector_id": str(getattr(row, "id", "")),
        "name": getattr(row, "name", "") or "",
        "connector_type": getattr(row, "connector_type", "") or "",
        "last_sync": last_sync,
        "poll_interval_seconds": interval,
        "error_count": error_count,
        "events_ingested": int(getattr(row, "events_ingested", 0) or 0),
        "oauth_refresh_failures": oauth_failures,
        "schema_drift_at": getattr(row, "last_schema_drift_at", None),
    }

    if not getattr(row, "is_enabled", True):
        return ConnectorHealth(
            **base,
            state=HealthState.DISABLED,
            reason="Disabled. Not counted against fleet health.",
            seconds_since_sync=None,
            missed_intervals=None,
        )

    if last_sync is None:
        return ConnectorHealth(
            **base,
            state=HealthState.UNPROVEN,
            reason=(
                "Enabled but has never completed a poll. Usually a credential "
                "the vendor accepted at save time but rejects for reads — check "
                "the connectors service log for the vendor's own error."
            ),
            seconds_since_sync=None,
            missed_intervals=None,
        )

    if last_sync.tzinfo is None:
        last_sync = last_sync.replace(tzinfo=UTC)
    elapsed = max(0, int((now - last_sync).total_seconds()))
    missed = round(elapsed / interval, 1)

    # An OAuth refresh failure is terminal in a way a poll failure is not:
    # the credential is gone and no amount of waiting fixes it.
    if oauth_failures >= 3:
        return ConnectorHealth(
            **base,
            state=HealthState.FAILED,
            reason=(f"OAuth refresh has failed {oauth_failures} times. The grant was most likely revoked; reconnect rather than wait."),
            seconds_since_sync=elapsed,
            missed_intervals=missed,
        )

    if missed >= FAILED_INTERVALS:
        return ConnectorHealth(
            **base,
            state=HealthState.FAILED,
            reason=(
                f"No successful poll in {_humanise(elapsed)} ({missed:g} missed intervals). Alerts from this source have stopped arriving."
            ),
            seconds_since_sync=elapsed,
            missed_intervals=missed,
        )

    if error_count >= ERROR_THRESHOLD:
        return ConnectorHealth(
            **base,
            state=HealthState.DEGRADED,
            reason=(f"{error_count} consecutive poll errors. Syncing recently but not cleanly."),
            seconds_since_sync=elapsed,
            missed_intervals=missed,
        )

    if missed >= STALE_INTERVALS:
        return ConnectorHealth(
            **base,
            state=HealthState.DEGRADED,
            reason=(f"Last poll {_humanise(elapsed)} ago against a {_humanise(interval)} cadence ({missed:g} missed intervals)."),
            seconds_since_sync=elapsed,
            missed_intervals=missed,
        )

    return ConnectorHealth(
        **base,
        state=HealthState.HEALTHY,
        reason=f"Last poll {_humanise(elapsed)} ago.",
        seconds_since_sync=elapsed,
        missed_intervals=missed,
    )


def _humanise(seconds: int) -> str:
    delta = timedelta(seconds=seconds)
    if delta.days:
        return f"{delta.days}d"
    hours, rest = divmod(seconds, 3600)
    if hours:
        return f"{hours}h"
    minutes = rest // 60
    return f"{minutes}m" if minutes else f"{seconds}s"


def assess_fleet(rows: list[Any], *, now: datetime | None = None) -> FleetHealth:
    now = now or datetime.now(UTC)
    assessed = [assess_connector(row, now=now) for row in rows]
    # Worst first: an operator opening this wants the broken one, not an
    # alphabetical list they have to scan.
    order = {
        HealthState.FAILED: 0,
        HealthState.DEGRADED: 1,
        HealthState.UNPROVEN: 2,
        HealthState.HEALTHY: 3,
        HealthState.DISABLED: 4,
    }
    assessed.sort(key=lambda c: (order[c.state], -(c.seconds_since_sync or 0)))
    return FleetHealth(generated_at=now, connectors=assessed)
