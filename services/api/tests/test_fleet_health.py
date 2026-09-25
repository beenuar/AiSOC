"""Fleet health: the surface that answers "what quietly stopped working".

Every field this reads was already being written and nothing read them
together, which produces the failure this platform is least able to
tolerate — a connector stops polling, alerts from that source stop
arriving, and the console looks calm because an absence of alerts is
indistinguishable from an absence of threats.

The tests concentrate on the two judgements that make this useful rather
than noisy: staleness measured against each connector's own cadence, and
the states that must *not* be reported as failures.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import pytest
from app.services.fleet_health import (
    ERROR_THRESHOLD,
    HealthState,
    assess_connector,
    assess_fleet,
)

NOW = datetime(2026, 9, 22, 12, 0, tzinfo=UTC)


@dataclass
class Row:
    """Stands in for the Connector ORM row."""

    id: str = "c1"
    name: str = "Prod Okta"
    connector_type: str = "okta"
    is_enabled: bool = True
    last_sync: datetime | None = None
    error_count: int = 0
    events_ingested: int = 100
    oauth_refresh_failures: int = 0
    last_schema_drift_at: datetime | None = None
    connector_config: dict = field(default_factory=dict)


def ago(**kwargs) -> datetime:
    return NOW - timedelta(**kwargs)


class TestStalenessIsRelativeToCadence:
    """A global threshold either pages constantly on slow connectors or
    stays silent on fast ones."""

    def test_a_fast_connector_is_stale_after_twenty_minutes(self) -> None:
        row = Row(last_sync=ago(minutes=20), connector_config={"poll_interval_seconds": 300})
        assert assess_connector(row, now=NOW).state is HealthState.DEGRADED

    def test_a_daily_connector_is_healthy_after_twenty_minutes(self) -> None:
        row = Row(last_sync=ago(minutes=20), connector_config={"poll_interval_seconds": 86400})
        assert assess_connector(row, now=NOW).state is HealthState.HEALTHY

    def test_a_daily_connector_is_stale_after_four_days(self) -> None:
        row = Row(last_sync=ago(days=4), connector_config={"poll_interval_seconds": 86400})
        assert assess_connector(row, now=NOW).state is HealthState.DEGRADED

    def test_one_missed_poll_is_not_a_finding(self) -> None:
        """Alerting on a single missed poll produces noise that gets the
        whole surface muted."""
        row = Row(last_sync=ago(minutes=6), connector_config={"poll_interval_seconds": 300})
        assert assess_connector(row, now=NOW).state is HealthState.HEALTHY

    def test_long_enough_becomes_failed_not_degraded(self) -> None:
        row = Row(last_sync=ago(hours=2), connector_config={"poll_interval_seconds": 300})
        result = assess_connector(row, now=NOW)
        assert result.state is HealthState.FAILED
        assert "stopped arriving" in result.reason

    @pytest.mark.parametrize("interval", [0, -1, None, "", "abc"])
    def test_a_nonsense_cadence_falls_back_rather_than_dividing_by_zero(self, interval: object) -> None:
        row = Row(
            last_sync=ago(minutes=1),
            connector_config={"poll_interval_seconds": interval},
        )
        assert assess_connector(row, now=NOW).state is HealthState.HEALTHY


class TestStatesThatAreNotFailures:
    def test_never_synced_is_unproven_not_failed(self) -> None:
        """ "Something broke" and "this was never finished" are different
        operator actions."""
        result = assess_connector(Row(last_sync=None), now=NOW)
        assert result.state is HealthState.UNPROVEN
        assert "never completed a poll" in result.reason

    def test_disabled_is_not_unhealthy(self) -> None:
        """Reporting it as degraded trains people to ignore the degraded
        count, which is how a real failure gets missed."""
        row = Row(is_enabled=False, last_sync=ago(days=90))
        assert assess_connector(row, now=NOW).state is HealthState.DISABLED

    def test_a_disabled_connector_does_not_drag_down_the_fleet(self) -> None:
        fleet = assess_fleet(
            [Row(id="a", last_sync=ago(minutes=1)), Row(id="b", is_enabled=False)],
            now=NOW,
        )
        assert fleet.worst_state is HealthState.HEALTHY


class TestErrorsAndCredentials:
    def test_errors_matter_even_when_syncing_recently(self) -> None:
        """A connector erroring every poll but still "recent" is broken."""
        row = Row(last_sync=ago(minutes=1), error_count=ERROR_THRESHOLD)
        assert assess_connector(row, now=NOW).state is HealthState.DEGRADED

    def test_repeated_oauth_failure_is_terminal(self) -> None:
        """The credential is gone; no amount of waiting fixes it, so this
        outranks recency."""
        row = Row(last_sync=ago(minutes=1), oauth_refresh_failures=3)
        result = assess_connector(row, now=NOW)
        assert result.state is HealthState.FAILED
        assert "reconnect rather than wait" in result.reason

    def test_one_oauth_failure_is_not_terminal(self) -> None:
        row = Row(last_sync=ago(minutes=1), oauth_refresh_failures=1)
        assert assess_connector(row, now=NOW).state is HealthState.HEALTHY


class TestFleetRollup:
    def test_one_broken_connector_is_not_averaged_away(self) -> None:
        """Nineteen working connectors must not hide the one that stopped —
        the one that stopped is the whole question."""
        rows = [Row(id=f"ok{i}", last_sync=ago(minutes=1)) for i in range(19)]
        rows.append(Row(id="broken", last_sync=ago(days=3)))
        assert assess_fleet(rows, now=NOW).worst_state is HealthState.FAILED

    def test_worst_first_ordering(self) -> None:
        """An operator opening this wants the broken one, not an
        alphabetical list to scan."""
        rows = [
            Row(id="healthy", last_sync=ago(minutes=1)),
            Row(id="failed", last_sync=ago(days=3)),
            Row(id="unproven", last_sync=None),
            Row(id="degraded", last_sync=ago(minutes=20)),
        ]
        states = [c.state for c in assess_fleet(rows, now=NOW).connectors]
        assert states == [
            HealthState.FAILED,
            HealthState.DEGRADED,
            HealthState.UNPROVEN,
            HealthState.HEALTHY,
        ]

    def test_counts_cover_every_state(self) -> None:
        fleet = assess_fleet([Row(last_sync=ago(minutes=1))], now=NOW)
        assert set(fleet.counts) == {s.value for s in HealthState}
        assert fleet.counts["healthy"] == 1

    def test_an_empty_fleet_is_healthy_not_broken(self) -> None:
        fleet = assess_fleet([], now=NOW)
        assert fleet.worst_state is HealthState.HEALTHY

    def test_serialises(self) -> None:
        import json

        fleet = assess_fleet([Row(last_sync=ago(minutes=1))], now=NOW)
        payload = json.loads(json.dumps(fleet.to_dict()))
        assert payload["state"] == "healthy"
        assert payload["connectors"][0]["last_sync"].startswith("2026-")

    def test_a_naive_timestamp_does_not_crash(self) -> None:
        """Postgres can hand back a naive datetime depending on the column
        and driver; subtracting it from an aware one raises."""
        row = Row(last_sync=datetime(2026, 9, 22, 11, 59))
        assert assess_connector(row, now=NOW).state is HealthState.HEALTHY


class TestReasons:
    def test_every_state_explains_itself_actionably(self) -> None:
        """ "Unhealthy" tells an operator nothing they can act on."""
        rows = [
            Row(id="a", last_sync=ago(minutes=1)),
            Row(id="b", last_sync=ago(minutes=20)),
            Row(id="c", last_sync=ago(days=3)),
            Row(id="d", last_sync=None),
            Row(id="e", is_enabled=False),
        ]
        for connector in assess_fleet(rows, now=NOW).connectors:
            assert connector.reason.strip(), f"{connector.connector_id} has no reason"
            # "Unhealthy" is a restatement of the state, not a reason.
            assert "unhealthy" not in connector.reason.lower()

            if connector.state in (HealthState.HEALTHY, HealthState.DISABLED):
                continue
            # A non-healthy state has to say what is wrong in terms an
            # operator can act on — a duration, a count, or a next step.
            assert any(token in connector.reason.lower() for token in ("poll", "credential", "oauth", "error", "reconnect")), (
                f"{connector.connector_id}: {connector.reason!r} is not actionable"
            )
