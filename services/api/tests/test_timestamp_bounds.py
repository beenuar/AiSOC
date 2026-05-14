"""Tests for ``app.services.timestamp_bounds``.

Pins the contract that protects ``Alert.first_seen`` / ``last_seen`` /
``event_time`` from connector-supplied 1970 epochs and 2099 timestamps:

* recognised fields (``published``, ``time``, ``@timestamp``, …) parse
  correctly across string / int / float / datetime inputs;
* timestamps older than ``MIN_AGE`` clamp to the floor;
* timestamps further in the future than ``MAX_FUTURE`` clamp to the ceiling;
* timestamps inside the window pass through unchanged with ``was_clamped=False``;
* env caps clamp to hard maxima and reject junk like other AiSOC helpers.

AiSOC — open-source AI Security Operations Center (MIT License)
Author: Beenu Arora <beenu@cyble.com>
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from app.services.timestamp_bounds import (
    coerce_with_bounds,
    max_age_days,
    max_future_seconds,
)


@pytest.fixture
def fixed_now() -> datetime:
    """A fixed reference instant so tests don't race the wall clock."""
    return datetime(2026, 5, 14, 12, 0, 0, tzinfo=UTC)


# ════════════════════════════════════════════════════════════════════════════
# Section 1: timestamp parsing across input shapes
# ════════════════════════════════════════════════════════════════════════════


class TestTimestampParsing:
    """Different connectors emit timestamps in different shapes."""

    def test_parses_iso8601_string_with_offset(self, fixed_now: datetime) -> None:
        event = {"published": "2026-05-14T11:00:00+00:00"}
        ts, clamped = coerce_with_bounds(event, now=fixed_now)
        assert ts == datetime(2026, 5, 14, 11, 0, 0, tzinfo=UTC)
        assert not clamped

    def test_parses_iso8601_with_z_suffix(self, fixed_now: datetime) -> None:
        """Many connectors emit RFC 3339 with a trailing ``Z``."""
        event = {"published": "2026-05-14T11:00:00Z"}
        ts, clamped = coerce_with_bounds(event, now=fixed_now)
        assert ts == datetime(2026, 5, 14, 11, 0, 0, tzinfo=UTC)
        assert not clamped

    def test_parses_naive_iso8601_as_utc(self, fixed_now: datetime) -> None:
        """A naïve string defaults to UTC — naïve in code, UTC on the wire."""
        event = {"published": "2026-05-14T11:00:00"}
        ts, _ = coerce_with_bounds(event, now=fixed_now)
        assert ts is not None
        assert ts.tzinfo == UTC

    def test_parses_unix_seconds(self, fixed_now: datetime) -> None:
        # 2026-05-14T11:00:00Z → 1778756400
        event = {"published": 1778756400}
        ts, clamped = coerce_with_bounds(event, now=fixed_now)
        assert ts == datetime(2026, 5, 14, 11, 0, 0, tzinfo=UTC)
        assert not clamped

    def test_parses_unix_milliseconds(self, fixed_now: datetime) -> None:
        # values > 1e12 are presumed milliseconds
        event = {"published": 1778756400000}
        ts, clamped = coerce_with_bounds(event, now=fixed_now)
        assert ts == datetime(2026, 5, 14, 11, 0, 0, tzinfo=UTC)
        assert not clamped

    def test_parses_datetime_object_with_tz(self, fixed_now: datetime) -> None:
        when = datetime(2026, 5, 14, 11, 0, 0, tzinfo=UTC)
        event = {"published": when}
        ts, _ = coerce_with_bounds(event, now=fixed_now)
        assert ts == when

    def test_pins_utc_on_naive_datetime(self, fixed_now: datetime) -> None:
        """A naïve ``datetime`` gets UTC pinned on. We never silently
        treat a naïve datetime as local time — that's the timezone bug
        we're explicitly defending against."""
        when = datetime(2026, 5, 14, 11, 0, 0)
        event = {"published": when}
        ts, _ = coerce_with_bounds(event, now=fixed_now)
        assert ts is not None
        assert ts.tzinfo == UTC

    def test_falls_back_through_field_aliases(self, fixed_now: datetime) -> None:
        """Falls through ``published`` → ``time`` → ``@timestamp`` etc."""
        event = {"@timestamp": "2026-05-14T11:00:00Z"}
        ts, _ = coerce_with_bounds(event, now=fixed_now)
        assert ts == datetime(2026, 5, 14, 11, 0, 0, tzinfo=UTC)

    def test_returns_none_when_no_timestamp_field(self, fixed_now: datetime) -> None:
        event = {"actor": "alice", "event_type": "user.login"}
        ts, clamped = coerce_with_bounds(event, now=fixed_now)
        assert ts is None
        assert not clamped

    def test_returns_none_for_unparseable_string(self, fixed_now: datetime) -> None:
        event = {"published": "not a real timestamp"}
        ts, _ = coerce_with_bounds(event, now=fixed_now)
        assert ts is None

    def test_returns_none_for_empty_string(self, fixed_now: datetime) -> None:
        event = {"published": "   "}
        ts, _ = coerce_with_bounds(event, now=fixed_now)
        assert ts is None

    def test_handles_non_dict_event(self, fixed_now: datetime) -> None:
        """Defensive: non-dict input must not crash the sanitiser pipeline."""
        ts, clamped = coerce_with_bounds("not a dict", now=fixed_now)  # type: ignore[arg-type]
        assert ts is None
        assert not clamped


# ════════════════════════════════════════════════════════════════════════════
# Section 2: clamping outside the accepted window
# ════════════════════════════════════════════════════════════════════════════


class TestClamping:
    """Out-of-window timestamps clamp to the boundary and flag ``was_clamped``."""

    def test_inside_window_passes_through(self, fixed_now: datetime) -> None:
        """A recent timestamp must not be clamped."""
        recent = fixed_now - timedelta(minutes=10)
        event = {"published": recent.isoformat()}
        ts, clamped = coerce_with_bounds(event, now=fixed_now)
        assert ts == recent
        assert not clamped

    def test_ancient_timestamp_clamps_to_floor(self, fixed_now: datetime) -> None:
        """A 1970 epoch must pin to ``now - MIN_AGE`` so SLA timers stay sane."""
        ancient = datetime(1970, 1, 1, tzinfo=UTC)
        event = {"published": ancient.isoformat()}
        ts, clamped = coerce_with_bounds(
            event,
            now=fixed_now,
            max_age=timedelta(days=90),
        )
        assert clamped
        assert ts == fixed_now - timedelta(days=90)

    def test_far_future_timestamp_clamps_to_ceiling(self, fixed_now: datetime) -> None:
        """A 2099 timestamp must pin to ``now + MAX_FUTURE`` so it can't
        masquerade as the most recent activity globally."""
        future = datetime(2099, 1, 1, tzinfo=UTC)
        event = {"published": future.isoformat()}
        ts, clamped = coerce_with_bounds(
            event,
            now=fixed_now,
            max_future=timedelta(seconds=300),
        )
        assert clamped
        assert ts == fixed_now + timedelta(seconds=300)

    def test_just_past_window_clamps(self, fixed_now: datetime) -> None:
        """A timestamp 91 days back with a 90-day window must clamp."""
        too_old = fixed_now - timedelta(days=91)
        event = {"published": too_old.isoformat()}
        ts, clamped = coerce_with_bounds(
            event,
            now=fixed_now,
            max_age=timedelta(days=90),
        )
        assert clamped
        assert ts == fixed_now - timedelta(days=90)

    def test_exact_window_boundary_is_inclusive(self, fixed_now: datetime) -> None:
        """A timestamp exactly at ``now - MIN_AGE`` is accepted (not clamped)."""
        on_edge = fixed_now - timedelta(days=90)
        event = {"published": on_edge.isoformat()}
        ts, clamped = coerce_with_bounds(
            event,
            now=fixed_now,
            max_age=timedelta(days=90),
        )
        assert ts == on_edge
        assert not clamped

    def test_clock_skew_inside_max_future_is_accepted(self, fixed_now: datetime) -> None:
        """1 second of future clock skew is tolerated."""
        slightly_future = fixed_now + timedelta(seconds=1)
        event = {"published": slightly_future.isoformat()}
        ts, clamped = coerce_with_bounds(
            event,
            now=fixed_now,
            max_future=timedelta(seconds=300),
        )
        assert ts == slightly_future
        assert not clamped


# ════════════════════════════════════════════════════════════════════════════
# Section 3: env-driven caps & operator safety
# ════════════════════════════════════════════════════════════════════════════


class TestEnvCaps:
    """The env-var knobs must clamp to hard maxima and tolerate junk."""

    def test_default_max_age_is_90_days(self) -> None:
        assert max_age_days() == 90

    def test_default_max_future_is_300_seconds(self) -> None:
        assert max_future_seconds() == 300

    def test_env_override_lowers_age(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AISOC_SUBMIT_MAX_TIMESTAMP_AGE_DAYS", "30")
        assert max_age_days() == 30

    def test_env_zero_falls_back_to_default_age(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A non-positive value is silently ignored — operators sometimes
        type 0 to "disable" caps; we explicitly refuse that footgun."""
        monkeypatch.setenv("AISOC_SUBMIT_MAX_TIMESTAMP_AGE_DAYS", "0")
        assert max_age_days() == 90

    def test_env_garbage_falls_back_to_default_age(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AISOC_SUBMIT_MAX_TIMESTAMP_AGE_DAYS", "not-a-number")
        assert max_age_days() == 90

    def test_env_huge_age_clamps_to_hard_max(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """An operator typing a century mustn't disable bounds."""
        monkeypatch.setenv("AISOC_SUBMIT_MAX_TIMESTAMP_AGE_DAYS", "999999")
        assert max_age_days() == 365 * 10

    def test_env_future_clamps_to_hard_max(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AISOC_SUBMIT_MAX_FUTURE_SECONDS", "86400")
        # 1 day requested, hard cap is 1 hour.
        assert max_future_seconds() == 3600
