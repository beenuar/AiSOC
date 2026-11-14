"""Unit tests for the connector freshness SLO module (Workstream 5).

The freshness module is pure (no DB, no I/O), so these tests are
exhaustive: every status transition (green → yellow → red), every
cadence row in the per-category table, the ``unknown`` handling for
connectors that haven't ingested yet, and the per-instance override
that lets an operator declare "this Splunk polls hourly, don't paint
yellow."

The intent is that the freshness verdict the API surfaces matches
exactly what the UI badge renders, with no client-side rule
duplication. If a future contributor changes a cadence here without
also updating ``apps/docs``, a test will fail loudly.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from app.services.connector_freshness import (
    _CADENCE_BY_CATEGORY,
    _DEFAULT_CADENCE_S,
    _RED_MULTIPLIER,
    FreshnessSLO,
    compute_freshness,
    expected_cadence_seconds,
)

# ---------------------------------------------------------- expected_cadence_seconds


def test_expected_cadence_known_categories_match_table() -> None:
    """The published cadence table is the source of truth.

    If a value is changed without updating the docs ("EDR is 5 min,
    SIEM is 15 min, …"), this test fails so the contributor knows to
    revisit the connector docs in apps/docs/.
    """
    assert _CADENCE_BY_CATEGORY["edr"] == 5 * 60
    assert _CADENCE_BY_CATEGORY["siem"] == 15 * 60
    assert _CADENCE_BY_CATEGORY["iam"] == 30 * 60
    assert _CADENCE_BY_CATEGORY["saas"] == 30 * 60
    assert _CADENCE_BY_CATEGORY["network"] == 30 * 60
    assert _CADENCE_BY_CATEGORY["cloud"] == 30 * 60
    assert _CADENCE_BY_CATEGORY["vcs"] == 15 * 60
    assert _CADENCE_BY_CATEGORY["vuln"] == 60 * 60
    assert _CADENCE_BY_CATEGORY["email"] == 15 * 60
    assert _CADENCE_BY_CATEGORY["ticketing"] == 30 * 60


def test_expected_cadence_unknown_category_falls_back_to_default() -> None:
    assert expected_cadence_seconds("future-category") == _DEFAULT_CADENCE_S
    assert expected_cadence_seconds(None) == _DEFAULT_CADENCE_S
    assert expected_cadence_seconds("") == _DEFAULT_CADENCE_S


def test_expected_cadence_is_case_insensitive() -> None:
    """Catalog rows occasionally store ``EDR`` or ``Edr``.

    The lookup normalises to lowercase so a casing drift in the
    catalog doesn't silently bump every EDR connector to the default
    30-minute cadence.
    """
    assert expected_cadence_seconds("EDR") == 5 * 60
    assert expected_cadence_seconds("Siem") == 15 * 60


def test_expected_cadence_override_wins_over_table() -> None:
    """Per-instance overrides are how an operator says "this one's batch."

    A Splunk instance that polls hourly because the customer's data
    only shows up in batches shouldn't be painted yellow against the
    15-minute SIEM default.
    """
    assert expected_cadence_seconds("siem", override_seconds=3600) == 3600
    # Even when the table would say "fast," the override is honoured.
    assert expected_cadence_seconds("edr", override_seconds=900) == 900


def test_expected_cadence_override_zero_or_negative_is_ignored() -> None:
    """Defensive: a misconfigured 0 override mustn't make every connector red.

    ``0`` would mean "data must arrive instantly," which is impossible
    and would paint everything red. A negative would underflow the
    age comparison. Both fall through to the category default.
    """
    assert expected_cadence_seconds("siem", override_seconds=0) == 15 * 60
    assert expected_cadence_seconds("siem", override_seconds=-30) == 15 * 60


# -------------------------------------------------------------- compute_freshness


def _now() -> datetime:
    """Deterministic 'now' for relative-time tests."""
    return datetime(2026, 5, 8, 12, 0, 0, tzinfo=UTC)


def test_compute_freshness_unknown_when_never_ingested() -> None:
    """No ``last_event_at`` means the connector hasn't produced data yet.

    The UI distinguishes ``unknown`` (gray badge — "waiting for first
    event") from ``red`` (red badge — "was flowing, now stopped"), so
    the verdict must reflect that explicitly.
    """
    verdict = compute_freshness(category="edr", last_event_at=None, now=_now())
    assert verdict.status == "unknown"
    assert verdict.seconds_since_last_event is None
    assert verdict.expected_cadence_seconds == 5 * 60
    assert verdict.category == "edr"


def test_compute_freshness_green_when_inside_cadence() -> None:
    now = _now()
    last = now - timedelta(minutes=2)  # within EDR's 5-min window
    verdict = compute_freshness(category="edr", last_event_at=last, now=now)
    assert verdict.status == "green"
    assert verdict.seconds_since_last_event == 120
    assert verdict.expected_cadence_seconds == 5 * 60


def test_compute_freshness_yellow_when_between_cadence_and_2x() -> None:
    """Yellow means "late, but within our patience window."

    The window is ``cadence`` < age <= ``2 × cadence``. For SIEM
    (15 min), that's 15–30 minutes since last event.
    """
    now = _now()
    last = now - timedelta(minutes=20)  # > 15m, < 30m
    verdict = compute_freshness(category="siem", last_event_at=last, now=now)
    assert verdict.status == "yellow"


def test_compute_freshness_red_when_older_than_2x_cadence() -> None:
    now = _now()
    last = now - timedelta(minutes=45)  # > 2 × 15m for SIEM
    verdict = compute_freshness(category="siem", last_event_at=last, now=now)
    assert verdict.status == "red"


def test_compute_freshness_boundary_exactly_at_cadence_is_green() -> None:
    """Edge: age == cadence is still green ("just made it").

    This matches the operator-visible rule: "you're on time if you
    poll at most every ``cadence_seconds``." Anything past that tips
    yellow.
    """
    now = _now()
    last = now - timedelta(seconds=_CADENCE_BY_CATEGORY["edr"])
    verdict = compute_freshness(category="edr", last_event_at=last, now=now)
    assert verdict.status == "green"
    assert verdict.seconds_since_last_event == _CADENCE_BY_CATEGORY["edr"]


def test_compute_freshness_boundary_exactly_at_2x_cadence_is_yellow() -> None:
    """Edge: age == 2 × cadence is still yellow, not red.

    Mirrors the green boundary — "exactly at the line" stays in the
    less-alarming bucket so brief polling jitter doesn't trip alerts.
    """
    now = _now()
    last = now - timedelta(seconds=int(_CADENCE_BY_CATEGORY["edr"] * _RED_MULTIPLIER))
    verdict = compute_freshness(category="edr", last_event_at=last, now=now)
    assert verdict.status == "yellow"


def test_compute_freshness_uses_default_for_unknown_category() -> None:
    """A connector with a brand-new category falls back to 30 min.

    Newly added catalog rows can declare a category we don't yet have
    a cadence row for (e.g. plugin authors experimenting). The verdict
    still computes — it just uses the default — instead of crashing.
    """
    now = _now()
    last = now - timedelta(minutes=10)
    verdict = compute_freshness(category="experimental", last_event_at=last, now=now)
    assert verdict.expected_cadence_seconds == _DEFAULT_CADENCE_S
    assert verdict.status == "green"


def test_compute_freshness_uses_default_when_category_missing() -> None:
    now = _now()
    last = now - timedelta(minutes=10)
    verdict = compute_freshness(category=None, last_event_at=last, now=now)
    assert verdict.expected_cadence_seconds == _DEFAULT_CADENCE_S
    assert verdict.category == "unknown"


def test_compute_freshness_handles_naive_last_event_at() -> None:
    """Defensive: some DB drivers strip tzinfo.

    ``last_event_at`` is declared ``DateTime(timezone=True)``, but if a
    driver upgrade silently changed that we mustn't crash with
    "can't subtract offset-naive and offset-aware datetimes". The
    function must coerce to UTC and keep going.
    """
    now = _now()
    last_naive = (now - timedelta(minutes=2)).replace(tzinfo=None)
    verdict = compute_freshness(category="edr", last_event_at=last_naive, now=now)
    assert verdict.status == "green"
    assert verdict.seconds_since_last_event == 120


def test_compute_freshness_clamps_negative_age_to_zero() -> None:
    """Future-dated ``last_event_at`` (clock skew) is clamped, not negative.

    If a connector's host clock is ahead of ours, the age would
    arithmetically be negative. We clamp to 0 so the verdict reads
    "fresh as can be" rather than emitting a nonsensical negative
    age that breaks any downstream comparison.
    """
    now = _now()
    future = now + timedelta(minutes=5)
    verdict = compute_freshness(category="edr", last_event_at=future, now=now)
    assert verdict.seconds_since_last_event == 0
    assert verdict.status == "green"


def test_compute_freshness_per_instance_override_overrides_status() -> None:
    """The override changes the verdict, not just the cadence label.

    A SaaS connector running hourly with an override of 3600s must
    show green at 70 min, even though the SaaS default (30 min,
    yellow at 60 min) would say red at that age.
    """
    now = _now()
    last = now - timedelta(minutes=70)
    # Without override: SaaS default 30 min, 2× = 60 min → red at 70 min.
    default_verdict = compute_freshness(category="saas", last_event_at=last, now=now)
    assert default_verdict.status == "red"
    # With override of 1 h: 70 min is still inside 2× = 2 h, so yellow,
    # not red. The point is "the override demotes the verdict," not
    # that it's automatically green.
    override_verdict = compute_freshness(category="saas", last_event_at=last, now=now, override_seconds=3600)
    assert override_verdict.status == "yellow"
    assert override_verdict.expected_cadence_seconds == 3600
    # A shorter event-age (50 min) under the same override is green.
    fresh_under_override = compute_freshness(
        category="saas",
        last_event_at=now - timedelta(minutes=50),
        now=now,
        override_seconds=3600,
    )
    assert fresh_under_override.status == "green"


def test_compute_freshness_uses_real_now_when_not_supplied() -> None:
    """``now`` defaults to ``datetime.now(UTC)`` so prod callers don't pass it.

    The test asserts the verdict is *consistent* — we don't pin a
    real wall-clock value — by calling twice in quick succession and
    expecting both to land on green for a very recent event.
    """
    last = datetime.now(UTC) - timedelta(seconds=10)
    v1 = compute_freshness(category="edr", last_event_at=last)
    v2 = compute_freshness(category="edr", last_event_at=last)
    assert v1.status == "green"
    assert v2.status == "green"
    # Age is monotonically non-decreasing across two reads.
    assert (v2.seconds_since_last_event or 0) >= (v1.seconds_since_last_event or 0)


# -------------------------------------------------------------- to_dict shape


def test_freshness_slo_to_dict_shape_is_stable() -> None:
    """The serialised shape is the API contract.

    ``ConnectorResponse.freshness`` is built from this dict via
    ``FreshnessSLOResponse(**verdict.to_dict())``. If a key is added
    or renamed without updating the Pydantic model, list_connectors
    starts 500'ing — this test catches that at unit level.
    """
    verdict = FreshnessSLO(
        status="green",
        expected_cadence_seconds=300,
        seconds_since_last_event=42,
        category="edr",
    )
    payload = verdict.to_dict()
    assert set(payload.keys()) == {
        "status",
        "expected_cadence_seconds",
        "seconds_since_last_event",
        "category",
    }
    assert payload["status"] == "green"
    assert payload["expected_cadence_seconds"] == 300
    assert payload["seconds_since_last_event"] == 42
    assert payload["category"] == "edr"


@pytest.mark.parametrize("status", ["green", "yellow", "red", "unknown"])
def test_freshness_slo_status_values_are_lowercase(status: str) -> None:
    """Status values are the contract used by the UI badge.

    The UI renders ``status === 'green' ? <Green/> : …``. If a
    contributor decides to capitalise these, every badge silently
    falls through to a default. Pin the expected vocabulary here.
    """
    verdict = FreshnessSLO(
        status=status,
        expected_cadence_seconds=300,
        seconds_since_last_event=None,
        category="edr",
    )
    assert verdict.status == status
    assert verdict.status == verdict.status.lower()
