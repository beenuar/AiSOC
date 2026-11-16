"""Entity-risk wire timestamps are ISO-8601, aware or naive input (#1931).

The engine mixes two datetime provenances: ``last_seen``/``promoted_at`` come
from naive ``datetime.utcnow()``, while a contributor's ``occurred_at`` is
the alert's vendor-parsed event time, which arrives timezone-aware. The old
serialisation appended ``"Z"`` to ``isoformat()`` unconditionally, so aware
values went out as ``…+00:00Z`` — an offset *and* a Z, which is not ISO-8601
and crashed strict consumers (and non-UTC offsets would have shipped a wrong
wall-clock reading as well as a malformed one).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from uuid import uuid4

import pytest
from app.models.alert import AlertSeverity, RawAlert
from app.services.entity_risk import EntityRiskEngine, _utc_iso

from tests.test_entity_risk import _TENANT, _FakeRedis


def _parseable(ts: str) -> datetime:
    """fromisoformat with the single-Z form normalised; raises on malformed."""
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


# ────────────────────────────────────────────────────────────────────────────
# The helper itself
# ────────────────────────────────────────────────────────────────────────────


def test_naive_input_keeps_the_z_form() -> None:
    naive = datetime(2026, 11, 15, 13, 22, 10)
    assert _utc_iso(naive) == "2026-11-15T13:22:10Z"


def test_aware_utc_input_gets_a_single_z() -> None:
    aware = datetime(2026, 11, 15, 13, 22, 10, tzinfo=UTC)
    out = _utc_iso(aware)
    assert out == "2026-11-15T13:22:10Z"
    assert "+00:00" not in out
    # The exact regression: the old expression emitted offset-plus-Z.
    assert aware.isoformat() + "Z" == "2026-11-15T13:22:10+00:00Z"  # what used to ship
    assert out != aware.isoformat() + "Z"


def test_non_utc_offset_is_converted_not_just_relabelled() -> None:
    plus2 = datetime(2026, 11, 15, 15, 22, 10, tzinfo=timezone(timedelta(hours=2)))
    out = _utc_iso(plus2)
    assert out == "2026-11-15T13:22:10Z"
    assert _parseable(out) == plus2


# ────────────────────────────────────────────────────────────────────────────
# Through the real signal path
# ────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_record_wire_shape_timestamps_all_parse() -> None:
    """An alert with an aware vendor event time must serialise cleanly in
    ``last_seen``, ``promoted_at`` and every contributor ``at``."""
    engine = EntityRiskEngine(_FakeRedis())  # type: ignore[arg-type]
    alert = RawAlert(
        id=uuid4(),
        tenant_id=_TENANT,
        source="test",
        title="probe",
        severity=AlertSeverity.CRITICAL,
        username="alice",
        risk_score=1.0,
        event_time=datetime(2026, 11, 15, 13, 22, 10, tzinfo=UTC),
    )
    # Enough criticals to cross the promotion threshold so promoted_at is set.
    for _ in range(6):
        await engine.observe(alert)

    record = await engine.get(_TENANT, "user", "alice")
    assert record is not None
    wire = record.to_dict()

    assert "+00:00Z" not in wire["last_seen"]
    _parseable(wire["last_seen"])
    if wire["promoted_at"] is not None:
        assert "+00:00Z" not in wire["promoted_at"]
        _parseable(wire["promoted_at"])
    assert wire["contributors"], "expected contributing alerts on the record"
    for contributor in wire["contributors"]:
        assert "+00:00Z" not in contributor["at"], f"malformed contributor timestamp: {contributor['at']}"
        assert _parseable(contributor["at"]) == datetime(2026, 11, 15, 13, 22, 10, tzinfo=UTC)
