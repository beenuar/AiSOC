"""A non-promoted event must leave a thread to pull, at bounded cost.

The gap: ``promote_normalized_event`` returned ``None`` and the consumer
incremented ``_METRICS["not_promoted"]``. The aggregate reached ``/metrics``,
so an operator could see that events were being dropped — and nothing else.
Not which connector, not what shape, not why. "I connected my SIEM and no
alerts appeared" is the single most likely question a new user asks, and a
counter cannot answer it.

Two properties are asserted here, and they pull against each other, which is
the whole design problem:

* the explanation is **useful** — it names the connector, the OCSF class and
  category, the severity, and which promotion condition was not met;
* the explanation is **bounded** — this is the hot path, and on a normal
  tenant most ingested telemetry is correctly not promoted, so a line per
  event would be the highest-volume log in the platform.
"""

from __future__ import annotations

import uuid

import pytest
from app.services import promoter
from app.services.promoter import promote_normalized_event, reset_not_promoted_state

TENANT = "00000000-0000-0000-0000-000000000001"


class _CapturingLogger:
    """Records structlog-style kwargs calls without asserting on formatting."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []

    def info(self, event: str, **kw: object) -> None:
        self.calls.append((event, dict(kw)))

    def warning(self, event: str, **kw: object) -> None:  # pragma: no cover - unused
        self.calls.append((event, dict(kw)))

    def of(self, event: str) -> list[dict]:
        return [kw for name, kw in self.calls if name == event]


@pytest.fixture
def captured(monkeypatch: pytest.MonkeyPatch) -> _CapturingLogger:
    log = _CapturingLogger()
    monkeypatch.setattr(promoter, "logger", log)
    reset_not_promoted_state()
    yield log
    reset_not_promoted_state()


def _unpromotable(
    *,
    class_uid: int | None = 4001,
    severity_id: int | None = 0,
    connector_type: str = "splunk_enterprise",
) -> dict:
    """An event that fails both promotion branches."""
    ocsf: dict = {
        "class_name": "Network Activity",
        "tenant_uid": TENANT,
        "metadata": {"product": {"name": "Splunk Enterprise", "vendor_name": "Splunk"}},
        "src_endpoint": {"ip": "10.0.0.1"},
    }
    if class_uid is not None:
        ocsf["class_uid"] = class_uid
    if severity_id is not None:
        ocsf["severity_id"] = severity_id
    return {
        "id": str(uuid.uuid4()),
        "tenant_id": TENANT,
        "connector_type": connector_type,
        "ocsf_event": ocsf,
    }


class TestTheExplanationIsUseful:
    def test_names_the_connector_class_severity_and_failed_condition(self, captured):
        assert promote_normalized_event(_unpromotable()) is None

        (entry,) = captured.of("promoter.not_promoted")
        assert entry["connector_type"] == "splunk_enterprise"
        assert entry["ocsf_class_uid"] == 4001
        assert entry["ocsf_category"] == 4
        assert entry["severity_id"] == 0
        assert entry["promote_severity_floor"] == 4
        # Both branches failed, so both are named — they are different fixes:
        # a profile's classUID versus its severity map.
        assert "not 2 (Findings)" in entry["reason"]
        assert "below the promote floor" in entry["reason"]

    def test_says_severity_is_absent_rather_than_reporting_it_as_zero(self, captured):
        # The `splunk_enterprise` shape: no severity field anywhere. Reporting
        # "severity 0" invites a hunt for the rule that set it to 0; the field
        # was never populated, and that points at the connector profile.
        assert promote_normalized_event(_unpromotable(severity_id=None)) is None

        (entry,) = captured.of("promoter.not_promoted")
        assert entry["severity_id"] is None
        assert "severity_id is absent" in entry["reason"]

    def test_says_the_event_is_in_the_lake_so_nobody_hunts_for_lost_data(self, captured):
        assert promote_normalized_event(_unpromotable()) is None

        (entry,) = captured.of("promoter.not_promoted")
        assert "lake" in entry["note"]
        assert entry["event_id"]

    def test_a_promoted_event_is_not_logged_as_dropped(self, captured):
        promoted = _unpromotable(class_uid=2001)
        assert promote_normalized_event(promoted) is not None

        assert captured.of("promoter.not_promoted") == []

    def test_high_severity_telemetry_promotes_and_is_not_logged(self, captured):
        assert promote_normalized_event(_unpromotable(severity_id=4)) is not None

        assert captured.of("promoter.not_promoted") == []


class TestTheExplanationIsBounded:
    def test_one_line_per_shape_not_per_event(self, captured):
        for _ in range(500):
            promote_normalized_event(_unpromotable())

        # 500 identical events, one explanation. Without this the busiest log
        # line in the platform is the one describing routine, correct silence.
        assert len(captured.of("promoter.not_promoted")) == 1

    def test_a_second_distinct_shape_is_explained_on_its_first_event(self, captured):
        for _ in range(50):
            promote_normalized_event(_unpromotable(connector_type="splunk_enterprise"))
        for _ in range(50):
            promote_normalized_event(_unpromotable(connector_type="zeek"))

        explained = captured.of("promoter.not_promoted")
        assert {e["connector_type"] for e in explained} == {"splunk_enterprise", "zeek"}
        # Immediately, on the first event of the new shape — somebody who has
        # just connected a source is watching the log right now.
        assert len(explained) == 2

    def test_severity_and_class_are_part_of_the_shape(self, captured):
        promote_normalized_event(_unpromotable(severity_id=0))
        promote_normalized_event(_unpromotable(severity_id=3))
        promote_normalized_event(_unpromotable(class_uid=6003))

        assert len(captured.of("promoter.not_promoted")) == 3

    def test_tracked_shapes_are_capped_so_a_garbage_class_cannot_grow_them(self, captured):
        # A connector emitting a distinct class_uid per event would otherwise
        # make the sampler a memory leak and the log unbounded again.
        for i in range(promoter._MAX_TRACKED_SHAPES + 250):
            promote_normalized_event(_unpromotable(class_uid=9000 + i))

        assert len(captured.of("promoter.not_promoted")) == promoter._MAX_TRACKED_SHAPES
        assert len(promoter._sampler.pending) <= promoter._MAX_TRACKED_SHAPES

    def test_the_rollup_reports_counts_for_everything_after_the_first(self, captured, monkeypatch):
        # Drive the clock rather than sleeping: the rollup interval is 60s.
        clock = {"t": 1000.0}
        monkeypatch.setattr(promoter.time, "monotonic", lambda: clock["t"])

        for _ in range(300):
            promote_normalized_event(_unpromotable())
        assert captured.of("promoter.not_promoted_rollup") == []

        clock["t"] += promoter._ROLLUP_SECONDS + 1
        promote_normalized_event(_unpromotable())

        (rollup,) = captured.of("promoter.not_promoted_rollup")
        assert rollup["total"] == 301
        assert rollup["distinct_shapes"] == 1
        assert rollup["top"][0]["connector_type"] == "splunk_enterprise"
        assert rollup["top"][0]["count"] == 301

    def test_the_rollup_window_resets_so_counts_are_per_window(self, captured, monkeypatch):
        clock = {"t": 1000.0}
        monkeypatch.setattr(promoter.time, "monotonic", lambda: clock["t"])

        promote_normalized_event(_unpromotable())
        clock["t"] += promoter._ROLLUP_SECONDS + 1
        promote_normalized_event(_unpromotable())
        clock["t"] += promoter._ROLLUP_SECONDS + 1
        promote_normalized_event(_unpromotable())

        rollups = captured.of("promoter.not_promoted_rollup")
        assert len(rollups) == 2
        # Second window counts only what happened in it, not cumulatively.
        assert rollups[1]["total"] == 1
