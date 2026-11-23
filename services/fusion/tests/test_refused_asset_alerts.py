"""A refused AI asset observed again raises a triage alert (WS5.3).

The recorder half (the judged-score guard + `drain_refused`) is proven
against live Postgres in `test_ai_asset_recorder_live.py`; this file pins
the consumer half: each drained notice becomes one high-severity RawAlert
through the ordinary fusion path, a malformed notice is skipped rather
than wedging the sweep, and draining means a notice alerts exactly once.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from app.models.alert import AlertSeverity, RawAlert
from app.workers.consumer import FusionWorker

TENANT = str(uuid.uuid4())


class _FakeRecorder:
    def __init__(self, notices: list[dict[str, str]]) -> None:
        self._notices = notices

    def drain_refused(self) -> list[dict[str, str]]:
        out = self._notices
        self._notices = []
        return out


def _notice(**overrides: str) -> dict[str, str]:
    base = {
        "tenant_id": TENANT,
        "kind": "coding_agent",
        "external_id": "agent-7f2",
        "display_name": "Example Coder",
        "vendor": "example",
        "discovery_source": "ai-runtime",
    }
    base.update(overrides)
    return base


@pytest.mark.asyncio
async def test_each_notice_becomes_one_high_alert_citing_the_decision() -> None:
    consumer = FusionWorker.__new__(FusionWorker)
    consumer._ai_assets = _FakeRecorder([_notice()])  # type: ignore[assignment]  # duck-typed drain seam
    persisted: list[tuple[RawAlert, str | None]] = []

    async def _capture(alert: RawAlert, *, source_event_id: str | None = None, session: Any = None) -> None:
        persisted.append((alert, source_event_id))

    consumer._fuse_and_persist = _capture  # type: ignore[assignment]  # the test's capture seam
    await consumer._raise_refused_asset_alerts()

    assert len(persisted) == 1
    alert, source_event_id = persisted[0]
    assert alert.severity == AlertSeverity.HIGH
    assert alert.source == "ai_inventory"
    assert "REFUSED" in alert.description
    assert "Example Coder" in alert.title
    assert source_event_id == f"ai-refused:{TENANT}:agent-7f2"
    # The drain emptied: a second sweep alerts nothing.
    await consumer._raise_refused_asset_alerts()
    assert len(persisted) == 1


@pytest.mark.asyncio
async def test_a_malformed_notice_is_skipped_not_wedging() -> None:
    consumer = FusionWorker.__new__(FusionWorker)
    consumer._ai_assets = _FakeRecorder([_notice(tenant_id="not-a-uuid"), _notice()])  # type: ignore[assignment]  # duck-typed drain seam
    persisted: list[RawAlert] = []

    async def _capture(alert: RawAlert, *, source_event_id: str | None = None, session: Any = None) -> None:
        persisted.append(alert)

    consumer._fuse_and_persist = _capture  # type: ignore[assignment]  # the test's capture seam
    await consumer._raise_refused_asset_alerts()
    assert len(persisted) == 1, "the bad notice is logged and skipped; the good one alerts"
