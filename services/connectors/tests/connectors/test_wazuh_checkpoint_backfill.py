"""A source-side outage no longer deletes its window from the lake (#1860).

The report that forced this, proven in production with canary events: a Wazuh
manager's disk filled, the indexer went read-only behind a flood-stage
watermark, and filebeat retried its bulk sends for eight hours. The connector
polled *successfully* the whole time — empty windows, fresh ``last_sync``,
zero errors — so the outage-backfill worker (keyed on the connector's own
failures) never fired. When filebeat drained, the canaries landed in the
indexer carrying their original timestamps, inside windows already polled.
``[now - since, now]`` had moved on; nothing ever requested them again.

The fix is the cursor the platform already had, finally allowed to open the
request window: the left edge advances only on rows ingest accepted, so a
successful-but-empty poll holds it in place and the window grows over the gap
instead of sliding past it. These tests drive the reported sequence end to
end against the real connector and the real checkpoint machinery, with only
the HTTP transport stubbed.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from app.connectors import wazuh
from app.connectors.wazuh import WazuhConnector

_GTE = re.compile(r"now-(\d+)s")


def _hit(doc_id: str, ts: datetime) -> dict[str, Any]:
    return {
        "_id": doc_id,
        "_source": {
            "rule": {"level": 8, "id": "100222", "description": f"canary {doc_id}"},
            "agent": {"name": "host-1", "id": "001"},
            "@timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
        },
        "sort": [int(ts.timestamp() * 1000), 1],
    }


def _connector(
    monkeypatch: pytest.MonkeyPatch,
    handler: Callable[[httpx.Request], httpx.Response],
) -> WazuhConnector:
    real_client = httpx.AsyncClient

    def factory(*args: Any, **client_kwargs: Any) -> httpx.AsyncClient:
        client_kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **client_kwargs)

    monkeypatch.setattr(wazuh.httpx, "AsyncClient", factory)
    return WazuhConnector(
        indexer_url="https://indexer.example:9200",
        username="aisoc",
        password="secret",  # noqa: S106 — test credential
        vuln_mode="alerts",
    )


def _requested_lookback(request: httpx.Request) -> int:
    body = json.loads(request.content.decode())
    gte = body["query"]["bool"]["must"][0]["range"]["@timestamp"]["gte"]
    match = _GTE.fullmatch(gte)
    assert match, f"gte is not the relative form this connector sends: {gte!r}"
    return int(match.group(1))


class TestTheWindowOpensAtTheCursor:
    @pytest.mark.asyncio
    async def test_without_a_cursor_the_window_is_the_clock_window(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """First poll ever — today's behaviour, unchanged."""
        seen: list[int] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(_requested_lookback(request))
            return httpx.Response(200, json={"hits": {"hits": []}})

        connector = _connector(monkeypatch, handler)
        connector.set_checkpoint(None)
        await connector.fetch_alerts(since_seconds=300)
        assert seen == [300]

    @pytest.mark.asyncio
    async def test_a_cursor_behind_the_clock_widens_the_request(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The core of #1860: eight hours behind means an eight-hour request."""
        eight_hours = 8 * 3600
        cursor_time = datetime.now(UTC) - timedelta(seconds=eight_hours)
        seen: list[int] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(_requested_lookback(request))
            return httpx.Response(200, json={"hits": {"hits": []}})

        connector = _connector(monkeypatch, handler)
        connector.set_checkpoint({"time": cursor_time.isoformat(), "id": "doc-A"})
        await connector.fetch_alerts(since_seconds=300)

        assert len(seen) == 1
        # Cursor age plus the clock-skew overlap, allowing a few seconds of
        # test runtime. 300 — the old answer — is the regression.
        assert eight_hours < seen[0] <= eight_hours + connector.checkpoint_overlap_seconds + 30, (
            f"requested lookback {seen[0]}s does not cover the 8h gap behind the cursor"
        )

    @pytest.mark.asyncio
    async def test_the_lookback_cap_bounds_the_request(self, monkeypatch: pytest.MonkeyPatch) -> None:
        ancient = datetime.now(UTC) - timedelta(days=30)
        seen: list[int] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(_requested_lookback(request))
            return httpx.Response(200, json={"hits": {"hits": []}})

        connector = _connector(monkeypatch, handler)
        connector.set_checkpoint({"time": ancient.isoformat(), "id": "doc-old"})
        await connector.fetch_alerts(since_seconds=300)
        assert seen == [connector.max_checkpoint_lookback_seconds]

    def test_an_unparseable_cursor_time_falls_back_to_the_clock_window(self) -> None:
        connector = WazuhConnector(
            indexer_url="https://indexer.example:9200",
            username="aisoc",
            password="secret",  # noqa: S106 — test credential
        )
        connector.set_checkpoint({"time": "not-a-timestamp", "id": "x"})
        assert connector.checkpointed_since_seconds(300) == 300


class TestTheIssue1860SequenceEndToEnd:
    """Poll through the outage exactly as reported, canaries included."""

    @pytest.mark.asyncio
    async def test_canaries_that_drain_late_are_read_on_the_next_poll(self, monkeypatch: pytest.MonkeyPatch) -> None:
        now = datetime.now(UTC)
        t0 = now - timedelta(hours=9)  # last event accepted before the outage
        canary_1 = _hit("CANARY-7F3K9Q", now - timedelta(hours=8))
        canary_2 = _hit("CANARY-2ND-WAVE-88Q", now - timedelta(hours=5))

        responses: list[list[dict[str, Any]]] = [
            [_hit("doc-A", t0)],  # poll 1 — healthy
            [],  # poll 2 — indexer behind, poll "succeeds"
            [canary_1, canary_2],  # poll 3 — filebeat drained
        ]
        requested: list[int] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requested.append(_requested_lookback(request))
            return httpx.Response(200, json={"hits": {"hits": responses[len(requested) - 1]}})

        # Poll 1: a healthy read; the scheduler persists the staged cursor
        # after ingest accepts.
        connector = _connector(monkeypatch, handler)
        connector.set_checkpoint(None)
        first = await connector.fetch_alerts(since_seconds=300)
        assert [a["alert_id"] for a in first] == ["doc-A"]
        persisted = connector.get_checkpoint()
        assert persisted and persisted["id"] == "doc-A"

        # Poll 2, during the source-side outage: the poll succeeds and returns
        # nothing. Nothing moved, so the scheduler persists nothing and the
        # cursor stays at doc-A — this is the property the clock window lacked.
        connector = _connector(monkeypatch, handler)
        connector.set_checkpoint(persisted)
        assert await connector.fetch_alerts(since_seconds=300) == []
        assert connector.get_checkpoint() is None, "an empty poll must not advance the cursor"

        # Poll 3, after filebeat drains: the window must reach back to the
        # cursor, and both canaries — original timestamps, hours inside
        # already-polled windows — must come out.
        connector = _connector(monkeypatch, handler)
        connector.set_checkpoint(persisted)
        recovered = await connector.fetch_alerts(since_seconds=300)

        assert requested[1] == 300 or requested[1] > 300  # outage poll: cursor already widened it
        assert requested[2] > 8 * 3600, (
            f"recovery poll requested only {requested[2]}s — the canaries' window was never re-opened (this is the pre-#1860 behaviour)"
        )
        assert [a["alert_id"] for a in recovered] == ["CANARY-7F3K9Q", "CANARY-2ND-WAVE-88Q"]
        advanced = connector.get_checkpoint()
        assert advanced and advanced["id"] == "CANARY-2ND-WAVE-88Q"

    @pytest.mark.asyncio
    async def test_rows_the_cursor_already_accepted_are_not_resubmitted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The overlap re-reads the cursor row; apply_checkpoint drops it."""
        now = datetime.now(UTC)
        old = _hit("doc-A", now - timedelta(hours=2))
        fresh = _hit("doc-B", now - timedelta(minutes=5))

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"hits": {"hits": [old, fresh]}})

        connector = _connector(monkeypatch, handler)
        connector.set_checkpoint({"time": old["_source"]["@timestamp"], "id": "doc-A"})
        out = await connector.fetch_alerts(since_seconds=300)
        assert [a["alert_id"] for a in out] == ["doc-B"]
