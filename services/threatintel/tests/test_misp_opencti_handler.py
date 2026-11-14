"""A high-volume MISP or OpenCTI poll must flush IOCs to the pipeline in
bounded batches, not accumulate every event's indicators into one list and hand
the whole thing to ``ingest_iocs`` in a single call.

``ThreatIntelPipeline.ingest_iocs`` does per-item work for every indicator in a
call — a Redis dedup round-trip and a Qdrant embedding. On a busy MISP instance
(or a large OpenCTI export) a 24-hour window is easily tens of thousands of
attributes; one unbounded call holds the entire feed in memory and stalls the
poll. ``handle_otx_feed`` was already fixed for exactly this; ``handle_misp_feed``
and ``handle_opencti_feed`` shared the ``all_iocs.extend(...)`` pattern.
"""

from __future__ import annotations

from typing import Any

import pytest
from app.feeds.handlers import _INGEST_BATCH, handle_misp_feed, handle_opencti_feed


class _RecordingPipeline:
    """Records the size of each ``ingest_iocs`` call."""

    def __init__(self) -> None:
        self.batch_sizes: list[int] = []

    async def ingest_iocs(self, iocs: list[dict[str, Any]], *, source: str) -> dict[str, int]:
        self.batch_sizes.append(len(iocs))
        return {"new": len(iocs), "duplicates": 0}


class _FakeMispClient:
    def __init__(self, events: int, iocs_per_event: int) -> None:
        self._events = events
        self._per = iocs_per_event

    async def get_recent_events(self, since_hours: int = 24) -> list[dict[str, Any]]:
        return [{"id": i} for i in range(self._events)]

    def extract_iocs(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        base = event["id"] * self._per
        return [{"type": "ip-dst", "value": str(base + j)} for j in range(self._per)]


class _FakeOpenCtiClient:
    def __init__(self, nodes: int, iocs_per_node: int) -> None:
        self._nodes = nodes
        self._per = iocs_per_node

    async def get_recent_indicators(self, since_hours: int = 24) -> list[dict[str, Any]]:
        return [{"id": i} for i in range(self._nodes)]

    def extract_iocs(self, node: dict[str, Any]) -> list[dict[str, Any]]:
        base = node["id"] * self._per
        return [{"type": "domain", "value": f"n{base + j}.example"} for j in range(self._per)]


@pytest.mark.asyncio
async def test_misp_handler_flushes_in_bounded_batches() -> None:
    total = _INGEST_BATCH * 2 + 500
    client = _FakeMispClient(events=total // 5, iocs_per_event=5)
    pipeline = _RecordingPipeline()

    await handle_misp_feed(client, pipeline, since_hours=24)  # type: ignore[arg-type]

    assert pipeline.batch_sizes, "handler ingested nothing"
    assert all(n <= _INGEST_BATCH for n in pipeline.batch_sizes), f"a batch exceeded the cap of {_INGEST_BATCH}: {pipeline.batch_sizes}"
    assert len(pipeline.batch_sizes) >= 3, f"the feed was not split into multiple batches: {pipeline.batch_sizes}"
    assert sum(pipeline.batch_sizes) == total, "IOCs were lost or duplicated across batches"


@pytest.mark.asyncio
async def test_opencti_handler_flushes_in_bounded_batches() -> None:
    total = _INGEST_BATCH * 2 + 500
    client = _FakeOpenCtiClient(nodes=total // 5, iocs_per_node=5)
    pipeline = _RecordingPipeline()

    await handle_opencti_feed(client, pipeline, since_hours=24)  # type: ignore[arg-type]

    assert pipeline.batch_sizes, "handler ingested nothing"
    assert all(n <= _INGEST_BATCH for n in pipeline.batch_sizes), f"a batch exceeded the cap of {_INGEST_BATCH}: {pipeline.batch_sizes}"
    assert len(pipeline.batch_sizes) >= 3, f"the feed was not split into multiple batches: {pipeline.batch_sizes}"
    assert sum(pipeline.batch_sizes) == total, "IOCs were lost or duplicated across batches"


@pytest.mark.asyncio
async def test_empty_feeds_ingest_nothing() -> None:
    """A quiet poll must not call ingest_iocs at all (no empty-batch flush)."""
    misp_pipeline = _RecordingPipeline()
    await handle_misp_feed(_FakeMispClient(events=0, iocs_per_event=5), misp_pipeline)  # type: ignore[arg-type]
    assert misp_pipeline.batch_sizes == []

    octi_pipeline = _RecordingPipeline()
    await handle_opencti_feed(_FakeOpenCtiClient(nodes=0, iocs_per_node=5), octi_pipeline)  # type: ignore[arg-type]
    assert octi_pipeline.batch_sizes == []
