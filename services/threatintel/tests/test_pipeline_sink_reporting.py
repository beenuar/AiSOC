"""A batch that landed somewhere does not report zero (issue #1278).

`ingest_iocs` returned `indexed`, which was the OpenSearch bulk-index
count and nothing else. OpenSearch is a `full`-profile store and
`threatintel` now runs in CORE, so on a stock install the call raises,
`indexed` keeps its `0` initialiser, and the Qdrant write on the very next
line succeeds — producing `indexed: 0` in the logs for a batch of ~1,700
CISA KEV entries that stored correctly.

That is the number an operator checks to decide whether the feed works,
and a zero beside a successful write reads as a measurement rather than
as a missing one. It was the single most misleading signal in the report:
`/threat-intel/feeds` and `/iocs` returning `[]` is correct behaviour for
two tenant-owned stores nobody has written to, but `indexed: 0` beside
them made the whole thing look like a broken feed.
"""

from __future__ import annotations

from typing import Any

import pytest
from app.feeds.pipeline import ThreatIntelPipeline

IOCS = [{"type": "vulnerability", "value": f"CVE-2026-{n:04d}"} for n in range(3)]


class _Bloom:
    def __init__(self) -> None:
        self._seen: set[str] = set()

    async def contains(self, key: str) -> bool:
        return key in self._seen

    async def add(self, key: str) -> None:
        self._seen.add(key)


class _Sink:
    """A store that either works or is absent. `absent` raises the way an
    unreachable host does, which is the condition CORE is actually in."""

    def __init__(self, *, absent: bool = False) -> None:
        self.absent = absent

    async def bulk_index_iocs(self, iocs: list[dict[str, Any]]) -> int:
        if self.absent:
            raise ConnectionError("opensearch: name or service not known")
        return len(iocs)

    async def upsert_iocs(self, iocs: list[dict[str, Any]], **_kw: Any) -> None:
        if self.absent:
            raise ConnectionError("store unreachable")


def _pipeline(*, opensearch: bool, qdrant: bool, neo4j: bool) -> ThreatIntelPipeline:
    # The stores are substituted by duck type rather than by subclass: the
    # real ones each own a live client, and the property under test is which
    # store answered, not what any of them does internally.
    return ThreatIntelPipeline(
        bloom=_Bloom(),  # type: ignore[arg-type]
        os_store=_Sink(absent=not opensearch),  # type: ignore[arg-type]
        qdrant_store=_Sink(absent=not qdrant),  # type: ignore[arg-type]
        neo4j_store=_Sink(absent=not neo4j),  # type: ignore[arg-type]
        kafka_producer=None,
        kafka_topic="t",
    )


class TestTheCoreProfileReportsWhatItStored:
    @pytest.mark.asyncio
    async def test_a_core_install_does_not_report_zero_for_a_stored_batch(self) -> None:
        """CORE exactly: OpenSearch and Neo4j are `full`-profile and absent,
        Qdrant is present and is what `/indicators` reads."""
        stats = await _pipeline(opensearch=False, qdrant=True, neo4j=False).ingest_iocs(IOCS, source="cisa-kev")

        assert stats["new"] == 3
        assert stats["indexed"] == 3, "a batch that landed in the CORE store reported zero"

    @pytest.mark.asyncio
    async def test_an_unreachable_store_is_none_not_zero(self) -> None:
        """The distinction the whole issue turns on: `0` is a count, `None`
        is 'nobody counted'."""
        stats = await _pipeline(opensearch=False, qdrant=True, neo4j=False).ingest_iocs(IOCS, source="cisa-kev")

        assert stats["sinks"]["opensearch"] is None
        assert stats["sinks"]["neo4j"] is None
        assert stats["sinks"]["qdrant"] == 3

    @pytest.mark.asyncio
    async def test_a_batch_that_landed_nowhere_really_does_report_zero(self) -> None:
        """The control. The fix must not make every batch look successful."""
        stats = await _pipeline(opensearch=False, qdrant=False, neo4j=False).ingest_iocs(IOCS, source="cisa-kev")

        assert stats["indexed"] == 0
        assert set(stats["sinks"].values()) == {None}

    @pytest.mark.asyncio
    async def test_the_full_profile_still_reports_every_sink(self) -> None:
        stats = await _pipeline(opensearch=True, qdrant=True, neo4j=True).ingest_iocs(IOCS, source="cisa-kev")

        assert stats["indexed"] == 3
        assert stats["sinks"] == {"opensearch": 3, "qdrant": 3, "neo4j": 3}

    @pytest.mark.asyncio
    async def test_duplicates_are_still_counted_and_not_restored(self) -> None:
        """The dedup half is untouched; a second pass stores nothing because
        there is nothing new, which is a real zero."""
        pipeline = _pipeline(opensearch=False, qdrant=True, neo4j=False)
        await pipeline.ingest_iocs(IOCS, source="cisa-kev")
        second = await pipeline.ingest_iocs(IOCS, source="cisa-kev")

        assert second["new"] == 0
        assert second["duplicate"] == 3
        assert "indexed" not in second or second.get("indexed", 0) == 0

    @pytest.mark.asyncio
    async def test_an_empty_batch_is_not_an_error(self) -> None:
        stats = await _pipeline(opensearch=True, qdrant=True, neo4j=True).ingest_iocs([], source="cisa-kev")
        assert stats["total"] == 0
