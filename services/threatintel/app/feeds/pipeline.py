"""
Threat intelligence ingestion pipeline.

Handles the full lifecycle for each normalized IOC/actor batch:
  1. Bloom-filter deduplication (Redis)
  2. OpenSearch bulk index
  3. Qdrant vector upsert
  4. Neo4j graph merge
  5. Kafka event emission (optional)

AiSOC — open-source AI Security Operations Center (MIT License)
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import structlog

from app.storage.bloom import RedisBloomFilter
from app.storage.neo4j import Neo4jStore
from app.storage.opensearch import OpenSearchStore
from app.storage.qdrant import QdrantStore

logger = structlog.get_logger(__name__)


class ThreatIntelPipeline:
    """
    Central ingestion pipeline for all threat intel feeds.

    Coordinates deduplication and multi-sink storage.
    """

    def __init__(
        self,
        bloom: RedisBloomFilter,
        os_store: OpenSearchStore,
        qdrant_store: QdrantStore,
        neo4j_store: Neo4jStore,
        kafka_producer: Any | None = None,
        kafka_topic: str = "threat-intel-events",
    ) -> None:
        self._bloom = bloom
        self._os = os_store
        self._qdrant = qdrant_store
        self._neo4j = neo4j_store
        self._kafka = kafka_producer
        self._kafka_topic = kafka_topic

    async def ingest_iocs(
        self,
        iocs: list[dict[str, Any]],
        source: str,
    ) -> dict[str, Any]:
        """
        Ingest a batch of normalized IOCs.

        Returns counts for ``total`` / ``new`` / ``duplicate`` / ``indexed``,
        plus a ``sinks`` map naming what each store took. A sink reports
        ``None`` when it could not be reached, which is a different fact
        from storing nothing — see the comment at the write site.
        """
        if not iocs:
            return {"total": 0, "new": 0, "duplicate": 0}

        # --- Per-sink dedup + write to storage sinks ---
        #
        # Every sink is best-effort and independent. OpenSearch is a `full`-
        # profile store a service that now runs in CORE does not have, so its
        # write raises while Qdrant — the CORE store the console reads through —
        # succeeds. Dedup is therefore keyed *per sink* (`{sink}:{type}:{value}`)
        # and a key is recorded only *after* that sink accepts the write.
        #
        # A single global `type:value` key, added before the write, marked an
        # IOC seen for every sink the moment any one of them took it: a batch
        # that reached Qdrant on CORE was never written to OpenSearch once the
        # deployment moved to `full`, because the next poll read the whole batch
        # as duplicate and skipped it — so OpenSearch, and the search API and
        # enrichment that read it, stayed permanently behind. Per-sink keys
        # backfill a store that was unreachable at first write on the next poll
        # instead of skipping it forever. This is the backfill half of issue
        # #1278, whose reporting half fixed the misleading `indexed: 0`.
        #
        # `indexed` (kept) now means "stored in at least one sink"; `sinks`
        # carries the per-store detail, where `None` is an unreachable store,
        # not an empty one.
        writers: list[tuple[str, Any]] = [
            ("opensearch", self._os.bulk_index_iocs),
            ("qdrant", self._qdrant.upsert_iocs),
            ("neo4j", self._neo4j.upsert_iocs),
        ]

        def _key(sink: str, ioc: dict[str, Any]) -> str:
            return f"{sink}:{ioc.get('type', '?')}:{ioc.get('value', '?')}"

        sinks: dict[str, int | None] = {}
        # Keyed on the global "type:value" identity, deduped for Kafka. (The
        # comment must not start with `type:` — mypy reads that as a type
        # comment and refuses the file with a syntax error on some versions.)
        stored_iocs: dict[str, dict[str, Any]] = {}

        for name, writer in writers:
            pending = [ioc for ioc in iocs if not await self._bloom.contains(_key(name, ioc))]
            if not pending:
                sinks[name] = 0
                continue
            try:
                count = await writer(pending)
            except Exception as exc:
                # Unreachable: leave this sink's keys unset so the next poll
                # retries it rather than treating the batch as already stored.
                sinks[name] = None
                logger.warning("IOC sink write failed", sink=name, source=source, error=str(exc))
                continue
            for ioc in pending:
                await self._bloom.add(_key(name, ioc))
                stored_iocs.setdefault(f"{ioc.get('type', '?')}:{ioc.get('value', '?')}", ioc)
            # OpenSearch returns its bulk count; the others return None on success.
            sinks[name] = count if isinstance(count, int) else len(pending)

        new_count = len(stored_iocs)
        duplicates = len(iocs) - new_count
        stored = max((count for count in sinks.values() if count is not None), default=0)
        unavailable = sorted(name for name, count in sinks.items() if count is None)
        logger.info(
            "IOC batch stored",
            source=source,
            total=len(iocs),
            new=new_count,
            duplicate=duplicates,
            stored=stored,
            sinks=dict(sinks),
            unavailable=unavailable or None,
        )

        # --- Emit Kafka events ---
        if self._kafka and stored_iocs:
            await self._emit_kafka_events(list(stored_iocs.values()), event_type="NEW_IOC", source=source)

        return {
            "total": len(iocs),
            "new": new_count,
            "duplicate": duplicates,
            "indexed": stored,
            "sinks": sinks,
        }

    async def ingest_actors(
        self,
        actors: list[dict[str, Any]],
        source: str,
    ) -> dict[str, int]:
        """Ingest a batch of normalized threat actors."""
        if not actors:
            return {"total": 0, "new": 0}

        indexed = 0
        try:
            indexed = await self._os.bulk_index_actors(actors)
        except Exception as exc:
            logger.warning("OpenSearch actor index failed", error=str(exc))

        try:
            await self._qdrant.upsert_actors(actors)
        except Exception as exc:
            logger.warning("Qdrant actor upsert failed", error=str(exc))

        try:
            await self._neo4j.upsert_actors(actors)
        except Exception as exc:
            logger.warning("Neo4j actor upsert failed", error=str(exc))

        return {"total": len(actors), "indexed": indexed}

    async def ingest_relationships(
        self,
        relationships: list[dict[str, Any]],
        source: str,
    ) -> int:
        """Ingest STIX relationships into Neo4j."""
        try:
            await self._neo4j.upsert_relationships(relationships)
            return len(relationships)
        except Exception as exc:
            logger.warning("Neo4j relationship upsert failed", error=str(exc))
            return 0

    async def _emit_kafka_events(
        self,
        items: list[dict[str, Any]],
        event_type: str,
        source: str,
    ) -> None:
        """Emit Kafka messages for downstream consumers."""
        ts = datetime.now(UTC).isoformat()
        for item in items:
            payload = json.dumps(
                {
                    "event_type": event_type,
                    "source": source,
                    "timestamp": ts,
                    "data": item,
                }
            ).encode()
            try:
                await self._kafka.send(self._kafka_topic, value=payload)
            except Exception as exc:
                logger.debug("Kafka emit failed", error=str(exc))
