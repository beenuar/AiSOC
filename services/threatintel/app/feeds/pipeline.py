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

        # --- Dedup via Bloom filter ---
        new_iocs: list[dict[str, Any]] = []
        duplicates = 0

        for ioc in iocs:
            bloom_key = f"{ioc.get('type', '?')}:{ioc.get('value', '?')}"
            if await self._bloom.contains(bloom_key):
                duplicates += 1
            else:
                await self._bloom.add(bloom_key)
                new_iocs.append(ioc)

        logger.info(
            "IOC dedup complete",
            source=source,
            total=len(iocs),
            new=len(new_iocs),
            duplicate=duplicates,
        )

        if not new_iocs:
            return {"total": len(iocs), "new": 0, "duplicate": duplicates}

        # --- Write to storage sinks ---
        #
        # Every sink is best-effort, OpenSearch included. It was the one
        # unguarded call here, which made a store that ships in the `full`
        # profile a hard requirement of a service that now runs in CORE: an
        # exception from it aborted the batch before Qdrant — the CORE store,
        # and the one the console reads through — was written at all. A feed
        # that can reach one of its sinks should write to that one.
        # `indexed` was the OpenSearch return value and nothing else, so on
        # CORE — where OpenSearch is not in the profile — a batch of 1,739
        # KEV entries that landed correctly in Qdrant reported `indexed: 0`
        # (issue #1278). A zero beside a successful write is the shape this
        # project treats as worse than a missing number: it reads as a
        # measurement, and it is the number an operator checks to decide
        # whether the feed works.
        #
        # Each sink now reports itself, and `None` means "this store was not
        # reachable" rather than "it stored nothing".
        sinks: dict[str, int | None] = {}

        try:
            sinks["opensearch"] = await self._os.bulk_index_iocs(new_iocs)
        except Exception as exc:
            sinks["opensearch"] = None
            logger.warning("OpenSearch IOC index failed", error=str(exc))

        try:
            await self._qdrant.upsert_iocs(new_iocs)
            sinks["qdrant"] = len(new_iocs)
        except Exception as exc:
            sinks["qdrant"] = None
            logger.warning("Qdrant IOC upsert failed", error=str(exc))

        try:
            await self._neo4j.upsert_iocs(new_iocs)
            sinks["neo4j"] = len(new_iocs)
        except Exception as exc:
            sinks["neo4j"] = None
            logger.warning("Neo4j IOC upsert failed", error=str(exc))

        stored = max((count for count in sinks.values() if count is not None), default=0)
        unavailable = sorted(name for name, count in sinks.items() if count is None)
        logger.info(
            "IOC batch stored",
            source=source,
            new=len(new_iocs),
            stored=stored,
            sinks=dict(sinks),
            unavailable=unavailable or None,
        )

        # --- Emit Kafka events ---
        if self._kafka:
            await self._emit_kafka_events(new_iocs, event_type="NEW_IOC", source=source)

        return {
            "total": len(iocs),
            "new": len(new_iocs),
            "duplicate": duplicates,
            # Kept, but it now means "stored in at least one sink" rather
            # than "stored in OpenSearch". `sinks` carries the detail, and a
            # `None` there is an unreachable store, not an empty one.
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
