"""
Feed handler functions for each threat intelligence source.

Each handler is registered with the FeedScheduler and invoked on
its configured polling interval. Handlers fetch from their source,
parse/normalize the data, and hand off to ThreatIntelPipeline.

AiSOC — open-source AI Security Operations Center (MIT License)
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import TYPE_CHECKING, Any

import structlog

from app.clients.cisa_kev import CisaKevClient
from app.clients.misp import MispClient
from app.clients.opencti import OpenCtiClient
from app.clients.otx import OtxClient
from app.clients.taxii import TaxiiClient
from app.parsers.stix import StixParser

if TYPE_CHECKING:
    from app.feeds.pipeline import ThreatIntelPipeline

logger = structlog.get_logger(__name__)


# ─── Bounded ingest ───────────────────────────────────────────────────────────


_INGEST_BATCH = 1000


async def _ingest_in_batches(
    pipeline: ThreatIntelPipeline,
    iocs: Iterable[dict[str, Any]],
    *,
    source: str,
) -> tuple[int, int]:
    """Flush an IOC stream to the pipeline in bounded batches.

    ``ingest_iocs`` does per-item work — a Redis dedup round-trip and a Qdrant
    embedding — for every indicator in a call. Accumulating a whole feed into
    one list and handing it over in a single call holds the feed in memory and
    stalls the poll; a busy MISP instance or a large OpenCTI export is easily
    tens of thousands of attributes in a 24-hour window. Consuming the stream
    and flushing every ``_INGEST_BATCH`` items keeps both memory and each
    ingest call bounded. Returns ``(total_new, total_ingested)``.
    """
    buffer: list[dict[str, Any]] = []
    total_new = 0
    total = 0
    for ioc in iocs:
        buffer.append(ioc)
        if len(buffer) >= _INGEST_BATCH:
            stats = await pipeline.ingest_iocs(buffer, source=source)
            total_new += stats.get("new", 0)
            total += len(buffer)
            buffer = []
    if buffer:
        stats = await pipeline.ingest_iocs(buffer, source=source)
        total_new += stats.get("new", 0)
        total += len(buffer)
    return total_new, total


# ─── TAXII Feed Handler ───────────────────────────────────────────────────────


async def handle_taxii_feed(
    client: TaxiiClient,
    pipeline: ThreatIntelPipeline,
    api_root: str,
    collection_id: str,
) -> None:
    """
    Fetch STIX bundle from TAXII 2.1 endpoint and ingest into pipeline.
    """
    source_label = f"taxii:{collection_id[:8]}"
    logger.info("Polling TAXII feed", collection=collection_id)

    try:
        objects = await client.get_objects(api_root, collection_id)
        if not objects:
            logger.debug("TAXII feed empty", collection=collection_id)
            return

        parser = StixParser(objects)
        iocs = parser.extract_iocs()
        actors = parser.extract_actors()
        relationships = parser.extract_relationships()

        if iocs:
            stats = await pipeline.ingest_iocs(iocs, source=source_label)
            logger.info("TAXII IOCs ingested", **stats)

        if actors:
            stats = await pipeline.ingest_actors(actors, source=source_label)
            logger.info("TAXII actors ingested", **stats)

        if relationships:
            count = await pipeline.ingest_relationships(relationships, source=source_label)
            logger.info("TAXII relationships ingested", count=count)

    except Exception as exc:
        logger.error("TAXII feed handler failed", collection=collection_id, error=str(exc))


# ─── MISP Feed Handler ────────────────────────────────────────────────────────


async def handle_misp_feed(
    client: MispClient,
    pipeline: ThreatIntelPipeline,
    since_hours: int = 24,
) -> None:
    """
    Fetch recent MISP events and extract IOCs.
    """
    logger.info("Polling MISP feed", since_hours=since_hours)

    try:
        events = await client.get_recent_events(since_hours=since_hours)
        total_new, total = await _ingest_in_batches(
            pipeline,
            (ioc for event in events for ioc in client.extract_iocs(event)),
            source="misp",
        )

        if total:
            logger.info("MISP IOCs ingested", new=total_new, total=total, event_count=len(events))

    except Exception as exc:
        logger.error("MISP feed handler failed", error=str(exc))


# ─── OTX Feed Handler ─────────────────────────────────────────────────────────


_OTX_INGEST_BATCH = 1000


async def handle_otx_feed(
    client: OtxClient,
    pipeline: ThreatIntelPipeline,
) -> None:
    """
    Fetch subscribed OTX pulses and ingest their IOC indicators in bounded batches.

    A subscribed pulse can be an aggregate feed with over a million indicators;
    building one list of every pulse's IOCs and handing it to ``ingest_iocs`` in
    a single call (per-item Redis dedup + Qdrant embedding) stalled the poll and
    left every store empty. Streaming the IOCs and flushing in batches keeps both
    memory and each ingest call bounded.
    """
    logger.info("Polling OTX feed")

    try:
        pulses = await client.get_subscribed_pulses(limit=100)
        buffer: list[dict[str, Any]] = []
        total_new = 0
        total_iocs = 0
        for pulse in pulses:
            for ioc in client.iter_iocs(pulse):
                buffer.append(ioc)
                if len(buffer) >= _OTX_INGEST_BATCH:
                    stats = await pipeline.ingest_iocs(buffer, source="otx")
                    total_new += stats.get("new", 0)
                    total_iocs += len(buffer)
                    buffer = []
        if buffer:
            stats = await pipeline.ingest_iocs(buffer, source="otx")
            total_new += stats.get("new", 0)
            total_iocs += len(buffer)

        if total_iocs:
            logger.info("OTX IOCs ingested", new=total_new, total=total_iocs, pulse_count=len(pulses))

    except Exception as exc:
        logger.error("OTX feed handler failed", error=repr(exc))


# ─── CISA KEV Feed Handler ────────────────────────────────────────────────────


async def handle_cisa_kev_feed(
    client: CisaKevClient,
    pipeline: ThreatIntelPipeline,
) -> None:
    """
    Fetch CISA KEV catalog and ingest vulnerability IOCs.
    """
    logger.info("Polling CISA KEV feed")

    try:
        entries = await client.fetch()
        iocs = [client.to_ioc(e) for e in entries]

        if iocs:
            stats = await pipeline.ingest_iocs(iocs, source="cisa-kev")
            logger.info("CISA KEV IOCs ingested", **stats)

    except Exception as exc:
        logger.error("CISA KEV feed handler failed", error=str(exc))


# ─── OpenCTI Feed Handler ─────────────────────────────────────────────────────


async def handle_opencti_feed(
    client: OpenCtiClient,
    pipeline: ThreatIntelPipeline,
    since_hours: int = 24,
) -> None:
    """
    Poll an OpenCTI platform for recent Indicators and extract IOCs.
    """
    logger.info("Polling OpenCTI feed", since_hours=since_hours)

    try:
        nodes = await client.get_recent_indicators(since_hours=since_hours)
        total_new, total = await _ingest_in_batches(
            pipeline,
            (ioc for node in nodes for ioc in client.extract_iocs(node)),
            source="opencti",
        )

        if total:
            logger.info("OpenCTI IOCs ingested", new=total_new, total=total, indicator_count=len(nodes))

    except Exception as exc:
        logger.error("OpenCTI feed handler failed", error=str(exc))
