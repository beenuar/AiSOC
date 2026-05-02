"""
Feed handler functions for each threat intelligence source.

Each handler is registered with the FeedScheduler and invoked on
its configured polling interval. Handlers fetch from their source,
parse/normalize the data, and hand off to ThreatIntelPipeline.

Cyble Open-Source AI Security Operations Center — MIT License
"""
from __future__ import annotations

import structlog
from typing import TYPE_CHECKING, Any

from app.clients.taxii import TaxiiClient
from app.clients.misp import MispClient
from app.clients.otx import OtxClient
from app.clients.cisa_kev import CisaKevClient
from app.parsers.stix import StixParser

if TYPE_CHECKING:
    from app.feeds.pipeline import ThreatIntelPipeline
    from app.config import Settings

logger = structlog.get_logger(__name__)


# ─── TAXII Feed Handler ───────────────────────────────────────────────────────

async def handle_taxii_feed(
    client: TaxiiClient,
    pipeline: "ThreatIntelPipeline",
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
    pipeline: "ThreatIntelPipeline",
    since_hours: int = 24,
) -> None:
    """
    Fetch recent MISP events and extract IOCs.
    """
    logger.info("Polling MISP feed", since_hours=since_hours)

    try:
        events = await client.get_recent_events(since_hours=since_hours)
        all_iocs: list[dict[str, Any]] = []
        for event in events:
            all_iocs.extend(client.extract_iocs(event))

        if all_iocs:
            stats = await pipeline.ingest_iocs(all_iocs, source="misp")
            logger.info("MISP IOCs ingested", **stats, event_count=len(events))

    except Exception as exc:
        logger.error("MISP feed handler failed", error=str(exc))


# ─── OTX Feed Handler ─────────────────────────────────────────────────────────

async def handle_otx_feed(
    client: OtxClient,
    pipeline: "ThreatIntelPipeline",
) -> None:
    """
    Fetch subscribed OTX pulses and extract IOC indicators.
    """
    logger.info("Polling OTX feed")

    try:
        pulses = await client.get_subscribed_pulses(limit=100)
        all_iocs: list[dict[str, Any]] = []
        for pulse in pulses:
            all_iocs.extend(client.extract_iocs(pulse))

        if all_iocs:
            stats = await pipeline.ingest_iocs(all_iocs, source="otx")
            logger.info("OTX IOCs ingested", **stats, pulse_count=len(pulses))

    except Exception as exc:
        logger.error("OTX feed handler failed", error=str(exc))


# ─── CISA KEV Feed Handler ────────────────────────────────────────────────────

async def handle_cisa_kev_feed(
    client: CisaKevClient,
    pipeline: "ThreatIntelPipeline",
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
