"""
AiSOC Threat Intelligence Feed Service

Polls multiple threat intelligence feeds on configurable intervals,
deduplicates via Redis Bloom filter, and writes normalized IOCs/actors
into OpenSearch, Qdrant, and Neo4j.

AiSOC — open-source AI Security Operations Center (MIT License)
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from functools import partial

import redis.asyncio as aioredis
import structlog
from aiokafka import AIOKafkaProducer
from fastapi import FastAPI
from neo4j import AsyncGraphDatabase
from opensearchpy import AsyncOpenSearch
from prometheus_client import Counter, make_asgi_app
from qdrant_client import AsyncQdrantClient

from app.actors.attribution import ThreatActorAttributionEngine
from app.airgap import airgap_status, is_host_allowed_for_airgap
from app.api.actor_attribution import router as actor_attribution_router
from app.clients.cisa_kev import CisaKevClient
from app.clients.misp import MispClient
from app.clients.otx import OtxClient
from app.clients.taxii import TaxiiClient
from app.config import settings
from app.feeds.handlers import (
    handle_cisa_kev_feed,
    handle_misp_feed,
    handle_otx_feed,
    handle_taxii_feed,
)
from app.feeds.pipeline import ThreatIntelPipeline
from app.feeds.scheduler import FeedScheduler
from app.storage.bloom import RedisBloomFilter
from app.storage.neo4j import Neo4jStore
from app.storage.opensearch import OpenSearchStore
from app.storage.qdrant import QdrantStore

structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer(),
    ],
    context_class=dict,
    logger_factory=structlog.PrintLoggerFactory(),
    cache_logger_on_first_use=True,
)
logger = structlog.get_logger(__name__)

# ─── Prometheus metrics ───────────────────────────────────────────────────────
iocs_ingested = Counter("threatintel_iocs_ingested_total", "Total IOCs ingested", ["source"])
actors_ingested = Counter("threatintel_actors_ingested_total", "Total actors ingested", ["source"])


# ─── Application lifespan ─────────────────────────────────────────────────────


def _airgap_check_feed_url(feed_name: str, url: str | None) -> bool:
    """Return True if a feed at ``url`` may be polled under current air-gap policy.

    Logs and refuses registration when air-gap mode is on and the feed's URL
    points at a public host that is not on the allowlist. Internal mirrors
    (RFC1918, ``.local``, ``.internal``, single-label hosts, allowlisted
    suffixes) are always permitted so customers running their own MISP or
    TAXII server inside the perimeter can keep polling normally.
    """

    if not settings.AISOC_AIRGAPPED:
        return True

    if not url:
        # Feeds without a configured URL (e.g. CISA KEV uses a hardcoded
        # public URL inside the client) are evaluated by their default URL
        # at the call site below; the bare check here only short-circuits
        # operator-supplied URLs.
        return True

    from urllib.parse import urlparse

    host = urlparse(url).hostname or ""
    allowed = is_host_allowed_for_airgap(host)
    if not allowed:
        logger.warning(
            "airgap.feed_blocked",
            feed=feed_name,
            host=host,
            reason="public host blocked by AISOC_AIRGAPPED policy",
        )
    return allowed


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    logger.info(
        "ThreatIntel service starting…",
        airgap=airgap_status(),
    )

    # ── Redis ──────────────────────────────────────────────────────────────────
    redis = aioredis.from_url(settings.REDIS_URL, decode_responses=False)

    # ── OpenSearch ────────────────────────────────────────────────────────────
    os_client = AsyncOpenSearch(
        hosts=[{"host": settings.OPENSEARCH_HOST, "port": settings.OPENSEARCH_PORT}],
        http_auth=(settings.OPENSEARCH_USER, settings.OPENSEARCH_PASSWORD) if settings.OPENSEARCH_USER else None,
        use_ssl=False,
    )

    # ── Qdrant ────────────────────────────────────────────────────────────────
    qdrant_client = AsyncQdrantClient(host=settings.QDRANT_HOST, port=settings.QDRANT_PORT)

    # ── Neo4j ─────────────────────────────────────────────────────────────────
    neo4j_driver = AsyncGraphDatabase.driver(
        settings.NEO4J_URI,
        auth=(settings.NEO4J_USER, settings.NEO4J_PASSWORD),
    )

    # ── Kafka (optional) ──────────────────────────────────────────────────────
    kafka_producer = None
    if settings.KAFKA_BOOTSTRAP_SERVERS:
        try:
            kafka_producer = AIOKafkaProducer(bootstrap_servers=settings.KAFKA_BOOTSTRAP_SERVERS)
            await kafka_producer.start()
        except Exception as exc:
            logger.warning("Kafka producer unavailable", error=str(exc))
            kafka_producer = None

    # ── Storage layer ─────────────────────────────────────────────────────────
    bloom = RedisBloomFilter(redis)
    os_store = OpenSearchStore(os_client)
    qdrant_store = QdrantStore(qdrant_client)
    neo4j_store = Neo4jStore(neo4j_driver)

    await os_store.initialize()
    try:
        await qdrant_store.initialize()
    except Exception as exc:
        logger.warning("Qdrant init failed", error=str(exc))

    # ── Pipeline ──────────────────────────────────────────────────────────────
    pipeline = ThreatIntelPipeline(
        bloom=bloom,
        os_store=os_store,
        qdrant_store=qdrant_store,
        neo4j_store=neo4j_store,
        kafka_producer=kafka_producer,
        kafka_topic=settings.KAFKA_TOPIC_THREAT_INTEL,
    )

    # ── Clients ───────────────────────────────────────────────────────────────
    taxii_client = TaxiiClient(
        base_url=settings.TAXII_URL,
        username=settings.TAXII_USERNAME,
        password=settings.TAXII_PASSWORD,
    )

    misp_client = (
        MispClient(
            url=settings.MISP_URL,
            api_key=settings.MISP_API_KEY,
        )
        if settings.MISP_URL
        else None
    )

    otx_client = (
        OtxClient(
            api_key=settings.OTX_API_KEY,
        )
        if settings.OTX_API_KEY
        else None
    )

    kev_client = CisaKevClient()

    # ── Scheduler ─────────────────────────────────────────────────────────────
    scheduler = FeedScheduler(pipeline)

    # Register TAXII feeds (skipped entirely if the configured TAXII server
    # is on the public Internet and AISOC_AIRGAPPED=1 — this prevents even
    # a single boot-time DNS lookup from leaking the deployment).
    if settings.TAXII_URL and settings.TAXII_COLLECTION_IDS and _airgap_check_feed_url("taxii", settings.TAXII_URL):
        for col_id in settings.TAXII_COLLECTION_IDS.split(","):
            col_id = col_id.strip()
            if col_id:
                scheduler.register(
                    feed_name=f"taxii:{col_id}",
                    handler=partial(
                        handle_taxii_feed,
                        client=taxii_client,
                        pipeline=pipeline,
                        api_root=settings.TAXII_API_ROOT,
                        collection_id=col_id,
                    ),
                    interval_seconds=settings.TAXII_POLL_INTERVAL,
                )

    # Register MISP feed
    if misp_client and _airgap_check_feed_url("misp", settings.MISP_URL):
        scheduler.register(
            feed_name="misp",
            handler=partial(handle_misp_feed, client=misp_client, pipeline=pipeline),
            interval_seconds=settings.MISP_POLL_INTERVAL,
        )

    # Register OTX feed (always public, so air-gapped mode unconditionally
    # disables it — there is no internal mirror of AlienVault OTX).
    if otx_client and _airgap_check_feed_url("otx", "https://otx.alienvault.com"):
        scheduler.register(
            feed_name="otx",
            handler=partial(handle_otx_feed, client=otx_client, pipeline=pipeline),
            interval_seconds=settings.OTX_POLL_INTERVAL,
        )

    # CISA KEV (always enabled — no key required) — public CISA URL, so
    # an air-gapped deployment must mirror the JSON internally and
    # override via an internal allowlist entry, otherwise we skip.
    if _airgap_check_feed_url("cisa-kev", "https://www.cisa.gov"):
        scheduler.register(
            feed_name="cisa-kev",
            handler=partial(handle_cisa_kev_feed, client=kev_client, pipeline=pipeline),
            interval_seconds=settings.CISA_KEV_POLL_INTERVAL,
        )

    scheduler.start()

    # Store refs for health endpoint
    app.state.scheduler = scheduler
    app.state.pipeline = pipeline
    app.state.redis = redis
    app.state.os_store = os_store

    # Threat actor attribution engine — shares the os_store so the IOC
    # component of the score can match against collected threat intel.
    app.state.attribution_engine = ThreatActorAttributionEngine(os_store=os_store)

    yield

    # ── Shutdown ──────────────────────────────────────────────────────────────
    scheduler.stop()
    if kafka_producer:
        await kafka_producer.stop()
    await neo4j_driver.close()
    await os_client.close()
    await redis.close()
    logger.info("ThreatIntel service stopped")


# ─── FastAPI app ──────────────────────────────────────────────────────────────

app = FastAPI(
    title="AiSOC Threat Intelligence Service",
    version="0.1.0",
    lifespan=lifespan,
)

# Mount Prometheus metrics
metrics_app = make_asgi_app()
app.mount("/metrics", metrics_app)

# Threat actor attribution router (v0)
app.include_router(actor_attribution_router)


@app.get("/health")
async def health() -> dict:
    """Health and status endpoint."""
    try:
        redis: aioredis.Redis = app.state.redis
        await redis.ping()
        redis_ok = True
    except Exception:
        redis_ok = False

    return {
        "status": "ok",
        "redis": redis_ok,
        "scheduler": app.state.scheduler._scheduler.running if hasattr(app.state, "scheduler") else False,
        "airgap": airgap_status(),
    }


@app.get("/api/v1/iocs/search")
async def search_iocs(
    value: str | None = None,
    ioc_type: str | None = None,
    source: str | None = None,
    limit: int = 20,
) -> dict:
    """Search stored IOCs."""
    pipeline: ThreatIntelPipeline = app.state.pipeline
    iocs = await pipeline._os.search_iocs(value=value, ioc_type=ioc_type, source=source, limit=limit)
    return {"total": len(iocs), "iocs": iocs}
