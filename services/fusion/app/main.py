import asyncio
import os
from contextlib import asynccontextmanager
from typing import Any

import redis.asyncio as aioredis
from fastapi import FastAPI

from app._health import install_health_routes, register_subscription
from app.api.router import router, set_worker
from app.core.config import settings
from app.core.logging import configure_logging, logger
from app.memory.provider import MemoryPriorProvider
from app.services import ioc_match
from app.services.ai_asset_recorder import AiAssetRecorder
from app.services.alert_enricher import AlertEnricher
from app.services.alert_sink import AlertSink
from app.services.attack_chain_grouper import AttackChainGrouper
from app.services.baselines import BaselineStore
from app.services.confidence import ConfidenceScorer
from app.services.correlator import Correlator
from app.services.deduplicator import Deduplicator
from app.services.detection_engine import DetectionEngine
from app.services.dlq_sink import PostgresDLQ
from app.services.entity_risk import EntityRiskEngine
from app.services.first_seen import FirstSeenStore
from app.services.fusion_engine import FusionEngine
from app.services.ioc_match import TenantIocMatcher
from app.services.lake_writer import LakeWriter
from app.services.sessions import SessionStore
from app.services.tenant_overlay import OverlayCache
from app.services.ueba_signal import UebaSignalCache
from app.services.windowed_detection import WindowedDetectionEngine
from app.workers.consumer import FusionWorker


def _log_worker_exit(task: asyncio.Task) -> None:
    """Say why the consume loop stopped, whatever the reason.

    A worker that ends cleanly is as much of a problem as one that raises:
    either way nothing is consuming ``raw_events`` any more, and both used to
    be silent.
    """
    if task.cancelled():
        logger.info("fusion.worker_cancelled")
        return
    exc = task.exception()
    if exc is None:
        logger.error("fusion.worker_exited", detail="consume loop returned; the subscription is gone")
        return
    logger.error("fusion.worker_died", error=str(exc), error_type=type(exc).__name__, exc_info=exc)


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging()
    logger.info("Starting AiSOC Alert Fusion Service", port=settings.http_port)

    # Short socket timeouts are part of the Redis fallback: a black-holed
    # connection must fail open into Postgres-backed dedup, not stall the
    # alert path waiting for a TCP read that never arrives.
    redis_client = aioredis.from_url(
        settings.redis_url,
        decode_responses=False,
        socket_connect_timeout=settings.redis_connect_timeout_seconds,
        socket_timeout=settings.redis_socket_timeout_seconds,
        health_check_interval=30,
    )

    dedup = Deduplicator(redis_client)
    correlator = Correlator(redis_client)
    entity_risk = EntityRiskEngine(redis_client)
    confidence_scorer = ConfidenceScorer(enabled=settings.confidence_enabled)
    # Phase A4 — behavioral-model fusion: one cache shared by the engine
    # (fuse-time lookup) and the worker (records the ueba.anomalies stream).
    ueba_cache = UebaSignalCache(redis_client, ttl_seconds=settings.ueba_signal_ttl_seconds) if settings.ueba_fusion_enabled else None
    # Phase C4 — fuse-time attack-chain grouping (shares the fusion Redis).
    chain_grouper = (
        AttackChainGrouper(redis_client, window_seconds=settings.attack_chain_window_seconds)
        if settings.attack_chain_grouping_enabled
        else None
    )
    # Wave 1 — fuse-time TI/vuln enrichment via the enrichment service.
    # Parity 3.1. The matcher reads `threat_intel_iocs` from the Postgres
    # this service already connects to, so it works on CORE where the
    # enrichment service (a `full` profile component) does not run. Without
    # it, `enrich()` caught a connection error, logged at debug and
    # returned `{}`, and the investigation agent received "could not check"
    # for every indicator on every alert.
    ioc_matcher = TenantIocMatcher(settings.database_url) if ioc_match.enabled() else None
    enricher = (
        AlertEnricher(
            base_url=settings.enrichment_service_url,
            timeout_seconds=settings.fuse_enrichment_timeout_seconds,
            malicious_risk_floor=settings.fuse_enrichment_risk_floor,
            ioc_matcher=ioc_matcher,
        )
        if settings.fuse_enrichment_enabled
        else None
    )
    # Wave 1 — live institutional-memory nudge: distil disposition history into
    # per-tenant per-signature priors and feed them to the confidence scorer.
    memory_provider = (
        MemoryPriorProvider() if os.getenv("AISOC_FUSION_MEMORY_NUDGE", "1").strip().lower() not in {"0", "false", "no", "off"} else None
    )
    engine = FusionEngine(
        dedup,
        correlator,
        entity_risk=entity_risk,
        confidence_scorer=confidence_scorer,
        ueba_cache=ueba_cache,
        chain_grouper=chain_grouper,
        enricher=enricher,
        memory_provider=memory_provider,
    )
    # Phase 3.1 — fused alerts land in the Postgres alert store so the spine
    # is continuous (raw event → alert row). Fail-soft: a missing/unreachable
    # DB never blocks the Kafka pipeline.
    sink = AlertSink(settings.database_url) if settings.alert_sink_enabled else None
    # Phase A1 — populate the ClickHouse event lake from the raw-events stream.
    lake = (
        LakeWriter(
            host=settings.clickhouse_host,
            port=settings.clickhouse_port,
            database=settings.clickhouse_database,
            user=settings.clickhouse_user,
            password=settings.clickhouse_password,
            batch_size=settings.lake_batch_size,
            batch_max_age_seconds=settings.lake_batch_max_age_seconds,
        )
        if settings.lake_writer_enabled
        else None
    )
    # Phase A2 — evaluate the executable detection corpus against the stream.
    detector = DetectionEngine() if settings.detection_engine_enabled else None
    # Wave 2 — windowed detections share the fusion Redis for sliding-window state.
    windowed_detector = WindowedDetectionEngine(redis_client) if settings.windowed_detection_enabled else None
    # Depth plan 3.3 — per-tenant first-seen memory, sharing the fusion Redis
    # the windowed engine already uses for sliding-window state.
    first_seen = FirstSeenStore(redis_client)
    # Depth plan 3.4 — per-principal behavioural baselines in CORE, on the
    # same Redis. ADR-0011 records why this is a fusion module rather than
    # the `full`-profile UEBA service.
    baselines = BaselineStore(redis_client)
    # Dead letters go to Postgres so they can be read back. Until now the
    # worker defaulted to LoggingDLQ, so a dropped event produced a log
    # line and nothing else — and an invisible drop is indistinguishable
    # from an event that never arrived.
    #
    # The pool is passed as a callable because `sink.start()` opens it
    # during `worker.start()`, after this point; capturing it eagerly would
    # capture None and drop every dead letter.
    # `ensure_pool`/`invalidate_pool` matter here: the DLQ shares the sink's
    # pool, and while the consumer is holding a message neither the alert path
    # nor anything else reconnects. Without them a Postgres outage that
    # invalidated the pool would turn the hold into a permanent stall.
    dlq = (
        PostgresDLQ(
            lambda: sink._pool,
            ensure_pool=sink.ensure_pool,
            invalidate_pool=sink.invalidate_pool,
        )
        if sink is not None
        else None
    )

    # Depth 6.1 — the observed AI estate. Shares the alert sink's pool for
    # the same reason the dead-letter queue does: one Postgres connection
    # pool per service, opened by `sink.start()` during `worker.start()`.
    # Passed as a callable because that happens after this point, and
    # capturing `sink._pool` eagerly would capture None and silently drop
    # every sighting for the life of the process.
    ai_assets = AiAssetRecorder(lambda: sink._pool) if sink is not None else None

    if sink is None:
        # Explicit, not inferred: this mode writes no alert rows and has no
        # durable DLQ. The consumer still retries and holds, but its committed
        # offsets are not evidence that an alert survived. Development-only.
        logger.warning(
            "fusion.alert_persistence_disabled",
            setting="AISOC_ALERT_SINK_ENABLED=false",
            detail=(
                "alerts are not persisted to Postgres and dead letters are log-only; "
                "Kafka offsets commit after processing, not after durable capture"
            ),
        )

    worker = FusionWorker(
        engine,
        sink=sink,
        dlq=dlq,
        lake=lake,
        detector=detector,
        windowed_detector=windowed_detector,
        first_seen=first_seen,
        baselines=baselines,
        # Parity 5.4. Per-tenant detection tuning as a versioned overlay
        # with hot reload. Without it the engine evaluated the shared
        # corpus and nothing else, so a tenant who disabled a noisy rule
        # in the console kept receiving its alerts.
        overlays=OverlayCache(_fusion_pool()),
        # Depth plan 2.4. Sessions per principal: the stateful half of the
        # projection `session.go` derives per event. Disabled by the same
        # switch as the alert sink, because a session row nothing can join
        # an alert to is a row nobody reads.
        sessions=SessionStore(_fusion_pool()) if settings.alert_sink_enabled else None,
        ueba_cache=ueba_cache,
        ai_assets=ai_assets,
    )
    set_worker(worker)

    # Start Kafka worker as a background task.
    #
    # The done-callback is what makes a dead worker findable. The task is held
    # on app.state, so it is never garbage-collected and asyncio never emits
    # its "Task exception was never retrieved" warning — without this, a
    # consume loop that died took the reason with it. The matching readiness
    # probe below is what stops /readyz answering 200 afterwards.
    worker_task = asyncio.create_task(worker.start())
    worker_task.add_done_callback(_log_worker_exit)
    register_subscription(app, "alerts+raw_events", lambda: worker.attached)
    app.state.worker_task = worker_task
    app.state.redis = redis_client

    # Wave 1 — periodically distil disposition history into memory priors so
    # the confidence nudge stays current (default every 6h). Best-effort.
    async def _refresh_memory_priors() -> None:
        interval = max(int(os.getenv("AISOC_FUSION_MEMORY_REFRESH_SECONDS", "21600")), 300)
        while True:
            try:
                if memory_provider is not None and sink is not None:
                    pool = await sink._ensure_pool()  # noqa: SLF001 — reuse the sink's pool
                    if pool is not None:
                        await memory_provider.refresh(pool)
            except Exception as exc:  # noqa: BLE001 — never crash the service on a refresh
                logger.warning("memory_prior_refresh_failed", error=str(exc))
            await asyncio.sleep(interval)

    memory_task = asyncio.create_task(_refresh_memory_priors()) if memory_provider is not None else None
    app.state.memory_task = memory_task

    # Phase 2.6 — flip /readyz to 200 now that Redis is open + the
    # Kafka consumer is running.
    app.state.mark_ready()

    logger.info("Alert Fusion Service ready")
    yield

    # Phase 2.6 — flip /readyz to 503 at the start of shutdown so the
    # orchestrator stops sending traffic before we tear Kafka down.
    app.state.mark_not_ready()

    # Shutdown
    logger.info("Shutting down Alert Fusion Service")
    await worker.stop()
    worker_task.cancel()
    if memory_task is not None:
        memory_task.cancel()
    await redis_client.aclose()
    logger.info("Alert Fusion Service stopped")


app = FastAPI(
    title="AiSOC Alert Fusion Service",
    description="Real-time alert deduplication and correlation engine",
    version="0.1.0",
    lifespan=lifespan,
)

# Phase 2.6 — k8s liveness + readiness probes (see app/_health.py).
_mark_ready, _mark_not_ready = install_health_routes(app, service_name="aisoc-fusion")
app.state.mark_ready = _mark_ready
app.state.mark_not_ready = _mark_not_ready

app.include_router(router)


_OVERLAY_POOL: Any = None


def _fusion_pool() -> Any:
    """One lazy Postgres pool, shared by the consumer's side readers.

    Built on first use rather than at import, because `main` runs before
    an event loop exists and `asyncpg.create_pool` needs one. The overlay
    cache tolerates `None` and returns the empty overlay, so a deployment
    with no database reachable detects exactly as it did before 5.4, and
    the session store logs and returns None for the same reason.

    Shared rather than one pool each: both sit on the consumer's hot path
    against the same database, and two pools is two connection budgets to
    size instead of one. Renamed from `_overlay_pool` when the session
    store (depth plan 2.4) became the second reader, because a name that
    says "overlay" while two things use it is how the next contributor
    opens a third.
    """
    global _OVERLAY_POOL  # noqa: PLW0603
    if _OVERLAY_POOL is None:
        _OVERLAY_POOL = _LazyPool(settings.database_url)
    return _OVERLAY_POOL


class _LazyPool:
    """Opens an asyncpg pool on first acquire."""

    def __init__(self, dsn: str) -> None:
        self._dsn = dsn
        self._pool: Any = None

    def acquire(self):  # noqa: ANN201
        return _LazyAcquire(self)

    async def _ensure(self) -> Any:
        if self._pool is not None:
            return self._pool
        import asyncpg

        dsn = self._dsn
        for prefix in ("postgresql+asyncpg://", "postgres+asyncpg://"):
            if dsn.startswith(prefix):
                dsn = "postgresql://" + dsn[len(prefix) :]
                break
        self._pool = await asyncpg.create_pool(dsn, min_size=1, max_size=2)
        return self._pool


class _LazyAcquire:
    def __init__(self, parent: _LazyPool) -> None:
        self._parent = parent
        self._ctx: Any = None

    async def __aenter__(self) -> Any:
        pool = await self._parent._ensure()
        self._ctx = pool.acquire()
        return await self._ctx.__aenter__()

    async def __aexit__(self, *exc: Any) -> None:
        if self._ctx is not None:
            await self._ctx.__aexit__(*exc)
