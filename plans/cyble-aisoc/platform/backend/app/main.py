"""FastAPI entrypoint."""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse

from app.agents.actor_profiler import scheduler as actor_profiler_scheduler
from app.agents.detection_validation import scheduler as bas_scheduler
from app.agents.exposure import scheduler as exposure_scheduler
from app.agents.supply_chain import scheduler as supply_chain_scheduler
from app.api.asset_routes import router as asset_router
from app.api.academy_routes import router as academy_router
from app.api.benchmark_public_routes import router as benchmark_public_router
from app.api.chaos_routes import router as chaos_router
from app.api.cold_storage_routes import router as cold_storage_router
from app.api.llm_cache_routes import router as llm_cache_router
from app.api.region_routes import router as region_router
from app.api.streaming_routes import router as streaming_router
from app.api.brand_routes import router as brand_router
from app.api.detection_author_routes import router as detection_author_router
from app.api.actor_routes import router as actor_router
from app.api.exposure_routes import router as exposure_router
from app.api.federation_routes import router as federation_router
from app.api.hitl_routes import router as hitl_router
from app.api.finops_routes import router as finops_router
from app.api.marketplace_routes import router as marketplace_router
from app.api.mobile_routes import router as mobile_router
from app.api.mssp_routes import router as mssp_router
from app.api.rollback_routes import router as rollback_router
from app.api.routes import router
from app.api.supply_chain_routes import router as supply_chain_router
from app.api.vertical_pack_routes import router as vertical_pack_router
from app.api.workspace_routes import router as workspace_router
from app.brand_responder import scheduler as brand_responder_scheduler
from app.config import settings
from app.db import init_db
from app.detections.runtime import get_engine
from app.hitl.gateway import gateway as hitl_gateway
from app.realtime import start_clickhouse_sink, stop_clickhouse_sink
from app.seed import seed_if_empty
from app.tools import registry  # noqa: F401  -- forces tool registration on import


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    if settings.seed_on_startup:
        seed_if_empty()
    # Boot the HITL SLA/escalation watcher so timed-out approvals get denied
    # (never auto-approved) and on-call escalations fire on schedule.
    hitl_gateway.start_background_tasks()
    # Warm the Sigma engine so the first /events request doesn't pay the
    # ~hundreds-of-ms cost of walking rules/ and parsing every YAML.
    get_engine()
    # Drain the OCSF stream into ClickHouse if the operator configured it.
    # No-op on a laptop where AISOC_CLICKHOUSE_URL is unset — the platform
    # keeps booting on SQLite alone.
    await start_clickhouse_sink()
    # Continuous Detection Validation (BAS) — replays the synthetic
    # OCSF catalogue against the live engine on a cadence and opens
    # proactive cases on drift. No-op when disabled in settings.
    bas_scheduler.start_background_tasks()
    # Closed-loop Exposure agent (t3a-closed-loop) — hourly CTI sweep
    # per tenant: dark-web, brand, ASM, vuln-intel → graph node +
    # proactive case + Responder routing + re-verification.
    exposure_scheduler.start_background_tasks()
    # Brand Responder (t3c-brand-takedown) — multi-hour sweep per tenant:
    # discover typosquats → score → evidence → submit takedowns across
    # registrar/host/registry/safe-browsing channels. Auto-files only
    # when the candidate score crosses brand_auto_takedown_threshold;
    # lower-confidence hits surface for human triage.
    brand_responder_scheduler.start_background_tasks()
    # Threat Actor Profiling (t3e-actor-profiling) — periodic per-tenant
    # sweep: scan IOCs → resolve canonical actor handles via CTI →
    # materialise ThreatActor + ActorIOCLink rows + ATTRIBUTED_TO graph
    # edges. Powers the actor card and IOC-pivot endpoints.
    actor_profiler_scheduler.start_background_tasks()
    # Supply-Chain Risk Fusion (t3f-supply-chain) — periodic per-tenant
    # sweep: fuse Cyble CTI signals (darkweb / brand / ASM / vuln intel)
    # against declared third-party Vendor rows; record VendorRiskSignal
    # audit log + DEPENDS_ON graph topology; open proactive Case when
    # rolling-window risk crosses the configured threshold.
    supply_chain_scheduler.start_background_tasks()
    try:
        yield
    finally:
        await supply_chain_scheduler.stop_background_tasks()
        await actor_profiler_scheduler.stop_background_tasks()
        await brand_responder_scheduler.stop_background_tasks()
        await exposure_scheduler.stop_background_tasks()
        await bas_scheduler.stop_background_tasks()
        await stop_clickhouse_sink()
        await hitl_gateway.stop_background_tasks()


app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    description="Agentic SOC platform — autonomous triage, investigation, response.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)
app.include_router(hitl_router)
app.include_router(rollback_router)
app.include_router(detection_author_router)
app.include_router(asset_router)
app.include_router(workspace_router)
app.include_router(mobile_router)
app.include_router(exposure_router)
app.include_router(federation_router)
app.include_router(brand_router)
app.include_router(vertical_pack_router)
app.include_router(actor_router)
app.include_router(supply_chain_router)
app.include_router(marketplace_router)
app.include_router(mssp_router)
app.include_router(finops_router)
app.include_router(academy_router)
app.include_router(benchmark_public_router)
app.include_router(streaming_router)
app.include_router(region_router)
app.include_router(chaos_router)
app.include_router(llm_cache_router)
app.include_router(cold_storage_router)


@app.get("/")
def root():
    return {
        "app": settings.app_name,
        "env": settings.env,
        "llm_provider": settings.llm_provider,
        "autonomy_level": settings.autonomy_level,
    }


@app.get("/signup")
def signup_redirect():
    """Redirect /signup to Cyble contact page (permanent)."""
    return RedirectResponse(
        url="https://cyble.com/contact-us/",
        status_code=301,
    )
