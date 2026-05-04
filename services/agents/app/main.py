import os
from contextlib import asynccontextmanager
from typing import AsyncGenerator

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.router import router
from app.api.investigate import router as investigate_router
from app.api.playbooks import router as playbook_router
from app.api.contextual import router as contextual_router
from app.core.telemetry import instrument_app
from app.investigator import ledger as investigation_ledger
from app.playbook import PlaybookStore
from app.tools.mitre_full import load_attck_corpus, embed_techniques_into_qdrant

logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Load resources on startup."""
    # Seed playbook store with default templates
    try:
        store = PlaybookStore.default()
        n = store.seed_defaults()
        if n:
            logger.info("playbook_store.seeded", count=n)
    except Exception as exc:
        logger.warning("Playbook store seed failed", error=str(exc))

    # Load full MITRE ATT&CK corpus
    try:
        await load_attck_corpus()
    except Exception as exc:
        logger.warning("MITRE ATT&CK corpus load failed at startup", error=str(exc))

    # Embed into Qdrant for RAG (only if configured)
    qdrant_url = os.getenv("QDRANT_URL", "")
    openai_key = os.getenv("OPENAI_API_KEY", "")
    if qdrant_url and openai_key:
        try:
            await embed_techniques_into_qdrant(
                qdrant_url=qdrant_url,
                openai_api_key=openai_key,
            )
        except Exception as exc:
            logger.warning("ATT&CK Qdrant embedding skipped", error=str(exc))

    # Warm up the investigation-ledger pool. This is best-effort: if the DB is
    # unreachable we keep running, ledger writes just become no-ops.
    try:
        await investigation_ledger.get_pool()
    except Exception as exc:  # noqa: BLE001
        logger.warning("investigation_ledger.warmup_failed", error=str(exc))

    yield

    # Drain the pool so the container exits cleanly on shutdown.
    try:
        await investigation_ledger.close_pool()
    except Exception as exc:  # noqa: BLE001
        logger.warning("investigation_ledger.close_failed", error=str(exc))


app = FastAPI(
    title="AiSOC Agent Orchestrator",
    description="LangGraph-based autonomous investigation and response agents",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS — the web console talks to this service directly (it does not go through
# the Next.js rewrite layer for agent endpoints because we want to stream
# NDJSON without buffering through the proxy). Origins are comma-separated via
# the CORS_ORIGINS env var; default keeps localhost dev usable out of the box.
_cors_origins_raw = os.getenv(
    "CORS_ORIGINS",
    "http://localhost:3000,http://localhost:3001,http://127.0.0.1:3000",
)
_cors_origins = [o.strip() for o in _cors_origins_raw.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# OpenTelemetry auto-instrumentation (FastAPI + httpx)
instrument_app(app)

app.include_router(router, prefix="/api/v1")
app.include_router(investigate_router)  # prefix already set in investigate.py
app.include_router(playbook_router)     # prefix: /api/v1/playbooks
app.include_router(contextual_router)   # prefix: /api/v1/contextual


@app.get("/health")
async def health():
    from app.tools.mitre_full import get_coverage_summary
    summary = get_coverage_summary()
    return {
        "status": "healthy",
        "service": "aisoc-agents",
        "attck_corpus": summary,
    }
