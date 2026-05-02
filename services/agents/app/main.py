import os
from contextlib import asynccontextmanager
from typing import AsyncGenerator

import structlog
from fastapi import FastAPI

from app.api.router import router
from app.tools.mitre_full import load_attck_corpus, embed_techniques_into_qdrant

logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Load resources on startup."""
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

    yield


app = FastAPI(
    title="AiSOC Agent Orchestrator",
    description="LangGraph-based autonomous investigation and response agents",
    version="0.1.0",
    lifespan=lifespan,
)

app.include_router(router, prefix="/api/v1")


@app.get("/health")
async def health():
    from app.tools.mitre_full import get_coverage_summary
    summary = get_coverage_summary()
    return {
        "status": "healthy",
        "service": "aisoc-agents",
        "attck_corpus": summary,
    }
