import structlog
from fastapi import FastAPI
from app.api.router import router

logger = structlog.get_logger()

app = FastAPI(
    title="AiSOC Agent Orchestrator",
    description="LangGraph-based autonomous investigation and response agents",
    version="0.1.0",
)

app.include_router(router, prefix="/api/v1")


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "aisoc-agents"}
