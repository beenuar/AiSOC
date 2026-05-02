import structlog
from fastapi import FastAPI
from app.api.router import router

app = FastAPI(
    title="AiSOC Action Execution Service",
    description="Blast-radius gated response action execution with human-in-the-loop approvals",
    version="0.1.0",
)

app.include_router(router, prefix="/api/v1")


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "aisoc-actions"}
