"""AiSOC Core API - FastAPI Application Entry Point."""
import time
from contextlib import asynccontextmanager
from typing import AsyncGenerator

import structlog
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST

from app.api.v1.router import api_router
from app.core.config import settings
from app.core.logging import configure_logging
from app.db.database import engine
from app.db.neo4j import init_neo4j, close_neo4j
from app.models import Base

logger = structlog.get_logger(__name__)

# Prometheus metrics
REQUEST_COUNT = Counter(
    "aisoc_http_requests_total",
    "Total HTTP requests",
    ["method", "endpoint", "status"],
)
REQUEST_LATENCY = Histogram(
    "aisoc_http_request_duration_seconds",
    "HTTP request latency",
    ["method", "endpoint"],
)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan handler for startup and shutdown tasks."""
    configure_logging()
    logger.info("AiSOC API starting up", version=settings.VERSION, environment=settings.ENVIRONMENT)

    # Create all database tables (dev only; use Alembic migrations in prod)
    if settings.ENVIRONMENT == "development":
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("Database tables created (development mode)")

    # Initialize Neo4j graph layer
    try:
        await init_neo4j()
    except Exception as exc:
        logger.warning("Neo4j unavailable at startup – graph features disabled", error=str(exc))

    yield

    logger.info("AiSOC API shutting down")
    await engine.dispose()
    await close_neo4j()


def create_application() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="AiSOC Platform API",
        description=(
            "Open-source AI Security Operations Center by Cyble. "
            "Autonomous threat detection, investigation, and response."
        ),
        version=settings.VERSION,
        docs_url="/api/docs" if settings.ENVIRONMENT != "production" else None,
        redoc_url="/api/redoc" if settings.ENVIRONMENT != "production" else None,
        openapi_url="/api/openapi.json" if settings.ENVIRONMENT != "production" else None,
        lifespan=lifespan,
    )

    # Middleware
    app.add_middleware(GZipMiddleware, minimum_size=1000)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Routers
    app.include_router(api_router)

    return app


app = create_application()


@app.middleware("http")
async def metrics_middleware(request: Request, call_next) -> Response:
    """Collect Prometheus metrics for each request."""
    start_time = time.time()
    response = await call_next(request)
    duration = time.time() - start_time

    endpoint = request.url.path
    REQUEST_COUNT.labels(request.method, endpoint, response.status_code).inc()
    REQUEST_LATENCY.labels(request.method, endpoint).observe(duration)

    response.headers["X-Request-Duration"] = f"{duration:.4f}"
    return response


@app.get("/health", tags=["system"])
async def health_check() -> dict:
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "aisoc-api",
        "version": settings.VERSION,
    }


@app.get("/metrics", tags=["system"])
async def metrics() -> Response:
    """Prometheus metrics endpoint."""
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
