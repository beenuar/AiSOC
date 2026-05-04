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
from app.auth.oidc import router as oidc_router
from app.auth.saml import router as saml_router
from app.core.config import settings
from app.middleware.audit_middleware import AuditMiddleware
from app.middleware.demo_mode import DemoModeMiddleware
from app.core.logging import configure_logging
from app.core.telemetry import instrument_app
from app.db.database import engine
from app.db.neo4j import init_neo4j, close_neo4j
from app.graphql.schema import graphql_router
from app.models import Base
from app.services.plugin_manager import get_plugin_manager

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
        try:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            logger.info("Database tables created (development mode)")
        except Exception as exc:
            # Tables already exist or another worker beat us to it — safe to ignore in dev.
            logger.warning("create_all skipped (likely already applied)", error=str(exc))

    # Initialize Neo4j graph layer
    try:
        await init_neo4j()
    except Exception as exc:
        logger.warning("Neo4j unavailable at startup – graph features disabled", error=str(exc))

    # Auto-discover plugins from AISOC_PLUGINS_DIR
    try:
        plugin_mgr = get_plugin_manager()
        loaded = await plugin_mgr.discover()
        logger.info("plugin discovery complete", count=len(loaded), plugins=loaded)
    except Exception as exc:
        logger.warning("plugin discovery failed – continuing without plugins", error=str(exc))

    yield

    logger.info("AiSOC API shutting down")
    await engine.dispose()
    await close_neo4j()


def create_application() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="AiSOC Platform API",
        description=(
            "AiSOC — open-source AI Security Operations Center. "
            "Autonomous threat detection, investigation, and response."
        ),
        version=settings.VERSION,
        docs_url="/api/docs" if settings.ENVIRONMENT != "production" else None,
        redoc_url="/api/redoc" if settings.ENVIRONMENT != "production" else None,
        openapi_url="/api/openapi.json" if settings.ENVIRONMENT != "production" else None,
        lifespan=lifespan,
    )

    # OpenTelemetry auto-instrumentation (FastAPI + SQLAlchemy + httpx)
    instrument_app(app)

    # Middleware
    # Order matters: outermost = last added in Starlette. CORS/GZip must wrap
    # everything else, then DemoMode (so its 403 still gets CORS headers),
    # then Audit (so denied writes are still logged).
    app.add_middleware(AuditMiddleware)
    app.add_middleware(DemoModeMiddleware)
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
    app.include_router(saml_router)
    app.include_router(oidc_router)
    app.include_router(graphql_router, prefix="/graphql", tags=["graphql"])

    return app


app = create_application()


@app.middleware("http")
async def api_version_middleware(request: Request, call_next) -> Response:
    """Add API version metadata headers to every response.

    X-API-Version   – the stable version of the current route prefix
    X-API-Stability – 'stable' for /api/v1, 'preview' for anything else
    """
    response = await call_next(request)
    path = request.url.path
    if path.startswith("/api/v1/"):
        response.headers["X-API-Version"] = "v1"
        response.headers["X-API-Stability"] = "stable"
    elif path.startswith("/api/"):
        response.headers["X-API-Version"] = "preview"
        response.headers["X-API-Stability"] = "preview"
    return response


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
