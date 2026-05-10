"""AiSOC Core API - FastAPI Application Entry Point."""

import asyncio
import hmac
import time
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, HTTPException, Request, Response, Security, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest

from app.api.v1.router import api_router
from app.auth.oidc import router as oidc_router
from app.auth.saml import router as saml_router
from app.core.airgap import airgap_status
from app.core.config import settings, warn_if_insecure_defaults
from app.core.logging import configure_logging
from app.core.telemetry import instrument_app
from app.db.clickhouse import close_clickhouse
from app.db.database import engine
from app.db.neo4j import close_neo4j, init_neo4j
from app.graphql.schema import graphql_router
from app.middleware.audit_middleware import AuditMiddleware
from app.middleware.demo_mode import DemoModeMiddleware
from app.models import Base
from app.services.plugin_manager import get_plugin_manager
from app.workers.oauth_refresh import run_forever as run_oauth_refresh
from app.workers.weekly_digest_task import run_forever as run_weekly_digest

_DEV_ENVIRONMENTS = {"development", "dev", "local", "demo", "test"}
_metrics_bearer = HTTPBearer(auto_error=False)

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

    # Surface insecure defaults (placeholder SECRET_KEY, missing METRICS_TOKEN
    # outside dev, plugin trust mode disabled outside dev) at the top of the
    # log stream so operators see them before anything else.
    warn_if_insecure_defaults(settings)

    # Create all database tables (dev only; use Alembic migrations in prod)
    if settings.ENVIRONMENT == "development":
        try:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            logger.info("Database tables created (development mode)")
        except Exception as exc:
            # Tables already exist or another worker beat us to it — safe to ignore in dev.
            logger.warning("create_all skipped (likely already applied)", error=str(exc))

    # Apply raw-SQL migrations (services/api/migrations/*.sql). These cover
    # tables that aren't part of the SQLAlchemy ORM (aisoc_cases, MSSP, EASM,
    # connector schema-drift, etc.). The runner is idempotent: each migration
    # is tracked in aisoc_schema_migrations so it only runs once. We exclude
    # production for now since prod is expected to have a managed migration
    # pipeline; demo / dev environments bootstrap themselves on boot so the
    # first deploy of a new feature is usable immediately.
    if settings.ENVIRONMENT in _DEV_ENVIRONMENTS:
        try:
            from app.scripts.run_migrations import main as run_sql_migrations  # noqa: PLC0415

            await run_sql_migrations()
            logger.info("SQL migrations applied", environment=settings.ENVIRONMENT)
        except Exception as exc:
            logger.warning("SQL migration run failed", error=str(exc))

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

    # Workstream 5 (self-healing): kick off the OAuth refresh worker. It runs
    # as a background asyncio task that owns its own DB session per tick. We
    # gate on settings so tests / scheduler-replicas can opt out.
    oauth_refresh_task: asyncio.Task | None = None
    if settings.OAUTH_REFRESH_WORKER_ENABLED:
        try:
            oauth_refresh_task = asyncio.create_task(run_oauth_refresh(), name="oauth_refresh_worker")
            logger.info("oauth_refresh worker started")
        except Exception as exc:
            logger.warning("oauth_refresh worker failed to start", error=str(exc))

    # WS-G2: Weekly executive digest auto-generation worker. Generates a
    # PDF (or HTML fallback) digest for every active tenant every Monday at
    # 00:xx UTC and persists a ReportArtefact row.
    # Author: Beenu <beenu@cyble.com>
    weekly_digest_task: asyncio.Task | None = None
    if settings.WEEKLY_DIGEST_WORKER_ENABLED:
        try:
            weekly_digest_task = asyncio.create_task(run_weekly_digest(), name="weekly_digest_worker")
            logger.info("weekly_digest worker started")
        except Exception as exc:
            logger.warning("weekly_digest worker failed to start", error=str(exc))

    yield

    logger.info("AiSOC API shutting down")
    if oauth_refresh_task is not None and not oauth_refresh_task.done():
        oauth_refresh_task.cancel()
        try:
            await oauth_refresh_task
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            logger.warning("oauth_refresh worker shutdown error", error=str(exc))

    if weekly_digest_task is not None and not weekly_digest_task.done():
        weekly_digest_task.cancel()
        try:
            await weekly_digest_task
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            logger.warning("weekly_digest worker shutdown error", error=str(exc))
    await engine.dispose()
    await close_neo4j()
    # Close the ClickHouse warm-tier client. We don't pre-init it on
    # startup — the singleton is created lazily on the first lake query
    # so deployments without a ClickHouse host don't pay the cost — but
    # we do need to release the socket cleanly on shutdown.
    await close_clickhouse()


def create_application() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="AiSOC Platform API",
        description=("AiSOC — open-source AI Security Operations Center. Autonomous threat detection, investigation, and response."),
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
    """Health check endpoint.

    Includes the current air-gap policy snapshot so operators can confirm
    zero-egress mode is engaged on this pod (Tier 3.1).
    """
    return {
        "status": "healthy",
        "service": "aisoc-api",
        "version": settings.VERSION,
        "airgap": airgap_status(),
    }


def _metrics_environment_is_dev() -> bool:
    return (settings.ENVIRONMENT or "").strip().lower() in _DEV_ENVIRONMENTS


@app.get("/metrics", tags=["system"])
async def metrics(
    creds: HTTPAuthorizationCredentials | None = Security(_metrics_bearer),
) -> Response:
    """Prometheus metrics endpoint.

    Auth gate:

    * If ``settings.METRICS_TOKEN`` is set, callers MUST present
      ``Authorization: Bearer <METRICS_TOKEN>``. Comparison uses
      ``hmac.compare_digest`` to avoid timing leaks.
    * If ``METRICS_TOKEN`` is empty, the endpoint is open **only** in a
      development-class environment. In any other environment we refuse
      the scrape with a 401 so operators don't accidentally ship an
      unauthenticated metrics endpoint to the open internet.
    """
    token = (settings.METRICS_TOKEN or "").strip()

    if token:
        presented = (creds.credentials if creds else "") or ""
        if not hmac.compare_digest(presented, token):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid metrics token",
                headers={"WWW-Authenticate": 'Bearer realm="metrics"'},
            )
    elif not _metrics_environment_is_dev():
        # Production-ish environment with no token configured: refuse rather
        # than expose internal counters anonymously.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="metrics endpoint requires METRICS_TOKEN outside development",
            headers={"WWW-Authenticate": 'Bearer realm="metrics"'},
        )

    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
