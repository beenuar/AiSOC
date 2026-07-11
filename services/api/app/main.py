"""AiSOC Core API - FastAPI Application Entry Point."""

import asyncio
import hmac
import time
from collections.abc import AsyncGenerator, Awaitable, Callable
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, HTTPException, Request, Response, Security, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest

from app._health import install_health_routes
from app.api.v1.router import api_router
from app.auth.oidc import router as oidc_router
from app.auth.saml import router as saml_router
from app.core.airgap import airgap_status
from app.core.config import enforce_secure_defaults, is_dev_env, settings
from app.core.cors import build_cors_kwargs
from app.core.logging import configure_logging
from app.core.scheduler_lock import scheduler_lock
from app.core.telemetry import instrument_app
from app.db.clickhouse import close_clickhouse
from app.db.database import engine
from app.db.neo4j import close_neo4j, init_neo4j
from app.graphql.schema import graphql_router
from app.middleware.audit_middleware import AuditMiddleware
from app.middleware.demo_mode import DemoModeMiddleware
from app.models import Base
from app.services.plugin_manager import get_plugin_manager
from app.workers.hunt_scheduler import run_forever as run_hunt_scheduler
from app.workers.oauth_refresh import run_forever as run_oauth_refresh
from app.workers.weekly_digest_task import run_forever as run_weekly_digest

_metrics_bearer = HTTPBearer(auto_error=False)

logger = structlog.get_logger(__name__)

_SCHEDULER_LOCK_RETRY_SECONDS = 5

# 15m covers slow OAuth due-batch refreshes while each provider call is bounded
# by OAUTH_REFRESH_HTTP_TIMEOUT_SECONDS.
_OAUTH_REFRESH_LOCK_TTL_SECONDS = 900
# Weekly digest can fan out across tenants + PDF generation, so use a longer
# lease to avoid duplicate report generation during slow runs.
_WEEKLY_DIGEST_LOCK_TTL_SECONDS = 5400
# Hunt sweep can execute multiple saved hunts + case opens in one tick; 5m
# covers slow sweeps while still recovering quickly after replica loss.
_HUNT_SCHEDULER_LOCK_TTL_SECONDS = 300


async def _run_guarded_scheduler_worker(
    *,
    job_name: str,
    ttl_seconds: int,
    worker: Callable[[], Awaitable[None]],
) -> None:
    while True:
        async with scheduler_lock(job_name=job_name, ttl_seconds=ttl_seconds) as should_run:
            if not should_run:
                await asyncio.sleep(_SCHEDULER_LOCK_RETRY_SECONDS)
                continue
            await worker()
            return


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
    # log stream so operators see them before anything else. In production this
    # hard-fails the boot rather than serving with a known-bad secret (Phase 2).
    enforce_secure_defaults(settings)

    # Create all database tables (dev only; use Alembic migrations in prod).
    # We keep this narrowly scoped to the canonical ``"development"`` label
    # so demo / test / local don't quietly run ``create_all`` on top of a
    # real schema. The looser dev gate is used below for SQL migrations.
    if (settings.ENVIRONMENT or "").strip().lower() == "development":
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
    if settings.is_dev:
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
            oauth_refresh_task = asyncio.create_task(
                _run_guarded_scheduler_worker(
                    job_name="oauth_refresh",
                    ttl_seconds=_OAUTH_REFRESH_LOCK_TTL_SECONDS,
                    worker=run_oauth_refresh,
                ),
                name="oauth_refresh_worker",
            )
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
            weekly_digest_task = asyncio.create_task(
                _run_guarded_scheduler_worker(
                    job_name="weekly_digest",
                    ttl_seconds=_WEEKLY_DIGEST_LOCK_TTL_SECONDS,
                    worker=run_weekly_digest,
                ),
                name="weekly_digest_worker",
            )
            logger.info("weekly_digest worker started")
        except Exception as exc:
            logger.warning("weekly_digest worker failed to start", error=str(exc))

    # T3.4: Saved-hunt scheduler. Sweeps aisoc_saved_hunts on a tick and
    # fires any hunt whose cron schedule says it's due. Default off until
    # the executor is wired (see app.workers.hunt_scheduler TODO).
    hunt_scheduler_task: asyncio.Task | None = None
    if settings.HUNT_SCHEDULER_ENABLED:
        try:
            hunt_scheduler_task = asyncio.create_task(
                _run_guarded_scheduler_worker(
                    job_name="hunt_scheduler",
                    ttl_seconds=_HUNT_SCHEDULER_LOCK_TTL_SECONDS,
                    worker=run_hunt_scheduler,
                ),
                name="hunt_scheduler_worker",
            )
            logger.info("hunt_scheduler worker started")
        except Exception as exc:
            logger.warning("hunt_scheduler worker failed to start", error=str(exc))

    # Phase 2.6 — flip /readyz to 200. All lifespan-managed
    # dependencies have been touched at this point (DB, Redis,
    # Neo4j, schedulers); the load balancer can route traffic
    # to this pod safely now.
    app.state.mark_ready()

    yield

    # Phase 2.6 — flip /readyz to 503 the instant we begin
    # shutdown, so the orchestrator drains in-flight requests
    # without sending us new ones.
    app.state.mark_not_ready()

    logger.info("AiSOC API shutting down")
    if oauth_refresh_task is not None and not oauth_refresh_task.done():
        oauth_refresh_task.cancel()
        try:
            await oauth_refresh_task
        except asyncio.CancelledError:
            logger.debug("oauth_refresh worker cancelled during shutdown")
        except Exception as exc:
            logger.warning("oauth_refresh worker shutdown error", error=type(exc).__name__)

    if weekly_digest_task is not None and not weekly_digest_task.done():
        weekly_digest_task.cancel()
        try:
            await weekly_digest_task
        except asyncio.CancelledError:
            logger.debug("weekly_digest worker cancelled during shutdown")
        except Exception as exc:
            logger.warning("weekly_digest worker shutdown error", error=type(exc).__name__)

    if hunt_scheduler_task is not None and not hunt_scheduler_task.done():
        hunt_scheduler_task.cancel()
        try:
            await hunt_scheduler_task
        except asyncio.CancelledError:
            logger.debug("hunt_scheduler worker cancelled during shutdown")
        except Exception as exc:
            logger.warning("hunt_scheduler worker shutdown error", error=type(exc).__name__)
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
        # Docs are exposed in every non-production environment. We use the
        # ``is_production`` predicate (the inverse of the dev set) so any
        # operator who names a new dev-class environment in DEV_ENVIRONMENTS
        # automatically gets docs without touching this file.
        docs_url="/api/docs" if not settings.is_production else None,
        redoc_url="/api/redoc" if not settings.is_production else None,
        openapi_url="/api/openapi.json" if not settings.is_production else None,
        lifespan=lifespan,
    )

    # Phase 2.6 — k8s-style liveness (/livez) + readiness (/readyz).
    # /livez always 200 once the process is up. /readyz returns 503
    # until the lifespan startup hook calls ``_mark_ready()``.
    # /health (the pre-existing endpoint) is kept for backwards
    # compatibility with operators who scripted against it.
    mark_ready, mark_not_ready = install_health_routes(app, service_name="aisoc-api")
    app.state.mark_ready = mark_ready
    app.state.mark_not_ready = mark_not_ready

    # OpenTelemetry auto-instrumentation (FastAPI + SQLAlchemy + httpx)
    instrument_app(app)

    # Middleware
    # Order matters: outermost = last added in Starlette. CORS/GZip must wrap
    # everything else, then DemoMode (so its 403 still gets CORS headers),
    # then Audit (so denied writes are still logged).
    app.add_middleware(AuditMiddleware)
    app.add_middleware(DemoModeMiddleware)
    app.add_middleware(GZipMiddleware, minimum_size=1000)
    # CORS allow-list is resolved from AISOC_CORS_ORIGINS / CORS_ORIGINS via
    # the shared helper; settings.CORS_ORIGINS is the Pydantic-parsed fallback
    # for when neither env var is set (e.g. local pytest). The helper also
    # enforces "no wildcard with credentials in production" so bad deploys
    # fail loudly at startup instead of silently turning into CSRF targets.
    app.add_middleware(
        CORSMiddleware,
        **build_cors_kwargs(
            service_name="api",
            allow_credentials=True,
            default_origins=settings.CORS_ORIGINS,
        ),
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


def _metrics_endpoint_label(request: Request) -> str:
    """Pick a low-cardinality label for the request's route.

    Using ``request.url.path`` directly is dangerous: any unmatched path
    (think ``/api/v1/cases/<uuid>``, ``/static/<sha>``, or attacker-supplied
    junk like ``/.git/config``) becomes its own Prometheus time series.
    Over time this blows up the metrics backend and turns the ``/metrics``
    endpoint into an outage vector.

    FastAPI/Starlette resolves the matched route into ``request.scope["route"]``
    once routing has run. We use ``route.path`` (the parameterized template,
    e.g. ``/api/v1/cases/{case_id}``) when available, and fall back to a
    single ``__unmatched__`` bucket for 404s. This caps cardinality at
    "number of declared routes" instead of "number of distinct URLs ever
    requested".
    """
    route = request.scope.get("route") if request.scope else None
    template = getattr(route, "path", None)
    if isinstance(template, str) and template:
        return template
    return "__unmatched__"


@app.middleware("http")
async def metrics_middleware(request: Request, call_next) -> Response:
    """Collect Prometheus metrics for each request."""
    start_time = time.time()
    response = await call_next(request)
    duration = time.time() - start_time

    endpoint = _metrics_endpoint_label(request)
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
    # Delegate to the canonical helper so the dev allow-list stays in one
    # place. We intentionally read ``settings.ENVIRONMENT`` (cached) rather
    # than ``os.environ`` because boot-time CORS/docs decisions were made
    # against the same cached value — flipping it at request time would be
    # inconsistent.
    return is_dev_env(settings.ENVIRONMENT)


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
