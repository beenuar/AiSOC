"""
AiSOC API Configuration
AiSOC — open-source AI Security Operations Center
MIT License
"""

import logging
import warnings
from functools import lru_cache
from typing import Any

from pydantic import PostgresDsn, RedisDsn, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Default placeholders shipped in source. Anything matching these in a
# non-development environment triggers a hard startup warning (see
# ``warn_if_insecure_defaults`` below). Exposed as a constant so tests
# and infra can reference the same canonical list.
INSECURE_SECRET_KEY_DEFAULTS: frozenset[str] = frozenset(
    {
        "change-me-in-production-at-least-32-chars",
        "dev_secret_key_change_in_production",
        "changeme",
        "secret",
    }
)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        # pydantic-settings v2 attempts to JSON-decode environment variables
        # whose annotation is a complex type (list/dict/...) BEFORE any
        # ``field_validator(mode="before")`` runs. That breaks our documented
        # convention of comma-separated values for fields like ``CORS_ORIGINS``
        # (e.g. ``CORS_ORIGINS=http://localhost:3000``). Disabling decoding
        # makes the raw string flow into the validator unchanged, which then
        # parses the comma-separated form. Operators who prefer JSON syntax
        # can still pass ``["..."]`` via the .env file pathway because the
        # validator falls through for non-string inputs.
        enable_decoding=False,
    )

    # App
    APP_NAME: str = "AiSOC API"
    APP_VERSION: str = "0.1.0"
    ENV: str = "development"
    ENVIRONMENT: str = "development"  # alias for ENV
    VERSION: str = "0.1.0"  # alias for APP_VERSION
    DEBUG: bool = False
    API_PREFIX: str = "/api/v1"

    # Security
    SECRET_KEY: str = "change-me-in-production-at-least-32-chars"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    ALGORITHM: str = "HS256"

    # Bearer token required to scrape ``/metrics`` outside development.
    # Empty string disables the gate (development default). When set, the
    # endpoint requires ``Authorization: Bearer <METRICS_TOKEN>`` and
    # otherwise returns 401. Prefer a long random hex string mounted as
    # a kubernetes secret / fly.io secret in production.
    METRICS_TOKEN: str = ""

    # Database
    DATABASE_URL: PostgresDsn = "postgresql+asyncpg://aisoc:aisoc@localhost:5432/aisoc"
    DATABASE_POOL_SIZE: int = 20
    DATABASE_MAX_OVERFLOW: int = 10

    # Redis
    REDIS_URL: RedisDsn = "redis://localhost:6379/0"
    REDIS_POOL_SIZE: int = 20

    # ClickHouse
    CLICKHOUSE_HOST: str = "localhost"
    CLICKHOUSE_PORT: int = 9000
    CLICKHOUSE_DATABASE: str = "aisoc"
    CLICKHOUSE_USER: str = "default"
    CLICKHOUSE_PASSWORD: str = ""

    # Kafka
    # Canonical name across the stack is ``KAFKA_BOOTSTRAP_SERVERS`` (see
    # ``.env.example`` and the docker-compose files). ``KAFKA_BROKERS`` is
    # kept as a backward-compatible alias for older deployments.
    KAFKA_BOOTSTRAP_SERVERS: str = "localhost:9092"
    KAFKA_BROKERS: str = "localhost:9092"
    KAFKA_TOPIC_EVENTS: str = "aisoc.normalized_events"
    KAFKA_TOPIC_ALERTS: str = "aisoc.alerts"

    # OpenSearch
    OPENSEARCH_URL: str = "http://localhost:9200"

    # Neo4j
    NEO4J_URI: str = "bolt://localhost:7687"
    NEO4J_USER: str = "neo4j"
    NEO4J_PASSWORD: str = ""

    # Qdrant
    QDRANT_URL: str = "http://localhost:6333"

    # CORS
    CORS_ORIGINS: list[str] = ["http://localhost:3000", "http://localhost:3001"]

    # Observability
    OTEL_ENDPOINT: str = ""
    LOG_LEVEL: str = "INFO"

    # Multi-tenancy
    MAX_TENANTS: int = 1000
    DEFAULT_TENANT_PLAN: str = "starter"

    # Plugin system
    AISOC_PLUGINS_DIR: str = "/opt/aisoc/plugins"

    # Plugin signature trust gate.
    #   strict   – signed-and-verified manifests are required; unsigned or
    #              invalid plugins are refused. Default in production.
    #   warn     – unsigned/invalid plugins still load, but a structured
    #              warning log is emitted and the plugin record carries
    #              ``signature_status="warn"``. Useful while bootstrapping
    #              a key-rotation workflow.
    #   disabled – signature checks are skipped entirely. Only sane in a
    #              fully isolated dev sandbox.
    # Public keys live in ``PLUGIN_TRUSTED_KEYS_DIR`` as PEM files; any
    # plugin whose ``manifest.signature`` verifies under one of them is
    # considered trusted.
    PLUGIN_TRUST_MODE: str = "strict"
    PLUGIN_TRUSTED_KEYS_DIR: str = "/opt/aisoc/plugin-keys"

    # Mobile responder PWA
    # Web push runs in the realtime service; this base URL is used by the API
    # gateway proxy at /api/v1/push/* so the frontend never has to know the
    # realtime service exists. Internal token must match REALTIME's
    # AISOC_INTERNAL_TOKEN to authorize internal push fan-out.
    REALTIME_BASE_URL: str = "http://realtime:8086"
    REALTIME_INTERNAL_TOKEN: str = ""

    # Relying party identity for WebAuthn / Passkey ceremonies. RP_ID must
    # match the eTLD+1 of the PWA origin (no scheme, no port). RP_NAME is
    # what the OS prompt shows the user.
    PASSKEY_RP_ID: str = "localhost"
    PASSKEY_RP_NAME: str = "AiSOC"
    PASSKEY_RP_ORIGINS: list[str] = [
        "http://localhost:3000",
        "http://localhost:3001",
    ]
    PASSKEY_CHALLENGE_TTL_SECONDS: int = 300

    @field_validator("PASSKEY_RP_ORIGINS", mode="before")
    @classmethod
    def parse_passkey_origins(cls, v: Any) -> list[str]:
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        return v

    # Demo mode (hosted at tryaisoc.com)
    # When AISOC_DEMO_MODE=true the API rejects mutating requests outside the
    # demo tenant with 403, surfaces a banner, and pre-seeds canonical data.
    AISOC_DEMO_MODE: bool = False
    AISOC_DEMO_TENANT: str = "demo"
    AISOC_DEMO_BANNER: str = "Demo data resets daily at 00:00 UTC. All write actions are disabled."

    # Optional services (toggle off for the lean Fly.io demo).
    # When true the corresponding subsystem skips connection setup at boot
    # and the API returns 503 for endpoints that require it.
    AISOC_DISABLE_KAFKA: bool = False
    AISOC_DISABLE_CLICKHOUSE: bool = False
    AISOC_DISABLE_OPENSEARCH: bool = False
    AISOC_DISABLE_NEO4J: bool = False
    AISOC_DISABLE_QDRANT: bool = False

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def parse_cors(cls, v: Any) -> list[str]:
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",")]
        return v


@lru_cache
def get_settings() -> Settings:
    return Settings()


def _is_dev_env(env: str) -> bool:
    return (env or "").strip().lower() in {"development", "dev", "local", "demo", "test"}


def warn_if_insecure_defaults(s: Settings | None = None) -> list[str]:
    """Emit a structured warning for each insecure default still in place.

    Returns the list of warning messages emitted. Called from
    ``app.main`` during startup so operators see the warnings in the
    very first lines of the API container's stdout — same place they'd
    look for a panic.

    The list is also returned so a /health/secrets endpoint (or a
    deploy-time CI check) can assert on it without re-implementing the
    rule. We deliberately ``warnings.warn`` rather than ``logger.error``
    so test suites can assert on the warning category.
    """
    s = s or settings
    msgs: list[str] = []

    if s.SECRET_KEY in INSECURE_SECRET_KEY_DEFAULTS:
        msgs.append("SECRET_KEY is set to a known insecure placeholder; rotate before exposing this instance to the network.")

    # /metrics auth: outside dev we expect a non-empty token.
    if not _is_dev_env(s.ENVIRONMENT) and not s.METRICS_TOKEN:
        msgs.append("METRICS_TOKEN is empty in a non-development environment — /metrics is currently unauthenticated.")

    # Plugin trust mode: never silently default to disabled in prod.
    if not _is_dev_env(s.ENVIRONMENT) and s.PLUGIN_TRUST_MODE.lower() == "disabled":
        msgs.append("PLUGIN_TRUST_MODE=disabled outside development — plugins will load without signature verification.")

    logger = logging.getLogger("aisoc.config")
    for msg in msgs:
        # ``stacklevel=2`` so the warning points at the caller of
        # ``warn_if_insecure_defaults`` rather than this helper.
        warnings.warn(msg, RuntimeWarning, stacklevel=2)
        logger.warning("insecure_default: %s", msg)

    return msgs


settings = get_settings()
