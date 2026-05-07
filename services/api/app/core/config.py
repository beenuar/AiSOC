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

    # Application-layer encryption key for connector credentials and other
    # sensitive ``auth_config`` payloads stored in Postgres. Must be a 32-byte
    # url-safe base64 key (the Fernet format). Generate one with
    # ``python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"``
    # and load it via Fly secrets / k8s secret. When empty in a development
    # environment the API auto-generates a process-local key on first use and
    # logs a warning; outside development the API refuses to encrypt or
    # decrypt anything until it's set, so credentials cannot be silently
    # written in plaintext. Rotate by re-encrypting via
    # ``AISOC_CREDENTIAL_KEY_ROTATION_FROM`` (comma-separated previous keys).
    AISOC_CREDENTIAL_KEY: str = ""
    AISOC_CREDENTIAL_KEY_ROTATION_FROM: str = ""

    # Internal URL for the connectors microservice. The API service proxies
    # catalog lookups (``GET /connectors``) and stateless connection tests
    # (``POST /connectors/{type}/test``) to this URL so the wizard UI can
    # render schema-driven forms and verify credentials before saving.
    # Default targets the docker-compose hostname; override locally with
    # e.g. ``http://localhost:8088`` when the connectors service is
    # exposed on the host. Empty disables proxying entirely (catalog and
    # test endpoints will return 503).
    CONNECTORS_SERVICE_URL: str = "http://connectors:8003"
    CONNECTORS_SERVICE_TIMEOUT_SECONDS: float = 15.0

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
    CORS_ORIGINS: list[str] = [
        "http://localhost:3000",
        "http://localhost:3001",
        "https://tryaisoc.com",
        "https://www.tryaisoc.com",
    ]

    # Observability
    OTEL_ENDPOINT: str = ""
    LOG_LEVEL: str = "INFO"

    # Multi-tenancy
    MAX_TENANTS: int = 1000
    DEFAULT_TENANT_PLAN: str = "starter"

    # Plugin system
    AISOC_PLUGINS_DIR: str = "/opt/aisoc/plugins"

    # Feature flags (Tier 3.5)
    AISOC_VULN_BOOST: bool = True

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

    # ------------------------------------------------------------------
    # v6 capability flags (AiSOC v6 capability roadmap).
    # Every capability ships behind a flag so operators can stage rollout.
    # All default to True in development; production deployments can pin
    # individual flags via env vars (e.g. ``AISOC_FEATURE_RBA=false``).
    # ------------------------------------------------------------------
    # Wave 1 — close 2026 table-stakes
    AISOC_FEATURE_RBA: bool = True  # Risk-Based Alerting + entity rollup
    AISOC_FEATURE_CONFIDENCE: bool = True  # Detection confidence + explainability
    AISOC_FEATURE_CHATOPS_VERIFY: bool = True  # Slack/Teams interactive user verification
    AISOC_FEATURE_DETECTION_DRIFT: bool = True  # Weekly purple-team drift sweep
    AISOC_FEATURE_KPI_BAR: bool = True  # 2026 KPI bar in SLA dashboard

    # Wave 2 — eval-graded differentiation
    AISOC_FEATURE_DAC: bool = True  # Detection-as-code lifecycle
    AISOC_FEATURE_HUNT_AS_CODE: bool = True  # YAML hunt corpus + scheduler
    AISOC_FEATURE_BENCHMARK_PUBLIC: bool = True  # Public scoreboard
    AISOC_FEATURE_AIVAI_EVAL: bool = True  # AI-vs-AI adversary suite

    # Wave 3 — operational maturity
    AISOC_FEATURE_FED_SEARCH: bool = True  # Federated SIEM search
    AISOC_FEATURE_MSSP: bool = True  # Parent-tenant console
    AISOC_FEATURE_ASSET_INVENTORY: bool = True  # Asset table + KEV/EPSS
    AISOC_FEATURE_INSIDER_THREAT: bool = True  # Insider-threat module
    AISOC_FEATURE_REMEDIATION_TIERS: bool = True  # L0–L4 maturity tiers

    # Wave 4 — strategic moat
    AISOC_FEATURE_INTERNAL_TI: bool = True  # Closed-case IOC extraction
    AISOC_FEATURE_CSPM: bool = True  # Cloud security posture
    AISOC_FEATURE_IDENTITY_GRAPH: bool = True  # Identity-first correlation graph
    AISOC_FEATURE_BOARD_REPORTS: bool = True  # Auto-generated monthly board reports

    # Drift sweep cadence (hours). Used by services/purple-team scheduler when
    # AISOC_FEATURE_DETECTION_DRIFT is True. Defaults to 168h (weekly).
    AISOC_DRIFT_SWEEP_INTERVAL_HOURS: int = 168

    # ------------------------------------------------------------------
    # Air-gapped operating mode (Tier 3.1 — air-gapped certification).
    # When AISOC_AIRGAPPED is True the API:
    #   * refuses to make any LLM / threat-intel / model-phone-home
    #     HTTP request to a host not in AISOC_AIRGAP_ALLOWLIST (or a
    #     private IP / .local / *.internal hostname),
    #   * surfaces a banner in the UI and a structured warning at boot
    #     when an LLM is configured against a public host,
    #   * pins detection rule and threat-intel feeds to local-only
    #     sources (the rule loader skips any feed whose URL violates
    #     the egress rule and logs the skip).
    # The flag is honored by ``services/api/app/core/airgap.py`` —
    # any HTTP outbound code path can call ``enforce_airgap_for_url(url)``
    # to assert before issuing a request.
    # ------------------------------------------------------------------
    # EASM (External Attack Surface Management) — Tier 3.6.
    # ------------------------------------------------------------------
    AISOC_FEATURE_EASM: bool = True
    AISOC_EASM_SHODAN_API_KEY: str = ""
    AISOC_EASM_CENSYS_API_ID: str = ""
    AISOC_EASM_CENSYS_API_SECRET: str = ""
    AISOC_EASM_ACTIVE_SCAN_ENABLED: bool = False  # lightweight port probe; off by default
    AISOC_EASM_SCAN_PORTS: list[int] = [22, 80, 443, 8080, 8443, 3389]

    @field_validator("AISOC_EASM_SCAN_PORTS", mode="before")
    @classmethod
    def parse_scan_ports(cls, v: Any) -> list[int]:
        if isinstance(v, str):
            return [int(p.strip()) for p in v.split(",") if p.strip()]
        return v

    AISOC_AIRGAPPED: bool = False
    # Comma-separated host (or host:port) allowlist that overrides the
    # blanket egress block when AISOC_AIRGAPPED=True. Use this for an
    # internal LLM gateway (e.g. ``llm.corp.local``) or a private
    # threat-intel mirror. Private IPs (RFC1918, loopback, link-local)
    # and ``.local`` / ``.internal`` / ``.lan`` hostnames are always
    # implicitly allowed.
    AISOC_AIRGAP_ALLOWLIST: list[str] = []

    @field_validator("AISOC_AIRGAP_ALLOWLIST", mode="before")
    @classmethod
    def parse_airgap_allowlist(cls, v: Any) -> list[str]:
        if isinstance(v, str):
            return [host.strip().lower() for host in v.split(",") if host.strip()]
        if isinstance(v, list):
            return [str(host).strip().lower() for host in v if str(host).strip()]
        return v

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

    # Connector credential vault: refuse to silently boot without an encryption
    # key outside development. Without this, ``Connector.auth_config`` would
    # round-trip in plaintext.
    if not _is_dev_env(s.ENVIRONMENT) and not s.AISOC_CREDENTIAL_KEY:
        msgs.append("AISOC_CREDENTIAL_KEY is empty in a non-development environment — connector credentials cannot be encrypted at rest.")

    # Air-gap sanity check: if an operator flipped on AISOC_AIRGAPPED but
    # the LLM is still pointed at a public endpoint (api.openai.com, etc.)
    # surface that as an insecure-default rather than silently 503-ing
    # every LLM-backed endpoint at request time.
    if s.AISOC_AIRGAPPED:
        # Lazy import to avoid a circular reference (airgap.py imports settings).
        try:
            from app.core.airgap import is_host_allowed_for_airgap
            import os as _os

            llm_base = _os.getenv("LLM_BASE_URL") or _os.getenv("OPENAI_BASE_URL") or ""
            if llm_base:
                from urllib.parse import urlparse as _urlparse

                host = (_urlparse(llm_base).hostname or "").lower()
                if host and not is_host_allowed_for_airgap(host, s.AISOC_AIRGAP_ALLOWLIST):
                    msgs.append(
                        f"AISOC_AIRGAPPED=true but LLM_BASE_URL host '{host}' is not in the airgap allowlist — "
                        "LLM calls will be refused. Point LLM_BASE_URL at a local Ollama/vLLM endpoint or add "
                        "the host to AISOC_AIRGAP_ALLOWLIST."
                    )
        except Exception:  # pragma: no cover - never let the warning helper itself fail boot
            pass

    logger = logging.getLogger("aisoc.config")
    for msg in msgs:
        # ``stacklevel=2`` so the warning points at the caller of
        # ``warn_if_insecure_defaults`` rather than this helper.
        warnings.warn(msg, RuntimeWarning, stacklevel=2)
        logger.warning("insecure_default: %s", msg)

    return msgs


settings = get_settings()
