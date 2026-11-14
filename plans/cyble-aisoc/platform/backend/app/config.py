"""Runtime configuration for the AiSOC backend.

Reads from environment variables. All values have sensible defaults so the
platform runs out of the box without any secrets.
"""
from __future__ import annotations

from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="AISOC_", extra="ignore")

    app_name: str = "Cyble AiSOC"
    env: str = "dev"
    db_path: Path = Path("data/aisoc.db")
    seed_on_startup: bool = True

    # LLM provider: "mock" (default, deterministic offline), "openai", "anthropic"
    llm_provider: str = "mock"
    openai_api_key: str | None = None
    anthropic_api_key: str | None = None
    llm_model: str = "claude-3-5-sonnet-20241022"

    # ── Tiered model routing (Theme 2n: t2n-multimodel) ────────────────
    # The plan (cyble-aisoc-plan.md L416–L419) calls for "one model per
    # agent role, evaluated quarterly." We implement that as three named
    # slots so operators can pin (e.g.) Opus for PREMIUM, Sonnet for
    # DEFAULT, Haiku for FAST without code changes. Per-tier provider
    # overrides let an MSSP mix providers across slots (Opus on Anthropic
    # for Investigator, GPT-4o-mini on OpenAI for Reporter, etc.).
    #
    # Empty/None defaults mean "fall back to llm_model / llm_provider",
    # preserving v1 single-model behaviour for anyone who hasn't opted in.
    llm_model_premium: str | None = None
    llm_model_default: str | None = None
    llm_model_fast: str | None = None
    llm_provider_premium: str | None = None
    llm_provider_default: str | None = None
    llm_provider_fast: str | None = None

    # Per-agent model + provider overrides. The fields are explicit
    # (rather than a dict) so pydantic-settings can map them from env
    # vars like AISOC_LLM_MODEL_INVESTIGATOR, AISOC_LLM_PROVIDER_RESPONDER.
    llm_model_investigator: str | None = None
    llm_model_responder: str | None = None
    llm_model_reporter: str | None = None
    llm_model_triager: str | None = None
    llm_model_hunter: str | None = None
    llm_model_phishing: str | None = None
    llm_model_planner: str | None = None
    llm_model_itdr: str | None = None
    llm_model_cdr: str | None = None
    llm_model_detection_author: str | None = None
    llm_provider_investigator: str | None = None
    llm_provider_responder: str | None = None
    llm_provider_reporter: str | None = None
    llm_provider_triager: str | None = None
    llm_provider_hunter: str | None = None
    llm_provider_phishing: str | None = None
    llm_provider_planner: str | None = None
    llm_provider_itdr: str | None = None
    llm_provider_cdr: str | None = None
    llm_provider_detection_author: str | None = None

    def per_agent_model_override(self, agent: str) -> str | None:
        """Return the per-agent model override for `agent`, if any."""
        return getattr(self, f"llm_model_{agent}", None) if agent else None

    def per_agent_provider_override(self, agent: str) -> str | None:
        """Return the per-agent provider override for `agent`, if any."""
        return getattr(self, f"llm_provider_{agent}", None) if agent else None

    # ── Memory substrate (Theme 1) ─────────────────────────────────────
    # Embedding provider for episodic memory + future semantic search.
    # "hashbag" = the offline-friendly deterministic fallback that ships
    # with the demo. "openai" / "sentence-transformers" hit real models
    # and require their respective SDKs to be installed.
    embedding_provider: str = "hashbag"  # hashbag | openai | sentence-transformers
    embedding_model: str = "text-embedding-3-small"  # for openai
    embedding_st_model: str = "all-MiniLM-L6-v2"  # for sentence-transformers
    embedding_dim: int = 128  # only used by hashbag

    # Episodic case memory backend.
    # "sqlite"   = SQLModel-backed (default, always works).
    # "qdrant"   = Qdrant client; the SQLite store still receives writes so
    #              we never lose history if Qdrant is unreachable.
    # "pgvector" = PostgreSQL + pgvector extension; same durability pattern
    #              (SQLite mirror remains the source of truth).
    episodic_backend: str = "sqlite"  # sqlite | qdrant | pgvector
    qdrant_url: str | None = None  # e.g. http://localhost:6333
    qdrant_api_key: str | None = None
    qdrant_collection_prefix: str = "aisoc_episodic"
    # pgvector — set pgvector_dsn to enable. Example:
    #   postgresql://aisoc:aisoc@localhost:5432/aisoc
    # The table is created on first use; tenant_id is indexed for fast
    # per-tenant + MSSP fan-out reads.
    pgvector_dsn: str | None = None
    pgvector_table: str = "aisoc_episodic_memory"

    # Short-term scratchpad backend (per-case working memory).
    # "memory" = in-process dict (default, single-process only).
    # "redis" = Redis with per-case TTL; falls back to in-memory if
    # the redis SDK is missing or the connection fails on boot.
    scratchpad_backend: str = "memory"  # memory | redis
    redis_url: str | None = None  # e.g. redis://localhost:6379/0
    scratchpad_ttl_seconds: int = 24 * 3600  # 1 day per case

    # Threat graph backend (entities + relationships across cases).
    # "sqlite" = SQLModel nodes/edges (default, always works).
    # "neo4j" = real graph DB via bolt:// — falls back to SQLite mirror
    # so reads still answer even if the graph DB is down.
    graph_backend: str = "sqlite"  # sqlite | neo4j
    neo4j_uri: str | None = None  # e.g. bolt://localhost:7687
    neo4j_user: str = "neo4j"
    neo4j_password: str | None = None

    # Detection Knowledge Base — the fourth memory layer.
    # Indexes Sigma rules so agents (Hunter, Detection Author, Investigator)
    # can ask "what detection content do we already have for X?" via vector
    # similarity, keyword, tag, severity, and logsource filters.
    #
    # "memory"        = in-process index over the loaded RulePack (default,
    #                   zero dependencies, fine for tens of thousands of rules).
    # "elasticsearch" = real ES/OpenSearch index; falls back to memory if the
    #                   client SDK is missing or the cluster is unreachable.
    # Rules are *shared* — they are detection content, not customer data —
    # but the search API still accepts an optional tenant_id so vertical
    # rule packs (Theme 3d) can shadow built-ins on a per-tenant basis later.
    detection_kb_backend: str = "memory"  # memory | elasticsearch
    detection_kb_rules_path: Path = Path("app/detections/rules")
    detection_kb_index: str = "aisoc_detections"
    # Weighting for the hybrid score: final = w_vec*cosine + w_kw*keyword.
    # Tuned so a strong keyword hit (e.g. exact tag) beats a fuzzy semantic
    # match, but semantic similarity still surfaces conceptually-related
    # rules a Hunter wouldn't have grepped for by hand.
    detection_kb_weight_vector: float = 0.6
    detection_kb_weight_keyword: float = 0.4
    elasticsearch_url: str | None = None  # e.g. http://localhost:9200
    elasticsearch_api_key: str | None = None
    elasticsearch_username: str | None = None
    elasticsearch_password: str | None = None

    # Agent autonomy controls (Trust & Safety)
    autonomy_level: str = "supervised"  # off | supervised | autonomous
    require_hitl_above: str = "WRITE-REVERSIBLE"  # blast-radius gate

    # HITL gateway — blocking analyst approval for risky tool calls.
    # On timeout the action is DENIED, not approved. Escalation is fired.
    hitl_sla_seconds: int = 900  # 15 minutes to decide
    hitl_escalation_seconds: int = 300  # escalate to on-call after 5 min if still pending
    hitl_poll_interval_ms: int = 250  # how often the agent re-checks state
    hitl_require_mfa: bool = True  # production posture
    # Optional out-of-band notification surfaces (Slack/Teams interactive cards)
    hitl_slack_webhook: str | None = None
    hitl_teams_webhook: str | None = None
    # Public base URL used in interactive cards (so "Approve" links land in the console)
    hitl_console_base_url: str = "http://localhost:8479"

    # Prompt-injection defense (applied to every tool output before it
    # re-enters the LLM context). See app/security/prompt_injection.py.
    # Hard block on classifier verdict=MALICIOUS. Default false: we tag and
    # warn the LLM but let it continue, so an over-eager classifier never
    # blackholes a case. Flip to true in high-autonomy deployments.
    tool_output_injection_block: bool = False
    # Per-string cap before the LLM-facing copy is truncated.
    tool_output_max_chars: int = 8000
    # Per-record cap for the immutable audit row (we still persist a preview
    # of huge dumps but trim to keep SQLite happy).
    tool_output_audit_max_chars: int = 64000

    # Tenant defaults
    default_tenant: str = "demo-tenant"
    # Seed an MSSP demo tenant + two child tenants so the MSSP fan-out flow
    # has data to operate on without a real-customer onboarding step.
    demo_mssp_tenant: str = "demo-mssp"
    demo_mssp_children: list[str] = ["demo-tenant-acme", "demo-tenant-globex"]

    # JWT auth — HMAC-SHA256, see app/security/jwt.py.
    # Generate per-environment via `openssl rand -hex 32` and set
    # AISOC_JWT_SECRET_KEY in the deployment env. The dev default here is
    # intentionally guessable; production refuses to start if it's still
    # set (see `Settings.__post_init__`-style guard below).
    jwt_secret_key: str = "dev-secret-change-me-32+-bytes-long-please-or-else"
    jwt_algorithm: str = "HS256"
    jwt_issuer: str = "aisoc"
    jwt_audience: str = "aisoc-console"
    jwt_default_ttl_seconds: int = 8 * 3600  # 8h working day

    # Dev convenience: if true (default in dev), routes that require a
    # tenant context accept missing bearer tokens and fall back to the
    # default tenant. MUST be false in prod.
    dev_allow_anon_tenant: bool = True

    # Connector SDK (Theme 1) — encryption of per-tenant integration
    # credentials at rest. The Fernet key is base64-urlsafe and 32 bytes
    # decoded; generate via `python -c "from cryptography.fernet import
    # Fernet; print(Fernet.generate_key().decode())"`.
    #
    # - In dev/test: if unset, we autogenerate a key and persist it at
    #   `data/connector_secrets.key` (chmod 600) so secrets survive
    #   restarts. Logged as a warning so you know it happened.
    # - In production: must be supplied via env (`AISOC_CONNECTOR_SECRETS_KEY`),
    #   sourced from KMS / Vault / Kubernetes Secret. Boot fails otherwise.
    connector_secrets_key: str | None = None
    # Where to persist the dev-autogen key. Kept beside the SQLite DB on
    # purpose: same trust boundary, same backup story.
    connector_secrets_key_path: Path = Path("data/connector_secrets.key")

    cors_origins: list[str] = [
        "http://localhost:3000",
        "http://localhost:8477",
        "http://127.0.0.1:3000",
    ]

    # ── Realtime data plane (Theme 1: t1-realtime-data) ───────────────
    # Stream backend for the OCSF → detection → sink → websocket pipeline.
    # "memory" = in-process asyncio queues (default, zero dependencies).
    # "kafka"  = aiokafka against the configured brokers; falls back to
    # in-memory with a warning if brokers are unset.
    stream_backend: str = "memory"  # memory | kafka
    kafka_brokers: str | None = None  # e.g. "broker1:9092,broker2:9092"
    kafka_client_id: str = "aisoc-backend"
    # Bounded buffer per in-memory subscriber. Drop-newest on overflow
    # (see app/realtime/stream.py); we prefer pipeline liveness over
    # completeness on a dev box.
    stream_memory_queue_size: int = 500
    stream_memory_history_size: int = 100

    # ClickHouse — analytical sink for OCSF events. Off by default; when
    # enabled the realtime pipeline writes every normalized event into
    # ClickHouse for retro-hunt + dashboarding while still serving Sigma
    # detection from the stream. Setting clickhouse_url enables the sink.
    clickhouse_url: str | None = None  # e.g. http://localhost:8123
    clickhouse_database: str = "aisoc"
    clickhouse_events_table: str = "events_ocsf"
    clickhouse_user: str = "default"
    clickhouse_password: str | None = None
    # Batching keeps us from hammering ClickHouse one INSERT per event.
    # Flush whichever fires first.
    clickhouse_batch_size: int = 500
    clickhouse_flush_interval_seconds: float = 2.0

    # ── Continuous Detection Validation scheduler (Theme 2h: t2h-bas) ──
    # The BAS agent replays a synthetic OCSF catalogue every
    # ``bas_scan_interval_seconds`` and opens proactive cases on drift.
    # Disable on dev boxes that don't want the periodic noise; the
    # ``POST /detection-validation/scan`` endpoint remains usable.
    bas_scheduler_enabled: bool = True
    # Default cadence: once per day. Tunable per-deployment; deliberately
    # not minute-frequency because each run replays the full catalogue
    # against the live engine and opens cases on drift.
    bas_scan_interval_seconds: int = 24 * 3600
    # Initial delay after process boot before the first scan. Small in
    # dev so you see a run quickly; bump in prod so a fleet rolling
    # restart doesn't fire N concurrent BAS scans simultaneously.
    bas_initial_delay_seconds: int = 60
    # Hard stop per scan so a stuck rule pack can't pin the scheduler.
    # The detection engine itself is fast (ms per event) — anything past
    # this is almost certainly a bug in newly-loaded content.
    bas_scan_timeout_seconds: int = 300

    # ── Closed-loop Exposure scheduler (Theme 3a: t3a-closed-loop) ──
    # The Exposure agent sweeps Cyble CTI feeds (dark-web credential
    # exposure, brand intel / typosquats, ASM new surface, vuln intel),
    # opens proactive cases, routes deterministic containment through
    # the Responder, and re-verifies the same CTI signal after a window.
    # Disable on dev boxes that don't want the periodic case churn; the
    # ``POST /exposure/sweep`` endpoint remains usable for ad-hoc runs.
    exposure_scheduler_enabled: bool = True
    # Cadence between full sweeps. Hourly is the sweet spot — dark-web
    # leaks and typosquats appear unpredictably and an analyst who finds
    # a fresh credential exposure 24h after it landed has already lost.
    exposure_scan_interval_seconds: int = 60 * 60
    # Initial delay so a fleet rolling-restart doesn't fire N concurrent
    # exposure sweeps. Small in dev for fast feedback.
    exposure_initial_delay_seconds: int = 90
    # Hard stop per tenant sweep. Four CTI tool calls + graph writes +
    # case + responder routing should be well under a minute even with
    # a real LLM in the loop; anything past this is almost certainly a
    # stuck downstream API.
    exposure_sweep_timeout_seconds: int = 180
    # Re-verification window: once an exposure case is opened, the
    # agent re-queries the same CTI signal after this interval. If the
    # signal is gone we close the case (CLOSED_BENIGN); if it persists
    # we escalate. 24h matches typical takedown / credential-reset SLA.
    exposure_verification_window_seconds: int = 24 * 3600

    # ──────────────────────────────────────────────────────────────
    # Threat Actor Profiling agent (t3e-actor-profiling).
    # ──────────────────────────────────────────────────────────────
    # The Actor Profiler scans tenant IOCs, resolves canonical actor
    # profiles via ``cti.actor_lookup``, and materialises tenant-scoped
    # ``ThreatActor`` / ``ActorIOCLink`` rows plus ``ATTRIBUTED_TO``
    # graph edges. Disable on dev boxes where the periodic sweep isn't
    # useful; the ad-hoc ``POST /actors/sweep`` endpoint stays available.
    actor_profiler_scheduler_enabled: bool = True
    # Cadence between full sweeps. Slower than Exposure because
    # attribution drifts on hour-to-day timescales, not minute-to-hour.
    # 30 min is plenty fresh for the actor-card UI and keeps the demo
    # CTI mock from being hammered.
    actor_profiler_scan_interval_seconds: int = 30 * 60
    # Initial delay so rolling restarts don't fan out N concurrent
    # actor-lookup calls.
    actor_profiler_initial_delay_seconds: int = 60
    # Hard stop per tenant sweep. Worst case: scan_limit IOCs × one
    # enrich_ioc call + one actor_lookup per distinct handle + graph
    # writes. Even at 500 IOCs with cold caches this should land under
    # 60s; the 120s ceiling is the "downstream API is stuck" tripwire.
    actor_profiler_sweep_timeout_seconds: int = 120

    # ──────────────────────────────────────────────────────────────
    # Federated cross-tenant signal aggregation (t3b-federated).
    # ──────────────────────────────────────────────────────────────
    # Hash of the current consent terms a tenant must accept to
    # contribute. Rotate when the terms change; existing consent rows
    # under a previous hash are ignored by the aggregator until the
    # tenant re-consents under the new hash. Stored as a 64-char hex
    # SHA-256 so audit logs can pin which terms version applied.
    federation_terms_hash: str = (
        "0" * 64  # dev default; production rotates per deployment.
    )
    # k-anonymity threshold. The aggregator refuses to emit a count
    # for any (signal_class, signal_key) backed by fewer than this
    # many *distinct* contributing tenants. 5 is the common floor;
    # tune up for very small fleets to avoid re-identification.
    federation_k_anonymity: int = 5
    # Differential-privacy epsilon for the Laplace mechanism applied
    # to counts. Smaller = more privacy / more noise. ε=1.0 is a
    # common operational midpoint for counts; the test suite asserts
    # the noise distribution against this value.
    federation_dp_epsilon: float = 1.0
    # Sensitivity Δf of the count query. One tenant's contribution
    # can change the true count by at most this; for a "distinct
    # contributing tenants" count, Δf = 1.
    federation_dp_sensitivity: float = 1.0
    # Ingest window: only signals contributed within this many days
    # count toward an aggregate. Keeps stale tenant footprints from
    # dominating queries forever and bounds the impact of an opt-out
    # request (anything older than the window is no longer queried).
    federation_window_days: int = 30

    # ──────────────────────────────────────────────────────────────
    # Brand Responder (t3c-brand-takedown).
    # ──────────────────────────────────────────────────────────────
    # Minimum score a typosquat must reach to be recorded as a
    # candidate at all. Below this we treat the detector hit as
    # noise and drop it. Mirrors detector.detect_typosquats(min_score=)
    # so operators can tune from one place.
    brand_min_candidate_score: int = 30
    # Score threshold above which the Responder Agent auto-files a
    # takedown without HITL. Plan §3d calls for "policy-gated
    # autonomous takedown"; anything between min_candidate and this
    # threshold is parked in NEW for human triage.
    brand_auto_takedown_threshold: int = 80
    # Default fan-out channels for an auto-filed takedown. Order
    # matters only for status_history readability; submissions
    # themselves are independent.
    brand_default_channels: list[str] = [
        "registrar_abuse",
        "host_abuse",
        "safe_browsing",
    ]
    # Scheduler controls — mirror the Exposure scheduler shape so an
    # operator who already knows one knob set knows the other. The
    # Brand Responder runs less often than the broad Exposure sweep
    # because takedowns are downstream of brand-intel and we want to
    # give registrars time to action what we already filed.
    brand_scheduler_enabled: bool = True
    brand_scan_interval_seconds: int = 6 * 60 * 60  # 6 hours
    brand_initial_delay_seconds: int = 120
    brand_sweep_timeout_seconds: int = 180

    # ──────────────────────────────────────────────────────────────
    # Third-party / Supply-Chain Risk Fusion (t3f-supply-chain).
    # ──────────────────────────────────────────────────────────────
    # Per-tenant agent that fuses CTI signals (dark-web mentions,
    # brand intel, ASM exposures, vuln intel) against the tenant's
    # declared third-party footprint and opens proactive cases when
    # a vendor's rolling risk score crosses the configured threshold.
    supply_chain_scheduler_enabled: bool = True
    # Cadence between sweeps. Slower than Exposure (4h vs 1h) because
    # third-party signals shift on hour-to-day timescales and the
    # CTI tools we hammer aren't free; we trade freshness for cost.
    supply_chain_scan_interval_seconds: int = 4 * 60 * 60
    # Initial delay so a fleet rolling-restart doesn't fan out N
    # concurrent CTI calls.
    supply_chain_initial_delay_seconds: int = 90
    # Hard stop per tenant sweep. Each vendor in the catalogue costs
    # ~4 CTI tool calls + graph writes; even a tenant with 25 vendors
    # should land well under this ceiling.
    supply_chain_sweep_timeout_seconds: int = 240
    # Open a proactive Case when the rolling 30-day risk score for a
    # vendor crosses this threshold. Tuned against the deterministic
    # mock CTI mocks: a critical vendor with one high-confidence
    # darkweb hit + one ransomware-CVE clears 90 with multiplier=2.0.
    # Operators can lower this in dev to validate end-to-end without
    # heavy seed data.
    supply_chain_case_open_threshold: int = 90
    # Length of the rolling window over which past-sweep signals are
    # summed into the per-vendor score. Longer = catches accumulating
    # risk; shorter = recency-biased.
    supply_chain_rolling_window_days: int = 30

    # ──────────────────────────────────────────────────────────────
    # Multi-region active-active SaaS (t6-multi-region).
    # ──────────────────────────────────────────────────────────────
    # The region this process is serving. The router compares it to
    # each tenant's home_region to decide whether to serve the request
    # locally or forward it to the home-region peer. ``us-east-1``
    # is the dev default — production deployments override per region.
    region_id: str = "us-east-1"
    # Comma-separated list of every region in the active-active mesh,
    # in the form ``region_id|base_url|residency_zone``. Example::
    #     us-east-1|https://us-east.aisoc.local|us
    #     eu-west-1|https://eu-west.aisoc.local|eu
    # The local region is allowed to appear in the list; it is matched
    # by ``region_id`` and used to compute the residency zone of the
    # active deployment.
    region_peers: str = "us-east-1|http://localhost:8478|us"
    # Default residency zone for tenants whose ``home_region`` is not
    # explicitly set. ``us`` and ``eu`` are the two we model in the
    # tests; production rolls out one zone per region.
    region_default_residency_zone: str = "us"
    # Hard refusal: if a tenant's home_region falls outside this set,
    # reject requests with a 451 ("Unavailable For Legal Reasons")
    # rather than silently routing them. Empty = no restriction.
    region_allowed_residency_zones: str = ""


settings = Settings()
settings.db_path.parent.mkdir(parents=True, exist_ok=True)

# Production safety: refuse to boot with the dev defaults still in place.
# `env=prod` is the only environment where this trips — dev/test/demo all
# happily run with the publicly-known dev secret.
if settings.env.lower() in {"prod", "production"}:
    if "dev-secret" in settings.jwt_secret_key or len(settings.jwt_secret_key) < 32:
        raise RuntimeError(
            "AISOC_JWT_SECRET_KEY must be set to a 32+ byte secret in production"
        )
    if settings.dev_allow_anon_tenant:
        raise RuntimeError(
            "AISOC_DEV_ALLOW_ANON_TENANT must be false in production"
        )
    if not settings.connector_secrets_key:
        raise RuntimeError(
            "AISOC_CONNECTOR_SECRETS_KEY must be set (44-char Fernet key) in production"
        )
