from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        populate_by_name=True,
        extra="ignore",
    )

    # Service
    service_name: str = "aisoc-fusion"
    http_port: int = Field(default=8003, alias="HTTP_PORT")
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")
    environment: str = Field(default="development", alias="ENVIRONMENT")

    # Kafka
    kafka_bootstrap_servers: str = Field(default="localhost:9092", alias="KAFKA_BOOTSTRAP_SERVERS")
    kafka_topic_alerts_raw: str = Field(default="aisoc.alerts.raw", alias="KAFKA_TOPIC_ALERTS_RAW")
    kafka_topic_alerts_fused: str = Field(default="aisoc.alerts.fused", alias="KAFKA_TOPIC_ALERTS_FUSED")
    kafka_consumer_group: str = Field(default="aisoc-fusion-consumer", alias="KAFKA_CONSUMER_GROUP")
    # Phase 3.1 spine bridge — ingest's normalized-event topic. Fusion promotes
    # findings + high/critical telemetry into RawAlerts (app/services/promoter.py).
    kafka_topic_raw_events: str = Field(default="aisoc.raw_events", alias="KAFKA_TOPIC_RAW_EVENTS")
    event_promotion_enabled: bool = Field(default=True, alias="AISOC_EVENT_PROMOTION_ENABLED")
    # Phase 3.1 spine bridge — persist fused (non-duplicate) alerts to the
    # Postgres alert store (app/services/alert_sink.py). Fail-soft by design.
    #
    # Disabling this also disables the durable DLQ (main.py wires PostgresDLQ
    # only when the sink exists) and the session store. The worker then runs
    # in an explicitly persistence-free mode: alerts stream over Kafka but no
    # row is written, and a refused event is only logged. Do not read a
    # committed Kafka offset in that mode as proof of durable capture.
    alert_sink_enabled: bool = Field(default=True, alias="AISOC_ALERT_SINK_ENABLED")
    # Bounded time for one insert/duplicate-verification. A hung connection
    # must surface as a retryable outcome, not stall the partition forever.
    alert_sink_operation_timeout_seconds: float = Field(default=10.0, alias="AISOC_ALERT_SINK_OPERATION_TIMEOUT_SECONDS")

    # Consumer durability. Transient persistence/publish failures are retried
    # with exponential backoff + jitter and the Kafka offset is not committed
    # until the message is durable (or captured by the DLQ). The recovery
    # interval is the long, capped delay used when the primary store *and*
    # the DLQ are both unreachable: the message is held, not dropped.
    consumer_max_retries: int = Field(default=8, alias="AISOC_CONSUMER_MAX_RETRIES")
    consumer_retry_base_seconds: float = Field(default=0.5, alias="AISOC_CONSUMER_RETRY_BASE_SECONDS")
    consumer_retry_max_seconds: float = Field(default=30.0, alias="AISOC_CONSUMER_RETRY_MAX_SECONDS")
    consumer_recovery_retry_seconds: float = Field(default=10.0, alias="AISOC_CONSUMER_RECOVERY_RETRY_SECONDS")
    kafka_send_timeout_seconds: float = Field(default=30.0, alias="AISOC_KAFKA_SEND_TIMEOUT_SECONDS")
    # How long stop() waits for the in-flight message before closing clients.
    # Work that does not finish is left uncommitted, so it is re-delivered.
    shutdown_grace_seconds: float = Field(default=15.0, alias="AISOC_SHUTDOWN_GRACE_SECONDS")

    # Phase A1 — archive every normalized OCSF event into the ClickHouse event
    # lake (app/services/lake_writer.py). Independent of promotion: an event
    # that isn't promoted to an alert must still be queryable via /lake/sql.
    # Fail-soft; disables itself if clickhouse-driver / the server is absent.
    lake_writer_enabled: bool = Field(default=True, alias="AISOC_LAKE_WRITER_ENABLED")
    clickhouse_host: str = Field(default="localhost", alias="CLICKHOUSE_HOST")
    clickhouse_port: int = Field(default=9000, alias="CLICKHOUSE_PORT")
    clickhouse_database: str = Field(default="aisoc", alias="CLICKHOUSE_DATABASE")
    clickhouse_user: str = Field(default="default", alias="CLICKHOUSE_USER")
    clickhouse_password: str = Field(default="", alias="CLICKHOUSE_PASSWORD")
    lake_batch_size: int = Field(default=100, alias="AISOC_LAKE_BATCH_SIZE")
    lake_batch_max_age_seconds: float = Field(default=2.0, alias="AISOC_LAKE_BATCH_MAX_AGE_SECONDS")
    # A failed ClickHouse batch is retained and retried, not dropped. These
    # bound that retention: when the cap is reached the oldest rows are
    # discarded with an explicit counter/log, never silently.
    lake_max_buffer_rows: int = Field(default=10000, alias="AISOC_LAKE_MAX_BUFFER_ROWS")
    lake_reconnect_base_seconds: float = Field(default=0.5, alias="AISOC_LAKE_RECONNECT_BASE_SECONDS")
    lake_reconnect_max_seconds: float = Field(default=30.0, alias="AISOC_LAKE_RECONNECT_MAX_SECONDS")
    # A server-side/data error is retried this many times, then the batch is
    # dropped explicitly. Connection errors keep the batch (bounded above)
    # because the store being down is not evidence that the rows are bad.
    lake_max_data_failures: int = Field(default=5, alias="AISOC_LAKE_MAX_DATA_FAILURES")

    # Phase A2 — evaluate the executable native detection corpus against the
    # live event stream (app/services/detection_engine.py). Each firing rule
    # becomes a RawAlert routed through fusion.
    detection_engine_enabled: bool = Field(default=True, alias="AISOC_DETECTION_ENGINE_ENABLED")
    # Stateful / windowed detections (brute force, spray, scans) — Redis-backed
    # sliding-window thresholds evaluated alongside the stateless corpus.
    windowed_detection_enabled: bool = Field(default=True, alias="AISOC_WINDOWED_DETECTION_ENABLED")

    # Phase A4 — consume the UEBA behavioral-anomaly stream and fold each
    # entity's latest anomaly into alert confidence + anomaly score at fuse
    # time (app/services/ueba_signal.py). Completes the three-model story.
    ueba_fusion_enabled: bool = Field(default=True, alias="AISOC_UEBA_FUSION_ENABLED")
    kafka_topic_ueba_anomalies: str = Field(default="ueba.anomalies", alias="KAFKA_TOPIC_UEBA_ANOMALIES")
    ueba_signal_ttl_seconds: int = Field(default=86400, alias="AISOC_UEBA_SIGNAL_TTL_SECONDS")

    # Phase C4 — form/extend attack chains at fuse time so related alerts
    # auto-collapse into one ordered incident (app/services/attack_chain_grouper.py).
    attack_chain_grouping_enabled: bool = Field(default=True, alias="AISOC_ATTACK_CHAIN_GROUPING_ENABLED")
    attack_chain_window_seconds: int = Field(default=3600, alias="AISOC_ATTACK_CHAIN_WINDOW_SECONDS")

    # Redis. Dedup/correlation are hints, not the source of truth (Postgres is),
    # so a Redis outage must degrade rather than raise. Short socket timeouts
    # keep a black-holed Redis from stalling the alert path.
    redis_url: str = Field(default="redis://localhost:6379/2", alias="REDIS_URL")
    redis_socket_timeout_seconds: float = Field(default=5.0, alias="AISOC_REDIS_SOCKET_TIMEOUT_SECONDS")
    redis_connect_timeout_seconds: float = Field(default=5.0, alias="AISOC_REDIS_CONNECT_TIMEOUT_SECONDS")
    dedup_window_seconds: int = Field(default=300, alias="DEDUP_WINDOW_SECONDS")
    correlation_window_seconds: int = Field(default=3600, alias="CORRELATION_WINDOW_SECONDS")

    # Database
    database_url: str = Field(
        default="postgresql+asyncpg://aisoc:aisoc_secret@localhost:5432/aisoc",
        alias="DATABASE_URL",
    )

    # Fusion settings
    dedup_similarity_threshold: float = Field(default=0.85, alias="DEDUP_SIMILARITY_THRESHOLD")
    max_alerts_per_incident: int = Field(default=500, alias="MAX_ALERTS_PER_INCIDENT")
    incident_auto_close_hours: int = Field(default=72, alias="INCIDENT_AUTO_CLOSE_HOURS")

    # Risk-Based Alerting (RBA) — accumulates signals onto entities (user / host /
    # ip / domain) before promotion. Targets the published 2026 KPI bar of
    # alert-to-incident ratio ≥ 50:1.
    rba_enabled: bool = Field(default=True, alias="AISOC_FEATURE_RBA")
    rba_promotion_threshold: float = Field(default=80.0, alias="RBA_PROMOTION_THRESHOLD")
    rba_window_seconds: int = Field(default=86400, alias="RBA_WINDOW_SECONDS")  # 24h decay window
    rba_decay_half_life_seconds: int = Field(default=14400, alias="RBA_DECAY_HALF_LIFE_SECONDS")  # 4h half-life
    # Severity points contributed by each correlated alert. Keep additive and
    # capped so a single noisy detection can't promote on its own.
    rba_severity_weights_critical: float = Field(default=40.0, alias="RBA_W_CRITICAL")
    rba_severity_weights_high: float = Field(default=20.0, alias="RBA_W_HIGH")
    rba_severity_weights_medium: float = Field(default=8.0, alias="RBA_W_MEDIUM")
    rba_severity_weights_low: float = Field(default=3.0, alias="RBA_W_LOW")
    rba_severity_weights_info: float = Field(default=1.0, alias="RBA_W_INFO")
    rba_max_top_entities: int = Field(default=100, alias="RBA_MAX_TOP_ENTITIES")

    # Detection confidence + explainability — every fused alert carries a
    # high/medium/low label and an evidence chain. Disabled only as a
    # break-glass; the UI degrades gracefully (no chip / no rationale panel).
    confidence_enabled: bool = Field(default=True, alias="AISOC_FEATURE_CONFIDENCE")

    # Vuln↔alert correlation w/ exploit-in-wild boost (Tier 3.5)
    vuln_boost_enabled: bool = Field(default=True, alias="AISOC_VULN_BOOST")

    # Enrichment service
    enrichment_service_url: str = Field(default="http://localhost:8082", alias="ENRICHMENT_SERVICE_URL")
    # Fuse-time streaming enrichment: call the enrichment service for each
    # alert's IOCs and merge TI / vuln matches into fused.enrichments so the
    # confidence threat_intel factor + exploit-in-wild boost actually fire.
    # Best-effort + short timeout; no provider keys => empty result (no fake TI).
    fuse_enrichment_enabled: bool = Field(default=True, alias="AISOC_FUSE_ENRICHMENT")
    fuse_enrichment_timeout_seconds: float = Field(default=3.0, alias="AISOC_FUSE_ENRICHMENT_TIMEOUT")
    fuse_enrichment_risk_floor: float = Field(default=50.0, alias="AISOC_FUSE_ENRICHMENT_RISK_FLOOR")


settings = Settings()
