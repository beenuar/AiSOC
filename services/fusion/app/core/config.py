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
    alert_sink_enabled: bool = Field(default=True, alias="AISOC_ALERT_SINK_ENABLED")

    # Redis
    redis_url: str = Field(default="redis://localhost:6379/2", alias="REDIS_URL")
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


settings = Settings()
