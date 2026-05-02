from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    # Service
    service_name: str = "aisoc-fusion"
    http_port: int = Field(default=8003, alias="HTTP_PORT")
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")
    environment: str = Field(default="development", alias="ENVIRONMENT")

    # Kafka
    kafka_bootstrap_servers: str = Field(
        default="localhost:9092", alias="KAFKA_BOOTSTRAP_SERVERS"
    )
    kafka_topic_alerts_raw: str = Field(
        default="aisoc.alerts.raw", alias="KAFKA_TOPIC_ALERTS_RAW"
    )
    kafka_topic_alerts_fused: str = Field(
        default="aisoc.alerts.fused", alias="KAFKA_TOPIC_ALERTS_FUSED"
    )
    kafka_consumer_group: str = Field(
        default="aisoc-fusion-consumer", alias="KAFKA_CONSUMER_GROUP"
    )

    # Redis
    redis_url: str = Field(default="redis://localhost:6379/2", alias="REDIS_URL")
    dedup_window_seconds: int = Field(default=300, alias="DEDUP_WINDOW_SECONDS")
    correlation_window_seconds: int = Field(
        default=3600, alias="CORRELATION_WINDOW_SECONDS"
    )

    # Database
    database_url: str = Field(
        default="postgresql+asyncpg://aisoc:aisoc_secret@localhost:5432/aisoc",
        alias="DATABASE_URL",
    )

    # Fusion settings
    dedup_similarity_threshold: float = Field(
        default=0.85, alias="DEDUP_SIMILARITY_THRESHOLD"
    )
    max_alerts_per_incident: int = Field(default=500, alias="MAX_ALERTS_PER_INCIDENT")
    incident_auto_close_hours: int = Field(
        default=72, alias="INCIDENT_AUTO_CLOSE_HOURS"
    )

    # Enrichment service
    enrichment_service_url: str = Field(
        default="http://localhost:8082", alias="ENRICHMENT_SERVICE_URL"
    )

    class Config:
        env_file = ".env"
        populate_by_name = True


settings = Settings()
