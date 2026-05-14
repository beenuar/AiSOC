from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        populate_by_name=True,
        extra="ignore",
    )

    database_url: str = Field(
        default="postgresql+asyncpg://aisoc:aisoc@localhost:5432/aisoc",
        validation_alias=AliasChoices("DATABASE_URL", "UEBA_DATABASE_URL"),
    )

    kafka_bootstrap_servers: str = Field(
        default="localhost:9092",
        validation_alias=AliasChoices("KAFKA_BOOTSTRAP_SERVERS", "UEBA_KAFKA_BOOTSTRAP_SERVERS"),
    )
    kafka_input_topic: str = Field(
        default="security.events",
        validation_alias=AliasChoices("KAFKA_INPUT_TOPIC", "UEBA_KAFKA_INPUT_TOPIC"),
    )
    kafka_output_topic: str = Field(
        default="ueba.anomalies",
        validation_alias=AliasChoices("KAFKA_OUTPUT_TOPIC", "UEBA_KAFKA_OUTPUT_TOPIC"),
    )
    kafka_consumer_group: str = Field(
        default="ueba-service",
        validation_alias=AliasChoices("KAFKA_CONSUMER_GROUP", "UEBA_KAFKA_CONSUMER_GROUP"),
    )

    baseline_window_days: int = Field(
        default=30,
        validation_alias=AliasChoices("BASELINE_WINDOW_DAYS", "UEBA_BASELINE_WINDOW_DAYS"),
    )
    anomaly_threshold: float = Field(
        default=3.0,
        validation_alias=AliasChoices("ANOMALY_THRESHOLD", "UEBA_ANOMALY_THRESHOLD"),
    )
    peer_group_min_size: int = Field(
        default=3,
        validation_alias=AliasChoices("PEER_GROUP_MIN_SIZE", "UEBA_PEER_GROUP_MIN_SIZE"),
    )
    scoring_batch_size: int = Field(
        default=100,
        validation_alias=AliasChoices("SCORING_BATCH_SIZE", "UEBA_SCORING_BATCH_SIZE"),
    )

    otel_endpoint: str = Field(
        default="http://localhost:4317",
        validation_alias=AliasChoices("OTEL_ENDPOINT", "UEBA_OTEL_ENDPOINT"),
    )
    service_name: str = Field(
        default="aisoc-ueba",
        validation_alias=AliasChoices("SERVICE_NAME", "UEBA_SERVICE_NAME"),
    )

    host: str = Field(
        default="0.0.0.0",
        validation_alias=AliasChoices("HOST", "UEBA_HOST"),
    )
    port: int = Field(
        default=8004,
        validation_alias=AliasChoices("PORT", "UEBA_PORT"),
    )


settings = Settings()
