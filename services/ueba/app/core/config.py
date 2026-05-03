from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="UEBA_", env_file=".env", extra="ignore")

    # Database
    database_url: str = "postgresql+asyncpg://aisoc:aisoc@localhost:5432/aisoc"

    # Kafka
    kafka_bootstrap_servers: str = "localhost:9092"
    kafka_input_topic: str = "security.events"
    kafka_output_topic: str = "ueba.anomalies"
    kafka_consumer_group: str = "ueba-service"

    # UEBA tuning
    baseline_window_days: int = 30        # days of history for baseline computation
    anomaly_threshold: float = 3.0        # z-score threshold for anomaly flagging
    peer_group_min_size: int = 3          # minimum peers for peer-group analysis
    scoring_batch_size: int = 100         # events processed per scoring batch

    # OTel
    otel_endpoint: str = "http://localhost:4317"
    service_name: str = "aisoc-ueba"

    # API
    host: str = "0.0.0.0"
    port: int = 8004


settings = Settings()
