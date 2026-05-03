from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="HONEYTOKEN_", env_file=".env", extra="ignore")

    # Database
    database_url: str = "postgresql+asyncpg://aisoc:aisoc@localhost:5432/aisoc"

    # Webhook alerting
    alert_webhook_url: str = ""
    alert_webhook_secret: str = "changeme"

    # Token defaults
    token_ttl_days: int = 365

    # OTel
    otel_endpoint: str = "http://localhost:4317"
    service_name: str = "aisoc-honeytokens"

    # API
    host: str = "0.0.0.0"
    port: int = 8005


settings = Settings()
