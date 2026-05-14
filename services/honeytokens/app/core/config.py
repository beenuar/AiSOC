from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="HONEYTOKEN_", env_file=".env", extra="ignore")

    # Database
    database_url: str = "postgresql+asyncpg://aisoc:aisoc@localhost:5432/aisoc"

    # Webhook alerting. ``alert_webhook_secret`` previously defaulted to the
    # literal string ``"changeme"`` — anyone running this service with the
    # defaults would sign every outbound honeytoken alert with a public secret,
    # so a downstream verifier couldn't distinguish a real trigger from a
    # forged one. We now default to empty and require operators to wire a
    # real HMAC secret before alerts will be signed.
    alert_webhook_url: str = ""
    alert_webhook_secret: str = ""

    # Token defaults
    token_ttl_days: int = 365

    # OTel
    otel_endpoint: str = "http://localhost:4317"
    service_name: str = "aisoc-honeytokens"

    # API
    host: str = "0.0.0.0"
    port: int = 8005


settings = Settings()
