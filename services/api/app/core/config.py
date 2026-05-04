"""
AiSOC API Configuration
Cyble Open-Source AI Security Operations Center
MIT License
"""
from functools import lru_cache
from typing import Annotated, Any

from pydantic import AnyHttpUrl, PostgresDsn, RedisDsn, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # App
    APP_NAME: str = "AiSOC API"
    APP_VERSION: str = "0.1.0"
    ENV: str = "development"
    ENVIRONMENT: str = "development"  # alias for ENV
    VERSION: str = "0.1.0"           # alias for APP_VERSION
    DEBUG: bool = False
    API_PREFIX: str = "/api/v1"

    # Security
    SECRET_KEY: str = "change-me-in-production-at-least-32-chars"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    ALGORITHM: str = "HS256"

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

    # Demo mode (hosted at demo.aisoc.dev)
    # When AISOC_DEMO_MODE=true the API rejects mutating requests outside the
    # demo tenant with 403, surfaces a banner, and pre-seeds canonical data.
    AISOC_DEMO_MODE: bool = False
    AISOC_DEMO_TENANT: str = "demo"
    AISOC_DEMO_BANNER: str = (
        "Demo data resets daily at 00:00 UTC. All write actions are disabled."
    )

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


settings = get_settings()
