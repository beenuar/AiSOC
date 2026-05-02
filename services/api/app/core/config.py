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
