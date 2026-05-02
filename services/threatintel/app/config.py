"""Configuration for the AiSOC Threat Intelligence service."""
from __future__ import annotations

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Service
    APP_NAME: str = "AiSOC ThreatIntel"
    VERSION: str = "0.1.0"
    ENVIRONMENT: str = "development"

    # Redis (bloom filter + cache)
    REDIS_URL: str = "redis://redis:6379/2"
    BLOOM_CAPACITY: int = 10_000_000
    BLOOM_ERROR_RATE: float = 0.001

    # OpenSearch
    OPENSEARCH_HOST: str = "opensearch"
    OPENSEARCH_PORT: int = 9200
    OPENSEARCH_USER: str = ""
    OPENSEARCH_PASSWORD: str = ""
    OPENSEARCH_INDEX_IOC: str = "threatintel-iocs"
    OPENSEARCH_INDEX_ACTOR: str = "threatintel-actors"

    # Qdrant
    QDRANT_HOST: str = "qdrant"
    QDRANT_PORT: int = 6333
    QDRANT_COLLECTION_IOC: str = "threatintel_iocs"

    # Neo4j
    NEO4J_URI: str = "bolt://neo4j:7687"
    NEO4J_USER: str = "neo4j"
    NEO4J_PASSWORD: str = "aisoc_secret"

    # Kafka
    KAFKA_BOOTSTRAP_SERVERS: str = "redpanda:9092"
    KAFKA_TOPIC_THREAT_INTEL: str = "aisoc.threat_intel"
    # Legacy alias
    KAFKA_BROKERS: str = "redpanda:9092"
    KAFKA_TOPIC_IOC: str = "aisoc.ioc_enrichments"

    # TAXII 2.1
    TAXII_URL: str = ""
    TAXII_USERNAME: str = ""
    TAXII_PASSWORD: str = ""
    TAXII_API_ROOT: str = ""
    TAXII_COLLECTION_IDS: str = ""   # comma-separated collection IDs

    # MISP
    MISP_URL: str = ""
    MISP_API_KEY: str = ""
    MISP_VERIFY_SSL: bool = True

    # OTX AlienVault
    OTX_API_KEY: str = ""
    OTX_BASE_URL: str = "https://otx.alienvault.com"

    # CISA KEV
    CISA_KEV_URL: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    # OpenCTI
    OPENCTI_URL: str = ""
    OPENCTI_TOKEN: str = ""

    # Poll intervals (seconds)
    TAXII_POLL_INTERVAL: int = 900      # 15 min
    MISP_POLL_INTERVAL: int = 1800      # 30 min
    OTX_POLL_INTERVAL: int = 1800       # 30 min
    CISA_KEV_POLL_INTERVAL: int = 86400 # 24 h
    # Legacy alias
    CISA_POLL_INTERVAL: int = 86400

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
