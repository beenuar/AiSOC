"""Configuration for the AiSOC Threat Intelligence service."""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # Service
    APP_NAME: str = "AiSOC ThreatIntel"
    VERSION: str = "0.1.0"
    ENVIRONMENT: str = "development"

    # Optional shared-secret gate for the /api/v1/actors/* HTTP surface.
    # When set, callers must present ``Authorization: Bearer <token>``
    # (constant-time compared). Unset keeps the historical internal-only
    # behaviour (unauthenticated). Mirrors the actions->api
    # ``AISOC_API_SERVICE_TOKEN`` inter-service-token convention.
    AISOC_THREATINTEL_SERVICE_TOKEN: str = ""

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
    KAFKA_TOPIC_IOC: str = "aisoc.ioc_enrichments"

    # TAXII 2.1
    TAXII_URL: str = ""
    TAXII_USERNAME: str = ""
    TAXII_PASSWORD: str = ""
    TAXII_API_ROOT: str = ""
    TAXII_COLLECTION_IDS: str = ""  # comma-separated collection IDs

    # MISP
    MISP_URL: str = ""
    MISP_API_KEY: str = ""
    MISP_VERIFY_SSL: bool = True

    # OTX AlienVault
    OTX_API_KEY: str = ""
    OTX_BASE_URL: str = "https://otx.alienvault.com"

    # CISA KEV
    CISA_KEV_URL: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    # NetAPI — keyless public IP and domain lists, CC BY 4.0.
    #
    # Off by default, and that is a measured choice rather than caution: a
    # first poll of the default datasets embeds ~169k indicators and grows the
    # Qdrant IOC collection by roughly a gigabyte. Both are one-time costs an
    # operator should opt into rather than inherit from an upgrade. The
    # figures and the reasoning are in apps/docs/docs/threat-intel/netapi.md.
    NETAPI_ENABLED: bool = False
    NETAPI_IPS_URL: str = "https://netapi.com/api2/netapi-compromised-ips.txt"
    # The short domain list is the default: it is the full list minus the
    # sinkholed domains, and it measured roughly half the ingest cost and half
    # the storage of the full one. Point this at
    # netapi-compromised-domains.txt for the full list.
    NETAPI_DOMAINS_URL: str = "https://netapi.com/api2/netapi-compromised-domains-short.txt"

    # OpenCTI
    OPENCTI_URL: str = ""
    OPENCTI_TOKEN: str = ""
    OPENCTI_VERIFY_SSL: bool = True

    # Poll intervals (seconds)
    TAXII_POLL_INTERVAL: int = 900  # 15 min
    MISP_POLL_INTERVAL: int = 1800  # 30 min
    OTX_POLL_INTERVAL: int = 1800  # 30 min
    OPENCTI_POLL_INTERVAL: int = 1800  # 30 min
    CISA_KEV_POLL_INTERVAL: int = 86400  # 24 h
    # Legacy alias
    CISA_POLL_INTERVAL: int = 86400
    # The lists are rebuilt on the publisher's schedule, and an unchanged one
    # costs a 304 with no body and no pipeline work, so polling hourly is
    # cheap. See the client docstring for the measured conditional-request
    # behaviour of each list.
    NETAPI_POLL_INTERVAL: int = 3600  # 1 h

    # Air-gap egress policy (Tier 3.1).
    # When enabled, public threat-intel feeds (OTX, CISA KEV, MISP/TAXII/
    # OpenCTI hosted on the public Internet) will refuse to register at
    # boot and any direct outbound HTTP from this service is blocked at
    # request time. Mirror the AiSOC API service contract so a single
    # AISOC_AIRGAPPED=1 in the deploy environment turns the whole stack
    # into zero-egress mode.
    AISOC_AIRGAPPED: bool = False
    AISOC_AIRGAP_ALLOWLIST: list[str] = []


settings = Settings()
