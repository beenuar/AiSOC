"""Configuration settings for the AiSOC osquery TLS service.

All settings are read from environment variables prefixed with
``AISOC_OSQUERY_TLS_``, with sane defaults for local dev.
"""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AISOC_OSQUERY_TLS_",
        env_file=".env",
        extra="ignore",
    )

    # --- Database -------------------------------------------------------
    # Reuses the main API Postgres; all tables live in the `osquery_tls` schema.
    database_url: str = "postgresql+asyncpg://aisoc:aisoc@localhost:5432/aisoc"

    # --- Ingest service -------------------------------------------------
    # Where normalised osquery rows are forwarded to.
    ingest_url: str = "http://ingest:8080"

    # --- Enrollment auth ------------------------------------------------
    # The enroll secret that osqueryd must present. In production this should
    # be a long random string stored in a secrets manager and rotated
    # periodically.  Per-tenant secrets are looked up by the ``X-AiSOC-Tenant``
    # request header; this value is used as the fallback single-tenant secret.
    enroll_secret: str = "change-me-in-production"

    # --- mTLS -----------------------------------------------------------
    # When True the service validates the client TLS certificate on every
    # request after enroll.  The client cert CN must match host_identifier.
    require_client_cert: bool = False

    # --- Service identity -----------------------------------------------
    # Public hostname (used to build TLS flag-file docs).
    public_hostname: str = "osquery.tryaisoc.com"

    # --- Pack stubs (overridden fully in PR5) ---------------------------
    # Default query interval for the baseline schedule shipped to every node.
    default_interval_seconds: int = 300

    # --- Log level ------------------------------------------------------
    log_level: str = "INFO"


settings = Settings()
