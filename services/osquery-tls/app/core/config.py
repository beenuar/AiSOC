"""Configuration settings for the AiSOC osquery TLS service.

All settings are read from environment variables prefixed with
``AISOC_OSQUERY_TLS_``, with sane defaults for local dev.
"""

from __future__ import annotations

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AISOC_OSQUERY_TLS_",
        env_file=".env",
        populate_by_name=True,
        extra="ignore",
    )

    # --- Database -------------------------------------------------------
    # Reuses the main API Postgres; all tables live in the `osquery_tls` schema.
    #
    # ``env_prefix`` means every other field here is read as
    # ``AISOC_OSQUERY_TLS_<FIELD>``, and this one used to be as well — while
    # ``docker-compose.yml`` set plain ``DATABASE_URL`` on this service, as it
    # does for every other. The variable was therefore inert: the service fell
    # back to the default below, which names the *owner* role, so pointing the
    # deployment at the DML-only runtime role changed nothing here.
    #
    # Both spellings now resolve, unprefixed first, the same convention
    # ``services/ueba`` and ``services/fusion`` already use. The alias replaces
    # the prefix for this field only; the rest of the settings are untouched.
    database_url: str = Field(
        default="postgresql+asyncpg://aisoc:aisoc@localhost:5432/aisoc",
        validation_alias=AliasChoices("DATABASE_URL", "AISOC_OSQUERY_TLS_DATABASE_URL"),
    )

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
    # Public hostname operators point agents' ``--tls_hostname`` at. Set this
    # per deployment. Declared but not yet read anywhere in this service —
    # flag-file rendering still has to be wired up.
    public_hostname: str = "localhost"

    # --- Pack stubs (overridden fully in PR5) ---------------------------
    # Default query interval for the baseline schedule shipped to every node.
    default_interval_seconds: int = 300

    # --- Log level ------------------------------------------------------
    log_level: str = "INFO"


settings = Settings()
