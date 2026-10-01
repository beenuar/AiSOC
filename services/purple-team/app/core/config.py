"""Purple Team service configuration."""

from __future__ import annotations

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="PURPLE_TEAM_",
        env_file=".env",
        populate_by_name=True,
        extra="ignore",
    )

    # Database.
    #
    # ``env_prefix`` means every other field here is read as
    # ``PURPLE_TEAM_<FIELD>``, and this one used to be as well — while
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
        validation_alias=AliasChoices("DATABASE_URL", "PURPLE_TEAM_DATABASE_URL"),
    )

    # Caldera integration. The key has no default on purpose: it used to be
    # the literal `ADMIN123`, which is Caldera's own published first-run
    # credential, so a deployment that never configured Caldera still built a
    # client holding it and pointed that client at whatever `caldera_url`
    # resolved to. The failure mode was not "purple-team does not work", it
    # was "purple-team authenticates to a Caldera instance with the default
    # password", which succeeds against any Caldera nobody rotated.
    caldera_url: str = "http://localhost:8888"
    caldera_api_key: str = ""

    # Atomic Red Team
    art_repo_path: str = "/opt/atomic-red-team"
    art_atomics_path: str = "/opt/atomic-red-team/atomics"

    # There used to be an ``attack_stix_url`` here, defaulting to the MITRE CTI
    # bundle on a public CDN "for coverage mapping". Nothing in this service
    # ever read it — not the coverage mapper, not the drift scheduler, not the
    # routes. A dead setting is not harmless when its default is an external
    # host: it is documented, it is settable, and it makes reaching a CDN look
    # like the decision somebody already took. The services that do need the
    # bundle (``agents``, ``ingest``) read it from ``ATTCK_DATA_PATH`` on disk.
    # If coverage mapping ever needs it here, take the same local-file route.

    # OTel
    otel_endpoint: str = "http://localhost:4317"
    service_name: str = "aisoc-purple-team"

    # API
    host: str = "0.0.0.0"
    port: int = 8006

    # Drift snapshot scheduler
    # Default cadence: weekly (7 days) — matches the 2026 KPI bar's
    # "delta vs. last week" mandate. Set to 0 to disable.
    drift_snapshot_interval_seconds: int = 7 * 24 * 60 * 60
    drift_scheduler_enabled: bool = True


settings = Settings()
