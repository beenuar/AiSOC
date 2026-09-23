"""
Application configuration for the AiSOC Slack bot.

All secrets (Slack tokens, AiSOC API keys) come from environment variables /
mounted secret files. The bot itself stores nothing — it only forwards
requests to ``services/api`` and ``services/actions``.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class SlackBotSettings(BaseSettings):
    """
    Runtime configuration for the Slack bot.

    Loaded from process environment (``.env`` is honoured for local dev).
    Field names match the env var names exactly so deployment manifests can
    map secrets directly without a translation table.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # --- Slack -------------------------------------------------------------

    SLACK_BOT_TOKEN: str = Field(
        default="",
        description="Slack bot user OAuth token (xoxb-…).",
    )
    SLACK_SIGNING_SECRET: str = Field(
        default="",
        description=(
            "Slack signing secret used by Bolt to verify request signatures. "
            "Required in production; an empty value disables signature checks "
            "and is only acceptable for local pytest runs."
        ),
    )

    # --- AiSOC backend -----------------------------------------------------

    AISOC_API_BASE_URL: str = Field(
        default="http://aisoc-api:8000",
        description="Base URL for the services/api FastAPI app.",
    )
    AISOC_ACTIONS_BASE_URL: str = Field(
        default="http://aisoc-actions:8085",
        description="Base URL for the services/actions FastAPI app.",
    )
    AISOC_API_SERVICE_TOKEN: str = Field(
        default="",
        description=("aisoc_… API key the bot uses to call services/api. Must hold at least cases:read, cases:write, alerts:read."),
    )
    AISOC_ACTIONS_SERVICE_TOKEN: str = Field(
        default="",
        description=("aisoc_… API key for services/actions. May reuse the API service token if the same principal has actions:write."),
    )

    # --- Tenant + UX -------------------------------------------------------

    AISOC_DEFAULT_TENANT_ID: str = Field(
        default="00000000-0000-0000-0000-000000000000",
        description=(
            "Tenant UUID associated with this Slack workspace. v1 assumes a "
            "single Slack workspace ↔ single AiSOC tenant mapping; multi-"
            "tenant workspaces will be addressed in a later workstream."
        ),
    )
    AISOC_WEB_BASE_URL: str = Field(
        default="https://app.tryaisoc.com",
        description="Public web app URL used to deep-link case cards.",
    )

    # --- Proactive notification -------------------------------------------

    SLACK_APPROVALS_CHANNEL: str = Field(
        default="",
        description=(
            "Channel the bot posts approval cards into when an agent raises "
            "one. Empty disables proactive posting, which is the correct "
            "default: a bot that posts into a channel nobody chose is worse "
            "than one that posts nowhere."
        ),
    )
    AISOC_INTERNAL_TOKEN: str = Field(
        default="",
        description=(
            "Shared secret for /internal/* routes. These are called by other "
            "AiSOC services, never by Slack, so they carry no Slack signature "
            "and need their own check. Empty refuses every internal call "
            "outside dev mode."
        ),
    )

    # --- Service plumbing --------------------------------------------------

    AISOC_SLACK_BOT_PORT: int = Field(
        default=8089,
        description="Port the FastAPI app should listen on.",
    )
    AISOC_HTTP_TIMEOUT_SECONDS: float = Field(
        default=10.0,
        description="Default timeout for outbound HTTP calls to AiSOC services.",
    )

    # --- Helpers -----------------------------------------------------------

    @property
    def signature_verification_enabled(self) -> bool:
        """
        Bolt's signature verification is mandatory in production. Tests run
        without a signing secret, so we let them opt out explicitly.
        """
        return bool(self.SLACK_SIGNING_SECRET)


@lru_cache(maxsize=1)
def get_settings() -> SlackBotSettings:
    return SlackBotSettings()
