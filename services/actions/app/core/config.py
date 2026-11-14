"""Application configuration for the AiSOC Actions service.

Loaded once at import time from environment (and optional ``.env``). Two settings
matter for the ChatOps user-verification flow added in Wave 1:

* ``AISOC_CREDENTIAL_KEY`` — the same Fernet key the API + connectors services
  use. We only need it when the action payload itself ships an encrypted
  ``vault:v1:`` token (e.g. a Slack bot token persisted by the click-and-connect
  connector flow). See ``app.security.credential_vault``.
* ``AISOC_API_BASE_URL`` + ``AISOC_API_SERVICE_TOKEN`` — used to call the
  ``services/api`` ``add_timeline_event`` endpoint when a ChatOps response lands.

We deliberately do **not** auto-generate credential keys here. The actions
service is internal infrastructure, so missing config should fail loud, not
silently invent ephemeral keys that would break decryption on restart.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class ActionsSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    AISOC_API_BASE_URL: str = Field(
        default="http://aisoc-api:8000",
        description="Base URL of the services/api FastAPI app, e.g. http://aisoc-api:8000.",
    )
    AISOC_API_SERVICE_TOKEN: str = Field(
        default="",
        description=(
            "API-key token (aisoc_…) used by services/actions to call services/api "
            "endpoints that require cases:write. Mounted as a secret in production."
        ),
    )

    AISOC_CREDENTIAL_KEY: str = Field(
        default="",
        description=(
            "Fernet key shared with services/api + services/connectors. Required "
            "only when an action payload contains a vault:v1: ciphertext."
        ),
    )
    AISOC_CREDENTIAL_KEY_ROTATION_FROM: str = Field(
        default="",
        description="Comma-separated historical Fernet keys for transparent re-decryption.",
    )

    AISOC_FEATURE_CHATOPS_VERIFY: bool = Field(
        default=True,
        description="Master toggle for the Slack/Teams interactive user-verification action.",
    )

    # Depth 7.1 — mailbox remediation (search / purge / restore / sender
    # block) across the recipients of a reported phishing message.
    #
    # **Off by default, unlike every flag above it.** A capability that
    # reaches out of the platform and removes somebody's mail is not one an
    # upgrade should silently acquire: an operator who upgrades AiSOC has
    # consented to a new version, not to the platform being able to delete
    # from every mailbox in their tenant. Turning it on is a deliberate act,
    # and the arms say exactly that when it is off rather than simulating a
    # purge — a dry run reporting a send or a purge that never happened is
    # the defect that shipped in NotifySlackExecutor.
    AISOC_FEATURE_MAILBOX_REMEDIATION: bool = Field(
        default=False,
        description=(
            "Master toggle for mailbox remediation (search_mailboxes, purge_email, "
            "restore_email, block_sender, unblock_sender). Off by default: enabling it "
            "grants AiSOC the ability to remove mail from the tenant's mailboxes."
        ),
    )

    AISOC_CHATOPS_RESPONSE_SECRET: str = Field(
        default="",
        description=("HMAC secret used to sign ChatOps response tokens so we can verify a callback genuinely came from a message we sent."),
    )

    AISOC_CHATOPS_TIMEOUT_SECONDS: int = Field(
        default=900,
        description="How long a verification prompt stays valid (default 15 min).",
    )

    AISOC_ACTIONS_PUBLIC_URL: str = Field(
        default="http://localhost:8003",
        description=(
            "Externally-reachable base URL of services/actions. Used to build the callback links embedded in ChatOps verification messages."
        ),
    )

    # Wave 4 (W4.3) — bearer token that callers of the mutating action routes
    # must present. When unset the routes are open only in dev mode; in
    # production a missing token fails closed (503).
    AISOC_ACTIONS_SERVICE_TOKEN: str = Field(
        default="",
        description="Shared bearer token required on POST /actions + approve/reject. Mounted as a secret in production.",
    )
    AISOC_DEV_MODE: bool = Field(
        default=False,
        description="Canonical dev-mode flag. When true, unauthenticated action routes are permitted (never set in production).",
    )
    # Wave 4 (W4.2) — when true, every action MUST carry an authenticated
    # principal (system-initiated principal-less calls are rejected).
    AISOC_ACTIONS_REQUIRE_PRINCIPAL: bool = Field(
        default=False,
        description="Require a structured ActionPrincipal on every action request.",
    )
    # T3.6 — the *approval* path, which is separate from the request path
    # above and defaults the other way. An approval with no identity cannot
    # satisfy separation of duties at all, so a principal-less approval is not
    # a legacy convenience, it is the control being absent. Slack and Teams
    # approvals ran in exactly that state: the bot verified who clicked, then
    # called approve with no approver.
    AISOC_ACTIONS_REQUIRE_APPROVER: bool = Field(
        default=True,
        description="Refuse approve/reject calls that carry no resolvable approver identity.",
    )
    # Maps a verified ChatOps identity onto an authorization principal. JSON
    # inline or `file:/path/to.json`. Unset means nobody can approve over
    # ChatOps, which is the correct default for a control that was absent.
    # See app/security/chatops_identity.py for the shape.
    AISOC_CHATOPS_APPROVERS: str = Field(
        default="",
        description="JSON (or file: path) mapping platform user ids to approver principals.",
    )


@lru_cache(maxsize=1)
def get_settings() -> ActionsSettings:
    return ActionsSettings()
