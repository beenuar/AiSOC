"""Per-tenant BYOK LLM credential ORM model (WS-H2).

Backs the ``/api/v1/llm/credentials`` endpoints and is consumed at request
time by ``services/agents/app/api/explain.py`` to resolve which API key,
model, and base URL to use when generating an alert explanation.

Why one row per tenant
----------------------
Every buyer we have spoken to wants exactly one active LLM credential.
"Multiple stored credentials with one marked active" is a v1.1 polish; if
we need it we can drop the PK and add an ``is_active`` partial unique
index without a destructive migration.

Encryption
----------
``api_key_vault`` is opaque ciphertext (``vault:v1:<base64>``) produced by
:class:`app.security.credential_vault.CredentialVault`. The plaintext key
never round-trips to the UI — the read endpoint exposes ``has_api_key:
bool`` only and the audit log records the *fact* of rotation, not the
key material.

Provider whitelist
------------------
The ``provider`` enum is enforced at the DB layer (CHECK constraint in
``038_tenant_llm_credentials.sql``) and mirrored in the application's
classification logic at
:func:`app.api.v1.endpoints.llm_status._classify_provider`. Any change to
the enum is a coordinated migration + code edit.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class TenantLlmCredential(Base):
    """Per-tenant LLM provider configuration for BYOK + air-gap routing.

    The row resolves three questions for the request path:

    * Which provider to call (``provider``).
    * Where to send the request (``base_url``; ``NULL`` falls back to the
      provider's canonical endpoint, encoded in
      :data:`app.api.v1.endpoints.llm_status._PROVIDER_DEFAULTS`).
    * Which API key to authenticate with (``api_key_vault``; ``NULL`` is
      legitimate for ``local-*`` providers without auth).

    ``model`` and ``settings`` are optional overrides; the application
    layer is expected to fall back to platform defaults when they are
    ``NULL``.
    """

    __tablename__ = "tenant_llm_credentials"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        primary_key=True,
    )
    # One of: openai | anthropic | azure-openai | local-ollama |
    # local-vllm | local-litellm | custom. The DB enforces this via a
    # CHECK constraint (see 038_tenant_llm_credentials.sql); the
    # application layer mirrors the list in llm_status._classify_provider.
    provider: Mapped[str] = mapped_column(String(40), nullable=False)
    # Optional override of the provider's default base URL. Required for
    # ``custom`` and the three ``local-*`` providers (the API endpoint
    # validates this on PUT). NULL for hosted providers means "use the
    # canonical endpoint".
    base_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Optional model override. NULL means "use the platform default
    # (gpt-4o-mini for openai, claude-3-5-sonnet for anthropic, etc.)".
    model: Mapped[str | None] = mapped_column(String(120), nullable=True)
    # Vault-encrypted API key. Format: vault:v1:<base64>. Nullable because
    # local-* providers without auth legitimately have no key.
    api_key_vault: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Provider-specific settings escape hatch (e.g. Azure deployment name,
    # OpenAI organization id, max_tokens override). Empty in v1.0; v1.1
    # features can populate this without a migration.
    settings: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    # Soft-disable without deleting. Lets an operator pause LLM for a
    # tenant during a key rotation without losing the saved configuration.
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
        nullable=False,
    )
    # Bumped only when api_key_vault changes (the API endpoint manages
    # this). Drives the "rotated 3 days ago" hint in the Settings UI so
    # operators have a key-hygiene signal at a glance.
    last_rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
