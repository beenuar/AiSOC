"""OAuth ORM models — hosted one-click connector flow.

Two tables back the ``/api/v1/oauth/start`` + ``/api/v1/oauth/callback``
endpoints:

* :class:`OAuthAppCredential`
    Per-tenant, per-connector-class OAuth client_id / client_secret.
    The platform does not bake in a single shared client; each tenant
    registers their own OAuth app (or a managed-deployment operator
    pre-fills it for the tenant). ``client_secret_vault`` is opaque
    ciphertext from :class:`app.security.credential_vault.CredentialVault`
    and is never returned in plaintext.

* :class:`OAuthState`
    Short-lived nonce that we use as the OAuth ``state`` parameter to
    defend against CSRF and to thread the originating tenant +
    connector + redirect intent through the round-trip to the upstream
    provider. Rows TTL out at 10 minutes; a row is also deleted on first
    successful callback (single-use).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class OAuthAppCredential(Base):
    """Per-tenant, per-connector-class OAuth client credentials.

    Composite primary key (tenant_id, connector_type) — a tenant only
    ever has one OAuth app per connector class, since the upstream
    provider conflates app identity with credential identity. If we
    ever need to support multiple (e.g. dev + prod GitHub apps) we'll
    bolt on an opaque ``credential_id`` later; for now the simpler
    model is fine.
    """

    __tablename__ = "oauth_app_credentials"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        primary_key=True,
    )
    connector_type: Mapped[str] = mapped_column(String(50), primary_key=True)
    client_id: Mapped[str] = mapped_column(Text, nullable=False)
    # Encrypted client secret (vault:v1:<base64>). Never round-trips to
    # the UI; we expose only ``has_secret: bool`` in the GET endpoint.
    client_secret_vault: Mapped[str] = mapped_column(Text, nullable=False)
    # Optional override of the default authorize/token URLs for on-prem
    # providers (Atlassian Data Center, GitHub Enterprise Server,
    # internal Okta orgs). NULL means use the default from the
    # connector's OAuthHints.
    authorize_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    token_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Optional scope downscoping. NULL means use the default scopes
    # from the connector's OAuthHints. Stored as JSON array of strings.
    scopes: Mapped[list[str] | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )


class OAuthState(Base):
    """Short-lived OAuth state nonce + threaded context.

    The lifecycle is:

    1. ``/oauth/start`` generates a 32-byte URL-safe token, persists a
       row capturing (tenant, user, connector_type, optional connector_id,
       optional PKCE verifier, extras, return_to), and 302s to the
       provider's authorize URL with ``state=<token>``.
    2. The provider 302s back to ``/oauth/callback?code=…&state=…``.
    3. The callback looks up the row (verifying expiry), exchanges the
       code, deletes the row (single-use), and creates or updates the
       connector. Then it 302s the operator to ``return_to``.

    A periodic worker can sweep expired rows via
    ``DELETE FROM oauth_states WHERE expires_at < now()``.
    """

    __tablename__ = "oauth_states"

    state: Mapped[str] = mapped_column(Text, primary_key=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=True,
    )
    connector_type: Mapped[str] = mapped_column(String(50), nullable=False)
    # NULL means the callback should create a new connector row;
    # non-NULL means we're re-authing an existing instance.
    connector_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("connectors.id", ondelete="CASCADE"),
        nullable=True,
    )
    # PKCE code_verifier for providers that mandate it (Atlassian 3LO).
    code_verifier: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Free-form hint that becomes part of connector_config so the
    # callback knows what extras to persist (e.g. {"organization": "acme"}
    # for GitHub, {"admin_email": "..."} for Google Workspace).
    extras: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    # Where to redirect the operator after the callback. Defaults to
    # /onboarding so the verify-data-flowing screen lights up.
    return_to: Mapped[str] = mapped_column(Text, default="/onboarding", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
