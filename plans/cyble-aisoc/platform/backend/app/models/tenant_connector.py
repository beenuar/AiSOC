"""Per-tenant connector configuration row (Theme 1 — Real connectors).

A single row represents "tenant X has connector Y for kind Z configured
with these parameters and these (encrypted) credentials". The admin API
CRUDs rows here; the :class:`~app.connectors.registry.ConnectorRegistry`
reads rows here to lazily build live :class:`BaseConnector` instances on
demand.

Security model
--------------
Sensitive credentials (API keys, OAuth secrets, service-account passwords)
are never stored in plaintext. They pass through
:mod:`app.connectors.sdk.secrets` on the way in (``seal_dict``) and on
the way out (``unseal_dict``); the row's ``secrets_encrypted`` column
holds Fernet ciphertexts. Admin API, registry, and tests must use
:meth:`set_secrets` / :meth:`merge_secrets` / :meth:`decrypted_secrets`
rather than touching the JSON blob directly, so encryption is enforced
by the only public path that exists.

Uniqueness
----------
A tenant has at most one connector per :class:`ConnectorKind`. The
``(tenant_id, kind)`` unique constraint enforces that at the DB layer
so the "two SIEMs, which one wins?" ambiguity never arises in v1.
Multi-vendor fan-out is on the roadmap (``t1-realtime-data``) and will
introduce a join table; this row will evolve, not be replaced.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import UniqueConstraint
from sqlmodel import Column, Field, JSON, SQLModel

from app.connectors.sdk.base import ConnectorConfig, ConnectorKind
from app.connectors.sdk.secrets import seal_dict, unseal_dict


class TenantConnector(SQLModel, table=True):
    __table_args__ = (
        UniqueConstraint("tenant_id", "kind", name="uq_tenant_connector_kind"),
    )

    id: Optional[int] = Field(default=None, primary_key=True)
    tenant_id: str = Field(index=True)
    # ConnectorKind value as a string ("siem" / "edr" / "idp" / "email" / …).
    # Stored as plain str rather than a SQLAlchemy Enum so adding a new
    # kind in app/connectors/sdk/base.py does not require a schema
    # migration on existing rows.
    kind: str = Field(index=True)
    # Concrete vendor inside the kind: "splunk", "crowdstrike", "okta",
    # "m365", … Used by the registry to look up the right factory.
    vendor: str = Field(index=True)
    # Operators flip this to fall back to the mock connector for a tenant
    # without forgetting their credentials.
    enabled: bool = Field(default=True, index=True)

    # Non-secret per-tenant parameters (host, index, default lookback,
    # region, allowlists, …). JSON to stay schema-flexible across vendors.
    params: dict[str, Any] = Field(
        default_factory=dict,
        sa_column=Column(JSON),
    )
    # Sealed credentials: each value is a Fernet ciphertext token. Keys
    # are the names connectors look up (e.g. "api_key", "client_secret",
    # "service_account_password"). NEVER WRITE PLAINTEXT HERE — use
    # set_secrets() / merge_secrets() so encryption is enforced.
    secrets_encrypted: dict[str, str] = Field(
        default_factory=dict,
        sa_column=Column(JSON),
    )

    # Populated by the admin "Test connection" path and the periodic
    # health check job. The error string is truncated to keep the row
    # small; full stack lives in app logs.
    last_health_check_at: datetime | None = Field(default=None)
    last_health_status: str | None = Field(default=None, index=True)
    last_health_error: str | None = Field(default=None)

    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )

    # ── credential helpers (the only safe way to read/write secrets) ──

    def set_secrets(self, plaintext: dict[str, str]) -> None:
        """Replace all stored credentials with sealed ciphertexts.

        Pass an empty mapping to clear secrets entirely.
        """
        self.secrets_encrypted = seal_dict(plaintext or {})
        self._touch()

    def merge_secrets(self, plaintext: dict[str, str]) -> None:
        """Seal-then-overlay the given credentials onto existing ones.

        Use this for PATCH-style updates where the operator is rotating
        one key without re-supplying the others.
        """
        if not plaintext:
            return
        merged = dict(self.secrets_encrypted or {})
        merged.update(seal_dict(plaintext))
        self.secrets_encrypted = merged
        self._touch()

    def decrypted_secrets(self) -> dict[str, str]:
        """Return the plaintext credentials.

        Raises :class:`~app.connectors.sdk.secrets.SecretsDecryptError`
        when neither the active key nor any
        ``AISOC_CONNECTOR_SECRETS_KEYS_PREVIOUS`` entry can open the
        sealed values.
        """
        return unseal_dict(self.secrets_encrypted or {})

    def secret_names(self) -> list[str]:
        """Names of stored secrets, sorted, without decrypting values."""
        return sorted((self.secrets_encrypted or {}).keys())

    # ── conversion to the runtime dataclass ───────────────────────────

    @property
    def connector_kind(self) -> ConnectorKind:
        """Parse the stored ``kind`` string into a :class:`ConnectorKind`."""
        return ConnectorKind(self.kind)

    def to_runtime_config(self) -> ConnectorConfig:
        """Build the dataclass the registry hands to a live connector."""
        return ConnectorConfig(
            tenant_id=self.tenant_id,
            kind=self.connector_kind,
            vendor=self.vendor,
            params=dict(self.params or {}),
            secrets=self.decrypted_secrets(),
            enabled=self.enabled,
        )

    # ── housekeeping ──────────────────────────────────────────────────

    def _touch(self) -> None:
        self.updated_at = datetime.now(timezone.utc)

    def __repr__(self) -> str:  # pragma: no cover - debug only
        return (
            f"<TenantConnector id={self.id} tenant={self.tenant_id!r} "
            f"kind={self.kind!r} vendor={self.vendor!r} "
            f"enabled={self.enabled} secrets={len(self.secrets_encrypted or {})}>"
        )
