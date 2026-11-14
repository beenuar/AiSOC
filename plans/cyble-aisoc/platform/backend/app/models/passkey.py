"""Passkey credentials — WebAuthn-style mobile authenticator binding (Theme 2m).

Mobile HITL approval at 2am can't ask the on-call analyst to fish out a TOTP
seed; the modern answer is platform passkeys (FaceID / TouchID / Android
BiometricPrompt + WebAuthn). This table stores the *server-side* half of that
binding: one row per (principal, credential_id) so we can re-verify an
assertion later and link a HITL decision to a specific authenticator.

We deliberately do **not** ship a full FIDO2/WebAuthn server here — that's a
real cryptographic protocol with attestation chains and counter logic, and
slipping a half-baked implementation into the audit path would create the
exact security theater this plan exists to avoid. Instead we model the
*contract* end-to-end:

- ``credential_id``  — opaque public key identifier (mobile device sends this).
- ``public_key``     — COSE-encoded EC2/RSA public key (PEM-as-text in dev).
- ``sign_counter``   — replay-protection counter; monotonic per credential.
- ``aaguid``         — authenticator model (Apple, Google, YubiKey, etc.).
- ``transports``     — usb/nfc/ble/internal — drives UI hints on the client.
- ``last_used_at``   — for "trusted device" expiry.

A real deployment swaps the placeholder verifier in ``app.hitl.passkey`` for
``py_webauthn`` or ``fido2`` without touching this table.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlmodel import Field, SQLModel


class PasskeyCredential(SQLModel, table=True):
    """A registered passkey for an analyst principal."""

    id: Optional[int] = Field(default=None, primary_key=True)

    # Tenant scoping. A passkey is registered against a principal *within* a
    # tenant; an MSSP analyst pivoting into a child tenant uses the same
    # passkey, but the row lives under their home tenant.
    tenant_id: str = Field(index=True)

    # JWT subject ("alice@cyble.com" / "agent-svc-1") this credential authenticates.
    principal: str = Field(index=True)

    # Opaque per-credential id from the authenticator. Unique server-wide.
    credential_id: str = Field(index=True, unique=True)

    # COSE-encoded public key. We store text (base64 of CBOR in real impl) so
    # the column survives the dev sqlite + alembic migration path.
    public_key: str

    # Authenticator model GUID — Apple = 00000000-..., Google = ..., etc.
    # Optional because some platforms strip it for privacy.
    aaguid: str | None = None

    # Transports advertised at registration (comma-separated: "internal,hybrid").
    transports: str | None = None

    # Friendly label the analyst sees ("Alice's iPhone 15").
    label: str | None = None

    # Replay protection. WebAuthn assertions carry a monotonically increasing
    # counter; rejecting a counter that didn't advance defeats clone replay.
    sign_counter: int = Field(default=0)

    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), index=True
    )
    last_used_at: datetime | None = None
    revoked_at: datetime | None = None

    @property
    def is_active(self) -> bool:
        return self.revoked_at is None
