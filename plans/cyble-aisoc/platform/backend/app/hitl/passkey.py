"""Passkey (WebAuthn-shaped) registration and assertion verification.

Backs the mobile HITL approver (Theme 2m). Real WebAuthn is a substantial
spec — attestation chains, COSE keys, FIDO metadata, RP-ID hashing,
counter monotonicity, origin binding, user-presence/user-verification bits.
We model the full *contract* end-to-end so the route, audit, and replay-defense
shapes are correct, and leave a single seam (``_verify_signature``) that a
production deployment swaps for ``py_webauthn`` / ``fido2`` without touching
the call sites.

What we do enforce, even in dev:

1. **Challenge binding.** Every assertion must reference a server-issued
   challenge from the in-process registry. The challenge is single-use and
   expires after :data:`CHALLENGE_TTL_SECONDS`.
2. **Counter monotonicity.** ``sign_counter`` must strictly advance, or the
   assertion is rejected as a possible clone replay.
3. **Tenant binding.** The credential row is loaded under the active tenant
   context, so an MSSP analyst can't reuse a child-tenant passkey against
   a different tenant.
4. **Receipt hash.** Every successful assertion produces a deterministic
   receipt hash (``credential_id|new_counter|challenge``) that lands on the
   HitlRequest row, making the decision auditable end-to-end.

The dev signature scheme is HMAC-SHA256 over the challenge using the stored
``public_key`` string as the shared secret. That keeps the demo working
without shipping ECDSA verification, while leaving real crypto for the
real verifier seam.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlmodel import select

from app.db import session_scope
from app.hitl.mfa import MfaReceipt, MfaVerificationError
from app.models.passkey import PasskeyCredential


CHALLENGE_TTL_SECONDS = 120


# ── In-process challenge registry ────────────────────────────────────────
#
# WebAuthn challenges are short-lived nonces issued by the relying party. A
# real deployment persists them in Redis with TTL so multi-replica boots stay
# consistent; for the local backend, an in-memory dict guarded by a lock is
# the right shape — fast, race-safe, automatically GC'd on restart.

_challenge_lock = threading.Lock()
_active_challenges: dict[str, "_PendingChallenge"] = {}


@dataclass
class _PendingChallenge:
    challenge: str  # base64url, the value sent to the client
    purpose: str  # "register" | "assert"
    principal: str
    tenant_id: str
    expires_at: float  # epoch seconds


def _now_epoch() -> float:
    return time.time()


def _new_challenge(purpose: str, principal: str, tenant_id: str) -> str:
    raw = secrets.token_bytes(32)
    challenge = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    with _challenge_lock:
        _gc_expired_locked()
        _active_challenges[challenge] = _PendingChallenge(
            challenge=challenge,
            purpose=purpose,
            principal=principal,
            tenant_id=tenant_id,
            expires_at=_now_epoch() + CHALLENGE_TTL_SECONDS,
        )
    return challenge


def _consume_challenge(challenge: str, purpose: str) -> _PendingChallenge:
    with _challenge_lock:
        _gc_expired_locked()
        pending = _active_challenges.pop(challenge, None)
    if pending is None:
        raise PasskeyVerificationError("challenge not found or already used")
    if pending.purpose != purpose:
        raise PasskeyVerificationError(
            f"challenge purpose mismatch (expected {purpose}, got {pending.purpose})"
        )
    if pending.expires_at < _now_epoch():
        raise PasskeyVerificationError("challenge expired")
    return pending


def _gc_expired_locked() -> None:
    now = _now_epoch()
    stale = [c for c, p in _active_challenges.items() if p.expires_at < now]
    for c in stale:
        _active_challenges.pop(c, None)


# ── Public types ─────────────────────────────────────────────────────────


class PasskeyVerificationError(MfaVerificationError):
    """Raised when a passkey assertion (or registration) cannot be verified.

    Subclasses :class:`MfaVerificationError` so existing HITL routes that
    already handle MFA failures degrade gracefully.
    """


@dataclass
class RegistrationChallenge:
    """Server-issued challenge the client signs during enrollment."""

    challenge: str
    rp_id: str
    rp_name: str
    user_id: str
    user_name: str
    timeout_ms: int
    pub_key_cred_params: list[dict]  # algorithms the server accepts


@dataclass
class AssertionChallenge:
    """Server-issued challenge the client signs during HITL approval."""

    challenge: str
    rp_id: str
    allow_credentials: list[dict]
    timeout_ms: int
    user_verification: str  # "required" — biometric required on the device


@dataclass
class RegisteredPasskey:
    id: int
    credential_id: str
    label: str | None
    aaguid: str | None
    transports: str | None
    created_at: datetime
    last_used_at: datetime | None


# ── Registration ─────────────────────────────────────────────────────────


def issue_registration_challenge(
    *, principal: str, tenant_id: str, user_name: str | None = None
) -> RegistrationChallenge:
    """Begin a passkey registration ceremony for ``principal``.

    The returned challenge is single-use and bound to the principal — a
    different analyst can't finalize against it. The client returns the
    challenge alongside the new credential id and public key.
    """
    challenge = _new_challenge("register", principal, tenant_id)
    return RegistrationChallenge(
        challenge=challenge,
        rp_id="aisoc.local",
        rp_name="Cyble AiSOC",
        user_id=base64.urlsafe_b64encode(principal.encode()).rstrip(b"=").decode(),
        user_name=user_name or principal,
        timeout_ms=60_000,
        pub_key_cred_params=[
            {"type": "public-key", "alg": -7},  # ES256
            {"type": "public-key", "alg": -257},  # RS256
        ],
    )


def finalize_registration(
    *,
    tenant_id: str,
    principal: str,
    challenge: str,
    credential_id: str,
    public_key: str,
    aaguid: str | None = None,
    transports: str | None = None,
    label: str | None = None,
) -> RegisteredPasskey:
    """Persist a verified passkey credential.

    The dev implementation trusts the public key bytes as presented and
    treats them as the HMAC secret used by :func:`_verify_signature`. A
    production replacement parses COSE/CBOR, validates attestation, and
    stores the canonical public key.
    """
    pending = _consume_challenge(challenge, "register")
    if pending.principal != principal:
        raise PasskeyVerificationError(
            "challenge principal mismatch — registration must use the same "
            "principal that requested the challenge"
        )
    if pending.tenant_id != tenant_id:
        raise PasskeyVerificationError("challenge tenant mismatch")

    if not credential_id or not public_key:
        raise PasskeyVerificationError("credential_id and public_key are required")

    with session_scope() as s:
        existing = s.exec(
            select(PasskeyCredential).where(
                PasskeyCredential.credential_id == credential_id
            )
        ).first()
        if existing is not None:
            raise PasskeyVerificationError("credential_id already registered")

        row = PasskeyCredential(
            tenant_id=tenant_id,
            principal=principal,
            credential_id=credential_id,
            public_key=public_key,
            aaguid=aaguid,
            transports=transports,
            label=label,
            sign_counter=0,
        )
        s.add(row)
        s.flush()
        s.refresh(row)
        return RegisteredPasskey(
            id=row.id or 0,
            credential_id=row.credential_id,
            label=row.label,
            aaguid=row.aaguid,
            transports=row.transports,
            created_at=row.created_at,
            last_used_at=row.last_used_at,
        )


def list_passkeys(*, tenant_id: str, principal: str) -> list[RegisteredPasskey]:
    """List the active passkeys an analyst has registered.

    Filters by tenant to keep MSSP analysts from accidentally seeing each
    other's authenticators when they share a directory subject.
    """
    with session_scope() as s:
        rows = s.exec(
            select(PasskeyCredential)
            .where(PasskeyCredential.tenant_id == tenant_id)
            .where(PasskeyCredential.principal == principal)
            .where(PasskeyCredential.revoked_at.is_(None))  # type: ignore[union-attr]
        ).all()
        return [
            RegisteredPasskey(
                id=r.id or 0,
                credential_id=r.credential_id,
                label=r.label,
                aaguid=r.aaguid,
                transports=r.transports,
                created_at=r.created_at,
                last_used_at=r.last_used_at,
            )
            for r in rows
        ]


def revoke_passkey(*, tenant_id: str, principal: str, credential_id: str) -> None:
    """Mark a passkey revoked. Future assertions against it are rejected."""
    with session_scope() as s:
        row = s.exec(
            select(PasskeyCredential)
            .where(PasskeyCredential.tenant_id == tenant_id)
            .where(PasskeyCredential.principal == principal)
            .where(PasskeyCredential.credential_id == credential_id)
        ).first()
        if row is None:
            raise PasskeyVerificationError("passkey not found")
        row.revoked_at = datetime.now(timezone.utc)
        s.add(row)


# ── Assertion / HITL approval ────────────────────────────────────────────


def issue_assertion_challenge(
    *, principal: str, tenant_id: str
) -> AssertionChallenge:
    """Issue a challenge the analyst's device will sign to approve a HITL."""
    challenge = _new_challenge("assert", principal, tenant_id)
    # Materialize the credential descriptors *inside* the session — once it
    # closes the rows detach and SQLAlchemy raises DetachedInstanceError on
    # any lazy attribute access. Holding them as plain dicts also makes the
    # caller's life easier: no ORM types leak across the seam.
    with session_scope() as s:
        rows = s.exec(
            select(PasskeyCredential)
            .where(PasskeyCredential.tenant_id == tenant_id)
            .where(PasskeyCredential.principal == principal)
            .where(PasskeyCredential.revoked_at.is_(None))  # type: ignore[union-attr]
        ).all()
        allow_credentials = [
            {
                "type": "public-key",
                "id": r.credential_id,
                "transports": (r.transports or "internal").split(","),
            }
            for r in rows
        ]
    return AssertionChallenge(
        challenge=challenge,
        rp_id="aisoc.local",
        allow_credentials=allow_credentials,
        timeout_ms=60_000,
        user_verification="required",
    )


def _verify_signature(public_key: str, challenge: str, signature: str) -> bool:
    """Verify the client's signature over ``challenge``.

    Dev implementation: HMAC-SHA256 using the stored public_key string as a
    shared secret. The client computes the same HMAC; this keeps the
    end-to-end demo testable. A production deployment replaces this with
    real ECDSA / RSA verification via ``py_webauthn``.
    """
    expected = hmac.new(public_key.encode(), challenge.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def verify_assertion(
    *,
    tenant_id: str,
    principal: str,
    credential_id: str,
    challenge: str,
    signature: str,
    sign_counter: int,
) -> MfaReceipt:
    """Verify a passkey assertion for a HITL decision.

    On success, returns an :class:`MfaReceipt` that the HITL gateway can
    persist on the request row. The receipt hash is bound to (credential_id,
    new_counter, challenge) so the audit trail can replay the chain later.

    Raises :class:`PasskeyVerificationError` on any failure — unknown
    credential, revoked credential, counter regression, signature mismatch,
    or challenge expiry/reuse. The HITL routes translate that into a 401 so
    a missed approval doesn't get stuck.
    """
    pending = _consume_challenge(challenge, "assert")
    if pending.principal != principal:
        raise PasskeyVerificationError("challenge principal mismatch")
    if pending.tenant_id != tenant_id:
        raise PasskeyVerificationError("challenge tenant mismatch")

    with session_scope() as s:
        row = s.exec(
            select(PasskeyCredential)
            .where(PasskeyCredential.tenant_id == tenant_id)
            .where(PasskeyCredential.principal == principal)
            .where(PasskeyCredential.credential_id == credential_id)
        ).first()
        if row is None:
            raise PasskeyVerificationError("credential not registered for principal")
        if not row.is_active:
            raise PasskeyVerificationError("credential revoked")
        if sign_counter <= row.sign_counter:
            # Either replay (counter didn't advance) or clone (counter reset).
            # The defensive answer is the same: reject.
            raise PasskeyVerificationError(
                f"sign_counter must advance: stored={row.sign_counter} presented={sign_counter}"
            )
        if not _verify_signature(row.public_key, challenge, signature):
            raise PasskeyVerificationError("signature verification failed")

        row.sign_counter = sign_counter
        row.last_used_at = datetime.now(timezone.utc)
        s.add(row)
        # Receipt hash binds credential, new counter, and the consumed
        # challenge — replay-resistant by construction.
        receipt_payload = json.dumps(
            {"cred": credential_id, "ctr": sign_counter, "chal": challenge},
            sort_keys=True,
        )
        digest = hashlib.sha256(receipt_payload.encode()).hexdigest()
        return MfaReceipt(method="webauthn", receipt_hash=digest)


__all__ = [
    "AssertionChallenge",
    "PasskeyVerificationError",
    "RegisteredPasskey",
    "RegistrationChallenge",
    "finalize_registration",
    "issue_assertion_challenge",
    "issue_registration_challenge",
    "list_passkeys",
    "revoke_passkey",
    "verify_assertion",
]
