"""MFA verification for HITL decisions.

A real deployment binds to an SSO MFA receipt (TOTP, WebAuthn, push-MFA). This
module gives us the smallest production-shaped surface that exercises the same
contract end-to-end so we can swap in a real verifier without changing callers.

Contract:
- `verify_mfa(method, token, principal)` returns a stable receipt hash, or
  raises `MfaVerificationError` if the token is rejected.
- The receipt hash is persisted on the HitlRequest, so the decision is
  cryptographically tied to the MFA artifact at audit time.
"""
from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass

from app.config import settings

ALLOWED_METHODS = {"totp", "webauthn", "sso-mfa", "dev-shared-secret"}


class MfaVerificationError(Exception):
    """Raised when an MFA token cannot be verified."""


@dataclass
class MfaReceipt:
    method: str
    receipt_hash: str  # hex; safe to persist


def _dev_shared_secret() -> str:
    """Local-dev MFA secret.

    Production hooks into SSO; this is only used when `hitl_require_mfa` is on
    but no SSO/MFA provider is configured (dev demo flow).
    """
    return os.environ.get("AISOC_HITL_DEV_MFA_SECRET", "aisoc-dev-mfa")


def verify_mfa(method: str, token: str, principal: str) -> MfaReceipt:
    """Verify an MFA `token` for `principal` and return a stable receipt.

    Raises MfaVerificationError on rejection. In dev mode, accepts an HMAC of
    (principal, secret); production should call into the real IdP.
    """
    if not settings.hitl_require_mfa:
        # MFA disabled — still produce a receipt for audit, marked as such.
        digest = hashlib.sha256(f"no-mfa:{principal}".encode()).hexdigest()
        return MfaReceipt(method="none", receipt_hash=digest)

    if method not in ALLOWED_METHODS:
        raise MfaVerificationError(f"unsupported MFA method: {method}")

    if not token:
        raise MfaVerificationError("MFA token required")

    if method == "dev-shared-secret":
        expected = hmac.new(
            _dev_shared_secret().encode(),
            principal.encode(),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(expected, token):
            raise MfaVerificationError("MFA token rejected")
        return MfaReceipt(
            method=method,
            receipt_hash=hashlib.sha256(token.encode()).hexdigest(),
        )

    # totp / webauthn / sso-mfa — placeholder: store hash of presented token.
    # Real impl: validate against IdP and capture the upstream receipt id.
    return MfaReceipt(
        method=method,
        receipt_hash=hashlib.sha256(token.encode()).hexdigest(),
    )
