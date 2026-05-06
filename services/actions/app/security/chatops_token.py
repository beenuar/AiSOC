"""HMAC-signed tokens for ChatOps verification callbacks.

The ChatOps verifier posts an interactive message containing one signed
callback URL per choice (e.g. ``acknowledge`` / ``deny`` / ``escalate``).
When the user clicks, the callback endpoint validates that:

* the token was actually minted by us (HMAC over the payload),
* the token has not expired (``exp`` field, default 15 min),
* the token has not been replayed (single-use enforcement is the caller's
  job — we hand back the parsed claims, including ``action_id``, so an
  in-memory or Redis-backed used-token set can dedupe).

Wire format is intentionally tiny: ``<b64url(payload)>.<hex(hmac_sha256)>``.
That keeps URLs short enough for Slack/Teams attachments and lets us avoid
adding a JWT library (``cryptography`` + stdlib is plenty here).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Final
from uuid import UUID

_TOKEN_VERSION: Final[str] = "v1"


class ChatOpsTokenError(ValueError):
    """Raised when a callback token fails to validate.

    Surfaces a coarse reason ('expired', 'invalid_signature', 'malformed')
    so the callback endpoint can return a stable user-facing message
    without leaking which check failed.
    """


@dataclass(frozen=True)
class ChatOpsTokenClaims:
    action_id: UUID
    case_id: UUID
    tenant_id: UUID
    choice: str
    user_ref: str
    issued_at: int
    expires_at: int


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _sign(payload_b64: str, secret: str) -> str:
    mac = hmac.new(secret.encode("utf-8"), payload_b64.encode("ascii"), hashlib.sha256)
    return mac.hexdigest()


def mint_token(
    *,
    action_id: UUID,
    case_id: UUID,
    tenant_id: UUID,
    choice: str,
    user_ref: str,
    secret: str,
    ttl_seconds: int,
) -> str:
    """Produce a signed callback token.

    ``user_ref`` is whatever stable identifier the executor wants to record
    on the timeline (email, sub, employee ID). It is not used for auth — the
    signature alone authenticates the click — but it lets the callback log
    the right principal without trusting a query-string field.
    """
    if not secret:
        raise ChatOpsTokenError("AISOC_CHATOPS_RESPONSE_SECRET is required to mint tokens")
    if choice not in {"acknowledge", "deny", "escalate"}:
        raise ChatOpsTokenError(f"unsupported choice: {choice!r}")

    now = int(time.time())
    body = {
        "v": _TOKEN_VERSION,
        "aid": str(action_id),
        "cid": str(case_id),
        "tid": str(tenant_id),
        "ch": choice,
        "ur": user_ref,
        "iat": now,
        "exp": now + max(int(ttl_seconds), 1),
    }
    payload_b64 = _b64url_encode(json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    sig = _sign(payload_b64, secret)
    return f"{payload_b64}.{sig}"


def verify_token(token: str, secret: str, *, now: int | None = None) -> ChatOpsTokenClaims:
    """Validate signature + expiry and return parsed claims.

    Constant-time signature compare via ``hmac.compare_digest``. Caller is
    responsible for replay protection — re-using ``action_id`` should be
    rejected once a response has already been recorded against it.
    """
    if not secret:
        raise ChatOpsTokenError("AISOC_CHATOPS_RESPONSE_SECRET is required to verify tokens")
    if not isinstance(token, str) or token.count(".") != 1:
        raise ChatOpsTokenError("malformed")

    payload_b64, sig = token.split(".", 1)
    expected = _sign(payload_b64, secret)
    if not hmac.compare_digest(expected, sig):
        raise ChatOpsTokenError("invalid_signature")

    try:
        body = json.loads(_b64url_decode(payload_b64))
    except (ValueError, json.JSONDecodeError) as exc:
        raise ChatOpsTokenError("malformed") from exc

    if body.get("v") != _TOKEN_VERSION:
        raise ChatOpsTokenError("malformed")

    try:
        claims = ChatOpsTokenClaims(
            action_id=UUID(body["aid"]),
            case_id=UUID(body["cid"]),
            tenant_id=UUID(body["tid"]),
            choice=str(body["ch"]),
            user_ref=str(body.get("ur", "")),
            issued_at=int(body["iat"]),
            expires_at=int(body["exp"]),
        )
    except (KeyError, ValueError) as exc:
        raise ChatOpsTokenError("malformed") from exc

    current = int(now if now is not None else time.time())
    if current >= claims.expires_at:
        raise ChatOpsTokenError("expired")

    return claims
