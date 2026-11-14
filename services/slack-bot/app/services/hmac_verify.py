"""
HMAC verification for AiSOC approval callbacks.

Slack's own ``slack_bolt`` already verifies inbound slash-command and
``block_actions`` payloads against ``SLACK_SIGNING_SECRET`` — that path
is untouched. T3.6 adds a *second* signed surface used by:

* Teams Adaptive Cards (``services/teams-bot``) — Microsoft delivers the
  card-action payload with a bearer JWT, but we also want to verify the
  embedded ``action_token`` we minted ourselves so a replayed action
  payload can be detected even before Microsoft's outer signature is
  checked.
* Email approvals (``services/api/app/services/email_approval.py``) —
  the recipient clicks a signed URL; the API endpoint must verify the
  signature + freshness window before flipping the action state.

Both surfaces share this single primitive: a timing-safe HMAC-SHA256
verifier with an optional max-age window. The signed payload is always
the canonical bytes the issuer wanted to bind (typically
``"<action_id>|<approver>|<expires_at_unix>"``); callers decide how to
canonicalise.

Why a homegrown helper instead of ``itsdangerous`` / ``jwt``?

* Zero new dependencies (the API already pulls ``itsdangerous`` via
  Starlette, but the Slack bot doesn't and we don't want it to). Pure
  ``hmac``/``hashlib`` keeps the runtime surface tiny and dependency
  audits painless.
* The shape we need is *just* "verify this payload was minted by us in
  the last hour" — JWT brings claims/algorithms/key-id headers we don't
  use and would have to maintain.
* It's testable as a single pure function.

The signing key is *not* loaded at import — callers pass it in
explicitly, which keeps the secret out of any module-level state and
makes it trivial to inject a test key.
"""

from __future__ import annotations

import hashlib
import hmac
import time

__all__ = ["sign", "verify", "HmacVerificationError"]


class HmacVerificationError(ValueError):
    """Raised when a signed payload fails any leg of verification."""


def sign(payload: bytes | str, *, secret: str) -> str:
    """
    Mint a signed HMAC-SHA256 token for ``payload``.

    Returns a lowercase hex digest (64 chars). Callers append/embed it in
    whatever envelope they ship (URL query, hidden form field, Teams
    Adaptive Card ``data`` payload, …).
    """
    if not secret:
        raise HmacVerificationError("HMAC secret is empty — refusing to sign")
    msg = payload.encode("utf-8") if isinstance(payload, str) else payload
    return hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()


def verify(
    payload: bytes | str,
    signature: str,
    *,
    secret: str,
    max_age_seconds: int | None = None,
    timestamp: float | None = None,
) -> None:
    """
    Constant-time HMAC verification of ``signature`` against ``payload``.

    Parameters
    ----------
    payload
        Canonical bytes that were signed.
    signature
        Hex digest as produced by :func:`sign`.
    secret
        Shared signing secret. Empty strings are rejected so a missing
        env var can never silently accept any signature.
    max_age_seconds
        Optional freshness window. When set, ``timestamp`` (the unix
        seconds the payload was minted) must be inside the window or
        the call raises. Used by the email-approval flow for the 1-hour
        TTL — Slack/Teams callbacks pass ``None`` since their outer
        transport (Bolt / MS Teams JWT) already handles replay.
    timestamp
        Unix seconds at which the payload was issued. Required when
        ``max_age_seconds`` is set.

    Raises
    ------
    HmacVerificationError
        On any failure: empty secret, mismatched digest length,
        constant-time mismatch, or expired payload.
    """
    if not secret:
        raise HmacVerificationError("HMAC secret is empty — refusing to verify")
    if not signature:
        raise HmacVerificationError("Missing signature")

    expected = sign(payload, secret=secret)
    # ``compare_digest`` rejects non-equal length inputs in constant time
    # and shields against timing oracles on the per-byte comparison.
    if not hmac.compare_digest(expected, signature):
        raise HmacVerificationError("Signature mismatch")

    if max_age_seconds is not None:
        if timestamp is None:
            raise HmacVerificationError("max_age_seconds set but timestamp not provided")
        age = time.time() - float(timestamp)
        if age > max_age_seconds:
            raise HmacVerificationError(f"Signature expired ({int(age)}s > {max_age_seconds}s)")
        if age < -60:
            # Allow a small clock-skew window in the future direction
            # (-60s) so we don't reject a payload minted on a slightly
            # ahead-of-NTP issuer.
            raise HmacVerificationError("Signature timestamp is in the future")
