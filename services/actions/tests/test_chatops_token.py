"""Round-trip tests for the ChatOps callback HMAC tokens.

This module is security-critical: the only thing protecting the callback
endpoint from forged "the user said yes" responses is the signature on
these tokens. Every check below is here because if it silently regresses,
a malicious chat user could acknowledge prompts that were never sent to
them, suppressing legitimate alerts.
"""

from __future__ import annotations

import time
from uuid import uuid4

import pytest
from app.security.chatops_token import (
    ChatOpsTokenError,
    mint_token,
    verify_token,
)

_SECRET = "test-secret-do-not-use-in-prod"


def _mint(**overrides):
    """Mint a token with sensible defaults so individual tests can override
    only the field they care about."""
    base = {
        "action_id": uuid4(),
        "case_id": uuid4(),
        "tenant_id": uuid4(),
        "choice": "acknowledge",
        "user_ref": "alice@example.com",
        "secret": _SECRET,
        "ttl_seconds": 900,
    }
    base.update(overrides)
    return base, mint_token(**base)


def test_round_trip_returns_original_claims():
    args, token = _mint()
    claims = verify_token(token, _SECRET)
    assert claims.action_id == args["action_id"]
    assert claims.case_id == args["case_id"]
    assert claims.tenant_id == args["tenant_id"]
    assert claims.choice == "acknowledge"
    assert claims.user_ref == "alice@example.com"
    assert claims.expires_at > claims.issued_at


def test_tampered_payload_fails_signature():
    _, token = _mint()
    payload, sig = token.split(".", 1)
    # Flip a single character in the payload — should invalidate HMAC.
    tampered_payload = payload[:-1] + ("A" if payload[-1] != "A" else "B")
    with pytest.raises(ChatOpsTokenError, match="invalid_signature"):
        verify_token(f"{tampered_payload}.{sig}", _SECRET)


def test_wrong_secret_fails_signature():
    _, token = _mint()
    with pytest.raises(ChatOpsTokenError, match="invalid_signature"):
        verify_token(token, "different-secret")


def test_expired_token_is_rejected():
    _, token = _mint(ttl_seconds=1)
    # Verify in the future, past the TTL.
    with pytest.raises(ChatOpsTokenError, match="expired"):
        verify_token(token, _SECRET, now=int(time.time()) + 5)


def test_unsupported_choice_is_rejected_at_mint_time():
    """Tokens for unknown choices never get minted, so the callback handler
    never has to make a policy call about how to log them."""
    with pytest.raises(ChatOpsTokenError, match="unsupported choice"):
        mint_token(
            action_id=uuid4(),
            case_id=uuid4(),
            tenant_id=uuid4(),
            choice="confirm-everything",  # not in the allowed set
            user_ref="alice",
            secret=_SECRET,
            ttl_seconds=900,
        )


def test_missing_secret_at_mint_or_verify_is_rejected():
    with pytest.raises(ChatOpsTokenError):
        mint_token(
            action_id=uuid4(),
            case_id=uuid4(),
            tenant_id=uuid4(),
            choice="deny",
            user_ref="alice",
            secret="",
            ttl_seconds=900,
        )
    _, token = _mint()
    with pytest.raises(ChatOpsTokenError):
        verify_token(token, "")


def test_malformed_token_fails_clean():
    with pytest.raises(ChatOpsTokenError, match="malformed"):
        verify_token("not-a-valid-token", _SECRET)
    with pytest.raises(ChatOpsTokenError, match="malformed"):
        verify_token("a.b.c", _SECRET)


def test_each_choice_produces_distinct_tokens():
    """Defensive: same action+case but different choice must produce
    different signatures. Otherwise the callback can't tell which button
    the user pressed."""
    base = {
        "action_id": uuid4(),
        "case_id": uuid4(),
        "tenant_id": uuid4(),
        "user_ref": "alice",
        "secret": _SECRET,
        "ttl_seconds": 900,
    }
    ack = mint_token(choice="acknowledge", **base)
    deny = mint_token(choice="deny", **base)
    escalate = mint_token(choice="escalate", **base)
    assert len({ack, deny, escalate}) == 3
