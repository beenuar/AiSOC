"""
Unit tests for :mod:`app.services.hmac_verify`.

Coverage:

* sign/verify round-trip with the canonical payload form
* signature mismatch raises HmacVerificationError
* empty secret on sign and verify is rejected
* missing signature is rejected
* freshness window — expired, future-skew, within window
* timing-safe compare path (digest length mismatch)
"""

from __future__ import annotations

import time

import pytest
from app.services.hmac_verify import HmacVerificationError, sign, verify

SECRET = "test-secret-not-real"


def test_sign_and_verify_roundtrip():
    payload = "approve|action-1|case-9|1700000000"
    signature = sign(payload, secret=SECRET)
    # Should be a 64-char hex digest.
    assert len(signature) == 64
    int(signature, 16)
    verify(payload, signature, secret=SECRET)


def test_verify_rejects_wrong_signature():
    payload = "approve|action-1|case-9|1700000000"
    signature = sign(payload, secret=SECRET)
    with pytest.raises(HmacVerificationError, match="mismatch"):
        verify(payload, signature[:-1] + ("0" if signature[-1] != "0" else "1"), secret=SECRET)


def test_verify_rejects_signature_with_wrong_secret():
    payload = "approve|action-1|case-9|1700000000"
    signature = sign(payload, secret=SECRET)
    with pytest.raises(HmacVerificationError, match="mismatch"):
        verify(payload, signature, secret="different-secret")


def test_sign_rejects_empty_secret():
    with pytest.raises(HmacVerificationError, match="empty"):
        sign("anything", secret="")


def test_verify_rejects_empty_secret():
    with pytest.raises(HmacVerificationError, match="empty"):
        verify("anything", "deadbeef", secret="")


def test_verify_rejects_missing_signature():
    with pytest.raises(HmacVerificationError, match="Missing"):
        verify("payload", "", secret=SECRET)


def test_verify_rejects_short_digest():
    # constant-time compare rejects unequal-length inputs.
    payload = "approve|action-1|case-9|1700000000"
    full = sign(payload, secret=SECRET)
    with pytest.raises(HmacVerificationError, match="mismatch"):
        verify(payload, full[:32], secret=SECRET)


def test_verify_expires_outside_window():
    payload = "approve|action-1|case-9|0"
    signature = sign(payload, secret=SECRET)
    # 2 hours ago, max_age = 1h
    issued_at = time.time() - 7200
    with pytest.raises(HmacVerificationError, match="expired"):
        verify(payload, signature, secret=SECRET, max_age_seconds=3600, timestamp=issued_at)


def test_verify_within_window():
    payload = "approve|action-1|case-9|0"
    signature = sign(payload, secret=SECRET)
    # 30 minutes ago, max_age = 1h
    issued_at = time.time() - 1800
    verify(payload, signature, secret=SECRET, max_age_seconds=3600, timestamp=issued_at)


def test_verify_rejects_future_timestamp_beyond_skew():
    payload = "approve|action-1|case-9|0"
    signature = sign(payload, secret=SECRET)
    # 5 minutes in the future — past the 60s skew window
    issued_at = time.time() + 300
    with pytest.raises(HmacVerificationError, match="future"):
        verify(payload, signature, secret=SECRET, max_age_seconds=3600, timestamp=issued_at)


def test_verify_requires_timestamp_when_max_age_set():
    payload = "approve|action-1|case-9|0"
    signature = sign(payload, secret=SECRET)
    with pytest.raises(HmacVerificationError, match="timestamp"):
        verify(payload, signature, secret=SECRET, max_age_seconds=3600)
