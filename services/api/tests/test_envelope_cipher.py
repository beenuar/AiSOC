"""Tests for KMS envelope encryption + rotation (Phase 1.6).

Offline via FakeKmsKeyManager. The core guarantees:
- round-trip correctness,
- plaintext never appears in the stored token (what lands in a DB row),
- KEK rotation is a re-wrap that never re-encrypts the secret body,
- tampering fails closed.
"""

from __future__ import annotations

import pytest
from app.security.envelope_cipher import (
    EnvelopeCipher,
    EnvelopeError,
    FakeKmsKeyManager,
    LocalKeyManager,
)
from cryptography.fernet import Fernet

SECRET = "crowdstrike-api-token-SUPERSECRET-9f3a"


def test_round_trip_fake_kms():
    cipher = EnvelopeCipher(FakeKmsKeyManager())
    token = cipher.encrypt(SECRET)
    assert token.startswith("vault:v2:")
    assert cipher.decrypt(token) == SECRET


def test_plaintext_never_appears_in_token():
    cipher = EnvelopeCipher(FakeKmsKeyManager())
    token = cipher.encrypt(SECRET)
    # The token is exactly what gets written to the DB row / could hit a log.
    assert SECRET not in token
    for frag in ("SUPERSECRET", "crowdstrike-api-token"):
        assert frag not in token


def test_each_encrypt_uses_a_fresh_dek():
    cipher = EnvelopeCipher(FakeKmsKeyManager())
    t1 = cipher.encrypt(SECRET)
    t2 = cipher.encrypt(SECRET)
    assert t1 != t2  # fresh DEK per secret -> different ciphertext + wrapped dek
    assert cipher.decrypt(t1) == cipher.decrypt(t2) == SECRET


def test_kek_rotation_then_rewrap():
    km = FakeKmsKeyManager()  # starts at kek-1
    cipher = EnvelopeCipher(km)
    token_v1 = cipher.encrypt(SECRET)
    assert ":kek-1:" in token_v1

    # Rotate the KEK. The old token still decrypts because the old KEK is
    # retained for unwrap.
    km.rotate("kek-2")
    assert cipher.decrypt(token_v1) == SECRET

    # Re-wrap: DEK is unwrapped with kek-1 and re-wrapped with kek-2. The
    # ciphertext body is unchanged; only the wrapped-DEK segment rotates.
    token_v2 = cipher.rewrap(token_v1)
    assert ":kek-2:" in token_v2
    assert token_v1.rsplit(":", 1)[-1] == token_v2.rsplit(":", 1)[-1]  # same ciphertext body
    assert cipher.decrypt(token_v2) == SECRET


def test_local_key_manager_round_trip_and_rotation():
    kek1 = Fernet.generate_key()
    kek2 = Fernet.generate_key()
    cipher1 = EnvelopeCipher(LocalKeyManager(kek1, key_id="local-1"))
    token = cipher1.encrypt(SECRET)
    assert ":local-1:" in token

    # New primary KEK, old kept for unwrap.
    cipher2 = EnvelopeCipher(LocalKeyManager(kek2, key_id="local-2", historical={"local-1": kek1}))
    assert cipher2.decrypt(token) == SECRET
    rewrapped = cipher2.rewrap(token)
    assert ":local-2:" in rewrapped
    assert cipher2.decrypt(rewrapped) == SECRET


def test_tampered_ciphertext_fails_closed():
    cipher = EnvelopeCipher(FakeKmsKeyManager())
    token = cipher.encrypt(SECRET)
    tampered = token[:-4] + ("AAAA" if not token.endswith("AAAA") else "BBBB")
    with pytest.raises(EnvelopeError):
        cipher.decrypt(tampered)


def test_plaintext_passthrough_and_idempotent_encrypt():
    cipher = EnvelopeCipher(FakeKmsKeyManager())
    assert cipher.decrypt("plain-legacy-value") == "plain-legacy-value"
    token = cipher.encrypt(SECRET)
    assert cipher.encrypt(token) == token  # already enveloped -> unchanged


def test_malformed_token_raises():
    cipher = EnvelopeCipher(FakeKmsKeyManager())
    with pytest.raises(EnvelopeError):
        cipher._parse("vault:v2:onlyonesegment")


def test_unwrap_with_unknown_kek_fails():
    km = FakeKmsKeyManager()
    cipher = EnvelopeCipher(km)
    token = cipher.encrypt(SECRET)
    fresh = EnvelopeCipher(FakeKmsKeyManager())  # different in-memory KEKs
    with pytest.raises(EnvelopeError):
        fresh.decrypt(token)
