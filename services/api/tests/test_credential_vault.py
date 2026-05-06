"""Tests for :mod:`app.security.credential_vault`.

These tests are intentionally hermetic — they construct vaults with explicit
keys rather than relying on the global singleton, so they don't depend on
process env vars or the order other test modules import settings in.
"""

from __future__ import annotations

import pytest
from app.security.credential_vault import (
    _CIPHER_PREFIX,
    CredentialVault,
    CredentialVaultError,
)
from cryptography.fernet import Fernet


@pytest.fixture
def vault() -> CredentialVault:
    return CredentialVault(Fernet.generate_key())


def test_round_trip_string(vault: CredentialVault) -> None:
    ct = vault.encrypt("super-secret-token")
    assert ct.startswith(_CIPHER_PREFIX)
    assert "super-secret-token" not in ct
    assert vault.decrypt(ct) == "super-secret-token"


def test_encrypt_is_idempotent(vault: CredentialVault) -> None:
    """Re-encrypting an already-encrypted value is a no-op."""
    ct = vault.encrypt("v")
    assert vault.encrypt(ct) == ct


def test_decrypt_passes_plaintext_through(vault: CredentialVault) -> None:
    """Plaintext rows from older builds must round-trip cleanly."""
    assert vault.decrypt("not-encrypted-yet") == "not-encrypted-yet"


def test_encrypt_dict_recursive(vault: CredentialVault) -> None:
    payload = {
        "client_id": "abc",
        "client_secret": "shh",
        "service_account": {
            "private_key": "-----BEGIN PRIVATE KEY-----\nXYZ\n-----END PRIVATE KEY-----",
            "client_email": "svc@example.iam.gserviceaccount.com",
        },
        "tags": ["prod", "us-east"],
        "max_events": 500,
        "enabled": True,
    }
    encrypted = vault.encrypt_dict(payload)

    assert encrypted["client_id"].startswith(_CIPHER_PREFIX)
    assert encrypted["client_secret"].startswith(_CIPHER_PREFIX)
    assert encrypted["service_account"]["private_key"].startswith(_CIPHER_PREFIX)
    assert encrypted["service_account"]["client_email"].startswith(_CIPHER_PREFIX)
    # Lists of strings get encrypted at the leaves.
    for tag in encrypted["tags"]:
        assert tag.startswith(_CIPHER_PREFIX)
    # Numbers and bools are untouched.
    assert encrypted["max_events"] == 500
    assert encrypted["enabled"] is True

    decrypted = vault.decrypt_dict(encrypted)
    assert decrypted == payload


def test_encrypt_dict_with_secret_keys_filter(vault: CredentialVault) -> None:
    payload = {
        "client_id": "public-id",  # leave alone
        "client_secret": "shh",     # encrypt
        "region": "us-east-1",      # leave alone
    }
    encrypted = vault.encrypt_dict(payload, secret_keys={"client_secret"})
    assert encrypted["client_id"] == "public-id"
    assert encrypted["region"] == "us-east-1"
    assert encrypted["client_secret"].startswith(_CIPHER_PREFIX)


def test_invalid_key_raises() -> None:
    with pytest.raises(CredentialVaultError):
        CredentialVault(b"not-a-real-key")


def test_empty_key_raises() -> None:
    with pytest.raises(CredentialVaultError):
        CredentialVault(b"")


def test_rotation_decrypts_old_ciphertext() -> None:
    """A new primary key plus the old key in rotation must decrypt old rows."""
    old_key = Fernet.generate_key()
    new_key = Fernet.generate_key()

    old_vault = CredentialVault(old_key)
    legacy_ct = old_vault.encrypt("legacy-secret")

    rotated = CredentialVault(new_key, historical_keys=[old_key])
    assert rotated.decrypt(legacy_ct) == "legacy-secret"
    # New writes use the new primary, but old reads still work.
    new_ct = rotated.encrypt("new-secret")
    assert rotated.decrypt(new_ct) == "new-secret"


def test_tampered_ciphertext_rejected(vault: CredentialVault) -> None:
    ct = vault.encrypt("important")
    tampered = ct[:-3] + "AAA"  # mutate the trailing chars of the token
    with pytest.raises(CredentialVaultError):
        vault.decrypt(tampered)


def test_non_string_inputs_rejected(vault: CredentialVault) -> None:
    with pytest.raises(CredentialVaultError):
        vault.encrypt(123)  # type: ignore[arg-type]
    with pytest.raises(CredentialVaultError):
        vault.decrypt(None)  # type: ignore[arg-type]


def test_invalid_rotation_key_is_skipped_not_fatal() -> None:
    """One bad rotation entry must not take the whole vault offline."""
    primary = Fernet.generate_key()
    bogus = b"definitely-not-a-fernet-key"
    v = CredentialVault(primary, historical_keys=[bogus])
    ct = v.encrypt("ok")
    assert v.decrypt(ct) == "ok"
