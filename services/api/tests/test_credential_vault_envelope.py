"""Envelope encryption must be reachable from the vault, and safe to enable.

``EnvelopeCipher`` existed, was unit-tested, and had zero callers, while the
threat model cited it as the control mitigating "a DB dump exposes every
connector credential". Wiring it is only half the job: the risk in switching
a credential store's format is stranding the secrets already stored, so these
tests are weighted towards the compatibility boundary rather than the crypto,
which ``test_envelope_cipher.py`` already covers.
"""

from __future__ import annotations

import pytest
from app.core.config import settings
from app.security.credential_vault import (
    CredentialVault,
    CredentialVaultError,
    _build_envelope,
    get_vault,
    reset_vault_for_tests,
)
from app.security.envelope_cipher import EnvelopeCipher, LocalKeyManager
from cryptography.fernet import Fernet

PRIMARY = Fernet.generate_key()
KEK = Fernet.generate_key()


def _envelope() -> EnvelopeCipher:
    return EnvelopeCipher(LocalKeyManager(KEK))


class TestWritePath:
    def test_default_still_writes_v1(self) -> None:
        vault = CredentialVault(PRIMARY)
        token = vault.encrypt("s3cret")
        assert token.startswith("vault:v1:")
        assert vault.decrypt(token) == "s3cret"

    def test_envelope_mode_writes_v2(self) -> None:
        vault = CredentialVault(PRIMARY, envelope=_envelope())
        token = vault.encrypt("s3cret")
        assert token.startswith("vault:v2:")
        assert vault.decrypt(token) == "s3cret"

    def test_v2_token_does_not_contain_the_secret(self) -> None:
        vault = CredentialVault(PRIMARY, envelope=_envelope())
        assert "AKIAIOSFODNN7EXAMPLE" not in vault.encrypt("AKIAIOSFODNN7EXAMPLE")

    def test_each_secret_gets_a_distinct_dek(self) -> None:
        """The blast-radius property: one leaked DEK must expose one secret."""
        vault = CredentialVault(PRIMARY, envelope=_envelope())
        a = vault.encrypt("same value")
        b = vault.encrypt("same value")
        assert a != b
        wrapped_a = a.split(":")[3]
        wrapped_b = b.split(":")[3]
        assert wrapped_a != wrapped_b

    def test_encrypt_is_idempotent_across_both_versions(self) -> None:
        vault = CredentialVault(PRIMARY, envelope=_envelope())
        v2 = vault.encrypt("x")
        assert vault.encrypt(v2) == v2
        v1 = CredentialVault(PRIMARY).encrypt("x")
        assert vault.encrypt(v1) == v1, "a v1 token must not be double-encrypted into v2"


class TestReadCompatibility:
    """Enabling envelope mode must not strand secrets written before it."""

    def test_v1_written_before_the_switch_still_reads(self) -> None:
        before = CredentialVault(PRIMARY)
        token = before.encrypt("legacy-credential")

        after = CredentialVault(PRIMARY, envelope=_envelope())
        assert after.decrypt(token) == "legacy-credential"

    def test_mixed_dict_round_trips(self) -> None:
        """A real auth_config mid-migration: some leaves v1, some v2."""
        legacy = CredentialVault(PRIMARY)
        payload = {
            "api_key": legacy.encrypt("old-key"),
            "region": "us-east-1",
            "nested": {"token": legacy.encrypt("old-token")},
        }

        vault = CredentialVault(PRIMARY, envelope=_envelope())
        payload["client_secret"] = vault.encrypt("new-secret")

        out = vault.decrypt_dict(payload)
        assert out["api_key"] == "old-key"
        assert out["nested"]["token"] == "old-token"
        assert out["client_secret"] == "new-secret"
        assert out["region"] == "us-east-1"

    def test_rewriting_a_row_upgrades_it_to_v2(self) -> None:
        """The documented migration path: rows upgrade when next written."""
        vault = CredentialVault(PRIMARY, envelope=_envelope())
        legacy_token = CredentialVault(PRIMARY).encrypt("secret")
        plaintext = vault.decrypt(legacy_token)
        assert vault.encrypt(plaintext).startswith("vault:v2:")

    def test_plaintext_still_passes_through(self) -> None:
        vault = CredentialVault(PRIMARY, envelope=_envelope())
        assert vault.decrypt("not-encrypted-at-all") == "not-encrypted-at-all"


class TestFailClosed:
    def test_v2_token_without_an_envelope_is_an_error_not_a_passthrough(self) -> None:
        """The dangerous case: disabling envelope mode with v2 rows present.

        Returning the token unchanged would hand ciphertext to a connector as
        if it were a credential, producing a vendor auth failure that looks
        like a customer configuration problem.
        """
        token = CredentialVault(PRIMARY, envelope=_envelope()).encrypt("secret")
        plain_vault = CredentialVault(PRIMARY)
        with pytest.raises(CredentialVaultError, match="envelope encryption is disabled"):
            plain_vault.decrypt(token)

    def test_wrong_kek_fails_closed(self) -> None:
        token = CredentialVault(PRIMARY, envelope=_envelope()).encrypt("secret")
        other = EnvelopeCipher(LocalKeyManager(Fernet.generate_key()))
        with pytest.raises(CredentialVaultError, match="envelope decrypt failed"):
            CredentialVault(PRIMARY, envelope=other).decrypt(token)

    def test_tampered_v2_token_fails_closed(self) -> None:
        vault = CredentialVault(PRIMARY, envelope=_envelope())
        token = vault.encrypt("secret")
        head, _, tail = token.rpartition(":")
        tampered = f"{head}:{'A' + tail[1:]}"
        with pytest.raises(CredentialVaultError):
            vault.decrypt(tampered)


class TestConfiguration:
    @pytest.fixture(autouse=True)
    def _reset(self) -> None:
        reset_vault_for_tests()
        yield
        reset_vault_for_tests()

    def test_off_is_the_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(settings, "AISOC_CREDENTIAL_ENVELOPE", "off")
        assert _build_envelope() is None

    @pytest.mark.parametrize("value", ["", "off", "OFF", "none", "0", "false"])
    def test_disabled_spellings(self, monkeypatch: pytest.MonkeyPatch, value: str) -> None:
        monkeypatch.setattr(settings, "AISOC_CREDENTIAL_ENVELOPE", value)
        assert _build_envelope() is None

    def test_local_mode_requires_a_kek(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(settings, "AISOC_CREDENTIAL_ENVELOPE", "local")
        monkeypatch.setattr(settings, "AISOC_CREDENTIAL_KEK", "")
        with pytest.raises(CredentialVaultError, match="AISOC_CREDENTIAL_KEK"):
            _build_envelope()

    def test_local_mode_builds(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(settings, "AISOC_CREDENTIAL_ENVELOPE", "local")
        monkeypatch.setattr(settings, "AISOC_CREDENTIAL_KEK", KEK.decode())
        monkeypatch.setattr(settings, "AISOC_CREDENTIAL_KEK_ROTATION_FROM", "")
        cipher = _build_envelope()
        assert cipher is not None
        assert cipher.decrypt(cipher.encrypt("v")) == "v"

    def test_aws_mode_requires_a_key_id(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(settings, "AISOC_CREDENTIAL_ENVELOPE", "aws")
        monkeypatch.setattr(settings, "AISOC_KMS_KEY_ID", "")
        with pytest.raises(CredentialVaultError, match="AISOC_KMS_KEY_ID"):
            _build_envelope()

    def test_unknown_mode_refuses_rather_than_silently_downgrading(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A typo must not leave the deployment writing v1 while believing v2."""
        monkeypatch.setattr(settings, "AISOC_CREDENTIAL_ENVELOPE", "kms-v2")
        with pytest.raises(CredentialVaultError, match="not recognised"):
            _build_envelope()

    def test_get_vault_honours_the_setting(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(settings, "AISOC_CREDENTIAL_KEY", PRIMARY.decode())
        monkeypatch.setattr(settings, "AISOC_CREDENTIAL_KEY_ROTATION_FROM", "")
        monkeypatch.setattr(settings, "AISOC_CREDENTIAL_ENVELOPE", "local")
        monkeypatch.setattr(settings, "AISOC_CREDENTIAL_KEK", KEK.decode())
        monkeypatch.setattr(settings, "AISOC_CREDENTIAL_KEK_ROTATION_FROM", "")
        assert get_vault().encrypt("s").startswith("vault:v2:")
