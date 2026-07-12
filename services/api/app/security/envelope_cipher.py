"""KMS/HSM envelope encryption for the credential vault (Phase 1.6).

The `CredentialVault` (`credential_vault.py`) protects connector secrets with a
single Fernet key mounted from an env var. That is adequate for a hobby deploy
but not for what this vault actually holds: live credentials to CrowdStrike,
AWS, Okta, Splunk, and GitHub. Compromising the env key compromises everything.

This module adds an optional **envelope-encryption** layer:

- A fresh random **data encryption key (DEK)** is generated per secret and used
  to encrypt the plaintext (Fernet / AES-128-CBC + HMAC).
- The DEK is then **wrapped (encrypted) by a key encryption key (KEK)** that
  never leaves the KMS/HSM. Only the wrapped DEK + ciphertext are stored.
- Token format: ``vault:v2:<kek_id>:<b64 wrapped_dek>:<b64 ciphertext>``.

Because the KEK stays in KMS, a database dump or a leaked env var does not
reveal the DEKs, and **key rotation is re-wrapping the DEKs** (cheap, no
plaintext ever touches the process beyond the DEK) rather than re-encrypting
every secret body.

The `KeyManager` protocol keeps the KMS backend pluggable:

- `LocalKeyManager` — KEK is a Fernet key from the environment (default; matches
  today's trust model but with per-secret DEKs).
- `AwsKmsKeyManager` — wraps DEKs via AWS KMS ``encrypt``/``decrypt`` (boto3,
  lazy-imported). GCP KMS / HashiCorp Vault Transit implement the same protocol.
- `FakeKmsKeyManager` — in-memory, rotatable; lets the envelope round-trip and
  the rotation/re-wrap flow be unit-tested offline with no cloud credentials.

This module is pure (no DB, no `settings` import) so it is trivially testable.
"""

from __future__ import annotations

import base64
from typing import Protocol, runtime_checkable

from cryptography.fernet import Fernet, InvalidToken

_ENVELOPE_PREFIX = "vault:v2:"


class EnvelopeError(RuntimeError):
    """Raised when envelope encryption/decryption cannot proceed safely."""


@runtime_checkable
class KeyManager(Protocol):
    """Wraps/unwraps data-encryption keys with a KEK held in a KMS/HSM."""

    @property
    def key_id(self) -> str:
        """Identifier of the current (primary) KEK, embedded in the token."""

    def wrap(self, dek: bytes) -> bytes:
        """Encrypt a DEK under the current KEK."""

    def unwrap(self, wrapped: bytes, key_id: str) -> bytes:
        """Decrypt a DEK that was wrapped under the KEK named ``key_id``."""


class LocalKeyManager:
    """KEK is a local Fernet key (env-mounted). Default backend.

    Supports rotation: pass historical KEKs so DEKs wrapped under an old KEK
    still unwrap until they have been re-wrapped.
    """

    def __init__(self, primary_key: bytes, *, key_id: str = "local-1", historical: dict[str, bytes] | None = None) -> None:
        self._key_id = key_id
        try:
            self._primary = Fernet(primary_key)
        except (TypeError, ValueError) as exc:
            raise EnvelopeError(f"invalid local KEK: {exc}") from exc
        self._ring: dict[str, Fernet] = {key_id: self._primary}
        for kid, key in (historical or {}).items():
            try:
                self._ring[kid] = Fernet(key)
            except (TypeError, ValueError):
                continue

    @property
    def key_id(self) -> str:
        return self._key_id

    def wrap(self, dek: bytes) -> bytes:
        return self._primary.encrypt(dek)

    def unwrap(self, wrapped: bytes, key_id: str) -> bytes:
        fernet = self._ring.get(key_id)
        if fernet is None:
            raise EnvelopeError(f"no KEK available for key_id {key_id!r}")
        try:
            return fernet.decrypt(wrapped)
        except InvalidToken as exc:
            raise EnvelopeError("wrapped DEK failed integrity check") from exc


class AwsKmsKeyManager:
    """Wraps DEKs via AWS KMS. Requires boto3 + AWS credentials at runtime.

    The KEK never leaves KMS; we call ``encrypt``/``decrypt`` on the DEK bytes.
    ``key_id`` is the KMS key ARN/alias, and KMS resolves the correct key
    material for ``decrypt`` from the ciphertext blob, so rotation is handled by
    KMS-managed key versions transparently.
    """

    def __init__(self, kms_key_id: str, *, client: object | None = None) -> None:
        self._key_id = kms_key_id
        if client is not None:
            self._client = client
        else:  # pragma: no cover - requires AWS creds
            import boto3  # type: ignore[import]

            self._client = boto3.client("kms")

    @property
    def key_id(self) -> str:
        return self._key_id

    def wrap(self, dek: bytes) -> bytes:  # pragma: no cover - requires AWS/mocked client
        resp = self._client.encrypt(KeyId=self._key_id, Plaintext=dek)  # type: ignore[attr-defined]
        return resp["CiphertextBlob"]

    def unwrap(self, wrapped: bytes, key_id: str) -> bytes:  # pragma: no cover - requires AWS/mocked client
        resp = self._client.decrypt(CiphertextBlob=wrapped, KeyId=self._key_id)  # type: ignore[attr-defined]
        return resp["Plaintext"]


class FakeKmsKeyManager:
    """In-memory KMS stand-in for tests. Rotatable.

    Wrapping XORs the DEK with a per-KEK keystream (deterministic, reversible) —
    good enough to prove the envelope + rotation flow without a crypto backend.
    """

    def __init__(self) -> None:
        self._keys: dict[str, bytes] = {}
        self._current: str = ""
        self.rotate("kek-1")

    def rotate(self, key_id: str) -> None:
        import os

        self._keys[key_id] = os.urandom(32)
        self._current = key_id

    @property
    def key_id(self) -> str:
        return self._current

    def _xor(self, data: bytes, key: bytes) -> bytes:
        return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

    def wrap(self, dek: bytes) -> bytes:
        return self._xor(dek, self._keys[self._current])

    def unwrap(self, wrapped: bytes, key_id: str) -> bytes:
        key = self._keys.get(key_id)
        if key is None:
            raise EnvelopeError(f"no KEK for {key_id!r}")
        return self._xor(wrapped, key)


class EnvelopeCipher:
    """Per-secret envelope encryption over a pluggable :class:`KeyManager`."""

    def __init__(self, key_manager: KeyManager) -> None:
        self._km = key_manager

    def encrypt(self, plaintext: str) -> str:
        if not isinstance(plaintext, str):
            raise EnvelopeError(f"encrypt expects str, got {type(plaintext).__name__}")
        if plaintext.startswith(_ENVELOPE_PREFIX):
            return plaintext
        dek = Fernet.generate_key()
        ciphertext = Fernet(dek).encrypt(plaintext.encode("utf-8"))
        wrapped = self._km.wrap(dek)
        return (
            f"{_ENVELOPE_PREFIX}{self._km.key_id}:"
            f"{base64.urlsafe_b64encode(wrapped).decode('ascii')}:"
            f"{base64.urlsafe_b64encode(ciphertext).decode('ascii')}"
        )

    def _parse(self, token: str) -> tuple[str, bytes, bytes]:
        if not token.startswith(_ENVELOPE_PREFIX):
            raise EnvelopeError("not a vault:v2 envelope token")
        body = token[len(_ENVELOPE_PREFIX) :]
        try:
            key_id, wrapped_b64, ct_b64 = body.split(":", 2)
            # binascii.Error (raised by b64decode) is a ValueError subclass.
            wrapped = base64.urlsafe_b64decode(wrapped_b64)
            ciphertext = base64.urlsafe_b64decode(ct_b64)
        except ValueError as exc:
            raise EnvelopeError(f"malformed envelope token: {exc}") from exc
        return key_id, wrapped, ciphertext

    def decrypt(self, token: str) -> str:
        if not isinstance(token, str):
            raise EnvelopeError(f"decrypt expects str, got {type(token).__name__}")
        if not token.startswith(_ENVELOPE_PREFIX):
            return token  # plaintext / v1 pass-through
        key_id, wrapped, ciphertext = self._parse(token)
        dek = self._km.unwrap(wrapped, key_id)
        try:
            return Fernet(dek).decrypt(ciphertext).decode("utf-8")
        except (InvalidToken, ValueError) as exc:
            # ValueError covers a corrupt/wrong DEK (e.g. unwrapped under the
            # wrong KEK) producing invalid Fernet key material. Fail closed.
            raise EnvelopeError("ciphertext failed integrity check") from exc

    def rewrap(self, token: str) -> str:
        """Re-wrap the DEK under the current KEK without touching plaintext.

        This is the rotation primitive: after rotating the KEK, run this over
        every stored token. The DEK is unwrapped with its original KEK and
        re-wrapped with the current one; the secret body is never re-encrypted
        and the plaintext never leaves KMS's reach.
        """
        key_id, wrapped, ciphertext = self._parse(token)
        dek = self._km.unwrap(wrapped, key_id)
        rewrapped = self._km.wrap(dek)
        return (
            f"{_ENVELOPE_PREFIX}{self._km.key_id}:"
            f"{base64.urlsafe_b64encode(rewrapped).decode('ascii')}:"
            f"{base64.urlsafe_b64encode(ciphertext).decode('ascii')}"
        )
