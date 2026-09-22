"""Application-layer encryption for connector credentials.

This module wraps :mod:`cryptography.fernet` to give the rest of the API a
narrow, opinionated interface for storing connector ``auth_config`` payloads
encrypted at rest. The model column itself stays a regular JSONB blob so
operators can query for which tenant owns which connector without having to
decrypt anything; only the field values inside the JSON are ciphertext.

Why Fernet (AES-128-CBC + HMAC-SHA256, plus a versioned token format) rather
than rolling our own AES-GCM:

* Authenticated encryption out of the box — tampering raises
  :class:`InvalidToken`, never a silent partial decrypt.
* Built-in support for **multi-key rotation** via :class:`MultiFernet`. We use
  it so operators can rotate ``AISOC_CREDENTIAL_KEY`` without a downtime
  migration: new writes use the primary key, old reads still resolve through
  any key listed in ``AISOC_CREDENTIAL_KEY_ROTATION_FROM``.
* Battle-tested and audited; we'd rather lean on the upstream than ship a
  hand-rolled crypto module in an open-source SOC product.

What the vault deliberately does **not** do:

* It does not derive a key from the user's password. We expect operators to
  generate a key with :func:`cryptography.fernet.Fernet.generate_key` and
  mount it via Fly.io secret / k8s secret / vault. Plaintext keys never
  appear in logs.
* It does not encrypt the *whole* ``auth_config`` blob as a single
  ciphertext. Each leaf string value is encrypted individually so:
    1. structural fields (e.g. region, base URL) stay queryable for ops, and
    2. partial decryption failures don't lose the rest of the row.

The vault is intentionally pure — it does not touch the DB, doesn't take a
``Settings`` instance, and is therefore trivially unit-testable without a
live Postgres or Redis.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from threading import Lock
from typing import Any, Final

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from app.core.config import is_dev_env, settings
from app.security.envelope_cipher import (
    AwsKmsKeyManager,
    EnvelopeCipher,
    EnvelopeError,
    LocalKeyManager,
)

logger = logging.getLogger("aisoc.credential_vault")

# Sentinel prefix that marks a string value as already-encrypted ciphertext.
# We tag every value we write so the decrypt path can distinguish "this is
# encrypted, run it through Fernet" from "this is a plaintext we just got
# back from a never-encrypted legacy row, leave it alone". The prefix is
# deliberately not a valid Fernet token start byte (``gAAAAA...``) so we
# can never accidentally interpret a real ciphertext as plaintext.
_CIPHER_PREFIX: Final[str] = "vault:v1:"

# Envelope tokens (per-secret DEK, wrapped by a KEK). Reads always accept
# both prefixes; which one a *write* produces depends on configuration.
# See ``app.security.envelope_cipher``.
_ENVELOPE_PREFIX: Final[str] = "vault:v2:"


class CredentialVaultError(RuntimeError):
    """Raised when the vault cannot encrypt/decrypt safely.

    The caller should treat this as fatal for the current request rather than
    fall back to plaintext — that's the whole point of the vault.
    """


def _split_keys(raw: str) -> list[bytes]:
    """Parse a comma-separated list of base64 Fernet keys."""
    return [k.strip().encode("ascii") for k in raw.split(",") if k.strip()]


class CredentialVault:
    """Encrypt and decrypt connector credential payloads.

    Constructed from a primary key and an optional list of historical keys.
    The historical keys are only used for *decryption* via :class:`MultiFernet`
    so that a rotation is a two-step process:

    1. Add the old key to ``AISOC_CREDENTIAL_KEY_ROTATION_FROM`` and the new
       key to ``AISOC_CREDENTIAL_KEY``. Restart. All new writes use the new
       key, all old rows still decrypt.
    2. Run a maintenance job that re-saves every connector instance, which
       re-encrypts under the new primary. Once that's done, drop the old key
       from the rotation list.

    The class is *not* thread-locked at the per-call level (Fernet is
    thread-safe), but the lazy-init path uses a lock so concurrent requests
    don't race to generate a development-only ephemeral key.
    """

    def __init__(
        self,
        primary_key: bytes,
        historical_keys: list[bytes] | None = None,
        envelope: EnvelopeCipher | None = None,
    ) -> None:
        if not primary_key:
            raise CredentialVaultError("CredentialVault requires a non-empty primary key")
        try:
            primary = Fernet(primary_key)
        except (TypeError, ValueError) as exc:
            raise CredentialVaultError(f"AISOC_CREDENTIAL_KEY is not a valid Fernet key: {exc}") from exc

        keyring: list[Fernet] = [primary]
        for k in historical_keys or []:
            try:
                keyring.append(Fernet(k))
            except (TypeError, ValueError) as exc:
                # We log but don't fail — a bad rotation key shouldn't take the
                # whole API down. The operator will see the warning and the
                # affected ciphertexts will simply fail to decrypt.
                logger.warning("ignoring invalid rotation key: %s", exc)

        self._fernet = MultiFernet(keyring) if len(keyring) > 1 else primary
        # When set, new writes are envelope-encrypted. The Fernet keyring
        # stays live regardless so v1 rows written before the switch still
        # read — enabling envelope mode must never strand existing secrets.
        self._envelope = envelope

    @classmethod
    def with_envelope(
        cls,
        primary_key: bytes,
        envelope: EnvelopeCipher,
        *,
        historical_keys: list[bytes] | None = None,
    ) -> CredentialVault:
        """Build a vault whose *writes* are envelope-encrypted.

        A named constructor rather than a keyword argument on ``__init__``.
        Four modules in this repo are importable as
        ``app.security.credential_vault`` — the API owns the write path and
        services/actions, agents and connectors ship vendored read-path
        copies — so a call site passing ``envelope=`` is ambiguous to any
        reader, and to static analysis, about which class it means. The
        vendored copies have no such classmethod, which makes the intent
        unambiguous at the call site.

        Reads remain backward compatible either way: a ``vault:v1`` token
        written before envelope mode was enabled still decrypts.
        """
        return cls(primary_key, historical_keys=historical_keys, envelope=envelope)

    # --------------------------------------------------------------------- core

    def encrypt(self, value: str) -> str:
        """Encrypt a single string and return ``vault:v1:<token>``.

        Returns the input unchanged if it's already a vault token, so the
        caller can re-encrypt an entire dict idempotently.
        """
        if not isinstance(value, str):
            raise CredentialVaultError(f"vault.encrypt expects str, got {type(value).__name__}")
        if value.startswith(_CIPHER_PREFIX) or value.startswith(_ENVELOPE_PREFIX):
            return value
        if self._envelope is not None:
            try:
                return self._envelope.encrypt(value)
            except EnvelopeError as exc:
                # Falling back to v1 here would quietly downgrade the control
                # an operator explicitly enabled, so refuse instead.
                raise CredentialVaultError(f"envelope encryption failed: {exc}") from exc
        token = self._fernet.encrypt(value.encode("utf-8")).decode("ascii")
        return f"{_CIPHER_PREFIX}{token}"

    def decrypt(self, value: str) -> str:
        """Decrypt a vault-tagged string. Plaintext passes through.

        Plaintext pass-through is required so the vault stays compatible with
        rows written by older builds that didn't encrypt anything yet. We log
        on the plaintext path so operators have a clear migration signal.
        """
        if not isinstance(value, str):
            raise CredentialVaultError(f"vault.decrypt expects str, got {type(value).__name__}")
        if value.startswith(_ENVELOPE_PREFIX):
            if self._envelope is None:
                raise CredentialVaultError(
                    "found a vault:v2 envelope token but envelope encryption is disabled. "
                    "Set AISOC_CREDENTIAL_ENVELOPE (and the matching KEK) to the "
                    "configuration these secrets were written under."
                )
            try:
                return self._envelope.decrypt(value)
            except EnvelopeError as exc:
                raise CredentialVaultError(f"envelope decrypt failed: {exc}") from exc
        if not value.startswith(_CIPHER_PREFIX):
            return value
        token = value[len(_CIPHER_PREFIX) :].encode("ascii")
        try:
            return self._fernet.decrypt(token).decode("utf-8")
        except InvalidToken as exc:
            raise CredentialVaultError("ciphertext failed integrity check (key rotated without re-encrypt?)") from exc

    # ------------------------------------------------------------- dict helpers

    def encrypt_dict(self, payload: Mapping[str, Any], *, secret_keys: set[str] | None = None) -> dict[str, Any]:
        """Encrypt the *secret* string fields inside an ``auth_config`` blob.

        We default to encrypting **every** string value, which is the safe
        behaviour for connector secrets where almost everything (tokens,
        keys, JSON service-account blobs, even tenant IDs) leaks information
        an attacker could weaponise. Pass ``secret_keys`` if you want to
        restrict encryption to a specific subset of keys; everything else
        round-trips as-is.

        Lists and nested dicts are recursed into so a JSON service-account
        key (a deeply nested object) ends up fully encrypted at the leaves.
        """
        return self._walk(payload, encrypt=True, secret_keys=secret_keys)

    def decrypt_dict(self, payload: Mapping[str, Any], *, secret_keys: set[str] | None = None) -> dict[str, Any]:
        """Inverse of :meth:`encrypt_dict`. Safe to call on partially-encrypted dicts."""
        return self._walk(payload, encrypt=False, secret_keys=secret_keys)

    def _walk(self, payload: Any, *, encrypt: bool, secret_keys: set[str] | None, _key: str | None = None) -> Any:
        op = self.encrypt if encrypt else self.decrypt
        if isinstance(payload, Mapping):
            out: dict[str, Any] = {}
            for k, v in payload.items():
                # If the caller restricted to specific keys, leave everything
                # else alone. Otherwise fall through and recurse.
                if secret_keys is not None and k not in secret_keys and not isinstance(v, Mapping | list):
                    out[k] = v
                else:
                    out[k] = self._walk(v, encrypt=encrypt, secret_keys=secret_keys, _key=k)
            return out
        if isinstance(payload, list):
            return [self._walk(item, encrypt=encrypt, secret_keys=secret_keys, _key=_key) for item in payload]
        if isinstance(payload, str):
            return op(payload)
        # Booleans, numbers, None — no encryption to apply.
        return payload


# --------------------------------------------------------------- module helper

_vault_singleton: CredentialVault | None = None
_vault_lock = Lock()


def _build_envelope() -> EnvelopeCipher | None:
    """Construct the envelope cipher from configuration, or ``None`` when off.

    Refuses to start rather than silently degrading: an operator who sets
    AISOC_CREDENTIAL_ENVELOPE=aws and mistypes the key id should get a boot
    failure, not connector secrets written under the weaker v1 scheme while
    the deployment believes KMS is in the path.
    """
    mode = (settings.AISOC_CREDENTIAL_ENVELOPE or "off").strip().lower()
    if mode in ("", "off", "false", "0", "none"):
        return None

    if mode == "local":
        kek = (settings.AISOC_CREDENTIAL_KEK or "").strip().encode("ascii")
        if not kek:
            raise CredentialVaultError(
                "AISOC_CREDENTIAL_ENVELOPE=local requires AISOC_CREDENTIAL_KEK "
                "(a Fernet key). Generate one with: python -c "
                '"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"'
            )
        historical: dict[str, bytes] = {}
        for index, key in enumerate(_split_keys(settings.AISOC_CREDENTIAL_KEK_ROTATION_FROM or "")):
            historical[f"local-{index}"] = key
        try:
            return EnvelopeCipher(LocalKeyManager(kek, historical=historical or None))
        except EnvelopeError as exc:
            raise CredentialVaultError(f"invalid AISOC_CREDENTIAL_KEK: {exc}") from exc

    if mode in ("aws", "kms", "aws-kms"):
        key_id = (settings.AISOC_KMS_KEY_ID or "").strip()
        if not key_id:
            raise CredentialVaultError("AISOC_CREDENTIAL_ENVELOPE=aws requires AISOC_KMS_KEY_ID " "(a KMS key id, alias or ARN).")
        return EnvelopeCipher(AwsKmsKeyManager(key_id))

    raise CredentialVaultError(f"AISOC_CREDENTIAL_ENVELOPE={mode!r} is not recognised; expected off, local or aws.")


def get_vault() -> CredentialVault:
    """Return the process-wide :class:`CredentialVault`.

    On the first call we resolve the primary key from
    ``settings.AISOC_CREDENTIAL_KEY``. If unset:

    * In development we auto-generate an **ephemeral** key (logged as a
      warning) so localhost demos work without ceremony. The key is *not*
      persisted, so credentials encrypted in one process won't decrypt in
      a fresh one — that's fine for development and forces operators to
      configure a real key the moment they leave it.
    * Outside development we raise — silently encrypting under a throwaway
      key would be worse than refusing to run.
    """
    global _vault_singleton
    if _vault_singleton is not None:
        return _vault_singleton
    with _vault_lock:
        if _vault_singleton is not None:  # pragma: no cover - racing init
            return _vault_singleton
        primary = (settings.AISOC_CREDENTIAL_KEY or "").strip().encode("ascii")
        if not primary:
            # NB: vault startup is a boot-time decision so we read from the
            # cached ``settings`` (the same value our env warnings used),
            # not from the live process env. If an operator monkey-patches
            # the env post-boot, the vault key check has already happened.
            if not is_dev_env(settings.ENVIRONMENT):
                raise CredentialVaultError("AISOC_CREDENTIAL_KEY is required outside development; refusing to start credential vault.")
            primary = Fernet.generate_key()
            logger.warning(
                "AISOC_CREDENTIAL_KEY is not set; using ephemeral process-local key. Connector secrets will not survive a restart. "
                "Generate a key with "
                '`python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`'
                " and set AISOC_CREDENTIAL_KEY."
            )
        rotation = _split_keys(settings.AISOC_CREDENTIAL_KEY_ROTATION_FROM or "")
        envelope = _build_envelope()
        if envelope is not None:
            logger.info(
                "credential vault: envelope encryption enabled (%s); new writes use vault:v2",
                (settings.AISOC_CREDENTIAL_ENVELOPE or "").strip().lower(),
            )
        _vault_singleton = CredentialVault(primary, historical_keys=rotation, envelope=envelope)
        return _vault_singleton


def reset_vault_for_tests() -> None:
    """Drop the cached singleton. Test helper only."""
    global _vault_singleton
    with _vault_lock:
        _vault_singleton = None
