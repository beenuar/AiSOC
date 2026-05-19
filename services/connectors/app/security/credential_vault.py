"""Vendored credential vault for the connectors microservice.

The canonical implementation lives in ``services/api/app/security/credential_vault.py``.
We vendor the **read path** here so the connectors service can decrypt the
``auth_config`` blobs the API service wrote, without standing up a back-channel
RPC for "please decrypt this secret for me" (which would just push the secret
across the wire in plaintext anyway and add an extra failure surface).

Both services agree on a single deployment-level secret, ``AISOC_CREDENTIAL_KEY``,
mounted via the same secrets store (Fly secrets / k8s secret / vault). As long
as the two services see the same key material, ciphertexts written by one
decrypt cleanly in the other.

Differences vs. the API copy:

* No dependency on ``app.core.config.Settings`` — env vars are read directly so
  this module stays trivial to test in isolation and adds no import cycle into
  the connectors service.
* No dev-mode "auto-generate ephemeral key" behaviour. If the API service
  generated an ephemeral key in development, this service won't have it; that's
  actually fine because in dev we generally only test connector classes with
  brand-new credentials and never reach the decrypt path.
* Encryption is still implemented (kept symmetric with the API copy) so a
  future re-encrypt maintenance job could run from either side.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Mapping
from threading import Lock
from typing import Any, Final

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

logger = logging.getLogger("aisoc.connectors.credential_vault")

# Tag every value we write so we can distinguish ciphertext from legacy
# plaintext on the decrypt path. Must match the API service's prefix byte-for-byte.
_CIPHER_PREFIX: Final[str] = "vault:v1:"


class CredentialVaultError(RuntimeError):
    """Raised when the vault cannot encrypt/decrypt safely."""


def _split_keys(raw: str) -> list[bytes]:
    return [k.strip().encode("ascii") for k in raw.split(",") if k.strip()]


class CredentialVault:
    """Encrypt and decrypt connector credentials.

    See the canonical docstring in
    ``services/api/app/security/credential_vault.py`` for the full design
    rationale (Fernet, MultiFernet, leaf-level encryption, no key derivation).
    """

    def __init__(self, primary_key: bytes, historical_keys: list[bytes] | None = None) -> None:
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
                logger.warning("ignoring invalid rotation key: %s", exc)

        self._fernet = MultiFernet(keyring) if len(keyring) > 1 else primary

    def encrypt(self, value: str) -> str:
        if not isinstance(value, str):
            raise CredentialVaultError(f"vault.encrypt expects str, got {type(value).__name__}")
        if value.startswith(_CIPHER_PREFIX):
            return value
        token = self._fernet.encrypt(value.encode("utf-8")).decode("ascii")
        return f"{_CIPHER_PREFIX}{token}"

    def decrypt(self, value: str) -> str:
        if not isinstance(value, str):
            raise CredentialVaultError(f"vault.decrypt expects str, got {type(value).__name__}")
        if not value.startswith(_CIPHER_PREFIX):
            return value
        token = value[len(_CIPHER_PREFIX) :].encode("ascii")
        try:
            return self._fernet.decrypt(token).decode("utf-8")
        except InvalidToken as exc:
            raise CredentialVaultError(
                "ciphertext failed integrity check — likely AISOC_CREDENTIAL_KEY mismatch between API and connectors services"
            ) from exc

    def encrypt_dict(self, payload: Mapping[str, Any], *, secret_keys: set[str] | None = None) -> dict[str, Any]:
        return self._walk(payload, encrypt=True, secret_keys=secret_keys)

    def decrypt_dict(self, payload: Mapping[str, Any], *, secret_keys: set[str] | None = None) -> dict[str, Any]:
        return self._walk(payload, encrypt=False, secret_keys=secret_keys)

    def _walk(
        self,
        payload: Any,
        *,
        encrypt: bool,
        secret_keys: set[str] | None,
        _key: str | None = None,
    ) -> Any:
        op = self.encrypt if encrypt else self.decrypt
        if isinstance(payload, Mapping):
            out: dict[str, Any] = {}
            for k, v in payload.items():
                if secret_keys is not None and k not in secret_keys and not isinstance(v, Mapping | list):
                    out[k] = v
                else:
                    out[k] = self._walk(v, encrypt=encrypt, secret_keys=secret_keys, _key=k)
            return out
        if isinstance(payload, list):
            return [self._walk(item, encrypt=encrypt, secret_keys=secret_keys, _key=_key) for item in payload]
        if isinstance(payload, str):
            return op(payload)
        return payload


_vault_singleton: CredentialVault | None = None
_vault_lock = Lock()


def get_vault() -> CredentialVault:
    """Return the process-wide vault, lazily constructed from env vars.

    Unlike the API copy this function deliberately raises if
    ``AISOC_CREDENTIAL_KEY`` is missing — the connectors microservice exists
    to *poll* sources using already-stored credentials, so running without a
    key is never the right behaviour, even in dev.
    """
    global _vault_singleton
    if _vault_singleton is not None:
        return _vault_singleton
    with _vault_lock:
        if _vault_singleton is not None:  # pragma: no cover - racing init
            return _vault_singleton
        primary = (os.getenv("AISOC_CREDENTIAL_KEY") or "").strip().encode("ascii")
        if not primary:
            raise CredentialVaultError(
                "AISOC_CREDENTIAL_KEY is required for the connectors service to decrypt stored credentials. "
                "Mount the same key the API service uses."
            )
        rotation = _split_keys(os.getenv("AISOC_CREDENTIAL_KEY_ROTATION_FROM") or "")
        _vault_singleton = CredentialVault(primary, historical_keys=rotation)
        return _vault_singleton


def reset_vault_for_tests() -> None:
    global _vault_singleton
    with _vault_lock:
        _vault_singleton = None
