"""Vendored credential vault for the agents microservice (read path).

The canonical implementation lives in
``services/api/app/security/credential_vault.py``. We vendor the **read path**
here so the agents service can decrypt the ``api_key_vault`` blobs that the
API service wrote into ``tenant_llm_credentials``, without standing up a
back-channel "please decrypt this for me" RPC (which would just push the
secret across the wire in plaintext anyway and add a failure surface).

Both services agree on a single deployment-level secret,
``AISOC_CREDENTIAL_KEY``, mounted via the same secrets store (Fly secrets,
k8s secret, vault, etc.). As long as the two services see the same key
material, ciphertexts written by one decrypt cleanly in the other.

Differences vs. the API copy:

* No dependency on ``app.core.config.Settings`` — env vars are read directly
  so this module stays trivial to test in isolation and adds no import cycle
  into the agents service.
* No dev-mode "auto-generate ephemeral key" behaviour. If the API generated
  an ephemeral key in development, this service would not have it; tenant
  BYOK lookups simply fall back to the environment baseline in that case.
* Encryption is still implemented (kept symmetric with the API copy) so a
  future re-encrypt maintenance job could run from either side.

Differences vs. the connectors copy: :func:`get_vault` here returns ``None``
when ``AISOC_CREDENTIAL_KEY`` is missing instead of raising. The agents
service must keep generating deterministic explanations even when no BYOK
infrastructure is configured — tenant overrides simply degrade to env-only
in that case.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Mapping
from threading import Lock
from typing import Any, Final

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

logger = logging.getLogger("aisoc.agents.credential_vault")

# Tag every value we write so we can distinguish ciphertext from legacy
# plaintext on the decrypt path. Must match the API service's prefix
# byte-for-byte.
_CIPHER_PREFIX: Final[str] = "vault:v1:"


class CredentialVaultError(RuntimeError):
    """Raised when the vault cannot encrypt/decrypt safely."""


def _split_keys(raw: str) -> list[bytes]:
    return [k.strip().encode("ascii") for k in raw.split(",") if k.strip()]


class CredentialVault:
    """Encrypt and decrypt tenant LLM credentials.

    See the canonical docstring in
    ``services/api/app/security/credential_vault.py`` for the full design
    rationale (Fernet, MultiFernet, leaf-level encryption, no key derivation).
    """

    def __init__(
        self,
        primary_key: bytes,
        historical_keys: list[bytes] | None = None,
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
                "ciphertext failed integrity check — likely AISOC_CREDENTIAL_KEY mismatch between API and agents services"
            ) from exc

    def encrypt_dict(
        self,
        payload: Mapping[str, Any],
        *,
        secret_keys: set[str] | None = None,
    ) -> dict[str, Any]:
        return self._walk(payload, encrypt=True, secret_keys=secret_keys)

    def decrypt_dict(
        self,
        payload: Mapping[str, Any],
        *,
        secret_keys: set[str] | None = None,
    ) -> dict[str, Any]:
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


_vault_lock = Lock()
# Use a mutable container so all mutations are visible to CodeQL static analysis
_vault_state: dict[str, object] = {"singleton": None, "warned_missing_key": False}


def get_vault() -> CredentialVault | None:
    """Return the process-wide vault, lazily constructed from env vars.

    Returns ``None`` (with a single warning log line per process) when
    ``AISOC_CREDENTIAL_KEY`` is missing. Callers should treat that as
    "BYOK decryption not configured" and fall through to the environment
    baseline rather than failing the request.
    """
    if _vault_state["singleton"] is not None:
        return _vault_state["singleton"]  # type: ignore[return-value]
    with _vault_lock:
        if _vault_state["singleton"] is not None:  # pragma: no cover - racing init
            return _vault_state["singleton"]  # type: ignore[return-value]
        primary = (os.getenv("AISOC_CREDENTIAL_KEY") or "").strip().encode("ascii")
        if not primary:
            if not _vault_state["warned_missing_key"]:
                logger.warning(
                    "AISOC_CREDENTIAL_KEY not set; tenant LLM BYOK overrides "
                    "will be ignored and explain will use the environment "
                    "baseline only"
                )
                _vault_state["warned_missing_key"] = True
            return None
        rotation = _split_keys(os.getenv("AISOC_CREDENTIAL_KEY_ROTATION_FROM") or "")
        _vault_state["singleton"] = CredentialVault(primary, historical_keys=rotation)
        return _vault_state["singleton"]  # type: ignore[return-value]


def reset_vault_for_tests() -> None:
    """Reset the lazy singleton so tests can re-key per case."""
    with _vault_lock:
        _vault_state["singleton"] = None
        _vault_state["warned_missing_key"] = False
