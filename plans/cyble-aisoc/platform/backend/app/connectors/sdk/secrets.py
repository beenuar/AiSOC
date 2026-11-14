"""Symmetric encryption for per-tenant connector credentials at rest.

All sensitive connector configuration — API keys, OAuth client secrets,
service-account passwords — passes through this module on its way to the
database and on its way back into a live connector instance.

Design choices
--------------
- **Fernet (AES-128-CBC + HMAC-SHA256)** from ``pyca/cryptography``. It is
  authenticated, prefixed with a version byte, includes its own IV, and is
  trivially correct to use. We do not roll our own.
- **Single active key** sourced from ``AISOC_CONNECTOR_SECRETS_KEY``. In
  production this is supplied by KMS / Vault / a Kubernetes Secret. In
  development we autogenerate a key on first boot and persist it at
  ``data/connector_secrets.key`` (mode 0600) so reboots don't invalidate
  stored credentials.
- **MultiFernet** is used internally so we can support key rotation later
  by accepting ``AISOC_CONNECTOR_SECRETS_KEYS_PREVIOUS`` (comma-separated)
  without a schema change. New writes use the active key; old reads still
  decrypt with any historical key.
- Ciphertext is stored as a UTF-8 string (Fernet token is urlsafe base64),
  which slots cleanly into JSON columns and survives ``str(...)`` for free.

Public surface
--------------
- ``seal(plaintext: str) -> str``
- ``unseal(ciphertext: str) -> str``
- ``seal_dict(values: dict[str, str]) -> dict[str, str]``
- ``unseal_dict(values: dict[str, str]) -> dict[str, str]``
- ``rotate(old_ciphertext: str) -> str`` (re-encrypts under the current key)

The module raises :class:`SecretsConfigError` on misconfiguration (e.g.
missing key in production) and :class:`SecretsDecryptError` when a stored
value cannot be decrypted — most likely because the key changed and the
operator did not list the previous one in
``AISOC_CONNECTOR_SECRETS_KEYS_PREVIOUS``.
"""
from __future__ import annotations

import logging
import os
import stat
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from app.config import settings

logger = logging.getLogger(__name__)


class SecretsConfigError(RuntimeError):
    """Raised when the secrets module can't be initialised."""


class SecretsDecryptError(RuntimeError):
    """Raised when a ciphertext fails to decrypt under all known keys."""


# Module-level singleton, lazily built. We don't build at import time so
# that tests can monkey-patch ``settings.connector_secrets_key`` and call
# :func:`reset_for_tests` to get a clean slate.
_engine: MultiFernet | None = None


def _load_or_create_dev_key(path: Path) -> str:
    """Read a persisted dev key from ``path`` or generate one on miss.

    Only used outside of production. The file is created with mode 0600.
    """
    if path.exists():
        try:
            existing = path.read_text(encoding="utf-8").strip()
            if existing:
                # Validate length so a corrupt file produces a clear error.
                Fernet(existing.encode("utf-8"))
                return existing
        except (OSError, ValueError) as exc:  # pragma: no cover - defensive
            logger.warning(
                "connector_secrets: failed to read dev key from %s (%s); regenerating",
                path,
                exc,
            )

    path.parent.mkdir(parents=True, exist_ok=True)
    new_key = Fernet.generate_key().decode("utf-8")
    path.write_text(new_key, encoding="utf-8")
    try:
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except OSError:  # pragma: no cover - Windows / odd filesystems
        pass
    logger.warning(
        "connector_secrets: generated dev key at %s; set "
        "AISOC_CONNECTOR_SECRETS_KEY in production",
        path,
    )
    return new_key


def _build_engine() -> MultiFernet:
    """Construct the :class:`MultiFernet` from configured keys."""
    active = settings.connector_secrets_key
    if not active:
        if settings.env.lower() in {"prod", "production"}:
            # Belt-and-braces; app/config.py also guards this.
            raise SecretsConfigError(
                "AISOC_CONNECTOR_SECRETS_KEY must be set in production"
            )
        active = _load_or_create_dev_key(settings.connector_secrets_key_path)

    try:
        active_fernet = Fernet(active.encode("utf-8"))
    except (ValueError, TypeError) as exc:
        raise SecretsConfigError(
            "AISOC_CONNECTOR_SECRETS_KEY is not a valid 44-char Fernet key: "
            f"{exc}"
        ) from exc

    fernets: list[Fernet] = [active_fernet]

    previous_csv = os.environ.get("AISOC_CONNECTOR_SECRETS_KEYS_PREVIOUS", "")
    for raw in (k.strip() for k in previous_csv.split(",") if k.strip()):
        try:
            fernets.append(Fernet(raw.encode("utf-8")))
        except (ValueError, TypeError) as exc:
            raise SecretsConfigError(
                f"AISOC_CONNECTOR_SECRETS_KEYS_PREVIOUS contains an invalid key: {exc}"
            ) from exc

    return MultiFernet(fernets)


def _engine_or_init() -> MultiFernet:
    global _engine
    if _engine is None:
        _engine = _build_engine()
    return _engine


def reset_for_tests() -> None:
    """Drop the cached engine so a test can re-init with different settings."""
    global _engine
    _engine = None


# ── public surface ─────────────────────────────────────────────────────


def seal(plaintext: str) -> str:
    """Encrypt ``plaintext`` under the current key. Returns a Fernet token."""
    if not isinstance(plaintext, str):
        raise TypeError(f"seal() expects str, got {type(plaintext).__name__}")
    token = _engine_or_init().encrypt(plaintext.encode("utf-8"))
    return token.decode("utf-8")


def unseal(ciphertext: str) -> str:
    """Decrypt a previously-sealed value. Raises :class:`SecretsDecryptError`."""
    if not isinstance(ciphertext, str):
        raise TypeError(f"unseal() expects str, got {type(ciphertext).__name__}")
    try:
        plain = _engine_or_init().decrypt(ciphertext.encode("utf-8"))
    except InvalidToken as exc:
        raise SecretsDecryptError(
            "failed to decrypt connector secret; the active key may have rotated. "
            "Set AISOC_CONNECTOR_SECRETS_KEYS_PREVIOUS to include the old key."
        ) from exc
    return plain.decode("utf-8")


def seal_dict(values: dict[str, str]) -> dict[str, str]:
    """Encrypt each value in a flat ``{name: secret}`` mapping."""
    return {k: seal(v) for k, v in values.items()}


def unseal_dict(values: dict[str, str]) -> dict[str, str]:
    """Decrypt each value in a flat ``{name: ciphertext}`` mapping."""
    return {k: unseal(v) for k, v in values.items()}


def rotate(ciphertext: str) -> str:
    """Decrypt with any known key and re-encrypt with the active key.

    Use this in a background job after promoting a new key, so that
    eventually every row in :class:`ConnectorConfig` is sealed under the
    latest key and the previous-key list can be retired.
    """
    return seal(unseal(ciphertext))
