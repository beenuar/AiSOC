"""
AiSOC Plugin Manager
Discovers, validates, loads, and dispatches calls to installed plugins.

Plugin layout expected on disk (two manifest formats accepted):
  PLUGINS_DIR/
    my-enricher/
      plugin.yaml          ← preferred manifest (connector|enricher|responder|detection|widget)
      plugin.py            ← Python module with a class called Plugin
        class Plugin:
            async def run(self, payload: dict, context: dict) -> dict: ...
    another-connector/
      aisoc-plugin.json    ← legacy manifest format (still supported)
      plugin.py

Signature verification
----------------------
Every plugin executes arbitrary Python via ``importlib`` + ``exec_module``,
so the loader treats unsigned code as hostile. Each plugin directory may
ship a ``plugin.sig`` file whose contents are an Ed25519 signature, in
hex, over a canonical JSON encoding of the manifest plus the SHA-256
hash of every ``*.py`` file in the directory (sorted). The signing key
must match one of the PEM-encoded public keys in
``PLUGIN_TRUSTED_KEYS_DIR``.

The ``PLUGIN_TRUST_MODE`` setting controls behaviour:

* ``strict``   – default in prod. Refuse to load unsigned/invalid plugins.
* ``warn``     – load but mark ``signature_status`` as ``unsigned`` or
  ``invalid`` and log loudly.
* ``disabled`` – skip checks entirely (dev sandbox only).

OCI image support (oras pull):
  Pass an OCI reference to install_from_oci() — the manager pulls the image
  layer via the ORAS CLI (must be installed) and extracts it into PLUGINS_DIR.

MIT License — AiSOC (open-source AI Security Operations Center)
"""

from __future__ import annotations

import asyncio
import hashlib
import importlib.util
import inspect
import json
import os
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

try:
    import yaml as _yaml

    _YAML_AVAILABLE = True
except ModuleNotFoundError:
    _YAML_AVAILABLE = False

logger = structlog.get_logger(__name__)

# Manifest file names — plugin.yaml takes precedence over legacy aisoc-plugin.json
_MANIFEST_YAML = "plugin.yaml"
_MANIFEST_JSON = "aisoc-plugin.json"

# Signature artifact written by ``aisoc plugin sign`` — hex-encoded Ed25519
# over the canonical manifest+source digest.
_SIGNATURE_FILE = "plugin.sig"

# v4.0 expanded valid types (connector|enricher|responder|detection|widget) + legacy
VALID_PLUGIN_TYPES = {"enricher", "action", "connector", "responder", "detection", "widget"}

# Trust modes for the signature gate (see module docstring).
TRUST_MODE_STRICT = "strict"
TRUST_MODE_WARN = "warn"
TRUST_MODE_DISABLED = "disabled"
_VALID_TRUST_MODES = {TRUST_MODE_STRICT, TRUST_MODE_WARN, TRUST_MODE_DISABLED}


# ── Manifest model ────────────────────────────────────────────────────────────


@dataclass
class PluginManifest:
    id: str
    name: str
    version: str
    plugin_type: str  # connector | enricher | responder | detection | widget | action
    description: str = ""
    author: str = ""
    tags: list[str] = field(default_factory=list)
    config_schema: dict[str, Any] = field(default_factory=dict)
    # v4.0 additions
    homepage: str = ""
    license: str = ""
    min_aisoc_version: str = ""
    oci_image: str = ""  # optional OCI image reference (registry/repo:tag)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PluginManifest:
        return cls(
            id=data["id"],
            name=data["name"],
            version=data["version"],
            plugin_type=data["plugin_type"],
            description=data.get("description", ""),
            author=data.get("author", ""),
            tags=data.get("tags", []),
            config_schema=data.get("config_schema", {}),
            homepage=data.get("homepage", ""),
            license=data.get("license", ""),
            min_aisoc_version=data.get("min_aisoc_version", ""),
            oci_image=data.get("oci_image", ""),
        )


# ── Loaded plugin record ──────────────────────────────────────────────────────


@dataclass
class LoadedPlugin:
    manifest: PluginManifest
    plugin_dir: Path
    instance: Any  # the Plugin() object from plugin.py
    loaded_at: float = field(default_factory=time.time)
    error: str | None = None
    enabled: bool = True
    # ``verified`` – signature verified against a key in PLUGIN_TRUSTED_KEYS_DIR.
    # ``invalid``  – signature present but verification failed (warn mode only).
    # ``unsigned`` – no signature artifact present (warn mode only).
    # ``skipped``  – trust mode was ``disabled``; no check was attempted.
    signature_status: str = "skipped"
    signing_key_id: str | None = None

    @property
    def plugin_id(self) -> str:
        return self.manifest.id


# ── PluginError ───────────────────────────────────────────────────────────────


class PluginError(Exception):
    """Raised when plugin operations fail."""

    def __init__(self, plugin_id: str, message: str) -> None:
        super().__init__(f"[{plugin_id}] {message}")
        self.plugin_id = plugin_id


# ── Manifest helpers ──────────────────────────────────────────────────────────


def _read_manifest(plugin_dir: Path) -> dict[str, Any]:
    """
    Read the plugin manifest from plugin.yaml (preferred) or aisoc-plugin.json (legacy).
    Raises PluginError if neither is found or parsing fails.
    """
    yaml_path = plugin_dir / _MANIFEST_YAML
    json_path = plugin_dir / _MANIFEST_JSON

    if yaml_path.exists():
        if not _YAML_AVAILABLE:
            raise PluginError(
                plugin_dir.name,
                "plugin.yaml found but PyYAML is not installed; run `pip install pyyaml`",
            )
        try:
            raw = _yaml.safe_load(yaml_path.read_text())
            if not isinstance(raw, dict):
                raise ValueError("YAML root must be a mapping")
            return raw
        except Exception as exc:
            raise PluginError(plugin_dir.name, f"invalid plugin.yaml: {exc}") from exc

    if json_path.exists():
        try:
            return json.loads(json_path.read_text())
        except (json.JSONDecodeError, OSError) as exc:
            raise PluginError(plugin_dir.name, f"invalid aisoc-plugin.json: {exc}") from exc

    raise PluginError(plugin_dir.name, f"no manifest found (expected {_MANIFEST_YAML} or {_MANIFEST_JSON})")


# ── Signature helpers ─────────────────────────────────────────────────────────


def _canonical_plugin_digest(plugin_dir: Path, manifest_raw: dict[str, Any]) -> bytes:
    """Return the 32-byte SHA-256 digest of the canonical signing payload.

    The signing payload is a canonical JSON document that includes:

    * the manifest dict with the ``signature``/``trust`` keys removed,
    * a sorted map of ``{relative_path: sha256_hex}`` for every ``*.py``
      file in the plugin directory tree.

    Any change to the manifest or any source file invalidates the
    signature, so an attacker cannot swap ``plugin.py`` after signing.
    The digest is what publishers actually sign with their Ed25519 key.
    """
    sanitized = {k: v for k, v in manifest_raw.items() if k not in {"signature", "trust"}}

    file_hashes: dict[str, str] = {}
    for path in sorted(plugin_dir.rglob("*.py")):
        if not path.is_file():
            continue
        rel = path.relative_to(plugin_dir).as_posix()
        h = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        file_hashes[rel] = h.hexdigest()

    payload = {"manifest": sanitized, "files": file_hashes}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).digest()


def _read_signature(plugin_dir: Path) -> bytes | None:
    """Return the raw signature bytes, or ``None`` if no sig file exists.

    The on-disk format is permissive: callers can ship a binary blob OR a
    hex-encoded text file (the publishing pipeline uses hex because it
    survives copy/paste and code review). We try hex first and fall back
    to raw bytes; an Ed25519 signature is always 64 bytes long, which
    rules out a text file containing newlines or other whitespace.
    """
    sig_path = plugin_dir / _SIGNATURE_FILE
    if not sig_path.exists():
        return None

    raw = sig_path.read_bytes()

    # Try hex first — text-only plugin.sig is the documented publishing format.
    text = raw.strip()
    try:
        decoded = bytes.fromhex(text.decode("ascii"))
        if len(decoded) == 64:  # Ed25519 signatures are exactly 64 bytes
            return decoded
        except (UnicodeDecodeError, ValueError):
            pass  # not a hex-encoded Ed25519 signature; fall through to raw bytes

    # Otherwise treat the file as raw signature bytes.
    if len(raw) == 64:
        return raw

    raise PluginError(
        plugin_dir.name,
        f"invalid {_SIGNATURE_FILE}: expected 64 raw bytes or hex-encoded equivalent",
    )


def _load_trusted_keys(keys_dir: Path) -> list[tuple[str, bytes]]:
    """Load every PEM file under ``keys_dir`` as a candidate trust anchor.

    Returns a list of ``(key_id, pem_bytes)`` tuples, where ``key_id`` is
    the file stem (e.g. ``aisoc-core`` for ``aisoc-core.pem``). Missing
    directories yield an empty list — callers decide whether that's fatal
    based on trust mode.
    """
    if not keys_dir.exists() or not keys_dir.is_dir():
        return []
    keys: list[tuple[str, bytes]] = []
    for path in sorted(keys_dir.iterdir()):
        if path.suffix.lower() not in {".pem", ".pub"}:
            continue
        try:
            keys.append((path.stem, path.read_bytes()))
        except OSError as exc:
            logger.warning("could not read trusted key", path=str(path), error=str(exc))
    return keys


def _verify_plugin_signature(
    plugin_dir: Path,
    manifest_raw: dict[str, Any],
    trust_mode: str,
    trusted_keys: list[tuple[str, bytes]],
) -> tuple[str, str | None]:
    """Verify ``plugin.sig`` and return ``(signature_status, key_id)``.

    Raises ``PluginError`` when ``trust_mode='strict'`` and verification
    fails. In ``warn`` mode failures are logged and the loader proceeds
    with ``signature_status='unsigned'`` (no sig file) or ``'invalid'``
    (sig present but verification failed / no trusted keys). In
    ``disabled`` mode we short-circuit to ``'skipped'`` without touching
    the disk.
    """
    if trust_mode == TRUST_MODE_DISABLED:
        return "skipped", None

    sig_bytes = _read_signature(plugin_dir)
    plugin_id = manifest_raw.get("id", plugin_dir.name)

    if sig_bytes is None:
        msg = f"plugin '{plugin_id}' has no {_SIGNATURE_FILE}"
        if trust_mode == TRUST_MODE_STRICT:
            raise PluginError(plugin_id, msg + " (PLUGIN_TRUST_MODE=strict)")
        logger.warning("plugin unsigned but trust_mode=warn", plugin_id=plugin_id)
        return "unsigned", None

    if not trusted_keys:
        msg = "no trusted public keys configured"
        if trust_mode == TRUST_MODE_STRICT:
            raise PluginError(plugin_id, msg + " (set PLUGIN_TRUSTED_KEYS_DIR)")
        logger.warning("no trusted keys; signature ignored", plugin_id=plugin_id)
        return "invalid", None

    digest = _canonical_plugin_digest(plugin_dir, manifest_raw)

    # Try every configured key; any single match is enough to trust the plugin.
    from app.core.security import verify_ed25519_signature  # noqa: PLC0415

    for key_id, pem in trusted_keys:
        try:
            verify_ed25519_signature(pem, digest, sig_bytes)
            return "verified", key_id
        except ValueError:
            continue

    msg = f"signature did not verify against any of {len(trusted_keys)} trusted keys"
    if trust_mode == TRUST_MODE_STRICT:
        raise PluginError(plugin_id, msg)
    logger.warning("plugin signature invalid but trust_mode=warn", plugin_id=plugin_id)
    return "invalid", None


# ── Plugin Manager ────────────────────────────────────────────────────────────


class PluginManager:
    """
    Singleton-style manager that:
    - Discovers plugins from PLUGINS_DIR (both plugin.yaml and aisoc-plugin.json)
    - Validates manifests (v4.0 types: connector|enricher|responder|detection|widget)
    - Dynamically imports plugin.py
    - Supports installing plugins from OCI images via `oras pull`
    - Routes enricher / action / connector / responder calls
    """

    def __init__(self, plugins_dir: str | Path | None = None) -> None:
        self._plugins: dict[str, LoadedPlugin] = {}
        if plugins_dir is not None:
            self._plugins_dir = Path(plugins_dir)
        else:
            try:
                from app.core.config import settings as _cfg  # noqa: PLC0415

                self._plugins_dir = Path(_cfg.AISOC_PLUGINS_DIR)
            except Exception:
                self._plugins_dir = Path(os.getenv("AISOC_PLUGINS_DIR", "/opt/aisoc/plugins"))
        self._lock = asyncio.Lock()

    # ── Discovery ─────────────────────────────────────────────────────────────

    async def discover(self) -> list[str]:
        """
        Scan PLUGINS_DIR for subdirectories that contain plugin.yaml or aisoc-plugin.json.
        Returns a list of plugin IDs successfully loaded.
        """
        if not self._plugins_dir.exists():
            logger.info("plugins directory not found; skipping discovery", path=str(self._plugins_dir))
            return []

        loaded: list[str] = []
        for entry in sorted(self._plugins_dir.iterdir()):
            if not entry.is_dir():
                continue
            has_yaml = (entry / _MANIFEST_YAML).exists()
            has_json = (entry / _MANIFEST_JSON).exists()
            if not (has_yaml or has_json):
                continue
            try:
                plugin_id = await self._load_plugin(entry)
                loaded.append(plugin_id)
            except Exception as exc:
                logger.error("failed to load plugin", plugin_dir=str(entry), error=str(exc))
        logger.info("plugin discovery complete", loaded=len(loaded), plugins=loaded)
        return loaded

    async def _load_plugin(self, plugin_dir: Path) -> str:
        """Load a single plugin directory. Supports plugin.yaml and aisoc-plugin.json."""
        raw = _read_manifest(plugin_dir)

        missing = [f for f in ("id", "name", "version", "plugin_type") if not raw.get(f)]
        if missing:
            raise PluginError(plugin_dir.name, f"manifest missing fields: {missing}")

        if raw["plugin_type"] not in VALID_PLUGIN_TYPES:
            raise PluginError(
                raw.get("id", plugin_dir.name),
                f"invalid plugin_type '{raw['plugin_type']}'; must be one of {sorted(VALID_PLUGIN_TYPES)}",
            )

        manifest = PluginManifest.from_dict(raw)

        # ── Signature gate (runs BEFORE we exec arbitrary Python) ────────────
        trust_mode, trusted_keys = self._trust_config()
        signature_status, signing_key_id = _verify_plugin_signature(plugin_dir, raw, trust_mode, trusted_keys)

        plugin_module_path = plugin_dir / "plugin.py"
        if not plugin_module_path.exists():
            raise PluginError(manifest.id, "plugin.py not found")

        module_name = f"aisoc_plugin_{manifest.id.replace('.', '_').replace('-', '_')}"
        spec = importlib.util.spec_from_file_location(module_name, plugin_module_path)
        if spec is None or spec.loader is None:
            raise PluginError(manifest.id, "could not create module spec for plugin.py")

        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        try:
            spec.loader.exec_module(module)  # type: ignore[union-attr]
        except Exception as exc:
            raise PluginError(manifest.id, f"error importing plugin.py: {exc}") from exc

        plugin_cls = getattr(module, "Plugin", None)
        if plugin_cls is None:
            raise PluginError(manifest.id, "plugin.py must define a class named 'Plugin'")

        instance = plugin_cls()

        async with self._lock:
            loaded = LoadedPlugin(
                manifest=manifest,
                plugin_dir=plugin_dir,
                instance=instance,
                signature_status=signature_status,
                signing_key_id=signing_key_id,
            )
            self._plugins[manifest.id] = loaded

        logger.info(
            "plugin loaded",
            plugin_id=manifest.id,
            name=manifest.name,
            version=manifest.version,
            type=manifest.plugin_type,
            signature_status=signature_status,
            signing_key_id=signing_key_id,
        )
        return manifest.id

    def _trust_config(self) -> tuple[str, list[tuple[str, bytes]]]:
        """Resolve PLUGIN_TRUST_MODE + load trusted public keys from disk."""
        try:
            from app.core.config import settings as _cfg  # noqa: PLC0415

            mode = (_cfg.PLUGIN_TRUST_MODE or TRUST_MODE_STRICT).lower()
            keys_dir = Path(_cfg.PLUGIN_TRUSTED_KEYS_DIR)
        except Exception:  # pragma: no cover — config import failures handled in tests
            mode = os.getenv("PLUGIN_TRUST_MODE", TRUST_MODE_STRICT).lower()
            keys_dir = Path(os.getenv("PLUGIN_TRUSTED_KEYS_DIR", "/opt/aisoc/plugin-keys"))

        if mode not in _VALID_TRUST_MODES:
            logger.warning(
                "invalid PLUGIN_TRUST_MODE; falling back to strict",
                value=mode,
                allowed=sorted(_VALID_TRUST_MODES),
            )
            mode = TRUST_MODE_STRICT

        return mode, _load_trusted_keys(keys_dir)

    # ── OCI image install (oras pull) ─────────────────────────────────────────

    async def install_from_oci(self, oci_ref: str, plugin_id_hint: str | None = None) -> str:
        """
        Pull a plugin OCI image using the `oras` CLI and install it into PLUGINS_DIR.

        The OCI image must contain a single layer whose media type is
        ``application/vnd.aisoc.plugin.v1+tar`` or any tar/gzip layer.
        The extracted directory must contain a valid plugin manifest.

        Prerequisites: `oras` CLI must be installed and on PATH.
        Install: https://oras.land/docs/installation

        Returns the plugin_id after successful installation.
        """
        self._plugins_dir.mkdir(parents=True, exist_ok=True)

        with tempfile.TemporaryDirectory(prefix="aisoc-oci-") as tmp:
            tmp_path = Path(tmp)
            logger.info("pulling OCI image", ref=oci_ref, tmp=str(tmp_path))

            # oras pull into tmp directory
            try:
                proc = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: subprocess.run(
                        ["oras", "pull", oci_ref, "--output", str(tmp_path)],
                        capture_output=True,
                        text=True,
                        timeout=120,
                    ),
                )
            except FileNotFoundError as exc:
                raise PluginError(
                    oci_ref,
                    "oras CLI not found. Install from https://oras.land/docs/installation",
                ) from exc
            except subprocess.TimeoutExpired as exc:
                raise PluginError(oci_ref, "oras pull timed out after 120 s") from exc

            if proc.returncode != 0:
                raise PluginError(oci_ref, f"oras pull failed: {proc.stderr.strip()}")

            # Determine extracted plugin directory
            subdirs = [d for d in tmp_path.iterdir() if d.is_dir()]
            if not subdirs:
                # Flat pull — treat tmp itself as the plugin directory
                extracted = tmp_path
            else:
                extracted = subdirs[0]

            # Read manifest to get the canonical id
            raw = _read_manifest(extracted)
            plugin_id = raw.get("id") or plugin_id_hint or extracted.name

            dest = self._plugins_dir / plugin_id
            if dest.exists():
                import shutil

                shutil.rmtree(dest)

            import shutil

            shutil.copytree(extracted, dest)
            logger.info("OCI plugin extracted", ref=oci_ref, dest=str(dest))

        # Load the freshly extracted plugin
        loaded_id = await self._load_plugin(dest)
        logger.info("OCI plugin installed and loaded", plugin_id=loaded_id, ref=oci_ref)
        return loaded_id

    # ── Management ────────────────────────────────────────────────────────────

    def list_plugins(self, plugin_type: str | None = None) -> list[LoadedPlugin]:
        plugins = list(self._plugins.values())
        if plugin_type:
            plugins = [p for p in plugins if p.manifest.plugin_type == plugin_type]
        return plugins

    def get_plugin(self, plugin_id: str) -> LoadedPlugin | None:
        return self._plugins.get(plugin_id)

    async def enable(self, plugin_id: str) -> None:
        async with self._lock:
            p = self._plugins.get(plugin_id)
            if p is None:
                raise PluginError(plugin_id, "plugin not found")
            p.enabled = True
        logger.info("plugin enabled", plugin_id=plugin_id)

    async def disable(self, plugin_id: str) -> None:
        async with self._lock:
            p = self._plugins.get(plugin_id)
            if p is None:
                raise PluginError(plugin_id, "plugin not found")
            p.enabled = False
        logger.info("plugin disabled", plugin_id=plugin_id)

    async def unload(self, plugin_id: str) -> None:
        async with self._lock:
            if plugin_id not in self._plugins:
                raise PluginError(plugin_id, "plugin not found")
            del self._plugins[plugin_id]
        logger.info("plugin unloaded", plugin_id=plugin_id)

    async def reload(self, plugin_id: str) -> None:
        """Unload a plugin and reload it from disk."""
        p = self._plugins.get(plugin_id)
        if p is None:
            raise PluginError(plugin_id, "plugin not found")
        plugin_dir = p.plugin_dir
        await self.unload(plugin_id)
        await self._load_plugin(plugin_dir)

    # ── Dispatch ──────────────────────────────────────────────────────────────

    async def run_enricher(self, plugin_id: str, payload: dict, context: dict | None = None) -> dict:
        p = self._get_enabled(plugin_id, expected_type="enricher")
        return await self._invoke(p, payload, context or {})

    async def run_action(self, plugin_id: str, payload: dict, context: dict | None = None) -> dict:
        p = self._get_enabled(plugin_id, expected_type="action")
        return await self._invoke(p, payload, context or {})

    async def run_connector(self, plugin_id: str, payload: dict, context: dict | None = None) -> dict:
        p = self._get_enabled(plugin_id, expected_type="connector")
        return await self._invoke(p, payload, context or {})

    async def run_responder(self, plugin_id: str, payload: dict, context: dict | None = None) -> dict:
        p = self._get_enabled(plugin_id, expected_type="responder")
        return await self._invoke(p, payload, context or {})

    async def run_any(self, plugin_id: str, payload: dict, context: dict | None = None) -> dict:
        p = self._get_enabled(plugin_id, expected_type=None)
        return await self._invoke(p, payload, context or {})

    def _get_enabled(self, plugin_id: str, expected_type: str | None) -> LoadedPlugin:
        p = self._plugins.get(plugin_id)
        if p is None:
            raise PluginError(plugin_id, "plugin not found")
        if not p.enabled:
            raise PluginError(plugin_id, "plugin is disabled")
        if expected_type and p.manifest.plugin_type != expected_type:
            raise PluginError(
                plugin_id,
                f"expected plugin_type={expected_type}, got {p.manifest.plugin_type}",
            )
        return p

    async def _invoke(self, loaded: LoadedPlugin, payload: dict, context: dict) -> dict:
        run_fn = getattr(loaded.instance, "run", None)
        if run_fn is None:
            raise PluginError(loaded.plugin_id, "Plugin class missing 'run' method")
        try:
            if inspect.iscoroutinefunction(run_fn):
                result = await run_fn(payload, context)
            else:
                result = run_fn(payload, context)
        except Exception as exc:
            logger.error("plugin invocation error", plugin_id=loaded.plugin_id, error=str(exc))
            raise PluginError(loaded.plugin_id, f"execution error: {exc}") from exc
        return result if isinstance(result, dict) else {"result": result}


# ── Module-level singleton ────────────────────────────────────────────────────

_manager: PluginManager | None = None


def get_plugin_manager() -> PluginManager:
    global _manager
    if _manager is None:
        _manager = PluginManager()
    return _manager
