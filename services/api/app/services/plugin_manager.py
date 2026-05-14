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
import re
import shutil
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

# ── Hardening primitives (H-3) ────────────────────────────────────────────────
#
# Plugin IDs end up as path components beneath ``PLUGINS_DIR`` and as Python
# module names; OCI references end up as argv to a CLI process. We constrain
# both to safe, well-known shapes so a hostile manifest or operator-supplied
# reference cannot pivot into path traversal, argv injection, or namespace
# collisions with real Python packages.

# Plugin id: lowercase alphanumerics + ``.``/``-``/``_``, must start with an
# alphanumeric, 2–64 chars. This rules out ``..``, ``../escape``, absolute
# paths, NULs, slashes, whitespace, and shell metacharacters. The regex is
# intentionally narrower than what some manifests historically accepted —
# new plugins MUST conform; ``discover()`` swallows the resulting
# ``PluginError`` for legacy ids, so the user-visible impact is the
# offending plugin being skipped with a loud log.
_PLUGIN_ID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{1,63}$")

# OCI reference: ``host[:port]/repo[:tag][@digest]`` with the usual character
# set. We additionally forbid a leading ``-`` (which would be parsed as a
# flag by ``oras``), whitespace, NULs, and shell metacharacters. The exact
# OCI grammar is broader than this but every valid reference in the wild
# satisfies the constraints below.
_OCI_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,254}$")

# Cloud-metadata-style hosts that must never end up as the registry, even
# if the regex above accepts them syntactically. ``install_from_oci`` is
# operator-driven so this is mostly belt-and-braces, but plugins are
# privileged enough that we keep the list.
_OCI_FORBIDDEN_HOST_SUBSTRINGS = (
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.azure.com",
)


def _validate_plugin_id(plugin_id: str) -> str:
    """Return ``plugin_id`` if it is a safe path/module component.

    Raises ``PluginError`` otherwise. Plugin ids are user-controlled via
    manifests, so this is the canonical chokepoint before they touch the
    filesystem or ``importlib``.
    """
    if not isinstance(plugin_id, str) or not _PLUGIN_ID_RE.match(plugin_id):
        raise PluginError(
            str(plugin_id),
            "invalid plugin id; must match [A-Za-z0-9][A-Za-z0-9._-]{1,63}",
        )
    # Extra hardening: even if the regex says yes, paranoid path-component
    # checks make path-traversal impossible.
    if plugin_id in {".", ".."} or "/" in plugin_id or "\\" in plugin_id or "\x00" in plugin_id:
        raise PluginError(plugin_id, "invalid plugin id; path separators or NUL not allowed")
    return plugin_id


def _validate_oci_ref(oci_ref: str) -> str:
    """Return ``oci_ref`` if it is safe to pass as argv to ``oras pull``.

    Rejects empty refs, leading ``-`` (flag injection), whitespace, NULs,
    shell metacharacters, and the well-known metadata-service hosts that
    have no business being a plugin registry.
    """
    if not isinstance(oci_ref, str) or not oci_ref:
        raise PluginError("oci", "oci_ref must be a non-empty string")
    if oci_ref.startswith("-"):
        raise PluginError(oci_ref, "oci_ref must not start with '-' (argv injection guard)")
    if not _OCI_REF_RE.match(oci_ref):
        raise PluginError(
            oci_ref,
            "oci_ref contains characters that are not allowed; expected host[:port]/repo[:tag][@digest]",
        )
    lowered = oci_ref.lower()
    if any(bad in lowered for bad in _OCI_FORBIDDEN_HOST_SUBSTRINGS):
        raise PluginError(oci_ref, "oci_ref host is on the forbidden metadata-service deny list")
    return oci_ref


def _assert_no_symlinks(root: Path) -> None:
    """Raise ``PluginError`` if ``root`` contains *any* symbolic link.

    OCI layers can legally pack symlinks; for plugin payloads we treat any
    symlink as hostile because they can point at ``/etc/passwd``, the
    instance-metadata service over a network share, the ``PLUGINS_DIR``
    of another tenant, or back into the temp dir to create a loop. The
    plugin contract is "ordinary files only".
    """
    if root.is_symlink():
        raise PluginError(root.name, f"refusing to ingest symlink: {root}")
    for entry in root.rglob("*"):
        if entry.is_symlink():
            raise PluginError(
                root.name,
                f"plugin payload contains a symlink and is rejected: {entry.relative_to(root)}",
            )


def _safe_copytree(src: Path, dest: Path) -> None:
    """Copy ``src`` to ``dest`` without following symlinks.

    Callers must run :func:`_assert_no_symlinks` first; this helper is the
    second line of defence in case the validation/copy steps ever drift
    out of order.
    """
    shutil.copytree(src, dest, symlinks=True)


def _select_extracted_plugin_dir(tmp_path: Path) -> Path:
    """Pick the plugin root from a freshly-pulled OCI tree.

    The historical behaviour of just ``subdirs[0]`` was order-dependent and
    could silently install whichever directory happened to sort first when
    a tarball packed multiple top-level dirs (e.g. a stray ``docs/``). We
    instead prefer a subdir that actually contains a manifest, fall back to
    the temp dir itself for flat pulls, and refuse to pick when more than
    one candidate looks plugin-shaped.
    """
    if (tmp_path / _MANIFEST_YAML).exists() or (tmp_path / _MANIFEST_JSON).exists():
        return tmp_path

    subdirs = sorted(d for d in tmp_path.iterdir() if d.is_dir())
    if not subdirs:
        return tmp_path

    candidates = [d for d in subdirs if (d / _MANIFEST_YAML).exists() or (d / _MANIFEST_JSON).exists()]
    if len(candidates) == 1:
        return candidates[0]
    if len(candidates) > 1:
        names = ", ".join(c.name for c in candidates)
        raise PluginError(
            "oci",
            f"OCI image contains multiple plugin directories ({names}); expected exactly one",
        )

    # No manifest in any subdir — fall back to the single-subdir behaviour
    # for legacy images, but only if there is exactly one candidate.
    if len(subdirs) == 1:
        return subdirs[0]
    raise PluginError(
        "oci",
        "OCI image contains multiple top-level directories but no manifest; unable to pick plugin root",
    )


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

        # Plugin ids end up as path components and synthesized module names.
        # Reject anything that would let a hostile manifest pivot via
        # ``../`` or shell metacharacters before we touch the filesystem.
        _validate_plugin_id(str(raw["id"]))

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
        Pull a plugin OCI image using the ``oras`` CLI and install it into PLUGINS_DIR.

        The OCI image must contain a single layer whose media type is
        ``application/vnd.aisoc.plugin.v1+tar`` or any tar/gzip layer.
        The extracted directory must contain a valid plugin manifest.

        Hardening (H-3):

        * ``oci_ref`` and any caller-supplied ``plugin_id_hint`` are validated
          before they reach ``argv`` so a hostile reference cannot inject a
          flag (e.g. ``--config /etc/passwd``) or run a different binary.
        * The freshly extracted tree is scanned for symbolic links; if any
          are present the install is rejected outright. OCI tarballs can
          legally pack symlinks but a plugin payload that does is treated
          as adversarial — they trivially break out of ``PLUGINS_DIR``.
        * Signature verification runs against the *temp* directory before
          anything is copied into ``PLUGINS_DIR``. An attacker who can publish
          an image but not the signing key never gets to write malicious
          ``plugin.py`` to a place the runtime will later import.
        * The final copy uses ``copytree`` with ``symlinks=True`` so links are
          preserved as links rather than followed (defence in depth — the
          symlink check above should have already failed the install).

        Prerequisites: ``oras`` CLI must be installed and on PATH.
        Install: https://oras.land/docs/installation

        Returns the plugin_id after successful installation.
        """
        # 1) Input validation — argv hygiene before any subprocess work.
        _validate_oci_ref(oci_ref)
        if plugin_id_hint is not None:
            _validate_plugin_id(plugin_id_hint)

        self._plugins_dir.mkdir(parents=True, exist_ok=True)

        with tempfile.TemporaryDirectory(prefix="aisoc-oci-") as tmp:
            tmp_path = Path(tmp)
            logger.info("pulling OCI image", ref=oci_ref, tmp=str(tmp_path))

            # 2) Pull. We pass argv as a list (no shell). The ref has already
            #    been regex-validated, so a hostile ref cannot inject flags;
            #    ``--`` is defence-in-depth and MUST come after the ``--output``
            #    flag so oras parses ``--output`` as a flag and the ref as the
            #    sole positional argument. Swapping the order silently breaks
            #    ``oras pull`` at runtime ("unexpected positional argument").
            try:
                proc = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: subprocess.run(
                        ["oras", "pull", "--output", str(tmp_path), "--", oci_ref],
                        capture_output=True,
                        text=True,
                        timeout=120,
                        check=False,
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

            # 3) Reject symlinks at the temp-dir level before we even read
            #    the manifest. A hostile ``plugin.yaml`` could be a symlink
            #    into ``/etc`` and we don't want ``_read_manifest`` reading
            #    arbitrary files.
            _assert_no_symlinks(tmp_path)

            # 4) Find the extracted plugin directory. Prefer a subdir that
            #    actually contains a manifest; fall back to the temp dir
            #    itself for "flat" pulls.
            extracted = _select_extracted_plugin_dir(tmp_path)

            # 5) Read manifest and bind the canonical plugin_id. The id
            #    must satisfy the same shape rules as discovered plugins
            #    so it cannot escape ``PLUGINS_DIR`` or shadow another id.
            raw = _read_manifest(extracted)
            plugin_id = str(raw.get("id") or plugin_id_hint or extracted.name)
            _validate_plugin_id(plugin_id)
            if plugin_id_hint is not None and raw.get("id") and raw["id"] != plugin_id_hint:
                raise PluginError(
                    plugin_id,
                    f"manifest id '{raw['id']}' does not match plugin_id_hint '{plugin_id_hint}'",
                )

            # 6) Verify the signature against the *temp* directory, BEFORE
            #    we copy anything into PLUGINS_DIR. In ``strict`` mode this
            #    raises and the temp dir is cleaned up by the context
            #    manager — nothing malicious ever lands on disk inside the
            #    plugins root.
            trust_mode, trusted_keys = self._trust_config()
            _verify_plugin_signature(extracted, raw, trust_mode, trusted_keys)

            # 7) Atomically install into PLUGINS_DIR. We use ``symlinks=True``
            #    so links would be preserved-as-links rather than followed,
            #    but ``_assert_no_symlinks`` above should already have made
            #    that path unreachable.
            dest = self._plugins_dir / plugin_id
            if dest.exists():
                shutil.rmtree(dest)
            _safe_copytree(extracted, dest)
            logger.info("OCI plugin extracted", ref=oci_ref, dest=str(dest))

        # 8) Load the freshly extracted plugin. ``_load_plugin`` re-runs the
        #    signature gate against the final location, which is what
        #    ``LoadedPlugin.signature_status`` ultimately reflects.
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
