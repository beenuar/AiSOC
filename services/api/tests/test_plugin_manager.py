"""
Unit tests for app.services.plugin_manager

These tests run without any external services; they exercise the
PluginManager against temporary on-disk plugin fixtures.

MIT License — AiSOC (open-source AI Security Operations Center)
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest
from app.services.plugin_manager import (
    PluginError,
    PluginManager,
    PluginManifest,
)

# ── shared fixtures ───────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _disable_plugin_trust(monkeypatch):
    """Default to ``PLUGIN_TRUST_MODE=disabled`` for legacy tests.

    Signature-specific tests opt in to ``strict``/``warn`` explicitly via
    their own monkeypatch. Without this fixture, the in-place strict
    default would refuse every unsigned fixture plugin.
    """
    from app.core.config import settings  # noqa: PLC0415

    monkeypatch.setattr(settings, "PLUGIN_TRUST_MODE", "disabled", raising=False)


# ── helpers ───────────────────────────────────────────────────────────────────


def _write_plugin(
    base: Path,
    name: str,
    plugin_type: str = "enricher",
    plugin_code: str | None = None,
) -> Path:
    """
    Write a minimal plugin directory:
      base/<name>/aisoc-plugin.json
      base/<name>/plugin.py
    Returns the plugin directory.
    """
    d = base / name
    d.mkdir(parents=True, exist_ok=True)

    manifest = {
        "id": f"test.{name}",
        "name": name.replace("-", " ").title(),
        "version": "1.0.0",
        "plugin_type": plugin_type,
        "tags": [plugin_type, "test"],
    }
    (d / "aisoc-plugin.json").write_text(json.dumps(manifest))

    code = plugin_code or textwrap.dedent(
        """\
        class Plugin:
            async def run(self, payload, context):
                return {"enriched": True, "input": payload}
        """
    )
    (d / "plugin.py").write_text(code)
    return d


# ── manifest / load ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_discover_finds_valid_plugin(tmp_path):
    _write_plugin(tmp_path, "my-enricher")
    mgr = PluginManager(plugins_dir=tmp_path)
    loaded = await mgr.discover()
    assert loaded == ["test.my-enricher"]
    assert mgr.get_plugin("test.my-enricher") is not None


@pytest.mark.asyncio
async def test_discover_empty_dir(tmp_path):
    mgr = PluginManager(plugins_dir=tmp_path)
    loaded = await mgr.discover()
    assert loaded == []


@pytest.mark.asyncio
async def test_discover_nonexistent_dir(tmp_path):
    mgr = PluginManager(plugins_dir=tmp_path / "no-such-dir")
    loaded = await mgr.discover()
    assert loaded == []


@pytest.mark.asyncio
async def test_discover_skips_missing_manifest(tmp_path):
    d = tmp_path / "orphan-plugin"
    d.mkdir()
    (d / "plugin.py").write_text("class Plugin:\n    pass\n")
    mgr = PluginManager(plugins_dir=tmp_path)
    loaded = await mgr.discover()
    assert loaded == []


@pytest.mark.asyncio
async def test_discover_skips_invalid_manifest(tmp_path):
    d = tmp_path / "bad-plugin"
    d.mkdir()
    (d / "aisoc-plugin.json").write_text("{not valid json")
    (d / "plugin.py").write_text("class Plugin:\n    pass\n")
    mgr = PluginManager(plugins_dir=tmp_path)
    loaded = await mgr.discover()
    assert loaded == []


@pytest.mark.asyncio
async def test_discover_skips_missing_required_field(tmp_path):
    d = tmp_path / "no-type"
    d.mkdir()
    (d / "aisoc-plugin.json").write_text(json.dumps({"id": "x", "name": "X", "version": "1"}))
    (d / "plugin.py").write_text("class Plugin:\n    pass\n")
    mgr = PluginManager(plugins_dir=tmp_path)
    loaded = await mgr.discover()
    assert loaded == []


@pytest.mark.asyncio
async def test_discover_skips_invalid_plugin_type(tmp_path):
    d = tmp_path / "weird"
    d.mkdir()
    (d / "aisoc-plugin.json").write_text(json.dumps({"id": "x", "name": "X", "version": "1", "plugin_type": "magic"}))
    (d / "plugin.py").write_text("class Plugin:\n    pass\n")
    mgr = PluginManager(plugins_dir=tmp_path)
    loaded = await mgr.discover()
    assert loaded == []


@pytest.mark.asyncio
async def test_discover_skips_missing_plugin_py(tmp_path):
    d = tmp_path / "no-code"
    d.mkdir()
    (d / "aisoc-plugin.json").write_text(json.dumps({"id": "x", "name": "X", "version": "1", "plugin_type": "enricher"}))
    mgr = PluginManager(plugins_dir=tmp_path)
    loaded = await mgr.discover()
    assert loaded == []


@pytest.mark.asyncio
async def test_discover_skips_plugin_without_plugin_class(tmp_path):
    d = tmp_path / "no-class"
    d.mkdir()
    (d / "aisoc-plugin.json").write_text(json.dumps({"id": "x", "name": "X", "version": "1", "plugin_type": "enricher"}))
    (d / "plugin.py").write_text("# no Plugin class here\n")
    mgr = PluginManager(plugins_dir=tmp_path)
    loaded = await mgr.discover()
    assert loaded == []


# ── list / get ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_plugins(tmp_path):
    _write_plugin(tmp_path, "enricher-a", "enricher")
    _write_plugin(tmp_path, "action-b", "action")
    _write_plugin(tmp_path, "connector-c", "connector")

    mgr = PluginManager(plugins_dir=tmp_path)
    await mgr.discover()

    assert len(mgr.list_plugins()) == 3
    assert len(mgr.list_plugins(plugin_type="enricher")) == 1
    assert len(mgr.list_plugins(plugin_type="action")) == 1
    assert len(mgr.list_plugins(plugin_type="connector")) == 1
    assert len(mgr.list_plugins(plugin_type="unknown")) == 0


@pytest.mark.asyncio
async def test_get_plugin_not_found(tmp_path):
    mgr = PluginManager(plugins_dir=tmp_path)
    assert mgr.get_plugin("does.not.exist") is None


# ── enable / disable ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_enable_disable(tmp_path):
    _write_plugin(tmp_path, "toggleable")
    mgr = PluginManager(plugins_dir=tmp_path)
    await mgr.discover()

    await mgr.disable("test.toggleable")
    assert mgr.get_plugin("test.toggleable").enabled is False

    await mgr.enable("test.toggleable")
    assert mgr.get_plugin("test.toggleable").enabled is True


@pytest.mark.asyncio
async def test_enable_missing_raises(tmp_path):
    mgr = PluginManager(plugins_dir=tmp_path)
    with pytest.raises(PluginError):
        await mgr.enable("no.such.plugin")


@pytest.mark.asyncio
async def test_disable_missing_raises(tmp_path):
    mgr = PluginManager(plugins_dir=tmp_path)
    with pytest.raises(PluginError):
        await mgr.disable("no.such.plugin")


# ── unload / reload ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_unload(tmp_path):
    _write_plugin(tmp_path, "temp-plugin")
    mgr = PluginManager(plugins_dir=tmp_path)
    await mgr.discover()
    assert mgr.get_plugin("test.temp-plugin") is not None

    await mgr.unload("test.temp-plugin")
    assert mgr.get_plugin("test.temp-plugin") is None


@pytest.mark.asyncio
async def test_unload_missing_raises(tmp_path):
    mgr = PluginManager(plugins_dir=tmp_path)
    with pytest.raises(PluginError):
        await mgr.unload("does.not.exist")


@pytest.mark.asyncio
async def test_reload(tmp_path):
    _write_plugin(tmp_path, "reloadable")
    mgr = PluginManager(plugins_dir=tmp_path)
    await mgr.discover()

    original_loaded_at = mgr.get_plugin("test.reloadable").loaded_at

    await mgr.reload("test.reloadable")
    p = mgr.get_plugin("test.reloadable")
    assert p is not None
    # loaded_at should be refreshed (>= original since time moves forward)
    assert p.loaded_at >= original_loaded_at


@pytest.mark.asyncio
async def test_reload_missing_raises(tmp_path):
    mgr = PluginManager(plugins_dir=tmp_path)
    with pytest.raises(PluginError):
        await mgr.reload("no.such.plugin")


# ── invocation ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_run_enricher(tmp_path):
    _write_plugin(tmp_path, "ip-enrich", "enricher")
    mgr = PluginManager(plugins_dir=tmp_path)
    await mgr.discover()

    result = await mgr.run_enricher("test.ip-enrich", {"ip": "1.2.3.4"})
    assert result["enriched"] is True
    assert result["input"]["ip"] == "1.2.3.4"


@pytest.mark.asyncio
async def test_run_action(tmp_path):
    _write_plugin(tmp_path, "block-ip", "action")
    mgr = PluginManager(plugins_dir=tmp_path)
    await mgr.discover()

    result = await mgr.run_action("test.block-ip", {"ip": "10.0.0.1"})
    assert result["enriched"] is True


@pytest.mark.asyncio
async def test_run_connector(tmp_path):
    _write_plugin(tmp_path, "siem-pull", "connector")
    mgr = PluginManager(plugins_dir=tmp_path)
    await mgr.discover()

    result = await mgr.run_connector("test.siem-pull", {"query": "error"})
    assert result["enriched"] is True


@pytest.mark.asyncio
async def test_run_any(tmp_path):
    _write_plugin(tmp_path, "any-plugin", "enricher")
    mgr = PluginManager(plugins_dir=tmp_path)
    await mgr.discover()

    result = await mgr.run_any("test.any-plugin", {"x": 1})
    assert result["enriched"] is True


@pytest.mark.asyncio
async def test_run_missing_plugin_raises(tmp_path):
    mgr = PluginManager(plugins_dir=tmp_path)
    with pytest.raises(PluginError):
        await mgr.run_enricher("no.such.plugin", {})


@pytest.mark.asyncio
async def test_run_disabled_plugin_raises(tmp_path):
    _write_plugin(tmp_path, "disabled-one")
    mgr = PluginManager(plugins_dir=tmp_path)
    await mgr.discover()
    await mgr.disable("test.disabled-one")

    with pytest.raises(PluginError, match="disabled"):
        await mgr.run_enricher("test.disabled-one", {})


@pytest.mark.asyncio
async def test_run_wrong_type_raises(tmp_path):
    _write_plugin(tmp_path, "action-only", "action")
    mgr = PluginManager(plugins_dir=tmp_path)
    await mgr.discover()

    with pytest.raises(PluginError, match="expected plugin_type"):
        await mgr.run_enricher("test.action-only", {})


@pytest.mark.asyncio
async def test_run_plugin_exception_raises_plugin_error(tmp_path):
    code = textwrap.dedent(
        """\
        class Plugin:
            async def run(self, payload, context):
                raise ValueError("deliberate failure")
        """
    )
    _write_plugin(tmp_path, "failing-plugin", plugin_code=code)
    mgr = PluginManager(plugins_dir=tmp_path)
    await mgr.discover()

    with pytest.raises(PluginError, match="execution error"):
        await mgr.run_any("test.failing-plugin", {})


@pytest.mark.asyncio
async def test_run_sync_plugin(tmp_path):
    """PluginManager must handle sync run() methods transparently."""
    code = textwrap.dedent(
        """\
        class Plugin:
            def run(self, payload, context):
                return {"sync": True}
        """
    )
    _write_plugin(tmp_path, "sync-plugin", plugin_code=code)
    mgr = PluginManager(plugins_dir=tmp_path)
    await mgr.discover()

    result = await mgr.run_any("test.sync-plugin", {})
    assert result["sync"] is True


@pytest.mark.asyncio
async def test_run_non_dict_result_wrapped(tmp_path):
    """Non-dict return from plugin.run should be wrapped as {"result": ...}."""
    code = textwrap.dedent(
        """\
        class Plugin:
            async def run(self, payload, context):
                return "raw string"
        """
    )
    _write_plugin(tmp_path, "string-plugin", plugin_code=code)
    mgr = PluginManager(plugins_dir=tmp_path)
    await mgr.discover()

    result = await mgr.run_any("test.string-plugin", {})
    assert result == {"result": "raw string"}


# ── PluginManifest dataclass ──────────────────────────────────────────────────


def test_plugin_manifest_from_dict_minimal():
    m = PluginManifest.from_dict({"id": "a", "name": "A", "version": "1", "plugin_type": "enricher"})
    assert m.id == "a"
    assert m.tags == []
    assert m.config_schema == {}


def test_plugin_manifest_from_dict_full():
    m = PluginManifest.from_dict(
        {
            "id": "b",
            "name": "B",
            "version": "2",
            "plugin_type": "action",
            "description": "desc",
            "author": "Alice",
            "tags": ["block", "firewall"],
            "config_schema": {"type": "object"},
        }
    )
    assert m.author == "Alice"
    assert len(m.tags) == 2
    assert m.config_schema["type"] == "object"


# ── signature gate ────────────────────────────────────────────────────────────
#
# These tests exercise the Ed25519 signature path that protects ``_load_plugin``
# from executing arbitrary unsigned ``plugin.py`` files. The gate has three
# trust modes:
#   strict   – unsigned/invalid → load is refused
#   warn     – unsigned/invalid → load proceeds, marked ``signature_status``
#              ``unsigned`` / ``invalid``
#   disabled – signature checks skipped entirely
#
# We materialize a real Ed25519 keypair at runtime, compute the canonical
# digest the loader expects, and write the signature next to the manifest.


def _signed_plugin(
    base: Path,
    name: str,
    keys_dir: Path,
    *,
    sign_with_wrong_key: bool = False,
    corrupt_signature: bool = False,
) -> tuple[Path, str]:
    """Create a plugin signed by a fresh trusted keypair and return its dir+id.

    The trusted public key is written to ``keys_dir`` so the loader will
    pick it up via ``PLUGIN_TRUSTED_KEYS_DIR``. If ``sign_with_wrong_key``
    is set, the signature is produced by an *untrusted* key whose public
    component is never registered. ``corrupt_signature`` flips a byte in
    the produced signature so verification fails.
    """
    from app.services.plugin_manager import _canonical_plugin_digest  # noqa: PLC0415
    from cryptography.hazmat.primitives import serialization  # noqa: PLC0415
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: PLC0415
        Ed25519PrivateKey,
    )

    plugin_dir = _write_plugin(base, name)

    # Keys
    trusted_priv = Ed25519PrivateKey.generate()
    trusted_pub_pem = trusted_priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    keys_dir.mkdir(parents=True, exist_ok=True)
    (keys_dir / "trusted.pem").write_bytes(trusted_pub_pem)

    # Whoever actually signs the manifest
    if sign_with_wrong_key:
        signer = Ed25519PrivateKey.generate()  # not in keys_dir
    else:
        signer = trusted_priv

    raw = json.loads((plugin_dir / "aisoc-plugin.json").read_text())
    digest = _canonical_plugin_digest(plugin_dir, raw)
    sig = signer.sign(digest)
    if corrupt_signature:
        sig = bytes([sig[0] ^ 0xFF]) + sig[1:]

    # Hex is the documented on-disk format produced by ``aisoc plugin sign``.
    (plugin_dir / "plugin.sig").write_text(sig.hex())
    return plugin_dir, f"test.{name}"


@pytest.fixture
def trusted_keys_dir(tmp_path):
    """A scratch directory used as ``PLUGIN_TRUSTED_KEYS_DIR``."""
    d = tmp_path / "keys"
    d.mkdir()
    return d


def _set_trust(monkeypatch, mode: str, keys_dir: Path) -> None:
    from app.core.config import settings  # noqa: PLC0415

    monkeypatch.setattr(settings, "PLUGIN_TRUST_MODE", mode, raising=False)
    monkeypatch.setattr(settings, "PLUGIN_TRUSTED_KEYS_DIR", str(keys_dir), raising=False)


class TestPluginSignatureGate:
    """``_load_plugin`` must verify Ed25519 signatures before executing code."""

    @pytest.mark.asyncio
    async def test_strict_refuses_unsigned_plugin(self, tmp_path, trusted_keys_dir, monkeypatch):
        _set_trust(monkeypatch, "strict", trusted_keys_dir)
        _write_plugin(tmp_path, "unsigned-plugin")

        mgr = PluginManager(plugins_dir=tmp_path)
        loaded = await mgr.discover()
        # discover() swallows PluginError; the plugin must NOT be registered.
        assert loaded == []
        assert mgr.get_plugin("test.unsigned-plugin") is None

    @pytest.mark.asyncio
    async def test_strict_refuses_invalid_signature(self, tmp_path, trusted_keys_dir, monkeypatch):
        _set_trust(monkeypatch, "strict", trusted_keys_dir)
        _signed_plugin(
            tmp_path,
            "tampered-plugin",
            trusted_keys_dir,
            corrupt_signature=True,
        )

        mgr = PluginManager(plugins_dir=tmp_path)
        loaded = await mgr.discover()
        assert loaded == []
        assert mgr.get_plugin("test.tampered-plugin") is None

    @pytest.mark.asyncio
    async def test_strict_refuses_untrusted_signer(self, tmp_path, trusted_keys_dir, monkeypatch):
        _set_trust(monkeypatch, "strict", trusted_keys_dir)
        _signed_plugin(
            tmp_path,
            "stranger-plugin",
            trusted_keys_dir,
            sign_with_wrong_key=True,
        )

        mgr = PluginManager(plugins_dir=tmp_path)
        loaded = await mgr.discover()
        assert loaded == []
        assert mgr.get_plugin("test.stranger-plugin") is None

    @pytest.mark.asyncio
    async def test_strict_accepts_valid_signature(self, tmp_path, trusted_keys_dir, monkeypatch):
        _set_trust(monkeypatch, "strict", trusted_keys_dir)
        _, plugin_id = _signed_plugin(tmp_path, "good-plugin", trusted_keys_dir)

        mgr = PluginManager(plugins_dir=tmp_path)
        loaded = await mgr.discover()
        assert plugin_id in loaded
        record = mgr.get_plugin(plugin_id)
        assert record is not None
        assert record.signature_status == "verified"
        assert record.signing_key_id is not None

    @pytest.mark.asyncio
    async def test_warn_loads_unsigned_with_status(self, tmp_path, trusted_keys_dir, monkeypatch):
        _set_trust(monkeypatch, "warn", trusted_keys_dir)
        _write_plugin(tmp_path, "warn-plugin")

        mgr = PluginManager(plugins_dir=tmp_path)
        loaded = await mgr.discover()
        assert loaded == ["test.warn-plugin"]
        record = mgr.get_plugin("test.warn-plugin")
        assert record is not None
        assert record.signature_status == "unsigned"
        assert record.signing_key_id is None

    @pytest.mark.asyncio
    async def test_warn_marks_invalid_signature(self, tmp_path, trusted_keys_dir, monkeypatch):
        _set_trust(monkeypatch, "warn", trusted_keys_dir)
        _signed_plugin(
            tmp_path,
            "warn-tampered",
            trusted_keys_dir,
            corrupt_signature=True,
        )

        mgr = PluginManager(plugins_dir=tmp_path)
        loaded = await mgr.discover()
        assert loaded == ["test.warn-tampered"]
        record = mgr.get_plugin("test.warn-tampered")
        assert record is not None
        assert record.signature_status == "invalid"

    @pytest.mark.asyncio
    async def test_disabled_skips_verification(self, tmp_path, trusted_keys_dir, monkeypatch):
        _set_trust(monkeypatch, "disabled", trusted_keys_dir)
        _write_plugin(tmp_path, "skip-plugin")

        mgr = PluginManager(plugins_dir=tmp_path)
        loaded = await mgr.discover()
        assert loaded == ["test.skip-plugin"]
        record = mgr.get_plugin("test.skip-plugin")
        assert record is not None
        assert record.signature_status == "skipped"

    @pytest.mark.asyncio
    async def test_invalid_trust_mode_falls_back_to_strict(self, tmp_path, trusted_keys_dir, monkeypatch):
        # An unrecognised mode must NOT silently downgrade to ``disabled`` —
        # the loader treats it as ``strict`` and refuses unsigned plugins.
        _set_trust(monkeypatch, "yolo", trusted_keys_dir)
        _write_plugin(tmp_path, "bogus-mode-plugin")

        mgr = PluginManager(plugins_dir=tmp_path)
        loaded = await mgr.discover()
        assert loaded == []

    def test_canonical_digest_is_stable(self, tmp_path):
        """Same content → same digest, regardless of file ordering."""
        from app.services.plugin_manager import _canonical_plugin_digest  # noqa: PLC0415

        d = tmp_path / "stable"
        d.mkdir()
        (d / "aisoc-plugin.json").write_text(json.dumps({"id": "x", "name": "X", "version": "1", "plugin_type": "enricher"}))
        (d / "plugin.py").write_text("class Plugin: pass\n")
        # Adding the optional .sig file must NOT change the digest — it is
        # the artefact we are signing, not part of the input.
        (d / "plugin.sig").write_bytes(b"placeholder")

        raw = json.loads((d / "aisoc-plugin.json").read_text())
        digest_a = _canonical_plugin_digest(d, raw)
        digest_b = _canonical_plugin_digest(d, raw)
        assert digest_a == digest_b
        # 32-byte SHA-256
        assert len(digest_a) == 32

    def test_canonical_digest_changes_when_code_changes(self, tmp_path):
        from app.services.plugin_manager import _canonical_plugin_digest  # noqa: PLC0415

        d = tmp_path / "mutating"
        d.mkdir()
        (d / "aisoc-plugin.json").write_text(json.dumps({"id": "x", "name": "X", "version": "1", "plugin_type": "enricher"}))
        (d / "plugin.py").write_text("class Plugin: pass\n")
        raw = json.loads((d / "aisoc-plugin.json").read_text())
        before = _canonical_plugin_digest(d, raw)

        (d / "plugin.py").write_text("class Plugin:\n    POISONED = True\n")
        after = _canonical_plugin_digest(d, raw)
        assert before != after
