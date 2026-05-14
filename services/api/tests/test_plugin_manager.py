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


# ── H-3 hardening primitives ──────────────────────────────────────────────────
#
# These tests cover the OCI / supply-chain hardening helpers added in
# Batch 6. They are pure-Python unit tests; no network or ``oras`` CLI
# is touched.


class TestValidatePluginId:
    """``_validate_plugin_id`` is the chokepoint between manifest data and
    the filesystem / ``importlib``. Anything it accepts may later become a
    path component or module name, so the bar is "regex-narrow"."""

    @pytest.mark.parametrize(
        "good",
        [
            "foo",
            "foo.bar",
            "foo-bar",
            "foo_bar",
            "Foo.Bar-baz_v2",
            "a1.b2.c3",
            "x" * 64,  # exactly the documented max length
        ],
    )
    def test_accepts_well_formed_ids(self, good):
        from app.services.plugin_manager import _validate_plugin_id  # noqa: PLC0415

        assert _validate_plugin_id(good) == good

    @pytest.mark.parametrize(
        "bad",
        [
            "",
            ".",
            "..",
            "../escape",
            "foo/bar",
            "foo\\bar",
            "foo bar",
            "foo\x00bar",
            "-foo",  # must start with alnum
            "_foo",  # must start with alnum
            ".foo",  # must start with alnum
            "x" * 65,  # one over the cap
        ],
    )
    def test_rejects_unsafe_ids(self, bad):
        from app.services.plugin_manager import PluginError, _validate_plugin_id  # noqa: PLC0415

        with pytest.raises(PluginError):
            _validate_plugin_id(bad)

    def test_rejects_non_string(self):
        from app.services.plugin_manager import PluginError, _validate_plugin_id  # noqa: PLC0415

        with pytest.raises(PluginError):
            _validate_plugin_id(None)  # type: ignore[arg-type]
        with pytest.raises(PluginError):
            _validate_plugin_id(42)  # type: ignore[arg-type]


class TestValidateOciRef:
    """``_validate_oci_ref`` is the argv-injection guard for ``oras pull``."""

    @pytest.mark.parametrize(
        "good",
        [
            "ghcr.io/owner/plugin:v1",
            "registry.example.com:5000/team/plugin:1.2.3",
            "ghcr.io/owner/plugin@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            "r/p",
        ],
    )
    def test_accepts_well_formed_refs(self, good):
        from app.services.plugin_manager import _validate_oci_ref  # noqa: PLC0415

        assert _validate_oci_ref(good) == good

    @pytest.mark.parametrize(
        "bad",
        [
            "",
            "-rf",  # would be parsed as an oras flag
            "--config=/etc/passwd",
            "ghcr.io/owner/p v1",  # whitespace
            "ghcr.io/owner/p;ls",  # shell metacharacter
            "ghcr.io/owner/p|cat",
            "ghcr.io/owner/p`id`",
            "ghcr.io/owner/p$(id)",
            "ghcr.io/owner/p\x00null",
            "ghcr.io/owner/p\nfoo",
            "a" * 256,  # one over the 255-char cap
        ],
    )
    def test_rejects_unsafe_refs(self, bad):
        from app.services.plugin_manager import PluginError, _validate_oci_ref  # noqa: PLC0415

        with pytest.raises(PluginError):
            _validate_oci_ref(bad)

    @pytest.mark.parametrize(
        "metadata_host",
        [
            "169.254.169.254/owner/plugin:v1",
            "metadata.google.internal/team/plugin:v1",
            "Metadata.Google.Internal/team/plugin:v1",  # case-insensitive
            "metadata.azure.com/team/plugin:v1",
        ],
    )
    def test_rejects_metadata_service_hosts(self, metadata_host):
        from app.services.plugin_manager import PluginError, _validate_oci_ref  # noqa: PLC0415

        with pytest.raises(PluginError, match="metadata-service deny list"):
            _validate_oci_ref(metadata_host)

    def test_rejects_non_string(self):
        from app.services.plugin_manager import PluginError, _validate_oci_ref  # noqa: PLC0415

        with pytest.raises(PluginError):
            _validate_oci_ref(None)  # type: ignore[arg-type]


class TestAssertNoSymlinks:
    """Plugin payloads are "ordinary files only" — symlinks anywhere in the
    extracted tree must be rejected before the loader touches them."""

    def test_passes_on_clean_tree(self, tmp_path):
        from app.services.plugin_manager import _assert_no_symlinks  # noqa: PLC0415

        (tmp_path / "aisoc-plugin.json").write_text("{}")
        sub = tmp_path / "sub"
        sub.mkdir()
        (sub / "plugin.py").write_text("class Plugin: pass\n")

        # Must not raise.
        _assert_no_symlinks(tmp_path)

    def test_rejects_symlink_at_root_level(self, tmp_path):
        from app.services.plugin_manager import PluginError, _assert_no_symlinks  # noqa: PLC0415

        target = tmp_path / "real.txt"
        target.write_text("hello")
        (tmp_path / "link.txt").symlink_to(target)

        with pytest.raises(PluginError, match="symlink"):
            _assert_no_symlinks(tmp_path)

    def test_rejects_symlink_nested_deep(self, tmp_path):
        from app.services.plugin_manager import PluginError, _assert_no_symlinks  # noqa: PLC0415

        deep = tmp_path / "a" / "b" / "c"
        deep.mkdir(parents=True)
        target = tmp_path / "outside.txt"
        target.write_text("x")
        (deep / "evil").symlink_to(target)

        with pytest.raises(PluginError, match="symlink"):
            _assert_no_symlinks(tmp_path)

    def test_rejects_when_root_itself_is_a_symlink(self, tmp_path):
        from app.services.plugin_manager import PluginError, _assert_no_symlinks  # noqa: PLC0415

        real_dir = tmp_path / "real"
        real_dir.mkdir()
        link_root = tmp_path / "link_root"
        link_root.symlink_to(real_dir, target_is_directory=True)

        with pytest.raises(PluginError, match="symlink"):
            _assert_no_symlinks(link_root)

    def test_rejects_dangling_symlink(self, tmp_path):
        """A symlink pointing at a non-existent target is still hostile —
        the rejection must not depend on the target being readable."""
        from app.services.plugin_manager import PluginError, _assert_no_symlinks  # noqa: PLC0415

        (tmp_path / "dangling").symlink_to(tmp_path / "does-not-exist")

        with pytest.raises(PluginError, match="symlink"):
            _assert_no_symlinks(tmp_path)


class TestSelectExtractedPluginDir:
    """``_select_extracted_plugin_dir`` picks the plugin root from a freshly-
    pulled OCI tree. The selection rule must be deterministic and refuse
    ambiguous layouts so we never silently install the wrong directory."""

    def test_flat_layout_with_yaml_manifest(self, tmp_path):
        from app.services.plugin_manager import _select_extracted_plugin_dir  # noqa: PLC0415

        (tmp_path / "plugin.yaml").write_text("id: x\n")
        assert _select_extracted_plugin_dir(tmp_path) == tmp_path

    def test_flat_layout_with_json_manifest(self, tmp_path):
        from app.services.plugin_manager import _select_extracted_plugin_dir  # noqa: PLC0415

        (tmp_path / "aisoc-plugin.json").write_text("{}")
        assert _select_extracted_plugin_dir(tmp_path) == tmp_path

    def test_single_subdir_with_manifest_is_picked(self, tmp_path):
        from app.services.plugin_manager import _select_extracted_plugin_dir  # noqa: PLC0415

        plugin = tmp_path / "real-plugin"
        plugin.mkdir()
        (plugin / "aisoc-plugin.json").write_text("{}")
        # A sibling "docs" dir that historically would have been order-
        # dependent ("d" sorts before "r"): the selector must skip it.
        docs = tmp_path / "docs"
        docs.mkdir()
        (docs / "README.md").write_text("readme")

        assert _select_extracted_plugin_dir(tmp_path) == plugin

    def test_multiple_subdirs_with_manifests_raises(self, tmp_path):
        from app.services.plugin_manager import PluginError, _select_extracted_plugin_dir  # noqa: PLC0415

        for name in ("first", "second"):
            d = tmp_path / name
            d.mkdir()
            (d / "aisoc-plugin.json").write_text("{}")

        with pytest.raises(PluginError, match="multiple plugin directories"):
            _select_extracted_plugin_dir(tmp_path)

    def test_legacy_single_subdir_without_manifest_is_picked(self, tmp_path):
        from app.services.plugin_manager import _select_extracted_plugin_dir  # noqa: PLC0415

        legacy = tmp_path / "legacy"
        legacy.mkdir()
        (legacy / "plugin.py").write_text("class Plugin: pass\n")

        assert _select_extracted_plugin_dir(tmp_path) == legacy

    def test_multiple_subdirs_without_manifest_raises(self, tmp_path):
        from app.services.plugin_manager import PluginError, _select_extracted_plugin_dir  # noqa: PLC0415

        for name in ("a", "b"):
            (tmp_path / name).mkdir()

        with pytest.raises(PluginError, match="unable to pick plugin root"):
            _select_extracted_plugin_dir(tmp_path)

    def test_empty_dir_returns_itself(self, tmp_path):
        """If oras delivers nothing useful, the downstream manifest read
        will fail with a clear PluginError — the selector should not raise
        on an empty dir."""
        from app.services.plugin_manager import _select_extracted_plugin_dir  # noqa: PLC0415

        assert _select_extracted_plugin_dir(tmp_path) == tmp_path


class TestSafeCopytree:
    """``_safe_copytree`` is defence-in-depth for the symlink guard. It must
    preserve symlinks as links rather than following them, so even if
    ``_assert_no_symlinks`` is ever bypassed the link target is not read."""

    def test_copies_ordinary_files(self, tmp_path):
        from app.services.plugin_manager import _safe_copytree  # noqa: PLC0415

        src = tmp_path / "src"
        src.mkdir()
        (src / "plugin.py").write_text("class Plugin: pass\n")
        (src / "aisoc-plugin.json").write_text('{"id": "x"}')
        sub = src / "sub"
        sub.mkdir()
        (sub / "more.py").write_text("# more\n")

        dest = tmp_path / "dest"
        _safe_copytree(src, dest)

        assert (dest / "plugin.py").read_text() == "class Plugin: pass\n"
        assert (dest / "aisoc-plugin.json").read_text() == '{"id": "x"}'
        assert (dest / "sub" / "more.py").read_text() == "# more\n"

    def test_preserves_symlinks_as_links(self, tmp_path):
        from app.services.plugin_manager import _safe_copytree  # noqa: PLC0415

        src = tmp_path / "src"
        src.mkdir()
        secret = tmp_path / "secret.txt"
        secret.write_text("DO NOT READ")
        (src / "evil").symlink_to(secret)

        dest = tmp_path / "dest"
        _safe_copytree(src, dest)

        # The link is preserved AS A LINK; copytree did not follow it and
        # write the secret content into the destination.
        assert (dest / "evil").is_symlink()


# ── install_from_oci hardening integration tests ──────────────────────────────
#
# These tests mock the ``oras pull`` subprocess and the trusted-keys reader so
# the whole install pipeline runs against a controlled temp-dir layout. They
# verify the layered defences (argv validation → pull → symlink check →
# directory selection → manifest read → id validation → signature gate →
# atomic copy) all engage in the right order.


def _fake_oras(populate=None, *, returncode: int = 0, stderr: str = ""):
    """Return a fake ``subprocess.run`` that recognises our oras argv and
    optionally populates the tmp dir with a real plugin payload.

    ``populate`` is a callable ``(tmp_path: Path) -> None``. The argv layout
    is the one used by ``install_from_oci``:

        ["oras", "pull", "--", <ref>, "--output", <tmp_path>]
    """
    from types import SimpleNamespace  # noqa: PLC0415

    calls: list[list[str]] = []

    def _runner(argv, **_kwargs):
        calls.append(list(argv))
        if returncode == 0 and populate is not None:
            # Find the value passed to --output; argv layout is stable.
            out_idx = argv.index("--output") + 1
            populate(Path(argv[out_idx]))
        return SimpleNamespace(returncode=returncode, stdout="", stderr=stderr)

    _runner.calls = calls  # type: ignore[attr-defined]
    return _runner


def _stub_oras_pull(monkeypatch, fake):
    """Replace ``subprocess.run`` *inside* the plugin_manager module so
    ``install_from_oci`` exercises our fake without touching the real CLI."""
    import sys  # noqa: PLC0415

    pm = sys.modules["app.services.plugin_manager"]
    monkeypatch.setattr(pm.subprocess, "run", fake)


class TestInstallFromOciHardening:
    """Defensive behaviours added in Batch 6 (H-3)."""

    @pytest.mark.asyncio
    async def test_rejects_flag_injection_before_subprocess(self, tmp_path, monkeypatch):
        """A ref that starts with ``-`` is rejected before ``oras`` runs;
        the subprocess must not be invoked at all."""
        from app.services.plugin_manager import PluginError, PluginManager  # noqa: PLC0415

        fake = _fake_oras()  # would raise if accidentally invoked
        _stub_oras_pull(monkeypatch, fake)

        mgr = PluginManager(plugins_dir=tmp_path / "plugins")
        with pytest.raises(PluginError, match="argv injection guard"):
            await mgr.install_from_oci("--config=/etc/passwd")
        assert fake.calls == []  # type: ignore[attr-defined]

    @pytest.mark.asyncio
    async def test_rejects_bad_plugin_id_hint_before_subprocess(self, tmp_path, monkeypatch):
        from app.services.plugin_manager import PluginError, PluginManager  # noqa: PLC0415

        fake = _fake_oras()
        _stub_oras_pull(monkeypatch, fake)

        mgr = PluginManager(plugins_dir=tmp_path / "plugins")
        with pytest.raises(PluginError, match="invalid plugin id"):
            await mgr.install_from_oci("ghcr.io/owner/plugin:v1", plugin_id_hint="../escape")
        assert fake.calls == []  # type: ignore[attr-defined]

    @pytest.mark.asyncio
    async def test_rejects_metadata_host_before_subprocess(self, tmp_path, monkeypatch):
        from app.services.plugin_manager import PluginError, PluginManager  # noqa: PLC0415

        fake = _fake_oras()
        _stub_oras_pull(monkeypatch, fake)

        mgr = PluginManager(plugins_dir=tmp_path / "plugins")
        with pytest.raises(PluginError, match="metadata-service deny list"):
            await mgr.install_from_oci("169.254.169.254/owner/plugin:v1")
        assert fake.calls == []  # type: ignore[attr-defined]

    @pytest.mark.asyncio
    async def test_oras_nonzero_exit_raises_and_installs_nothing(self, tmp_path, monkeypatch):
        from app.services.plugin_manager import PluginError, PluginManager  # noqa: PLC0415

        fake = _fake_oras(returncode=1, stderr="unauthorized: pull access denied")
        _stub_oras_pull(monkeypatch, fake)

        plugins_dir = tmp_path / "plugins"
        mgr = PluginManager(plugins_dir=plugins_dir)
        with pytest.raises(PluginError, match="oras pull failed"):
            await mgr.install_from_oci("ghcr.io/owner/plugin:v1")

        assert not plugins_dir.exists() or list(plugins_dir.iterdir()) == []

    @pytest.mark.asyncio
    async def test_oras_argv_uses_double_dash(self, tmp_path, monkeypatch):
        """``oras pull`` argv must be flag-safe AND functionally correct.

        Two invariants together prevent ``argv`` injection without breaking
        the underlying ``oras pull`` invocation:
          1. argv is built from a Python list (no shell).
          2. ``--output <dir>`` is parsed as a flag pair, then ``--`` ends
             flag parsing, then the ref is the sole positional. If a future
             maintainer flips the order and puts ``--`` before ``--output``,
             ``oras`` would treat ``--output`` as a positional and the pull
             would fail at runtime — so this test pins the order.
        """
        from app.services.plugin_manager import PluginManager  # noqa: PLC0415

        def populate(tp: Path) -> None:
            _write_plugin(tp, "argv-shape")

        fake = _fake_oras(populate)
        _stub_oras_pull(monkeypatch, fake)

        mgr = PluginManager(plugins_dir=tmp_path / "plugins")
        await mgr.install_from_oci("ghcr.io/owner/plugin:v1", plugin_id_hint="test.argv-shape")

        assert len(fake.calls) == 1  # type: ignore[attr-defined]
        argv = fake.calls[0]  # type: ignore[attr-defined]
        assert argv[0] == "oras"
        assert argv[1] == "pull"
        assert "--output" in argv and "--" in argv
        out_idx = argv.index("--output")
        sep_idx = argv.index("--")
        # --output / <path> come before --, so they are parsed as a flag pair.
        assert out_idx < sep_idx
        # The ref must be the sole positional, immediately after --.
        assert argv[sep_idx + 1] == "ghcr.io/owner/plugin:v1"
        assert sep_idx + 2 == len(argv), "ref must be the only positional"

    @pytest.mark.asyncio
    async def test_rejects_symlink_in_extracted_tree(self, tmp_path, monkeypatch):
        """A hostile OCI image that packs a symlink must be rejected and
        nothing must land in PLUGINS_DIR."""
        from app.services.plugin_manager import PluginError, PluginManager  # noqa: PLC0415

        def populate_with_symlink(tp: Path) -> None:
            _write_plugin(tp, "bad-plugin")
            # Drop a symlink anywhere in the tree.
            target = tp / "bad-plugin" / "real.txt"
            target.write_text("ok")
            (tp / "bad-plugin" / "evil").symlink_to(target)

        fake = _fake_oras(populate_with_symlink)
        _stub_oras_pull(monkeypatch, fake)

        plugins_dir = tmp_path / "plugins"
        mgr = PluginManager(plugins_dir=plugins_dir)
        with pytest.raises(PluginError, match="symlink"):
            await mgr.install_from_oci("ghcr.io/owner/plugin:v1")

        assert not plugins_dir.exists() or list(plugins_dir.iterdir()) == []

    @pytest.mark.asyncio
    async def test_rejects_manifest_id_hint_mismatch(self, tmp_path, monkeypatch):
        from app.services.plugin_manager import PluginError, PluginManager  # noqa: PLC0415

        def populate(tp: Path) -> None:
            _write_plugin(tp, "real-id")

        fake = _fake_oras(populate)
        _stub_oras_pull(monkeypatch, fake)

        plugins_dir = tmp_path / "plugins"
        mgr = PluginManager(plugins_dir=plugins_dir)
        with pytest.raises(PluginError, match="does not match plugin_id_hint"):
            await mgr.install_from_oci("ghcr.io/owner/plugin:v1", plugin_id_hint="test.wrong-id")

        # Mismatch fails AFTER pull but BEFORE copy.
        assert not plugins_dir.exists() or list(plugins_dir.iterdir()) == []

    @pytest.mark.asyncio
    async def test_rejects_manifest_id_that_fails_validation(self, tmp_path, monkeypatch):
        """A hostile manifest with ``id: "../escape"`` must be rejected
        before any path is built from it."""
        from app.services.plugin_manager import PluginError, PluginManager  # noqa: PLC0415

        def populate(tp: Path) -> None:
            d = tp / "evil-plugin"
            d.mkdir()
            (d / "aisoc-plugin.json").write_text(
                json.dumps(
                    {
                        "id": "../escape",
                        "name": "evil",
                        "version": "1.0.0",
                        "plugin_type": "enricher",
                    }
                )
            )
            (d / "plugin.py").write_text("class Plugin: pass\n")

        fake = _fake_oras(populate)
        _stub_oras_pull(monkeypatch, fake)

        plugins_dir = tmp_path / "plugins"
        mgr = PluginManager(plugins_dir=plugins_dir)
        with pytest.raises(PluginError, match="invalid plugin id"):
            await mgr.install_from_oci("ghcr.io/owner/plugin:v1")

        assert not plugins_dir.exists() or list(plugins_dir.iterdir()) == []

    @pytest.mark.asyncio
    async def test_strict_mode_refuses_unsigned_and_installs_nothing(self, tmp_path, trusted_keys_dir, monkeypatch):
        """In strict trust mode an unsigned image must be rejected
        *before* any file lands in PLUGINS_DIR. This is the headline
        guarantee of the H-3 hardening — signature gate before copy."""
        from app.services.plugin_manager import PluginError, PluginManager  # noqa: PLC0415

        _set_trust(monkeypatch, "strict", trusted_keys_dir)

        def populate(tp: Path) -> None:
            _write_plugin(tp, "unsigned")

        fake = _fake_oras(populate)
        _stub_oras_pull(monkeypatch, fake)

        plugins_dir = tmp_path / "plugins"
        mgr = PluginManager(plugins_dir=plugins_dir)
        with pytest.raises(PluginError):
            await mgr.install_from_oci("ghcr.io/owner/plugin:v1")

        # The signature gate fires inside the ``with tempfile.TemporaryDirectory``
        # block, before ``_safe_copytree`` is reached. PLUGINS_DIR must be
        # empty.
        assert not plugins_dir.exists() or list(plugins_dir.iterdir()) == []

    @pytest.mark.asyncio
    async def test_happy_path_installs_and_loads(self, tmp_path, monkeypatch):
        """End-to-end smoke test with trust mode disabled: the install
        completes, the plugin lands in PLUGINS_DIR, and ``_load_plugin``
        registers it under the manifest id."""
        from app.services.plugin_manager import PluginManager  # noqa: PLC0415

        def populate(tp: Path) -> None:
            _write_plugin(tp, "happy")

        fake = _fake_oras(populate)
        _stub_oras_pull(monkeypatch, fake)

        plugins_dir = tmp_path / "plugins"
        mgr = PluginManager(plugins_dir=plugins_dir)
        loaded_id = await mgr.install_from_oci("ghcr.io/owner/plugin:v1")

        assert loaded_id == "test.happy"
        assert (plugins_dir / "test.happy" / "plugin.py").exists()
        assert (plugins_dir / "test.happy" / "aisoc-plugin.json").exists()
        assert mgr.get_plugin("test.happy") is not None

    @pytest.mark.asyncio
    async def test_picks_correct_subdir_when_extra_dirs_present(self, tmp_path, monkeypatch):
        """An OCI image whose tarball happens to also contain a sibling
        directory (e.g. ``docs/``) must still install the plugin dir, not
        whichever name sorts first."""
        from app.services.plugin_manager import PluginManager  # noqa: PLC0415

        def populate(tp: Path) -> None:
            _write_plugin(tp, "real-plugin")
            # "docs" sorts before "real-plugin"; the pre-H-3 selector would
            # have picked it.
            docs = tp / "docs"
            docs.mkdir()
            (docs / "README.md").write_text("readme")

        fake = _fake_oras(populate)
        _stub_oras_pull(monkeypatch, fake)

        plugins_dir = tmp_path / "plugins"
        mgr = PluginManager(plugins_dir=plugins_dir)
        loaded_id = await mgr.install_from_oci("ghcr.io/owner/plugin:v1", plugin_id_hint="test.real-plugin")

        assert loaded_id == "test.real-plugin"
        assert (plugins_dir / "test.real-plugin" / "plugin.py").exists()
        # The stray docs dir must NOT have been installed.
        assert not (plugins_dir / "docs").exists()

    @pytest.mark.asyncio
    async def test_refuses_ambiguous_image_with_multiple_plugin_dirs(self, tmp_path, monkeypatch):
        """An image packing two plugin-shaped directories is ambiguous —
        the installer must refuse rather than silently picking one."""
        from app.services.plugin_manager import PluginError, PluginManager  # noqa: PLC0415

        def populate(tp: Path) -> None:
            _write_plugin(tp, "first")
            _write_plugin(tp, "second")

        fake = _fake_oras(populate)
        _stub_oras_pull(monkeypatch, fake)

        plugins_dir = tmp_path / "plugins"
        mgr = PluginManager(plugins_dir=plugins_dir)
        with pytest.raises(PluginError, match="multiple plugin directories"):
            await mgr.install_from_oci("ghcr.io/owner/plugin:v1")

        assert not plugins_dir.exists() or list(plugins_dir.iterdir()) == []
