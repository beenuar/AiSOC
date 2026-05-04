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
    LoadedPlugin,
    PluginError,
    PluginManager,
    PluginManifest,
)


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
    (d / "aisoc-plugin.json").write_text(
        json.dumps({"id": "x", "name": "X", "version": "1", "plugin_type": "magic"})
    )
    (d / "plugin.py").write_text("class Plugin:\n    pass\n")
    mgr = PluginManager(plugins_dir=tmp_path)
    loaded = await mgr.discover()
    assert loaded == []


@pytest.mark.asyncio
async def test_discover_skips_missing_plugin_py(tmp_path):
    d = tmp_path / "no-code"
    d.mkdir()
    (d / "aisoc-plugin.json").write_text(
        json.dumps({"id": "x", "name": "X", "version": "1", "plugin_type": "enricher"})
    )
    mgr = PluginManager(plugins_dir=tmp_path)
    loaded = await mgr.discover()
    assert loaded == []


@pytest.mark.asyncio
async def test_discover_skips_plugin_without_plugin_class(tmp_path):
    d = tmp_path / "no-class"
    d.mkdir()
    (d / "aisoc-plugin.json").write_text(
        json.dumps({"id": "x", "name": "X", "version": "1", "plugin_type": "enricher"})
    )
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
    plugin_dir = _write_plugin(tmp_path, "reloadable")
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
    m = PluginManifest.from_dict(
        {"id": "a", "name": "A", "version": "1", "plugin_type": "enricher"}
    )
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
