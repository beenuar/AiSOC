"""Tests for the plugin manifest loader."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from aisoc_plugin_sdk import load_manifest, PluginLoadError
from aisoc_plugin_sdk.loader import load_plugin_from_directory


def write_manifest(tmp_path: Path, content: str) -> None:
    (tmp_path / "aisoc-plugin.yaml").write_text(textwrap.dedent(content))


def test_load_manifest_valid(tmp_path: Path) -> None:
    write_manifest(tmp_path, """
        id: myorg.test-enricher
        name: Test Enricher
        version: 1.2.3
        plugin_type: enricher
        description: A test enricher plugin
        author: Test Author
        tags:
          - test
          - enricher
    """)
    manifest = load_manifest(tmp_path)
    assert manifest.id == "myorg.test-enricher"
    assert manifest.version == "1.2.3"
    assert manifest.plugin_type == "enricher"
    assert "test" in manifest.tags


def test_load_manifest_missing_file(tmp_path: Path) -> None:
    with pytest.raises(PluginLoadError, match="aisoc-plugin.yaml"):
        load_manifest(tmp_path)


def test_load_manifest_invalid_yaml(tmp_path: Path) -> None:
    (tmp_path / "aisoc-plugin.yaml").write_text("id: [unclosed")
    with pytest.raises(PluginLoadError):
        load_manifest(tmp_path)


def test_load_manifest_invalid_schema(tmp_path: Path) -> None:
    write_manifest(tmp_path, """
        id: test.plugin
        name: Test
        version: 1.0.0
        plugin_type: invalid_type
    """)
    with pytest.raises(PluginLoadError, match="Invalid manifest"):
        load_manifest(tmp_path)


def test_load_plugin_from_directory(tmp_path: Path) -> None:
    write_manifest(tmp_path, """
        id: test.loader-enricher
        name: Loader Enricher
        version: 1.0.0
        plugin_type: enricher
    """)
    (tmp_path / "plugin.py").write_text(textwrap.dedent("""
        from aisoc_plugin_sdk import (
            EnricherPlugin, PluginManifest, PluginContext,
            EnrichmentRequest, EnrichmentResult,
        )

        class _Plugin(EnricherPlugin):
            @property
            def manifest(self) -> PluginManifest:
                return PluginManifest(
                    id="test.loader-enricher",
                    name="Loader Enricher",
                    version="1.0.0",
                    plugin_type="enricher",
                )

            async def enrich(self, req: EnrichmentRequest, ctx: PluginContext) -> EnrichmentResult:
                return EnrichmentResult(
                    indicator_type=req.indicator_type,
                    indicator_value=req.indicator_value,
                )

        def create_plugin() -> _Plugin:
            return _Plugin()
    """))

    plugin = load_plugin_from_directory(tmp_path)
    assert plugin.manifest.id == "test.loader-enricher"


def test_load_plugin_missing_entry_point(tmp_path: Path) -> None:
    write_manifest(tmp_path, """
        id: test.no-entry
        name: No Entry
        version: 1.0.0
        plugin_type: action
    """)
    with pytest.raises(PluginLoadError, match="plugin.py"):
        load_plugin_from_directory(tmp_path)


def test_load_plugin_missing_factory(tmp_path: Path) -> None:
    write_manifest(tmp_path, """
        id: test.no-factory
        name: No Factory
        version: 1.0.0
        plugin_type: action
    """)
    (tmp_path / "plugin.py").write_text("# no create_plugin here\n")
    with pytest.raises(PluginLoadError, match="create_plugin"):
        load_plugin_from_directory(tmp_path)
