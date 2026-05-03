"""Plugin manifest loader and validator.

Reads ``aisoc-plugin.yaml`` from a plugin package directory, validates it
against the ``PluginManifest`` schema, and returns a typed manifest object.
"""

from __future__ import annotations

import importlib
import importlib.util
import sys
from pathlib import Path
from typing import Any

try:
    import yaml  # type: ignore[import-untyped]
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False

from .plugin import AiSOCPlugin, PluginManifest


class PluginLoadError(Exception):
    """Raised when a plugin cannot be loaded."""


def load_manifest(plugin_dir: Path) -> PluginManifest:
    """Parse and validate ``aisoc-plugin.yaml`` inside *plugin_dir*.

    Args:
        plugin_dir: Directory that contains ``aisoc-plugin.yaml``.

    Returns:
        Validated :class:`PluginManifest`.

    Raises:
        PluginLoadError: If the file is missing, unparseable, or invalid.
    """
    if not _YAML_AVAILABLE:
        raise PluginLoadError(
            "PyYAML is required to load plugin manifests. "
            "Install it with: pip install pyyaml"
        )
    manifest_path = plugin_dir / "aisoc-plugin.yaml"
    if not manifest_path.exists():
        raise PluginLoadError(f"No aisoc-plugin.yaml found in {plugin_dir}")

    try:
        raw: dict[str, Any] = yaml.safe_load(manifest_path.read_text())
    except yaml.YAMLError as exc:
        raise PluginLoadError(f"Failed to parse {manifest_path}: {exc}") from exc

    try:
        return PluginManifest.model_validate(raw)
    except Exception as exc:
        raise PluginLoadError(f"Invalid manifest in {manifest_path}: {exc}") from exc


def load_plugin_from_directory(plugin_dir: Path) -> AiSOCPlugin:
    """Load a plugin from a directory.

    The directory must contain:
    - ``aisoc-plugin.yaml`` — manifest file
    - ``plugin.py`` (or package) — must expose a ``create_plugin()`` factory
      that returns an :class:`AiSOCPlugin` instance.

    Args:
        plugin_dir: Path to the plugin directory.

    Returns:
        An instantiated :class:`AiSOCPlugin`.

    Raises:
        PluginLoadError: On any load failure.
    """
    manifest = load_manifest(plugin_dir)

    # Try loading ``plugin.py`` from the directory
    entry_point = plugin_dir / "plugin.py"
    if not entry_point.exists():
        raise PluginLoadError(
            f"No plugin.py entry point found in {plugin_dir}. "
            "Create a plugin.py that exposes a create_plugin() function."
        )

    module_name = f"_aisoc_plugin_{manifest.id.replace('.', '_').replace('-', '_')}"
    spec = importlib.util.spec_from_file_location(module_name, entry_point)
    if spec is None or spec.loader is None:
        raise PluginLoadError(f"Cannot import {entry_point}")

    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)  # type: ignore[union-attr]
    except Exception as exc:
        raise PluginLoadError(f"Error executing {entry_point}: {exc}") from exc

    factory = getattr(module, "create_plugin", None)
    if factory is None:
        raise PluginLoadError(
            f"{entry_point} must define a create_plugin() function "
            "that returns an AiSOCPlugin instance."
        )

    try:
        plugin: AiSOCPlugin = factory()
    except Exception as exc:
        raise PluginLoadError(
            f"create_plugin() in {entry_point} raised an error: {exc}"
        ) from exc

    if not isinstance(plugin, AiSOCPlugin):
        raise PluginLoadError(
            f"create_plugin() must return an AiSOCPlugin, got {type(plugin)}"
        )

    return plugin
