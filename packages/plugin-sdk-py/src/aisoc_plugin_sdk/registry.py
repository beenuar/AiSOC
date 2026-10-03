"""Plugin registry — tracks loaded plugin instances by ID."""

from __future__ import annotations

import structlog

from .plugin import AiSOCPlugin, PluginContext
from .enricher import EnricherPlugin
from .action import ActionPlugin
from .connector import ConnectorPlugin

logger = structlog.get_logger(__name__)


class PluginRegistry:
    """Central registry for all loaded AiSOC plugins."""

    def __init__(self) -> None:
        self._plugins: dict[str, AiSOCPlugin] = {}

    # ── Registration ─────────────────────────────────────────────────────────

    def register(self, plugin: AiSOCPlugin) -> None:
        """Register a plugin instance."""
        pid = plugin.manifest.id
        if pid in self._plugins:
            logger.warning("plugin_already_registered", plugin_id=pid)
        self._plugins[pid] = plugin
        logger.info("plugin_registered", plugin_id=pid, type=plugin.manifest.plugin_type)

    def unregister(self, plugin_id: str) -> None:
        """Remove a plugin from the registry."""
        self._plugins.pop(plugin_id, None)

    # ── Loading ───────────────────────────────────────────────────────────────

    async def load_all(self, ctx: PluginContext) -> None:
        """Call on_load for every registered plugin."""
        for pid, plugin in self._plugins.items():
            try:
                await plugin.on_load(ctx)
                logger.info("plugin_loaded", plugin_id=pid)
            except Exception:
                logger.exception("plugin_load_failed", plugin_id=pid)

    async def unload_all(self) -> None:
        """Call on_unload for every registered plugin."""
        for pid, plugin in self._plugins.items():
            try:
                await plugin.on_unload()
                logger.info("plugin_unloaded", plugin_id=pid)
            except Exception:
                logger.exception("plugin_unload_failed", plugin_id=pid)

    # ── Lookups ───────────────────────────────────────────────────────────────

    def get(self, plugin_id: str) -> AiSOCPlugin | None:
        return self._plugins.get(plugin_id)

    def enrichers(self) -> list[EnricherPlugin]:
        return [p for p in self._plugins.values() if isinstance(p, EnricherPlugin)]

    def actions(self) -> list[ActionPlugin]:
        return [p for p in self._plugins.values() if isinstance(p, ActionPlugin)]

    def connectors(self) -> list[ConnectorPlugin]:
        return [p for p in self._plugins.values() if isinstance(p, ConnectorPlugin)]

    def all(self) -> list[AiSOCPlugin]:
        return list(self._plugins.values())

    def __len__(self) -> int:
        return len(self._plugins)
