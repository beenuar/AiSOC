"""Convenience decorators for defining plugins as plain functions."""

from __future__ import annotations

import functools
from typing import Any, Callable

from .plugin import PluginManifest
from .enricher import EnricherPlugin, EnrichmentRequest, EnrichmentResult
from .action import ActionPlugin, ActionRequest, ActionResult


def enricher(
    id: str,
    name: str,
    version: str = "1.0.0",
    description: str = "",
    author: str = "",
    tags: list[str] | None = None,
) -> Callable:
    """Decorator that wraps an async function into an EnricherPlugin.

    Example::

        @enricher(id="myorg.vt-enricher", name="VirusTotal Enricher")
        async def vt_enrich(request: EnrichmentRequest, ctx: PluginContext) -> EnrichmentResult:
            ...
    """
    def decorator(fn: Callable) -> type[EnricherPlugin]:
        manifest = PluginManifest(
            id=id,
            name=name,
            version=version,
            description=description,
            author=author,
            tags=tags or [],
            plugin_type="enricher",
        )

        class _FunctionEnricher(EnricherPlugin):
            @property
            def manifest(self) -> PluginManifest:  # type: ignore[override]
                return manifest

            async def enrich(self, request: EnrichmentRequest, ctx: Any) -> EnrichmentResult:
                return await fn(request, ctx)

        _FunctionEnricher.__name__ = fn.__name__
        _FunctionEnricher.__qualname__ = fn.__qualname__
        return _FunctionEnricher

    return decorator


def action(
    id: str,
    name: str,
    actions: list[str],
    version: str = "1.0.0",
    description: str = "",
    author: str = "",
    tags: list[str] | None = None,
) -> Callable:
    """Decorator that wraps an async function into an ActionPlugin.

    Example::

        @action(id="myorg.block-ip", name="Block IP", actions=["block_ip"])
        async def block_ip_action(request: ActionRequest, ctx: PluginContext) -> ActionResult:
            ...
    """
    def decorator(fn: Callable) -> type[ActionPlugin]:
        manifest = PluginManifest(
            id=id,
            name=name,
            version=version,
            description=description,
            author=author,
            tags=tags or [],
            plugin_type="action",
        )
        _actions = actions

        class _FunctionAction(ActionPlugin):
            @property
            def manifest(self) -> PluginManifest:  # type: ignore[override]
                return manifest

            def supported_actions(self) -> list[str]:
                return _actions

            async def execute(self, request: ActionRequest, ctx: Any) -> ActionResult:
                return await fn(request, ctx)

        _FunctionAction.__name__ = fn.__name__
        _FunctionAction.__qualname__ = fn.__qualname__
        return _FunctionAction

    return decorator


def connector(
    id: str,
    name: str,
    version: str = "1.0.0",
    description: str = "",
    author: str = "",
    tags: list[str] | None = None,
) -> Callable:
    """Marker decorator — intended for use with ConnectorPlugin subclasses to set manifest metadata."""
    def decorator(cls: type) -> type:
        manifest = PluginManifest(
            id=id,
            name=name,
            version=version,
            description=description,
            author=author,
            tags=tags or [],
            plugin_type="connector",
        )

        @property  # type: ignore[misc]
        def _manifest(self: Any) -> PluginManifest:
            return manifest

        cls.manifest = _manifest  # type: ignore[assignment]
        return cls

    return decorator
