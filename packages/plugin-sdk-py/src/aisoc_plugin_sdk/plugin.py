"""Base plugin abstractions for AiSOC plugins."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, Field


class PluginManifest(BaseModel):
    """Declares plugin identity and capabilities."""

    id: str = Field(..., description="Unique plugin identifier, e.g. 'myorg.virustotal-enricher'")
    name: str = Field(..., description="Human-readable name")
    version: str = Field(..., description="SemVer string, e.g. '1.0.0'")
    description: str = Field(default="", description="Short description shown in the marketplace")
    author: str = Field(default="", description="Author or organisation name")
    tags: list[str] = Field(default_factory=list, description="Free-form tags for discovery")
    plugin_type: str = Field(
        ...,
        description="One of: enricher | action | connector",
        pattern="^(enricher|action|connector)$",
    )


class PluginContext(BaseModel):
    """Runtime context passed to every plugin invocation."""

    api_base_url: str = Field(..., description="AiSOC API base URL, e.g. 'http://api:8000'")
    api_token: str = Field(..., description="Scoped API token for this plugin")
    config: dict[str, Any] = Field(
        default_factory=dict,
        description="Plugin-level config from aisoc-plugin.yaml",
    )


class PluginResult(BaseModel):
    """Generic wrapper for plugin output."""

    success: bool
    data: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None


class AiSOCPlugin(ABC):
    """Base class for all AiSOC plugins."""

    @property
    @abstractmethod
    def manifest(self) -> PluginManifest:
        """Return the plugin manifest."""

    async def on_load(self, ctx: PluginContext) -> None:
        """Called once when the plugin is loaded. Override to initialise resources."""

    async def on_unload(self) -> None:
        """Called when the plugin is unloaded. Override to clean up resources."""
