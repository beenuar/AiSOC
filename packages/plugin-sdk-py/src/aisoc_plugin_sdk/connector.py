"""Data-source connector plugin base class."""

from __future__ import annotations

from abc import abstractmethod
from typing import Any, AsyncIterator

from pydantic import BaseModel, Field

from .plugin import AiSOCPlugin, PluginContext


class ConnectorConfig(BaseModel):
    """Configuration for a connector plugin instance."""

    connector_id: str = Field(..., description="Unique connector instance identifier")
    enabled: bool = True
    poll_interval_seconds: int = Field(60, ge=10, description="Polling interval in seconds")
    extra: dict[str, Any] = Field(default_factory=dict, description="Connector-specific settings")


class ConnectorPlugin(AiSOCPlugin):
    """Base class for data-source connector plugins.

    Connectors are responsible for ingesting events from external systems
    (SIEMs, ticketing systems, cloud logs, etc.) and normalising them into
    the AiSOC event format.
    """

    @abstractmethod
    async def test_connection(self, ctx: PluginContext) -> bool:
        """Verify connectivity to the upstream data source. Return True if healthy."""

    @abstractmethod
    async def fetch_events(
        self,
        ctx: PluginContext,
        since: str | None = None,
    ) -> AsyncIterator[dict[str, Any]]:
        """Yield normalised events from the upstream source.

        Args:
            ctx: Plugin context with credentials and config.
            since: ISO-8601 timestamp cursor; fetch events after this point.

        Yields:
            Normalised event dicts conforming to the AiSOC OCSF event schema.
        """
