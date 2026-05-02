"""
Base connector interface for all integrations.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class BaseConnector(ABC):
    """All connectors implement this interface."""

    connector_id: str = ""
    connector_name: str = ""

    @abstractmethod
    async def test_connection(self) -> dict[str, Any]:
        """Test connectivity and credential validity."""
        ...

    @abstractmethod
    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        """Fetch recent alerts/events from the source."""
        ...

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        """
        Normalize a raw event to a common AiSOC alert schema.
        Subclasses should override for source-specific normalization.
        """
        return raw
