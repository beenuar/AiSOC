"""Enricher plugin base class."""

from __future__ import annotations

from abc import abstractmethod
from typing import Any

from pydantic import BaseModel, Field

from .plugin import AiSOCPlugin, PluginContext


class EnrichmentRequest(BaseModel):
    """Payload sent to an enricher plugin."""

    indicator_type: str = Field(
        ...,
        description="Type of indicator: ip | domain | url | hash | email",
    )
    indicator_value: str = Field(..., description="The indicator value to enrich")
    case_id: str | None = Field(None, description="Associated case ID, if any")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Caller-supplied metadata")


class EnrichmentResult(BaseModel):
    """Result returned by an enricher plugin."""

    indicator_type: str
    indicator_value: str
    enrichments: dict[str, Any] = Field(
        default_factory=dict,
        description="Key-value enrichment data to merge into the indicator record",
    )
    tags: list[str] = Field(default_factory=list, description="Tags to apply to the indicator")
    malicious: bool | None = Field(None, description="True/False/None if enricher can determine")
    confidence: float | None = Field(
        None, ge=0.0, le=1.0, description="Confidence score 0–1, if applicable"
    )
    raw: dict[str, Any] = Field(
        default_factory=dict, description="Raw upstream API response for audit purposes"
    )


class EnricherPlugin(AiSOCPlugin):
    """Base class for enricher plugins."""

    @abstractmethod
    async def enrich(
        self, request: EnrichmentRequest, ctx: PluginContext
    ) -> EnrichmentResult:
        """Enrich an indicator and return structured results."""
