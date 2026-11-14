"""Shared data models for the three-tier memory system."""

from __future__ import annotations

import enum
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class MemoryTier(str, enum.Enum):
    session = "session"
    working = "working"
    institutional = "institutional"


class MemoryEntry(BaseModel):
    tier: MemoryTier
    tenant_id: str
    run_id: str | None = None
    key: str
    value: Any
    created_at: datetime = Field(default_factory=datetime.utcnow)
    ttl_seconds: int | None = None
    tags: list[str] = Field(default_factory=list)
    analyst_override: bool = False
    override_reason: str | None = None


class OverrideFeedback(BaseModel):
    """Captures analyst correction for retroactive re-disposition and
    institutional memory ingestion."""

    tenant_id: str
    run_id: str
    alert_id: str
    original_verdict: str
    corrected_verdict: str
    analyst_id: str | None = None
    reason: str | None = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
