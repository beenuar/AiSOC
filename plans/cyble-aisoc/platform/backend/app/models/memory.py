"""Episodic memory — past cases the agent can recall via similarity search.

Uses a tiny in-process embedding (hash-bag, deterministic) for offline operation.
Swap for real embeddings (OpenAI / sentence-transformers) when needed.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional
from sqlmodel import Field, SQLModel, JSON, Column


class EpisodicMemory(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    # Episodic recall is strictly tenant-local: the agent on tenant A
    # must never get "you saw this before" hints from tenant B's history.
    # Cross-tenant pattern sharing is a separate, opt-in federated-signal
    # feature (Theme 3b) that goes through k-anonymity + DP first.
    tenant_id: str = Field(default="demo-tenant", index=True)
    case_id: int = Field(foreign_key="case.id", unique=True)
    title: str
    narrative: str
    verdict: str
    tags: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    embedding: list[float] = Field(default_factory=list, sa_column=Column(JSON))
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
