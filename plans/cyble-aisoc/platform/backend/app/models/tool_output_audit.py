"""Immutable audit log of raw tool output.

The agent persists the *sanitized* tool result on `ToolCall.result` because
that is what every downstream surface (case file, transcript, LLM context)
should consume. But for forensics, red-team replays, and "did the vendor
actually send us this string?" investigations we also need the *raw*
pre-defense bytes.

That is this table. One row per tool call, written even when the defender
hard-blocks. The defender's verdict is denormalized in for fast queries
(e.g. "show me every tool call this week that tripped the override-instruction
classifier") without joining out to a separate verdict table.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlmodel import Column, Field, JSON, SQLModel


class ToolOutputAudit(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    # Denormalized so cross-tenant forensic queries are impossible by
    # construction at this layer.
    tenant_id: str = Field(default="demo-tenant", index=True)
    case_id: int = Field(foreign_key="case.id", index=True)
    trace_id: int | None = Field(default=None, foreign_key="agenttrace.id")
    tool_call_id: int | None = Field(default=None, foreign_key="toolcall.id", index=True)
    tool_name: str = Field(index=True)
    integration: str = Field(index=True)

    # Raw pre-defense output (may be truncated by
    # `ToolOutputDefender.truncate_for_audit` for sanity).
    raw_output: dict = Field(default_factory=dict, sa_column=Column(JSON))
    # Sanitized + schema-validated output (pre-provenance-wrap), the same
    # payload that `ToolCall.result` holds. Stored redundantly so an audit
    # query is self-contained.
    sanitized_output: dict = Field(default_factory=dict, sa_column=Column(JSON))

    # Defender verdict, denormalized for query speed.
    risk: str = Field(default="clean", index=True)
    signals: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    notes: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    schema_violations: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    blocked: bool = Field(default=False, index=True)

    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
