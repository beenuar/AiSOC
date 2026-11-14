"""Tool invocation record. Risk-classified per the plan's MCP tool registry."""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from sqlmodel import Field, SQLModel, JSON, Column


class RiskClass(str, Enum):
    READ = "READ"
    WRITE_REVERSIBLE = "WRITE-REVERSIBLE"
    WRITE_SIGNIFICANT = "WRITE-SIGNIFICANT"
    DESTRUCTIVE = "DESTRUCTIVE"


class ToolCall(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    # Denormalized from `Case.tenant_id` so tool-audit queries don't have
    # to join (and so a stale Case row can't grant cross-tenant access).
    tenant_id: str = Field(default="demo-tenant", index=True)
    case_id: int = Field(foreign_key="case.id", index=True)
    trace_id: int | None = Field(default=None, foreign_key="agenttrace.id")
    tool_name: str = Field(index=True)
    integration: str = Field(index=True)
    risk_class: RiskClass
    params: dict = Field(default_factory=dict, sa_column=Column(JSON))
    result: dict = Field(default_factory=dict, sa_column=Column(JSON))
    success: bool = True
    error: str | None = None
    hitl_required: bool = False
    hitl_approved_by: str | None = None
    duration_ms: int = 0
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # ── Rollback / reverse-action audit trail (t1-reverse-actions) ─────
    # When this row IS a rollback, `rollback_of_id` points at the original
    # forward action it reverses. The forward row is mutated in turn:
    # `rolled_back_at` + `rolled_back_by` are stamped so a single SELECT
    # against either row exposes the full undo graph for audit (SOC2,
    # ISO27001) without a second join.
    rollback_of_id: Optional[int] = Field(
        default=None, foreign_key="toolcall.id", index=True
    )
    rolled_back_at: Optional[datetime] = None
    # Free-form actor id ("agent:responder", "user:42", "system:sla-timeout").
    # Not FK-constrained because rollbacks can be triggered by non-user
    # actors (background SLA watcher, dry-run unwind, etc.).
    rolled_back_by: Optional[str] = None
