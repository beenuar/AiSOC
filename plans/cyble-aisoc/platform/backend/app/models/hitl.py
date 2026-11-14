"""Human-in-the-Loop (HITL) approval request — blocking gate for risky actions.

This replaces the prior demo-auto-approve stub. Every WRITE-REVERSIBLE,
WRITE-SIGNIFICANT, or DESTRUCTIVE tool call (per autonomy + risk policy) creates
one row here, blocks the agent until a decision is recorded, and emits an audit
trail on both the request and the decision.

State machine (no auto-approve on timeout — explicit decision required):

                ┌──────────────┐
                │   PENDING    │
                └──────┬───────┘
                       │
        ┌──────────────┼──────────────┬──────────────┐
        ▼              ▼              ▼              ▼
   APPROVED        DENIED         TIMEOUT        CANCELLED
   (analyst,    (analyst,      (SLA expired,   (case closed
    MFA-bound)   MFA-bound)     action denied)  before decision)

Only APPROVED unblocks the tool. TIMEOUT explicitly denies and is escalated.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from sqlmodel import JSON, Column, Field, SQLModel


class HitlState(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


class HitlChannel(str, Enum):
    """Surface that delivered the decision (audit-relevant)."""

    CONSOLE = "console"
    SLACK = "slack"
    TEAMS = "teams"
    MOBILE = "mobile"
    API = "api"
    SYSTEM = "system"  # for TIMEOUT / CANCELLED system-generated decisions


class HitlRequest(SQLModel, table=True):
    """A blocking approval request for a risky tool invocation."""

    id: Optional[int] = Field(default=None, primary_key=True)

    # Tenant scoping (denormalized from Case.tenant_id). The HITL pending
    # queue is fanned out per-tenant; an analyst on tenant A must never
    # see (or decide) an approval request from tenant B.
    tenant_id: str = Field(default="demo-tenant", index=True)

    # Linkage
    case_id: int = Field(foreign_key="case.id", index=True)
    trace_id: int | None = Field(default=None, foreign_key="agenttrace.id")
    tool_call_id: int | None = Field(default=None, foreign_key="toolcall.id", index=True)

    # What is being requested
    agent: str = Field(index=True)
    tool_name: str = Field(index=True)
    integration: str = Field(index=True)
    risk_class: str  # RiskClass value
    params: dict = Field(default_factory=dict, sa_column=Column(JSON))
    rationale: str = ""  # agent's stated reason
    blast_radius: dict = Field(default_factory=dict, sa_column=Column(JSON))

    # State
    state: HitlState = Field(default=HitlState.PENDING, index=True)
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), index=True
    )
    expires_at: datetime  # SLA — decision deadline
    decided_at: datetime | None = None

    # Decision audit
    decided_by: str | None = None  # analyst principal (sub from JWT, or "system")
    decided_by_mfa_token: str | None = None  # MFA receipt (hash of OTP / passkey id)
    decided_by_mfa_method: str | None = None  # totp / webauthn / sso-mfa
    decided_channel: HitlChannel | None = None
    decision_reason: str | None = None  # analyst comment

    # Notifications fired
    notifications: list[dict] = Field(
        default_factory=list, sa_column=Column(JSON)
    )  # [{channel, sent_at, ok, error?}]

    # Escalation
    escalated: bool = False
    escalated_at: datetime | None = None
    escalation_target: str | None = None
