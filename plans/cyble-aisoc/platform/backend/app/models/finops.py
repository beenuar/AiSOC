"""FinOps tables (t5-finops): per-tenant LLM cost budgets.

We store the *intent* of the operator — "this tenant gets a $500
monthly budget for LLM spend, alert at 80% utilisation". Actual spend
is computed on demand from :class:`AgentTrace` rows so the budget
table never has to be kept in sync.

The table is small on purpose. A full billing system would track per-
SKU usage, invoices, payment terms, refunds, ... that's not what
FinOps for AI needs. We need a knob the operator can twist.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlmodel import Field, SQLModel


class FinOpsBudget(SQLModel, table=True):
    """One row per tenant budget."""

    __tablename__ = "finops_budget"

    id: Optional[int] = Field(default=None, primary_key=True)

    # Tenant scoping. UNIQUE so a tenant has at most one active
    # budget — operators set the *current* budget; history is
    # captured in the ``updated_at`` audit column.
    tenant_id: str = Field(unique=True, index=True)

    # Monthly cap in USD. Stored as float (we round to cents at the
    # API boundary). 0 or negative is treated as "alerts only, no
    # cap" by the alerting helper.
    monthly_usd: float = Field(default=500.0)

    # Alert threshold expressed as a fraction of the monthly cap.
    # ``0.8`` means "alert when 80% of the budget is consumed". The
    # platform pings the configured channel(s) once per threshold
    # cross — repeat suppression lives in the notifier layer, not
    # here.
    alert_threshold: float = Field(default=0.8)

    # Free-form contact (slack-channel-id, email, webhook URL). The
    # alert dispatcher knows how to interpret common formats; this
    # column is a string so we don't have to migrate when we add a
    # new channel.
    alert_target: str = Field(default="")

    # ROI knob: dollar value the operator assigns to one analyst
    # hour saved by automation. This becomes the ROI numerator in
    # :class:`ROIEstimate`. Defaults to 100 USD/hr — a reasonable
    # mid-market loaded SOC analyst rate.
    analyst_hourly_usd: float = Field(default=100.0)

    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
