"""FinOps for AI (t5-finops).

Reuses the observability layer (token spend per case) and layers on:

  - Per-tenant cost rollups by day, by agent, by model.
  - Analyst-time-saved -> dollars-saved estimate (the ROI numerator).
  - Per-tenant monthly budgets with breach alerts.
  - REST endpoints under ``/finops/...`` powering the dashboard.

We deliberately avoid building a generic billing engine. The point is
to make the platform's cost legible to operators (engineering /
finance) and to surface ROI to the customer (analyst hours saved).
"""
from app.finops.cost import (
    AgentCostRow,
    BudgetStatus,
    DailySpendRow,
    FinOpsBudget,
    FinOpsRollup,
    ModelCostRow,
    ROIEstimate,
    budget_status,
    finops_rollup,
    set_budget,
)

__all__ = [
    "AgentCostRow",
    "BudgetStatus",
    "DailySpendRow",
    "FinOpsBudget",
    "FinOpsRollup",
    "ModelCostRow",
    "ROIEstimate",
    "budget_status",
    "finops_rollup",
    "set_budget",
]
