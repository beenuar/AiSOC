"""Counterfactual / why-not explanations for case files (t4-counterfactual).

Public surface:

    from app.explain import explain_case

    facts = explain_case(case_id, tenant_id)

The explainer is deterministic and evidence-grounded — it walks the
case's :class:`AgentTrace` rows, :class:`ToolCall` rows, and
:class:`HitlRequest` rows and produces a structured "why this, why not
that" list that the case file UI renders verbatim.
"""
from app.explain.counterfactual import (
    CaseExplanation,
    CounterfactualFact,
    explain_case,
)

__all__ = [
    "CaseExplanation",
    "CounterfactualFact",
    "explain_case",
]
