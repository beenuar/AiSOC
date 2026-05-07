"""Autonomy guardrails — per-action confidence thresholds.

Every action the agent can take (e.g. ``block_ip``, ``isolate_host``) carries
three confidence cutoffs:

* ``auto``        — execute autonomously
* ``review``      — queue for analyst review
* ``escalation``  — escalate to senior on-call (anything below is rejected)

Defaults live here; site policy can override via YAML; tenant admins can
override per-tenant via the DB / admin UI.

Usage::

    from app.policy import GuardrailPolicy, AutonomyDecision

    policy = await GuardrailPolicy.load(tenant_id="t1")
    decision = policy.decide("block_ip", confidence=0.72)
    if decision.decision is AutonomyDecision.AUTO:
        await do_block(ip)
    elif decision.decision is AutonomyDecision.REVIEW:
        await queue_for_analyst_review(decision)
    elif decision.decision is AutonomyDecision.ESCALATE:
        await page_oncall(decision)
    else:  # REJECT
        await abandon_action(decision)
"""

from .guardrails import (
    ActionResult,
    ActionThresholds,
    AutonomyDecision,
    DecisionResult,
    GuardrailPolicy,
    default_thresholds,
    reset_tenant_cache,
    reset_yaml_cache,
    yaml_thresholds,
)

__all__ = [
    "ActionResult",
    "ActionThresholds",
    "AutonomyDecision",
    "DecisionResult",
    "GuardrailPolicy",
    "default_thresholds",
    "reset_tenant_cache",
    "reset_yaml_cache",
    "yaml_thresholds",
]
