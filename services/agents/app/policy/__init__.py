"""Autonomy guardrails — per-action confidence thresholds.

Each action the agent can take (e.g. ``block_ip``, ``isolate_host``)
is associated with a minimum confidence threshold.  If the agent's
self-assessed confidence for an action is below the threshold, the
action is held for human review rather than executed autonomously.

Defaults live here; tenant admins can override via the DB / API.

Usage::

    from app.policy import GuardrailPolicy, ActionResult

    policy = await GuardrailPolicy.load(tenant_id="t1")
    result = policy.evaluate("block_ip", confidence=0.72)
    if result.allowed:
        await do_block(ip)
    else:
        await queue_for_human_review(action, result.reason)
"""

from .guardrails import ActionResult, GuardrailPolicy

__all__ = ["GuardrailPolicy", "ActionResult"]
