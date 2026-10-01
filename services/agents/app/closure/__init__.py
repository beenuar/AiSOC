"""Closure policy and the kill switch.

Its own package rather than a module under ``app.policy``, deliberately.
``app/policy/__init__.py`` re-exports everything in ``guardrails``, so
importing any sibling from there executes that re-export and makes a module
with no caller look reachable to ``scripts/check_module_reachability.py``.
Placing this here keeps that gate's verdict on ``guardrails`` honest.
"""

from .policy import ClosureDecision, decide, kill_switch_engaged, reset_cache

__all__ = ["ClosureDecision", "decide", "kill_switch_engaged", "reset_cache"]
