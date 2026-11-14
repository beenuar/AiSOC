"""Closure policy and the kill switch.

Its own package rather than a module under ``app.policy``, deliberately.
``app/policy/__init__.py`` re-exports everything in ``guardrails``, so
importing any sibling from there executes that re-export and makes a module
with no caller look reachable to ``scripts/check_module_reachability.py``.
Placing this here keeps that gate's verdict on ``guardrails`` honest.
"""

from .policy import (
    POOL_READY,
    POOL_UNAVAILABLE,
    POOL_UNCONFIGURED,
    ClosureDecision,
    decide,
    kill_switch_engaged,
    reset_cache,
    resolve_pool,
    shared_pool,
)

# `authorization` is deliberately NOT re-exported here. It imports
# `app.agents.dispositions`, and `app.agents` reaches back into this package,
# so eagerly importing it from the package root would be a cycle. Callers
# import `app.closure.authorization` directly, which is also the honest
# spelling for a chokepoint: it should be obvious in a diff when a module
# starts depending on it.

__all__ = [
    "POOL_READY",
    "POOL_UNAVAILABLE",
    "POOL_UNCONFIGURED",
    "ClosureDecision",
    "decide",
    "kill_switch_engaged",
    "reset_cache",
    "resolve_pool",
    "shared_pool",
]
