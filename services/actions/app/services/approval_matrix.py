"""The approval matrix, re-exported from where both services can read it.

Every door still imports ``evaluate_contract`` from here and the grading has
not changed. The rules themselves moved one directory across to
``app/live_actions/approval_rules.py``, beside ``contract.py`` and
``capability_contracts.py``, so that the three form a unit importing nothing
but each other and the standard library — which is what lets ``services/api``
carry a byte-identical copy at ``app/_vendor/action_contracts/`` and answer
"would this verb auto-execute" with the same function the dispatcher uses
rather than with a second opinion of its own.

``scripts/sync_vendored_action_contracts.py --check`` keeps the two copies
identical. ``tests/test_approval_doors_agree.py`` reads imports from this
module path by name, so the path staying put is load-bearing rather than
merely convenient.
"""

from __future__ import annotations

from app.live_actions.approval_rules import (
    AUTOMATIC_CONFIDENCE_FLOOR,
    DEFAULT_TIER,
    TIER_FULL_NAMES,
    TIER_LABELS,
    TIER_MAX_AUTOMATIC,
    TIER_ORDER,
    ApprovalDecision,
    evaluate,
    evaluate_contract,
    logger,
    tier_from_env_value,
)

__all__ = [
    "AUTOMATIC_CONFIDENCE_FLOOR",
    "DEFAULT_TIER",
    "TIER_FULL_NAMES",
    "TIER_LABELS",
    "TIER_MAX_AUTOMATIC",
    "TIER_ORDER",
    "ApprovalDecision",
    "evaluate",
    "evaluate_contract",
    "logger",
    "tier_from_env_value",
]
