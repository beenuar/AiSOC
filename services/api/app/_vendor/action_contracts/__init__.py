"""Vendored mirror of the action contracts from ``services/actions``.

Do not hand-edit the modules beside this one. They are byte-identical copies
of ``services/actions/app/live_actions/{contract,capability_contracts,approval_rules}.py``
maintained by ``scripts/sync_vendored_action_contracts.py``, which CI runs in
``--check`` mode.

This file is the package marker and exists only here: the source modules live
in a package whose own ``__init__`` imports the dispatcher, the registry and
every vendor adapter, none of which belong in the API image.

What the API uses it for: the console's autonomy page has to say whether a
response verb would actually auto-execute under the deployment's autonomy
tier. Answering that with a second rule is what the page used to do, and it
announced an autopilot posture on a deployment that queues every containment
verb for a human. See ``app/services/autonomy_effective.py``.

The time gates (``ResponseSchedule``, ``BusinessWindow``, ``apply_schedule``)
are exported for the same reason. They were absent from this list while the
console's autonomy page answered "would this verb auto-execute" without them,
so a tenant in a declared change freeze read a page saying their verbs run
unattended — which was true of the page and, until the dispatcher was wired to
the schedule, also true of the dispatcher.
"""

from .approval_rules import (
    AUTOMATIC_CONFIDENCE_FLOOR,
    DEFAULT_TIER,
    TIER_FULL_NAMES,
    TIER_LABELS,
    TIER_MAX_AUTOMATIC,
    TIER_ORDER,
    ApprovalDecision,
    BusinessWindow,
    ResponseSchedule,
    apply_schedule,
    evaluate,
    evaluate_contract,
    tier_from_env_value,
)
from .capability_contracts import CAPABILITY_CONTRACTS, CapabilityContract
from .contract import NEVER_AUTONOMOUS, ActionImpact, ApprovalRequirement, Reversal

__all__ = [
    "AUTOMATIC_CONFIDENCE_FLOOR",
    "CAPABILITY_CONTRACTS",
    "DEFAULT_TIER",
    "NEVER_AUTONOMOUS",
    "TIER_FULL_NAMES",
    "TIER_LABELS",
    "TIER_MAX_AUTOMATIC",
    "TIER_ORDER",
    "ActionImpact",
    "ApprovalDecision",
    "ApprovalRequirement",
    "BusinessWindow",
    "CapabilityContract",
    "ResponseSchedule",
    "Reversal",
    "apply_schedule",
    "evaluate",
    "evaluate_contract",
    "tier_from_env_value",
]
