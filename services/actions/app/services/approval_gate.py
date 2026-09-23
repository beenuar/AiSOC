"""The gate that actually runs on ``POST /actions``, combining both axes.

``BlastRadiusGate`` asks one question: is this verb's blast radius within the
auto-execute limit. That is a property of the verb alone, so the same answer
comes back for a 40%-confidence guess and a corroborated finding.

``approval_matrix.evaluate`` asks the other one — confidence against the
action's declared impact, under the tenant's autonomy tier — and it was
written, documented, unit-tested, listed in the claim-to-gate matrix as
GATED, and **called by nothing**. A repository-wide search for
``approval_matrix`` found the module, its own test, the contract checker and
two doc mentions. The gate the docs described was not the gate that ran.

This module runs both and takes the stricter, which is the composition rule
the matrix already states for its own three inputs: each can raise a
requirement, none can lower it. So switching it on cannot make anything
auto-execute that did not before.

Two honest limits, both logged rather than papered over:

Seven of the 25 ``ActionType`` members have no capability contract
(``ack_alert``, ``notify_slack``, ``run_playbook`` and four others). For
those the matrix has no impact to reason about and blast radius decides
alone. That is recorded at debug rather than guessed at, because inventing an
impact for an unmapped verb is how a gate starts certifying things it never
examined.

A request with no ``confidence`` is treated as the lowest band. For anything
above READ_ONLY impact that means analyst approval, which is a real tightening
of the previous behaviour and is the intended direction.
"""

from __future__ import annotations

import structlog

from app.live_actions.capability_contracts import CAPABILITY_CONTRACTS
from app.live_actions.contract import ApprovalRequirement
from app.models.action import ActionRequest, ActionStatus, BlastRadius
from app.services.approval_matrix import evaluate as evaluate_matrix

logger = structlog.get_logger()

#: Conservative default when no tenant policy can be read. Mirrors
#: ``dispatcher.configured_tier``: L1 notifies, it does not act.
_DEFAULT_TIER = "L1"


def _tier_label(tier: object) -> str:
    """Map a ``MaturityTier`` (or anything tier-shaped) onto ``L0``..``L4``."""
    name = getattr(tier, "name", None)
    if isinstance(name, str) and name.startswith("L"):
        return name.split("_")[0]
    value = getattr(tier, "value", tier)
    if isinstance(value, int) and 0 <= value <= 4:
        return f"L{value}"
    return _DEFAULT_TIER


async def _resolve_tier(tenant_id: object) -> str:
    """The tenant's autonomy tier, falling back to the deployment default.

    Imported lazily: ``resolve_tenant_policy`` reaches for a database, and the
    submit path has to keep working in the many tests and deployments that
    have none.
    """
    try:
        from app.services.tenant_policy import resolve_tenant_policy

        policy = await resolve_tenant_policy(tenant_id)
    except Exception as exc:  # noqa: BLE001 — no policy store is a normal state
        logger.debug("approval_gate.tier_unresolved", error=str(exc))
        return _DEFAULT_TIER
    return _tier_label(getattr(policy, "tier", None))


async def apply_matrix(
    request: ActionRequest,
    status: ActionStatus,
    blast_radius: BlastRadius,
    reason: str,
) -> tuple[ActionStatus, str]:
    """Raise the blast-radius verdict to whatever the matrix demands.

    Returns the (possibly unchanged) status and the reason that decided it.
    Never lowers: a blast-radius gate that already demands approval keeps
    demanding it whatever the confidence says.
    """
    contract = CAPABILITY_CONTRACTS.get(request.action_type.value)
    if contract is None:
        logger.debug(
            "approval_gate.no_capability_contract",
            action_type=request.action_type.value,
            note="blast radius decides alone; impact is unknown for this verb",
        )
        return status, reason

    decision = evaluate_matrix(
        impact=contract.impact,
        declared_approval=contract.approval,
        confidence=request.confidence,
        tier=await _resolve_tier(request.tenant_id),
    )

    if decision.is_blocked:
        logger.info(
            "Action prohibited by contract",
            action_type=request.action_type.value,
            impact=decision.impact.value,
            reason=decision.reason,
        )
        return ActionStatus.REJECTED, decision.reason

    if decision.requirement == ApprovalRequirement.AUTOMATIC:
        # The matrix is content. Blast radius may still have gated it, and
        # that verdict stands.
        return status, reason

    if status == ActionStatus.AWAITING_APPROVAL:
        # Already gated. Keep the matrix's reason, which names confidence and
        # impact — more use to the approver than "blast radius exceeded".
        return status, decision.reason

    logger.info(
        "Action requires approval (confidence x impact)",
        action_type=request.action_type.value,
        blast_radius=blast_radius,
        impact=decision.impact.value,
        confidence=decision.confidence,
        tier=decision.tier,
        reason=decision.reason,
    )
    return ActionStatus.AWAITING_APPROVAL, decision.reason
