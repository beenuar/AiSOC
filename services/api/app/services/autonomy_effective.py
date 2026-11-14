"""What the console may truthfully say about autonomy.

The autonomy settings page used to answer "does this action auto-execute"
from the per-action confidence thresholds it edits: an ``auto`` threshold
below 1.0 meant some confidence level let the agent act, so the action
auto-executed. Nineteen of nineteen shipped defaults are below 1.0 and seven
of them are high- or critical-blast, so a stock install opened on
**"Autopilot — 7 high-blast actions auto-execute"**.

Nothing about that was true, and the reason is worth stating precisely
because the shape recurs.

*The table the page edits has no production reader.* ``aisoc_autonomy_thresholds``
is read by ``services/agents/app/policy/guardrails.py``, which no production
path imports — ``services/agents/app/closure/policy.py`` says so in its own
words. A threshold written here changes nothing today.

*The control that does gate execution is somewhere else entirely.* A response
verb reaches a vendor through ``services/actions``, which grades it on the
tenant's L0–L4 maturity tier and the verb's own capability contract. The
deployment default is L1, which auto-executes nothing above a read, and every
containment verb's contract declares ``analyst`` — so the dispatcher queues
every one of those seven for a human.

So this module answers the question from the control that actually decides.
``evaluate_contract`` here is the same function the dispatcher calls; it
reaches it through ``app/_vendor/action_contracts/``, a byte-identical mirror
kept in step by ``scripts/sync_vendored_action_contracts.py --check``. A
second implementation would drift, and the drift is the defect.

Two deliberate choices about how the question is asked:

**Confidence is pinned at 1.0.** The console is not grading a finding; it is
describing a posture. Asking at the most permissive confidence any decision
could carry makes a "no" the strongest available statement: not "this did not
clear the bar today" but "nothing clears the bar".

**Two answers, not one.** ``auto_executes`` is the answer at the ceiling this
tenant currently has. ``auto_executes_at_any_tier`` asks the same question at
L4, the top of the ladder. The second is what makes the copilot claim
defensible, because it is immune to a tier change, a ``force_auto`` override
and an earned grant alike: a contract floor may be raised and never lowered.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any

import structlog
from sqlalchemy import text

from app._vendor.action_contracts import (
    CAPABILITY_CONTRACTS,
    TIER_LABELS,
    TIER_MAX_AUTOMATIC,
    TIER_ORDER,
    evaluate_contract,
)
from app._vendor.action_contracts.approval_rules import (
    DEFAULT_TIER,
    EARNED_TIER_CEILING_LABEL,
    tier_from_env_value,
)

logger = structlog.get_logger(__name__)

#: Same variable ``services/actions`` reads. See :func:`resolve_effective_tier`
#: for what it can and cannot tell us.
TIER_ENV = "AISOC_MATURITY_TIER"

#: Tier used when a policy row exists and cannot be read. Mirrors
#: ``tenant_policy.UNREADABLE_POLICY_FLOOR``: if a per-tenant policy may exist
#: and we cannot read it, inheriting a possibly-more-permissive default is how
#: a page comes to claim autonomy nobody authorised.
UNREADABLE_POLICY_FLOOR = DEFAULT_TIER

#: Where the tier came from, in the vocabulary ``TenantPolicy.source`` uses.
SOURCE_TENANT_POLICY = "tenant_policy"
SOURCE_ENVIRONMENT = "environment"
SOURCE_UNREADABLE = "unreadable_policy_floor"


@dataclass(frozen=True)
class EffectiveTier:
    """The autonomy ceiling in force, and where it came from."""

    tier: str
    label: str
    source: str
    #: Highest impact this tier executes without an analyst. ``None`` at L0,
    #: which executes nothing at all — not even a read.
    max_automatic_impact: str | None
    action_overrides: dict[str, Any] = field(default_factory=dict)
    #: Verbs holding a standing ``auto_execute`` grant. These lift the ceiling
    #: to L3 for that verb alone.
    earned_verbs: frozenset[str] = frozenset()


@dataclass(frozen=True)
class ActionAutonomy:
    """Whether one named action can reach a vendor without a human."""

    #: The capability it resolves to in the action registry, or ``None`` when
    #: no executor is registered under this name.
    capability: str | None
    executable: bool
    auto_executes: bool
    auto_executes_at_any_tier: bool
    #: The ceiling applied to this action specifically, which an override or
    #: an earned grant can raise above the tenant's own tier.
    tier: str
    reason: str


def _tier_rank(tier: str) -> int:
    return TIER_ORDER.index(tier) if tier in TIER_ORDER else 0


def _as_dict(value: Any) -> dict[str, Any]:
    """JSONB arrives as a dict on asyncpg and as a string on some drivers."""
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return {}
    return value if isinstance(value, dict) else {}


def _effective(tier: str, source: str, **rest: Any) -> EffectiveTier:
    ceiling = TIER_MAX_AUTOMATIC.get(tier)
    return EffectiveTier(
        tier=tier,
        label=TIER_LABELS.get(tier, tier),
        source=source,
        max_automatic_impact=ceiling.value if ceiling is not None else None,
        **rest,
    )


def tier_from_environment() -> EffectiveTier:
    """The deployment-wide tier, parsed the way the dispatcher parses it.

    One caveat is worth being plain about on the page as well as here: this
    reads *this process's* environment. ``AISOC_MATURITY_TIER`` is set per
    container, so an operator who exports it for the actions service alone
    would see the default here. No compose file, Helm value or Terraform
    default in this repository sets it, so the two agree out of the box — and
    a tenant that has chosen a tier in the console has a row, which is read
    first and is not subject to this at all.
    """
    raw = os.environ.get(TIER_ENV, "")
    tier, recognised = tier_from_env_value(raw)
    if not recognised:
        logger.warning("autonomy_effective.bad_tier_env", value=raw.strip().upper())
    return _effective(tier, SOURCE_ENVIRONMENT)


async def _earned_verbs(db: Any, tenant_id: str) -> frozenset[str]:
    """Verbs this tenant has earned the right to run unattended.

    Read without re-checking the evidence behind each grant, which
    ``tenant_policy._load_earned_verbs`` does before the dispatcher honours
    one. That makes this *more* generous than the dispatcher, which is the
    correct direction for a display: a page that omits a grant would tell an
    operator a human signs off on something that in fact runs by itself.
    """
    try:
        rows = (
            (
                await db.execute(
                    text(
                        """
                        SELECT scope_key
                        FROM aisoc_autonomy_grants
                        WHERE tenant_id = :tenant_id
                          AND state = 'granted'
                          AND scope_kind = 'action_verb'
                          AND capability = 'auto_execute'
                        """
                    ),
                    {"tenant_id": str(tenant_id)},
                )
            )
            .mappings()
            .all()
        )
    except Exception as exc:  # noqa: BLE001 — an unreadable grant list is not a tier failure
        logger.warning("autonomy_effective.grants_unreadable", tenant_id=str(tenant_id), error=str(exc)[:300])
        return frozenset()
    return frozenset(str(row["scope_key"]) for row in rows)


async def resolve_effective_tier(db: Any, tenant_id: str) -> EffectiveTier:
    """Resolve the autonomy ceiling in the same order ``services/actions`` does.

    Tenant policy row, then the deployment environment, then a conservative
    floor when a row may exist and cannot be read. Written against the same
    table ``tenant_policy._load_from_store`` reads — ``remediation_maturity``,
    which this service owns the write path for behind
    ``PUT /api/v1/remediation/config`` — so the console is reading the row the
    dispatcher will act on rather than a copy of it.
    """
    try:
        row = (
            (
                await db.execute(
                    text("SELECT maturity_tier, action_overrides FROM remediation_maturity WHERE tenant_id = :tenant_id"),
                    {"tenant_id": str(tenant_id)},
                )
            )
            .mappings()
            .first()
        )
    except Exception as exc:  # noqa: BLE001 — never inherit a permissive default on error
        logger.warning("autonomy_effective.policy_unreadable", tenant_id=str(tenant_id), error=str(exc)[:300])
        return _effective(UNREADABLE_POLICY_FLOOR, SOURCE_UNREADABLE)

    earned = await _earned_verbs(db, tenant_id)

    if row is None:
        base = tier_from_environment()
        return _effective(base.tier, base.source, earned_verbs=earned)

    level = row["maturity_tier"]
    if not isinstance(level, int) or not 0 <= level < len(TIER_ORDER):
        # A tier outside the ladder is a corrupt row, not a posture. The
        # dispatcher raises here and lands on its own floor; so do we.
        logger.warning("autonomy_effective.tier_out_of_range", tenant_id=str(tenant_id), value=str(level)[:40])
        return _effective(UNREADABLE_POLICY_FLOOR, SOURCE_UNREADABLE, earned_verbs=earned)

    return _effective(
        TIER_ORDER[level],
        SOURCE_TENANT_POLICY,
        action_overrides=_as_dict(row["action_overrides"]),
        earned_verbs=earned,
    )


#: Said once rather than per action, because fifteen of the nineteen shipped
#: threshold rows land on it and a reader should recognise the same sentence.
NO_EXECUTOR_REASON = "No response capability is registered under this name, so no dispatch path runs it. These thresholds are advisory."


def grade_action(action: str, effective: EffectiveTier) -> ActionAutonomy:
    """Would *action* reach a vendor without a human, on this deployment?

    The answer comes from ``evaluate_contract`` — the function both dispatch
    doors call — so the page cannot disagree with the product without the
    byte-comparison gate failing first.
    """
    contract = CAPABILITY_CONTRACTS.get(action)
    if contract is None:
        return ActionAutonomy(
            capability=None,
            executable=False,
            auto_executes=False,
            auto_executes_at_any_tier=False,
            tier=effective.tier,
            reason=NO_EXECUTOR_REASON,
        )

    override = _as_dict(effective.action_overrides.get(action))
    if override.get("block"):
        return ActionAutonomy(
            capability=action,
            executable=True,
            auto_executes=False,
            auto_executes_at_any_tier=False,
            tier=effective.tier,
            reason="Blocked by a tenant policy override. No tier or confidence executes it.",
        )

    # An override is a human writing down a decision about one verb, so it
    # lifts the ceiling to the top of the ladder; an earned grant is an
    # inference from triage agreement and stops at L3. Both raise the ceiling
    # only — the contract's own floor still applies underneath.
    tier = effective.tier
    if override.get("force_auto"):
        tier = TIER_ORDER[-1]
    elif action in effective.earned_verbs and _tier_rank(tier) < _tier_rank(EARNED_TIER_CEILING_LABEL):
        tier = EARNED_TIER_CEILING_LABEL

    now = evaluate_contract(contract=contract, confidence=1.0, tier=tier)
    ever = evaluate_contract(contract=contract, confidence=1.0, tier=TIER_ORDER[-1])

    return ActionAutonomy(
        capability=action,
        executable=True,
        auto_executes=now.can_auto_execute,
        auto_executes_at_any_tier=ever.can_auto_execute,
        tier=tier,
        reason=now.reason,
    )
