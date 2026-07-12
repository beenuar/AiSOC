"""Autonomy-safety policy + rollback-capability contract (Phase 9).

The reality audit found three holes behind the "L0-L4 automation maturity gates
every action" claim: (1) **dry-run is opt-in**, not the default, so a
mis-configured caller executes for real; (2) **~15 executors' `rollback()`
silently `return True`** without any reverse vendor call — the platform claims
to roll back containment it never reversed; (3) **there is no post-action
verification** that a containment actually took effect.

This module is the decision + contract layer that closes those holes honestly:

* :func:`decide` computes an :class:`AutonomyDecision` from the L0-L4 tier and
  blast radius. **Dry-run is the default**: anything not explicitly permitted to
  auto-execute is previewed (`DRY_RUN`), never silently executed. CRITICAL never
  auto-executes; HIGH only at L4 with a whitelist entry AND the
  ``AISOC_ALLOW_HIGH_BLAST_AUTO`` break-glass flag.
* :func:`rollback_capability` makes the rollback claim **honest and bounded**:
  only actions in :data:`REVERSIBLE_ACTIONS` (today, exactly ``block_ip``) may
  claim `REVERSIBLE`; everything else is `UNSUPPORTED`, so a caller learns "this
  cannot be auto-reversed" instead of a silent `True` lie. The gate pins the set
  so widening it requires a conscious edit (and a real reverse implementation).
* Every executed containment (`AUTO`, blast ≥ MEDIUM) sets
  ``requires_verification`` — post-action verification is mandated, and the
  :class:`AutonomyScorecard` counts executions that were never verified so the
  gap is visible rather than assumed-away.

Wiring these into the live REST router (`api/router.py`) is tracked as 9b; this
lands the policy + contract + gate so the semantics are enforced and honest.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum

from app.models.action import (
    ACTION_BLAST_RADIUS,
    APPROVAL_REQUIRED_ACTIONS,
    ActionRequest,
    ActionType,
    BlastRadius,
)
from app.services.maturity import _AUTO_ALLOWED_AT_TIER, MaturityTier

_BLAST_ORDER = {
    BlastRadius.MINIMAL: 0,
    BlastRadius.LOW: 1,
    BlastRadius.MEDIUM: 2,
    BlastRadius.HIGH: 3,
    BlastRadius.CRITICAL: 4,
}


class AutonomyMode(str, Enum):
    BLOCKED = "blocked"  # not permitted, not even a dry-run (e.g. L0 observe)
    DRY_RUN = "dry_run"  # simulate only — no real effect (the SAFE default)
    QUEUED_APPROVAL = "queued_approval"  # needs a human to execute
    AUTO = "auto"  # permitted to execute unattended


class RollbackCapability(str, Enum):
    REVERSIBLE = "reversible"  # a real reverse vendor call exists
    UNSUPPORTED = "unsupported"  # no automatic rollback — say so, don't fake it


# The ONLY actions with a real reverse implementation today. `block_ip` reverses
# via the AWS security-group `unblock_ip` call. Widening this set requires
# implementing (and testing) a real reverse path — the gate pins it so it can't
# grow silently to re-introduce the "rollback returns True" lie.
REVERSIBLE_ACTIONS: frozenset[ActionType] = frozenset({ActionType.BLOCK_IP})


class VerificationOutcome(str, Enum):
    VERIFIED = "verified"  # re-queried the vendor; the effect is present
    UNVERIFIED = "unverified"  # no verifier ran (the honest default today)
    FAILED = "failed"  # re-queried; the effect is NOT present


@dataclass(frozen=True)
class AutonomyDecision:
    mode: AutonomyMode
    blast_radius: BlastRadius
    tier: MaturityTier
    rollback: RollbackCapability
    requires_verification: bool
    reason: str

    @property
    def will_execute_for_real(self) -> bool:
        return self.mode is AutonomyMode.AUTO


def rollback_capability(action_type: ActionType) -> RollbackCapability:
    return RollbackCapability.REVERSIBLE if action_type in REVERSIBLE_ACTIONS else RollbackCapability.UNSUPPORTED


def default_dry_run() -> bool:
    """Dry-run-by-default unless an operator explicitly opts out."""
    raw = os.environ.get("AISOC_ACTIONS_DEFAULT_DRY_RUN")
    if raw is None:
        return True
    return raw.strip().lower() not in {"0", "false", "no", "off"}


def allow_high_blast_auto() -> bool:
    """Break-glass: permit unattended HIGH-blast auto-execution. Default off."""
    raw = os.environ.get("AISOC_ALLOW_HIGH_BLAST_AUTO")
    if raw is None:
        return False
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def decide(
    request: ActionRequest,
    *,
    tier: MaturityTier,
    dry_run_default: bool | None = None,
    high_blast_auto: bool | None = None,
    whitelisted: bool = False,
) -> AutonomyDecision:
    """Compute the autonomy decision. Dry-run is the safe default."""
    if dry_run_default is None:
        dry_run_default = default_dry_run()
    if high_blast_auto is None:
        high_blast_auto = allow_high_blast_auto()

    blast = ACTION_BLAST_RADIUS.get(request.action_type, BlastRadius.HIGH)
    rb = rollback_capability(request.action_type)

    def _decision(mode: AutonomyMode, reason: str) -> AutonomyDecision:
        requires_verification = mode is AutonomyMode.AUTO and _BLAST_ORDER[blast] >= _BLAST_ORDER[BlastRadius.MEDIUM]
        return AutonomyDecision(
            mode=mode,
            blast_radius=blast,
            tier=tier,
            rollback=rb,
            requires_verification=requires_verification,
            reason=reason,
        )

    # L0 is observe-only: nothing executes, not even a dry-run preview.
    if tier == MaturityTier.L0_OBSERVE:
        return _decision(AutonomyMode.BLOCKED, "tier L0 (observe-only) blocks all execution")

    # CRITICAL blast never auto-executes at any tier.
    if blast == BlastRadius.CRITICAL:
        return _decision(AutonomyMode.QUEUED_APPROVAL, "CRITICAL blast radius always requires human approval")

    allowed = _AUTO_ALLOWED_AT_TIER.get(tier, set())
    if blast in allowed:
        # HIGH is the sensitive top of the ladder: L4 + whitelist + break-glass.
        if blast == BlastRadius.HIGH:
            if tier == MaturityTier.L4_AUTOMATE and whitelisted and high_blast_auto:
                return _decision(AutonomyMode.AUTO, "HIGH auto-executed: L4 + whitelisted + break-glass enabled")
            reasons = []
            if tier != MaturityTier.L4_AUTOMATE:
                reasons.append("not L4")
            if not whitelisted:
                reasons.append("not whitelisted")
            if not high_blast_auto:
                reasons.append("AISOC_ALLOW_HIGH_BLAST_AUTO off")
            return _decision(AutonomyMode.QUEUED_APPROVAL, f"HIGH blast requires approval ({', '.join(reasons)})")
        # Approval-required action types always gate on a human, even if the
        # tier would otherwise permit the blast radius.
        if request.action_type in APPROVAL_REQUIRED_ACTIONS:
            return _decision(AutonomyMode.QUEUED_APPROVAL, "action type always requires human approval")
        return _decision(AutonomyMode.AUTO, f"{blast.value} permitted to auto-execute at tier {tier.name}")

    # Not permitted to auto-execute at this tier → SAFE DEFAULT is a dry-run
    # preview (never a silent real execution), unless dry-run is disabled, in
    # which case it queues for approval.
    if dry_run_default:
        return _decision(AutonomyMode.DRY_RUN, f"{blast.value} above tier {tier.name} allowance → dry-run preview (safe default)")
    return _decision(AutonomyMode.QUEUED_APPROVAL, f"{blast.value} above tier {tier.name} allowance → queued for approval")


@dataclass
class AutonomyScorecard:
    """Aggregates autonomy decisions + outcomes so the safety posture is
    observable: how many executed unattended, how many of those were verified,
    and how many touched irreversible actions."""

    total: int = 0
    by_mode: dict[str, int] = field(default_factory=dict)
    executed: int = 0
    executed_verified: int = 0
    executed_unverified: int = 0
    irreversible_executed: int = 0

    def record(self, decision: AutonomyDecision, *, verification: VerificationOutcome | None = None) -> None:
        self.total += 1
        self.by_mode[decision.mode.value] = self.by_mode.get(decision.mode.value, 0) + 1
        if decision.will_execute_for_real:
            self.executed += 1
            if verification is VerificationOutcome.VERIFIED:
                self.executed_verified += 1
            else:
                # Never verified (or verification failed) → count as a gap.
                self.executed_unverified += 1
            if decision.rollback is RollbackCapability.UNSUPPORTED:
                self.irreversible_executed += 1

    def summary(self) -> dict[str, object]:
        verified_rate = (self.executed_verified / self.executed) if self.executed else 1.0
        return {
            "total": self.total,
            "by_mode": dict(self.by_mode),
            "executed": self.executed,
            "executed_verified": self.executed_verified,
            "executed_unverified": self.executed_unverified,
            "irreversible_executed": self.irreversible_executed,
            "verified_rate": round(verified_rate, 4),
        }
