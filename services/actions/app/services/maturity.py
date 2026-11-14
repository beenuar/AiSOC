"""
L0–L4 Auto-remediation maturity tier gate.

Each tenant has a maturity_tier (0–4) that controls which actions are allowed
to execute automatically versus requiring human approval.

  L0 — Observe:    All actions routed to approval queue.
  L1 — Notify:     MINIMAL blast-radius actions are automatic.
  L2 — Contain:    LOW blast-radius actions are automatic.
  L3 — Remediate:  MEDIUM blast-radius actions are automatic.
  L4 — Automate:   HIGH blast-radius actions are automatic (with whitelist check).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any

from app.models.action import ACTION_BLAST_RADIUS, ActionRequest, BlastRadius


class MaturityTier(IntEnum):
    L0_OBSERVE = 0
    L1_NOTIFY = 1
    L2_CONTAIN = 2
    L3_REMEDIATE = 3
    L4_AUTOMATE = 4

    @property
    def label(self) -> str:
        return {
            0: "L0-Observe",
            1: "L1-Notify",
            2: "L2-Contain",
            3: "L3-Remediate",
            4: "L4-Automate",
        }[int(self)]


# Which blast-radius levels are allowed to auto-execute at each tier.
_AUTO_ALLOWED_AT_TIER: dict[MaturityTier, set[BlastRadius]] = {
    MaturityTier.L0_OBSERVE: set(),
    MaturityTier.L1_NOTIFY: {BlastRadius.MINIMAL},
    MaturityTier.L2_CONTAIN: {BlastRadius.MINIMAL, BlastRadius.LOW},
    MaturityTier.L3_REMEDIATE: {BlastRadius.MINIMAL, BlastRadius.LOW, BlastRadius.MEDIUM},
    MaturityTier.L4_AUTOMATE: {
        BlastRadius.MINIMAL,
        BlastRadius.LOW,
        BlastRadius.MEDIUM,
        BlastRadius.HIGH,
    },
}


@dataclass
class GateDecision:
    """Result of a maturity gate evaluation."""

    action_id: str
    action_type: str
    blast_radius: str
    maturity_tier: int
    decision: str  # 'auto' | 'queued_approval' | 'blocked'
    rationale: str = ""
    overrides_applied: list[str] = field(default_factory=list)


@dataclass
class TenantMaturityConfig:
    """Maturity configuration for a single tenant."""

    tenant_id: str
    maturity_tier: int = 0
    action_overrides: dict[str, Any] = field(default_factory=dict)
    whitelist: list[dict[str, Any]] = field(default_factory=list)

    def tier(self) -> MaturityTier:
        return MaturityTier(self.maturity_tier)


def evaluate_gate(request: ActionRequest, config: TenantMaturityConfig) -> GateDecision:
    """
    Evaluate whether *request* may auto-execute given *config*.

    Returns a :class:`GateDecision` with decision 'auto', 'queued_approval',
    or 'blocked'.
    """
    blast = ACTION_BLAST_RADIUS.get(request.action_type, BlastRadius.HIGH)
    tier = config.tier()
    overrides_applied: list[str] = []

    # ------------------------------------------------------------------
    # 1. Check per-action-type override in tenant config
    # ------------------------------------------------------------------
    action_key = request.action_type.value if hasattr(request.action_type, "value") else str(request.action_type)
    override = config.action_overrides.get(action_key, {})

    if override.get("block"):
        return GateDecision(
            action_id=str(request.id),
            action_type=action_key,
            blast_radius=blast.value,
            maturity_tier=int(tier),
            decision="blocked",
            rationale=f"Action type '{action_key}' is blocked by tenant override.",
            overrides_applied=["block_override"],
        )

    if override.get("force_auto"):
        overrides_applied.append("force_auto_override")
        return GateDecision(
            action_id=str(request.id),
            action_type=action_key,
            blast_radius=blast.value,
            maturity_tier=int(tier),
            decision="auto",
            rationale=f"Action type '{action_key}' is force-auto by tenant override.",
            overrides_applied=overrides_applied,
        )

    # ------------------------------------------------------------------
    # 2. Check whitelist (only relevant at L4 for HIGH blast-radius)
    # ------------------------------------------------------------------
    if blast == BlastRadius.HIGH and tier == MaturityTier.L4_AUTOMATE:
        whitelist_match = _check_whitelist(request, config.whitelist)
        if whitelist_match is None:
            return GateDecision(
                action_id=str(request.id),
                action_type=action_key,
                blast_radius=blast.value,
                maturity_tier=int(tier),
                decision="queued_approval",
                rationale=(
                    f"HIGH blast-radius action at L4 requires whitelist entry. No matching whitelist entry found for '{action_key}'."
                ),
            )
        overrides_applied.append(f"whitelist:{whitelist_match}")

    # ------------------------------------------------------------------
    # 3. Standard tier gate
    # ------------------------------------------------------------------
    allowed_radii = _AUTO_ALLOWED_AT_TIER.get(tier, set())
    if blast in allowed_radii:
        return GateDecision(
            action_id=str(request.id),
            action_type=action_key,
            blast_radius=blast.value,
            maturity_tier=int(tier),
            decision="auto",
            rationale=f"Tier {tier.label}: '{blast.value}' blast-radius auto-execution permitted.",
            overrides_applied=overrides_applied,
        )

    return GateDecision(
        action_id=str(request.id),
        action_type=action_key,
        blast_radius=blast.value,
        maturity_tier=int(tier),
        decision="queued_approval",
        rationale=(f"Tier {tier.label}: '{blast.value}' blast-radius requires human approval."),
        overrides_applied=overrides_applied,
    )


def _check_whitelist(request: ActionRequest, whitelist: list[dict[str, Any]]) -> str | None:
    """
    Return the whitelist entry id/key if the action matches a whitelist entry,
    or None if no match.
    """
    action_key = request.action_type.value if hasattr(request.action_type, "value") else str(request.action_type)
    for entry in whitelist:
        if entry.get("action_type") != action_key:
            continue
        constraints: dict[str, Any] = entry.get("constraints", {})
        # Simple prefix constraint check on request.target
        if target_prefix := constraints.get("target_prefix"):
            if not request.target.startswith(target_prefix):
                continue
        return entry.get("id", "whitelist_entry")
    return None
