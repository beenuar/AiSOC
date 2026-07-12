"""Phase 9 — autonomy-safety policy + rollback-capability contract + scorecard.

Proves the three holes the reality audit flagged are closed at the policy level:
dry-run is the SAFE DEFAULT (never a silent real execution), the rollback claim
is honest and bounded (no silent `return True`), and every unattended
containment mandates post-action verification (with the gap counted, not hidden).
"""

from __future__ import annotations

from uuid import uuid4

from app.models.action import ActionRequest, ActionType, BlastRadius
from app.services.autonomy_safety import (
    REVERSIBLE_ACTIONS,
    AutonomyDecision,
    AutonomyMode,
    AutonomyScorecard,
    RollbackCapability,
    VerificationOutcome,
    decide,
    rollback_capability,
)
from app.services.maturity import MaturityTier


def _req(action_type: ActionType) -> ActionRequest:
    return ActionRequest(incident_id=uuid4(), tenant_id=uuid4(), action_type=action_type, target="host-1")


# ── Dry-run is the safe default ──────────────────────────────────────────────


def test_over_tier_blast_defaults_to_dry_run_not_execution():
    # BLOCK_IP is MEDIUM; L2 permits only MINIMAL/LOW → must NOT auto-execute.
    d = decide(_req(ActionType.BLOCK_IP), tier=MaturityTier.L2_CONTAIN, dry_run_default=True)
    assert d.mode is AutonomyMode.DRY_RUN
    assert d.will_execute_for_real is False


def test_dry_run_disabled_queues_for_approval_instead():
    d = decide(_req(ActionType.BLOCK_IP), tier=MaturityTier.L2_CONTAIN, dry_run_default=False)
    assert d.mode is AutonomyMode.QUEUED_APPROVAL


def test_l0_blocks_everything():
    d = decide(_req(ActionType.NOTIFY_SLACK), tier=MaturityTier.L0_OBSERVE)
    assert d.mode is AutonomyMode.BLOCKED


# ── Tiered auto-execution ────────────────────────────────────────────────────


def test_minimal_auto_executes_at_l1_without_verification():
    d = decide(_req(ActionType.NOTIFY_SLACK), tier=MaturityTier.L1_NOTIFY)
    assert d.mode is AutonomyMode.AUTO
    assert d.requires_verification is False  # MINIMAL < MEDIUM


def test_medium_auto_executes_at_l3_and_requires_verification():
    d = decide(_req(ActionType.BLOCK_IP), tier=MaturityTier.L3_REMEDIATE)
    assert d.mode is AutonomyMode.AUTO
    assert d.requires_verification is True  # any executed containment must be verified


def test_medium_approval_required_action_queues_even_when_tier_permits():
    # RESET_PASSWORD is MEDIUM + approval-required.
    d = decide(_req(ActionType.RESET_PASSWORD), tier=MaturityTier.L3_REMEDIATE)
    assert d.mode is AutonomyMode.QUEUED_APPROVAL


# ── HIGH blast: L4 + whitelist + break-glass ─────────────────────────────────


def test_high_queues_without_break_glass():
    d = decide(_req(ActionType.ISOLATE_HOST), tier=MaturityTier.L4_AUTOMATE, whitelisted=True, high_blast_auto=False)
    assert d.mode is AutonomyMode.QUEUED_APPROVAL
    assert "AISOC_ALLOW_HIGH_BLAST_AUTO off" in d.reason


def test_high_queues_without_whitelist():
    d = decide(_req(ActionType.ISOLATE_HOST), tier=MaturityTier.L4_AUTOMATE, whitelisted=False, high_blast_auto=True)
    assert d.mode is AutonomyMode.QUEUED_APPROVAL
    assert "not whitelisted" in d.reason


def test_high_auto_only_at_l4_whitelisted_with_break_glass():
    d = decide(_req(ActionType.ISOLATE_HOST), tier=MaturityTier.L4_AUTOMATE, whitelisted=True, high_blast_auto=True)
    assert d.mode is AutonomyMode.AUTO
    assert d.requires_verification is True


def test_high_never_auto_below_l4():
    d = decide(_req(ActionType.ISOLATE_HOST), tier=MaturityTier.L3_REMEDIATE, whitelisted=True, high_blast_auto=True)
    assert d.mode is not AutonomyMode.AUTO


def test_critical_never_auto_executes(monkeypatch):
    from app.models import action as action_model

    monkeypatch.setitem(action_model.ACTION_BLAST_RADIUS, ActionType.BLOCK_IP, BlastRadius.CRITICAL)
    d = decide(_req(ActionType.BLOCK_IP), tier=MaturityTier.L4_AUTOMATE, whitelisted=True, high_blast_auto=True)
    assert d.mode is AutonomyMode.QUEUED_APPROVAL
    assert "CRITICAL" in d.reason


# ── Rollback-capability contract (honest, bounded, pinned) ───────────────────


def test_only_block_ip_is_reversible_today():
    assert rollback_capability(ActionType.BLOCK_IP) is RollbackCapability.REVERSIBLE
    for at in (ActionType.ISOLATE_HOST, ActionType.DISABLE_USER, ActionType.RESET_PASSWORD, ActionType.BLOCK_DOMAIN):
        assert rollback_capability(at) is RollbackCapability.UNSUPPORTED


def test_reversible_set_is_pinned():
    # Widening this set requires a conscious edit AND a real reverse impl — it
    # can't grow silently and re-introduce the "rollback returns True" lie.
    assert REVERSIBLE_ACTIONS == frozenset({ActionType.BLOCK_IP})


def test_decision_carries_rollback_capability():
    d = decide(_req(ActionType.ISOLATE_HOST), tier=MaturityTier.L2_CONTAIN)
    assert d.rollback is RollbackCapability.UNSUPPORTED


# ── Scorecard makes the safety posture observable ────────────────────────────


def test_scorecard_counts_unverified_executions_as_a_gap():
    card = AutonomyScorecard()
    auto = decide(_req(ActionType.BLOCK_IP), tier=MaturityTier.L3_REMEDIATE)
    dry = decide(_req(ActionType.ISOLATE_HOST), tier=MaturityTier.L2_CONTAIN)  # DRY_RUN
    card.record(auto)  # executed, no verification supplied → gap
    card.record(dry)  # not executed
    card.record(auto, verification=VerificationOutcome.VERIFIED)  # executed + verified
    s = card.summary()
    assert s["total"] == 3
    assert s["executed"] == 2
    assert s["executed_unverified"] == 1
    assert s["executed_verified"] == 1
    assert s["verified_rate"] == 0.5


def test_scorecard_tracks_irreversible_executions():
    card = AutonomyScorecard()
    # An AUTO execution of an UNSUPPORTED-rollback action is the risky case.
    d = AutonomyDecision(
        mode=AutonomyMode.AUTO,
        blast_radius=BlastRadius.MEDIUM,
        tier=MaturityTier.L4_AUTOMATE,
        rollback=RollbackCapability.UNSUPPORTED,
        requires_verification=True,
        reason="test",
    )
    card.record(d)
    assert card.summary()["irreversible_executed"] == 1
