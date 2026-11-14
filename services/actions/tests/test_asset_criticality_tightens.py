"""The asset modifier tightens approval and can never loosen it.

`evaluate_contract` grades a verb at one impact rank higher when the target
asset's criticality is critical/high. Four properties, each its own test
class, and the **positive control is the point**: a fail-closed safety
control that is stuck closed reads as working caution, so the control that
matters most asserts an *unknown* criticality keeps every verb exactly as it
was — a deployment with no CMDB must lose nothing.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest
from app.live_actions.approval_rules import ApprovalRequirement, evaluate_contract
from app.live_actions.contract import ActionImpact


@dataclass(frozen=True)
class _Contract:
    impact: ActionImpact
    approval: ApprovalRequirement


def _grade(impact: ActionImpact, *, criticality: str | None, confidence: float = 0.99, tier: str = "L4"):
    return evaluate_contract(
        contract=_Contract(impact=impact, approval=ApprovalRequirement.AUTOMATIC),
        confidence=confidence,
        tier=tier,
        asset_criticality=criticality,
    )


class TestPositiveControl:
    """Unknown keeps the verb — the control that catches stuck-closed."""

    @pytest.mark.parametrize("criticality", [None, "", "medium", "low", "none", "weird-value"])
    @pytest.mark.parametrize("impact", list(ActionImpact))
    def test_non_tightening_criticality_grades_identically(self, impact: ActionImpact, criticality: str | None) -> None:
        with_ctx = _grade(impact, criticality=criticality)
        without = _grade(impact, criticality=None)
        assert with_ctx.requirement == without.requirement
        assert with_ctx.impact == without.impact


class TestTighten:
    def test_a_critical_asset_raises_one_rank(self) -> None:
        plain = _grade(ActionImpact.MODERATE, criticality=None)
        tightened = _grade(ActionImpact.MODERATE, criticality="critical")
        assert tightened.impact == ActionImpact.HIGH
        assert plain.impact == ActionImpact.MODERATE
        assert "asset's criticality is critical" in tightened.reason

    def test_high_impact_on_a_critical_asset_grades_severe(self) -> None:
        # SEVERE is in NEVER_AUTONOMOUS territory for autonomy purposes:
        # the raise must move the requirement in the restrictive direction.
        plain = _grade(ActionImpact.HIGH, criticality="critical")
        assert plain.impact == ActionImpact.SEVERE

    @pytest.mark.parametrize("criticality", ["critical", "high", "CRITICAL", " High "])
    def test_both_tiers_and_any_casing_tighten(self, criticality: str) -> None:
        assert _grade(ActionImpact.LOW, criticality=criticality).impact == ActionImpact.MODERATE


class TestDeliberateNonRaises:
    def test_read_only_is_never_raised(self) -> None:
        """A read against a domain controller is still a read. Queueing pure
        reads is the regression the doors-agree work exists to prevent."""
        graded = _grade(ActionImpact.READ_ONLY, criticality="critical")
        assert graded.impact == ActionImpact.READ_ONLY
        assert graded.requirement == _grade(ActionImpact.READ_ONLY, criticality=None).requirement

    def test_severe_is_not_raised_to_irreversible(self) -> None:
        """Irreversibility is a factual property of the verb: context can
        demand a human, it cannot make an undoable action undoable — and
        PROHIBITED would forbid rather than tighten."""
        graded = _grade(ActionImpact.SEVERE, criticality="critical")
        assert graded.impact == ActionImpact.SEVERE
        assert graded.requirement != ApprovalRequirement.PROHIBITED


class TestTightenOnlyInvariant:
    """Sweep: with context, the requirement is never less restrictive."""

    _ORDER = {
        ApprovalRequirement.AUTOMATIC: 0,
        ApprovalRequirement.ANALYST: 1,
        ApprovalRequirement.MANDATORY_HUMAN: 2,
        ApprovalRequirement.PROHIBITED: 3,
    }

    @pytest.mark.parametrize("impact", list(ActionImpact))
    @pytest.mark.parametrize("criticality", ["critical", "high", "medium", "low", None])
    @pytest.mark.parametrize("confidence", [0.2, 0.8, 0.99])
    @pytest.mark.parametrize("tier", ["L0", "L2", "L4"])
    def test_never_less_restrictive(self, impact: ActionImpact, criticality: str | None, confidence: float, tier: str) -> None:
        base = evaluate_contract(
            contract=_Contract(impact=impact, approval=ApprovalRequirement.AUTOMATIC),
            confidence=confidence,
            tier=tier,
        )
        with_ctx = evaluate_contract(
            contract=_Contract(impact=impact, approval=ApprovalRequirement.AUTOMATIC),
            confidence=confidence,
            tier=tier,
            asset_criticality=criticality,
        )
        assert self._ORDER[with_ctx.requirement] >= self._ORDER[base.requirement]
