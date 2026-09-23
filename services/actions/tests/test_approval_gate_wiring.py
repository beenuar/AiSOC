"""The documented gate has to be the gate that runs.

``approval_matrix.evaluate`` implements approval as confidence x impact under
the tenant's autonomy tier. It was written, documented, unit-tested and listed
in the claim-to-gate matrix as GATED — and a repository-wide search for
``approval_matrix`` found only the module, its own test, the contract checker
and two doc mentions. **Zero production callers.** ``POST /actions`` gated on
blast radius alone, which is a property of the verb, so the same answer came
back for a 40%-confidence guess and a corroborated finding.

A passing unit test on an uncalled function is indistinguishable from a
working control. These tests are about the wiring, not the matrix.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from app.live_actions.capability_contracts import CAPABILITY_CONTRACTS
from app.models.action import ActionRequest, ActionStatus, ActionType, BlastRadius
from app.services.approval_gate import apply_matrix
from app.services.blast_radius import BlastRadiusGate


def _request(action_type: ActionType, confidence: float | None = None) -> ActionRequest:
    return ActionRequest(
        incident_id=uuid4(),
        tenant_id=uuid4(),
        action_type=action_type,
        target="WKSTN-01",
        confidence=confidence,
    )


async def _gated(request: ActionRequest) -> tuple[ActionStatus, str]:
    status, blast_radius, reason = BlastRadiusGate().evaluate(request)
    return await apply_matrix(request, status, blast_radius, reason)


class TestTheMatrixActuallyRuns:
    @pytest.mark.asyncio
    async def test_a_low_confidence_action_is_gated_that_blast_radius_alone_approved(self, monkeypatch: pytest.MonkeyPatch):
        """create_ticket is MINIMAL blast radius and its contract is
        AUTOMATIC, so nothing but confidence can gate it. Its declared impact
        is LOW, whose floor is 90%. At 40% the old gate approved it and the
        matrix does not."""
        monkeypatch.setenv("AISOC_MATURITY_TIER", "L4")
        request = _request(ActionType.CREATE_TICKET, confidence=0.40)

        before, _, _ = BlastRadiusGate().evaluate(request)
        after, reason = await _gated(request)

        assert before == ActionStatus.APPROVED
        assert after == ActionStatus.AWAITING_APPROVAL
        assert "40%" in reason

    @pytest.mark.asyncio
    async def test_missing_confidence_is_the_lowest_band_not_a_free_pass(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("AISOC_MATURITY_TIER", "L4")
        after, reason = await _gated(_request(ActionType.CREATE_TICKET))

        assert after == ActionStatus.AWAITING_APPROVAL
        assert "0%" in reason

    @pytest.mark.asyncio
    async def test_the_reason_names_confidence_and_impact(self, monkeypatch: pytest.MonkeyPatch):
        """'requires approval' with no reason is the kind of prompt people
        learn to click through."""
        monkeypatch.setenv("AISOC_MATURITY_TIER", "L4")
        _, reason = await _gated(_request(ActionType.CREATE_TICKET, confidence=0.5))

        assert "low" in reason.lower()
        assert "confidence" in reason.lower()

    @pytest.mark.asyncio
    async def test_a_contract_that_demands_an_analyst_is_not_relaxed_by_confidence(self, monkeypatch: pytest.MonkeyPatch):
        """block_ip's blast radius is inside the auto-execute limit, so the
        old gate approved it outright — while its own contract says an
        analyst must sign off. That contract had no reader."""
        monkeypatch.setenv("AISOC_MATURITY_TIER", "L4")
        request = _request(ActionType.BLOCK_IP, confidence=1.0)

        before, _, _ = BlastRadiusGate().evaluate(request)
        after, reason = await _gated(request)

        assert before == ActionStatus.APPROVED
        assert after == ActionStatus.AWAITING_APPROVAL
        assert "contract" in reason.lower()


class TestItCanOnlyTighten:
    @pytest.mark.asyncio
    async def test_an_already_gated_action_stays_gated_at_full_confidence(self):
        """isolate_host is in APPROVAL_REQUIRED_ACTIONS. No confidence and no
        tier may lift that."""
        request = _request(ActionType.ISOLATE_HOST, confidence=1.0)

        after, _ = await _gated(request)

        assert after == ActionStatus.AWAITING_APPROVAL

    @pytest.mark.asyncio
    async def test_the_matrix_never_approves_what_blast_radius_refused(self, monkeypatch: pytest.MonkeyPatch):
        """Composition rule: each input raises, none lowers."""
        request = _request(ActionType.ISOLATE_HOST, confidence=1.0)
        monkeypatch.setenv("AISOC_MATURITY_TIER", "L4")

        after, _ = await _gated(request)

        assert after == ActionStatus.AWAITING_APPROVAL


class TestTheTierIsHonoured:
    @pytest.mark.asyncio
    async def test_a_high_tier_and_high_confidence_can_auto_execute(self, monkeypatch: pytest.MonkeyPatch):
        """Otherwise the gate would be a one-way ratchet that never lets
        anything through, and operators would turn it off."""
        monkeypatch.setenv("AISOC_MATURITY_TIER", "L4")
        request = _request(ActionType.CREATE_TICKET, confidence=1.0)

        after, _ = await _gated(request)

        assert after == ActionStatus.APPROVED

    @pytest.mark.asyncio
    async def test_a_read_runs_at_l2_where_it_did_not_at_l1(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("AISOC_MATURITY_TIER", "L2")
        after, _ = await _gated(_request(ActionType.SEARCH_SIEM, confidence=0.0))

        assert after == ActionStatus.APPROVED

    @pytest.mark.asyncio
    async def test_the_default_tier_executes_nothing(self, monkeypatch: pytest.MonkeyPatch):
        """L1 is notify-only, which is the platform's copilot-default posture.
        This is a real tightening of POST /actions, which was tier-unaware."""
        monkeypatch.delenv("AISOC_MATURITY_TIER", raising=False)
        request = _request(ActionType.SEARCH_SIEM, confidence=1.0)

        after, reason = await _gated(request)

        assert after == ActionStatus.AWAITING_APPROVAL
        assert "L1" in reason


class TestVerbsWithNoContract:
    @pytest.mark.asyncio
    async def test_an_unmapped_verb_is_left_to_blast_radius(self):
        """Seven ActionType members have no capability contract. Inventing an
        impact for them is how a gate starts certifying things it never
        examined, so blast radius decides alone and the gap is logged."""
        assert ActionType.NOTIFY_SLACK.value not in CAPABILITY_CONTRACTS

        request = _request(ActionType.NOTIFY_SLACK, confidence=0.1)
        before, br, before_reason = BlastRadiusGate().evaluate(request)
        after, reason = await apply_matrix(request, before, br, before_reason)

        assert after == before
        assert reason == before_reason


class TestTierLabelMapping:
    @pytest.mark.parametrize(
        ("name", "expected"),
        [("L0_OBSERVE", "L0"), ("L1_NOTIFY", "L1"), ("L4_AUTOMATE", "L4")],
    )
    def test_maturity_tier_names_map_onto_matrix_labels(self, name: str, expected: str):
        from app.services.approval_gate import _tier_label

        class _Tier:
            pass

        tier = _Tier()
        tier.name = name
        assert _tier_label(tier) == expected

    def test_an_unrecognisable_tier_falls_back_conservatively(self):
        from app.services.approval_gate import _tier_label

        assert _tier_label(None) == "L1"
        assert _tier_label("nonsense") == "L1"


class TestConfidenceIsValidated:
    def test_a_confidence_outside_zero_to_one_is_refused_at_the_model(self):
        """Clamping silently would let a caller send 99 and mean 99%."""
        with pytest.raises(ValueError):
            _request(ActionType.BLOCK_IP, confidence=99.0)


def test_the_blast_radius_limit_is_unchanged():
    """This wave adds an axis; it does not move the existing one."""
    from app.services.blast_radius import _AUTO_EXECUTE_LIMIT

    assert _AUTO_EXECUTE_LIMIT == BlastRadius.MEDIUM
