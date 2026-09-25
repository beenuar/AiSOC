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
from app.live_actions import capability_contracts
from app.live_actions.capability_contracts import CAPABILITY_CONTRACTS, contract_for_action_type
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
    async def test_a_read_needs_no_confidence_at_any_acting_tier(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("AISOC_MATURITY_TIER", "L2")
        after, _ = await _gated(_request(ActionType.SEARCH_SIEM, confidence=0.0))

        assert after == ActionStatus.APPROVED

    @pytest.mark.asyncio
    async def test_the_default_tier_reads_without_asking_and_acts_only_with_permission(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """L1 is notify-only, and a query is not an act.

        This replaces a test that asserted ``search_siem`` reached the
        approval queue here. It did, and that was the bug: ``search_siem``
        declares ``read_only`` impact and ``automatic`` approval, and the
        contract gate's own rule is that a read requiring approval "is either
        mis-classified or is not actually a read". The registry door executed
        it at the same tier, so one verb had two grades.

        The notify-only posture is asserted in the same test rather than
        deleted with the defect, because that posture is real: a
        state-changing verb must still queue here.
        """
        monkeypatch.delenv("AISOC_MATURITY_TIER", raising=False)

        read, _ = await _gated(_request(ActionType.SEARCH_SIEM, confidence=1.0))
        assert read == ActionStatus.APPROVED

        act, reason = await _gated(_request(ActionType.CREATE_TICKET, confidence=1.0))
        assert act == ActionStatus.AWAITING_APPROVAL
        assert "L1" in reason


class TestTheAliasedVerbIsGatedToo:
    """``notify_slack`` was the last ActionType the matrix never saw.

    It was never a missing capability — the verb is ``notify``, it has had a
    contract throughout, and ``SlackNotify`` bridges the two names. What was
    missing was anything telling a lookup *by ActionType value* about that
    bridge, so ``apply_matrix`` found nothing, returned the blast-radius
    verdict unchanged, and the one verb most likely to auto-execute was the
    one verb graded without reference to confidence.
    """

    def test_the_two_names_are_not_the_same_string(self):
        """The premise. If these ever converge the alias becomes dead code,
        and the contract gate says so rather than leaving it to rot."""
        assert ActionType.NOTIFY_SLACK.value == "notify_slack"
        assert ActionType.NOTIFY_SLACK.value not in CAPABILITY_CONTRACTS
        assert "notify" in CAPABILITY_CONTRACTS

    def test_the_alias_resolves_to_the_notify_contract(self):
        assert contract_for_action_type(ActionType.NOTIFY_SLACK.value) is CAPABILITY_CONTRACTS["notify"]

    @pytest.mark.asyncio
    async def test_a_low_confidence_notify_no_longer_auto_executes(self):
        """Fails against the pre-change tree, which approved this outright.

        ``notify_slack`` is MINIMAL blast radius, so ``BlastRadiusGate``
        approves it on its own. With the contract now reachable the matrix
        gets a say, and at 10% confidence under the default L1 tier it
        demands an analyst.
        """
        request = _request(ActionType.NOTIFY_SLACK, confidence=0.1)
        before, br, before_reason = BlastRadiusGate().evaluate(request)
        after, reason = await apply_matrix(request, before, br, before_reason)

        assert before == ActionStatus.APPROVED
        assert after == ActionStatus.AWAITING_APPROVAL
        assert reason != before_reason

    @pytest.mark.asyncio
    async def test_the_alias_cannot_lower_a_requirement(self):
        """An alias route into the matrix must obey the same composition rule
        as a direct one: each input can raise a requirement, none can lower
        it. A LOW-impact contract must not talk a blocked action into running.
        """
        request = _request(ActionType.NOTIFY_SLACK, confidence=1.0)
        after, _ = await apply_matrix(request, ActionStatus.AWAITING_APPROVAL, BlastRadius.MINIMAL, "held by policy")

        assert after == ActionStatus.AWAITING_APPROVAL


class TestVerbsWithNoContract:
    @pytest.mark.asyncio
    async def test_an_unmapped_verb_is_still_left_to_blast_radius(self, monkeypatch: pytest.MonkeyPatch):
        """Every ActionType resolves a contract today and a gate keeps it that
        way, so this path is no longer reachable through the enum. It stays
        tested because the fallback is what stops the gate inventing an impact
        for a verb nobody declared — a gate that certifies what it never
        examined is the failure this whole module exists to avoid.

        Pulling the alias out is the smallest way to reach the branch.
        """
        monkeypatch.setattr(capability_contracts, "ACTION_TYPE_CAPABILITY_ALIASES", {})

        request = _request(ActionType.NOTIFY_SLACK, confidence=0.1)
        before, br, before_reason = BlastRadiusGate().evaluate(request)
        after, reason = await apply_matrix(request, before, br, before_reason)

        assert after == before
        assert reason == before_reason

    def test_no_action_type_is_left_unmapped(self):
        """The property the contract gate enforces, asserted here too so it
        fails in the service's own suite and not only in a CI script."""
        unmapped = [a.value for a in ActionType if contract_for_action_type(a.value) is None]
        assert unmapped == [], f"ActionType members with no reachable capability contract: {unmapped}"


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
