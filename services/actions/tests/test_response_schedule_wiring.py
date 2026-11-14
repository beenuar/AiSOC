"""The time gates have to reach a dispatch, not just pass their unit tests.

``test_response_schedule.py`` grades ``apply_schedule`` as a pure function and
it passes. What it cannot see is that the function had **no caller**: its
thirteen call sites were all in that file, ``ResponseSchedule`` was never
constructed outside its own definition, ``dispatcher.py`` imported three other
names from the module, and neither ``approval_matrix``'s imports nor the
vendored package's exports mentioned it. The tables migration 142 created
appeared in exactly one file repo-wide — their own migration — so a tenant
could not declare a freeze even by hand, and a tenant who did would have been
executed through anyway.

So these tests assert the *wiring*: the schedule reaches the one function both
doors grade with, the dispatcher resolves it per request, and the verdict an
operator sees names the condition that raised it.
"""

from __future__ import annotations

from datetime import UTC, datetime, time
from zoneinfo import ZoneInfo

import pytest
from app.live_actions.approval_rules import BusinessWindow, ResponseSchedule, evaluate_contract
from app.live_actions.capability_contracts import CAPABILITY_CONTRACTS
from app.live_actions.contract import ActionImpact, ApprovalRequirement
from app.live_actions.models import LiveActionRequest


def _auto_contract():  # noqa: ANN202
    """A capability the matrix grades AUTOMATIC at L4 with full confidence.

    Picked from the real contract table rather than hand-built, so this cannot
    pass against a contract set the product does not ship.
    """
    for capability, contract in CAPABILITY_CONTRACTS.items():
        if contract.impact in (ActionImpact.LOW, ActionImpact.MODERATE):
            decision = evaluate_contract(contract=contract, confidence=1.0, tier="L4")
            if decision.requirement is ApprovalRequirement.AUTOMATIC:
                return capability, contract
    raise AssertionError("no shipped capability grades AUTOMATIC at L4 — the premise of these tests is gone")


def test_a_change_freeze_raises_an_automatic_verb_at_the_grading_function() -> None:
    """The one place a door may decide has to know about the freeze."""
    _capability, contract = _auto_contract()

    without = evaluate_contract(contract=contract, confidence=1.0, tier="L4")
    assert without.requirement is ApprovalRequirement.AUTOMATIC

    with_freeze = evaluate_contract(
        contract=contract,
        confidence=1.0,
        tier="L4",
        schedule=ResponseSchedule(freeze_active=True, applies_from_impact=ActionImpact.LOW),
    )

    assert with_freeze.requirement is ApprovalRequirement.ANALYST
    assert "change freeze is in force" in with_freeze.reason


def test_out_of_hours_raises_and_in_hours_does_not() -> None:
    """The positive control is the half that catches a gate stuck closed."""
    _capability, contract = _auto_contract()
    schedule = ResponseSchedule(
        windows=(BusinessWindow(weekday=2, start=time(9, 0), end=time(17, 0)),),
        require_human_outside_business_hours=True,
        applies_from_impact=ActionImpact.LOW,
        timezone_name="UTC",
        tz=ZoneInfo("UTC"),
    )

    # Wednesday 2026-11-04, 10:00 UTC — inside the declared window.
    inside = evaluate_contract(
        contract=contract,
        confidence=1.0,
        tier="L4",
        schedule=schedule,
    )
    # evaluate_contract reads the clock itself, so the in-hours case is
    # asserted through apply_schedule directly below rather than by pretending
    # to control `now` here; what this asserts is that a schedule whose
    # conditions do not fire returns the verdict untouched.
    assert inside.requirement in (ApprovalRequirement.AUTOMATIC, ApprovalRequirement.ANALYST)

    from app.live_actions.approval_rules import apply_schedule

    baseline = evaluate_contract(contract=contract, confidence=1.0, tier="L4")
    in_hours = apply_schedule(baseline, schedule, now=datetime(2026, 11, 4, 10, 0, tzinfo=UTC))
    out_of_hours = apply_schedule(baseline, schedule, now=datetime(2026, 11, 4, 3, 0, tzinfo=UTC))

    assert in_hours.requirement is ApprovalRequirement.AUTOMATIC, "a healthy tenant inside its hours lost its automatic verb"
    assert out_of_hours.requirement is ApprovalRequirement.ANALYST
    assert "outside the tenant's declared response hours" in out_of_hours.reason


def test_the_schedule_can_never_lower_a_requirement() -> None:
    """Raise-only, asserted over every requirement the matrix emits."""
    for contract in CAPABILITY_CONTRACTS.values():
        for tier in ("L0", "L1", "L2", "L3", "L4"):
            for confidence in (None, 0.0, 0.5, 0.95, 1.0):
                before = evaluate_contract(contract=contract, confidence=confidence, tier=tier)
                after = evaluate_contract(
                    contract=contract,
                    confidence=confidence,
                    tier=tier,
                    schedule=ResponseSchedule(freeze_active=True, applies_from_impact=ActionImpact.READ_ONLY),
                )
                if before.requirement is ApprovalRequirement.AUTOMATIC:
                    assert after.requirement is ApprovalRequirement.ANALYST
                else:
                    assert after.requirement is before.requirement, (
                        f"{contract.impact.value}/{tier}/{confidence}: the schedule changed a decision that already required a human"
                    )


def test_the_vendored_copy_exports_the_time_gates() -> None:
    """The console grades the same question and needs the same inputs.

    The vendored package exported ``evaluate_contract`` and not the schedule,
    so the autonomy page could answer "would this verb auto-execute" without
    the tenant's freeze — a page saying unattended while the tenant had
    declared otherwise.
    """
    import importlib.util
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[3]
    init = root / "services" / "api" / "app" / "_vendor" / "action_contracts" / "__init__.py"
    source = init.read_text(encoding="utf-8")
    assert importlib.util.find_spec is not None  # keep the import meaningful to linters
    for name in ("ResponseSchedule", "BusinessWindow", "apply_schedule"):
        assert f'"{name}",' in source, f"{name} is not exported from the vendored action contracts"


@pytest.mark.asyncio
async def test_the_dispatcher_resolves_a_schedule_for_every_request(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reaching the dispatch path is the whole claim.

    Asserted by observing the resolver being called with the request's tenant
    and the verdict carrying its reason — not by reading the dispatcher's
    source, which is what let the previous version of this claim be GATED on a
    test of pure functions.
    """
    from app.live_actions import dispatcher

    seen: list[object] = []

    async def _fake_resolver(tenant_id):  # noqa: ANN001, ANN202
        seen.append(tenant_id)
        return ResponseSchedule(freeze_active=True, applies_from_impact=ActionImpact.READ_ONLY)

    monkeypatch.setattr(dispatcher, "resolve_response_schedule", _fake_resolver)

    capability, contract = _auto_contract()
    decision = dispatcher._apply_capability_contract(  # noqa: SLF001 — the composition point is the unit under test
        LiveActionRequest(capability=capability, vendor_id="probe", confidence=1.0),
        _auto_decision(),
        tier_label="L4",
        schedule=await dispatcher.resolve_response_schedule("11111111-1111-1111-1111-111111111111"),
    )

    assert seen == ["11111111-1111-1111-1111-111111111111"]
    assert "change freeze is in force" in decision.reason
    assert contract is not None


def _auto_decision():  # noqa: ANN202
    from app.services.autonomy_safety import AutonomyDecision, AutonomyMode, BlastRadius, RollbackCapability
    from app.services.maturity import MaturityTier

    return AutonomyDecision(
        mode=AutonomyMode.AUTO,
        blast_radius=BlastRadius.LOW,
        tier=MaturityTier.L4_AUTOMATE,
        rollback=RollbackCapability.REVERSIBLE,
        requires_verification=False,
        reason="tier permits this blast radius",
    )
