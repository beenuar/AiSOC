"""Verification must run on the live dispatch path, not just in its own test.

The market treats outcome verification as the line between recommending and
responding: proving the target's state actually changed, not that an API call
was accepted. AiSOC had the verifier and did not call it.

`AutonomyDecision.requires_verification` was computed for every auto-executed
action at MEDIUM blast or above and then dropped when the dispatcher assembled
its result. `PostActionVerifier` had no caller anywhere outside
`test_verification.py`, so the product could report that a containment call
succeeded and never that containment took effect.

These tests assert the wiring, which is the part that was missing. They are
deliberately written against `dispatch()` rather than the verifier, because a
passing verifier test is exactly what made this look covered.
"""

from __future__ import annotations

import uuid

import pytest
from app.live_actions import dispatcher as dispatcher_mod
from app.live_actions import registry
from app.live_actions.dispatcher import dispatch
from app.live_actions.models import LiveActionRequest, LiveActionResult, LiveActionStatus
from app.models.action import ActionType
from app.services.autonomy_safety import (
    AutonomyDecision,
    AutonomyMode,
    BlastRadius,
    RollbackCapability,
)
from app.services.maturity import MaturityTier
from app.services.verification import VerificationOutcome, VerificationResult

pytestmark = pytest.mark.asyncio


class _OkExecutor:
    """Minimal executor that reports success without touching a vendor."""

    _legacy_action_type = ActionType.ISOLATE_HOST

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return LiveActionResult(
            request_id=request.request_id,
            status=LiveActionStatus.SUCCEEDED,
            capability=request.capability,
            vendor_id=request.vendor_id,
            summary="isolated",
        )


def _decision(blast: BlastRadius, *, requires_verification: bool) -> AutonomyDecision:
    return AutonomyDecision(
        mode=AutonomyMode.AUTO,
        blast_radius=blast,
        tier=MaturityTier.L3_REMEDIATE,
        rollback=RollbackCapability.REVERSIBLE,
        requires_verification=requires_verification,
        reason="test",
    )


def _stub_govern(blast: BlastRadius, *, requires_verification: bool):
    """`_govern` is async (it reads the tenant's stored policy), so the stub is too."""

    async def _govern(request, action_type):  # noqa: ANN001, ANN202
        return _decision(blast, requires_verification=requires_verification)

    return _govern


def _request(**overrides) -> LiveActionRequest:
    payload = {
        "request_id": uuid.uuid4(),
        "capability": "isolate_host",
        "vendor_id": "crowdstrike",
        "target": "WIN-DC01",
        "dry_run": False,
        "tenant_id": uuid.uuid4(),
        "requested_by": "analyst@example.com",
    }
    payload.update(overrides)
    return LiveActionRequest(**payload)


@pytest.fixture(autouse=True)
def _wire(monkeypatch: pytest.MonkeyPatch):
    """Executor always succeeds; autonomy always demands verification."""
    monkeypatch.setattr(registry, "get_executor", lambda vendor, cap: _OkExecutor())
    monkeypatch.setattr(
        dispatcher_mod,
        "_govern",
        _stub_govern(BlastRadius.MEDIUM, requires_verification=True),
    )


def _stub_verifier(monkeypatch: pytest.MonkeyPatch, outcome: VerificationOutcome):
    class _V:
        async def verify(self, action_type, target, params):  # noqa: ANN001
            return VerificationResult(outcome, action_type, target, reason=f"stub {outcome.value}")

    monkeypatch.setattr(dispatcher_mod, "PostActionVerifier", lambda: _V())


async def test_verified_effect_is_recorded_on_the_result(monkeypatch: pytest.MonkeyPatch):
    _stub_verifier(monkeypatch, VerificationOutcome.VERIFIED)
    result = await dispatch(_request())
    assert result.status is LiveActionStatus.SUCCEEDED
    assert result.details["verification"] == "verified"


async def test_unverified_effect_does_not_become_a_confirmation(monkeypatch: pytest.MonkeyPatch):
    """No probe or no credentials must stay honest, not upgrade to verified."""
    _stub_verifier(monkeypatch, VerificationOutcome.UNVERIFIED)
    result = await dispatch(_request())
    assert result.details["verification"] == "unverified"
    assert result.status is LiveActionStatus.SUCCEEDED


async def test_action_that_reported_success_but_did_not_take_is_downgraded(
    monkeypatch: pytest.MonkeyPatch,
):
    """The case that matters: vendor said 200, the effect is absent.

    Leaving this COMPLETED is how a SOC comes to believe a host is contained
    when it is not.
    """
    _stub_verifier(monkeypatch, VerificationOutcome.FAILED)
    result = await dispatch(_request())
    assert result.status is LiveActionStatus.FAILED
    assert result.details["verification"] == "failed"
    assert result.error and "verification failed" in result.error


async def test_a_dry_run_is_not_verified(monkeypatch: pytest.MonkeyPatch):
    """Nothing happened, so there is nothing to re-query."""
    called = False

    class _V:
        async def verify(self, *a, **k):  # noqa: ANN002, ANN003
            nonlocal called
            called = True
            raise AssertionError("must not verify a dry run")

    monkeypatch.setattr(dispatcher_mod, "PostActionVerifier", lambda: _V())
    result = await dispatch(_request(dry_run=True))
    assert not called
    assert "verification" not in result.details


async def test_a_simulated_result_is_not_verified(monkeypatch: pytest.MonkeyPatch):
    """SIMULATED is the credential-less safe path — nothing to re-query."""

    class _Simulating:
        _legacy_action_type = ActionType.ISOLATE_HOST

        async def execute(self, request: LiveActionRequest) -> LiveActionResult:
            return LiveActionResult(
                request_id=request.request_id,
                status=LiveActionStatus.SIMULATED,
                capability=request.capability,
                vendor_id=request.vendor_id,
                summary="simulated",
            )

    monkeypatch.setattr(registry, "get_executor", lambda vendor, cap: _Simulating())

    class _V:
        async def verify(self, *a, **k):  # noqa: ANN002, ANN003
            raise AssertionError("must not verify a simulation")

    monkeypatch.setattr(dispatcher_mod, "PostActionVerifier", lambda: _V())
    result = await dispatch(_request())
    assert result.status is LiveActionStatus.SIMULATED
    assert "verification" not in result.details


async def test_verifier_crash_never_loses_the_succeeded_action(
    monkeypatch: pytest.MonkeyPatch,
):
    """The action already happened. Losing the record of it is worse."""

    class _V:
        async def verify(self, *a, **k):  # noqa: ANN002, ANN003
            raise RuntimeError("probe exploded")

    monkeypatch.setattr(dispatcher_mod, "PostActionVerifier", lambda: _V())
    result = await dispatch(_request())
    assert result.status is LiveActionStatus.SUCCEEDED
    assert result.details["verification"] == "unverified"
    assert "RuntimeError" in result.details["verification_reason"]


async def test_verification_is_skipped_when_policy_does_not_require_it(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(
        dispatcher_mod,
        "_govern",
        _stub_govern(BlastRadius.LOW, requires_verification=False),
    )

    class _V:
        async def verify(self, *a, **k):  # noqa: ANN002, ANN003
            raise AssertionError("must not verify when not required")

    monkeypatch.setattr(dispatcher_mod, "PostActionVerifier", lambda: _V())
    result = await dispatch(_request())
    assert "verification" not in result.details
