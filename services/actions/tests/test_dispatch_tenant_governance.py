"""The dispatcher must govern by the tenant's policy, not a global env var.

Companion to `test_tenant_policy.py`, which covers resolution in isolation.
These go through `dispatch()` because the defect was the wiring: the resolution
logic for per-tenant tiers existed in `maturity.evaluate_gate` and had no
caller anywhere in the tree.
"""

from __future__ import annotations

import uuid

import pytest
from app.live_actions import dispatcher as dispatcher_mod
from app.live_actions import registry
from app.live_actions.dispatcher import dispatch
from app.live_actions.models import LiveActionRequest, LiveActionResult, LiveActionStatus
from app.models.action import ActionType
from app.services.maturity import MaturityTier
from app.services.tenant_policy import TenantPolicy

pytestmark = pytest.mark.asyncio


class _OkExecutor:
    _legacy_action_type = ActionType.ISOLATE_HOST

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return LiveActionResult(
            request_id=request.request_id,
            status=LiveActionStatus.SUCCEEDED,
            capability=request.capability,
            vendor_id=request.vendor_id,
            summary="isolated",
        )


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
def _executor_and_no_verify(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(registry, "get_executor", lambda vendor, cap: _OkExecutor())

    # Keep these tests about governance: a stub verifier so a real probe never
    # runs and the assertions are about the autonomy verdict only.
    class _V:
        async def verify(self, action_type, target, params):  # noqa: ANN001
            from app.services.verification import VerificationOutcome, VerificationResult

            return VerificationResult(VerificationOutcome.UNVERIFIED, action_type, target, reason="stub")

    monkeypatch.setattr(dispatcher_mod, "PostActionVerifier", lambda: _V())


def _policy(monkeypatch: pytest.MonkeyPatch, policy: TenantPolicy):
    async def _resolve(tenant_id):  # noqa: ANN001, ANN202
        return policy

    monkeypatch.setattr(dispatcher_mod, "resolve_tenant_policy", _resolve)


async def test_an_observe_only_tenant_does_not_auto_execute(
    monkeypatch: pytest.MonkeyPatch,
):
    """L0 means the platform watches. Isolating a host is not watching."""
    _policy(monkeypatch, TenantPolicy(tier=MaturityTier.L0_OBSERVE, from_store=True))
    result = await dispatch(_request())
    assert result.status is not LiveActionStatus.SUCCEEDED


async def test_a_tenant_blocklist_entry_blocks_the_action(
    monkeypatch: pytest.MonkeyPatch,
):
    _policy(
        monkeypatch,
        TenantPolicy(
            tier=MaturityTier.L4_AUTOMATE,
            action_overrides={"isolate_host": {"block": True}},
            from_store=True,
            source="tenant_policy",
        ),
    )
    result = await dispatch(_request())
    assert result.status is LiveActionStatus.BLOCKED
    assert "blocked by tenant policy" in result.summary


async def test_force_auto_override_still_requires_verification(
    monkeypatch: pytest.MonkeyPatch,
):
    """Skipping the approval queue is not the same as skipping the proof.

    A tenant who force-autos host isolation has chosen to act without a human
    in the loop, which makes read-back confirmation more important, not less.
    """
    _policy(
        monkeypatch,
        TenantPolicy(
            tier=MaturityTier.L2_CONTAIN,
            action_overrides={"isolate_host": {"force_auto": True}},
            from_store=True,
            source="tenant_policy",
        ),
    )
    result = await dispatch(_request())
    assert result.status is LiveActionStatus.SUCCEEDED
    assert result.details["verification"] == "unverified"


async def test_whitelist_is_passed_through_to_the_autonomy_decision(
    monkeypatch: pytest.MonkeyPatch,
):
    """`decide(whitelisted=...)` was never passed, so L4 break-glass was dead.

    Asserted by observing that two otherwise identical L4 dispatches differ
    only by the presence of a whitelist entry.
    """
    seen: list[bool] = []
    real_decide = dispatcher_mod.decide

    def _spy(action_request, *, tier, whitelisted=False, **kw):  # noqa: ANN001, ANN003
        seen.append(whitelisted)
        return real_decide(action_request, tier=tier, whitelisted=whitelisted, **kw)

    monkeypatch.setattr(dispatcher_mod, "decide", _spy)

    _policy(monkeypatch, TenantPolicy(tier=MaturityTier.L4_AUTOMATE, from_store=True))
    await dispatch(_request())

    _policy(
        monkeypatch,
        TenantPolicy(
            tier=MaturityTier.L4_AUTOMATE,
            whitelist=[{"action_type": "isolate_host", "constraints": {}, "expires_at": None}],
            from_store=True,
        ),
    )
    await dispatch(_request())

    assert seen == [False, True]


async def test_the_policy_source_is_recorded_for_the_audit_trail(
    monkeypatch: pytest.MonkeyPatch,
):
    """An operator must be able to tell a tenant choice from a default."""
    _policy(
        monkeypatch,
        TenantPolicy(
            tier=MaturityTier.L4_AUTOMATE,
            action_overrides={"isolate_host": {"force_auto": True}},
            from_store=True,
            source="tenant_policy",
        ),
    )
    result = await dispatch(_request())
    assert "tenant_policy" in result.details["autonomy_reason"]
