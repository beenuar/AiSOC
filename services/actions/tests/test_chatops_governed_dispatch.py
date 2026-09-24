"""ChatOps verification: a working executor that had nowhere honest to land.

``ChatOpsVerifyExecutor`` has always worked and has always sat in
``EXECUTOR_REGISTRY``, and no live-action adapter reached it — so the only
route to it was the legacy ``ActionType`` endpoint, which has no capability
contract, no approval matrix and no autonomy policy in front of it.

It was left that way deliberately rather than registered, and the reason was
sound: the executor returns ``ActionStatus.RUNNING`` to mean "the prompt went
out and nobody has answered", ``LiveActionStatus`` had no state for that, and
``_to_live_status`` folded everything that was not FAILED or a simulation into
SUCCEEDED. Registering it as-is would have reported an unanswered question as
a completed action.

The fix is the missing state rather than the exemption — and ``AWAITING_COMPLETION``
turned out to be what evidence acquisition needed too, so one status covers
both executors that had no honest result to return.

Why this verb is analyst-gated at ``notify``'s impact: ``notify`` addresses a
SOC channel, this addresses the account under investigation. Sent
automatically on a true positive it tells an attacker they have been detected,
and the verb has no way to know whether the person it is asking is the
suspect.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from app.live_actions import builtins, registry
from app.live_actions.builtins import _to_live_status
from app.live_actions.capabilities import KNOWN_CAPABILITIES
from app.live_actions.capability_contracts import CAPABILITY_CONTRACTS
from app.live_actions.contract import ActionImpact, ApprovalRequirement
from app.live_actions.models import LiveActionRequest, LiveActionStatus
from app.models.action import ActionStatus, ActionType
from app.services.executor_registry import EXECUTOR_REGISTRY

PARAMS = {
    "webhook_url": "https://hooks.example.invalid/T000/B000/xxxx",
    "user_ref": "alice@example.invalid",
    "question": "Did you sign in from Lagos at 03:14?",
}


@pytest.fixture(autouse=True)
def _registered() -> None:
    registry.reset_for_tests()
    builtins.register_builtin_executors(overwrite=True)


@pytest.fixture
def _chatops_enabled(monkeypatch) -> None:
    """The executor hard-fails when the feature flag is off, by design."""
    from app.core.config import get_settings

    settings = get_settings()
    monkeypatch.setattr(settings, "AISOC_FEATURE_CHATOPS_VERIFY", True, raising=False)
    monkeypatch.setattr(settings, "AISOC_CHATOPS_RESPONSE_SECRET", "unit-test-placeholder", raising=False)


# ── The missing state ──────────────────────────────────────────────────────


def test_running_no_longer_collapses_into_succeeded() -> None:
    """The unit-level form of the defect that kept this executor unreachable."""
    assert _to_live_status(ActionStatus.RUNNING, {}) is LiveActionStatus.AWAITING_COMPLETION


def test_awaiting_completion_is_distinct_from_pending_approval() -> None:
    """They mean opposite things about whether the vendor was touched.

    PENDING_APPROVAL: nothing ran, policy wants a human first.
    AWAITING_COMPLETION: the vendor was touched and the outcome is not known.
    """
    assert LiveActionStatus.AWAITING_COMPLETION is not LiveActionStatus.PENDING_APPROVAL
    assert LiveActionStatus.AWAITING_COMPLETION.value == "awaiting_completion"


def test_a_simulation_still_wins_over_running() -> None:
    """Order matters: a simulated result must never read as work in flight."""
    assert _to_live_status(ActionStatus.RUNNING, {"note": "Simulation mode — nothing sent"}) is LiveActionStatus.SIMULATED


# ── Reachability ───────────────────────────────────────────────────────────


@pytest.mark.parametrize("vendor", ["slack", "teams"])
def test_chatops_verify_resolves_through_governed_dispatch(vendor: str) -> None:
    assert registry.get_executor(vendor, "chatops_verify") is not None, (
        f"{vendor}/chatops_verify does not resolve, so the only route to a working " f"executor is the ungoverned ActionType endpoint."
    )


def test_chatops_verify_is_in_the_vocabulary_and_has_a_contract() -> None:
    assert "chatops_verify" in KNOWN_CAPABILITIES
    assert ActionType.CHATOPS_VERIFY in EXECUTOR_REGISTRY

    contract = CAPABILITY_CONTRACTS["chatops_verify"]
    assert contract.impact is ActionImpact.LOW
    # Not automatic, unlike notify at the same impact: this one messages the
    # account under investigation rather than a SOC channel.
    assert contract.approval is ApprovalRequirement.ANALYST
    assert CAPABILITY_CONTRACTS["notify"].approval is ApprovalRequirement.AUTOMATIC
    # No probe, and the reason is recorded rather than silently absent.
    assert contract.has_verification_probe is False
    assert len(contract.verification_gap.strip()) > 40


# ── Behaviour ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_delivered_prompt_is_not_reported_as_a_completed_action(monkeypatch, _chatops_enabled) -> None:
    """The regression this whole change exists to prevent.

    Before ``AWAITING_COMPLETION`` this path produced SUCCEEDED, which tells a
    responder a question has been answered when it has only been asked.
    """
    from app.executors import chatops

    async def _delivered(**kwargs):
        return {"ok": True, "transport": "slack"}

    async def _timeline(**kwargs):
        return None

    monkeypatch.setattr(chatops, "send_slack_prompt", _delivered)
    monkeypatch.setattr(chatops, "post_timeline_event", _timeline)

    executor = registry.get_executor("slack", "chatops_verify")
    assert executor is not None
    result = await executor.execute(
        LiveActionRequest(
            capability="chatops_verify",
            vendor_id="slack",
            target="alice@example.invalid",
            params=dict(PARAMS),
            tenant_id=uuid4(),
        )
    )

    assert result.status is LiveActionStatus.AWAITING_COMPLETION
    assert result.status is not LiveActionStatus.SUCCEEDED
    assert "awaiting their reply" in result.summary


@pytest.mark.asyncio
async def test_each_arm_pins_its_own_transport(monkeypatch, _chatops_enabled) -> None:
    """A pin so the channel is the caller's choice of vendor, not a default.

    Unlike the SIEM arms there is no credential-ordering hazard to guard —
    both transports use the same single ``webhook_url`` — so the pin selects a
    message format rather than claiming an arm that could not have run.
    """
    from app.executors import chatops

    sent: list[str] = []

    async def _slack(**kwargs):
        sent.append("slack")
        return {"ok": True}

    async def _teams(**kwargs):
        sent.append("teams")
        return {"ok": True}

    async def _timeline(**kwargs):
        return None

    monkeypatch.setattr(chatops, "send_slack_prompt", _slack)
    monkeypatch.setattr(chatops, "send_teams_prompt", _teams)
    monkeypatch.setattr(chatops, "post_timeline_event", _timeline)

    for vendor in ("slack", "teams"):
        executor = registry.get_executor(vendor, "chatops_verify")
        assert executor is not None
        # `transport` is deliberately set to the *other* arm in the params, to
        # prove the pin wins over whatever the caller happened to pass.
        await executor.execute(
            LiveActionRequest(
                capability="chatops_verify",
                vendor_id=vendor,
                target="alice@example.invalid",
                params={**PARAMS, "transport": "teams" if vendor == "slack" else "slack"},
                tenant_id=uuid4(),
            )
        )

    assert sent == ["slack", "teams"]


@pytest.mark.asyncio
async def test_a_dry_run_asks_nobody_anything(monkeypatch, _chatops_enabled) -> None:
    """The adapter simulates rather than stripping credentials.

    The base adapter implements dry_run by deleting credential keys so the
    legacy executor falls into its simulation branch. This executor has no
    such branch on purpose — its docstring is explicit that an unreachable
    transport is a hard failure, because an action whose point is asking a
    person a question must not quietly not ask. Stripping the webhook would
    therefore report a preview as a failure, so the adapter short-circuits
    before anything mints a callback token or opens a socket.
    """
    from app.executors import chatops

    async def _tripwire(**kwargs):
        raise AssertionError("a dry run delivered a real ChatOps prompt")

    monkeypatch.setattr(chatops, "send_slack_prompt", _tripwire)
    monkeypatch.setattr(chatops, "send_teams_prompt", _tripwire)
    monkeypatch.setattr(chatops, "mint_token", lambda **kwargs: (_ for _ in ()).throw(AssertionError("a dry run minted a callback token")))

    executor = registry.get_executor("slack", "chatops_verify")
    assert executor is not None
    result = await executor.execute(
        LiveActionRequest(
            capability="chatops_verify",
            vendor_id="slack",
            target="alice@example.invalid",
            params=dict(PARAMS),
            dry_run=True,
            tenant_id=uuid4(),
        )
    )

    assert result.status is LiveActionStatus.SIMULATED
    assert "no prompt was delivered" in str(result.details.get("note", ""))


@pytest.mark.asyncio
async def test_an_undeliverable_prompt_still_fails(monkeypatch, _chatops_enabled) -> None:
    """AWAITING_COMPLETION must not become a place for failures to hide."""
    from app.executors import chatops
    from app.services.chatops_prompt import ChatOpsPromptError

    async def _boom(**kwargs):
        raise ChatOpsPromptError("channel_not_found")

    monkeypatch.setattr(chatops, "send_slack_prompt", _boom)

    executor = registry.get_executor("slack", "chatops_verify")
    assert executor is not None
    result = await executor.execute(
        LiveActionRequest(
            capability="chatops_verify",
            vendor_id="slack",
            target="alice@example.invalid",
            params=dict(PARAMS),
            tenant_id=uuid4(),
        )
    )

    assert result.status is LiveActionStatus.FAILED
    assert "channel_not_found" in (result.error or "")
