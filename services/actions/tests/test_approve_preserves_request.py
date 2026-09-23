"""An approved action must be the action that was approved.

``approve_action`` rebuilt the ``ActionRequest`` from the stored record and
omitted two fields: ``parameters`` and ``principal``. So an action gated
*because* of what it targets executed against empty parameters and reported
COMPLETED, and the executor's own authorization saw no identity behind the
run. An approval that silently changes what it approved is not an approval.

The record never carried ``parameters`` at all, so this is not a rebuild bug
alone — the submit path discarded them too, and nothing downstream could have
recovered them.
"""

from __future__ import annotations

import json
from uuid import uuid4

import pytest
from app.api import router as router_module
from app.core.config import get_settings
from app.models.action import (
    ActionPrincipal,
    ActionRequest,
    ActionResult,
    ActionStatus,
    ActionType,
    BlastRadius,
)
from app.security import chatops_identity

APPROVER_MAP = {
    "slack": {
        "U_LEAD": {
            "user_id": "dana@example.com",
            "permissions": ["actions:execute:high", "actions:execute:critical"],
            "roles": ["soc-lead"],
        }
    }
}


@pytest.fixture(autouse=True)
def _approver_map(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("AISOC_CHATOPS_APPROVERS", json.dumps(APPROVER_MAP))
    get_settings.cache_clear()
    chatops_identity.reset_cache()
    yield
    get_settings.cache_clear()
    chatops_identity.reset_cache()


@pytest.fixture(autouse=True)
def _clean_store():
    router_module._actions.clear()
    yield
    router_module._actions.clear()


class _CapturingExecutor:
    """Records the request it was handed, so the test can inspect it."""

    def __init__(self) -> None:
        self.seen: ActionRequest | None = None

    async def execute(self, request: ActionRequest):
        self.seen = request
        return ActionResult(
            action_id=request.id,
            status=ActionStatus.COMPLETED,
            blast_radius=BlastRadius.HIGH,
            output={"ok": True},
        )


def _request(**overrides) -> ActionRequest:
    kwargs = {
        "id": uuid4(),
        "incident_id": uuid4(),
        "tenant_id": uuid4(),
        "action_type": ActionType.ISOLATE_HOST,
        "target": "WKSTN-01",
        "rationale": "confirmed beacon",
        "parameters": {"reason": "c2", "duration_minutes": 60},
        # The requester needs the action's own permission to submit it at all
        # (W4.2 least-privilege), and must differ from the approver so
        # separation of duties has something to separate.
        "principal": ActionPrincipal(
            user_id="rory@example.com",
            permissions=["actions:execute:high"],
        ),
    }
    kwargs.update(overrides)
    return ActionRequest(**kwargs)


@pytest.mark.asyncio
async def test_submit_persists_the_parameters(monkeypatch: pytest.MonkeyPatch):
    """The record had no `parameters` key at all, so approve could not have
    restored them however carefully it was written."""
    executor = _CapturingExecutor()
    monkeypatch.setitem(router_module.EXECUTOR_REGISTRY, ActionType.ISOLATE_HOST, executor)

    request = _request()
    record = await router_module.submit_action(request)

    assert record["parameters"] == {"reason": "c2", "duration_minutes": 60}


@pytest.mark.asyncio
async def test_an_approved_action_executes_with_its_parameters(monkeypatch: pytest.MonkeyPatch):
    executor = _CapturingExecutor()
    monkeypatch.setitem(router_module.EXECUTOR_REGISTRY, ActionType.ISOLATE_HOST, executor)

    request = _request()
    record = await router_module.submit_action(request)
    assert record["status"] == ActionStatus.AWAITING_APPROVAL, "isolate_host must be gated for this test to mean anything"

    await router_module.approve_action(
        str(request.id),
        chatops_approver=router_module.ChatOpsApprover(platform="slack", platform_user_id="U_LEAD"),
    )

    assert executor.seen is not None
    assert executor.seen.parameters == {"reason": "c2", "duration_minutes": 60}


@pytest.mark.asyncio
async def test_the_executor_sees_the_approver_not_nobody(monkeypatch: pytest.MonkeyPatch):
    """The executor's own authorization has to evaluate the identity that
    authorised this run, and it was handed None."""
    executor = _CapturingExecutor()
    monkeypatch.setitem(router_module.EXECUTOR_REGISTRY, ActionType.ISOLATE_HOST, executor)

    request = _request()
    await router_module.submit_action(request)
    await router_module.approve_action(
        str(request.id),
        chatops_approver=router_module.ChatOpsApprover(platform="slack", platform_user_id="U_LEAD"),
    )

    assert executor.seen is not None
    assert executor.seen.principal is not None
    assert executor.seen.principal.user_id == "dana@example.com"


@pytest.mark.asyncio
async def test_identity_target_and_rationale_still_survive(monkeypatch: pytest.MonkeyPatch):
    executor = _CapturingExecutor()
    monkeypatch.setitem(router_module.EXECUTOR_REGISTRY, ActionType.ISOLATE_HOST, executor)

    request = _request()
    await router_module.submit_action(request)
    await router_module.approve_action(
        str(request.id),
        chatops_approver=router_module.ChatOpsApprover(platform="slack", platform_user_id="U_LEAD"),
    )

    assert executor.seen is not None
    assert executor.seen.id == request.id
    assert executor.seen.target == "WKSTN-01"
    assert executor.seen.rationale == "confirmed beacon"
    assert executor.seen.tenant_id == request.tenant_id
