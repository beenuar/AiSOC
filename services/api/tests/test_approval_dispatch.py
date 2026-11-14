"""Approving an action has to execute it.

``POST /approvals/{id}/decide`` flipped a row, notified the realtime service
and returned 200. It never touched ``services/actions``. So every tap of
Approve in the responder app recorded a decision and executed nothing, while
telling the operator the opposite — the worst shape a security control can
have, because "the host is contained" is exactly what it appeared to say.

These tests drive ``_dispatch_decision`` directly. The endpoint around it
needs a session, a tenant DB and RLS; the dispatch decision is the part that
was missing, and it is pure enough to pin on its own.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest
from app.api.v1.endpoints import approvals as endpoint
from app.services.actions_client import ActionsServiceError

TENANT = uuid.uuid4()
USER = uuid.uuid4()


def _row(**overrides):
    row = SimpleNamespace(
        id=uuid.uuid4(),
        tenant_id=TENANT,
        run_id=uuid.uuid4(),
        requested_by="agent",
        title="Isolate WKSTN-01",
        summary="Falcon detection with confirmed C2 beacon.",
        action={"action_type": "isolate_host", "target": "WKSTN-01", "parameters": {"reason": "c2"}},
    )
    for key, value in overrides.items():
        setattr(row, key, value)
    return row


def _user():
    """A real `CurrentUser`, not a stand-in.

    This was a `SimpleNamespace` carrying `roles=[...]` and
    `permissions=[...]` -- two attributes `CurrentUser` has never defined. The
    route read exactly those two through `getattr(..., [])`, so the double was
    shaped around the defect: in tests the attributes were there and the
    principal looked populated, while in production both defaults fired and
    every approval shipped an empty permission list.

    A double more accommodating than the real object cannot fail the way
    production fails, which is the whole reason this one did not.
    """
    from app.api.v1.deps import CurrentUser

    return CurrentUser(
        user_id=USER,
        tenant_id=TENANT,
        role="soc_lead",
        email="dana@example.com",
        resolved_permissions=frozenset({"cases:write", "actions:execute:high"}),
    )


@pytest.fixture
def calls(monkeypatch: pytest.MonkeyPatch) -> dict:
    recorded: dict = {"submit": [], "decide": []}

    async def _submit(**kwargs):
        recorded["submit"].append(kwargs)
        return {"id": kwargs["action_id"], "status": "awaiting_approval"}

    async def _decide(**kwargs):
        recorded["decide"].append(kwargs)
        return {"status": "completed", "blast_radius": "high"}

    monkeypatch.setattr(endpoint, "submit_action", _submit)
    monkeypatch.setattr(endpoint, "decide_action", _decide)
    return recorded


class TestTheHappyPath:
    @pytest.mark.asyncio
    async def test_an_approval_submits_then_approves(self, calls):
        row = _row()
        result = await endpoint._dispatch_decision(row, _user(), approve=True)

        assert result["state"] == "executed"
        assert result["action_status"] == "completed"
        assert len(calls["submit"]) == 1
        assert len(calls["decide"]) == 1
        assert calls["decide"][0]["approve"] is True

    @pytest.mark.asyncio
    async def test_the_approval_id_is_reused_as_the_action_id(self, calls):
        """Otherwise 'which action did this approval authorise' needs a join
        nobody wrote."""
        row = _row()
        await endpoint._dispatch_decision(row, _user(), approve=True)

        assert calls["submit"][0]["action_id"] == str(row.id)
        assert calls["decide"][0]["action_id"] == str(row.id)

    @pytest.mark.asyncio
    async def test_parameters_reach_the_actions_service(self, calls):
        row = _row()
        await endpoint._dispatch_decision(row, _user(), approve=True)

        assert calls["submit"][0]["parameters"] == {"reason": "c2"}

    @pytest.mark.asyncio
    async def test_the_requester_is_the_agent_not_the_approver(self, calls):
        """Sending the approver as requester would make them both, and
        separation of duties would pass by accident."""
        row = _row()
        await endpoint._dispatch_decision(row, _user(), approve=True)

        assert calls["submit"][0]["requested_by"] == "agent"
        assert calls["decide"][0]["approver"]["user_id"] == str(USER)

    @pytest.mark.asyncio
    async def test_tenant_comes_from_the_row(self, calls):
        row = _row()
        await endpoint._dispatch_decision(row, _user(), approve=True)

        assert calls["submit"][0]["tenant_id"] == str(TENANT)


class TestDenial:
    @pytest.mark.asyncio
    async def test_a_denial_rejects_upstream(self, calls):
        """Rejecting upstream matters: it moves the action out of
        awaiting_approval so a replayed approval link cannot later run it."""
        row = _row()
        result = await endpoint._dispatch_decision(row, _user(), approve=False)

        assert result["state"] == "declined"
        assert calls["decide"][0]["approve"] is False


class TestNothingToRun:
    @pytest.mark.asyncio
    async def test_an_approval_with_no_action_type_is_not_executable(self, calls):
        # A normal case: an approval can gate a human step.
        row = _row(action={"target": "WKSTN-01"})
        result = await endpoint._dispatch_decision(row, _user(), approve=True)

        assert result["state"] == "not_executable"
        assert calls["submit"] == []

    @pytest.mark.asyncio
    async def test_an_approval_with_no_target_is_not_executable(self, calls):
        row = _row(action={"action_type": "isolate_host"})
        result = await endpoint._dispatch_decision(row, _user(), approve=True)

        assert result["state"] == "not_executable"
        assert calls["submit"] == []


class TestFailureIsVisible:
    @pytest.mark.asyncio
    async def test_a_refused_submit_reports_failed(self, monkeypatch: pytest.MonkeyPatch):
        async def _submit(**_):
            raise ActionsServiceError("blast radius exceeds tier", status_code=403)

        monkeypatch.setattr(endpoint, "submit_action", _submit)
        result = await endpoint._dispatch_decision(_row(), _user(), approve=True)

        assert result["state"] == "failed"
        assert result["stage"] == "submit"
        assert "blast radius" in result["detail"]

    @pytest.mark.asyncio
    async def test_a_refused_decision_reports_which_stage(self, monkeypatch: pytest.MonkeyPatch):
        """submit succeeded and decide did not, which is a different operator
        problem from the service being down."""

        async def _submit(**kwargs):
            return {"id": kwargs["action_id"]}

        async def _decide(**_):
            raise ActionsServiceError("approver may not approve their own action", status_code=403)

        monkeypatch.setattr(endpoint, "submit_action", _submit)
        monkeypatch.setattr(endpoint, "decide_action", _decide)
        result = await endpoint._dispatch_decision(_row(), _user(), approve=True)

        assert result["state"] == "failed"
        assert result["stage"] == "decide"

    @pytest.mark.asyncio
    async def test_an_unreachable_service_reports_failed_not_executed(self, monkeypatch: pytest.MonkeyPatch):
        async def _submit(**_):
            raise ActionsServiceError("actions service unreachable: refused")

        monkeypatch.setattr(endpoint, "submit_action", _submit)
        result = await endpoint._dispatch_decision(_row(), _user(), approve=True)

        # Never "executed". Claiming execution on an unreachable executor is
        # the failure mode this whole wave exists to remove.
        assert result["state"] == "failed"


class TestThePrincipalReachesTheActionsService:
    """Nobody asserted on the principal, which is how an empty one shipped.

    The suite above checks the *shape* of the dispatch -- that submit happens
    before decide, that an unreachable service reports failed. It never looked
    inside the principal, so a principal carrying no permissions at all passed
    every test while 502-ing in production on the first real approval.
    """

    @pytest.mark.asyncio
    async def test_the_decision_carries_a_non_empty_permission_set(self, calls: dict) -> None:
        await endpoint._dispatch_decision(_row(), _user(), approve=True)

        assert calls["decide"], "no decision reached the actions service"
        approver = calls["decide"][0]["approver"]
        assert approver["permissions"], (
            "the approver's permission list is empty, which `has_action_permission` denies "
            "unconditionally -- this is the defect that 502'd every approval"
        )
        assert "cases:write" in approver["permissions"]

    @pytest.mark.asyncio
    async def test_the_submit_leg_identifies_the_caller_too(self, calls: dict) -> None:
        """Harmless only while `AISOC_ACTIONS_REQUIRE_PRINCIPAL` is false.
        Turning it on would have broken submit exactly as decide was broken."""
        await endpoint._dispatch_decision(_row(), _user(), approve=True)

        assert calls["submit"], "no submit reached the actions service"
        assert calls["submit"][0].get("principal"), "submit identifies no caller"

    @pytest.mark.asyncio
    async def test_the_role_travels_as_a_list(self, calls: dict) -> None:
        """`CurrentUser.role` is singular and the actions service reads a
        list. The old code read `user.roles`, which does not exist."""
        await endpoint._dispatch_decision(_row(), _user(), approve=True)

        assert calls["decide"][0]["approver"]["roles"] == ["soc_lead"]
