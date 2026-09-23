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
    return SimpleNamespace(
        user_id=USER,
        tenant_id=TENANT,
        email="dana@example.com",
        roles=["soc_lead"],
        permissions=["cases:write"],
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
