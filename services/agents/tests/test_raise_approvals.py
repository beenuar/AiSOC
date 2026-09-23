"""An action that needs approval has to reach somebody who can give it.

The `agent_approvals` table, the API on top of it and the whole responder-app
approvals screen all existed. Nothing inserted a row: the API docstring said
"the agents service calls this", and a grep of this service for `approvals`
returned nothing at all. So `requires_approval=True` described an approval
nobody could grant, and the queue was structurally empty on every deployment
— indistinguishable from a working feature with no pending work.
"""

from __future__ import annotations

import uuid

import pytest
from app.investigator import ledger as ledger_module
from app.models.state import ActionRisk, InvestigationState, ProposedAction
from app.workers.fused_alert_consumer import FusedAlertTriageWorker

TENANT = str(uuid.uuid4())


def _state(*actions: ProposedAction) -> InvestigationState:
    state = InvestigationState(
        run_id=uuid.uuid4(),
        incident_id=uuid.uuid4(),
        tenant_id=uuid.UUID(TENANT),
    )
    state.raw_alert = {"id": str(uuid.uuid4())}
    state.proposed_actions = list(actions)
    return state


def _action(**overrides) -> ProposedAction:
    kwargs = {
        "action_type": "isolate_host",
        "description": "Isolate WKSTN-01 pending review",
        "risk_level": ActionRisk.HIGH,
        "target": "WKSTN-01",
        "requires_approval": True,
        "rationale": "Confirmed C2 beacon.",
        "parameters": {"reason": "c2"},
    }
    kwargs.update(overrides)
    return ProposedAction(**kwargs)


@pytest.fixture
def raised(monkeypatch: pytest.MonkeyPatch) -> list[dict]:
    recorded: list[dict] = []

    async def _raise_approval(**kwargs):
        recorded.append(kwargs)
        return uuid.uuid4()

    monkeypatch.setattr(ledger_module, "raise_approval", _raise_approval)
    monkeypatch.delenv("AISOC_AGENT_RAISE_APPROVALS", raising=False)
    return recorded


class TestWhatGetsQueued:
    @pytest.mark.asyncio
    async def test_an_approval_requiring_action_is_queued(self, raised):
        worker = FusedAlertTriageWorker.__new__(FusedAlertTriageWorker)
        ids = await worker._raise_approvals(_state(_action()))

        assert len(ids) == 1
        assert len(raised) == 1
        assert raised[0]["action"]["action_type"] == "isolate_host"
        assert raised[0]["action"]["target"] == "WKSTN-01"

    @pytest.mark.asyncio
    async def test_an_action_that_does_not_require_approval_is_not_queued(self, raised):
        """This does not widen what the agent can do. The worker dispatches
        nothing either way; it queues the subset that was always meant to
        reach a human."""
        worker = FusedAlertTriageWorker.__new__(FusedAlertTriageWorker)
        ids = await worker._raise_approvals(_state(_action(requires_approval=False)))

        assert ids == []
        assert raised == []

    @pytest.mark.asyncio
    async def test_parameters_survive_onto_the_approval(self, raised):
        """The approval is what the actions service is later rebuilt from, so
        losing parameters here means approving a different action."""
        worker = FusedAlertTriageWorker.__new__(FusedAlertTriageWorker)
        await worker._raise_approvals(_state(_action()))

        assert raised[0]["action"]["parameters"] == {"reason": "c2"}

    @pytest.mark.asyncio
    async def test_the_rationale_becomes_the_summary_a_human_reads(self, raised):
        worker = FusedAlertTriageWorker.__new__(FusedAlertTriageWorker)
        await worker._raise_approvals(_state(_action()))

        assert raised[0]["summary"] == "Confirmed C2 beacon."

    @pytest.mark.asyncio
    async def test_several_actions_each_get_their_own_approval(self, raised):
        worker = FusedAlertTriageWorker.__new__(FusedAlertTriageWorker)
        ids = await worker._raise_approvals(
            _state(
                _action(),
                _action(action_type="disable_user", target="alice@example.com"),
            )
        )

        assert len(ids) == 2
        assert {call["action"]["action_type"] for call in raised} == {"isolate_host", "disable_user"}


class TestItStaysOptional:
    @pytest.mark.asyncio
    async def test_the_flag_turns_it_off(self, raised, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("AISOC_AGENT_RAISE_APPROVALS", "0")
        worker = FusedAlertTriageWorker.__new__(FusedAlertTriageWorker)

        assert await worker._raise_approvals(_state(_action())) == []
        assert raised == []

    @pytest.mark.asyncio
    async def test_a_ledger_failure_does_not_fail_triage(self, monkeypatch: pytest.MonkeyPatch):
        """The verdict is the valuable thing and it is already durable. A
        database that cannot take the approval must not discard it."""

        async def _raise_approval(**_):
            return None

        monkeypatch.setattr(ledger_module, "raise_approval", _raise_approval)
        worker = FusedAlertTriageWorker.__new__(FusedAlertTriageWorker)

        assert await worker._raise_approvals(_state(_action())) == []


class TestIdempotency:
    def test_the_same_action_maps_to_the_same_approval_id(self):
        """A Kafka replay must re-raise the same approval, not a second copy:
        an operator seeing the same containment request twice cannot tell
        which one is live."""
        tenant = uuid.uuid4()
        run = uuid.uuid4()
        action = {"action_type": "isolate_host", "target": "WKSTN-01"}

        first = ledger_module._deterministic_approval_id(tenant, run, action)
        second = ledger_module._deterministic_approval_id(tenant, run, dict(action))

        assert first == second

    def test_a_different_target_is_a_different_approval(self):
        tenant = uuid.uuid4()
        run = uuid.uuid4()

        a = ledger_module._deterministic_approval_id(tenant, run, {"action_type": "isolate_host", "target": "a"})
        b = ledger_module._deterministic_approval_id(tenant, run, {"action_type": "isolate_host", "target": "b"})

        assert a != b

    def test_a_different_tenant_is_a_different_approval(self):
        run = uuid.uuid4()
        action = {"action_type": "isolate_host", "target": "WKSTN-01"}

        a = ledger_module._deterministic_approval_id(uuid.uuid4(), run, action)
        b = ledger_module._deterministic_approval_id(uuid.uuid4(), run, action)

        assert a != b
