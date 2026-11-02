"""Approval deadlines that do something, and the limits on what.

Wave-2 Phase 6.3. Until this landed, every approval in the product behaved
identically at its deadline: the action did not happen, and nothing else
happened either. For the step that isolates a host believed to be
exfiltrating, "nobody answered, so we did nothing" is a decision nobody made
on purpose.

The tests that matter are the ones about the limits, not the feature:

* a ``contain`` outcome must name a verb, checked when the playbook is
  saved rather than three hours into an incident;
* the verb must be a **graded** one, so a timeout cannot dispatch something
  nobody classified;
* a read-only verb is refused, because a timeout that runs a search has not
  contained anything;
* and the dispatch goes through the ordinary governed path, so a queued
  action is recorded as queued. A timeout is not a tier promotion.
"""

from __future__ import annotations

from typing import Any

import pytest
from app.playbook import engine as engine_mod
from app.playbook import timeout_outcome
from app.playbook.timeout_outcome import (
    TimeoutOutcomeError,
    validate_timeout_outcome,
)

GRADED = {"isolate_host", "disable_user", "revoke_session"}


class TestValidationHappensAtSaveTime:
    def test_no_declaration_is_the_existing_behaviour(self) -> None:
        outcome = validate_timeout_outcome({}, known_verbs=GRADED)
        assert outcome.outcome == timeout_outcome.STAY_PAUSED
        assert outcome.is_default is True

    def test_an_unknown_outcome_is_refused(self) -> None:
        with pytest.raises(TimeoutOutcomeError, match="not one of"):
            validate_timeout_outcome({"timeout_outcome": "escalate_to_ciso"}, known_verbs=GRADED)

    def test_contain_without_a_verb_is_refused(self) -> None:
        """'Escalate to whatever seems appropriate' is an undeclared outcome
        with a name."""
        with pytest.raises(TimeoutOutcomeError, match="needs a 'timeout_capability'"):
            validate_timeout_outcome({"timeout_outcome": "contain"}, known_verbs=GRADED)

    def test_a_verb_nobody_graded_is_refused(self) -> None:
        with pytest.raises(TimeoutOutcomeError, match="not a graded verb"):
            validate_timeout_outcome(
                {"timeout_outcome": "contain", "timeout_capability": "delete_everything"},
                known_verbs=GRADED,
            )

    def test_a_verb_declared_on_a_non_contain_outcome_is_refused(self) -> None:
        """It would never be dispatched, so accepting it would be a
        configuration that reads as a control and is not one."""
        with pytest.raises(TimeoutOutcomeError, match="would never be dispatched"):
            validate_timeout_outcome(
                {"timeout_outcome": "rollback", "timeout_capability": "isolate_host"},
                known_verbs=GRADED,
            )

    def test_a_graded_verb_is_accepted_with_its_target(self) -> None:
        outcome = validate_timeout_outcome(
            {
                "timeout_outcome": "contain",
                "timeout_capability": "isolate_host",
                "timeout_target": "WS-1041",
                "timeout_params": {"vendor_id": "crowdstrike"},
            },
            known_verbs=GRADED,
        )
        assert outcome.capability == "isolate_host"
        assert outcome.target == "WS-1041"
        assert outcome.to_row()["timeout_params"]["target"] == "WS-1041"
        assert outcome.verified is True

    def test_an_unreadable_vocabulary_is_recorded_rather_than_treated_as_a_pass(self) -> None:
        """The agents image cannot import the capability contracts, which
        live in another service. The authority is the governed dispatch,
        which refuses a verb it cannot resolve; this flag records whether
        the author also got told early. An unknown bucket that silently
        passes is the defect this codebase keeps finding in its own gates,
        so it is a recorded ``False`` rather than an implied ``True``."""
        outcome = validate_timeout_outcome(
            {"timeout_outcome": "contain", "timeout_capability": "isolate_host"},
            known_verbs=set(),
        )
        assert outcome.verified is False

    def test_read_only_verbs_are_not_offerable(self) -> None:
        """Derived from the contract rather than from a list here, so a verb
        added to the product becomes offerable without a second edit."""
        verbs = timeout_outcome.graded_capabilities()
        if not verbs:
            pytest.skip("capability contracts are not importable in this image, which is the case this module documents")
        assert "search_siem" not in verbs
        assert "isolate_host" in verbs


class TestTheSweeperRunsTheDeclaration:
    pytestmark = pytest.mark.asyncio

    @staticmethod
    def _pause(**overrides: Any) -> dict[str, Any]:
        row = {
            "id": "11111111-1111-1111-1111-111111111111",
            "tenant_id": "22222222-2222-2222-2222-222222222222",
            "run_id": "run-7",
            "playbook_id": "pb-1",
            "step_id": "approve-isolation",
            "timeout_outcome": "contain",
            "timeout_capability": "isolate_host",
            "timeout_params": {"target": "WS-1041", "vendor_id": "crowdstrike"},
        }
        row.update(overrides)
        return row

    async def test_a_contain_outcome_dispatches_through_the_governed_path(self, monkeypatch) -> None:
        dispatched: list[dict[str, Any]] = []
        recorded: list[dict[str, Any]] = []

        async def _dispatch(**kwargs):
            dispatched.append(kwargs)
            return {"executed": True, "status": "completed"}

        async def _record(**kwargs):
            recorded.append(kwargs)
            return True

        monkeypatch.setattr(engine_mod.action_bridge, "dispatch_step", _dispatch)
        monkeypatch.setattr(engine_mod.playbook_pause, "record_timeout_result", _record)

        acted = await engine_mod.run_timeout_outcomes([self._pause()])

        assert acted == ["11111111-1111-1111-1111-111111111111"]
        assert dispatched[0]["capability"] == "isolate_host"
        assert dispatched[0]["target"] == "WS-1041"
        # The step id carries the timeout marker, so the ledger separates
        # "the analyst approved this" from "the deadline did this".
        assert dispatched[0]["playbook_step_id"].endswith(":timeout")
        assert recorded[0]["result"]["executed"] is True

    async def test_a_queued_action_is_not_recorded_as_a_containment(self, monkeypatch) -> None:
        """A timeout is not a tier promotion.

        ``executed`` is the single field meaning a vendor was touched. A
        verb the tenant's tier would not auto-execute queues here exactly
        as it would anywhere else, and the record has to say so — otherwise
        an operator reads a containment that did not happen.
        """
        recorded: list[dict[str, Any]] = []

        async def _dispatch(**_kwargs):
            return {"executed": False, "status": "pending_approval"}

        async def _record(**kwargs):
            recorded.append(kwargs)
            return True

        monkeypatch.setattr(engine_mod.action_bridge, "dispatch_step", _dispatch)
        monkeypatch.setattr(engine_mod.playbook_pause, "record_timeout_result", _record)

        await engine_mod.run_timeout_outcomes([self._pause()])
        assert recorded[0]["result"]["executed"] is False
        assert recorded[0]["result"]["dispatch"]["status"] == "pending_approval"

    async def test_a_failed_dispatch_is_recorded_and_does_not_stop_the_sweep(self, monkeypatch) -> None:
        recorded: list[dict[str, Any]] = []

        calls = {"n": 0}

        async def _dispatch(**_kwargs):
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("the action service is unreachable")
            return {"executed": True}

        async def _record(**kwargs):
            recorded.append(kwargs)
            return True

        monkeypatch.setattr(engine_mod.action_bridge, "dispatch_step", _dispatch)
        monkeypatch.setattr(engine_mod.playbook_pause, "record_timeout_result", _record)

        acted = await engine_mod.run_timeout_outcomes(
            [
                self._pause(id="aaaaaaaa-1111-1111-1111-111111111111"),
                self._pause(id="33333333-3333-3333-3333-333333333333"),
            ]
        )

        assert len(acted) == 2, "one failing deadline must not abandon the rest of the sweep"
        assert "unreachable" in recorded[0]["result"]["error"]
        assert recorded[0]["result"]["executed"] is False

    async def test_a_rollback_outcome_does_not_dispatch_a_verb(self, monkeypatch) -> None:
        dispatched: list[dict[str, Any]] = []
        recorded: list[dict[str, Any]] = []

        async def _dispatch(**kwargs):
            dispatched.append(kwargs)
            return {"executed": True}

        async def _record(**kwargs):
            recorded.append(kwargs)
            return True

        monkeypatch.setattr(engine_mod.action_bridge, "dispatch_step", _dispatch)
        monkeypatch.setattr(engine_mod.playbook_pause, "record_timeout_result", _record)

        await engine_mod.run_timeout_outcomes([self._pause(timeout_outcome="rollback", timeout_capability=None, timeout_params={})])

        assert not dispatched
        assert recorded[0]["result"]["rollback_requested"] is True

    async def test_a_stay_paused_row_is_skipped_rather_than_acted_on(self, monkeypatch) -> None:
        """The default outcome is the behaviour every playbook had before
        this existed: the action does not happen and the platform stays out
        of it. The row is still expired by the statement that handed it
        here, which is what keeps it from being a silent hang."""
        dispatched: list[dict[str, Any]] = []
        recorded: list[dict[str, Any]] = []

        async def _dispatch(**kwargs):
            dispatched.append(kwargs)
            return {"executed": True}

        async def _record(**kwargs):
            recorded.append(kwargs)
            return True

        monkeypatch.setattr(engine_mod.action_bridge, "dispatch_step", _dispatch)
        monkeypatch.setattr(engine_mod.playbook_pause, "record_timeout_result", _record)

        acted = await engine_mod.run_timeout_outcomes(
            [self._pause(timeout_outcome="stay_paused", timeout_capability=None, timeout_params={})]
        )

        assert acted == []
        assert not dispatched
        assert not recorded

    async def test_the_expiry_and_the_declaration_come_from_one_statement(self) -> None:
        """Not a style preference. The declaration lives on a row the
        expiry stops being `waiting`, so a separate read afterwards finds
        nothing and a separate read beforehand is a second cross-tenant
        sweep racing the first."""
        import inspect

        from app.playbook import pause as pause_mod

        source = inspect.getsource(pause_mod.expire_due_returning)
        assert "RETURNING" in source
        assert "timeout_outcome" in source
        assert not hasattr(pause_mod, "due_timeout_outcomes"), "a second sweep reintroduces the race this collapsed"
