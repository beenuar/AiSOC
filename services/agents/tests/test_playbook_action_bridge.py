"""A playbook step that names a response verb must reach governed dispatch.

The defect these cover passed every test in the repository while doing
nothing. `_handle_block_ip` and `_handle_isolate_host` returned
``{"action": ..., "simulated": True}`` from inside the engine, reached no
executor, and the run loop recorded SUCCESS — so a playbook an operator
believed contained real response steps contained none, and reported
COMPLETED. Twelve further step types had no handler at all.

The assertions below are therefore about *where the call went* and *what the
step claimed*, not about a return value being non-empty. A handler that
returns a dict is not a step that ran.
"""

from __future__ import annotations

from typing import Any

import pytest
from app.playbook import action_bridge
from app.playbook.engine import RESPONSE_STEP_TYPES, PlaybookEngine, RunStatus, StepStatus
from app.playbook.models import Playbook, PlaybookStep, StepType

pytestmark = pytest.mark.asyncio


def _playbook(*steps: PlaybookStep) -> Playbook:
    return Playbook(id="pb-1", name="Containment", steps=list(steps))


class _Recorder:
    """Stands in for the API hop and records exactly what it was asked."""

    def __init__(self, report: dict[str, Any] | None = None, raises: Exception | None = None) -> None:
        self.calls: list[dict[str, Any]] = []
        self._report = report or {"capability": "?", "status": "executed", "executed": True, "summary": "done"}
        self._raises = raises

    async def __call__(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)
        if self._raises is not None:
            raise self._raises
        return {**self._report, "capability": kwargs["capability"]}


@pytest.fixture
def bridge(monkeypatch: pytest.MonkeyPatch):
    """Install a recorder in place of the HTTP hop and return it."""

    def _install(report: dict[str, Any] | None = None, raises: Exception | None = None) -> _Recorder:
        recorder = _Recorder(report, raises)
        monkeypatch.setattr(action_bridge, "dispatch_step", recorder)
        return recorder

    return _install


class TestEveryResponseVerbReachesDispatch:
    async def test_all_fifteen_response_verbs_dispatch(self, bridge) -> None:
        """Pre-change: three returned `simulated: True` locally and twelve
        had no handler at all."""
        recorder = bridge()
        for step_type in sorted(RESPONSE_STEP_TYPES, key=lambda s: s.value):
            pb = _playbook(PlaybookStep(id="s1", name=step_type.value, type=step_type))
            run = await PlaybookEngine().run(pb, {"tenant_id": "t-1"})
            assert run.step_results[0]["status"] == StepStatus.SUCCESS, step_type.value

        dispatched = [c["capability"] for c in recorder.calls]
        assert sorted(dispatched) == sorted(s.value for s in RESPONSE_STEP_TYPES)

    async def test_the_three_that_used_to_simulate_now_reach_an_executor(self, bridge) -> None:
        """`block_ip`, `isolate_host` and `create_ticket` specifically.

        Named individually because these are the ones the `action.py` comment
        claimed already dispatched "step by step through this service".
        """
        recorder = bridge()
        pb = _playbook(
            PlaybookStep(id="s1", name="block", type=StepType.BLOCK_IP, params={"ip": "203.0.113.10"}),
            PlaybookStep(id="s2", name="isolate", type=StepType.ISOLATE_HOST, params={"host": "ws-042"}),
            PlaybookStep(id="s3", name="ticket", type=StepType.CREATE_TICKET),
        )
        run = await PlaybookEngine().run(pb, {"tenant_id": "t-1"})

        assert run.status == RunStatus.COMPLETED
        assert [c["capability"] for c in recorder.calls] == ["block_ip", "isolate_host", "create_ticket"]
        assert recorder.calls[0]["target"] == "203.0.113.10"
        assert recorder.calls[1]["target"] == "ws-042"
        for result in run.step_results:
            assert "simulated" not in result["result"]

    async def test_each_step_is_dispatched_separately_and_carries_its_own_id(self, bridge) -> None:
        """Per-step grading is the whole design: one request per step, so the
        contract is applied to each verb rather than to the playbook."""
        recorder = bridge()
        pb = _playbook(
            PlaybookStep(id="alpha", name="block", type=StepType.BLOCK_IP, params={"ip": "198.51.100.4"}),
            PlaybookStep(id="beta", name="disable", type=StepType.DISABLE_USER, params={"user": "jdoe"}),
        )
        run = await PlaybookEngine().run(pb, {"tenant_id": "t-1"})

        assert len(recorder.calls) == 2
        assert [c["playbook_step_id"] for c in recorder.calls] == ["alpha", "beta"]
        assert [c["capability"] for c in recorder.calls] == ["block_ip", "disable_user"]
        # Every dispatch names the run, so an isolated host is traceable to
        # the playbook that asked for it.
        assert all(c["playbook_run_id"] == run.run_id for c in recorder.calls)


class TestNoFakeSuccess:
    @pytest.mark.parametrize(
        ("status", "summary"),
        [
            ("pending_approval", "needs an analyst"),
            ("blocked", "blocked by policy"),
            ("simulated", "no vendor was touched"),
            ("dry_run", "previewed"),
            ("no_integration", "no enabled connector"),
            ("unsupported", "no executor is registered"),
        ],
    )
    async def test_a_step_that_did_not_execute_fails(self, bridge, status: str, summary: str) -> None:
        """`executed` is the single field that means a vendor was touched.

        Each of these is a real, distinct outcome and none of them is the
        step doing what it says, so none may be recorded as a success.
        """
        bridge({"status": status, "executed": False, "summary": summary})
        pb = _playbook(PlaybookStep(id="s1", name="isolate", type=StepType.ISOLATE_HOST, params={"host": "ws-1"}))
        run = await PlaybookEngine().run(pb, {"tenant_id": "t-1"})

        assert run.step_results[0]["status"] == StepStatus.FAILED
        assert run.status == RunStatus.FAILED
        assert status in run.step_results[0]["result"]["error"]

    async def test_awaiting_completion_counts_as_executed(self, bridge) -> None:
        """The vendor was touched and the outcome is not known yet.

        Distinct from `pending_approval`, where nothing ran. Failing this one
        would lose an action that is genuinely in flight.
        """
        bridge({"status": "awaiting_completion", "executed": True, "summary": "MDE accepted the acquisition"})
        pb = _playbook(PlaybookStep(id="s1", name="collect", type=StepType.RUN_SCRIPT, params={"host": "ws-1"}))
        run = await PlaybookEngine().run(pb, {"tenant_id": "t-1"})

        assert run.step_results[0]["status"] == StepStatus.SUCCESS
        assert run.step_results[0]["result"]["executed"] is True

    async def test_a_run_whose_response_steps_all_failed_is_not_completed(self, bridge) -> None:
        """The run-level version of the same claim."""
        bridge({"status": "pending_approval", "executed": False, "summary": "held"})
        pb = _playbook(
            PlaybookStep(id="s1", name="block", type=StepType.BLOCK_IP, on_failure="continue", params={"ip": "1.2.3.4"}),
            PlaybookStep(id="s2", name="isolate", type=StepType.ISOLATE_HOST, on_failure="continue", params={"host": "h"}),
        )
        run = await PlaybookEngine().run(pb, {"tenant_id": "t-1"})

        assert run.status == RunStatus.FAILED
        assert "2 of 2 steps failed" in (run.error or "")

    async def test_an_unreachable_bridge_fails_the_step_rather_than_simulating(self, bridge) -> None:
        """Falling back to a preview is how the original defect would return."""
        bridge(raises=action_bridge.BridgeUnavailable("the action service could not be reached"))
        pb = _playbook(PlaybookStep(id="s1", name="isolate", type=StepType.ISOLATE_HOST, params={"host": "ws-1"}))
        run = await PlaybookEngine().run(pb, {"tenant_id": "t-1"})

        assert run.step_results[0]["status"] == StepStatus.FAILED
        assert run.status == RunStatus.FAILED
        assert "could not be reached" in run.step_results[0]["result"]["error"]


class TestWhatTheBridgeSends:
    async def test_a_missing_tenant_is_refused_rather_than_guessed(self) -> None:
        """A response action with no tenant would be a cross-tenant action."""
        with pytest.raises(action_bridge.BridgeUnavailable, match="no tenant"):
            await action_bridge.dispatch_step(capability="isolate_host", tenant_id="")

    async def test_no_service_token_is_a_loud_refusal_not_a_silent_skip(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.delenv("AISOC_AGENTS_SERVICE_TOKEN", raising=False)
        with pytest.raises(action_bridge.BridgeUnavailable, match="AISOC_AGENTS_SERVICE_TOKEN"):
            await action_bridge.dispatch_step(capability="isolate_host", tenant_id="t-1")

    async def test_execution_is_off_by_default_so_a_step_previews(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Copilot is the platform's posture; a playbook does not opt out of it."""
        monkeypatch.delenv("AISOC_PLAYBOOK_ACTIONS_EXECUTE", raising=False)
        assert action_bridge.actions_execute() is False
        monkeypatch.setenv("AISOC_PLAYBOOK_ACTIONS_EXECUTE", "1")
        assert action_bridge.actions_execute() is True

    @pytest.mark.parametrize(
        ("context_value", "expected"),
        [
            (92, 0.92),  # alerts carry confidence as an int 0-100
            (0.92, 0.92),  # the agent carries it as a fraction
            (None, None),  # absent is the lowest band, not a middling default
        ],
    )
    async def test_confidence_reaches_the_matrix_in_the_shape_it_expects(
        self,
        bridge,
        context_value: float | None,
        expected: float | None,
    ) -> None:
        recorder = bridge()
        context: dict[str, Any] = {"tenant_id": "t-1"}
        if context_value is not None:
            context["confidence"] = context_value
        pb = _playbook(PlaybookStep(id="s1", name="isolate", type=StepType.ISOLATE_HOST, params={"host": "h"}))
        await PlaybookEngine().run(pb, context)

        assert recorder.calls[0]["confidence"] == expected

    async def test_a_pinned_vendor_is_forwarded_not_resolved_here(self, bridge) -> None:
        """Which vendor a tenant has is a fact only the API can read."""
        recorder = bridge()
        pb = _playbook(PlaybookStep(id="s1", name="isolate", type=StepType.ISOLATE_HOST, params={"host": "h", "vendor": "sentinelone"}))
        await PlaybookEngine().run(pb, {"tenant_id": "t-1"})

        assert recorder.calls[0]["vendor_id"] == "sentinelone"


class TestApprovalStaysUnbridged:
    async def test_approval_has_no_handler_and_says_why(self) -> None:
        """The one verb with no bridge. It is a pause, and the engine is an
        index walk with nothing to suspend — recorded rather than faked."""
        pb = _playbook(PlaybookStep(id="gate", name="sign-off", type=StepType.APPROVAL))
        run = await PlaybookEngine().run(pb, {"tenant_id": "t-1"})

        result = run.step_results[0]["result"]
        assert run.step_results[0]["status"] == StepStatus.FAILED
        assert result["unimplemented"] is True
        assert result["executed"] is False
        assert "no pause or resume" in result["error"]
        assert "pending_approval" in result["error"], "the reason must name the mechanism that replaced it"


class TestDryRunPreview:
    async def test_a_preview_names_the_verb_and_target_it_would_dispatch(self) -> None:
        """A preview of a containment playbook must read as one."""
        pb = _playbook(PlaybookStep(id="s1", name="isolate", type=StepType.ISOLATE_HOST, params={"host": "ws-042"}))
        run = await PlaybookEngine().run(pb, {"tenant_id": "t-1"}, dry_run=True)

        result = run.step_results[0]["result"]
        assert result["would_dispatch"] == "isolate_host"
        assert result["target"] == "ws-042"
        assert result["executed"] is False
