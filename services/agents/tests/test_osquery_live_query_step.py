"""The ``osquery_live_query`` step, after it stopped being an engine handler.

This file used to drive ``_handle_osquery_live_query`` with the three client
classes injected into ``sys.modules``. That mock was the defect: it supplied
``app.clients.osctrl_client``, which does not exist in the agents image, so
every test passed against an arrangement no deployment ever had. The handler
raised ``ModuleNotFoundError`` on the first line of its import block in
production, and for the one backend that could be reached it would have
called with no credentials, because it read ``auth_config`` off a connector
response whose model documents that the field is deliberately omitted.

The verb is now dispatched to ``services/actions``, where the three clients
live. What is left to test here is the engine's half: the backend picks the
vendor arm, the host comes from the step or the run context, and the timeout
is clamped before it leaves — ``params`` is an untyped dict that bypasses the
Pydantic bound on ``PlaybookStep.timeout_seconds``, which is the whole reason
the runtime clamp exists. The arms themselves are covered in
``services/actions/tests/test_notify_and_osquery_arms.py``.
"""

from __future__ import annotations

from typing import Any

import pytest
from app.playbook import engine as engine_mod
from app.playbook.models import PlaybookStep, StepType

pytestmark = pytest.mark.asyncio


def _step(params: dict[str, Any]) -> PlaybookStep:
    return PlaybookStep(id="s1", name="osquery-step", type=StepType.OSQUERY_LIVE_QUERY, params=params)


@pytest.fixture
def dispatched(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []

    async def _fake_dispatch(**kwargs: Any) -> dict[str, Any]:
        calls.append(kwargs)
        return {"executed": True, "status": "succeeded", "summary": "ran"}

    monkeypatch.setattr(engine_mod.action_bridge, "dispatch_step", _fake_dispatch)
    return calls


async def _run(step: PlaybookStep, context: dict[str, Any] | None = None) -> None:
    await engine_mod._HANDLERS[StepType.OSQUERY_LIVE_QUERY](step, {"tenant_id": "t", **(context or {})}, None)


class TestBackendSelectsTheArm:
    @pytest.mark.parametrize("backend", ["osctrl", "fleetdm", "aisoc_direct"])
    async def test_backend_becomes_the_vendor(self, dispatched: list[dict[str, Any]], backend: str) -> None:
        await _run(_step({"backend": backend, "template": "running_processes", "target_hosts": ["h1"]}))
        assert dispatched[0]["vendor_id"] == backend

    async def test_missing_backend_defaults_to_osctrl(self, dispatched: list[dict[str, Any]]) -> None:
        await _run(_step({"template": "running_processes", "target_hosts": ["h1"]}))
        assert dispatched[0]["vendor_id"] == "osctrl"

    async def test_an_unknown_backend_is_passed_through_not_substituted(self, dispatched: list[dict[str, Any]]) -> None:
        """Dispatch answers ``no_integration`` for a vendor with no arm.

        Substituting a default here would run the query on a fleet the author
        did not name, which is worse than refusing.
        """
        await _run(_step({"backend": "nonexistent", "template": "t", "target_hosts": ["h1"]}))
        assert dispatched[0]["vendor_id"] == "nonexistent"


class TestHostResolution:
    async def test_target_hosts_is_used_when_present(self, dispatched: list[dict[str, Any]]) -> None:
        await _run(_step({"template": "t", "target_hosts": ["h1", "h2"]}))
        assert dispatched[0]["params"]["target_hosts"] == ["h1", "h2"]

    async def test_host_from_context_when_no_target_hosts(self, dispatched: list[dict[str, Any]]) -> None:
        await _run(_step({"template": "t"}), {"host": "context-host"})
        assert dispatched[0]["params"]["target_hosts"] == ["context-host"]
        assert dispatched[0]["target"] == "context-host"


class TestRuntimeTimeoutClamp:
    """``params`` bypasses the Pydantic validator on ``PlaybookStep``.

    Kept from the previous version of this file, retargeted at the function
    that now owns the clamp. See ``test_playbook_models_bounds.py``'s
    ``TestParamsAreNotValidated`` for the matching failure at the model layer.
    """

    async def test_pathological_timeout_is_clamped(self, dispatched: list[dict[str, Any]]) -> None:
        from app.playbook.bounds import DEFAULT_MAX_TIMEOUT_SECONDS

        await _run(_step({"template": "t", "target_hosts": ["h1"], "timeout_seconds": 86_400}))
        assert dispatched[0]["params"]["timeout_seconds"] == DEFAULT_MAX_TIMEOUT_SECONDS

    async def test_negative_timeout_is_clamped_to_min(self, dispatched: list[dict[str, Any]]) -> None:
        from app.playbook.bounds import MIN_TIMEOUT_SECONDS

        await _run(_step({"template": "t", "target_hosts": ["h1"], "timeout_seconds": -5}))
        assert dispatched[0]["params"]["timeout_seconds"] == MIN_TIMEOUT_SECONDS

    async def test_missing_timeout_uses_the_handler_default(self, dispatched: list[dict[str, Any]]) -> None:
        await _run(_step({"template": "t", "target_hosts": ["h1"]}))
        assert dispatched[0]["params"]["timeout_seconds"] == 60

    async def test_in_range_timeout_passes_through(self, dispatched: list[dict[str, Any]]) -> None:
        await _run(_step({"template": "t", "target_hosts": ["h1"], "timeout_seconds": 120}))
        assert dispatched[0]["params"]["timeout_seconds"] == 120

    async def test_string_timeout_is_parsed_not_dropped(self, dispatched: list[dict[str, Any]]) -> None:
        """YAML may surface numeric strings; the clamp must parse them."""
        await _run(_step({"template": "t", "target_hosts": ["h1"], "timeout_seconds": "90"}))
        assert dispatched[0]["params"]["timeout_seconds"] == 90

    async def test_bool_timeout_does_not_become_one(self, dispatched: list[dict[str, Any]]) -> None:
        """``timeout_seconds: true`` must not coerce to 1.

        Every query would time out immediately, which is a quiet denial of
        service wearing a configuration typo.
        """
        await _run(_step({"template": "t", "target_hosts": ["h1"], "timeout_seconds": True}))
        assert dispatched[0]["params"]["timeout_seconds"] == 60

    async def test_an_operator_cannot_uncap_the_runtime_ceiling(
        self, dispatched: list[dict[str, Any]], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from app.playbook.bounds import ABSOLUTE_MAX_PARAM_TIMEOUT_SECONDS

        monkeypatch.setenv("AISOC_PLAYBOOK_MAX_TIMEOUT_SECONDS", "100000")
        await _run(_step({"template": "t", "target_hosts": ["h1"], "timeout_seconds": 50_000}))
        assert dispatched[0]["params"]["timeout_seconds"] == ABSOLUTE_MAX_PARAM_TIMEOUT_SECONDS


async def test_the_agents_image_no_longer_imports_the_actions_clients() -> None:
    """A negative control for the defect this item removed.

    ``app.clients`` is the package the old handler imported, and it has never
    existed in this service. Asserting it is still absent is what makes the
    rest of this file a statement about production rather than about a
    ``sys.modules`` arrangement a test set up.
    """
    import importlib.util

    assert importlib.util.find_spec("app.clients") is None
    assert "app.clients" not in engine_mod.__dict__
