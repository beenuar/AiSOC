"""
Unit tests for the osquery_live_query playbook step handler.

Tests exercise ``_handle_osquery_live_query`` directly with patched client
classes injected via sys.modules, so no real network calls are made.
"""

from __future__ import annotations

import sys
import types
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

# ---------------------------------------------------------------------------
# Inject stub modules BEFORE importing the engine (engine does lazy imports
# inside the handler, so sys.modules stubs are enough).
# ---------------------------------------------------------------------------


class AllowlistError(Exception):
    pass


class OsctrlError(Exception):
    pass


class FleetDMError(Exception):
    pass


def _inject_stubs(
    *,
    osctrl_live_query: Any = None,
    fleetdm_live_query: Any = None,
    direct_live_query: Any = None,
) -> None:
    """(Re-)inject stub modules with the provided live_query implementations."""

    # --- osquery_allowlist ---
    al_mod = types.ModuleType("app.clients.osquery_allowlist")
    al_mod.AllowlistError = AllowlistError  # type: ignore[attr-defined]
    sys.modules["app.clients.osquery_allowlist"] = al_mod

    # --- osctrl_client ---
    osc_instance = AsyncMock()
    if osctrl_live_query is not None:
        osc_instance.live_query = osctrl_live_query
    osc_cls = MagicMock(return_value=osc_instance)
    osc_mod = types.ModuleType("app.clients.osctrl_client")
    osc_mod.OsctrlClient = osc_cls  # type: ignore[attr-defined]
    osc_mod.OsctrlError = OsctrlError  # type: ignore[attr-defined]
    sys.modules["app.clients.osctrl_client"] = osc_mod

    # --- fleetdm_client ---
    fleet_instance = AsyncMock()
    if fleetdm_live_query is not None:
        fleet_instance.live_query = fleetdm_live_query
    fleet_cls = MagicMock(return_value=fleet_instance)
    fleet_mod = types.ModuleType("app.clients.fleetdm_client")
    fleet_mod.FleetDMClient = fleet_cls  # type: ignore[attr-defined]
    fleet_mod.FleetDMError = FleetDMError  # type: ignore[attr-defined]
    sys.modules["app.clients.fleetdm_client"] = fleet_mod

    # --- aisoc_direct_client ---
    direct_instance = AsyncMock()
    if direct_live_query is not None:
        direct_instance.live_query = direct_live_query
    direct_cls = MagicMock(return_value=direct_instance)
    direct_mod = types.ModuleType("app.clients.aisoc_direct_client")
    direct_mod.AiSOCDirectClient = direct_cls  # type: ignore[attr-defined]
    sys.modules["app.clients.aisoc_direct_client"] = direct_mod

    return osc_instance, fleet_instance, direct_instance  # type: ignore[return-value]


# Perform an initial injection before the engine import so sys.modules is
# populated when the engine module is loaded (even though the imports inside
# the handler are deferred, Python still needs the top-level `app` package).
_inject_stubs()

from app.playbook.engine import _handle_osquery_live_query  # noqa: E402
from app.playbook.models import PlaybookStep, StepType  # noqa: E402

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _step(params: dict[str, Any]) -> PlaybookStep:
    return PlaybookStep(
        id="s1",
        name="osquery-step",
        type=StepType.OSQUERY_LIVE_QUERY,
        params=params,
    )


def _ctx(**kwargs: Any) -> dict[str, Any]:
    base: dict[str, Any] = {"host": "host1", "connector_instance_id": ""}
    base.update(kwargs)
    return base


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestMissingTemplate:
    @pytest.mark.asyncio
    async def test_missing_template_returns_error(self) -> None:
        _inject_stubs()
        step = _step({"backend": "osctrl", "target_hosts": ["h1"], "base_url": "http://osc", "api_token": "t"})
        step.params.pop("template", None)
        result = await _handle_osquery_live_query(step, _ctx(), MagicMock())
        assert "error" in result
        assert result.get("partial") is True


class TestUnknownBackend:
    @pytest.mark.asyncio
    async def test_unknown_backend_returns_error(self) -> None:
        _inject_stubs()
        step = _step(
            {
                "backend": "nonexistent_backend",
                "template": "running_processes",
                "target_hosts": ["h1"],
            }
        )
        result = await _handle_osquery_live_query(step, _ctx(), MagicMock())
        assert "error" in result
        assert "nonexistent_backend" in result["error"]
        assert result.get("partial") is True


class TestAllowlistViolation:
    @pytest.mark.asyncio
    async def test_allowlist_error_caught(self) -> None:
        lq = AsyncMock(side_effect=AllowlistError("bad template"))
        _inject_stubs(osctrl_live_query=lq)

        step = _step(
            {
                "backend": "osctrl",
                "template": "running_processes",
                "target_hosts": ["h1"],
                "base_url": "http://osc",
                "api_token": "tok",
            }
        )
        result = await _handle_osquery_live_query(step, _ctx(), MagicMock())
        assert "error" in result
        assert "allowlist" in result["error"]
        assert result.get("partial") is True


class TestOsctrlDispatch:
    @pytest.mark.asyncio
    async def test_osctrl_backend_dispatches_correctly(self) -> None:
        expected = {"results": {"h1": [{"pid": "1"}]}, "partial": False}
        lq = AsyncMock(return_value=expected)
        osc_instance, _, _ = _inject_stubs(osctrl_live_query=lq)

        step = _step(
            {
                "backend": "osctrl",
                "template": "running_processes",
                "target_hosts": ["h1"],
                "base_url": "http://osc",
                "environment": "prod",
                "api_token": "tok",
            }
        )
        result = await _handle_osquery_live_query(step, _ctx(), MagicMock())
        assert result == expected
        lq.assert_awaited_once_with(["h1"], "running_processes", {}, 60)


class TestFleetDMDispatch:
    @pytest.mark.asyncio
    async def test_fleetdm_backend_dispatches_correctly(self) -> None:
        expected = {"results": {"h1": [{"user": "root"}]}, "partial": False}
        lq = AsyncMock(return_value=expected)
        _, fleet_instance, _ = _inject_stubs(fleetdm_live_query=lq)

        step = _step(
            {
                "backend": "fleetdm",
                "template": "logged_in_users",
                "target_hosts": ["h1"],
                "base_url": "http://fleet",
                "api_token": "fleet-tok",
            }
        )
        result = await _handle_osquery_live_query(step, _ctx(), MagicMock())
        assert result == expected
        lq.assert_awaited_once_with(["h1"], "logged_in_users", {}, 60)


class TestAiSOCDirectStub:
    @pytest.mark.asyncio
    async def test_aisoc_direct_not_implemented_is_safe(self) -> None:
        lq = AsyncMock(side_effect=NotImplementedError("PR4: not yet implemented"))
        _inject_stubs(direct_live_query=lq)

        step = _step(
            {
                "backend": "aisoc_direct",
                "template": "active_connections",
                "target_hosts": ["h1"],
                "base_url": "http://tls",
                "api_token": "x",
            }
        )
        result = await _handle_osquery_live_query(step, _ctx(), MagicMock())
        assert result.get("stub") is True
        assert result.get("partial") is True
        assert "PR4" in result.get("error", "")


class TestTemplateParams:
    @pytest.mark.asyncio
    async def test_template_params_forwarded(self) -> None:
        lq = AsyncMock(return_value={"results": {}, "partial": False})
        _inject_stubs(osctrl_live_query=lq)

        step = _step(
            {
                "backend": "osctrl",
                "template": "running_processes",
                "template_params": {"limit": 5},
                "target_hosts": ["h1"],
                "base_url": "http://osc",
                "api_token": "tok",
                "timeout_seconds": 30,
            }
        )
        await _handle_osquery_live_query(step, _ctx(), MagicMock())
        lq.assert_awaited_once_with(["h1"], "running_processes", {"limit": 5}, 30)


class TestHostFallback:
    @pytest.mark.asyncio
    async def test_host_from_context_when_no_target_hosts(self) -> None:
        lq = AsyncMock(return_value={"results": {}, "partial": False})
        _inject_stubs(osctrl_live_query=lq)

        step = _step(
            {
                "backend": "osctrl",
                "template": "running_processes",
                "base_url": "http://osc",
                "api_token": "tok",
                # No target_hosts — should fall back to context["host"]
            }
        )
        ctx = _ctx(host="context-host")
        await _handle_osquery_live_query(step, ctx, MagicMock())

        call_args = lq.call_args
        assert "context-host" in call_args[0][0]


# ---------------------------------------------------------------------------
# H-7 / Batch 10 — runtime clamp tests for params.timeout_seconds.
#
# These exercise the *runtime* defence (engine.clamp_timeout) rather than the
# Pydantic field cap, because params is an untyped dict and a malicious or
# malformed playbook can bypass the Pydantic validator entirely. See
# ``test_playbook_models_bounds.py::TestParamsAreNotValidated`` for the
# matching failure case at the model layer.
# ---------------------------------------------------------------------------


class TestRuntimeTimeoutClamp:
    @pytest.mark.asyncio
    async def test_pathological_timeout_is_clamped_to_default_max(self) -> None:
        """An attacker passes ``timeout_seconds: 86400`` (1 day).

        Without the runtime clamp, the connector thread would pin for 24h.
        With the clamp, the value collapses to DEFAULT_MAX_TIMEOUT_SECONDS.
        """
        from app.playbook.bounds import DEFAULT_MAX_TIMEOUT_SECONDS

        lq = AsyncMock(return_value={"results": {}, "partial": False})
        _inject_stubs(osctrl_live_query=lq)

        step = _step(
            {
                "backend": "osctrl",
                "template": "running_processes",
                "target_hosts": ["h1"],
                "base_url": "http://osc",
                "api_token": "tok",
                "timeout_seconds": 86_400,  # pathological
            }
        )
        await _handle_osquery_live_query(step, _ctx(), MagicMock())

        # Backend client must be called with the clamped value, not 86400.
        call_args = lq.call_args
        forwarded_timeout = call_args[0][3]  # 4th positional arg
        assert forwarded_timeout == DEFAULT_MAX_TIMEOUT_SECONDS

    @pytest.mark.asyncio
    async def test_negative_timeout_is_clamped_to_min(self) -> None:
        from app.playbook.bounds import MIN_TIMEOUT_SECONDS

        lq = AsyncMock(return_value={"results": {}, "partial": False})
        _inject_stubs(osctrl_live_query=lq)

        step = _step(
            {
                "backend": "osctrl",
                "template": "running_processes",
                "target_hosts": ["h1"],
                "base_url": "http://osc",
                "api_token": "tok",
                "timeout_seconds": -5,
            }
        )
        await _handle_osquery_live_query(step, _ctx(), MagicMock())

        call_args = lq.call_args
        forwarded_timeout = call_args[0][3]
        assert forwarded_timeout == MIN_TIMEOUT_SECONDS

    @pytest.mark.asyncio
    async def test_missing_timeout_uses_handler_default(self) -> None:
        """When params omits timeout_seconds, the handler default (60) wins."""
        lq = AsyncMock(return_value={"results": {}, "partial": False})
        _inject_stubs(osctrl_live_query=lq)

        step = _step(
            {
                "backend": "osctrl",
                "template": "running_processes",
                "target_hosts": ["h1"],
                "base_url": "http://osc",
                "api_token": "tok",
                # No timeout_seconds in params at all.
            }
        )
        await _handle_osquery_live_query(step, _ctx(), MagicMock())

        call_args = lq.call_args
        forwarded_timeout = call_args[0][3]
        assert forwarded_timeout == 60

    @pytest.mark.asyncio
    async def test_in_range_timeout_passes_through(self) -> None:
        lq = AsyncMock(return_value={"results": {}, "partial": False})
        _inject_stubs(osctrl_live_query=lq)

        step = _step(
            {
                "backend": "osctrl",
                "template": "running_processes",
                "target_hosts": ["h1"],
                "base_url": "http://osc",
                "api_token": "tok",
                "timeout_seconds": 120,
            }
        )
        await _handle_osquery_live_query(step, _ctx(), MagicMock())

        call_args = lq.call_args
        forwarded_timeout = call_args[0][3]
        assert forwarded_timeout == 120

    @pytest.mark.asyncio
    async def test_string_timeout_is_parsed_not_dropped(self) -> None:
        """YAML may surface numeric strings; the clamp must parse them."""
        lq = AsyncMock(return_value={"results": {}, "partial": False})
        _inject_stubs(osctrl_live_query=lq)

        step = _step(
            {
                "backend": "osctrl",
                "template": "running_processes",
                "target_hosts": ["h1"],
                "base_url": "http://osc",
                "api_token": "tok",
                "timeout_seconds": "90",  # string from YAML
            }
        )
        await _handle_osquery_live_query(step, _ctx(), MagicMock())

        call_args = lq.call_args
        forwarded_timeout = call_args[0][3]
        assert forwarded_timeout == 90

    @pytest.mark.asyncio
    async def test_bool_timeout_does_not_become_one(self) -> None:
        """``timeout_seconds: true`` MUST NOT coerce to 1 — that would silently
        cause every osquery to time out immediately, which is a sneaky DoS.
        """
        lq = AsyncMock(return_value={"results": {}, "partial": False})
        _inject_stubs(osctrl_live_query=lq)

        step = _step(
            {
                "backend": "osctrl",
                "template": "running_processes",
                "target_hosts": ["h1"],
                "base_url": "http://osc",
                "api_token": "tok",
                "timeout_seconds": True,  # malformed
            }
        )
        await _handle_osquery_live_query(step, _ctx(), MagicMock())

        call_args = lq.call_args
        forwarded_timeout = call_args[0][3]
        # Falls back to the handler default, NOT to int(True) == 1.
        assert forwarded_timeout == 60

    @pytest.mark.asyncio
    async def test_param_cap_is_runtime_ceiling_not_field_cap(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The runtime ceiling is the *param* cap (15 min), not the looser
        Pydantic field cap (1h). This pins the layered defence: approval
        steps may declare timeout=3600 on the typed field, but params-driven
        values cannot exceed the runtime cap.
        """
        from app.playbook.bounds import ABSOLUTE_MAX_PARAM_TIMEOUT_SECONDS

        # Operator typo: setting AISOC_PLAYBOOK_MAX_TIMEOUT_SECONDS=100000 must
        # NOT silently uncap the runtime guard.
        monkeypatch.setenv("AISOC_PLAYBOOK_MAX_TIMEOUT_SECONDS", "100000")

        lq = AsyncMock(return_value={"results": {}, "partial": False})
        _inject_stubs(osctrl_live_query=lq)

        step = _step(
            {
                "backend": "osctrl",
                "template": "running_processes",
                "target_hosts": ["h1"],
                "base_url": "http://osc",
                "api_token": "tok",
                "timeout_seconds": 50_000,  # would exceed the param cap
            }
        )
        await _handle_osquery_live_query(step, _ctx(), MagicMock())

        call_args = lq.call_args
        forwarded_timeout = call_args[0][3]
        assert forwarded_timeout == ABSOLUTE_MAX_PARAM_TIMEOUT_SECONDS
