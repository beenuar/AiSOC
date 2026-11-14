"""
T2.2 — ``/investigate`` orchestrator selection via ``AISOC_INVESTIGATE_USE_ROUTER``.

These tests pin the call-time dispatcher in
:mod:`app.api.investigate` that routes traffic between the legacy
:class:`InvestigatorOrchestrator` and the four-agent
:class:`RouterOrchestrator` based on an environment flag. They cover:

* Default-off behaviour (no env var → investigator path).
* Truthy / falsey parsing of the env var, including case insensitivity.
* The flag is re-read **on every call**, so operators can flip it
  without restarting the agents service.
* Parameter pass-through is identical regardless of which orchestrator
  is selected — the swap must be transparent to callers.

We don't spin up the FastAPI app here: the dispatcher is a pure
selector, and end-to-end behaviour of each orchestrator already has
dedicated test files. Patching the two ``stream`` / ``stream_kwargs``
entry points and asserting which one ran is a tighter spec for the
flag itself.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest

_AGENTS_ROOT = Path(__file__).resolve().parents[1]
if str(_AGENTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_AGENTS_ROOT))

from app.api import investigate as investigate_mod  # noqa: E402

FLAG = investigate_mod.USE_ROUTER_FLAG


# ---------------------------------------------------------------------------
# Flag parsing
# ---------------------------------------------------------------------------


def test_flag_defaults_off_when_env_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(FLAG, raising=False)
    assert investigate_mod.is_router_investigate_enabled() is False


@pytest.mark.parametrize(
    "value",
    ["1", "true", "TRUE", "True", "yes", "YES", "on", "On", "enabled", "ENABLED"],
)
def test_flag_truthy_values(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv(FLAG, value)
    assert investigate_mod.is_router_investigate_enabled() is True


@pytest.mark.parametrize(
    "value",
    ["", "0", "false", "no", "off", "disabled", "FALSE", "anything-else", "  "],
)
def test_flag_falsey_values(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv(FLAG, value)
    assert investigate_mod.is_router_investigate_enabled() is False


def test_flag_tolerates_whitespace(monkeypatch: pytest.MonkeyPatch) -> None:
    """Operators often paste with trailing whitespace; treat ``"  true  "`` as
    truthy so a stray newline in a .env file doesn't silently flip the path."""
    monkeypatch.setenv(FLAG, "  true  ")
    assert investigate_mod.is_router_investigate_enabled() is True


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------


@pytest.fixture
def patched_orchestrators(monkeypatch: pytest.MonkeyPatch) -> dict[str, list[dict[str, Any]]]:
    """Replace both orchestrator entry points with recording shims.

    Each shim returns an empty async generator so callers can iterate
    the result like a real stream. The list captured per orchestrator
    is the kwargs that arrived at that path.
    """
    calls: dict[str, list[dict[str, Any]]] = {"investigator": [], "router": []}

    async def _empty() -> Any:
        if False:  # pragma: no cover - generator stub
            yield {}

    def _fake_investigator_stream(**kwargs: Any):
        calls["investigator"].append(kwargs)
        return _empty()

    def _fake_router_stream_kwargs(**kwargs: Any):
        calls["router"].append(kwargs)
        return _empty()

    monkeypatch.setattr(investigate_mod._orch, "stream", _fake_investigator_stream, raising=True)
    monkeypatch.setattr(
        investigate_mod._router_orch,
        "stream_kwargs",
        _fake_router_stream_kwargs,
        raising=True,
    )
    return calls


def _exhaust(stream: Any) -> None:
    async def _go() -> None:
        async for _ in stream:
            pass

    asyncio.run(_go())


def test_dispatch_uses_investigator_when_flag_unset(
    monkeypatch: pytest.MonkeyPatch,
    patched_orchestrators: dict[str, list[dict[str, Any]]],
) -> None:
    monkeypatch.delenv(FLAG, raising=False)

    run_id = uuid4()
    stream = investigate_mod._investigate_stream(
        case_id="case-1",
        alert_summary="Suspicious OAuth consent",
        raw_alert={"sender": "x@y.example"},
        tenant_id="tenant-a",
        run_id=run_id,
    )
    _exhaust(stream)

    assert patched_orchestrators["investigator"], "investigator path should fire"
    assert not patched_orchestrators["router"], "router path must stay quiet"
    (call,) = patched_orchestrators["investigator"]
    assert call == {
        "case_id": "case-1",
        "alert_summary": "Suspicious OAuth consent",
        "raw_alert": {"sender": "x@y.example"},
        "tenant_id": "tenant-a",
        "run_id": run_id,
    }


def test_dispatch_uses_router_when_flag_set(
    monkeypatch: pytest.MonkeyPatch,
    patched_orchestrators: dict[str, list[dict[str, Any]]],
) -> None:
    monkeypatch.setenv(FLAG, "1")

    run_id = uuid4()
    stream = investigate_mod._investigate_stream(
        case_id="case-2",
        alert_summary="Phishing → identity → cloud",
        raw_alert={"urls": ["https://bad.example"]},
        tenant_id="tenant-b",
        run_id=run_id,
    )
    _exhaust(stream)

    assert patched_orchestrators["router"], "router path should fire"
    assert not patched_orchestrators["investigator"], "investigator must stay quiet"
    (call,) = patched_orchestrators["router"]
    assert call == {
        "case_id": "case-2",
        "alert_summary": "Phishing → identity → cloud",
        "raw_alert": {"urls": ["https://bad.example"]},
        "tenant_id": "tenant-b",
        "run_id": run_id,
    }


def test_flag_is_read_each_call_not_at_import(
    monkeypatch: pytest.MonkeyPatch,
    patched_orchestrators: dict[str, list[dict[str, Any]]],
) -> None:
    """Flipping the env var mid-process must take effect on the next call.

    If the flag were cached at import time, operators couldn't gradually
    cut traffic over to the router without restarting the service.
    """
    monkeypatch.delenv(FLAG, raising=False)
    _exhaust(
        investigate_mod._investigate_stream(
            case_id="c-a",
            alert_summary="first",
            raw_alert={},
            tenant_id="t",
        )
    )

    monkeypatch.setenv(FLAG, "true")
    _exhaust(
        investigate_mod._investigate_stream(
            case_id="c-b",
            alert_summary="second",
            raw_alert={},
            tenant_id="t",
        )
    )

    monkeypatch.delenv(FLAG, raising=False)
    _exhaust(
        investigate_mod._investigate_stream(
            case_id="c-c",
            alert_summary="third",
            raw_alert={},
            tenant_id="t",
        )
    )

    investigator_ids = [c["case_id"] for c in patched_orchestrators["investigator"]]
    router_ids = [c["case_id"] for c in patched_orchestrators["router"]]
    assert investigator_ids == ["c-a", "c-c"]
    assert router_ids == ["c-b"]


def test_dispatch_omits_run_id_when_not_supplied(
    monkeypatch: pytest.MonkeyPatch,
    patched_orchestrators: dict[str, list[dict[str, Any]]],
) -> None:
    """Both paths must accept ``run_id=None`` and let the orchestrator mint one.

    The endpoint passes ``run_uuid`` straight through from a freshly
    minted ``uuid4()`` today, but the WebSocket path doesn't supply
    one. Make sure the dispatcher doesn't accidentally drop the kwarg.
    """
    monkeypatch.setenv(FLAG, "1")
    _exhaust(
        investigate_mod._investigate_stream(
            case_id="c-router-no-run",
            alert_summary="x",
            raw_alert={},
            tenant_id="t",
        )
    )

    monkeypatch.delenv(FLAG, raising=False)
    _exhaust(
        investigate_mod._investigate_stream(
            case_id="c-inv-no-run",
            alert_summary="x",
            raw_alert={},
            tenant_id="t",
        )
    )

    (router_call,) = patched_orchestrators["router"]
    (inv_call,) = patched_orchestrators["investigator"]
    assert router_call["run_id"] is None
    assert inv_call["run_id"] is None


def test_module_state_unchanged_by_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    """Sanity: the flag never re-instantiates the orchestrators (they're
    process-singletons), and both module attributes survive a flag flip."""
    orig_investigator = investigate_mod._orch
    orig_router = investigate_mod._router_orch

    monkeypatch.setenv(FLAG, "1")
    assert investigate_mod.is_router_investigate_enabled() is True
    monkeypatch.delenv(FLAG, raising=False)
    assert investigate_mod.is_router_investigate_enabled() is False

    assert investigate_mod._orch is orig_investigator
    assert investigate_mod._router_orch is orig_router


# ---------------------------------------------------------------------------
# Defensive: signature should accept the kwargs the endpoint actually passes
# ---------------------------------------------------------------------------


def test_dispatcher_accepts_uuid_run_id(
    monkeypatch: pytest.MonkeyPatch,
    patched_orchestrators: dict[str, list[dict[str, Any]]],
) -> None:
    """``_run_and_store`` always supplies ``run_id`` as a UUID instance.

    Regression guard against a future refactor that types ``run_id``
    too narrowly (e.g. ``str``).
    """
    monkeypatch.delenv(FLAG, raising=False)
    run_id: UUID = uuid4()
    _exhaust(
        investigate_mod._investigate_stream(
            case_id="case",
            alert_summary="x",
            raw_alert={},
            tenant_id="default",
            run_id=run_id,
        )
    )
    (call,) = patched_orchestrators["investigator"]
    assert isinstance(call["run_id"], UUID)
    assert call["run_id"] == run_id
