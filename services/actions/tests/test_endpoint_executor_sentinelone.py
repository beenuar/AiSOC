"""
Phase 3.1 — integration tests that the endpoint executors dispatch
to SentinelOne when ``s1_*`` credentials are present and CrowdStrike
/ Defender credentials are not.

These tests don't talk to real S1; they stub the SentinelOne
client at the executor's import boundary so we can verify the
vendor selection logic without coupling to httpx-level details
(those are covered by ``test_sentinelone_client.py``).

Why a separate file from ``test_live_action_builtins.py``: that
file exercises the live-action dispatcher (the new vendor_id +
capability layer). The endpoint executors here are the *legacy*
ActionType-keyed router that still backs the human-in-the-loop
approval UI. Both layers must support SentinelOne for the playbook
to behave consistently regardless of which router fires.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from app.executors.endpoint import (
    IsolateHostExecutor,
    KillProcessExecutor,
    QuarantineFileExecutor,
    RunAVScanExecutor,
)
from app.models.action import ActionRequest, ActionStatus, ActionType


def _request(action_type: ActionType, target: str = "web-01", **params: object) -> ActionRequest:
    return ActionRequest(
        incident_id=uuid4(),
        tenant_id=uuid4(),
        action_type=action_type,
        target=target,
        parameters={
            "s1_console_url": "https://s1-console.example.com",
            "s1_api_token": "fake-token",
            **params,
        },
    )


class _FakeS1:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple, dict]] = []

    async def contain_host(self, hostname: str) -> dict:
        self.calls.append(("contain_host", (hostname,), {}))
        return {"success": True, "action": "contain_host", "agent_uuid": "u-1"}

    async def quarantine_file(self, hostname: str, file_path: str) -> dict:
        self.calls.append(("quarantine_file", (hostname, file_path), {}))
        return {"success": True, "action": "quarantine_file"}

    async def kill_process(self, hostname: str, *, pid: int | None = None, process_name: str | None = None) -> dict:
        self.calls.append(("kill_process", (hostname,), {"pid": pid, "process_name": process_name}))
        if not process_name:
            raise NotImplementedError("SentinelOne cannot kill by PID alone")
        return {"success": True, "action": "kill_process"}

    async def run_av_scan(self, hostname: str, scan_type: str = "Full") -> dict:
        self.calls.append(("run_av_scan", (hostname,), {"scan_type": scan_type}))
        return {"success": True, "action": "run_av_scan"}


@pytest.fixture
def fake_s1(monkeypatch: pytest.MonkeyPatch) -> _FakeS1:
    """Replace the executor's ``_s1_client`` factory with a stub.

    Patching the factory (rather than the SentinelOneClient class)
    keeps the test focused on the vendor-selection logic and avoids
    re-asserting URL paths that ``test_sentinelone_client.py``
    already covers.
    """
    from app.executors import endpoint

    fake = _FakeS1()
    monkeypatch.setattr(endpoint, "_s1_client", lambda params: fake)
    return fake


@pytest.mark.asyncio
async def test_isolate_host_uses_sentinelone_when_credentials_present(fake_s1: _FakeS1) -> None:
    req = _request(ActionType.ISOLATE_HOST)
    result = await IsolateHostExecutor().execute(req)

    assert result.status == ActionStatus.COMPLETED
    assert result.rollback_data["vendor"] == "sentinelone"
    assert fake_s1.calls == [("contain_host", ("web-01",), {})]


@pytest.mark.asyncio
async def test_quarantine_file_dispatches_to_sentinelone(fake_s1: _FakeS1) -> None:
    req = _request(ActionType.QUARANTINE_FILE, file_path="/tmp/evil.bin", file_hash="abc123")
    result = await QuarantineFileExecutor().execute(req)

    assert result.status == ActionStatus.COMPLETED
    assert result.rollback_data["vendor"] == "sentinelone"
    assert fake_s1.calls[0][1] == ("web-01", "/tmp/evil.bin")


@pytest.mark.asyncio
async def test_kill_process_falls_through_to_simulation_when_s1_unsupported(monkeypatch: pytest.MonkeyPatch) -> None:
    """When S1 raises NotImplementedError (e.g. PID-only call with no
    process_name), the executor must log + fall through to simulation
    rather than report a vendor failure. Other vendors would have
    worked; the playbook should remain advisable to swap vendors."""
    from app.executors import endpoint

    class _AlwaysUnsupportedS1:
        async def kill_process(self, *args: object, **kwargs: object) -> dict:
            raise NotImplementedError("SentinelOne can't kill by PID alone")

    monkeypatch.setattr(endpoint, "_s1_client", lambda params: _AlwaysUnsupportedS1())

    req = _request(ActionType.KILL_PROCESS, pid=1234)
    # Suppress the hostname-defaults-to-target shortcut: pass an
    # explicit empty process_name so the simulated S1's
    # NotImplementedError fires for the right reason.
    req.parameters["process_name"] = ""
    result = await KillProcessExecutor().execute(req)

    assert result.status == ActionStatus.COMPLETED  # simulation success
    assert result.output["pid"] == 1234
    assert "Simulation mode" in result.output["note"]


@pytest.mark.asyncio
async def test_kill_process_with_process_name_dispatches_to_sentinelone(fake_s1: _FakeS1) -> None:
    req = _request(ActionType.KILL_PROCESS, process_name="evil.exe")
    result = await KillProcessExecutor().execute(req)

    assert result.status == ActionStatus.COMPLETED
    assert result.rollback_data == {"vendor": "sentinelone"}


@pytest.mark.asyncio
async def test_run_av_scan_dispatches_to_sentinelone(fake_s1: _FakeS1) -> None:
    req = _request(ActionType.RUN_AV_SCAN, scan_type="Quick")
    result = await RunAVScanExecutor().execute(req)

    assert result.status == ActionStatus.COMPLETED
    assert result.rollback_data == {"vendor": "sentinelone"}
    assert fake_s1.calls[0][2]["scan_type"] == "Quick"


@pytest.mark.asyncio
async def test_isolate_host_simulation_note_lists_all_three_vendors() -> None:
    """Without credentials the simulation note should advertise
    every supported vendor so the operator picks the easiest path
    forward."""
    req = ActionRequest(
        incident_id=uuid4(),
        tenant_id=uuid4(),
        action_type=ActionType.ISOLATE_HOST,
        target="web-01",
        parameters={},
    )
    result = await IsolateHostExecutor().execute(req)

    note = result.output["note"]
    assert "cs_client_id" in note
    assert "mde_tenant_id" in note
    assert "s1_console_url" in note
