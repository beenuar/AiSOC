"""
Integration tests for the router triage API — T2.2 (v8.0).

These tests cover the new ``/api/v1/cases/{case_id}/triage`` endpoint
that wires :class:`RouterOrchestrator` into HTTP. They are deliberately
narrow (no real LLM calls): every sub-agent runner is monkeypatched to
a deterministic shim so the test suite stays fast and hermetic.

Gates exercised
---------------

* Endpoint accepts a POST, returns a ``run_id``, and reports the
  resolved topology (parallel / sequential) in the response.
* ``AISOC_AGENT_PARALLEL_TOPOLOGY`` env flag flips the topology used by
  the background task.
* Explicit ``topology`` field in the request body overrides the env
  flag for that run.
* Poll endpoint returns the final state with verdict, signals,
  topology, and wall-clock telemetry once the background task completes.
* Invalid ``topology`` values return ``400 Bad Request``.
* Polling an unknown run id returns ``404``.

The realtime emit helper is patched to a no-op so the tests don't need
a running realtime service.
"""

from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

_AGENTS_ROOT = Path(__file__).resolve().parents[1]
if str(_AGENTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_AGENTS_ROOT))

from app.api import triage as triage_module  # noqa: E402
from app.api.triage import router as triage_router  # noqa: E402
from app.models.state import AgentStatus, InvestigationState  # noqa: E402
from app.orchestrator import PARALLEL_TOPOLOGY_FLAG  # noqa: E402

SUBAGENT_SLEEP_MS = 10
AUTO_TRIAGE_SLEEP_MS = 5


def _build_app() -> FastAPI:
    """Construct a fresh FastAPI app with only the triage router mounted."""
    # Clear any cross-test state from the in-memory run store.
    triage_module._triage_runs.clear()
    app = FastAPI()
    app.include_router(triage_router)
    return app


def _multi_signal_payload() -> dict[str, Any]:
    """Body that triggers all four sub-agents under the classifier."""
    return {
        "alert_summary": (
            "Spear-phishing email led to credential theft on aws_iam role; "
            "impossible-travel login from Berlin then bulk download to attacker infra."
        ),
        "raw_alert": {
            "sender": "compliance@trusted-partner.example",
            "subject": "Action required: contract renewal",
            "urls": ["https://contract-renewal[.]example/login"],
            "username": "alice@corp.example",
            "user_email": "alice@corp.example",
            "source_ip": "203.0.113.42",
            "source_geo": "Berlin, DE",
            "auth_method": "saml",
            "mfa_status": "challenged",
            "cloud_provider": "aws",
            "region": "eu-west-1",
            "account_id": "111122223333",
            "resource_arn": "arn:aws:s3:::corp-backups",
            "principal_arn": "arn:aws:iam::111122223333:role/DataAnalyst",
            "data_volume_mb": 4096,
            "file_count": 871,
            "destination_domain": "attacker[.]example",
            "is_off_hours": True,
        },
        "tenant_id": "acme",
        "incident_id": "INC-PH-LATERAL",
    }


def _patch_runners(monkeypatch: pytest.MonkeyPatch, *, auto_close: bool = False) -> dict[str, list[str]]:
    """Replace the five LLM-backed runners with deterministic shims.

    Mirrors the pattern used by ``test_orchestrator_parallel.py`` so the
    integration test exercises the *same* router runtime the unit tests
    exercise — only the entry surface (HTTP POST vs direct call) differs.
    """
    call_log: dict[str, list[str]] = {
        "auto_triage": [],
        "phishing": [],
        "identity": [],
        "cloud": [],
        "insider": [],
    }

    async def fake_auto_triage(state: InvestigationState) -> InvestigationState:
        await asyncio.sleep(AUTO_TRIAGE_SLEEP_MS / 1000.0)
        state.iteration_count += 1
        state.status = AgentStatus.COMPLETED if auto_close else AgentStatus.RUNNING
        state.verdict = "benign" if auto_close else "true_positive"
        state.confidence = 0.95 if auto_close else 0.6
        state.confidence_basis = ["fake auto-triage rationale"]
        state.add_finding(f"Auto-triage (fake): verdict={state.verdict}, confidence={state.confidence}")
        call_log["auto_triage"].append(str(state.incident_id))
        return state

    def _make_runner(name: str, technique: str):
        async def _runner(state: InvestigationState) -> InvestigationState:
            await asyncio.sleep(SUBAGENT_SLEEP_MS / 1000.0)
            state.add_finding(f"{name} (fake): triggered on alert")
            if technique not in state.mitre_mappings:
                state.mitre_mappings.append(technique)
            state.verdict = "true_positive"
            state.confidence = max(state.confidence, 0.7 + 0.05 * len(call_log[name]))
            call_log[name].append(str(state.incident_id))
            return state

        return _runner

    targets: list[tuple[str, object]] = [
        ("app.agents.run_auto_triage", fake_auto_triage),
        ("app.agents.auto_triage_agent.run_auto_triage", fake_auto_triage),
        ("app.agents.run_phishing", _make_runner("phishing", "T1566.001")),
        ("app.agents.phishing_agent.run_phishing", _make_runner("phishing", "T1566.001")),
        ("app.agents.run_identity", _make_runner("identity", "T1078")),
        ("app.agents.identity_agent.run_identity", _make_runner("identity", "T1078")),
        ("app.agents.run_cloud", _make_runner("cloud", "T1078.004")),
        ("app.agents.cloud_agent.run_cloud", _make_runner("cloud", "T1078.004")),
        ("app.agents.run_insider_threat", _make_runner("insider", "T1567.002")),
        ("app.agents.insider_threat_agent.run_insider_threat", _make_runner("insider", "T1567.002")),
    ]
    for path, fn in targets:
        monkeypatch.setattr(path, fn, raising=False)

    return call_log


def _silence_realtime(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace ``_emit_event`` with a no-op so tests don't need realtime."""

    async def _noop(*_args: Any, **_kwargs: Any) -> None:
        return None

    monkeypatch.setattr(triage_module, "_emit_event", _noop)


def _poll_until_done(
    client: TestClient,
    run_id: str,
    *,
    timeout_s: float = 2.0,
    tenant_id: str = "acme",
) -> dict[str, Any]:
    """Poll GET /triage/{run_id} until ``status != "running"`` or timeout.

    Defaults to ``tenant_id="acme"`` because that's what
    :func:`_multi_signal_payload` posts; pass an override for tests that
    launch from a different tenant.
    """
    deadline = time.perf_counter() + timeout_s
    last: dict[str, Any] = {}
    while time.perf_counter() < deadline:
        resp = client.get(f"/api/v1/triage/{run_id}", params={"tenant_id": tenant_id})
        assert resp.status_code == 200, resp.text
        last = resp.json()
        if last.get("status") != "running":
            return last
        time.sleep(0.02)
    pytest.fail(f"triage run {run_id} did not complete in {timeout_s}s; last={last}")


# ---------------------------------------------------------------------------
# Topology resolution — env flag + explicit override
# ---------------------------------------------------------------------------


def test_post_launches_run_and_defaults_to_parallel(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Flag unset → parallel topology returned in the launch response."""
    monkeypatch.delenv(PARALLEL_TOPOLOGY_FLAG, raising=False)
    _silence_realtime(monkeypatch)
    _patch_runners(monkeypatch)
    client = TestClient(_build_app())

    resp = client.post("/api/v1/cases/CASE-001/triage", json=_multi_signal_payload())
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "running"
    assert body["topology"] == "parallel"
    assert body["case_id"] == "CASE-001"
    assert isinstance(body["run_id"], str)


def test_flag_off_runs_sequential_topology(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Flag set to a falsy value → sequential topology selected."""
    monkeypatch.setenv(PARALLEL_TOPOLOGY_FLAG, "0")
    _silence_realtime(monkeypatch)
    _patch_runners(monkeypatch)
    client = TestClient(_build_app())

    resp = client.post("/api/v1/cases/CASE-002/triage", json=_multi_signal_payload())
    assert resp.status_code == 200, resp.text
    assert resp.json()["topology"] == "sequential"

    final = _poll_until_done(client, resp.json()["run_id"])
    assert final["topology"] == "sequential"


def test_explicit_topology_override_beats_env_flag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Body-level ``topology`` override wins even when env flag disagrees."""
    monkeypatch.setenv(PARALLEL_TOPOLOGY_FLAG, "0")  # env says sequential
    _silence_realtime(monkeypatch)
    _patch_runners(monkeypatch)
    client = TestClient(_build_app())

    body = _multi_signal_payload()
    body["topology"] = "parallel"
    resp = client.post("/api/v1/cases/CASE-003/triage", json=body)
    assert resp.status_code == 200
    assert resp.json()["topology"] == "parallel"

    final = _poll_until_done(client, resp.json()["run_id"])
    assert final["topology"] == "parallel"


def test_invalid_topology_value_returns_400(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _silence_realtime(monkeypatch)
    _patch_runners(monkeypatch)
    client = TestClient(_build_app())

    body = _multi_signal_payload()
    body["topology"] = "diagonal"
    resp = client.post("/api/v1/cases/CASE-004/triage", json=body)
    assert resp.status_code == 400
    assert "diagonal" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# End-to-end flow — POST + poll → completed run with router telemetry
# ---------------------------------------------------------------------------


def test_run_completes_and_exposes_router_telemetry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Parallel run should expose verdict, signals, MITRE, wall-clock ms."""
    monkeypatch.delenv(PARALLEL_TOPOLOGY_FLAG, raising=False)
    _silence_realtime(monkeypatch)
    _patch_runners(monkeypatch)
    client = TestClient(_build_app())

    resp = client.post("/api/v1/cases/CASE-005/triage", json=_multi_signal_payload())
    assert resp.status_code == 200
    run_id = resp.json()["run_id"]

    final = _poll_until_done(client, run_id)

    assert final["status"] == "completed"
    assert final["topology"] == "parallel"
    assert final["verdict"] == "true_positive"
    assert set(final["signals"]) == {"phishing", "identity", "cloud", "insider"}
    # All four sub-agents fanned out → their techniques are present.
    assert {"T1566.001", "T1078", "T1078.004", "T1567.002"}.issubset(set(final["mitre_mappings"]))
    # Telemetry: wall-clock recorded as a non-negative number.
    assert isinstance(final.get("wall_clock_ms"), int | float)
    assert final["wall_clock_ms"] >= 0


def test_auto_close_short_circuits_router(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """High-confidence benign verdict during auto-triage skips sub-agents."""
    monkeypatch.delenv(PARALLEL_TOPOLOGY_FLAG, raising=False)
    _silence_realtime(monkeypatch)
    _patch_runners(monkeypatch, auto_close=True)
    client = TestClient(_build_app())

    resp = client.post("/api/v1/cases/CASE-006/triage", json=_multi_signal_payload())
    assert resp.status_code == 200
    run_id = resp.json()["run_id"]

    final = _poll_until_done(client, run_id)
    assert final["status"] == "completed"
    assert final["verdict"] == "benign"
    assert final["auto_closed"] is True
    assert final["signals"] == []  # no fan-out


# ---------------------------------------------------------------------------
# Error surfaces
# ---------------------------------------------------------------------------


def test_get_unknown_run_id_returns_404(monkeypatch: pytest.MonkeyPatch) -> None:
    _silence_realtime(monkeypatch)
    client = TestClient(_build_app())

    resp = client.get(f"/api/v1/triage/{uuid4()}")
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Triage run not found"


def test_post_accepts_minimal_body_with_only_case_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Empty body should not blow up — endpoint coerces defaults."""
    monkeypatch.delenv(PARALLEL_TOPOLOGY_FLAG, raising=False)
    _silence_realtime(monkeypatch)
    _patch_runners(monkeypatch)
    client = TestClient(_build_app())

    resp = client.post("/api/v1/cases/CASE-007/triage", json={})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["topology"] == "parallel"
    assert body["case_id"] == "CASE-007"


# ---------------------------------------------------------------------------
# Tenant isolation on GET — regression for PR review item
# (https://github.com/beenuar/AiSOC/pull/139)
# ---------------------------------------------------------------------------


def test_get_with_mismatched_tenant_returns_404(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A caller from tenant B must not see runs launched by tenant A.

    The handler returns 404 (not 403) on mismatch so a probing caller
    can't distinguish "wrong tenant" from "no such run" — same shape as
    the unknown-run-id branch above.
    """
    monkeypatch.delenv(PARALLEL_TOPOLOGY_FLAG, raising=False)
    _silence_realtime(monkeypatch)
    _patch_runners(monkeypatch)
    client = TestClient(_build_app())

    # Launch a run as tenant "acme".
    resp = client.post(
        "/api/v1/cases/CASE-TENANT-A/triage",
        json={**_multi_signal_payload(), "tenant_id": "acme"},
    )
    assert resp.status_code == 200, resp.text
    run_id = resp.json()["run_id"]

    # Owning tenant gets 200.
    own = client.get(f"/api/v1/triage/{run_id}", params={"tenant_id": "acme"})
    assert own.status_code == 200, own.text
    assert own.json()["tenant_id"] == "acme"

    # Different tenant gets 404, NOT 200 with the other tenant's findings.
    other = client.get(f"/api/v1/triage/{run_id}", params={"tenant_id": "evilcorp"})
    assert other.status_code == 404
    assert other.json()["detail"] == "Triage run not found"

    # Absent tenant_id falls back to "default" and still 404s — fail closed.
    no_tenant = client.get(f"/api/v1/triage/{run_id}")
    assert no_tenant.status_code == 404
    assert no_tenant.json()["detail"] == "Triage run not found"
