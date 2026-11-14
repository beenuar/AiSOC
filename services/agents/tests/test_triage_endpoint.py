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
import base64
import hashlib
import hmac
import json
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


# ---------------------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------------------
#
# These routes take their tenant from the caller's credential now, not from a
# `tenant_id` the caller supplies. The tests mint the same first-party HS256
# access token `services/api` issues, so they drive the real verification
# rather than a bypass.

TENANT_A = "aaaaaaaa-0000-0000-0000-00000000000a"
TENANT_B = "bbbbbbbb-0000-0000-0000-00000000000b"
_TEST_SECRET = "agents-triage-test-secret-at-least-32-chars"


def _console_token(tenant: str, *, sub: str = "analyst") -> str:
    def b64(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    header = b64(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = b64(
        json.dumps(
            {"sub": sub, "tenant_id": tenant, "type": "access", "exp": int(time.time()) + 600},
            separators=(",", ":"),
        ).encode()
    )
    sig = b64(hmac.new(_TEST_SECRET.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest())
    return f"{header}.{payload}.{sig}"


def _auth(tenant: str = TENANT_A) -> dict[str, str]:
    return {"Authorization": f"Bearer {_console_token(tenant)}"}


@pytest.fixture(autouse=True)
def _credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    """Configure the signing secret these tests mint tokens against."""
    monkeypatch.setenv("SECRET_KEY", _TEST_SECRET)
    monkeypatch.delenv("AISOC_SERVICE_TOKEN", raising=False)
    monkeypatch.delenv("AISOC_AGENTS_SERVICE_TOKEN", raising=False)
    monkeypatch.delenv("AISOC_DEV_MODE", raising=False)


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
        "tenant_id": TENANT_A,
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
    tenant_id: str = TENANT_A,
) -> dict[str, Any]:
    """Poll GET /triage/{run_id} until ``status != "running"`` or timeout.

    Polls as ``TENANT_A`` because that is what :func:`_multi_signal_payload`
    launches under; pass an override for tests that launch elsewhere. The
    tenant travels in the credential, not the query string — the route
    compares the run's tenant against the verified one.
    """
    deadline = time.perf_counter() + timeout_s
    last: dict[str, Any] = {}
    while time.perf_counter() < deadline:
        resp = client.get(f"/api/v1/triage/{run_id}", headers=_auth(tenant_id))
        assert resp.status_code == 200, resp.text
        last = resp.json()
        if last.get("status") != "running":
            return last
        time.sleep(0.02)
    # Use ``pytest.fail`` for the red-failure UX, then ``raise`` so the type
    # checker / CodeQL see the function ends on an explicit no-return path
    # (avoids ``py/mixed-returns`` from the implicit fall-through).
    pytest.fail(f"triage run {run_id} did not complete in {timeout_s}s; last={last}")
    raise AssertionError("unreachable")  # pragma: no cover


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

    resp = client.post("/api/v1/cases/CASE-001/triage", json=_multi_signal_payload(), headers=_auth())
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

    resp = client.post("/api/v1/cases/CASE-002/triage", json=_multi_signal_payload(), headers=_auth())
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
    resp = client.post("/api/v1/cases/CASE-003/triage", json=body, headers=_auth())
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
    resp = client.post("/api/v1/cases/CASE-004/triage", json=body, headers=_auth())
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

    resp = client.post("/api/v1/cases/CASE-005/triage", json=_multi_signal_payload(), headers=_auth())
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

    resp = client.post("/api/v1/cases/CASE-006/triage", json=_multi_signal_payload(), headers=_auth())
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

    resp = client.get(f"/api/v1/triage/{uuid4()}", headers=_auth())
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

    resp = client.post("/api/v1/cases/CASE-007/triage", json={}, headers=_auth())
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

    This test used to pass a `tenant_id` query parameter for both sides, so
    all it really checked was that the route compared a value against a copy
    of itself — which any caller enumerating run IDs could satisfy by simply
    guessing the tenant string too. Tenant B now arrives holding tenant B's
    credential, which is the only version of this assertion that means
    anything.
    """
    monkeypatch.delenv(PARALLEL_TOPOLOGY_FLAG, raising=False)
    _silence_realtime(monkeypatch)
    _patch_runners(monkeypatch)
    client = TestClient(_build_app())

    # Launch a run as tenant "acme".
    resp = client.post(
        "/api/v1/cases/CASE-TENANT-A/triage",
        json={**_multi_signal_payload(), "tenant_id": TENANT_A},
        headers=_auth(TENANT_A),
    )
    assert resp.status_code == 200, resp.text
    run_id = resp.json()["run_id"]

    # Owning tenant gets 200. Asserted first, so the refusals below are
    # refusals of something that genuinely exists.
    own = client.get(f"/api/v1/triage/{run_id}", headers=_auth(TENANT_A))
    assert own.status_code == 200, own.text
    assert own.json()["tenant_id"] == TENANT_A

    # Tenant B, holding tenant B's own valid credential, gets 404 — not 200
    # with tenant A's findings, and not 403 either.
    other = client.get(f"/api/v1/triage/{run_id}", headers=_auth(TENANT_B))
    assert other.status_code == 404
    assert other.json()["detail"] == "Triage run not found"

    # No credential at all is refused before the run is even looked up.
    anon = client.get(f"/api/v1/triage/{run_id}")
    assert anon.status_code == 401

    # A tenant named in the query string is not a tenant. The parameter is
    # gone; supplying it must not resurrect the old behaviour.
    spoofed = client.get(f"/api/v1/triage/{run_id}", params={"tenant_id": TENANT_A}, headers=_auth(TENANT_B))
    assert spoofed.status_code == 404
