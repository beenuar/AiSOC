"""Smoke test: chaos engineering harness (t6-chaos).

Covers:

* The engine is a no-op when nothing is scheduled.
* ``llm_outage`` raises a synthetic exception on the next match.
* ``tool_timeout`` raises after burning the configured delay.
* ``tool_malformed`` returns a substitute payload without raising.
* Wildcard targets (``llm.complete*``) match any prefixed call.
* Budgets are decremented and the fault retires when it hits zero.
* The HTTP surface (schedule + scenario + history + clear) gates
  scheduling behind admin and exposes the active-faults list to
  any authenticated caller.
"""
from __future__ import annotations

import os
import tempfile
import time

os.environ["AISOC_AUTH_DISABLED"] = "1"
os.environ["AISOC_LLM_PROVIDER"] = "mock"
DB_FILE = tempfile.NamedTemporaryFile(prefix="aisoc-chaos-", suffix=".db", delete=False)
DB_FILE.close()
os.environ["AISOC_DB_PATH"] = DB_FILE.name

from fastapi.testclient import TestClient  # noqa: E402

from app.chaos import (  # noqa: E402
    ChaosFault,
    ChaosKind,
    chaos_engine,
)
from app.chaos.engine import ChaosError, ChaosTimeout  # noqa: E402
from app.chaos.scenarios import builtin_scenarios  # noqa: E402
from app.config import settings  # noqa: E402
from app.main import app  # noqa: E402
from app.security.jwt import issue_tenant_token  # noqa: E402


def _expect(condition: bool, msg: str) -> None:
    if not condition:
        raise AssertionError(msg)


def _passthrough_smoke() -> None:
    chaos_engine.clear()
    _expect(
        chaos_engine.maybe_raise_llm("llm.complete:investigator") is None,
        "no scheduled fault — should pass through",
    )
    _expect(
        chaos_engine.apply_tool("tool.cti.enrich_ioc") is None,
        "no scheduled fault — tool should pass through",
    )


def _llm_outage_smoke() -> None:
    chaos_engine.clear()
    chaos_engine.schedule(
        ChaosFault(
            kind=ChaosKind.llm_outage,
            target="llm.complete:investigator",
            remaining=1,
            message="provider down",
        )
    )

    raised = False
    try:
        chaos_engine.maybe_raise_llm("llm.complete:investigator")
    except ChaosError as exc:
        raised = True
        _expect("provider down" in str(exc), f"message missing: {exc}")
    _expect(raised, "llm_outage did not raise")

    # Budget exhausted — next call passes through.
    _expect(
        chaos_engine.maybe_raise_llm("llm.complete:investigator") is None,
        "budget exhausted but fault still firing",
    )


def _wildcard_target_smoke() -> None:
    chaos_engine.clear()
    chaos_engine.schedule(
        ChaosFault(
            kind=ChaosKind.llm_outage,
            target="llm.complete*",
            remaining=2,
            message="pool unhealthy",
        )
    )

    fired = 0
    for target in ["llm.complete:triager", "llm.complete:reporter"]:
        try:
            chaos_engine.maybe_raise_llm(target)
        except ChaosError:
            fired += 1
    _expect(fired == 2, f"wildcard target should match both calls, got {fired}")
    _expect(
        chaos_engine.maybe_raise_llm("llm.complete:hunter") is None,
        "third call should pass-through after budget exhausted",
    )


def _tool_timeout_smoke() -> None:
    chaos_engine.clear()
    chaos_engine.schedule(
        ChaosFault(
            kind=ChaosKind.tool_timeout,
            target="tool.edr.isolate_host",
            remaining=1,
            delay_ms=50,
        )
    )
    start = time.perf_counter()
    raised = False
    try:
        chaos_engine.apply_tool("tool.edr.isolate_host")
    except ChaosTimeout:
        raised = True
    elapsed_ms = (time.perf_counter() - start) * 1000
    _expect(raised, "tool_timeout did not raise")
    _expect(elapsed_ms >= 40, f"timeout should burn delay, got {elapsed_ms}ms")


def _tool_malformed_smoke() -> None:
    chaos_engine.clear()
    chaos_engine.schedule(
        ChaosFault(
            kind=ChaosKind.tool_malformed,
            target="tool.cti.enrich_ioc",
            remaining=1,
            payload={"unexpected_key": "garbage"},
        )
    )
    payload = chaos_engine.apply_tool("tool.cti.enrich_ioc")
    _expect(payload is not None, "malformed fault should surface a substitute")
    _expect("unexpected_key" in payload, f"malformed payload missing keys: {payload}")


def _llm_malformed_smoke() -> None:
    chaos_engine.clear()
    chaos_engine.schedule(
        ChaosFault(
            kind=ChaosKind.llm_malformed,
            target="llm.complete:reporter",
            remaining=1,
            payload={"text": "INVALID-JSON{"},
        )
    )
    payload = chaos_engine.maybe_raise_llm("llm.complete:reporter")
    _expect(payload is not None, "llm_malformed should return a substitute")
    _expect(payload["text"] == "INVALID-JSON{", f"malformed payload mismatch: {payload}")


def _api_smoke() -> None:
    chaos_engine.clear()
    admin_token = issue_tenant_token(
        tenant_id=settings.default_tenant,
        subject="chaos-admin",
        roles=["admin"],
    )
    analyst_token = issue_tenant_token(
        tenant_id=settings.default_tenant,
        subject="analyst-1",
        roles=["analyst"],
    )

    with TestClient(app) as client:
        # Analyst can list (empty), but cannot schedule.
        r = client.get(
            "/chaos/faults",
            headers={"Authorization": f"Bearer {analyst_token}"},
        )
        _expect(r.status_code == 200, f"GET 200 expected, got {r.status_code}")
        _expect(r.json()["count"] == 0, "expected empty fault list at start")

        r = client.post(
            "/chaos/faults",
            json={"kind": "llm_outage", "target": "llm.complete:any"},
            headers={"Authorization": f"Bearer {analyst_token}"},
        )
        _expect(r.status_code == 403, f"non-admin schedule should 403, got {r.status_code}")

        # Admin can schedule.
        r = client.post(
            "/chaos/faults",
            json={
                "kind": "llm_outage",
                "target": "llm.complete:any",
                "remaining": 2,
                "message": "drill",
            },
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        _expect(r.status_code == 200, f"admin schedule 200 expected, got {r.status_code} {r.text}")
        body = r.json()
        _expect(body["target"] == "llm.complete:any", f"target mismatch: {body}")

        # Schedule a built-in scenario.
        r = client.post(
            "/chaos/scenarios/edr-tool-flaky",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        _expect(r.status_code == 200, f"scenario 200 expected, got {r.status_code} {r.text}")

        # Trigger a fault to populate history.
        try:
            chaos_engine.maybe_raise_llm("llm.complete:any")
        except ChaosError:
            pass

        r = client.get(
            "/chaos/history",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        _expect(r.status_code == 200, "history GET failed")
        history = r.json()
        _expect(history["count"] >= 1, f"history empty: {history}")

        # Clear faults requires admin.
        r = client.delete("/chaos/faults", headers={"Authorization": f"Bearer {analyst_token}"})
        _expect(r.status_code == 403, "non-admin DELETE should 403")

        r = client.delete("/chaos/faults", headers={"Authorization": f"Bearer {admin_token}"})
        _expect(r.status_code == 200, "admin DELETE should 200")
        _expect(len(chaos_engine.active_faults()) == 0, "active faults should be empty after clear")


def _builtin_scenarios_smoke() -> None:
    scenarios = builtin_scenarios()
    _expect(len(scenarios) >= 4, f"expected >=4 built-in scenarios, got {len(scenarios)}")
    names = {s.name for s in scenarios}
    for required in ("llm-provider-down", "edr-tool-flaky", "cti-malformed-response"):
        _expect(required in names, f"missing built-in scenario: {required}")


def main() -> None:
    _passthrough_smoke()
    _llm_outage_smoke()
    _wildcard_target_smoke()
    _tool_timeout_smoke()
    _tool_malformed_smoke()
    _llm_malformed_smoke()
    _builtin_scenarios_smoke()
    _api_smoke()
    print("ok: chaos smoke")


if __name__ == "__main__":
    main()
