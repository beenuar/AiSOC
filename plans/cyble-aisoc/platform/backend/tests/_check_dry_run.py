"""Smoke check for HITL pre-action dry-run + blast-radius (t4-dry-run).

Drives ``app/hitl/dry_run.py`` and the ``/hitl/dry-run`` endpoint
through :class:`fastapi.testclient.TestClient`:

  * Single-step ``POST /hitl/dry-run`` returns the deterministic
    simulation envelope (target, dependents, reversibility, severity,
    counterfactual, advisory, fingerprint).
  * Multi-step (``steps=[...]``) returns the aggregate runbook
    envelope with overall severity and unique-entities count.
  * An unknown ``tool_name`` returns a graceful unknown-tool response
    (no crash).
  * A dry-run on a real CMDB asset surfaces criticality / compliance
    fields in the target summary.
  * The HITL gateway auto-runs the simulator for every approval
    request, so creating a HITL via the gateway lands a populated
    ``blast_radius.simulation`` blob on the row that ``GET /hitl/{id}``
    returns.
  * Calling the simulator twice with the same args produces the same
    fingerprint (deterministic).

Run from ``platform/backend/``::

    PYTHONPATH=. python tests/_check_dry_run.py
"""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from pathlib import Path


def _bootstrap_env() -> Path:
    tmpdir = Path(tempfile.mkdtemp(prefix="aisoc-dryrun-test-"))
    db_path = tmpdir / "aisoc.db"
    os.environ["AISOC_DB_PATH"] = str(db_path)
    os.environ["AISOC_LLM_PROVIDER"] = "mock"
    os.environ["AISOC_SEED_ON_STARTUP"] = "false"
    os.environ["AISOC_AUTONOMY_LEVEL"] = "autonomous"
    os.environ["AISOC_ACTOR_PROFILER_SCHEDULER_ENABLED"] = "false"
    os.environ["AISOC_BAS_SCHEDULER_ENABLED"] = "false"
    os.environ["AISOC_EXPOSURE_SCHEDULER_ENABLED"] = "false"
    os.environ["AISOC_BRAND_SCHEDULER_ENABLED"] = "false"
    os.environ["AISOC_SUPPLY_CHAIN_SCHEDULER_ENABLED"] = "false"
    os.environ["AISOC_DEV_ALLOW_ANON_TENANT"] = "true"
    os.environ["AISOC_DEFAULT_TENANT"] = "demo-tenant"
    return db_path


DB_PATH = _bootstrap_env()
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient  # noqa: E402

from app.db import init_db, session_scope  # noqa: E402
from app.hitl.dry_run import simulate_action  # noqa: E402
from app.hitl.gateway import gateway  # noqa: E402
from app.main import app  # noqa: E402
from app.models.asset import (  # noqa: E402
    Asset,
    AssetCriticality,
    AssetEnvironment,
    AssetType,
)
from app.models.case import Case, CaseStatus, Severity  # noqa: E402
from app.models.hitl import HitlRequest  # noqa: E402
from app.models.tool_call import RiskClass  # noqa: E402
from app.models.trace import AgentName  # noqa: E402

init_db()


_PASSES: list[str] = []
_FAILS: list[tuple[str, str]] = []


def _ok(name: str) -> None:
    _PASSES.append(name)
    print(f"  PASS  {name}")


def _bad(name: str, msg: str) -> None:
    _FAILS.append((name, msg))
    print(f"  FAIL  {name}: {msg}")


def main() -> int:
    print(f"DB: {DB_PATH}")
    client = TestClient(app)

    # Seed a CMDB asset so the simulator has criticality/compliance to surface
    with session_scope() as session:
        asset = Asset(
            tenant_id="demo-tenant",
            asset_type=AssetType.HOST,
            key="srv-prod-01",
            name="srv-prod-01",
            criticality=AssetCriticality.CROWN_JEWEL,
            environment=AssetEnvironment.PROD,
            owner="ops@acme.com",
            business_unit="finance",
            compliance_scopes=["pci", "soc2"],
            data_classifications=["confidential"],
        )
        session.add(asset)
        session.commit()

    # ─── Single-step dry-run on registered tool ─────────────────────
    print("\n[dry-run] single step on known tool with seeded asset")
    resp = client.post(
        "/hitl/dry-run",
        json={
            "tool_name": "edr.isolate_host",
            "params": {"host": "srv-prod-01", "reason": "test"},
        },
    )
    if resp.status_code != 200:
        _bad("POST /hitl/dry-run 200", f"got {resp.status_code}: {resp.text[:200]}")
        return 1
    sim = resp.json()
    required = {
        "tool_name",
        "integration",
        "risk_class",
        "reversibility",
        "target",
        "dependents",
        "collateral_count",
        "severity_hint",
        "counterfactual",
        "advisory",
        "fingerprint",
    }
    if not required.issubset(sim.keys()):
        _bad("dry-run shape", f"missing={required - sim.keys()}")
        return 1
    _ok("dry-run shape (target/dependents/severity/counterfactual)")

    if sim["tool_name"] != "edr.isolate_host":
        _bad("tool_name echo", str(sim))
        return 1
    if sim["target"] is None:
        _bad("target resolved from CMDB", "target=None")
        return 1
    target = sim["target"]
    if target["criticality"] != AssetCriticality.CROWN_JEWEL.value:
        _bad("target criticality", str(target))
        return 1
    if "pci" not in target["compliance_scopes"]:
        _bad("target compliance_scopes", str(target))
        return 1
    _ok(
        f"target resolved: {target['key']} "
        f"crit={target['criticality']} env={target['environment']} "
        f"compliance={target['compliance_scopes']}"
    )

    # Severity must escalate to HIGH on a crown-jewel+pci+prod target
    if sim["severity_hint"] != "high":
        _bad("severity_hint=high on crown_jewel+pci+prod", str(sim["severity_hint"]))
        return 1
    _ok("severity_hint=high on crown_jewel+pci+prod target")

    # Reversibility must come from the registry — edr.isolate_host has a
    # registered reverse_tool (edr.release_host).
    if sim["reversibility"] != "reversible" or sim["reverse_tool"] != "edr.release_host":
        _bad(
            "reversibility from registry",
            f"reversibility={sim['reversibility']} reverse_tool={sim['reverse_tool']}",
        )
        return 1
    _ok("reversibility derived from registry (isolate_host -> release_host)")

    # Advisory non-empty when target has compliance scope
    if not sim["advisory"]:
        _bad("advisory non-empty", "got empty list")
        return 1
    if not any("compliance" in note.lower() for note in sim["advisory"]):
        _bad("advisory mentions compliance", str(sim["advisory"]))
        return 1
    _ok(f"advisory: {len(sim['advisory'])} notes incl. compliance")

    # Counterfactual non-empty
    if not sim["counterfactual"]:
        _bad("counterfactual non-empty", "got empty string")
        return 1
    _ok(f"counterfactual: '{sim['counterfactual'][:60]}...'")

    # ─── DESTRUCTIVE tool → reversibility=destructive + severity=high
    print("\n[dry-run] destructive tool")
    resp = client.post(
        "/hitl/dry-run",
        json={
            "tool_name": "edr.kill_process",
            "params": {"host": "srv-prod-01", "pid": 4242},
        },
    )
    if resp.status_code != 200:
        _bad("destructive dry-run 200", f"got {resp.status_code}")
        return 1
    sim2 = resp.json()
    if sim2["reversibility"] != "destructive":
        _bad("destructive classified", str(sim2["reversibility"]))
        return 1
    if sim2["severity_hint"] != "high":
        _bad("destructive => severity_hint=high", str(sim2["severity_hint"]))
        return 1
    if not any("DESTRUCTIVE" in note for note in sim2["advisory"]):
        _bad("destructive advisory", str(sim2["advisory"]))
        return 1
    _ok("destructive classified + severity=high + advisory raised")

    # ─── Unknown tool → graceful response ───────────────────────────
    print("\n[dry-run] unknown tool")
    resp = client.post(
        "/hitl/dry-run",
        json={"tool_name": "imaginary.tool", "params": {}},
    )
    if resp.status_code != 200:
        _bad("unknown tool 200", f"got {resp.status_code}")
        return 1
    sim3 = resp.json()
    if sim3["risk_class"] != "unknown":
        _bad("unknown tool risk_class", str(sim3["risk_class"]))
        return 1
    if not sim3["advisory"] or "not registered" not in sim3["advisory"][0]:
        _bad("unknown tool advisory", str(sim3["advisory"]))
        return 1
    _ok("unknown tool returns graceful response (risk_class=unknown + advisory)")

    # ─── 400 on missing payload ─────────────────────────────────────
    resp = client.post("/hitl/dry-run", json={"params": {}})
    if resp.status_code != 400:
        _bad("missing tool_name -> 400", f"got {resp.status_code}")
        return 1
    _ok("POST /hitl/dry-run with no tool_name and no steps -> 400")

    # ─── Multi-step (runbook) ───────────────────────────────────────
    print("\n[dry-run] multi-step runbook")
    resp = client.post(
        "/hitl/dry-run",
        json={
            "steps": [
                {
                    "tool_name": "edr.isolate_host",
                    "params": {"host": "srv-prod-01", "reason": "test"},
                },
                {
                    "tool_name": "edr.kill_process",
                    "params": {"host": "srv-prod-01", "pid": 9999},
                },
            ]
        },
    )
    if resp.status_code != 200:
        _bad("runbook 200", f"got {resp.status_code}")
        return 1
    rb = resp.json()
    required = {
        "steps",
        "severity_hint",
        "unique_entities_affected",
        "destructive_steps",
        "forward_only_steps",
        "fingerprint",
    }
    if not required.issubset(rb.keys()):
        _bad("runbook shape", f"missing={required - rb.keys()}")
        return 1
    if len(rb["steps"]) != 2:
        _bad("runbook step count", str(len(rb["steps"])))
        return 1
    if rb["severity_hint"] != "high":
        _bad("runbook severity rolls up to high", str(rb["severity_hint"]))
        return 1
    if "edr.kill_process" not in rb["destructive_steps"]:
        _bad("runbook destructive_steps", str(rb["destructive_steps"]))
        return 1
    _ok(
        f"runbook severity={rb['severity_hint']} "
        f"unique_entities={rb['unique_entities_affected']} "
        f"destructive={rb['destructive_steps']}"
    )

    # ─── Determinism: same input → same fingerprint ─────────────────
    sim_a = simulate_action(
        tool_name="edr.isolate_host",
        params={"host": "srv-prod-01", "reason": "test"},
        tenant_id="demo-tenant",
    )
    sim_b = simulate_action(
        tool_name="edr.isolate_host",
        params={"host": "srv-prod-01", "reason": "test"},
        tenant_id="demo-tenant",
    )
    if sim_a.fingerprint != sim_b.fingerprint:
        _bad(
            "fingerprint deterministic",
            f"{sim_a.fingerprint} != {sim_b.fingerprint}",
        )
        return 1
    _ok(f"fingerprint deterministic ({sim_a.fingerprint})")

    # ─── HITL gateway auto-populates blast_radius.simulation ────────
    print("\n[hitl] gateway auto-runs simulator")
    with session_scope() as session:
        case = Case(
            tenant_id="demo-tenant",
            title="dry-run gateway test",
            severity=Severity.HIGH,
            status=CaseStatus.NEW,
        )
        session.add(case)
        session.commit()
        session.refresh(case)
        case_id = case.id

    async def _request_hitl() -> int:
        req = await gateway.request_approval(
            case_id=case_id,
            tenant_id="demo-tenant",
            agent=AgentName.RESPONDER,
            tool_name="edr.isolate_host",
            integration="sentinelone",
            risk_class=RiskClass.WRITE_SIGNIFICANT,
            params={"host": "srv-prod-01", "reason": "smoke test"},
            rationale="smoke test from dry-run check",
        )
        return req.id

    req_id = asyncio.run(_request_hitl())
    if req_id is None:
        _bad("hitl request id", "got None")
        return 1
    resp = client.get(f"/hitl/{req_id}")
    if resp.status_code != 200:
        _bad(f"GET /hitl/{req_id} 200", f"got {resp.status_code}")
        return 1
    body = resp.json()
    blast = body.get("blast_radius") or {}
    if "simulation" not in blast:
        _bad(
            "hitl blast_radius.simulation populated",
            f"keys={list(blast.keys())}",
        )
        return 1
    if blast.get("severity_hint") != "high":
        _bad(
            "hitl blast_radius.severity_hint",
            f"got {blast.get('severity_hint')}",
        )
        return 1
    if blast.get("reversibility") != "reversible":
        _bad(
            "hitl blast_radius.reversibility",
            f"got {blast.get('reversibility')}",
        )
        return 1
    _ok(
        f"gateway auto-populated blast_radius "
        f"(severity={blast['severity_hint']}, "
        f"reversibility={blast['reversibility']}, "
        f"counterfactual={'yes' if blast.get('counterfactual') else 'no'})"
    )

    return 0


if __name__ == "__main__":
    rc = main()
    print(f"\n{len(_PASSES)} pass, {len(_FAILS)} fail")
    if _FAILS:
        for name, msg in _FAILS:
            print(f"  FAIL: {name} — {msg}")
    sys.exit(rc)
