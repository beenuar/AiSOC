"""Smoke check for the Marketplace + Open Eval Benchmark (t3g-mcp-marketplace).

Drives ``app/marketplace/`` and ``app/api/marketplace_routes.py`` through
:class:`fastapi.testclient.TestClient` so the full wire-in surface is
exercised:

  * ``GET /marketplace/tools`` returns MCP-aligned entries derived from
    the live :data:`app.tools.registry.registry`. Curated overlay
    metadata (verified, vendor, category) lands on Cyble-native CTI
    tools.
  * Filters work: ``?verified_only=true`` drops unverified entries,
    ``?category=siem`` narrows to SIEM, ``?max_risk=read`` honours risk
    classification, ``?cyble_native_only=true`` shows only the moat
    tools.
  * ``GET /marketplace/connectors`` returns one entry per registered
    connector factory (mocks excluded).
  * ``GET /marketplace/categories`` and ``GET /marketplace/stats``
    return non-trivial summaries.
  * ``GET /benchmark/scenarios`` returns the built-in suite.
  * ``POST /benchmark/run`` (subset) drives the live agent mesh,
    persists a :class:`BenchmarkRun` row, and surfaces a 0..100
    aggregate score with per-scenario detail.
  * ``GET /benchmark/leaderboard`` returns the persisted run, ordered
    by score descending then latency ascending.
  * ``GET /benchmark/runs/{run_id}`` returns the full per-scenario
    outcome blob.

Run from ``platform/backend/``::

    PYTHONPATH=. python tests/_check_marketplace.py
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path


def _bootstrap_env() -> Path:
    tmpdir = Path(tempfile.mkdtemp(prefix="aisoc-marketplace-test-"))
    db_path = tmpdir / "aisoc.db"
    os.environ["AISOC_DB_PATH"] = str(db_path)
    os.environ["AISOC_LLM_PROVIDER"] = "mock"
    os.environ["AISOC_LLM_MODEL"] = "mock-deterministic"
    os.environ["AISOC_SEED_ON_STARTUP"] = "false"
    os.environ["AISOC_AUTONOMY_LEVEL"] = "autonomous"
    # All schedulers off so we don't race the test.
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
from app.main import app  # noqa: E402
from app.marketplace import benchmark_runner, builtin_scenarios, catalog  # noqa: E402
from app.marketplace.scenarios import BENCHMARK_VERSION  # noqa: E402
from app.models.benchmark import BenchmarkRun  # noqa: E402
from app.models.tool_call import RiskClass  # noqa: E402
from app.tools import registry  # noqa: E402, F401  -- forces tool registration
from app.tools.registry import registry as tool_registry  # noqa: E402

# DB needs to exist before TestClient runs anything.
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
    print(f"Benchmark version: {BENCHMARK_VERSION}")

    client = TestClient(app)

    # ─── Catalog: tools ─────────────────────────────────────────────
    print("\n[marketplace] tools")
    resp = client.get("/marketplace/tools")
    if resp.status_code != 200:
        _bad("GET /marketplace/tools 200", f"got {resp.status_code}: {resp.text[:200]}")
        return 1
    body = resp.json()
    tools = body["tools"]
    if body["total"] != len(tools) or body["total"] == 0:
        _bad("tools total != len(tools) or empty", str(body)[:200])
        return 1
    _ok(f"GET /marketplace/tools returned {body['total']} entries")

    # MCP-aligned shape
    sample = tools[0]
    required_keys = {
        "name",
        "integration",
        "category",
        "vendor",
        "description",
        "risk_class",
        "cyble_native",
        "verified",
        "tags",
        "params_schema",
        "result_schema",
    }
    if not required_keys.issubset(sample.keys()):
        missing = required_keys - sample.keys()
        _bad("MCP-aligned shape", f"missing: {missing}")
        return 1
    _ok("MCP-aligned tool shape (name/params/result/risk/vendor/...)")

    # Cyble-native CTI tools come back verified
    cti_entries = [t for t in tools if t["name"].startswith("cti.")]
    if not cti_entries:
        _bad("cti.* tool present", "no cti.* tool registered")
        return 1
    if not any(t.get("verified") for t in cti_entries):
        _bad(
            "at least one verified cti.* tool",
            f"verified={[t.get('verified') for t in cti_entries]}",
        )
        return 1
    _ok(f"verified cyble cti tools surfaced ({len(cti_entries)} cti.* total)")

    # Filter: verified only
    resp = client.get("/marketplace/tools", params={"verified_only": "true"})
    verified = resp.json()["tools"]
    if any(not t["verified"] for t in verified):
        _bad("verified_only filter", "got an unverified entry through")
        return 1
    _ok(f"verified_only filter: {len(verified)} verified tools")

    # Filter: cyble_native_only
    resp = client.get("/marketplace/tools", params={"cyble_native_only": "true"})
    native = resp.json()["tools"]
    if any(not t["cyble_native"] for t in native):
        _bad("cyble_native_only filter", "got non-native through")
        return 1
    _ok(f"cyble_native_only filter: {len(native)} native tools")

    # Filter: max_risk=READ (case-insensitive)
    resp = client.get("/marketplace/tools", params={"max_risk": "read"})
    if resp.status_code != 200:
        _bad("max_risk=read 200", f"got {resp.status_code}")
        return 1
    read_only = resp.json()["tools"]
    if any(t["risk_class"] != RiskClass.READ.value for t in read_only):
        _bad("max_risk=read filter", "got a non-READ class tool")
        return 1
    _ok(f"max_risk=read filter (lowercase): {len(read_only)} read-class tools")

    # Filter: max_risk=WRITE-REVERSIBLE includes READ + WRITE-REVERSIBLE
    resp = client.get("/marketplace/tools", params={"max_risk": "WRITE-REVERSIBLE"})
    if resp.status_code != 200:
        _bad("max_risk=WRITE-REVERSIBLE 200", f"got {resp.status_code}")
        return 1
    rw = resp.json()["tools"]
    if rw and any(
        t["risk_class"] not in {RiskClass.READ.value, RiskClass.WRITE_REVERSIBLE.value}
        for t in rw
    ):
        _bad("max_risk=WRITE-REVERSIBLE filter", "got a destructive/significant tool through")
        return 1
    _ok(f"max_risk=WRITE-REVERSIBLE filter: {len(rw)} tools")

    # Filter: invalid max_risk -> 400
    resp = client.get("/marketplace/tools", params={"max_risk": "nope"})
    if resp.status_code != 400:
        _bad("max_risk invalid -> 400", f"got {resp.status_code}")
        return 1
    _ok("max_risk invalid -> 400")

    # ─── Catalog: connectors ────────────────────────────────────────
    print("\n[marketplace] connectors")
    resp = client.get("/marketplace/connectors")
    if resp.status_code != 200:
        _bad("GET /marketplace/connectors 200", f"got {resp.status_code}")
        return 1
    body = resp.json()
    connectors = body["connectors"]
    if not connectors:
        _bad("connectors non-empty", "registry returned 0 connectors")
        return 1
    if any(c["vendor_slug"] == "mock" for c in connectors):
        _bad("mocks hidden from catalog", "mock vendor leaked into listing")
        return 1
    _ok(f"GET /marketplace/connectors returned {len(connectors)} entries (no mocks)")

    # SIEM category narrows correctly
    resp = client.get("/marketplace/connectors", params={"category": "siem"})
    siem = resp.json()["connectors"]
    if siem and any(c["category"] != "siem" for c in siem):
        _bad("category=siem filter", "non-siem entry leaked through")
        return 1
    _ok(f"category=siem filter: {len(siem)} entries")

    # ─── Stats / categories ─────────────────────────────────────────
    resp = client.get("/marketplace/categories")
    cats = resp.json()["categories"]
    if not cats or not isinstance(cats, list):
        _bad("categories list", str(cats)[:200])
        return 1
    _ok(f"categories: {cats[:6]}{'...' if len(cats) > 6 else ''}")

    resp = client.get("/marketplace/stats")
    stats = resp.json()
    if stats["tools_total"] == 0 or stats["connectors_total"] == 0:
        _bad("stats non-zero totals", str(stats))
        return 1
    if stats["tools_verified"] > stats["tools_total"]:
        _bad("stats sanity", "verified > total")
        return 1
    _ok(
        f"stats: tools={stats['tools_total']} "
        f"(verified={stats['tools_verified']}, "
        f"native={stats['tools_cyble_native']}), "
        f"connectors={stats['connectors_total']} "
        f"(verified={stats['connectors_verified']})"
    )

    # ─── Catalog vs registry parity ─────────────────────────────────
    direct = catalog.list_tools()
    if len(direct) != len(tool_registry.all()):
        _bad(
            "catalog parity with tool registry",
            f"catalog={len(direct)} registry={len(tool_registry.all())}",
        )
        return 1
    _ok(f"catalog parity with registry ({len(direct)} tools each)")

    # ─── Benchmark scenarios ────────────────────────────────────────
    print("\n[benchmark] scenarios")
    resp = client.get("/benchmark/scenarios")
    if resp.status_code != 200:
        _bad("GET /benchmark/scenarios 200", f"got {resp.status_code}")
        return 1
    scen = resp.json()
    if scen["total"] == 0 or len(scen["scenarios"]) != scen["total"]:
        _bad("scenarios listed", str(scen)[:200])
        return 1
    if scen["version"] != BENCHMARK_VERSION:
        _bad("scenarios version match", f"got {scen['version']}")
        return 1
    expected_ids = {s.id for s in builtin_scenarios()}
    api_ids = {s["id"] for s in scen["scenarios"]}
    if expected_ids != api_ids:
        _bad(
            "scenario ids parity",
            f"diff={expected_ids ^ api_ids}",
        )
        return 1
    _ok(f"scenarios: {scen['total']} (ids={sorted(api_ids)})")

    # ─── Run a subset benchmark ─────────────────────────────────────
    print("\n[benchmark] run")
    target_ids = ["benign-printer-noise", "okta-aitm-session-theft"]
    resp = client.post(
        "/benchmark/run",
        json={"scenario_ids": target_ids, "notes": "smoke-test subset"},
    )
    if resp.status_code != 200:
        _bad("POST /benchmark/run 200", f"got {resp.status_code}: {resp.text[:200]}")
        return 1
    outcome = resp.json()
    if outcome["benchmark_version"] != BENCHMARK_VERSION:
        _bad("outcome version", f"got {outcome['benchmark_version']}")
        return 1
    if len(outcome["scenarios"]) != len(target_ids):
        _bad(
            "outcome scenario count",
            f"got {len(outcome['scenarios'])}, expected {len(target_ids)}",
        )
        return 1
    if not (0 <= outcome["aggregate_score"] <= 100):
        _bad("aggregate score range", str(outcome["aggregate_score"]))
        return 1
    _ok(
        f"benchmark run: score={outcome['aggregate_score']} "
        f"pass_rate={outcome['pass_rate']} "
        f"latency={outcome['total_latency_ms']}ms "
        f"run_id={outcome['run_id']}"
    )

    # Per-scenario shape
    scenario_outcome = outcome["scenarios"][0]
    expected_keys = {
        "scenario_id",
        "case_id",
        "score",
        "passed",
        "latency_ms",
        "verdict",
        "severity",
        "failure_reasons",
        "response_actions",
        "iocs",
        "techniques",
    }
    if not expected_keys.issubset(scenario_outcome.keys()):
        _bad(
            "scenario outcome shape",
            f"missing={expected_keys - scenario_outcome.keys()}",
        )
        return 1
    _ok("per-scenario outcome shape (score/passed/verdict/reasons)")

    # Run id is persisted
    if outcome["run_id"] is None:
        _bad("run_id persisted", "got None")
        return 1

    # ─── Leaderboard ────────────────────────────────────────────────
    print("\n[benchmark] leaderboard")
    resp = client.get("/benchmark/leaderboard")
    if resp.status_code != 200:
        _bad("GET /benchmark/leaderboard 200", f"got {resp.status_code}")
        return 1
    lb = resp.json()
    if not lb["leaderboard"]:
        _bad("leaderboard non-empty", "no rows")
        return 1
    top = lb["leaderboard"][0]
    if top["run_id"] != outcome["run_id"]:
        _bad(
            "top run is the run we just submitted",
            f"top={top['run_id']} we={outcome['run_id']}",
        )
        return 1
    _ok(f"leaderboard: top model={top['model_provider']}/{top['model_name']} score={top['aggregate_score']}")

    # Filter by version
    resp = client.get(
        "/benchmark/leaderboard",
        params={"benchmark_version": BENCHMARK_VERSION},
    )
    versioned = resp.json()["leaderboard"]
    if not versioned:
        _bad("leaderboard version filter", "no rows for current version")
        return 1
    _ok(f"leaderboard version filter: {len(versioned)} rows for {BENCHMARK_VERSION}")

    # Detail endpoint
    detail = client.get(f"/benchmark/runs/{outcome['run_id']}").json()
    if detail.get("run_id") != outcome["run_id"]:
        _bad("run detail run_id", str(detail)[:200])
        return 1
    if not detail.get("outcomes"):
        _bad("run detail outcomes", "empty")
        return 1
    _ok("GET /benchmark/runs/{id} returns persisted outcome blob")

    # 404 for missing run
    miss = client.get("/benchmark/runs/9999999")
    if miss.status_code != 404:
        _bad("missing run -> 404", f"got {miss.status_code}")
        return 1
    _ok("missing run -> 404")

    # ─── DB persistence sanity ──────────────────────────────────────
    print("\n[benchmark] db persistence")
    with session_scope() as s:
        rows = s.exec(
            __import__("sqlmodel").select(BenchmarkRun)
        ).all()
        if not rows:
            _bad("BenchmarkRun row exists", "0 rows in db")
            return 1
        row = next(r for r in rows if r.id == outcome["run_id"])
        if row.aggregate_score != outcome["aggregate_score"]:
            _bad(
                "row.aggregate_score == outcome.aggregate_score",
                f"row={row.aggregate_score} outcome={outcome['aggregate_score']}",
            )
            return 1
        if set(row.scenarios_run or []) != set(target_ids):
            _bad(
                "row.scenarios_run == target_ids (as sets)",
                f"row={list(row.scenarios_run or [])} target={target_ids}",
            )
            return 1
    _ok(f"BenchmarkRun persisted (run_id={outcome['run_id']})")

    # ─── Empty subset → 400 ─────────────────────────────────────────
    resp = client.post(
        "/benchmark/run", json={"scenario_ids": ["does-not-exist"]}
    )
    if resp.status_code != 400:
        _bad("unknown scenario_ids -> 400", f"got {resp.status_code}")
        return 1
    _ok("POST /benchmark/run with unknown ids -> 400")

    # ─── Direct runner sanity ───────────────────────────────────────
    print("\n[benchmark] direct runner")
    if benchmark_runner.scenario_count == 0:
        _bad("benchmark_runner.scenario_count > 0", "got 0")
        return 1
    _ok(f"direct runner sees {benchmark_runner.scenario_count} scenarios")

    # ─── Adversarial / red-team ─────────────────────────────────────
    print("\n[redteam] catalogue")
    resp = client.get("/redteam/attacks")
    if resp.status_code != 200:
        _bad("GET /redteam/attacks 200", f"got {resp.status_code}")
        return 1
    attacks_resp = resp.json()
    if attacks_resp["total"] == 0:
        _bad("redteam attacks listed", str(attacks_resp)[:200])
        return 1
    surfaces = {a["surface"] for a in attacks_resp["attacks"]}
    if not {"alert", "tool_output", "ioc_poison", "alert_flood"}.issubset(surfaces):
        _bad(
            "redteam attack surfaces coverage",
            f"surfaces={surfaces}",
        )
        return 1
    _ok(
        f"redteam catalogue: {attacks_resp['total']} attacks "
        f"across {len(surfaces)} surfaces"
    )

    # Run only the synchronous tool-output attacks (no agent mesh) so the
    # smoke test stays under a few seconds. The mesh-driven attacks get
    # exercised by the dedicated CI job that has a longer budget.
    sync_ids = [
        "tool-output-override-instruction",
        "tool-output-role-assertion",
        "tool-output-html-instruction",
        "tool-output-base64-payload",
        "tool-output-credential-exfil",
        "tool-output-schema-violation",
    ]
    print("\n[redteam] run (tool-output subset)")
    resp = client.post(
        "/redteam/run",
        json={"attack_ids": sync_ids, "notes": "smoke-test tool-output subset"},
    )
    if resp.status_code != 200:
        _bad("POST /redteam/run 200", f"got {resp.status_code}: {resp.text[:200]}")
        return 1
    rt = resp.json()
    if rt["benchmark_version"] != "redteam-0.1.0":
        _bad("redteam version", f"got {rt['benchmark_version']}")
        return 1
    if rt["attacks_run"] != len(sync_ids):
        _bad("attacks_run matches", f"got {rt['attacks_run']}")
        return 1
    if not (0.0 <= rt["block_rate"] <= 1.0):
        _bad("block_rate range", str(rt["block_rate"]))
        return 1
    # The defender must catch the four classic injection vectors at a
    # minimum (override, role-assertion, html-smuggle, schema-violation).
    if rt["block_rate"] < 0.5:
        _bad(
            "block_rate >= 0.5 on tool-output subset",
            f"got block_rate={rt['block_rate']} attacks={[a['attack_id'] for a in rt['attacks'] if not a['blocked']]}",
        )
        return 1
    _ok(
        f"redteam run: block_rate={rt['block_rate']} "
        f"({rt['attacks_blocked']}/{rt['attacks_run']}) "
        f"latency={rt['total_latency_ms']}ms"
    )

    # Per-attack outcome shape
    sample_attack = rt["attacks"][0]
    expected_keys = {
        "attack_id",
        "surface",
        "blocked",
        "failure_reasons",
        "defender_signals",
        "defender_risk",
        "schema_violations",
        "latency_ms",
    }
    if not expected_keys.issubset(sample_attack.keys()):
        _bad(
            "redteam outcome shape",
            f"missing={expected_keys - sample_attack.keys()}",
        )
        return 1
    _ok("per-attack outcome shape (blocked/signals/reasons)")

    # Schema-violation attack must record schema_violations
    sv = next(
        (a for a in rt["attacks"] if a["attack_id"] == "tool-output-schema-violation"),
        None,
    )
    if sv is None:
        _bad("schema-violation attack present", "missing")
        return 1
    if sv["blocked"] is False or not sv["schema_violations"]:
        _bad(
            "schema-violation defender catch",
            f"blocked={sv['blocked']} violations={sv['schema_violations']}",
        )
        return 1
    _ok(
        f"schema-violation caught ({len(sv['schema_violations'])} violations)"
    )

    # Override-instruction attack must surface the corresponding signal
    override = next(
        (a for a in rt["attacks"] if a["attack_id"] == "tool-output-override-instruction"),
        None,
    )
    if override is None or "override_instruction" not in override["defender_signals"]:
        _bad(
            "override-instruction signal",
            f"signals={override['defender_signals'] if override else None}",
        )
        return 1
    _ok("override-instruction signal raised")

    # Red-team leaderboard separates from the open benchmark
    resp = client.get("/redteam/leaderboard")
    rl = resp.json()["leaderboard"]
    if not rl:
        _bad("redteam leaderboard non-empty", "no rows")
        return 1
    if not all(row["benchmark_version"].startswith("redteam-") for row in rl):
        _bad(
            "redteam leaderboard scoping",
            "non-redteam row leaked into redteam leaderboard",
        )
        return 1
    _ok(f"redteam leaderboard: {len(rl)} rows, all redteam-* versioned")

    # Open-benchmark leaderboard must NOT show redteam rows
    resp = client.get("/benchmark/leaderboard")
    open_lb = resp.json()["leaderboard"]
    if any(row["benchmark_version"].startswith("redteam-") for row in open_lb):
        _bad(
            "open leaderboard scoping",
            "redteam row leaked into open-benchmark leaderboard",
        )
        return 1
    _ok("open leaderboard excludes redteam rows")

    return 0


if __name__ == "__main__":
    rc = main()
    print(f"\n{len(_PASSES)} pass, {len(_FAILS)} fail")
    if _FAILS:
        for name, msg in _FAILS:
            print(f"  FAIL: {name} — {msg}")
    sys.exit(rc)
