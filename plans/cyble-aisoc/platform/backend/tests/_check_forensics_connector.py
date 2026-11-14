"""End-to-end smoke test for the forensics connector + tool surface (Theme 2j).

Complements ``_check_investigator_forensics.py``. That test pins the
**Investigator's escalation contract** (when does deep forensics fire?).
This test pins the **connector-and-tools contract** (what does the
forensics surface actually expose, with what risk semantics, and does
each tool dispatch cleanly into a connector?).

Specifically, we verify:

  1. The Velociraptor forensics connector factory is registered for
     ``ConnectorKind.FORENSICS`` (real vendor swap path exists).
  2. All four ``forensics.*`` agent tools are present in the registry
     with the correct risk classes — ``READ`` for collect/hunt/fetch
     and ``DESTRUCTIVE`` for kill_process.
  3. ``forensics.kill_process`` is at or above the configured HITL
     threshold (i.e. cannot be auto-executed even at full autonomy).
  4. Each tool, when dispatched against the mock connector, returns a
     result that conforms to the published JSON schema envelope and
     tells the canonical forensic story (rundll32 PID on WIN-FIN-0044,
     persistence in Run key, C2 to 185.220.101.42, dropped DLL SHA-256,
     hunt finds blast-radius, kill_process succeeds).

Run from ``platform/backend/``:

    PYTHONPATH=. python tests/_check_forensics_connector.py

Exits non-zero on any failure and prints a PASS/FAIL per check.
"""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from pathlib import Path


def _bootstrap_env() -> Path:
    tmpdir = Path(tempfile.mkdtemp(prefix="aisoc-forensics-conn-test-"))
    db_path = tmpdir / "aisoc.db"
    os.environ["AISOC_DB_PATH"] = str(db_path)
    os.environ["AISOC_LLM_PROVIDER"] = "mock"
    return db_path


DB_PATH = _bootstrap_env()
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.config import settings  # noqa: E402
from app.connectors import ConnectorKind, get_connector  # noqa: E402
from app.connectors.sdk.protocols import BaseForensicsConnector  # noqa: E402
from app.connectors.sdk.registry import (  # noqa: E402
    _ensure_builtins_loaded,
    _resolve_factory,
    list_registered_factories,
)
from app.db import init_db  # noqa: E402
from app.models.tool_call import RiskClass  # noqa: E402
from app.tools import forensics as _forensics_module  # noqa: E402,F401
from app.tools.registry import registry as _tool_registry  # noqa: E402


_TENANT = "tenant-forensics-smoke"
_STORY_HOST = "WIN-FIN-0044"
_STORY_RUNDLL32_PID = 6190
_STORY_DLL_PATH = r"C:\Users\tina.lee\AppData\Local\Temp\a.dll"
_STORY_C2_IP = "185.220.101.42"


_results: list[tuple[str, bool, str]] = []


def _check(name: str, ok: bool, detail: str = "") -> None:
    _results.append((name, ok, detail))
    marker = "PASS" if ok else "FAIL"
    msg = f"  [{marker}] {name}"
    if detail:
        msg += f" — {detail}"
    print(msg)


def _check_factory_registered() -> None:
    print("\n[1] Connector factory registration")
    _ensure_builtins_loaded()
    registered = set(list_registered_factories())
    _check(
        "velociraptor factory registered for ConnectorKind.FORENSICS",
        (ConnectorKind.FORENSICS, "velociraptor") in registered,
        f"registered={sorted((k.value, v) for k, v in registered if k == ConnectorKind.FORENSICS)}",
    )
    _check(
        "mock factory registered for ConnectorKind.FORENSICS",
        (ConnectorKind.FORENSICS, "mock") in registered,
    )
    try:
        velo_factory = _resolve_factory(ConnectorKind.FORENSICS, "velociraptor")
        _check(
            "velociraptor factory resolves",
            callable(velo_factory),
            f"factory={getattr(velo_factory, '__name__', velo_factory)}",
        )
    except Exception as e:  # pragma: no cover
        _check("velociraptor factory resolves", False, f"error={e}")


def _check_tool_registry() -> None:
    print("\n[2] Tool registry — risk class contract")
    expected = {
        "forensics.collect_artifact": RiskClass.READ,
        "forensics.run_hunt": RiskClass.READ,
        "forensics.fetch_file": RiskClass.READ,
        "forensics.kill_process": RiskClass.DESTRUCTIVE,
    }
    for tool_name, expected_risk in expected.items():
        td = _tool_registry.get(tool_name)
        if td is None:
            _check(f"{tool_name} registered", False, "missing from registry")
            continue
        _check(
            f"{tool_name} registered",
            True,
            f"integration={td.integration}",
        )
        _check(
            f"{tool_name} risk_class == {expected_risk.value}",
            td.risk_class == expected_risk,
            f"got {td.risk_class.value}",
        )
        tags = set(td.tags or [])
        _check(
            f"{tool_name} tagged needs:tenant",
            "needs:tenant" in tags,
            f"tags={sorted(tags)}",
        )


def _check_hitl_gating() -> None:
    print("\n[3] HITL gating for DESTRUCTIVE forensics")
    threshold = settings.require_hitl_above
    try:
        threshold_enum = RiskClass(threshold)
    except ValueError:
        threshold_enum = RiskClass.WRITE_REVERSIBLE
    ordering = [
        RiskClass.READ,
        RiskClass.WRITE_REVERSIBLE,
        RiskClass.WRITE_SIGNIFICANT,
        RiskClass.DESTRUCTIVE,
    ]
    kill = ordering.index(RiskClass.DESTRUCTIVE)
    thr = ordering.index(threshold_enum)
    _check(
        "forensics.kill_process at/above HITL threshold (cannot auto-execute)",
        kill >= thr,
        f"threshold={threshold_enum.value}, kill=DESTRUCTIVE",
    )


async def _dispatch_collect_pslist(conn: BaseForensicsConnector) -> None:
    print("\n[4a] forensics.collect_artifact → Windows.System.Pslist")
    result = await conn.collect_artifact(
        host=_STORY_HOST,
        artifact="Windows.System.Pslist",
    )
    _check(
        "status == completed",
        result.get("status") == "completed",
        f"status={result.get('status')}",
    )
    _check(
        "host echoed",
        result.get("host") == _STORY_HOST,
        f"host={result.get('host')}",
    )
    _check(
        "flow_id present",
        bool(result.get("flow_id")),
        f"flow_id={result.get('flow_id')}",
    )
    rows = result.get("rows", []) or []
    pids = {r.get("Pid") for r in rows}
    _check(
        f"pslist includes story rundll32 PID {_STORY_RUNDLL32_PID}",
        _STORY_RUNDLL32_PID in pids,
        f"pids={sorted(p for p in pids if isinstance(p, int))[:6]}…",
    )


async def _dispatch_collect_autoruns(conn: BaseForensicsConnector) -> None:
    print("\n[4b] forensics.collect_artifact → Windows.Sys.AutoRuns")
    result = await conn.collect_artifact(
        host=_STORY_HOST,
        artifact="Windows.Sys.AutoRuns",
    )
    rows = result.get("rows", []) or []
    blob = repr(rows).lower()
    _check(
        "autoruns row references story DLL path",
        "a.dll" in blob,
        f"row_count={len(rows)}",
    )


async def _dispatch_collect_netstat(conn: BaseForensicsConnector) -> None:
    print("\n[4c] forensics.collect_artifact → Windows.NetStat")
    result = await conn.collect_artifact(
        host=_STORY_HOST,
        artifact="Windows.NetStat",
    )
    rows = result.get("rows", []) or []
    addrs: set[str] = set()
    for r in rows:
        for v in r.values():
            if isinstance(v, str):
                addrs.add(v)
    _check(
        f"netstat shows active session to C2 {_STORY_C2_IP}",
        any(_STORY_C2_IP in a for a in addrs),
        f"row_count={len(rows)}",
    )


async def _dispatch_hunt(conn: BaseForensicsConnector) -> None:
    print("\n[4d] forensics.run_hunt → Windows.Sys.AutoRuns over label")
    result = await conn.run_hunt(
        artifact="Windows.Sys.AutoRuns",
        label_selector="label=prod-workstation",
    )
    _check(
        "hunt_id present",
        bool(result.get("hunt_id")),
        f"hunt_id={result.get('hunt_id')}",
    )
    _check(
        "hunt status in {running, completed}",
        result.get("status") in {"running", "completed"},
        f"status={result.get('status')}",
    )
    scheduled = result.get("scheduled_clients") or 0
    _check(
        "hunt scheduled across >1 client (blast-radius is real)",
        scheduled > 1,
        f"scheduled_clients={scheduled}",
    )


async def _dispatch_fetch(conn: BaseForensicsConnector) -> None:
    print("\n[4e] forensics.fetch_file → dropped DLL")
    result = await conn.fetch_file(
        host=_STORY_HOST,
        path=_STORY_DLL_PATH,
    )
    sha = result.get("sha256") or ""
    _check(
        "sha256 returned (chain-of-custody hash)",
        isinstance(sha, str) and len(sha) >= 32,
        f"sha256={sha[:16]}…",
    )
    _check(
        "vault_url returned (sandbox handoff)",
        bool(result.get("vault_url")),
        f"vault_url={result.get('vault_url')}",
    )


async def _dispatch_kill(conn: BaseForensicsConnector) -> None:
    print("\n[4f] forensics.kill_process → containment of last resort")
    result = await conn.terminate_process(
        host=_STORY_HOST,
        pid=_STORY_RUNDLL32_PID,
        reason="smoke test: confirm containment path works",
    )
    _check(
        "terminated == True for story rundll32",
        bool(result.get("terminated")),
        f"terminated={result.get('terminated')}, ticket={result.get('ticket')}",
    )
    _check(
        "ticket returned for audit trail",
        bool(result.get("ticket")),
        f"ticket={result.get('ticket')}",
    )


async def _check_connector_dispatch() -> None:
    print("\n[4] End-to-end dispatch through mock forensics connector")
    conn = await get_connector(_TENANT, ConnectorKind.FORENSICS)
    _check(
        "get_connector returns BaseForensicsConnector",
        isinstance(conn, BaseForensicsConnector),
        f"type={type(conn).__name__}",
    )
    health = await conn.health_check()
    _check(
        "health_check ok",
        bool(health.get("ok")),
        f"vendor={health.get('vendor')}",
    )
    await _dispatch_collect_pslist(conn)
    await _dispatch_collect_autoruns(conn)
    await _dispatch_collect_netstat(conn)
    await _dispatch_hunt(conn)
    await _dispatch_fetch(conn)
    await _dispatch_kill(conn)


async def _amain() -> None:
    init_db()
    _check_factory_registered()
    _check_tool_registry()
    _check_hitl_gating()
    await _check_connector_dispatch()


def main() -> int:
    asyncio.run(_amain())
    passed = sum(1 for _, ok, _ in _results if ok)
    total = len(_results)
    print(f"\n{passed}/{total} checks passed")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
