#!/usr/bin/env python3
"""The golden pipeline: one real event through the real stack.

This is the canonical proof that AiSOC works end to end. It pushes a single
suspicious-PowerShell event into the ingest HTTP API and then follows it
through the actual production path — Kafka, fusion, detection, promotion,
Postgres — and finally reads it back out of the public API.

What it deliberately does NOT do
================================

It does not insert an alert. It does not call fusion's internals. It does not
stub Kafka. Every stage is observed from the outside, because a test that
reaches past a component cannot tell you that component works. The only thing
it asserts about the internals is what an operator could also check.

Each stage reports PASS or FAIL independently, so a break names the boundary
that broke rather than "the pipeline failed".

Usage
=====

    python3 tests/e2e/golden_pipeline/run_golden_pipeline.py

Environment (all optional; defaults match `docker compose up`):

    AISOC_INGEST_URL   default http://localhost:8081
    AISOC_API_URL      default http://localhost:8000
    AISOC_TENANT_ID    default the seeded canonical tenant
    AISOC_GOLDEN_TIMEOUT  seconds to wait for the alert (default 90)

Exit code is 0 only when every stage passes.
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field

INGEST_URL = os.environ.get("AISOC_INGEST_URL", "http://localhost:8081").rstrip("/")
API_URL = os.environ.get("AISOC_API_URL", "http://localhost:8000").rstrip("/")
TENANT_ID = os.environ.get("AISOC_TENANT_ID", "00000000-0000-0000-0000-000000000001")
TIMEOUT_SECONDS = int(os.environ.get("AISOC_GOLDEN_TIMEOUT", "90"))

#: Unique per run so a re-run cannot pass by finding the previous run's alert
#: — the failure mode that makes an end-to-end test permanently green.
RUN_ID = uuid.uuid4().hex[:12]
ALERT_TITLE = f"Golden pipeline: encoded PowerShell from Office [{RUN_ID}]"


@dataclass
class Report:
    stages: list[tuple[str, bool, str]] = field(default_factory=list)

    def record(self, name: str, ok: bool, detail: str = "") -> bool:
        self.stages.append((name, ok, detail))
        mark = "PASS" if ok else "FAIL"
        line = f"  [{mark}] {name}"
        if detail:
            line += f" — {detail}"
        print(line, flush=True)
        return ok

    @property
    def ok(self) -> bool:
        return all(ok for _, ok, _ in self.stages)


def _request(method: str, url: str, body: dict | None = None, timeout: float = 20.0) -> tuple[int, str]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    req.add_header("X-Tenant-ID", TENANT_ID)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed local URLs
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return 0, str(exc)


def golden_event() -> dict:
    """A realistic Windows endpoint detection.

    Office spawning an encoded PowerShell child is a genuine, widely-detected
    pattern (T1059.001 with T1566 delivery), so the alert this produces is
    recognisable rather than arbitrary.
    """
    return {
        "connector_id": f"golden-pipeline-{RUN_ID}",
        "connector_type": "crowdstrike",
        "source_format": "json",
        "events": [
            {
                "severity": "high",
                "title": ALERT_TITLE,
                "description": ("winword.exe spawned powershell.exe with an encoded command line on WIN-FIN-01"),
                "host": "WIN-FIN-01",
                "user": "j.doe",
                "process_name": "powershell.exe",
                "parent_process": "winword.exe",
                "command_line": "powershell.exe -nop -w hidden -enc JABzAD0A",
                "event_type": "process_create",
                "technique": "T1059.001",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }
        ],
    }


def main() -> int:
    print(f"\nGolden pipeline — run {RUN_ID}")
    print(f"  ingest: {INGEST_URL}")
    print(f"  api:    {API_URL}\n")
    r = Report()

    # ── 1. The two entry points are reachable ────────────────────────────
    status, body = _request("GET", f"{INGEST_URL}/health")
    if not r.record("ingest service is reachable", status == 200, f"HTTP {status}" if status != 200 else body[:60]):
        return _finish(r)

    status, body = _request("GET", f"{API_URL}/health")
    if not r.record("api service is reachable", status == 200, f"HTTP {status}" if status != 200 else ""):
        return _finish(r)

    # ── 2. Raw telemetry is accepted ─────────────────────────────────────
    status, body = _request("POST", f"{INGEST_URL}/v1/ingest/batch", golden_event(), timeout=30)
    accepted = 0
    if status == 200:
        try:
            accepted = int(json.loads(body).get("accepted", 0))
        except (ValueError, TypeError):
            accepted = 0
    if not r.record(
        "raw telemetry accepted by ingest",
        status == 200 and accepted == 1,
        f"HTTP {status} {body[:140]}",
    ):
        # The single most common cause, worth naming rather than making the
        # reader search: the broker refuses the first publish when the topic
        # does not exist and cannot be auto-created.
        print("\n  Hint: if this says 'failed to publish events', check Kafka:")
        print("    docker compose logs kafka | tail -40")
        print("    docker compose exec kafka kafka-topics --bootstrap-server localhost:29092 --list")
        return _finish(r)

    # ── 3..6. The event traverses Kafka -> fusion -> detection -> Postgres,
    # observed through the public API rather than by reaching inside. ─────
    print(f"\n  waiting up to {TIMEOUT_SECONDS}s for the alert to surface…", flush=True)
    deadline = time.time() + TIMEOUT_SECONDS
    alert: dict | None = None
    last_status = 0
    while time.time() < deadline:
        last_status, body = _request("GET", f"{API_URL}/api/v1/alerts?limit=50")
        if last_status == 200:
            try:
                items = json.loads(body).get("items", [])
            except (ValueError, TypeError):
                items = []
            for item in items:
                if RUN_ID in str(item.get("title", "")):
                    alert = item
                    break
        if alert:
            break
        time.sleep(3)

    if not r.record(
        "event traversed the spine and became an alert",
        alert is not None,
        "" if alert else (f"no alert carrying run id {RUN_ID} after {TIMEOUT_SECONDS}s (last API status {last_status})"),
    ):
        print("\n  The event was accepted but never became an alert. Check, in order:")
        print("    docker compose logs fusion | tail -60      # consumer + promotion")
        print("    docker compose exec kafka kafka-topics --bootstrap-server localhost:29092 --list")
        print("    docker compose exec postgres psql -U aisoc -d aisoc -c 'select count(*) from alerts;'")
        return _finish(r)

    assert alert is not None  # for type checkers; guarded above

    # ── 7. The alert is retrievable individually, not just in a list ─────
    alert_id = alert.get("id")
    status, body = _request("GET", f"{API_URL}/api/v1/alerts/{alert_id}")
    r.record("alert is retrievable by id from the API", status == 200, f"HTTP {status}" if status != 200 else str(alert_id))

    # ── 8. Provenance survived the journey ───────────────────────────────
    # These assertions exist because each one has been wrong in a shipped
    # release: severity collapsed, the vendor label doubled, and the
    # description arrived as a serialized payload.
    r.record(
        "severity survived normalization",
        alert.get("severity") in {"high", "critical"},
        f"severity={alert.get('severity')!r}",
    )

    connector_type = str(alert.get("connector_type") or "")
    words = connector_type.lower().split()
    r.record(
        "source attribution is not duplicated",
        bool(connector_type) and len(words) == len(set(words)),
        f"connector_type={connector_type!r}",
    )

    description = str(alert.get("description") or "")
    r.record(
        "description is prose, not a serialized payload",
        not description.strip().startswith(("{", "[")),
        f"description={description[:70]!r}",
    )

    return _finish(r)


def _finish(r: Report) -> int:
    passed = sum(1 for _, ok, _ in r.stages if ok)
    total = len(r.stages)
    print(f"\n{'PASS' if r.ok else 'FAIL'}: {passed}/{total} stages\n")
    return 0 if r.ok else 1


if __name__ == "__main__":
    sys.exit(main())
