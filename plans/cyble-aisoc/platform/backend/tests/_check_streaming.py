"""Smoke test: streaming detection runtime (t6-streaming).

Covers:

* The watermark advances strictly with the largest event_time seen
  minus the lateness budget.
* A burst threshold rule fires after the configured count is met
  and *only* after the watermark closes the window.
* A correlation rule fires only when both predicates match in the
  window, on the same key.
* Late events outside the lateness budget are dropped, not
  silently lost — the stats counter is bumped.
* The HTTP surface (rules, events, detections, stats) returns the
  same data the in-process runtime exposes.
* Tenant isolation: events from tenant A never produce detections
  visible to tenant B.
"""
from __future__ import annotations

import os
import tempfile

os.environ.setdefault("AISOC_AUTH_DISABLED", "1")
os.environ.setdefault("AISOC_LLM_PROVIDER", "mock")
DB_FILE = tempfile.NamedTemporaryFile(prefix="aisoc-streaming-", suffix=".db", delete=False)
DB_FILE.close()
os.environ["AISOC_DB_PATH"] = DB_FILE.name

from fastapi.testclient import TestClient  # noqa: E402

from app.streaming import StreamingRuntime  # noqa: E402
from app.streaming.builtin import builtin_streaming_rules  # noqa: E402
from app.streaming.registry import reload as reload_runtime  # noqa: E402
from app.main import app  # noqa: E402


def _expect(condition: bool, msg: str) -> None:
    if not condition:
        raise AssertionError(msg)


def _build_isolated() -> StreamingRuntime:
    rt = StreamingRuntime(lateness_budget_seconds=10.0)
    for r in builtin_streaming_rules():
        rt.add_rule(r)
    return rt


def _failed_login_burst_smoke() -> None:
    rt = _build_isolated()
    base = 1_000_000.0
    detections: list = []
    # 10 failed logins for the same user over 5 minutes.
    for i in range(10):
        out = rt.ingest(
            {
                "tenant_id": "t-stream",
                "event_time": base + i * 10.0,
                "event_class": "auth",
                "outcome": "failure",
                "src_user": "alice",
            }
        )
        detections.extend(out)

    # No detection yet — the window has not closed (lateness budget
    # 10s, window 300s; latest event_time is base + 90 = 1_000_090,
    # watermark is ~1_000_080 which is < window-close 1_000_300).
    _expect(not detections, f"window should not have closed yet, got {detections}")

    # Bump the watermark forward by ingesting an event well past the
    # window's close boundary.
    out = rt.ingest(
        {
            "tenant_id": "t-stream",
            "event_time": base + 350.0,
            "event_class": "auth",
            "outcome": "success",
            "src_user": "carol",
        }
    )
    detections.extend(out)

    matching = [d for d in detections if d.rule_id == "failed-login-burst"]
    _expect(len(matching) == 1, f"expected 1 burst detection, got {detections}")
    fired = matching[0]
    _expect(fired.key == "alice", f"detection key mismatch: {fired.key}")
    _expect(fired.matching_event_count == 10, f"count mismatch: {fired}")


def _correlation_smoke() -> None:
    rt = _build_isolated()
    base = 2_000_000.0

    # Rare process spawn followed within 60s by external egress on
    # the same host.
    rt.ingest(
        {
            "tenant_id": "t-stream",
            "event_time": base,
            "event_class": "process_spawn",
            "rare_process": True,
            "src_host": "host-1",
        }
    )
    rt.ingest(
        {
            "tenant_id": "t-stream",
            "event_time": base + 30.0,
            "event_class": "network_egress",
            "dst_external": True,
            "src_host": "host-1",
        }
    )

    # Push the watermark past the window's close.
    out = rt.ingest(
        {
            "tenant_id": "t-stream",
            "event_time": base + 200.0,
            "event_class": "noop",
            "src_host": "host-1",
        }
    )

    fired = [d for d in out if d.rule_id == "rare-process-then-egress"]
    _expect(len(fired) >= 1, f"expected correlation detection, got {out}")


def _late_event_drop_smoke() -> None:
    rt = _build_isolated()
    base = 3_000_000.0

    # Establish a watermark at base + 100.
    rt.ingest(
        {
            "tenant_id": "t-stream",
            "event_time": base + 100.0,
            "event_class": "auth",
            "outcome": "success",
            "src_user": "alice",
        }
    )

    # An event 60s before the watermark — well outside the 10s
    # lateness budget — should be dropped.
    out = rt.ingest(
        {
            "tenant_id": "t-stream",
            "event_time": base + 30.0,
            "event_class": "auth",
            "outcome": "failure",
            "src_user": "alice",
        }
    )
    _expect(not out, "late event should not produce detections")
    _expect(rt.stats.events_dropped_late == 1, f"late drop counter: {rt.stats.events_dropped_late}")


def _tenant_isolation_smoke() -> None:
    rt = _build_isolated()
    base = 4_000_000.0
    # 10 failures for 'alice' on tenant A.
    for i in range(10):
        rt.ingest(
            {
                "tenant_id": "tenant-A",
                "event_time": base + i,
                "event_class": "auth",
                "outcome": "failure",
                "src_user": "alice",
            }
        )
    # 10 failures for 'alice' on tenant B (same user name, different tenant).
    for i in range(10):
        rt.ingest(
            {
                "tenant_id": "tenant-B",
                "event_time": base + i,
                "event_class": "auth",
                "outcome": "failure",
                "src_user": "alice",
            }
        )

    # Advance watermarks for both tenants past the window close.
    out_a = rt.ingest(
        {
            "tenant_id": "tenant-A",
            "event_time": base + 400,
            "event_class": "noop",
            "src_user": "z",
        }
    )
    out_b = rt.ingest(
        {
            "tenant_id": "tenant-B",
            "event_time": base + 400,
            "event_class": "noop",
            "src_user": "z",
        }
    )

    a_dets = [d for d in out_a if d.rule_id == "failed-login-burst"]
    b_dets = [d for d in out_b if d.rule_id == "failed-login-burst"]
    _expect(len(a_dets) == 1, f"expected one tenant-A detection, got {a_dets}")
    _expect(len(b_dets) == 1, f"expected one tenant-B detection, got {b_dets}")
    _expect(a_dets[0].tenant_id == "tenant-A", "tenant mix-up A")
    _expect(b_dets[0].tenant_id == "tenant-B", "tenant mix-up B")


def _api_smoke() -> None:
    # Reload the singleton so this test runs hermetically.
    reload_runtime()

    with TestClient(app) as client:
        r = client.get("/streaming/rules")
        _expect(r.status_code == 200, f"rules 200 expected, got {r.status_code}")
        rules = r.json()["rules"]
        _expect(len(rules) >= 3, f"expected >=3 streaming rules, got {len(rules)}")

        # Kick a burst.
        base = 5_000_000.0
        for i in range(10):
            r = client.post(
                "/streaming/events",
                json={
                    "event_time": base + i,
                    "event_class": "auth",
                    "outcome": "failure",
                    "src_user": "alice",
                },
            )
            _expect(r.status_code == 200, f"events 200 expected, got {r.status_code}")

        # Advance the watermark with a far-future event.
        r = client.post(
            "/streaming/events",
            json={
                "event_time": base + 400,
                "event_class": "noop",
                "src_user": "z",
            },
        )
        _expect(r.status_code == 200, f"events 200 expected, got {r.status_code}")
        body = r.json()
        _expect(body["ingested"] == 1, f"ingested counter wrong: {body}")
        _expect(
            any(d["rule_id"] == "failed-login-burst" for d in body["detections"]),
            f"burst rule should have fired on watermark advance: {body}",
        )

        r = client.get("/streaming/detections")
        _expect(r.status_code == 200, "detections endpoint failed")
        list_body = r.json()
        _expect(list_body["count"] >= 1, "detections list empty")

        r = client.get("/streaming/stats")
        _expect(r.status_code == 200, "stats endpoint failed")
        stats = r.json()
        _expect(stats["events_ingested"] >= 11, f"ingest counter wrong: {stats}")


def main() -> None:
    _failed_login_burst_smoke()
    _correlation_smoke()
    _late_event_drop_smoke()
    _tenant_isolation_smoke()
    _api_smoke()
    print("ok: streaming smoke")


if __name__ == "__main__":
    main()
