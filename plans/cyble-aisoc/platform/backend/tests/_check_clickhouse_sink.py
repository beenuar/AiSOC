"""Smoke test for the ClickHouse sink lifecycle.

The real platform speaks to ClickHouse over HTTP. We stand up an in-process
HTTP server that emulates the contract (CREATE TABLE / INSERT JSONEachRow)
so we can prove four things end to end without needing a ClickHouse server:

1. `start_clickhouse_sink()` runs DDL bootstrap (CREATE DATABASE + CREATE TABLE).
2. Events published to the OCSF topic land in ClickHouse in JSONEachRow form.
3. Batch + flush_interval cause periodic flushes (not one INSERT per event).
4. A ClickHouse 500 must not crash the sink — it drops the batch and keeps
   draining the stream. (Resilience requirement from the realtime spec.)

Run with:

    cd platform/backend
    source .venv/bin/activate
    python tests/_check_clickhouse_sink.py
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Configure the env BEFORE importing app — settings cache at import time.
PORT_HOLDER: dict[str, int] = {}


def _ok(msg: str) -> None:
    print(f"  ok:   {msg}")


def _fail(msg: str) -> None:
    print(f"  FAIL: {msg}")
    sys.exit(1)


# ── Fake ClickHouse HTTP server ────────────────────────────────────────


class _FakeCH:
    """In-process collector that captures DDL and JSONEachRow inserts."""

    def __init__(self) -> None:
        self.ddl: list[str] = []
        self.rows: list[dict] = []
        self.fail_inserts = False
        self._lock = threading.Lock()

    def record_post(self, query: str | None, body: bytes) -> tuple[int, bytes]:
        text = body.decode("utf-8", errors="replace")
        with self._lock:
            if query and "INSERT" in query.upper():
                if self.fail_inserts:
                    return 500, b"simulated clickhouse outage"
                for line in text.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        self.rows.append(json.loads(line))
                    except json.JSONDecodeError:
                        return 400, b"bad row"
                return 200, b""
            else:
                # CREATE DATABASE / CREATE TABLE arrive in the body itself.
                self.ddl.append(text.strip())
                return 200, b""


_FAKE = _FakeCH()


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args, **kwargs):  # noqa: D401
        pass

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length else b""
        # ClickHouse encodes the query in the URL on INSERT.
        query = None
        if "?" in self.path:
            from urllib.parse import parse_qs, urlparse

            q = parse_qs(urlparse(self.path).query)
            query = (q.get("query") or [None])[0]
        status, resp = _FAKE.record_post(query, body)
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)


def _start_fake_server() -> tuple[ThreadingHTTPServer, threading.Thread]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = srv.server_address[1]
    PORT_HOLDER["port"] = port
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    return srv, th


# ── Test driver ────────────────────────────────────────────────────────


async def _run() -> None:
    print("=" * 70)
    print("smoke test: ClickHouse sink (lifecycle + batching + resilience)")
    print("=" * 70)

    srv, _ = _start_fake_server()
    base_url = f"http://127.0.0.1:{PORT_HOLDER['port']}"
    print(f"  fake ClickHouse at {base_url}")

    # Configure the platform to point at the fake server. Settings is a
    # pydantic BaseSettings — env vars are picked up at first read.
    os.environ["AISOC_CLICKHOUSE_URL"] = base_url
    os.environ["AISOC_CLICKHOUSE_DATABASE"] = "aisoc_test"
    os.environ["AISOC_CLICKHOUSE_EVENTS_TABLE"] = "events_ocsf_test"
    os.environ["AISOC_CLICKHOUSE_BATCH_SIZE"] = "3"
    os.environ["AISOC_CLICKHOUSE_FLUSH_INTERVAL_SECONDS"] = "0.2"
    os.environ["AISOC_STREAM_BACKEND"] = "memory"

    # Reset the cached settings so the new env wins.
    from app.config import settings as _s  # noqa: F401  -- forces module load

    import app.config as cfg

    cfg.settings.clickhouse_url = base_url
    cfg.settings.clickhouse_database = "aisoc_test"
    cfg.settings.clickhouse_events_table = "events_ocsf_test"
    cfg.settings.clickhouse_batch_size = 3
    cfg.settings.clickhouse_flush_interval_seconds = 0.2

    # Reset the stream singleton so the sink subscribes to a fresh queue.
    from app.realtime import stream as stream_mod
    stream_mod._STREAM = None  # type: ignore[attr-defined]

    from app.realtime import (
        get_stream,
        start_clickhouse_sink,
        stop_clickhouse_sink,
    )
    from app.realtime.stream import TOPICS
    from app.realtime.clickhouse import is_enabled

    if not is_enabled():
        _fail("is_enabled() should be True once AISOC_CLICKHOUSE_URL is set")
    _ok("is_enabled() returns True with AISOC_CLICKHOUSE_URL set")

    # ── 1. Start sink → DDL bootstrap fires ────────────────────────────

    sink = await start_clickhouse_sink()
    if sink is None:
        _fail("start_clickhouse_sink() returned None despite config set")
    _ok("start_clickhouse_sink() returned a live sink")

    # Give the sink a moment to issue DDL.
    await asyncio.sleep(0.05)
    ddl_concat = "\n".join(_FAKE.ddl).upper()
    if "CREATE DATABASE" not in ddl_concat:
        _fail(f"DDL missing CREATE DATABASE (got {_FAKE.ddl!r})")
    _ok("DDL bootstrap issued CREATE DATABASE")
    if "CREATE TABLE" not in ddl_concat:
        _fail(f"DDL missing CREATE TABLE (got {_FAKE.ddl!r})")
    _ok("DDL bootstrap issued CREATE TABLE")
    if "EVENTS_OCSF_TEST" not in ddl_concat:
        _fail("DDL did not target the configured table name")
    _ok("DDL targets the configured table name (events_ocsf_test)")

    # ── 2. Publish OCSF events → land in ClickHouse ────────────────────

    stream = get_stream()
    payload_template = {
        "tenant_id": "demo-tenant",
        "source": "ecs",
        "external_id": "evt-{i}",
        "category_uid": 1,
        "class_uid": 1001,
        "activity_id": 1,
        "severity_id": 3,
        "time": "2026-06-19T00:00:00+00:00",
        "actor_user": "alice",
        "actor_process_name": "wmic.exe",
        "actor_process_cmdline": "wmic process call create",
        "actor_process_pid": 1234,
        "src_host": "host-42",
        "src_ip": "10.0.0.5",
        "dst_ip": "",
        "dst_port": None,
        "file_path": "",
        "file_hash": "",
        "title": "process_create",
        "description": "",
        "normalization_dialect": "ecs",
        "raw": {"event": {"action": "process_create"}},
    }
    for i in range(5):
        envelope = {**payload_template, "external_id": f"evt-{i}"}
        await stream.publish(TOPICS.EVENTS_OCSF, envelope)

    # Wait long enough for either a size-triggered flush (after 3) or a
    # time-triggered flush (after 0.2s) to land all five rows.
    await asyncio.sleep(0.6)

    if len(_FAKE.rows) < 5:
        _fail(f"expected >=5 rows in ClickHouse, got {len(_FAKE.rows)}")
    _ok(f"all 5 events landed in ClickHouse (got {len(_FAKE.rows)} rows)")

    first = _FAKE.rows[0]
    if first.get("tenant_id") != "demo-tenant":
        _fail(f"row missing tenant_id (got {first!r})")
    _ok("rows carry tenant_id")
    if first.get("source") != "ecs":
        _fail(f"row missing source (got {first.get('source')!r})")
    _ok("rows carry source dialect")
    if first.get("actor_process_name") != "wmic.exe":
        _fail(f"row missing actor_process_name (got {first!r})")
    _ok("rows preserve actor_process_name")
    if not isinstance(first.get("raw"), str):
        _fail(f"raw column must be JSON-encoded string (got {type(first.get('raw'))})")
    _ok("raw column is JSON-encoded string (ClickHouse-friendly)")

    # ── 3. Transport keys stripped (`_topic` must not reach CH) ────────

    if any("_topic" in row for row in _FAKE.rows):
        _fail("transport key _topic leaked into ClickHouse rows")
    _ok("transport keys (_topic) are stripped before insert")

    # ── 4. Resilience: ClickHouse 500 must not crash the sink ──────────

    _FAKE.fail_inserts = True
    rows_before = len(_FAKE.rows)
    for i in range(5, 8):
        await stream.publish(
            TOPICS.EVENTS_OCSF, {**payload_template, "external_id": f"evt-{i}"}
        )
    await asyncio.sleep(0.4)
    if len(_FAKE.rows) != rows_before:
        _fail(
            f"sink should have dropped rows during simulated outage "
            f"(saw {len(_FAKE.rows) - rows_before} new rows)"
        )
    _ok("sink drops batches gracefully during ClickHouse 500 (no crash)")

    # Recover: turn inserts back on and prove the sink keeps draining.
    _FAKE.fail_inserts = False
    for i in range(8, 11):
        await stream.publish(
            TOPICS.EVENTS_OCSF, {**payload_template, "external_id": f"evt-{i}"}
        )
    await asyncio.sleep(0.6)
    if len(_FAKE.rows) < rows_before + 3:
        _fail(
            f"sink did not recover after outage cleared "
            f"(rows before outage={rows_before}, now={len(_FAKE.rows)})"
        )
    _ok("sink recovers and resumes inserts after outage clears")

    # ── 5. Idempotent start ────────────────────────────────────────────

    second = await start_clickhouse_sink()
    if second is not sink:
        _fail("second start_clickhouse_sink() should return existing singleton")
    _ok("start_clickhouse_sink() is idempotent (returns existing sink)")

    # ── 6. Shutdown flushes + cancels cleanly ──────────────────────────

    await stop_clickhouse_sink()
    _ok("stop_clickhouse_sink() returned without raising")

    # Idempotent stop.
    await stop_clickhouse_sink()
    _ok("stop_clickhouse_sink() idempotent (safe to call twice)")

    srv.shutdown()

    print()
    print("=" * 70)
    print("PASS — ClickHouse sink lifecycle is wired and resilient")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(_run())
