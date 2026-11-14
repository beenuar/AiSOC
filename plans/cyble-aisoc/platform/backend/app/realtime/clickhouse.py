"""ClickHouse adapter for OCSF event analytics.

ClickHouse is the analytical sink that lets the platform answer
"give me every process_create from host-42 in the last 30 days"
without scanning a billion-row SQLite table. The realtime pipeline
publishes normalized OCSF events to the stream; this module
subscribes to that stream and lands them in ClickHouse in batches.

Design constraints mirror the rest of the realtime package:

* **Feature-flagged.** Off unless ``AISOC_CLICKHOUSE_URL`` is set.
  The platform must boot and run end-to-end on SQLite alone.
* **HTTP-based.** We talk to ClickHouse over its HTTP interface
  using stdlib + ``urllib.request`` so the base install does not
  pull a Confluent / clickhouse-driver dependency. Operators who
  want native protocol throughput can wire their own adapter.
* **Batched writes.** One INSERT per event would melt ClickHouse;
  we accumulate up to ``clickhouse_batch_size`` rows or
  ``clickhouse_flush_interval_seconds`` whichever fires first.
* **Best-effort.** A ClickHouse outage must not stall ingest. We
  log + drop the failed batch and keep draining the stream. The
  alternative (block the consumer) would back-pressure all the
  way to the producer and we'd lose detection in real time.

Schema bootstrap is idempotent: each boot issues
``CREATE TABLE IF NOT EXISTS`` so a fresh ClickHouse comes up
ready, and an existing one is left alone.
"""
from __future__ import annotations

import asyncio
import json
import logging
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

from app.realtime.ocsf import OcsfEvent
from app.realtime.stream import TOPICS, get_stream


log = logging.getLogger(__name__)


# ── Schema ─────────────────────────────────────────────────────────────
#
# ClickHouse columns mirror the OcsfEvent dataclass with a couple of
# pragmatic tweaks:
#
# * ``time`` becomes the partition + primary-key prefix for fast range
#   scans (`WHERE time BETWEEN ...`).
# * ``raw`` is stored as a String (JSON-encoded) instead of a Nested type
#   so heterogeneous vendor payloads don't fight the schema.
# * Tenant + source are the natural partitioning dimensions for most
#   ad-hoc queries; we order on them.

_CREATE_TABLE_DDL = """
CREATE TABLE IF NOT EXISTS {db}.{table}
(
    tenant_id        LowCardinality(String),
    source           LowCardinality(String),
    external_id      String,
    category_uid     UInt16,
    class_uid        UInt32,
    activity_id      UInt16,
    severity_id      UInt8,
    time             DateTime64(3, 'UTC'),
    actor_user       String,
    actor_process_name String,
    actor_process_cmdline String,
    actor_process_pid Nullable(UInt32),
    src_host         String,
    src_ip           String,
    dst_ip           String,
    dst_port         Nullable(UInt16),
    file_path        String,
    file_hash        String,
    title            String,
    description      String,
    normalization_dialect LowCardinality(String),
    raw              String
)
ENGINE = MergeTree
PARTITION BY (tenant_id, toYYYYMM(time))
ORDER BY (tenant_id, source, time)
TTL toDateTime(time) + INTERVAL 90 DAY
SETTINGS index_granularity = 8192
"""


@dataclass
class ClickHouseConfig:
    """Connection parameters resolved from settings."""

    url: str
    database: str
    table: str
    user: str
    password: str | None
    batch_size: int
    flush_interval: float


class ClickHouseSink:
    """Background consumer that lands OCSF events into ClickHouse.

    Lifecycle:

    * :meth:`start` — DDL bootstrap, spawn the consumer task.
    * :meth:`stop` — flush, cancel task, idempotent.

    Not safe to start twice; the module-level :func:`get_clickhouse_sink`
    factory guards that.
    """

    def __init__(self, cfg: ClickHouseConfig, *, tenant_topic: str = TOPICS.EVENTS_OCSF):
        self._cfg = cfg
        self._topic = tenant_topic
        self._task: asyncio.Task[None] | None = None
        self._queue: asyncio.Queue[dict[str, Any]] | None = None
        self._stopped = asyncio.Event()
        self._buffer: list[dict[str, Any]] = []
        self._buffer_lock = asyncio.Lock()

    async def start(self) -> None:
        """Bootstrap schema and start draining the stream."""
        try:
            await self._bootstrap_schema()
        except Exception as exc:  # noqa: BLE001
            # Schema bootstrap failure is non-fatal: we log it and let
            # the sink try to insert anyway. If the table truly doesn't
            # exist the INSERT will fail and we'll log per batch.
            log.warning("clickhouse: schema bootstrap failed: %s", exc)

        stream = get_stream()
        self._queue = await stream.subscribe(self._topic, group="clickhouse-sink")
        self._task = asyncio.create_task(self._run(), name="clickhouse-sink")
        log.info(
            "clickhouse: sink started url=%s db=%s table=%s",
            self._cfg.url, self._cfg.database, self._cfg.table,
        )

    async def stop(self) -> None:
        """Flush remaining buffer and stop the consumer."""
        self._stopped.set()
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
            self._task = None
        if self._queue is not None:
            try:
                stream = get_stream()
                await stream.unsubscribe(self._queue)
            except Exception as exc:  # noqa: BLE001
                log.warning("clickhouse: unsubscribe failed: %s", exc)
            self._queue = None
        # Final flush.
        await self._flush()

    async def _run(self) -> None:
        """Drain the stream, batching by size + time."""
        assert self._queue is not None
        last_flush = asyncio.get_event_loop().time()
        try:
            while not self._stopped.is_set():
                timeout = max(
                    0.05,
                    self._cfg.flush_interval - (asyncio.get_event_loop().time() - last_flush),
                )
                try:
                    envelope = await asyncio.wait_for(self._queue.get(), timeout=timeout)
                except asyncio.TimeoutError:
                    envelope = None
                if envelope is not None:
                    async with self._buffer_lock:
                        self._buffer.append(envelope)
                now = asyncio.get_event_loop().time()
                async with self._buffer_lock:
                    full = len(self._buffer) >= self._cfg.batch_size
                if full or (now - last_flush) >= self._cfg.flush_interval:
                    await self._flush()
                    last_flush = now
        except asyncio.CancelledError:
            pass

    async def _flush(self) -> None:
        async with self._buffer_lock:
            if not self._buffer:
                return
            batch = self._buffer
            self._buffer = []
        try:
            await self._insert(batch)
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "clickhouse: flush failed (dropping %d events): %s",
                len(batch), exc,
            )

    # ── HTTP helpers ───────────────────────────────────────────────────

    async def _bootstrap_schema(self) -> None:
        ddl = _CREATE_TABLE_DDL.format(
            db=self._cfg.database, table=self._cfg.table
        )
        # CREATE DATABASE first; harmless if it exists.
        await self._exec(f"CREATE DATABASE IF NOT EXISTS {self._cfg.database}")
        await self._exec(ddl)

    async def _exec(self, sql: str) -> None:
        """Fire a SQL statement at ClickHouse, no response body expected."""
        await asyncio.to_thread(self._post_raw, sql)

    async def _insert(self, batch: list[dict[str, Any]]) -> None:
        """Bulk insert using JSONEachRow for resilience to schema additions."""
        if not batch:
            return
        # We accept either OcsfEvent envelopes from the stream (with a
        # leading ``_topic`` key) or raw dicts. Strip transport keys.
        rows: list[str] = []
        for env in batch:
            payload = {k: v for k, v in env.items() if not k.startswith("_")}
            payload.setdefault("tenant_id", "demo-tenant")
            # ``raw`` may already be a dict; ClickHouse wants the column
            # populated as a JSON string for our schema.
            if isinstance(payload.get("raw"), (dict, list)):
                payload["raw"] = json.dumps(payload["raw"], default=str)
            rows.append(json.dumps(payload, default=str))
        body = "\n".join(rows).encode("utf-8")
        # URL-encode the query so spaces and SQL punctuation survive transit
        # (Python 3.12+ rejects control characters in URLs, and ClickHouse
        # requires the query in the ``query=`` parameter on INSERT).
        params = urllib.parse.urlencode(
            {
                "database": self._cfg.database,
                "query": f"INSERT INTO {self._cfg.table} FORMAT JSONEachRow",
            }
        )
        url = f"{self._cfg.url.rstrip('/')}/?{params}"
        await asyncio.to_thread(self._post_bytes, url, body)

    def _post_raw(self, sql: str) -> None:
        params = urllib.parse.urlencode({"database": self._cfg.database})
        url = f"{self._cfg.url.rstrip('/')}/?{params}"
        self._post_bytes(url, sql.encode("utf-8"))

    def _post_bytes(self, url: str, body: bytes) -> None:
        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("Content-Type", "text/plain; charset=utf-8")
        if self._cfg.user:
            req.add_header("X-ClickHouse-User", self._cfg.user)
        if self._cfg.password:
            req.add_header("X-ClickHouse-Key", self._cfg.password)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                resp.read()
        except urllib.error.HTTPError as exc:
            # Surface the server's error body so the operator can debug.
            try:
                detail = exc.read().decode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001
                detail = ""
            raise RuntimeError(f"clickhouse HTTP {exc.code}: {detail[:500]}") from exc


# ── Module-level singleton ─────────────────────────────────────────────


_sink: ClickHouseSink | None = None


def is_enabled() -> bool:
    """True iff the operator configured a ClickHouse URL."""
    from app.config import settings
    return bool(getattr(settings, "clickhouse_url", None))


async def start_clickhouse_sink() -> ClickHouseSink | None:
    """Idempotent entry point used by app startup.

    Returns ``None`` if ClickHouse isn't configured — the app keeps
    running on SQLite-only.
    """
    global _sink
    if not is_enabled():
        return None
    if _sink is not None:
        return _sink
    from app.config import settings

    cfg = ClickHouseConfig(
        url=settings.clickhouse_url,  # type: ignore[arg-type]
        database=settings.clickhouse_database,
        table=settings.clickhouse_events_table,
        user=settings.clickhouse_user,
        password=settings.clickhouse_password,
        batch_size=settings.clickhouse_batch_size,
        flush_interval=settings.clickhouse_flush_interval_seconds,
    )
    sink = ClickHouseSink(cfg)
    await sink.start()
    _sink = sink
    return sink


async def stop_clickhouse_sink() -> None:
    global _sink
    if _sink is not None:
        await _sink.stop()
        _sink = None


def ocsf_event_to_row(oe: OcsfEvent, *, tenant_id: str) -> dict[str, Any]:
    """Helper for direct (non-stream) inserts — used by tests + ingest."""
    row = oe.to_dict()
    row["tenant_id"] = tenant_id
    if isinstance(row.get("raw"), (dict, list)):
        row["raw"] = json.dumps(row["raw"], default=str)
    return row
