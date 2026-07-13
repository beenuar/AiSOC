"""Write normalized OCSF events into the ClickHouse event lake (Phase A1).

The reality audit found the central SIEM gap: ingest publishes normalized OCSF
events to Kafka and fusion promotes a subset into Postgres alerts, but
**nothing populated the ClickHouse ``aisoc.raw_events`` lake** — the table and
its read API (``/api/v1/lake/sql``) existed with no writer, so every hunt/query
ran against an empty warehouse.

This module closes that gap. Fusion already deserializes every ``aisoc.raw_events``
Kafka message (for promotion), so it is the natural place to also archive each
event into the lake. Archival is independent of the promotion decision: a
Medium-severity event that is (correctly) not promoted to an alert must still be
queryable in the lake.

Design constraints (mirroring ``AlertSink``):

* **Fail-soft.** A ClickHouse outage must degrade to "events still flow through
  Kafka/fusion, lake archival is dropped for the outage window" — never crash
  the consumer. A failed flush drops that batch (best-effort archival) rather
  than growing an unbounded in-memory buffer.
* **Batched.** ClickHouse is happiest with bulk inserts, so events are buffered
  and flushed by size (``batch_size``) or age (``batch_max_age_seconds``); the
  consumer calls :meth:`flush_if_stale` each loop and :meth:`flush` on stop.
* **At-least-once with a deterministic ``event_id``.** MergeTree does not
  deduplicate, so a Kafka replay can produce a duplicate lake row. Each row
  carries the ingest event id (when it is a valid UUID) so downstream queries
  can ``argMax``/``LIMIT 1 BY event_id`` if exact-once is required. The Phase A1
  gate asserts *queryability* (``count >= 1``), not exact-once.

``clickhouse-driver`` is synchronous, so every insert is dispatched to a worker
thread via :func:`asyncio.to_thread` to keep the fusion event loop responsive.
If the driver is not installed (some dev images), the writer disables itself at
construction and logs once, rather than failing fusion import.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import time
import uuid
from datetime import UTC, datetime
from typing import Any

import structlog

logger = structlog.get_logger()

# Column order for the INSERT — must match ``_row`` and the ClickHouse schema in
# ``services/api/clickhouse/001_init.sql``.
_COLUMNS = (
    "event_id",
    "tenant_id",
    "event_time",
    "class_uid",
    "category_uid",
    "severity_id",
    "severity",
    "activity_id",
    "source_ip",
    "dest_ip",
    "src_port",
    "dst_port",
    "protocol",
    "src_hostname",
    "dst_hostname",
    "user_name",
    "process_name",
    "file_path",
    "hash_sha256",
    "connector_type",
    "raw_payload",
    "ocsf_json",
    "mitre_techniques",
    "mitre_tactics",
    "iocs",
)

_INSERT_SQL = f"INSERT INTO aisoc.raw_events ({', '.join(_COLUMNS)}) VALUES"

# ClickHouse IPv6 columns reject empty/invalid strings; "::" is the safe null.
_NULL_IP = "::"


def _get(obj: Any, *path: str) -> Any:
    cur: Any = obj
    for key in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _as_str(value: Any) -> str:
    return value if isinstance(value, str) else ("" if value is None else str(value))


def _as_ip(value: Any) -> str:
    """Normalise to a valid IP string; '::' when absent/invalid.

    Kept as a string in the row dict (readable, serialisable); converted to an
    ``ipaddress`` object only at insert time by :func:`_to_ip_obj`.
    """
    if not isinstance(value, str) or not value.strip():
        return _NULL_IP
    candidate = value.strip()
    try:
        ipaddress.ip_address(candidate)
        return candidate
    except ValueError:
        return _NULL_IP


def _to_ip_obj(value: str) -> ipaddress.IPv6Address:
    """Bind an IPv6-typed ClickHouse column.

    The column is ``IPv6``, so an IPv4 address must be mapped to its
    IPv4-mapped IPv6 form (``::ffff:a.b.c.d``); the driver rejects a bare
    ``IPv4Address``. Invalid input -> the null IPv6 ``::``.
    """
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return ipaddress.IPv6Address(_NULL_IP)
    if isinstance(addr, ipaddress.IPv4Address):
        return ipaddress.IPv6Address("::ffff:" + str(addr))
    return addr


def _tenant_uuid(message: dict[str, Any], ocsf: dict[str, Any]) -> str | None:
    raw = message.get("tenant_id") or ocsf.get("tenant_uid")
    try:
        return str(uuid.UUID(str(raw)))
    except (TypeError, ValueError):
        return None


def _event_time(ocsf: dict[str, Any]) -> datetime:
    """Return a naive-UTC ``datetime`` for the ClickHouse DateTime64 column.

    clickhouse-driver maps a Python ``datetime`` (not a string) onto DateTime64;
    a bad/absent timestamp falls back to now().
    """
    raw = ocsf.get("time")
    if isinstance(raw, str) and raw.strip():
        try:
            dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            return dt.astimezone(UTC).replace(tzinfo=None)
        except ValueError:
            pass
    return datetime.now(UTC).replace(tzinfo=None)


def _first_hash(ocsf: dict[str, Any]) -> str:
    fps = _get(ocsf, "file", "fingerprints")
    if isinstance(fps, list) and fps and isinstance(fps[0], dict):
        return _as_str(fps[0].get("value"))
    return _as_str(ocsf.get("hash_sha256"))


def _mitre(ocsf: dict[str, Any]) -> tuple[list[str], list[str]]:
    techniques: list[str] = []
    tactics: list[str] = []
    block = ocsf.get("mitre_attck")
    if isinstance(block, list):
        for entry in block:
            if not isinstance(entry, dict):
                continue
            tid = entry.get("technique_id")
            if isinstance(tid, str) and tid and tid not in techniques:
                techniques.append(tid)
            for name in entry.get("tactic_names") or []:
                if isinstance(name, str) and name and name not in tactics:
                    tactics.append(name)
    return techniques, tactics


def _iocs(ocsf: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for value in (
        _get(ocsf, "src_endpoint", "ip"),
        _get(ocsf, "dst_endpoint", "ip"),
        _first_hash(ocsf),
    ):
        if isinstance(value, str) and value.strip():
            out.append(value.strip())
    return out


def event_to_row(message: dict[str, Any]) -> dict[str, Any] | None:
    """Map an ingest NormalizedEvent envelope to a ClickHouse row dict.

    Returns ``None`` when the message has no OCSF body or no UUID tenant — such
    messages are handled (dead-lettered) elsewhere and must not reach the lake.
    """
    ocsf = message.get("ocsf_event")
    if not isinstance(ocsf, dict):
        return None
    tenant = _tenant_uuid(message, ocsf)
    if tenant is None:
        return None

    techniques, tactics = _mitre(ocsf)
    connector_type = _as_str(_get(ocsf, "metadata", "product", "name")) or _as_str(message.get("connector_type"))

    row: dict[str, Any] = {
        "tenant_id": tenant,
        "event_time": _event_time(ocsf),
        "class_uid": _as_int(ocsf.get("class_uid")),
        "category_uid": _as_int(ocsf.get("category_uid")),
        "severity_id": _as_int(ocsf.get("severity_id")),
        "severity": _as_str(ocsf.get("severity")),
        "activity_id": _as_int(ocsf.get("activity_id")),
        "source_ip": _as_ip(_get(ocsf, "src_endpoint", "ip")),
        "dest_ip": _as_ip(_get(ocsf, "dst_endpoint", "ip")),
        "src_port": _as_int(_get(ocsf, "src_endpoint", "port")),
        "dst_port": _as_int(_get(ocsf, "dst_endpoint", "port")),
        "protocol": _as_str(ocsf.get("protocol") or _get(ocsf, "connection_info", "protocol_name")),
        "src_hostname": _as_str(_get(ocsf, "device", "name") or _get(ocsf, "src_endpoint", "hostname")),
        "dst_hostname": _as_str(_get(ocsf, "dst_endpoint", "hostname")),
        "user_name": _as_str(_get(ocsf, "actor", "user", "name")),
        "process_name": _as_str(_get(ocsf, "process", "name")),
        "file_path": _as_str(_get(ocsf, "file", "path")),
        "hash_sha256": _first_hash(ocsf),
        "connector_type": connector_type,
        "raw_payload": _as_str(ocsf.get("raw_data"))[:65536],
        "ocsf_json": json.dumps(ocsf, default=str)[:262144],
        "mitre_techniques": techniques,
        "mitre_tactics": tactics,
        "iocs": _iocs(ocsf),
    }

    # Only set a deterministic event_id when the ingest id is a real UUID;
    # otherwise let ClickHouse default generateUUIDv4().
    raw_id = message.get("id") or message.get("event_id")
    try:
        row["event_id"] = str(uuid.UUID(str(raw_id)))
    except (TypeError, ValueError):
        row["event_id"] = None
    return row


class LakeWriter:
    """Batched, fail-soft ClickHouse writer for the ``aisoc.raw_events`` lake."""

    def __init__(
        self,
        *,
        host: str,
        port: int = 9000,
        database: str = "aisoc",
        user: str = "default",
        password: str = "",
        batch_size: int = 100,
        batch_max_age_seconds: float = 2.0,
    ) -> None:
        self._host = host
        self._port = port
        self._database = database
        self._user = user
        self._password = password
        self._batch_size = max(1, batch_size)
        self._batch_max_age = batch_max_age_seconds
        self._client: Any | None = None
        self._buffer: list[dict[str, Any]] = []
        self._buffer_started_at: float = 0.0
        self._disabled = False
        self.rows_written = 0
        self.flush_failures = 0

    async def start(self) -> None:
        if self._disabled:
            return
        try:
            from clickhouse_driver import Client  # noqa: PLC0415

            self._client = Client(
                host=self._host,
                port=self._port,
                database=self._database,
                user=self._user,
                password=self._password or "",
                connect_timeout=10,
            )
            logger.info("lake_writer.started", host=self._host, database=self._database)
        except ImportError:
            self._disabled = True
            logger.warning("lake_writer.disabled_no_driver")
        except Exception as exc:  # noqa: BLE001 — degrade, never crash the worker
            self._disabled = True
            logger.error("lake_writer.connect_failed", error=str(exc))

    async def stop(self) -> None:
        await self.flush()
        if self._client is not None:
            try:
                await asyncio.to_thread(self._client.disconnect)
            except Exception as exc:  # noqa: BLE001
                logger.warning("lake_writer.disconnect_failed", error=str(exc))
            self._client = None

    async def write_event(self, message: dict[str, Any]) -> bool:
        """Buffer one normalized event for the lake. Returns True if buffered.

        Flushes automatically when the buffer reaches ``batch_size``.
        """
        if self._disabled:
            return False
        row = event_to_row(message)
        if row is None:
            return False
        if not self._buffer:
            self._buffer_started_at = time.monotonic()
        self._buffer.append(row)
        if len(self._buffer) >= self._batch_size:
            await self.flush()
        return True

    async def flush_if_stale(self) -> None:
        if self._buffer and (time.monotonic() - self._buffer_started_at) >= self._batch_max_age:
            await self.flush()

    async def flush(self) -> None:
        if self._disabled or not self._buffer:
            return
        batch = self._buffer
        self._buffer = []
        client = self._client
        if client is None:
            return

        def _insert() -> None:
            # clickhouse-driver executes INSERT ... VALUES with a list of dicts.
            # Coerce the typed columns (IPv6) to the objects the driver binds,
            # and omit event_id when None so the column DEFAULT applies.
            rows: list[dict[str, Any]] = []
            for row in batch:
                out = {k: v for k, v in row.items() if not (k == "event_id" and v is None)}
                out["source_ip"] = _to_ip_obj(row["source_ip"])
                out["dest_ip"] = _to_ip_obj(row["dest_ip"])
                rows.append(out)
            client.execute(_INSERT_SQL, rows, types_check=True)

        try:
            await asyncio.to_thread(_insert)
            self.rows_written += len(batch)
        except Exception as exc:  # noqa: BLE001 — best-effort archival; drop the batch
            self.flush_failures += 1
            logger.error("lake_writer.flush_failed", error=str(exc), dropped=len(batch))

    def metrics(self) -> dict[str, int]:
        return {
            "rows_written": self.rows_written,
            "flush_failures": self.flush_failures,
            "buffered": len(self._buffer),
        }
