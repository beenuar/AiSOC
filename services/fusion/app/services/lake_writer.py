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
  Kafka/fusion, lake archival resumes when the store returns" — never crash the
  consumer. A failed connection flush retains the batch (bounded by
  ``max_buffer_rows``) and reconnects with capped backoff; rows are only
  discarded on explicit overflow or repeated non-connection errors, and both
  increments a counter so the archive gap is visible.
* **Batched.** ClickHouse is happiest with bulk inserts, so events are buffered
  and flushed by size (``batch_size``) or age (``batch_max_age_seconds``); the
  consumer calls :meth:`flush_if_stale` each loop and :meth:`flush` on stop.
* **At-least-once with a deterministic ``event_id``.** MergeTree does not
  deduplicate, so a Kafka replay can produce a duplicate lake row. Each row
  carries a stable identity so downstream queries can ``argMax``/``LIMIT 1 BY
  event_id`` if exact-once is required. Ingest ids are used verbatim when they
  are UUIDs; a non-UUID ingest id is mapped through a fixed UUIDv5 namespace,
  and an event with no id at all is keyed by its Kafka coordinates. Both are
  stable across retries *and process restarts* — a random id generated in
  memory was not, so a replay after a crash could not be collapsed. The Phase
  A1 gate asserts *queryability* (``count >= 1``), not exact-once.

``clickhouse-driver`` is synchronous, so every insert is dispatched to a worker
thread via :func:`asyncio.to_thread` to keep the fusion event loop responsive.
If the driver is not installed (some dev images), the writer disables itself at
construction and logs once, rather than failing fusion import.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import random
import time
import uuid
from datetime import UTC, datetime
from typing import Any

import structlog

from app.core.config import settings

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
    # The activity projection ingest builds on every event (depth plan 2.2).
    # These are columns and not only `ocsf_json` because a hunt that has to
    # JSONExtract out of a ZSTD blob cannot use an index.
    "actor_kind",
    "actor_kind_source",
    "actor_id",
    "actor_on_behalf_of",
    "action",
    "resource_type",
    "resource_id",
    "resource_owner",
    "src_country_code",
    "src_asn",
    "src_as_org",
    "src_reputation",
    "src_reputation_known",
    "client_family",
    "client_version",
    "client_category",
    "client_raw",
    "outcome",
    # Sessions per principal (depth plan 2.4). `session_id` is the same
    # deterministic uuid the Postgres row and the graph node carry, so a hunt
    # can join the three without any of them having coordinated at write time.
    # `session_key_kind` rides along because a query that counts events per
    # session means something different for a vendor session than for a
    # derived one, and a hunter who cannot see which they have will mix them.
    "session_id",
    "session_key",
    "session_key_kind",
    "session_originating_human",
)

_INSERT_SQL = f"INSERT INTO aisoc.raw_events ({', '.join(_COLUMNS)}) VALUES"

# ClickHouse IPv6 columns reject empty/invalid strings; "::" is the safe null.
_NULL_IP = "::"

#: Fixed namespace for deterministic lake identities. Never change it: every
#: replayed event would then look new to `LIMIT 1 BY event_id`, which is the
#: property the namespace exists to provide.
_EVENT_ID_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "https://aisoc.dev/fusion/lake/event-id")


def _stable_event_id(raw_id: Any) -> str | None:
    """A deterministic UUID for an ingest id that is not one already.

    Ingest derives its ids with UUIDv5, but the raw-events topic also accepts
    envelopes from other producers (and from older versions) whose ``id`` is
    not a UUID. Generating a random one made the lake row's identity depend on
    the process that wrote it: replaying the same Kafka message after a restart
    produced a second id for the same event.

    A UUIDv5 over the ingest id is stable across attempts *and* restarts, and
    still distinguishes two events that carry different ids. An absent/empty
    id returns ``None``; :meth:`LakeWriter.write_event` fills that from the
    Kafka coordinates, which are equally replay-stable.
    """
    if raw_id is None:
        return None
    text = str(raw_id)
    if not text:
        return None
    try:
        return str(uuid.UUID(text))
    except (ValueError, AttributeError, TypeError):
        return str(uuid.uuid5(_EVENT_ID_NAMESPACE, f"ingest:{text}"))


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


def _as_dict(value: Any) -> dict[str, Any]:
    """A nested object, or an empty one — never None.

    Sibling of `_as_str` and `_as_int` above, for the same reason: the
    projection reads an envelope a connector shaped, so any level of it can
    be missing or be the wrong type.
    """
    return value if isinstance(value, dict) else {}


def _as_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


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


def _activity_columns(ocsf: dict[str, Any]) -> dict[str, Any]:
    """Flatten the activity projection ingest put on the event.

    Every value is defaulted rather than left absent: ClickHouse's column
    order is positional at insert time, so a row missing one key would shift
    every column after it. An event from before depth plan 2.2, or from a
    replayed topic, has no ``activity`` block at all and must still insert.

    ``src_reputation_known`` is carried separately from the score because a
    clean verdict and an unreachable enrichment service both produce 0.0, and
    collapsing them would let a broken enrichment path read as a quiet estate.
    """
    act = _as_dict(ocsf.get("activity"))
    actor = _as_dict(act.get("actor"))
    resource = _as_dict(act.get("resource"))
    location = _as_dict(act.get("location"))
    client = _as_dict(location.get("client"))

    return {
        "actor_kind": _as_str(actor.get("kind")),
        "actor_kind_source": _as_str(actor.get("kind_source")),
        "actor_id": _as_str(actor.get("id")),
        "actor_on_behalf_of": _as_str(actor.get("on_behalf_of")),
        "action": _as_str(act.get("action")),
        "resource_type": _as_str(resource.get("type")),
        "resource_id": _as_str(resource.get("id") or resource.get("name")),
        "resource_owner": _as_str(resource.get("owner")),
        "src_country_code": _as_str(location.get("country_code")),
        "src_asn": _as_int(location.get("asn")),
        "src_as_org": _as_str(location.get("as_org")),
        "src_reputation": _as_float(location.get("reputation")),
        "src_reputation_known": 1 if location.get("reputation_known") else 0,
        "client_family": _as_str(client.get("family")),
        "client_version": _as_str(client.get("version")),
        "client_category": _as_str(client.get("category")),
        "client_raw": _as_str(client.get("raw"))[:1024],
        "outcome": _as_str(act.get("outcome")),
        **_session_columns(act),
    }


def _session_columns(act: dict[str, Any]) -> dict[str, Any]:
    """Flatten the session block, defaulting every key for the same reason.

    `session_id` is stamped onto the event by the fusion consumer after the
    Postgres upsert and before this writer runs. An event that reached the
    lake without going through that step — a replay, or a deployment with the
    alert sink off — carries the vendor key and kind but an empty id, which is
    the honest record: the grouping is known, the row it joins to is not.
    """
    session = _as_dict(act.get("session"))
    return {
        "session_id": _as_str(session.get("id")),
        "session_key": _as_str(session.get("key"))[:512],
        "session_key_kind": _as_str(session.get("key_kind")),
        "session_originating_human": _as_str(session.get("originating_human")),
    }


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
        **_activity_columns(ocsf),
    }

    # Only carry the ingest id when it identifies the event. A UUID is used
    # verbatim; a non-UUID id is mapped through the fixed namespace so a replay
    # (including one after a process restart) keeps the same row identity.
    # `write_event` fills a missing id from the Kafka coordinates, because the
    # driver cannot leave a column to its DEFAULT: it reads `row[name]` for
    # every column named in the INSERT.
    raw_id = message.get("id") or message.get("event_id")
    row["event_id"] = _stable_event_id(raw_id)
    return row


def _is_connection_lake_error(exc: BaseException) -> bool:
    """Whether a failed lake insert looks like transport, not bad data.

    A ClickHouse outage and a schema mismatch both raise from ``execute``. They
    need different answers: retain the batch for the outage, but count and
    eventually discard a batch the server keeps rejecting. Guessing wrong in
    the outage direction loses events; guessing wrong in the data direction
    grows the buffer until it hits its explicit bound.
    """
    name = type(exc).__name__.lower()
    if any(marker in name for marker in ("network", "socket", "timeout", "connection", "unavailable")):
        return True
    text = str(exc).lower()
    return any(
        marker in text
        for marker in (
            "connection",
            "connect",
            "refused",
            "reset",
            "timed out",
            "timeout",
            "unavailable",
            "clickhouse down",
            "server is not",
            "can't connect",
            "cannot connect",
        )
    )


class LakeWriter:
    """Batched, fail-soft ClickHouse writer for the ``aisoc.raw_events`` lake.

    A failed batch is **retained and retried**, not dropped. Retention is
    bounded by ``max_buffer_rows``; overflow discards the oldest rows and
    increments ``rows_dropped`` with an error log, because unbounded memory is
    a worse failure than an explicitly reported archive gap. A connection
    failure triggers a capped exponential reconnect, so an outage that ends
    does not require a fusion restart.
    """

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
        max_buffer_rows: int | None = None,
        reconnect_base_seconds: float | None = None,
        reconnect_max_seconds: float | None = None,
        max_data_failures: int | None = None,
        client_factory: Any | None = None,
    ) -> None:
        self._host = host
        self._port = port
        self._database = database
        self._user = user
        self._password = password
        self._batch_size = max(1, batch_size)
        self._batch_max_age = batch_max_age_seconds
        self._max_buffer_rows = max(self._batch_size, int(max_buffer_rows or settings.lake_max_buffer_rows))
        base_seconds = reconnect_base_seconds if reconnect_base_seconds is not None else settings.lake_reconnect_base_seconds
        self._reconnect_base = max(0.0, float(base_seconds))
        self._reconnect_max = max(self._reconnect_base, float(reconnect_max_seconds or settings.lake_reconnect_max_seconds))
        self._max_data_failures = max(1, int(max_data_failures or settings.lake_max_data_failures))
        self._client_factory = client_factory
        self._client: Any | None = None
        self._buffer: list[dict[str, Any]] = []
        self._buffer_started_at: float = 0.0
        # ImportError is the only permanent disable: without the driver there
        # is no code that can ever connect. A missing server is recoverable.
        self._disabled = False
        self._next_reconnect_at = 0.0
        self._reconnect_attempt = 0
        self._data_failures = 0
        self.rows_written = 0
        self.flush_failures = 0
        self.rows_dropped = 0
        self.connect_failures = 0
        self.reconnects = 0

    async def start(self) -> None:
        if self._disabled:
            return
        self._client = self._make_client()
        if self._client is not None:
            logger.info("lake_writer.started", host=self._host, database=self._database)

    def _make_client(self) -> Any | None:
        try:
            if self._client_factory is not None:
                client = self._client_factory()
            else:
                from clickhouse_driver import Client  # noqa: PLC0415

                client = Client(
                    host=self._host,
                    port=self._port,
                    database=self._database,
                    user=self._user,
                    password=self._password or "",
                    connect_timeout=10,
                    send_receive_timeout=30,
                )
        except ImportError:
            self._disabled = True
            logger.warning("lake_writer.disabled_no_driver")
            return None
        except Exception as exc:  # noqa: BLE001 — degrade, never crash the worker
            self.connect_failures += 1
            self._schedule_reconnect()
            logger.error(
                "lake_writer.connect_failed",
                error=str(exc),
                retry_in_seconds=round(max(0.0, self._next_reconnect_at - time.monotonic()), 1),
            )
            return None

        was_degraded = self._reconnect_attempt > 0
        self._reconnect_attempt = 0
        self._next_reconnect_at = 0.0
        if was_degraded:
            self.reconnects += 1
            logger.info("lake_writer.reconnected", host=self._host)
        return client

    def _schedule_reconnect(self) -> None:
        exponent = min(self._reconnect_attempt, 16)
        delay = min(self._reconnect_max, self._reconnect_base * (2**exponent))
        # Full jitter over [delay/2, delay) avoids a thundering herd of fusion
        # replicas reconnecting to the same ClickHouse at the same instant.
        self._next_reconnect_at = time.monotonic() + (delay / 2) + (random.random() * delay / 2)
        self._reconnect_attempt += 1

    def _ensure_client(self) -> Any | None:
        if self._client is not None:
            return self._client
        if time.monotonic() < self._next_reconnect_at:
            return None
        self._client = self._make_client()
        return self._client

    async def stop(self) -> None:
        await self.flush()
        if self._buffer:
            # The process is going away and the store did not accept these
            # rows. They are lost, so they belong in `rows_dropped`: a log line
            # alone would leave the metric claiming nothing was discarded.
            dropped = len(self._buffer)
            self.rows_dropped += dropped
            logger.error(
                "lake_writer.shutdown_retained_rows",
                rows=dropped,
                detail="ClickHouse did not accept the buffered batch before shutdown; rows are not durable",
            )
        if self._client is not None:
            try:
                await asyncio.to_thread(self._client.disconnect)
            except Exception as exc:  # noqa: BLE001
                logger.warning("lake_writer.disconnect_failed", error=str(exc))
            self._client = None

    async def write_event(
        self,
        message: dict[str, Any],
        *,
        topic: str | None = None,
        partition: int | None = None,
        offset: int | None = None,
    ) -> bool:
        """Buffer one normalized event for the lake. Returns True if buffered.

        Flushes automatically when the buffer reaches ``batch_size``. A failed
        flush leaves the batch buffered (bounded), so True still means the
        event was accepted for archival, not that it is already durable.

        ``topic``/``partition``/``offset`` are the Kafka coordinates of the
        record being archived. They are the fallback identity for an envelope
        that carries no ingest id: the same record re-delivered after a restart
        has the same coordinates, so it keeps the same lake ``event_id``.
        """
        if self._disabled:
            return False
        row = event_to_row(message)
        if row is None:
            return False
        if row["event_id"] is None:
            # The driver must still *bind* every column: it builds a block from
            # the INSERT's column list and reads `row[name]` for each column,
            # so an omitted key is a KeyError before a byte is sent — not the
            # column DEFAULT. The id is deterministic, so a retry of a
            # partially-sent batch keeps the same id and `LIMIT 1 BY event_id`
            # still works.
            row["event_id"] = self._fallback_event_id(row, topic=topic, partition=partition, offset=offset)
        if not self._buffer:
            self._buffer_started_at = time.monotonic()
        self._buffer.append(row)
        if len(self._buffer) >= self._batch_size:
            await self.flush()
        self._enforce_buffer_capacity()
        return True

    @staticmethod
    def _fallback_event_id(
        row: dict[str, Any],
        *,
        topic: str | None,
        partition: int | None,
        offset: int | None,
    ) -> str:
        """Identity for an event with neither an ingest id nor a UUID one.

        Kafka coordinates are preferred because they distinguish two distinct
        records that happen to carry identical content. A direct caller that
        supplies neither coordinates nor an id gets a content hash: still
        stable across restarts, but byte-identical events collapse to one id.
        The consumer always supplies coordinates, so production does not take
        that branch.
        """
        if topic is not None and partition is not None and offset is not None:
            return str(uuid.uuid5(_EVENT_ID_NAMESPACE, f"kafka:{topic}:{partition}:{offset}"))
        material = json.dumps(
            {
                "tenant_id": row.get("tenant_id"),
                "event_time": row.get("event_time"),
                "class_uid": row.get("class_uid"),
                "ocsf_json": row.get("ocsf_json"),
            },
            default=str,
            sort_keys=True,
        )
        return str(uuid.uuid5(_EVENT_ID_NAMESPACE, f"content:{material}"))

    async def flush_if_stale(self) -> None:
        if self._buffer and (time.monotonic() - self._buffer_started_at) >= self._batch_max_age:
            await self.flush()

    async def flush(self) -> None:
        if self._disabled or not self._buffer:
            return
        client = self._ensure_client()
        if client is None:
            return

        batch = self._buffer
        batch_started_at = self._buffer_started_at
        self._buffer = []
        self._buffer_started_at = 0.0

        def _insert() -> None:
            # clickhouse-driver executes INSERT ... VALUES with a list of dicts.
            # Coerce the typed columns (IPv6) to the objects the driver binds.
            # Every column in `_COLUMNS` must be a key in every row: the driver
            # reads `row[name]` per column, so a missing key raises KeyError
            # before a byte is sent and the column DEFAULT never gets a chance.
            rows: list[dict[str, Any]] = []
            for row in batch:
                out = dict(row)
                out["source_ip"] = _to_ip_obj(row["source_ip"])
                out["dest_ip"] = _to_ip_obj(row["dest_ip"])
                rows.append(out)
            client.execute(_INSERT_SQL, rows, types_check=True)

        try:
            await asyncio.to_thread(_insert)
            self.rows_written += len(batch)
            self._data_failures = 0
        except asyncio.CancelledError:
            # Cancellation (shutdown, task teardown) is a BaseException, so the
            # handler below never sees it. The batch was already popped from
            # the buffer; putting it back keeps cancellation from being a
            # silent row-loss path. The task still unwinds.
            self._buffer = batch + self._buffer
            self._buffer_started_at = batch_started_at
            self._enforce_buffer_capacity()
            raise
        except Exception as exc:  # noqa: BLE001 — never raise into the consumer
            self.flush_failures += 1
            connection_error = _is_connection_lake_error(exc)
            self._data_failures = 0 if connection_error else self._data_failures + 1

            # Retain, oldest-first. `self._buffer` may have grown while the
            # insert ran, so the failed batch goes in front of it.
            self._buffer = batch + self._buffer
            self._buffer_started_at = batch_started_at
            overflow = self._enforce_buffer_capacity()

            # Force a fresh client on the next attempt: a broken driver
            # connection otherwise fails every subsequent flush, which is the
            # permanent-disable failure in slower motion.
            self._client = None
            self._schedule_reconnect()

            if not connection_error and self._data_failures >= self._max_data_failures:
                dropped = len(self._buffer)
                self._buffer = []
                self._buffer_started_at = 0.0
                self._data_failures = 0
                self.rows_dropped += dropped
                logger.error(
                    "lake_writer.batch_dropped_after_data_errors",
                    dropped=dropped,
                    failures=self._max_data_failures,
                    error=str(exc),
                )
                return

            logger.error(
                "lake_writer.flush_failed",
                error=str(exc),
                retained=len(self._buffer),
                dropped_on_overflow=overflow,
                retryable=connection_error,
                retry_in_seconds=round(max(0.0, self._next_reconnect_at - time.monotonic()), 1),
            )

    def _enforce_buffer_capacity(self) -> int:
        overflow = max(0, len(self._buffer) - self._max_buffer_rows)
        if overflow:
            del self._buffer[:overflow]
            self.rows_dropped += overflow
            self._buffer_started_at = time.monotonic()
            logger.error(
                "lake_writer.buffer_overflow_dropped",
                dropped=overflow,
                cap=self._max_buffer_rows,
                detail="oldest buffered lake rows discarded; archive coverage has a gap",
            )
        return overflow

    def metrics(self) -> dict[str, int]:
        return {
            "rows_written": self.rows_written,
            "flush_failures": self.flush_failures,
            "buffered": len(self._buffer),
            "rows_dropped": self.rows_dropped,
            "connect_failures": self.connect_failures,
            "reconnects": self.reconnects,
        }
