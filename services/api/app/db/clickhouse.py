"""ClickHouse client for the tenant lake (Workstream 7).

ClickHouse is the warm-tier store for ``aisoc.raw_events``,
``aisoc.alert_metrics``, and ``aisoc.ioc_enrichments`` — see
``services/api/clickhouse/001_init.sql`` for the schema. Operators and the
agent runtime hit this tier via ``POST /api/v1/lake/sql`` and
``GET /api/v1/lake/schema``; that surface lives one layer above this file
in :mod:`app.api.v1.endpoints.lake`.

Why this module exists:

* ``clickhouse-driver`` is synchronous, but the API is FastAPI/asyncio.
  We wrap each query in :func:`asyncio.to_thread` so the event loop stays
  responsive while ClickHouse executes the statement on a background
  worker.
* We need a single connection-pool singleton so we don't pay the TCP +
  TLS handshake per request, and a single place to enforce server-side
  limits (``max_execution_time``, ``max_result_rows``, memory caps).
* The lake API takes untrusted SQL through a sqlglot rewriter (see
  :mod:`app.services.lake_sql`) before it ever reaches this client. This
  module is the *last mile* — it assumes the rewriter has already done
  its job, and only enforces the resource caps that ClickHouse itself
  understands.

Threat model boundary (must stay in sync with lake_sql.py):

* Predicate injection happens *upstream* in the rewriter. This client
  forwards SQL verbatim. A bug here can't introduce a tenant-isolation
  hole on its own, but it could leak by *omitting* the rewritten WHERE
  clause — so the only public ``execute`` method on this module
  deliberately has no SQL-modification helpers.
* Resource caps are enforced *here* via ``settings`` and ClickHouse
  query settings rather than via SQL ``LIMIT`` alone, because
  ``LIMIT`` only bounds the result, not the in-flight scan.

If ``clickhouse-driver`` isn't installed (some dev environments), the
client lazy-fails on first use rather than at import time. That keeps
the test suite usable for everything that doesn't touch the lake.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from app.core.config import settings

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------- public


@dataclass(frozen=True)
class LakeQueryResult:
    """Outcome of a successful ClickHouse query.

    Attributes
    ----------
    columns:
        Ordered list of column names. Stable across rows.
    rows:
        Each row is a list of cell values whose order matches
        :attr:`columns`. Rows are materialised — no streaming —
        because the rewriter clamps ``LIMIT`` to a sane row cap
        before we ever see the SQL.
    row_count:
        Cached ``len(rows)`` so callers don't have to re-count when
        they're shaping audit-log entries or OpenTelemetry
        attributes.
    elapsed_ms:
        Wall-clock time spent inside ClickHouse, measured from
        ``execute()`` entry to return. Useful for the lake's
        per-tenant rate-limiter feedback.
    """

    columns: list[str]
    rows: list[list[Any]]
    row_count: int
    elapsed_ms: int


class LakeQueryError(RuntimeError):
    """Generic ClickHouse failure surfaced to the lake API.

    The lake endpoints catch this and translate it to a 502 (server
    saw ClickHouse but ClickHouse misbehaved) or, for query timeouts
    and memory limits, a 422 with the offending message scrubbed.
    """


class LakeQueryTimeoutError(LakeQueryError):
    """ClickHouse exceeded ``LAKE_QUERY_TIMEOUT_SECONDS``."""


class LakeQueryNotConfiguredError(LakeQueryError):
    """``clickhouse-driver`` isn't installed or no host is configured.

    Distinct exception so the API can return a 503 with a clear
    operator-facing message ("ClickHouse not configured") instead of
    leaking driver-import tracebacks to the caller.
    """


# Default per-query settings sent to ClickHouse. These are the safety
# rails that protect the warm tier from a runaway agent prompt: the SQL
# rewriter clamps ``LIMIT``, but only the server can enforce execution
# time and bytes-scanned. We keep them as a module constant so tests
# can patch them and callers can layer overrides on top.
DEFAULT_QUERY_SETTINGS: dict[str, Any] = {
    # Hard cap on ClickHouse execution time. The async wrapper has its
    # own ``asyncio.wait_for`` on top — the server cap is the lower of
    # the two so we don't strand a query inside ClickHouse after the
    # client has given up.
    "max_execution_time": 30,
    # Cap individual queries at 1 GiB of working memory. Above this,
    # ClickHouse rejects with code 241 (MEMORY_LIMIT_EXCEEDED) which we
    # surface as a 422.
    "max_memory_usage": 1024 * 1024 * 1024,
    # Hard cap on rows ClickHouse will materialise into the result set.
    # Belt-and-braces with the rewriter's LIMIT clamp.
    "max_result_rows": 100_000,
    # Don't let a single query saturate the cluster.
    "max_threads": 4,
    # Defensively cap network egress per query at 256 MiB. The lake
    # API streams JSON to the client; this stops a pathological
    # ``SELECT *`` from raw_events from blowing through both the API
    # and the caller.
    "max_network_bandwidth": 256 * 1024 * 1024,
}


# Internal singleton holders. We cache the client on first use and keep
# it for the process lifetime; ``clickhouse-driver`` already pools the
# underlying TCP connections.
_client: Any | None = None
_client_lock = asyncio.Lock()


async def get_clickhouse_client() -> Any:
    """Return a process-wide ``clickhouse_driver.Client`` singleton.

    The first call acquires :data:`_client_lock` and instantiates the
    client; subsequent callers reuse it. We do the import lazily so
    environments without ``clickhouse-driver`` (e.g. CI runners that
    only exercise endpoints not requiring the lake) can still import
    :mod:`app.main` without choking.

    Raises
    ------
    LakeQueryNotConfiguredError
        If ``clickhouse-driver`` is not installed or the configured
        host is empty.
    """
    global _client
    if _client is not None:
        return _client

    async with _client_lock:
        if _client is not None:
            return _client

        try:
            from clickhouse_driver import Client  # noqa: PLC0415
        except ImportError as exc:  # pragma: no cover — env-specific
            raise LakeQueryNotConfiguredError(
                "clickhouse-driver is not installed; install it via `pip install clickhouse-driver` to enable the lake API"
            ) from exc

        host = (settings.CLICKHOUSE_HOST or "").strip()
        if not host:
            raise LakeQueryNotConfiguredError("CLICKHOUSE_HOST is not configured; set it in the API environment to enable the lake API")

        # ``settings_dict`` is forwarded to ClickHouse on every query;
        # we override per-call too, but having sane process-wide
        # defaults means a missing override still gets the safety
        # rails. ``send_receive_timeout`` is the network-level cap, so
        # we set it slightly above the per-query execution cap to
        # avoid spurious socket timeouts.
        try:
            _client = Client(
                host=host,
                port=settings.CLICKHOUSE_PORT,
                database=settings.CLICKHOUSE_DATABASE,
                user=settings.CLICKHOUSE_USER,
                password=settings.CLICKHOUSE_PASSWORD or "",
                connect_timeout=10,
                send_receive_timeout=DEFAULT_QUERY_SETTINGS["max_execution_time"] + 10,
                settings=DEFAULT_QUERY_SETTINGS,
            )
        except Exception as exc:  # pragma: no cover — driver-specific
            raise LakeQueryNotConfiguredError(f"failed to construct ClickHouse client: {exc}") from exc

        logger.info(
            "clickhouse client initialised",
            extra={
                "host": host,
                "port": settings.CLICKHOUSE_PORT,
                "database": settings.CLICKHOUSE_DATABASE,
            },
        )
        return _client


async def close_clickhouse() -> None:
    """Best-effort shutdown for the singleton client.

    ``clickhouse-driver``'s sync ``Client`` releases its socket on
    ``disconnect``. We schedule that on a worker thread to avoid
    blocking the event loop during shutdown.
    """
    global _client
    if _client is None:
        return
    client, _client = _client, None
    try:
        await asyncio.to_thread(client.disconnect)
    except Exception as exc:  # pragma: no cover — driver-specific
        logger.warning("clickhouse client disconnect failed", extra={"error": str(exc)})


async def execute_lake_query(
    sql: str,
    *,
    timeout_seconds: float | None = None,
    extra_settings: dict[str, Any] | None = None,
) -> LakeQueryResult:
    """Run a rewritten lake SQL statement and return columns + rows.

    The SQL passed in here MUST already have been through
    :func:`app.services.lake_sql.rewrite_for_tenant` — this function
    does no validation. It exists purely to:

    * dispatch the sync ``clickhouse-driver`` call into a worker
      thread so the asyncio loop stays responsive,
    * enforce a wall-clock timeout that's the lower of
      ``timeout_seconds`` and ClickHouse's
      ``max_execution_time``,
    * normalise the driver's exceptions into our
      :class:`LakeQueryError` family so the API layer can map them to
      HTTP responses without reaching into the driver's exception
      tree, and
    * format the result as columns/rows lists which the JSON
      response model expects.

    Parameters
    ----------
    sql:
        Rewritten SELECT/UNION/CTE query. ClickHouse dialect.
    timeout_seconds:
        Optional wall-clock cap. ``None`` falls back to
        :attr:`DEFAULT_QUERY_SETTINGS['max_execution_time']`. The
        effective cap is ``min(timeout_seconds, server_cap)``, plus a
        small grace so ClickHouse can finish its own timeout-raising
        path before we cancel.
    extra_settings:
        Optional ClickHouse query settings merged on top of
        :data:`DEFAULT_QUERY_SETTINGS`. Used by the lake endpoints to
        layer in per-tenant overrides (e.g. tighter row caps for
        unprivileged roles).

    Returns
    -------
    LakeQueryResult
        Columns, row data, row count, and elapsed milliseconds.

    Raises
    ------
    LakeQueryTimeoutError
        ClickHouse exceeded the wall-clock cap.
    LakeQueryError
        ClickHouse returned an error (syntax, permissions, memory).
    LakeQueryNotConfiguredError
        Driver missing or host unset.
    """
    client = await get_clickhouse_client()

    server_cap = float(DEFAULT_QUERY_SETTINGS["max_execution_time"])
    effective_cap = server_cap if timeout_seconds is None else min(server_cap, timeout_seconds)
    # Grace period so ClickHouse can raise its own timeout error before
    # we yank the work-thread out from under it. Without the grace, an
    # asyncio.TimeoutError races the ClickHouse timeout and we lose the
    # nicer server-side error message.
    asyncio_cap = effective_cap + 2.0

    merged_settings = {**DEFAULT_QUERY_SETTINGS}
    if extra_settings:
        merged_settings.update(extra_settings)
    # Clamp ``max_execution_time`` to whatever the caller asked for so
    # ClickHouse and our wrapper agree on the deadline.
    merged_settings["max_execution_time"] = int(effective_cap)

    loop = asyncio.get_running_loop()
    started = loop.time()

    def _run() -> tuple[list[list[Any]], list[tuple[str, str]]]:
        # ``with_column_types=True`` returns ``(rows, [(name, type), ...])``
        # which we need so the API can echo a stable column ordering.
        return client.execute(
            sql,
            with_column_types=True,
            settings=merged_settings,
        )

    try:
        rows, column_meta = await asyncio.wait_for(asyncio.to_thread(_run), timeout=asyncio_cap)
    except TimeoutError as exc:
        raise LakeQueryTimeoutError(f"lake query exceeded {effective_cap:.0f}s wall-clock timeout") from exc
    except LakeQueryError:
        raise
    except Exception as exc:
        # ``clickhouse-driver`` raises a hierarchy of its own
        # exceptions (ServerException, NetworkError, …). We don't
        # import them here to keep the soft dependency soft; instead
        # we sniff for the well-known ClickHouse timeout codes
        # because they're the ones we want to map to a different HTTP
        # status (422 not 502).
        message = str(exc)
        if "TIMEOUT_EXCEEDED" in message or "exceeded the timeout" in message.lower():
            raise LakeQueryTimeoutError(message) from exc
        # Surface a sanitised error — we deliberately don't include
        # the SQL in the message because it's the caller's input and
        # may be very large. The full SQL is logged separately by
        # the API endpoint with structured logging.
        raise LakeQueryError(f"clickhouse query failed: {message}") from exc

    elapsed_ms = int((loop.time() - started) * 1000)

    columns = [name for name, _type in column_meta]
    materialised: list[list[Any]] = [list(row) for row in rows]

    return LakeQueryResult(
        columns=columns,
        rows=materialised,
        row_count=len(materialised),
        elapsed_ms=elapsed_ms,
    )


async def fetch_lake_schema(
    *,
    tables: Iterable[str] | None = None,
) -> list[dict[str, Any]]:
    """Return column metadata for the lake's allowlisted tables.

    Powers ``GET /api/v1/lake/schema``. We query ``system.columns``
    directly with a tight ``WHERE`` clause built from the allowlist so
    the caller can't smuggle a different table name in through the
    ``tables`` argument — and so the result set is bounded.

    The shape of each entry is::

        {
            "table": "aisoc.raw_events",
            "columns": [
                {"name": "tenant_id", "type": "UUID", "comment": "..."},
                ...
            ],
        }

    Parameters
    ----------
    tables:
        Optional subset of allowlisted tables to filter to. Passing a
        non-allowlisted table is a programmer error (the endpoint is
        responsible for validating against
        :data:`app.services.lake_sql.ALLOWED_TABLES` first), so we
        defensively return an empty list in that case rather than
        raising — schema discovery shouldn't 500.
    """
    # Inline import to keep the lake_sql module the single source of
    # truth for the allowlist while avoiding a circular import at
    # module load (lake_sql doesn't depend on this module today, but
    # if it ever did we'd have a cycle).
    from app.services.lake_sql import ALLOWED_TABLES  # noqa: PLC0415

    requested = list(tables) if tables is not None else list(ALLOWED_TABLES)
    requested = [t for t in requested if t in ALLOWED_TABLES]
    if not requested:
        return []

    # Build a conjunction of ``(database = X AND table = Y)`` clauses
    # parameterised through clickhouse-driver. This avoids string-
    # interpolation injection even though the input is already
    # constrained to the allowlist.
    pairs: list[tuple[str, str]] = []
    params: dict[str, str] = {}
    where_clauses: list[str] = []
    for idx, fq in enumerate(sorted(set(requested))):
        db, tbl = fq.split(".", 1)
        pairs.append((db, tbl))
        params[f"db{idx}"] = db
        params[f"tbl{idx}"] = tbl
        where_clauses.append(f"(database = %(db{idx})s AND table = %(tbl{idx})s)")

    where = " OR ".join(where_clauses)
    sql = f"SELECT database, table, name, type, comment FROM system.columns WHERE {where} ORDER BY database, table, position"

    client = await get_clickhouse_client()

    def _run() -> Sequence[tuple[str, str, str, str, str]]:
        return client.execute(sql, params)

    try:
        rows = await asyncio.wait_for(
            asyncio.to_thread(_run),
            timeout=DEFAULT_QUERY_SETTINGS["max_execution_time"],
        )
    except TimeoutError as exc:
        raise LakeQueryTimeoutError("lake schema lookup timed out") from exc
    except Exception as exc:
        raise LakeQueryError(f"clickhouse schema lookup failed: {exc}") from exc

    by_table: dict[str, list[dict[str, Any]]] = {f"{db}.{tbl}": [] for db, tbl in pairs}
    for db, tbl, name, ctype, comment in rows:
        key = f"{db}.{tbl}"
        if key not in by_table:
            continue  # ClickHouse should never volunteer extras, but be safe.
        by_table[key].append({"name": name, "type": ctype, "comment": comment or ""})

    return [{"table": fq, "columns": cols} for fq, cols in by_table.items()]
