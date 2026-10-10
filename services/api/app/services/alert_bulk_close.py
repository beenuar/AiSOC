"""Bulk alert closure.

The console learned the hard way (see the ``alerts_bulk_close_backup_*``
relic tables) that closing thousands of noise alerts one PATCH at a time
is not a workflow, it is a punishment. This module is the sanctioned path:
one call, explicit id set or filter spec, a preflight count, a snapshot of
every row it is about to touch, then a single tenant-scoped UPDATE.

Guarantees
----------
* **Preflight over-match protection** — the filter is counted before it is
  applied; a caller who forgets a predicate and matches their entire queue
  gets ``409`` unless they raised ``max_count`` past the count. The guard
  is deliberately *interactive*: the 409 body carries the real number, so
  the retry is one keystroke, not an archaeology dig.
* **Recoverability** — every affected row's pre-change state is copied into
  a per-call backup table (``bulk_close_backup_<uuid-hex>``) before the
  UPDATE runs. Restoring is a ``UPDATE alerts SET ... FROM backup`` join
  away.
* **Fail closed on tenancy** — the WHERE clause is built once and reused
  verbatim by the count, the snapshot SELECT, and the UPDATE, and it always
  leads with the tenant predicate; there is no code path where an id list
  escapes the tenant that submitted it.
"""

from __future__ import annotations

import logging
import re
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Select, and_, func, select, text, update
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alert import Alert

logger = logging.getLogger(__name__)

#: Hard ceiling on one call's blast radius, independent of ``max_count``.
#: A caller may lower it, never raise it: bulk close is reversible but a
#: six-figure UPDATE is still a six-figure lock.
MAX_BULK_CLOSE_LIMIT = 10_000

#: Backstop below the ceiling: a caller who asks for the full 10k without
#: ever thinking still has to acknowledge the real matched count first.
DEFAULT_MAX_COUNT = 500

#: Backup-table names are generated (never user-supplied) but are still
#: interpolated into DDL, so they go through the same identifier gate.
# Backup tables live in aisoc_bulk_close_backup (migration 095): aisoc_app
# deliberately lacks CREATE in public — least privilege, live-caught 500.
_BACKUP_SCHEMA = "aisoc_bulk_close_backup"
_BACKUP_TABLE_RE = re.compile(r"^aisoc_bulk_close_backup\.bulk_close_backup_[0-9a-f]{32}$")

#: Log-injection guard (CodeQL py/log-injection): a bulk-close comment is
#: free text from the request. CR/LF and control bytes would forge extra
#: log lines (or break JSON handlers downstream); neutralise them and cap
#: the length before anything reaches the logger.
_LOG_UNSAFE_RE = re.compile(r"[\r\n\x00-\x1f\x7f]")


def _safe_log_text(value: str | None, *, limit: int = 120) -> str:
    """Single-line, control-char-free rendering of user free text for logs."""
    if not value:
        return ""
    return _LOG_UNSAFE_RE.sub(" ", value)[:limit]


#: Statuses an alert may be bulk-closed *to*. ``new``/``investigating`` are
#: excluded: those are queue states, and bulk-moving work into the queue is
#: not what this endpoint is for.
CLOSE_STATUSES = frozenset({"resolved", "false_positive", "closed"})

#: Alert statuses that count as still-open for the preflight count (an
#: already-closed row must not consume a caller's max_count budget).
OPEN_STATUSES = ("new", "triaging", "investigating", "in_progress", "escalated", "snoozed")


class BulkCloseOverMatch(Exception):
    """Raised when the filter matched more rows than ``max_count`` allows.

    Carries the actual count so the 409 body can teach the caller exactly
    what to adjust — never a bare 403 with a mystery number.
    """

    def __init__(self, matched: int, max_count: int) -> None:
        self.matched = matched
        self.max_count = max_count
        super().__init__(f"bulk close matched {matched} alerts, over max_count={max_count}")


class BulkCloseEmpty(Exception):
    """Nothing matched — surfaced as 404 rather than a silent 200/zero."""


def build_bulk_close_predicates(
    *,
    tenant_id: uuid.UUID,
    alert_ids: list[uuid.UUID] | None,
    statuses: list[str] | None,
    severities: list[str] | None,
    categories: list[str] | None,
    connector_types: list[str] | None,
    older_than: datetime | None,
) -> list[Any]:
    """Compose the WHERE list shared by the count, snapshot, and UPDATE.

    One builder for all three statements is the whole point: a predicate
    added here lands in every statement at once, so the rows counted,
    snapshotted, and updated can never drift apart.
    """
    preds: list[Any] = [Alert.tenant_id == tenant_id]
    if alert_ids:
        preds.append(Alert.id.in_(alert_ids))
    if statuses:
        preds.append(Alert.status.in_(statuses))
    if severities:
        preds.append(Alert.severity.in_(severities))
    if categories:
        preds.append(Alert.category.in_(categories))
    if connector_types:
        preds.append(Alert.connector_type.in_(connector_types))
    if older_than is not None:
        preds.append(Alert.created_at < older_than)
    elif not alert_ids:
        # A pure-filter close must not reach into already closed work:
        # re-closing closed rows would churn resolved_at and audit noise
        # for zero operational value. An explicit id list may still re-close
        # (analysts legitimately re-triage a wrongly-closed alert).
        preds.append(Alert.status.in_(OPEN_STATUSES))
    return preds


_SNAPSHOT_COLUMNS = (
    Alert.id,
    Alert.title,
    Alert.status,
    Alert.severity,
    Alert.priority,
    Alert.category,
    Alert.connector_type,
    Alert.tags,
    Alert.description,
    Alert.resolved_at,
    Alert.updated_at,
)


def _snapshot_select(preds: list[Any]) -> Select[tuple[Any, ...]]:
    return select(*_SNAPSHOT_COLUMNS).where(and_(*preds))


def _snapshot_sql(select_stmt: Select[tuple[Any, ...]], backup_table: str) -> str:
    """Render the snapshot SELECT into CREATE TABLE ... AS form.

    Compiled with ``literal_binds`` on purpose: the raw DDL string goes to
    asyncpg through ``text()``, and asyncpg has no pyformat binds — a
    leftover ``%(name)s`` placeholder from a psycopg2-style compile is a
    syntax error at the driver (live-caught 2026-10-06: HTTP 500,
    "syntax error at or near %").  literal_binds keeps the WHERE structure
    identical to the statement the endpoint counted and the UPDATE reuses,
    with SQLAlchemy handling all quoting/escaping of the values (which are
    tenant UUIDs and validated filter strings).
    """
    compiled = str(select_stmt.compile(dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}))
    # Strip the table qualifier from the projected columns: CREATE TABLE AS
    # derives column names, and `alerts.id` would name the column "id"
    # anyway — but PostgreSQL warns on qualified names in CTAS output,
    # so we emit the unqualified list ourselves.
    return f"CREATE TABLE {backup_table} AS SELECT * FROM ({compiled}) AS snapshot_rows"


async def bulk_close_alerts(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    actor_id: uuid.UUID | None,
    close_status: str,
    alert_ids: list[uuid.UUID] | None = None,
    statuses: list[str] | None = None,
    severities: list[str] | None = None,
    categories: list[str] | None = None,
    connector_types: list[str] | None = None,
    older_than: datetime | None = None,
    max_count: int = DEFAULT_MAX_COUNT,
    comment: str | None = None,
) -> dict[str, Any]:
    """Snapshot then close every alert matching the id set or filter.

    Returns ``{"backup_table", "closed_count", "matched_count", "close_status"}``.
    Raises :class:`BulkCloseOverMatch` (409 upstream), :class:`BulkCloseEmpty`
    (404 upstream), or ``ValueError`` for an invalid close target — all
    before any row is touched.
    """
    if close_status not in CLOSE_STATUSES:
        raise ValueError(f"close target must be one of {sorted(CLOSE_STATUSES)}")
    if not alert_ids and not (statuses or severities or categories or connector_types or older_than):
        # Neither ids nor filters would target the whole queue; refuse rather
        # than let a forgotten body close everything.
        raise ValueError("bulk close requires alert_ids or at least one filter")

    max_count = max(1, min(int(max_count), MAX_BULK_CLOSE_LIMIT))
    preds = build_bulk_close_predicates(
        tenant_id=tenant_id,
        alert_ids=alert_ids,
        statuses=statuses,
        severities=severities,
        categories=categories,
        connector_types=connector_types,
        older_than=older_than,
    )

    matched = int((await db.execute(select(func.count()).select_from(Alert).where(and_(*preds)))).scalar_one())
    if matched == 0:
        raise BulkCloseEmpty()
    if matched > max_count:
        raise BulkCloseOverMatch(matched=matched, max_count=max_count)

    backup_table = f"{_BACKUP_SCHEMA}.bulk_close_backup_{uuid.uuid4().hex}"
    if not _BACKUP_TABLE_RE.match(backup_table):  # pragma: no cover - belt over braces
        raise RuntimeError("generated backup table name failed identifier validation")

    select_stmt = _snapshot_select(preds)

    await db.execute(text(f"DROP TABLE IF EXISTS {backup_table}"))
    await db.execute(text(_snapshot_sql(select_stmt, backup_table)))

    now = datetime.now(UTC)
    updates: dict[str, Any] = {"status": close_status, "updated_at": now}
    updates["resolved_at"] = now
    result = await db.execute(update(Alert).where(and_(*preds)).values(**updates))
    closed = int(result.rowcount or 0)
    await db.commit()

    # Every interpolated value is neutralised or validated: tenant/actor are
    # server-side UUIDs, close_status is membership-checked against
    # CLOSE_STATUSES, backup_table is regex-validated above, comment is free
    # text and goes through _safe_log_text (CodeQL py/log-injection).
    logger.info(
        "alerts.bulk_close tenant=%s actor=%s matched=%d closed=%d target=%s backup=%s comment=%s",
        tenant_id,
        actor_id,
        matched,
        closed,
        close_status,
        backup_table,
        _safe_log_text(comment),
    )

    return {
        "backup_table": backup_table,
        "matched_count": matched,
        "closed_count": closed,
        "close_status": close_status,
    }
