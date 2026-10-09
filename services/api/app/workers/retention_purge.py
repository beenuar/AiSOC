"""Retention purge worker — the thing that makes a retention policy do something.

``app.services.retention`` has built correct, bounded, tenant-scoped purge SQL
since Wave 5, and its docstring says "the scheduler/worker that runs the purge
composes these". No such worker existed. ``build_lake_purge_sql`` and
``build_alert_purge_sql`` had exactly one caller each — the test asserting they
were well-formed. A tenant could configure retention in the UI, see it persist,
watch the claim-to-gate matrix call it GATED, and never lose a row.

Design notes that matter more than the code:

**Default off.** Turning a release upgrade into unannounced data deletion is
not acceptable, so ``RETENTION_WORKER_ENABLED`` defaults to false and the
worker logs loudly what it would do. Operators opt in.

**Dry-run first.** ``RETENTION_WORKER_DRY_RUN`` (default true when the worker
is first enabled) counts rows instead of deleting them, so an operator can see
the blast radius before arming it. The counts are logged and returned, so the
same code path proves the predicate is right.

**Only explicit policies.** The worker purges for tenants that have a
``retention_policies`` row. It deliberately does *not* apply
``DEFAULT_RETENTION`` to tenants that never configured anything: those defaults
exist to pre-fill a form, and treating them as an instruction would delete data
nobody asked to delete.

**Audit is excluded.** ``audit_days`` is storable but not purged here. The
audit log is an append-only hash chain (migration 043) whose entire value is
that no row was deleted, reordered, or rewritten; a retention purge would break
the chain and make every subsequent verification fail. Enforcing an audit
retention window needs chain-aware truncation with a re-anchored checkpoint,
which is a different piece of work. Saying so in one place beats a purge that
silently errors every tick.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.clickhouse import execute_lake_query
from app.db.cross_tenant import assert_cross_tenant_session
from app.db.database import AsyncSessionLocal
from app.services.retention import (
    _clamp,
    alerts_under_legal_hold,
    build_lake_purge_sql,
    may_purge,
    resolve_policy,
)
from app.workers._tick_failures import TickFailures

logger = logging.getLogger("aisoc.retention_purge")

# ClickHouse mutations are asynchronous by default: ALTER TABLE … DELETE
# returns as soon as the mutation is queued. Waiting makes the worker's own
# logs truthful about what has actually been removed.
_MUTATIONS_SYNC = {"mutations_sync": 1}


@dataclass
class TenantPurgeResult:
    tenant_id: uuid.UUID
    raw_events_days: int
    alerts_days: int
    lake_rows: int = 0
    alert_rows: int = 0
    #: Rows that were past the window and were not deleted because a legal
    #: hold covers this tenant. Counted rather than merely skipped: a hold
    #: that silently stops a purge and a purge that silently had nothing to
    #: do look identical in a log, and an auditor asking "did the hold
    #: work" can only be answered by a number.
    held_lake_rows: int = 0
    held_alert_rows: int = 0
    #: The matters the hold was placed under, so the operator reading the
    #: log knows which one to go and release.
    hold_refs: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def held(self) -> bool:
        return bool(self.hold_refs)


@dataclass
class PurgeRun:
    dry_run: bool
    started_at: datetime
    tenants: list[TenantPurgeResult] = field(default_factory=list)

    @property
    def lake_rows(self) -> int:
        return sum(t.lake_rows for t in self.tenants)

    @property
    def alert_rows(self) -> int:
        return sum(t.alert_rows for t in self.tenants)

    @property
    def held_lake_rows(self) -> int:
        return sum(t.held_lake_rows for t in self.tenants)

    @property
    def held_alert_rows(self) -> int:
        return sum(t.held_alert_rows for t in self.tenants)

    @property
    def tenants_held(self) -> int:
        return sum(1 for t in self.tenants if t.held)

    @property
    def errors(self) -> list[str]:
        return [e for t in self.tenants for e in t.errors]


def build_lake_count_sql(tenant_id: uuid.UUID, days: int) -> str:
    """Dry-run counterpart to ``build_lake_purge_sql``.

    Deliberately mirrors that function's predicate character for character. If
    the two drift, the dry run stops describing the delete, which is the only
    way an operator has to preview it.
    """
    days = _clamp(days)
    return (
        f"SELECT count() FROM aisoc.raw_events WHERE tenant_id = '{uuid.UUID(str(tenant_id))}' AND event_time < now() - INTERVAL {days} DAY"
    )


def build_alert_count_sql(days: int) -> tuple[str, dict[str, int]]:
    """Dry-run counterpart to ``build_alert_purge_sql``."""
    days = _clamp(days)
    return (
        "SELECT count(*) FROM alerts WHERE created_at < now() - make_interval(days => :days)",
        {"days": days},
    )


async def _load_policies(db: AsyncSession) -> list[tuple[uuid.UUID, dict[str, int]]]:
    """Tenants with an explicit retention policy row.

    The worker is cross-tenant by nature, and the per-tenant predicate is
    applied explicitly in each statement below rather than being inherited
    from a session GUC.

    This used to open with ``SET LOCAL row_security = off``. Under the runtime
    role (``migrations/061_runtime_app_role.sql``) that raises rather than
    relaxing anything, because Postgres refuses the query instead of ignoring
    the policy for a role the policy applies to. The cross-tenant read now
    rests on the ``OR current_tenant_id() IS NULL`` arm every policy carries,
    and the precondition that makes that arm apply is asserted instead of
    assumed.
    """
    await assert_cross_tenant_session(db, "retention purge policy load")
    rows = await db.execute(text("SELECT tenant_id, raw_events_days, alerts_days, audit_days FROM retention_policies ORDER BY tenant_id"))
    out: list[tuple[uuid.UUID, dict[str, int]]] = []
    for row in rows.mappings():
        out.append(
            (
                row["tenant_id"],
                {
                    "raw_events_days": row["raw_events_days"],
                    "alerts_days": row["alerts_days"],
                    "audit_days": row["audit_days"],
                },
            )
        )
    return out


async def _tenant_is_held(db: AsyncSession, tenant_id: uuid.UUID) -> list[str]:
    """Matter references for every live hold covering this tenant, or [].

    Read before every sweep rather than cached: a hold placed between two
    runs has to take effect on the next one, and a cache measured in hours
    is a cache that deletes evidence placed under hold this morning.

    **Why any hold stops the whole tenant.** Both purges here are bulk
    statements — one ClickHouse mutation over a tenant's aged events, one
    `DELETE` over its aged alerts — and neither can evaluate a per-subject
    predicate row by row without first enumerating which rows belong to the
    held user, host or case. So the conservative reading is the only safe
    one: if anything is held, nothing in that tenant is purged this sweep.
    That over-retains, which is recoverable; the alternative under-retains,
    which is not. Narrowing a hold to its own subjects is recorded as
    follow-up in DEPTH_PROGRESS.md rather than approximated here.

    The decision itself goes through ``may_purge`` so there is exactly one
    place in the tree where a hold beats a purge, and it returns a decision
    object rather than a boolean so a caller cannot read "held" as "not
    expired".
    """
    holds = await alerts_under_legal_hold(db, tenant_id)
    if not holds:
        return []
    decision = may_purge(
        expired=True,
        # The subject of a bulk tenant purge is the tenant. Every live hold
        # in this tenant matches it, which is the fail-closed reading
        # described above.
        subjects={hold.subject_kind: hold.subject_value for hold in holds},
        holds=holds,
    )
    if decision.may_purge:
        return []
    return sorted({hold.matter_ref or hold.id for hold in holds})


async def _purge_lake(tenant_id: uuid.UUID, days: int, *, dry_run: bool) -> int:
    """Delete (or count) lake events past the window. Returns the row count.

    ClickHouse ``ALTER TABLE … DELETE`` does not report affected rows, so even
    on the live path we count first. That costs one scan and buys an accurate
    number in the audit trail — worth it for an operation whose whole risk is
    deleting more than intended.
    """
    count_result = await execute_lake_query(build_lake_count_sql(tenant_id, days))
    doomed = int(count_result.rows[0][0]) if count_result.rows else 0
    if doomed == 0 or dry_run:
        return doomed

    await execute_lake_query(
        build_lake_purge_sql(tenant_id, days),
        extra_settings=_MUTATIONS_SYNC,
    )
    return doomed


async def _purge_alerts(db: AsyncSession, tenant_id: uuid.UUID, days: int, *, dry_run: bool) -> int:
    """Delete (or count) alerts past the window for one tenant.

    ``build_alert_purge_sql`` relies on RLS for the tenant scope, which is
    correct inside a request but wrong here: this session has row security
    disabled so it can enumerate every tenant. The tenant predicate is
    therefore bound explicitly, as a parameter. Without this the statement
    would delete every tenant's aged alerts under the first tenant's window.
    """
    count_sql, params = build_alert_count_sql(days)
    count_sql += " AND tenant_id = :tenant_id"
    params_with_tenant: dict[str, object] = {**params, "tenant_id": str(tenant_id)}

    doomed = int((await db.execute(text(count_sql), params_with_tenant)).scalar_one())
    if doomed == 0 or dry_run:
        return doomed

    await db.execute(
        text("DELETE FROM alerts WHERE tenant_id = :tenant_id AND created_at < now() - make_interval(days => :days)"),
        params_with_tenant,
    )
    return doomed


async def run_once(
    *,
    db: AsyncSession | None = None,
    dry_run: bool | None = None,
) -> PurgeRun:
    """One purge sweep across every tenant with an explicit retention policy."""
    if dry_run is None:
        dry_run = bool(getattr(settings, "RETENTION_WORKER_DRY_RUN", True))

    own_session = db is None
    if db is None:
        db = AsyncSessionLocal()
    run = PurgeRun(dry_run=dry_run, started_at=datetime.now(UTC))

    try:
        for tenant_id, config in await _load_policies(db):
            policy = resolve_policy(config)
            result = TenantPurgeResult(
                tenant_id=tenant_id,
                raw_events_days=policy.raw_events_days,
                alerts_days=policy.alerts_days,
            )

            try:
                result.hold_refs = await _tenant_is_held(db, tenant_id)
            except Exception as exc:
                # Unreadable hold evidence withholds the purge. The opposite
                # default deletes evidence under litigation because a query
                # failed, which is the one outcome that cannot be
                # apologised for.
                result.hold_refs = ["<unreadable>"]
                result.errors.append(f"legal_holds: {type(exc).__name__}")
                logger.warning("retention_purge.holds_unreadable tenant=%s err=%s", tenant_id, type(exc).__name__)

            # A held tenant is still counted, in dry-run mode, so the run
            # reports how much the hold is protecting rather than reporting
            # a tenant with nothing to purge.
            held = result.held
            try:
                purged = await _purge_lake(tenant_id, policy.raw_events_days, dry_run=dry_run or held)
                if held:
                    result.held_lake_rows = purged
                else:
                    result.lake_rows = purged
            except Exception as exc:
                # One unreachable store must not stop the other purges, and
                # must not look like "nothing needed deleting".
                result.errors.append(f"lake: {type(exc).__name__}")
                logger.warning(
                    "retention_purge.lake_failed tenant=%s err=%s",
                    tenant_id,
                    type(exc).__name__,
                )

            try:
                purged = await _purge_alerts(db, tenant_id, policy.alerts_days, dry_run=dry_run or held)
                if held:
                    result.held_alert_rows = purged
                else:
                    result.alert_rows = purged
            except Exception as exc:
                result.errors.append(f"alerts: {type(exc).__name__}")
                logger.warning(
                    "retention_purge.alerts_failed tenant=%s err=%s",
                    tenant_id,
                    type(exc).__name__,
                )

            if held:
                logger.info(
                    "retention_purge.held tenant=%s matters=%s lake_rows=%d alert_rows=%d",
                    tenant_id,
                    ",".join(result.hold_refs),
                    result.held_lake_rows,
                    result.held_alert_rows,
                )

            run.tenants.append(result)

        if not dry_run:
            await db.commit()
    finally:
        if own_session:
            await db.close()

    if run.tenants:
        logger.info(
            "retention_purge %s tenants=%d lake_rows=%d alert_rows=%d held_tenants=%d held_lake_rows=%d held_alert_rows=%d errors=%d",
            "preview (dry run, nothing deleted)" if dry_run else "applied",
            len(run.tenants),
            run.lake_rows,
            run.alert_rows,
            run.tenants_held,
            run.held_lake_rows,
            run.held_alert_rows,
            len(run.errors),
        )
    return run


async def run_forever() -> None:
    """Tick until cancelled. Owned by the API ``lifespan``, like the other workers."""
    interval = max(int(getattr(settings, "RETENTION_WORKER_INTERVAL_SECONDS", 21600)), 300)
    dry_run = bool(getattr(settings, "RETENTION_WORKER_DRY_RUN", True))
    logger.info(
        "retention_purge started interval=%ds mode=%s",
        interval,
        "dry-run" if dry_run else "delete",
    )
    if dry_run:
        logger.warning(
            "retention_purge is in dry-run: policies are evaluated and the row counts "
            "logged, but nothing is deleted. Set RETENTION_WORKER_DRY_RUN=false to arm it."
        )
    failures = TickFailures("retention_purge", logger)
    try:
        while True:
            try:
                await run_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # pragma: no cover - defensive
                failures.record_failure(exc)
            else:
                failures.record_success()
            await asyncio.sleep(interval)
    except asyncio.CancelledError:
        logger.info("retention_purge stopped")
        raise
