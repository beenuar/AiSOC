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

**Audit is included, through one function and nothing else.** ``audit_days``
was storable and purged by nothing, because the audit log is an append-only
hash chain (migration 043) whose entire value is that no row was deleted,
reordered or rewritten — remove the oldest rows and a perfectly intact chain
replays as `prev_hash mismatch` at index 0, which is the worst outcome for a
control whose only job is to tell tampering from innocence.

Depth 8.1 built the chain-aware truncation that was missing. Migration `111`
adds `audit_retention_truncate`, a `SECURITY DEFINER` function that records a
checkpoint — the cutoff, the count, the hash of the last row removed and the
predecessor the oldest survivor names — and only then deletes, in the same
transaction. Verification re-anchors on that checkpoint and the remainder
replays clean, while the removal becomes a fact an auditor can read rather
than an absence they have to infer. The application role has **no DELETE
privilege on `audit_log`**, so that function is not merely the intended path,
it is the only one.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from dataclasses import field as dataclass_field
from datetime import UTC, datetime

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.clickhouse import execute_lake_query
from app.db.cross_tenant import assert_cross_tenant_session
from app.db.database import AsyncSessionLocal
from app.services import governance
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
    audit_days: int = 0
    lake_rows: int = 0
    alert_rows: int = 0
    audit_rows: int = 0
    #: Rows that were past the window and were not deleted because a legal
    #: hold covers this tenant. Counted rather than merely skipped: a hold
    #: that silently stops a purge and a purge that silently had nothing to
    #: do look identical in a log, and an auditor asking "did the hold
    #: work" can only be answered by a number.
    held_lake_rows: int = 0
    held_alert_rows: int = 0
    held_audit_rows: int = 0
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
    def audit_rows(self) -> int:
        return sum(t.audit_rows for t in self.tenants)

    @property
    def held_lake_rows(self) -> int:
        return sum(t.held_lake_rows for t in self.tenants)

    @property
    def held_alert_rows(self) -> int:
        return sum(t.held_alert_rows for t in self.tenants)

    @property
    def held_audit_rows(self) -> int:
        return sum(t.held_audit_rows for t in self.tenants)

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


@dataclass
class HoldPosture:
    """How this tenant's live holds bear on the sweep (WS2.4).

    ``freeze_refs`` — matter refs of holds that stop the WHOLE tenant's
    purge: tenant-wide holds (that is what they mean) and any subject kind
    the purge statements cannot test per row. ``narrow_holds`` — holds on
    ``user`` / ``host`` / ``ip`` subjects, whose rows the purge statements
    exempt individually (within each hold's `covers_from`/`covers_until`
    window) while everything else purges on schedule.
    """

    freeze_refs: list[str] = dataclass_field(default_factory=list)
    narrow_holds: list[governance.LegalHold] = dataclass_field(default_factory=list)


async def _hold_posture(db: AsyncSession, tenant_id: uuid.UUID) -> HoldPosture:
    """Classify this tenant's live holds into freeze vs narrow.

    Read before every sweep rather than cached: a hold placed between two
    runs has to take effect on the next one, and a cache measured in hours
    is a cache that deletes evidence placed under hold this morning.

    **What narrowed, and what still freezes.** The purges used to stop the
    whole tenant on ANY live hold, because neither bulk statement could
    test a per-subject predicate row by row. They now can, for the subject
    kinds that map onto row columns (`NARROWABLE_HOLD_KINDS`: user, host,
    ip): the alerts DELETE subtracts rows matched through the affected-*
    arrays, and the lake mutation subtracts rows matched on
    user_name/hostname/IP — each within the hold's own time window. A
    tenant-wide hold, or any kind outside that set, keeps the fail-closed
    whole-tenant freeze; over-retaining is the recoverable direction.

    The freeze decision still goes through ``may_purge`` so there is
    exactly one place in the tree where a hold beats a purge.
    """
    holds = await alerts_under_legal_hold(db, tenant_id)
    posture = HoldPosture()
    if not holds:
        return posture
    posture.narrow_holds = [h for h in holds if h.narrows_purge()]
    freezing = [h for h in holds if not h.narrows_purge()]
    if freezing:
        decision = may_purge(
            expired=True,
            subjects={hold.subject_kind: hold.subject_value for hold in freezing},
            holds=freezing,
        )
        if not decision.may_purge:
            posture.freeze_refs = sorted({hold.matter_ref or hold.id for hold in freezing})
    return posture


#: One exemption arm per narrowable subject kind, ANDed with the hold's
#: window. Static SQL fragments with numbered binds; the composer only
#: chooses which fragments appear, never their text.
_ALERT_HOLD_ARMS: dict[str, str] = {
    "user": (
        "EXISTS (SELECT 1 FROM jsonb_array_elements_text(coalesce(alerts.affected_users, '[]'::jsonb)) "
        "AS held_u(name) WHERE lower(held_u.name) = lower(:hold_v_{n}))"
    ),
    "host": (
        "EXISTS (SELECT 1 FROM jsonb_array_elements_text(coalesce(alerts.affected_hosts, '[]'::jsonb)) "
        "AS held_h(name) WHERE lower(held_h.name) = lower(:hold_v_{n}))"
    ),
    "ip": (
        "EXISTS (SELECT 1 FROM jsonb_array_elements_text(coalesce(alerts.affected_ips, '[]'::jsonb)) "
        "AS held_i(name) WHERE lower(held_i.name) = lower(:hold_v_{n}))"
    ),
}


def build_alert_hold_exemption(
    holds: list[governance.LegalHold],
) -> tuple[str, dict[str, object]]:
    """The ``AND NOT (...)`` clause exempting held alert rows, plus binds.

    Empty holds → empty clause. Every value is a bind parameter; the only
    composition is which static arm appears for which hold.
    """
    terms: list[str] = []
    params: dict[str, object] = {}
    for n, hold in enumerate(h for h in holds if h.narrows_purge()):
        arm = _ALERT_HOLD_ARMS[hold.subject_kind].format(n=n)
        window: list[str] = []
        params[f"hold_v_{n}"] = hold.subject_value
        if hold.covers_from is not None:
            window.append(f"alerts.created_at >= :hold_from_{n}")
            params[f"hold_from_{n}"] = hold.covers_from
        if hold.covers_until is not None:
            window.append(f"alerts.created_at <= :hold_until_{n}")
            params[f"hold_until_{n}"] = hold.covers_until
        terms.append("(" + " AND ".join([arm, *window]) + ")")
    if not terms:
        return "", {}
    return " AND NOT (" + " OR ".join(terms) + ")", params


_LAKE_HOLD_ARMS: dict[str, str] = {
    "user": "lower(user_name) = lower(%(hold_v_{n})s)",
    "host": "(lower(src_hostname) = lower(%(hold_v_{n})s) OR lower(dst_hostname) = lower(%(hold_v_{n})s))",
    # IPv6 columns: compare as addresses, so '1.2.3.4' matches its mapped form.
    "ip": "(source_ip = toIPv6OrDefault(%(hold_v_{n})s) OR dest_ip = toIPv6OrDefault(%(hold_v_{n})s))",
}


def build_lake_hold_exemption(
    holds: list[governance.LegalHold],
) -> tuple[str, dict[str, object]]:
    """The ClickHouse ``AND NOT (...)`` clause exempting held lake rows."""
    terms: list[str] = []
    params: dict[str, object] = {}
    for n, hold in enumerate(h for h in holds if h.narrows_purge()):
        arm = _LAKE_HOLD_ARMS[hold.subject_kind].format(n=n)
        window: list[str] = []
        params[f"hold_v_{n}"] = hold.subject_value
        if hold.covers_from is not None:
            window.append(f"event_time >= %(hold_from_{n})s")
            params[f"hold_from_{n}"] = hold.covers_from
        if hold.covers_until is not None:
            window.append(f"event_time <= %(hold_until_{n})s")
            params[f"hold_until_{n}"] = hold.covers_until
        terms.append("(" + " AND ".join([arm, *window]) + ")")
    if not terms:
        return "", {}
    return " AND NOT (" + " OR ".join(terms) + ")", params


async def _purge_lake(
    tenant_id: uuid.UUID,
    days: int,
    *,
    dry_run: bool,
    narrow_holds: list[governance.LegalHold] | None = None,
) -> int:
    """Delete (or count) lake events past the window. Returns the row count.

    ClickHouse ``ALTER TABLE … DELETE`` does not report affected rows, so even
    on the live path we count first. That costs one scan and buys an accurate
    number in the audit trail — worth it for an operation whose whole risk is
    deleting more than intended.

    ``narrow_holds`` (WS2.4) subtracts each hold's rows — matched on
    user_name / hostnames / IPs within the hold's window — from both the
    count and the mutation, so a scoped hold protects exactly its own rows
    while the rest of the tenant purges on schedule. The lake TTL ceiling
    is untouched and untouchable; a hold older than `MAX_LAKE_DAYS` is only
    satisfiable through the archive tier, which the attestation states.
    """
    exempt_sql, exempt_params = build_lake_hold_exemption(narrow_holds or [])
    count_result = await execute_lake_query(build_lake_count_sql(tenant_id, days) + exempt_sql, params=exempt_params or None)
    doomed = int(count_result.rows[0][0]) if count_result.rows else 0
    if doomed == 0 or dry_run:
        return doomed

    await execute_lake_query(
        build_lake_purge_sql(tenant_id, days) + exempt_sql,
        params=exempt_params or None,
        extra_settings=_MUTATIONS_SYNC,
    )
    return doomed


async def _purge_audit(db: AsyncSession, tenant_id: uuid.UUID, days: int, *, dry_run: bool) -> int:
    """Truncate (or count) audit rows past the window for one tenant.

    The delete goes through `audit_retention_truncate`, which is not a
    style choice: the application role has no DELETE privilege on
    `audit_log`, so a statement here would be refused by Postgres. That
    function records the re-anchoring checkpoint and removes the rows in
    one transaction, so there is no ordering in which the rows are gone
    and the record of them is not.

    A window of zero is "no audit window configured" and purges nothing.
    `resolve_policy` fills the other two from `DEFAULT_RETENTION`; this one
    is deliberately not defaulted, because a default that silently starts
    deleting an audit trail is the kind of instruction nobody gave.
    """
    if days <= 0:
        return 0

    doomed = int(
        (
            await db.execute(
                text("SELECT count(*) FROM audit_log WHERE tenant_id = :tenant_id AND created_at < now() - make_interval(days => :days)"),
                {"tenant_id": str(tenant_id), "days": days},
            )
        ).scalar_one()
    )
    if doomed == 0 or dry_run:
        return doomed

    removed = (
        await db.execute(
            text("SELECT audit_retention_truncate(CAST(:tenant_id AS uuid), now() - make_interval(days => :days), :days)"),
            {"tenant_id": str(tenant_id), "days": days},
        )
    ).scalar_one()
    # The function's own count, not the one counted a moment ago. A row
    # written between the two is retained rather than reported as removed.
    return int(removed or 0)


async def _purge_alerts(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    days: int,
    *,
    dry_run: bool,
    narrow_holds: list[governance.LegalHold] | None = None,
) -> int:
    """Delete (or count) alerts past the window for one tenant.

    ``build_alert_purge_sql`` relies on RLS for the tenant scope, which is
    correct inside a request but wrong here: this session has row security
    disabled so it can enumerate every tenant. The tenant predicate is
    therefore bound explicitly, as a parameter. Without this the statement
    would delete every tenant's aged alerts under the first tenant's window.
    """
    exempt_sql, exempt_params = build_alert_hold_exemption(narrow_holds or [])
    count_sql, params = build_alert_count_sql(days)
    count_sql += " AND tenant_id = :tenant_id" + exempt_sql
    params_with_tenant: dict[str, object] = {**params, "tenant_id": str(tenant_id), **exempt_params}

    # nosemgrep — count_sql is machine-composed from fixed fragments; every value (tenant, days, hold subjects, windows) is a bound parameter
    doomed = int((await db.execute(text(count_sql), params_with_tenant)).scalar_one())
    if doomed == 0 or dry_run:
        return doomed

    await db.execute(
        # nosemgrep — exempt_sql comes from build_alert_hold_exemption: fixed fragments with every hold subject and window bound as :hold_* parameters
        text("DELETE FROM alerts WHERE tenant_id = :tenant_id AND created_at < now() - make_interval(days => :days)" + exempt_sql),
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
                # Read from the stored policy rather than from
                # `resolve_policy`, which fills an unset window from
                # `DEFAULT_RETENTION`. Those defaults exist to pre-fill a
                # form; treating one as an instruction to start truncating
                # an audit trail would delete evidence nobody asked to
                # delete.
                audit_days=int(config.get("audit_days") or 0),
            )

            narrow_holds: list[governance.LegalHold] = []
            try:
                posture = await _hold_posture(db, tenant_id)
                result.hold_refs = posture.freeze_refs
                narrow_holds = posture.narrow_holds
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
                purged = await _purge_lake(tenant_id, policy.raw_events_days, dry_run=dry_run or held, narrow_holds=narrow_holds)
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
                purged = await _purge_alerts(db, tenant_id, policy.alerts_days, dry_run=dry_run or held, narrow_holds=narrow_holds)
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

            try:
                purged = await _purge_audit(db, tenant_id, result.audit_days, dry_run=dry_run or held)
                if held:
                    result.held_audit_rows = purged
                else:
                    result.audit_rows = purged
            except Exception as exc:
                # Same reasoning as the two above: one failing store must
                # not read as "nothing needed deleting". It matters more
                # here, because the thing that did not happen is an
                # erasure somebody may have been told was performed.
                result.errors.append(f"audit: {type(exc).__name__}")
                logger.warning(
                    "retention_purge.audit_failed tenant=%s err=%s",
                    tenant_id,
                    type(exc).__name__,
                )

            if held:
                logger.info(
                    "retention_purge.held tenant=%s matters=%s lake_rows=%d alert_rows=%d audit_rows=%d",
                    tenant_id,
                    ",".join(result.hold_refs),
                    result.held_lake_rows,
                    result.held_alert_rows,
                    result.held_audit_rows,
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
