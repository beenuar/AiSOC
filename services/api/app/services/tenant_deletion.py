"""Tenant offboarding: erase one tenant from every store that holds its data.

There was no deletion path. ``DELETE FROM tenants`` relies on foreign-key
cascade, and 14 of the 72 tenant-scoped tables never declared one — including
``aisoc_institutional_memory`` (an offboarded customer's behavioural priors),
``aisoc_compliance_evidence`` and ``aisoc_kb_documents``. Those rows outlive
the tenant silently, which is a deletion-request problem rather than an
untidiness problem. The lake, graph and vector stores had no deletion path at
all.

Two design choices carry most of the value here.

**The Postgres table list is discovered at runtime**, from
``information_schema``, rather than being a constant someone must remember to
extend. A hardcoded list is correct on the day it is written and wrong at the
next migration, and the failure is invisible: deletion reports success while
leaving rows behind. Discovery means a new tenant-scoped table is covered the
moment it exists.

**Every store reports independently.** A tenant is only erased when all of
them succeeded, so a Neo4j outage cannot produce a "deleted" result while the
graph still holds the estate. The caller gets per-store counts and errors, and
``DeletionReport.complete`` is false if anything failed.

Deletion is irreversible and cross-tenant by nature, so the caller is
responsible for authorisation. ``dry_run=True`` (the default) counts without
deleting, because the first question anyone asks is "what exactly will this
remove".
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field

import httpx
from redis.asyncio import from_url as redis_from_url
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.clickhouse import execute_lake_query
from app.db.cross_tenant import assert_cross_tenant_session
from app.db.neo4j import get_session as neo4j_session

logger = logging.getLogger("aisoc.tenant_deletion")

# Discovered per run, but the tenants row itself must go last — deleting it
# first would cascade some tables out from under the count we are reporting.
_TENANTS_TABLE = "tenants"

# Reference data that is intentionally global (MITRE technique nodes, public
# threat-intel) must survive an offboarding. Everything else scoped to the
# tenant goes.
_GLOBAL_GRAPH_LABELS = ("Technique", "Tactic", "Mitigation", "Malware", "ThreatActor")


@dataclass
class StoreResult:
    store: str
    rows: int = 0
    detail: dict[str, int] = field(default_factory=dict)
    error: str | None = None
    skipped: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


@dataclass
class DeletionReport:
    tenant_id: uuid.UUID
    dry_run: bool
    stores: list[StoreResult] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        """True only when every store that holds data succeeded.

        A skipped store (not configured in this deployment) does not block
        completion; a failed one does. Reporting a partial erase as complete
        is the failure mode that turns a deletion request into a breach.
        """
        return all(s.ok for s in self.stores)

    @property
    def total_rows(self) -> int:
        return sum(s.rows for s in self.stores)

    def as_dict(self) -> dict[str, object]:
        return {
            "tenant_id": str(self.tenant_id),
            "dry_run": self.dry_run,
            "complete": self.complete,
            "total_rows": self.total_rows,
            "stores": [
                {
                    "store": s.store,
                    "rows": s.rows,
                    "detail": s.detail,
                    "error": s.error,
                    "skipped": s.skipped,
                }
                for s in self.stores
            ],
        }


async def discover_tenant_tables(db: AsyncSession) -> list[str]:
    """Every table in the public schema with a ``tenant_id`` column.

    Discovered rather than declared so a migration cannot silently add a
    tenant-scoped table that offboarding then misses.
    """
    rows = await db.execute(
        text(
            "SELECT c.table_name FROM information_schema.columns c "
            "JOIN information_schema.tables t "
            "  ON t.table_schema = c.table_schema AND t.table_name = c.table_name "
            "WHERE c.table_schema = 'public' "
            "  AND c.column_name = 'tenant_id' "
            "  AND t.table_type = 'BASE TABLE' "
            "ORDER BY c.table_name"
        )
    )
    return [r[0] for r in rows.fetchall()]


async def _count_dependent_organizations(db: AsyncSession, tenant_id: uuid.UUID) -> int:
    """Organisations this tenant *hosts*, which go with it.

    Discovery finds tables by a column literally named ``tenant_id``, and
    ``organizations.home_tenant_id`` is not one — so the row is removed by
    the foreign-key cascade but never appears in the report. A deletion
    report that undercounts is the same class of problem as one that
    overstates completeness: the operator signing off on an erasure needs to
    know an operator organisation was part of it.

    Only the organisation row and its membership go. The tenants it managed
    are other people's customers; they survive as unclaimed tenants, and
    ``organization_tenants`` loses its links by cascade.
    """
    return int(
        (
            await db.execute(
                text("SELECT count(*) FROM organizations WHERE home_tenant_id = :t"),
                {"t": str(tenant_id)},
            )
        ).scalar_one()
    )


async def purge_postgres(db: AsyncSession, tenant_id: uuid.UUID, *, dry_run: bool) -> StoreResult:
    result = StoreResult(store="postgres")
    try:
        # Cross-tenant by design, and the predicate below is explicit, so a
        # policy could only hide rows we are required to delete. An unbound
        # session sees all of them through the ``OR current_tenant_id() IS
        # NULL`` arm; a bound one would delete a fraction of the tenant's rows
        # and report the deletion complete, which for this operation is a
        # compliance claim rather than a log line.
        #
        # ``SET LOCAL row_security = off`` used to stand here and raises under
        # the runtime role (``migrations/061_runtime_app_role.sql``).
        await assert_cross_tenant_session(db, "tenant deletion purge")
        tables = await discover_tenant_tables(db)

        for table in tables:
            if table == _TENANTS_TABLE:
                continue
            # Identifiers cannot be bound, so they are restricted to what
            # information_schema returned — never caller input.
            if not table.replace("_", "").isalnum():
                raise ValueError(f"refusing to touch unexpected table name: {table!r}")

            count = (
                await db.execute(
                    text(f"SELECT count(*) FROM {table} WHERE tenant_id = :t"),
                    {"t": str(tenant_id)},
                )
            ).scalar_one()
            if not count:
                continue
            result.detail[table] = int(count)
            result.rows += int(count)
            if not dry_run:
                await db.execute(
                    text(f"DELETE FROM {table} WHERE tenant_id = :t"),
                    {"t": str(tenant_id)},
                )

        hosted_orgs = await _count_dependent_organizations(db, tenant_id)
        if hosted_orgs:
            result.detail["organizations"] = hosted_orgs
            result.rows += hosted_orgs
            if not dry_run:
                # Explicit rather than left to the cascade, so the delete and
                # the number we just reported are the same operation.
                await db.execute(text("DELETE FROM organizations WHERE home_tenant_id = :t"), {"t": str(tenant_id)})

        tenant_rows = (await db.execute(text("SELECT count(*) FROM tenants WHERE id = :t"), {"t": str(tenant_id)})).scalar_one()
        if tenant_rows:
            result.detail[_TENANTS_TABLE] = int(tenant_rows)
            result.rows += int(tenant_rows)
            if not dry_run:
                await db.execute(text("DELETE FROM tenants WHERE id = :t"), {"t": str(tenant_id)})
    except Exception as exc:
        result.error = f"{type(exc).__name__}: {exc}"
        logger.warning("tenant_deletion.postgres_failed tenant=%s err=%s", tenant_id, type(exc).__name__)
    return result


async def purge_lake(tenant_id: uuid.UUID, *, dry_run: bool) -> StoreResult:
    """Erase the tenant's rows from the ClickHouse event lake."""
    result = StoreResult(store="clickhouse")
    tid = str(uuid.UUID(str(tenant_id)))
    try:
        counted = await execute_lake_query(f"SELECT count() FROM aisoc.raw_events WHERE tenant_id = '{tid}'")
        result.rows = int(counted.rows[0][0]) if counted.rows else 0
        if result.rows and not dry_run:
            await execute_lake_query(
                f"ALTER TABLE aisoc.raw_events DELETE WHERE tenant_id = '{tid}'",
                extra_settings={"mutations_sync": 1},
            )
    except Exception as exc:
        result.error = f"{type(exc).__name__}: {exc}"
        logger.warning("tenant_deletion.lake_failed tenant=%s err=%s", tenant_id, type(exc).__name__)
    return result


async def purge_graph(tenant_id: uuid.UUID, *, dry_run: bool) -> StoreResult:
    """Erase the tenant's nodes from Neo4j, keeping global reference data.

    The Go writer MERGEs entities on ``natural_key`` with ``tenant_id`` as a
    property, so a shared node (a public IP seen by two tenants) carries the
    last writer's tenant. Deleting by tenant property is therefore the only
    available scope, and can remove a node another tenant also referenced.
    That is the safe direction for a deletion request: the node re-creates on
    the other tenant's next ingest, whereas leaving it would mean the
    offboarded tenant's data persists.
    """
    result = StoreResult(store="neo4j")
    labels = "|".join(_GLOBAL_GRAPH_LABELS)
    try:
        async with neo4j_session() as session:
            counted = await session.run(
                f"MATCH (n) WHERE n.tenant_id = $t AND NOT n:{labels} " "RETURN count(n) AS c",
                t=str(tenant_id),
            )
            record = await counted.single()
            result.rows = int(record["c"]) if record else 0
            if result.rows and not dry_run:
                # DETACH so relationships go with the node rather than
                # blocking the delete. Batched: a large estate in one
                # transaction is how a Neo4j offboarding runs out of heap.
                while True:
                    deleted = await session.run(
                        f"MATCH (n) WHERE n.tenant_id = $t AND NOT n:{labels} " "WITH n LIMIT 10000 DETACH DELETE n RETURN count(n) AS c",
                        t=str(tenant_id),
                    )
                    row = await deleted.single()
                    if not row or not int(row["c"]):
                        break
    except Exception as exc:
        result.error = f"{type(exc).__name__}: {exc}"
        logger.warning("tenant_deletion.graph_failed tenant=%s err=%s", tenant_id, type(exc).__name__)
    return result


async def purge_vectors(tenant_id: uuid.UUID, *, dry_run: bool) -> StoreResult:
    """Erase the tenant's points from Qdrant.

    Public feed intel is global by design and carries no ``tenant_id`` in its
    payload, so a tenant-filtered delete leaves it alone.
    """
    result = StoreResult(store="qdrant")
    if getattr(settings, "AISOC_DISABLE_QDRANT", False):
        result.skipped = "AISOC_DISABLE_QDRANT is set"
        return result

    base = str(getattr(settings, "QDRANT_URL", "") or "").rstrip("/")
    if not base:
        result.skipped = "QDRANT_URL is not configured"
        return result

    filter_body = {"filter": {"must": [{"key": "tenant_id", "match": {"value": str(tenant_id)}}]}}
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            collections = (await client.get(f"{base}/collections")).json()
            names = [c["name"] for c in collections.get("result", {}).get("collections", [])]

            for name in names:
                counted = await client.post(f"{base}/collections/{name}/points/count", json=filter_body)
                count = int(counted.json().get("result", {}).get("count", 0))
                if not count:
                    continue
                result.detail[name] = count
                result.rows += count
                if not dry_run:
                    response = await client.post(
                        f"{base}/collections/{name}/points/delete?wait=true",
                        json=filter_body,
                    )
                    response.raise_for_status()
    except Exception as exc:
        result.error = f"{type(exc).__name__}: {exc}"
        logger.warning("tenant_deletion.qdrant_failed tenant=%s err=%s", tenant_id, type(exc).__name__)
    return result


async def purge_cache(tenant_id: uuid.UUID, *, dry_run: bool) -> StoreResult:
    """Erase the tenant's Redis keys (``tenant:{id}:*``)."""
    result = StoreResult(store="redis")
    try:
        url = str(getattr(settings, "REDIS_URL", "") or "")
        if not url:
            result.skipped = "REDIS_URL is not configured"
            return result
        client = redis_from_url(url, decode_responses=True)
        try:
            async for key in client.scan_iter(match=f"tenant:{tenant_id}:*", count=500):
                result.rows += 1
                if not dry_run:
                    await client.delete(key)
        finally:
            await client.aclose()
    except Exception as exc:
        result.error = f"{type(exc).__name__}: {exc}"
        logger.warning("tenant_deletion.redis_failed tenant=%s err=%s", tenant_id, type(exc).__name__)
    return result


async def delete_tenant(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    *,
    dry_run: bool = True,
) -> DeletionReport:
    """Erase a tenant from every store. Irreversible when ``dry_run`` is false.

    Ordering matters: the satellite stores go first, and Postgres last. If the
    tenant row were removed first and a later store failed, the operator would
    be left with orphaned data and no tenant record naming who it belonged to.
    """
    report = DeletionReport(tenant_id=tenant_id, dry_run=dry_run)

    report.stores.append(await purge_lake(tenant_id, dry_run=dry_run))
    report.stores.append(await purge_graph(tenant_id, dry_run=dry_run))
    report.stores.append(await purge_vectors(tenant_id, dry_run=dry_run))
    report.stores.append(await purge_cache(tenant_id, dry_run=dry_run))
    report.stores.append(await purge_postgres(db, tenant_id, dry_run=dry_run))

    if not dry_run:
        if report.complete:
            await db.commit()
        else:
            # Leaving Postgres intact keeps the tenant record that names the
            # data still sitting in whichever store failed.
            await db.rollback()

    logger.info(
        "tenant_deletion %s tenant=%s rows=%d complete=%s failed=%s",
        "preview" if dry_run else "applied",
        tenant_id,
        report.total_rows,
        report.complete,
        [s.store for s in report.stores if not s.ok] or "none",
    )
    return report
