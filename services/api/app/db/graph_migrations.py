"""Versioned schema migrations for Neo4j.

There was no migration mechanism for any of the non-Postgres stores. Neo4j's
schema was a fixed list of ``CREATE … IF NOT EXISTS`` statements run at boot
with every failure swallowed at ``debug`` level. Three consequences, all of
which bite only on an existing deployment:

* **No way to change anything.** The list only creates. A property that needs
  backfilling, a constraint that needs replacing, an index that needs
  dropping — none are expressible, so a schema change lands on fresh installs
  and silently never lands on the deployments that have data.
* **No record of what was applied.** ``IF NOT EXISTS`` makes every run look
  identical whether the statement ran today or a year ago, so there is no way
  to ask a deployment which shape it is in.
* **Failures were invisible.** A constraint that cannot be created because
  existing data violates it logged at ``debug`` and the boot continued. The
  deployment then runs without the uniqueness guarantee the code assumes.

This module is the Neo4j counterpart to ``app.scripts.run_migrations``:
forward-only, numbered, recorded, and loud. Applied migrations are tracked as
``(:_AisocGraphMigration {id})`` nodes, which is the only state Neo4j offers
for this.

Adding a migration: append to ``MIGRATIONS``. Never edit or renumber an
existing one — a deployment that already recorded it will skip the edit, so
the two deployments diverge with no signal.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("aisoc.graph_migrations")

MIGRATION_LABEL = "_AisocGraphMigration"


@dataclass(frozen=True)
class GraphMigration:
    """One forward-only change to the graph schema.

    ``statements`` run in order. ``backfill`` runs after them and receives the
    session, for changes that need to touch data rather than schema — the
    thing the previous boot-time list could not express at all.

    ``allow_failure`` exists for statements that are genuinely optional on
    some Neo4j editions (full-text index syntax differs, vector indexes need
    5.13+). It is deliberately per-migration and off by default, because the
    old code applied it to everything.
    """

    id: str
    description: str
    statements: tuple[str, ...] = ()
    backfill: Callable[[Any], Awaitable[int]] | None = None
    allow_failure: bool = False
    tags: tuple[str, ...] = field(default_factory=tuple)


# ── 001: the pre-existing boot-time schema, captured as a migration ─────────
# Identical to what _create_schema() ran, so an existing deployment records
# 001 as applied and converges rather than re-running unknown statements.
_V1_CORE = (
    "CREATE CONSTRAINT IF NOT EXISTS FOR (h:Host) REQUIRE h.id IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (u:User) REQUIRE u.id IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (a:Alert) REQUIRE a.id IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (i:IOC) REQUIRE i.value IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (t:Technique) REQUIRE t.technique_id IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (c:Case) REQUIRE c.id IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (p:Process) REQUIRE p.id IS UNIQUE",
    "CREATE INDEX IF NOT EXISTS FOR (h:Host) ON (h.hostname)",
    "CREATE INDEX IF NOT EXISTS FOR (h:Host) ON (h.tenant_id)",
    "CREATE INDEX IF NOT EXISTS FOR (u:User) ON (u.username)",
    "CREATE INDEX IF NOT EXISTS FOR (u:User) ON (u.tenant_id)",
    "CREATE INDEX IF NOT EXISTS FOR (a:Alert) ON (a.tenant_id)",
    "CREATE INDEX IF NOT EXISTS FOR (a:Alert) ON (a.severity)",
    "CREATE INDEX IF NOT EXISTS FOR (i:IOC) ON (i.ioc_type)",
    "CREATE INDEX IF NOT EXISTS FOR (i:IOC) ON (i.tenant_id)",
    "CREATE INDEX IF NOT EXISTS FOR (t:Technique) ON (t.tactic)",
)

# ── 002: schema v1.1 context depth ──────────────────────────────────────────
# Every tenant-scoped label gets a tenant_id index, because tenant-scoped
# reads filter on it at every node of every path. Without the index those
# traversals degrade to a label scan, and the incident traversal touches five
# labels per hop.
_V11_CONTEXT = (
    # Identity depth
    "CREATE CONSTRAINT IF NOT EXISTS FOR (e:Employee) REQUIRE e.id IS UNIQUE",
    "CREATE INDEX IF NOT EXISTS FOR (e:Employee) ON (e.tenant_id)",
    "CREATE INDEX IF NOT EXISTS FOR (e:Employee) ON (e.email)",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (d:Department) REQUIRE d.id IS UNIQUE",
    "CREATE INDEX IF NOT EXISTS FOR (d:Department) ON (d.tenant_id)",
    # Asset depth
    "CREATE CONSTRAINT IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.id IS UNIQUE",
    "CREATE INDEX IF NOT EXISTS FOR (v:Vulnerability) ON (v.cve_id)",
    # Known-exploited is the field that changes triage priority, so it is
    # indexed rather than filtered after the fact.
    "CREATE INDEX IF NOT EXISTS FOR (v:Vulnerability) ON (v.known_exploited)",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (app:Application) REQUIRE app.id IS UNIQUE",
    "CREATE INDEX IF NOT EXISTS FOR (app:Application) ON (app.tenant_id)",
    "CREATE INDEX IF NOT EXISTS FOR (app:Application) ON (app.criticality)",
    # Cloud depth
    "CREATE CONSTRAINT IF NOT EXISTS FOR (ca:CloudAccount) REQUIRE ca.id IS UNIQUE",
    "CREATE INDEX IF NOT EXISTS FOR (ca:CloudAccount) ON (ca.tenant_id)",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (s:Secret) REQUIRE s.id IS UNIQUE",
    "CREATE INDEX IF NOT EXISTS FOR (s:Secret) ON (s.tenant_id)",
    # Threat depth. Malware/Campaign/ThreatActor/Tactic are global reference
    # data and carry no tenant_id, so they get no tenant index — the absence
    # is deliberate and matches the read-scope exemption.
    "CREATE CONSTRAINT IF NOT EXISTS FOR (m:Malware) REQUIRE m.id IS UNIQUE",
    "CREATE INDEX IF NOT EXISTS FOR (m:Malware) ON (m.name)",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (c:Campaign) REQUIRE c.id IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (ta:ThreatActor) REQUIRE ta.id IS UNIQUE",
    "CREATE INDEX IF NOT EXISTS FOR (ta:ThreatActor) ON (ta.name)",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (tac:Tactic) REQUIRE tac.id IS UNIQUE",
)


MIGRATIONS: tuple[GraphMigration, ...] = (
    GraphMigration(
        id="001_core_constraints",
        description="Baseline constraints and indexes (previously applied at boot)",
        statements=_V1_CORE,
    ),
    GraphMigration(
        id="002_schema_v1_1_context_depth",
        description=("Schema v1.1: identity, asset, cloud, business and threat context labels with tenant_id indexes for scoped traversal"),
        statements=_V11_CONTEXT,
        tags=("v1.1",),
    ),
)


async def applied_ids(session: Any) -> set[str]:
    """Migration ids this database has recorded."""
    result = await session.run(f"MATCH (m:{MIGRATION_LABEL}) RETURN m.id AS id")
    records = await result.data()
    return {r["id"] for r in records if r.get("id")}


async def _record(session: Any, migration: GraphMigration, applied_count: int) -> None:
    await session.run(
        f"MERGE (m:{MIGRATION_LABEL} {{id: $id}}) "
        "SET m.description = $description, m.applied_at = datetime(), "
        "m.statements = $statements, m.backfilled = $backfilled",
        id=migration.id,
        description=migration.description,
        statements=len(migration.statements),
        backfilled=applied_count,
    )


async def run_migrations(session: Any, *, strict: bool = True) -> list[str]:
    """Apply every unapplied migration in order. Returns the ids applied.

    ``strict`` (the default) re-raises the first failure. The previous code
    swallowed everything at ``debug``, so a deployment could boot without a
    uniqueness constraint the application assumes and nothing said so. Set
    ``strict=False`` only where a degraded graph is genuinely preferable to a
    failed boot, and expect the warning in the log to be acted on.
    """
    already = await applied_ids(session)
    applied: list[str] = []

    for migration in MIGRATIONS:
        if migration.id in already:
            continue

        logger.info("graph migration applying id=%s (%s)", migration.id, migration.description)
        for cypher in migration.statements:
            try:
                await session.run(cypher)
            except Exception as exc:
                if migration.allow_failure:
                    logger.warning(
                        "graph migration id=%s statement skipped (allow_failure): %s — %s",
                        migration.id,
                        cypher[:80],
                        type(exc).__name__,
                    )
                    continue
                logger.error(
                    "graph migration id=%s FAILED on: %s — %s: %s",
                    migration.id,
                    cypher[:120],
                    type(exc).__name__,
                    exc,
                )
                if strict:
                    raise
                break
        else:
            backfilled = 0
            if migration.backfill is not None:
                try:
                    backfilled = await migration.backfill(session)
                    logger.info("graph migration id=%s backfilled %d node(s)", migration.id, backfilled)
                except Exception as exc:
                    logger.error(
                        "graph migration id=%s backfill FAILED — %s: %s",
                        migration.id,
                        type(exc).__name__,
                        exc,
                    )
                    if strict:
                        raise
                    continue

            await _record(session, migration, backfilled)
            applied.append(migration.id)

    if applied:
        logger.info("graph migrations applied: %s", ", ".join(applied))
    else:
        logger.info("graph migrations: up to date (%d recorded)", len(already))
    return applied


async def pending_ids(session: Any) -> list[str]:
    """Migration ids not yet applied. For diagnostics and health output."""
    already = await applied_ids(session)
    return [m.id for m in MIGRATIONS if m.id not in already]
