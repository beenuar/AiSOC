"""Forward-only schema migrations for the Qdrant vector store.

The third of the three stores with no migration mechanism. Qdrant is the
awkward one, because the change most likely to be needed is the one it
cannot do.

**A collection's vector dimension and distance metric are immutable.**
Changing an embedding model changes the dimension, and there is no
`ALTER COLLECTION`. The migration is: create a new collection, re-embed
every point into it, swap an alias, drop the old one. That is a data
migration measured in hours for a large tenant, not a DDL statement — so
this module models it as one rather than pretending a dimension change is a
schema tweak.

**Aliases are the indirection that makes it survivable.** Code reads
through an alias, never a collection name directly. A re-embed builds
alongside the live collection and the alias flips atomically at the end, so
a failed migration leaves the old collection serving rather than a
half-populated new one.

What *is* cheap: payload indexes, quantization settings, HNSW parameters,
optimizer thresholds. Those are the ordinary migrations, and they are why
this exists even though re-embeds are rare.

Same shape as `graph_migrations.py` and `lake_migrations.py`: numbered,
append-only, applied ids recorded in the store itself. Qdrant has no table
to record them in, so the ledger is a dedicated collection holding one
point per applied migration — small, and it keeps the record in the store
being migrated rather than somewhere that can drift from it.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger("aisoc.vector_migrations")

#: Ledger collection. One point per applied migration, keyed by a stable
#: hash of the id so re-recording is idempotent.
MIGRATION_COLLECTION = "aisoc_migrations"

#: Minimal vector config for the ledger. Qdrant requires *some* vector
#: definition; one dimension is the smallest legal answer and the vectors
#: are never searched.
_LEDGER_DIM = 1


@dataclass(frozen=True)
class VectorMigration:
    """One forward-only change to the vector store.

    ``apply`` receives the client and does the work, rather than a list of
    statements: Qdrant's API is method calls, not a query language, and
    pretending otherwise would mean inventing a DSL whose only user is this
    file.

    ``rebuilds_collection`` marks the expensive class — a dimension or
    metric change that requires re-embedding every point. Flagged so an
    operator can see one coming in ``pending_ids()`` before it starts, since
    the difference between a one-second migration and a four-hour one should
    not be a surprise discovered at deploy time.
    """

    id: str
    description: str
    apply: Callable[[Any], Awaitable[None]]
    rebuilds_collection: bool = False
    tags: tuple[str, ...] = field(default_factory=tuple)


def _point_id(migration_id: str) -> int:
    """A stable positive integer id for a migration.

    Qdrant point ids are unsigned integers or UUIDs. Hashed with blake2b
    rather than `hash()` for the same reason the sandbox was fixed: CPython
    salts string hashing per process, so a ledger keyed on `hash()` would
    record the same migration under a different id on every restart and the
    runner would re-apply everything.
    """
    import hashlib

    digest = hashlib.blake2b(migration_id.encode(), digest_size=8).digest()
    return int.from_bytes(digest, "big") & 0x7FFF_FFFF_FFFF_FFFF


async def _ensure_ledger(client: Any) -> None:
    try:
        collections = await client.get_collections()
        names = {c.name for c in getattr(collections, "collections", [])}
    except Exception as exc:  # noqa: BLE001 - treated as absent, created below
        logger.warning("vector_migrations.list_failed error=%s", exc)
        names = set()

    if MIGRATION_COLLECTION in names:
        return

    from qdrant_client.models import Distance, VectorParams  # noqa: PLC0415

    await client.create_collection(
        collection_name=MIGRATION_COLLECTION,
        vectors_config=VectorParams(size=_LEDGER_DIM, distance=Distance.COSINE),
    )
    logger.info("vector_migrations.ledger_created")


async def applied_ids(client: Any) -> set[str]:
    """Migration ids this store already has."""
    await _ensure_ledger(client)
    try:
        points, _ = await client.scroll(collection_name=MIGRATION_COLLECTION, limit=1000, with_payload=True)
    except Exception as exc:  # noqa: BLE001 - an empty ledger is a normal first run
        logger.warning("vector_migrations.ledger_unreadable error=%s", exc)
        return set()

    return {str(p.payload["migration_id"]) for p in points or [] if getattr(p, "payload", None) and p.payload.get("migration_id")}


async def _record(client: Any, migration: VectorMigration) -> None:
    from qdrant_client.models import PointStruct  # noqa: PLC0415

    await client.upsert(
        collection_name=MIGRATION_COLLECTION,
        points=[
            PointStruct(
                id=_point_id(migration.id),
                vector=[0.0] * _LEDGER_DIM,
                payload={
                    "migration_id": migration.id,
                    "description": migration.description,
                    "applied_at": datetime.now(UTC).isoformat(),
                },
            )
        ],
    )


async def _apply_baseline(client: Any) -> None:
    """Records the pre-existing collections as the baseline.

    Creates nothing. `QdrantStore` builds its collections on first use, so
    an existing deployment already has them; the point is that the ledger
    agrees, and migration 002 onwards can assume a known starting shape.
    """
    return None


MIGRATIONS: tuple[VectorMigration, ...] = (
    VectorMigration(
        id="001_baseline",
        description=("Records the collections QdrantStore creates on first use as the baseline. Creates nothing."),
        apply=_apply_baseline,
        tags=("baseline",),
    ),
)


async def run_migrations(client: Any, *, strict: bool = True) -> list[str]:
    """Apply every unapplied migration in order. Returns the ids applied.

    Stops at the first failure: migration N+1 is written against the state N
    produced, and continuing past a failure leaves the store in a shape no
    migration describes.
    """
    already = await applied_ids(client)
    applied: list[str] = []

    for migration in MIGRATIONS:
        if migration.id in already:
            continue

        if migration.rebuilds_collection:
            logger.warning(
                "vector_migrations.rebuild_starting id=%s — this re-embeds "
                "every point and is measured in hours for a large tenant. The "
                "alias keeps the existing collection serving until it "
                "completes.",
                migration.id,
            )

        logger.info("vector_migrations.applying id=%s", migration.id)
        try:
            await migration.apply(client)
            await _record(client, migration)
        except Exception as exc:  # noqa: BLE001 - reported, re-raised under strict
            logger.error("vector_migrations.failed id=%s error=%s", migration.id, exc)
            if strict:
                raise
            return applied

        applied.append(migration.id)

    if applied:
        logger.info("vector_migrations.complete applied=%s", ",".join(applied))
    return applied


async def pending_ids(client: Any) -> list[str]:
    """Migrations this store has not applied. For health checks and preflight."""
    already = await applied_ids(client)
    return [m.id for m in MIGRATIONS if m.id not in already]


async def pending_rebuilds(client: Any) -> list[str]:
    """Pending migrations that re-embed. Surfaced separately because the
    difference between a one-second migration and a four-hour one should not
    be discovered at deploy time."""
    already = await applied_ids(client)
    return [m.id for m in MIGRATIONS if m.id not in already and m.rebuilds_collection]
