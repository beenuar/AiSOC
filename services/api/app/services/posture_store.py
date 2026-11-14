"""Read and write versioned identity-posture snapshots (depth plan 2.5).

Backs migration 103. The table's reason for existing is in its own comment
block; this module is the only thing that writes it, and it exists to keep
one invariant true from the application side as well as the index side:

    at most one row per (tenant, provider) has ``valid_until IS NULL``

and to make the point-in-time read the easy call to reach for, so a caller
asking "what could this identity do" does not quietly get "what can it do
now" because that query was shorter to write.

Every statement filters on ``tenant_id`` in the ``WHERE`` clause. RLS is
enabled on the table too, but the query-layer filter is the control being
relied on here: RLS depends on the session GUC being set, and a path that
forgets it would read across tenants with the policy still in force.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logger = structlog.get_logger(__name__)

#: Mirrors the CHECK constraint in migration 103. Declared here as well so a
#: bad provider is refused with a sentence naming the valid set rather than
#: an IntegrityError from the driver.
PROVIDERS: frozenset[str] = frozenset({"aws", "azure", "gcp", "gws", "github", "okta"})


def content_hash(snapshot: dict[str, Any]) -> str:
    """sha256 over a canonical rendering of the snapshot.

    ``sort_keys`` is what makes this stable: two collections of an unchanged
    estate differ only in dict ordering, and without it every re-collection
    would look like a posture change and the history would answer "when did
    this last change" with "every hour".
    """
    canonical = json.dumps(snapshot, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def counts(snapshot: dict[str, Any]) -> tuple[int, int, int]:
    """``(principals, resources, policies)`` for one snapshot.

    Counted from the collected document rather than from whatever the
    collector thought it fetched, so a truncated page shows up as a smaller
    number instead of agreeing with an optimistic running total.

    It lives here, beside the columns it fills, because the only reader of
    these three numbers is this table. An earlier draft had it in the
    connectors package, one import boundary away from the only thing that
    uses it, which is how a second definition starts.
    """
    principals = len(snapshot.get("principals") or ())
    resources = len(snapshot.get("resources") or ())
    policies = (
        len(snapshot.get("policies") or ())
        + len(snapshot.get("role_definitions") or ())
        + len(snapshot.get("roles") or ())
        + len(snapshot.get("admin_roles") or ())
    )
    return principals, resources, policies


@dataclass(frozen=True)
class PostureSnapshot:
    """One version of a provider's posture, and how complete it is."""

    id: uuid.UUID
    tenant_id: uuid.UUID
    provider: str
    connector_id: str
    snapshot: dict[str, Any]
    content_hash: str
    principal_count: int
    resource_count: int
    policy_count: int
    partial: bool
    collection_notes: list[str]
    collected_at: datetime
    valid_from: datetime
    valid_until: datetime | None

    @property
    def is_live(self) -> bool:
        return self.valid_until is None


def _row_to_snapshot(row: Any) -> PostureSnapshot:
    # asyncpg hands back jsonb already decoded; other drivers hand back a
    # string. Accepting both here keeps every caller from having to know
    # which one it is on.
    snapshot = row.snapshot if isinstance(row.snapshot, dict) else json.loads(row.snapshot or "{}")
    notes = row.collection_notes if isinstance(row.collection_notes, list) else json.loads(row.collection_notes or "[]")
    return PostureSnapshot(
        id=row.id if isinstance(row.id, uuid.UUID) else uuid.UUID(str(row.id)),
        tenant_id=row.tenant_id if isinstance(row.tenant_id, uuid.UUID) else uuid.UUID(str(row.tenant_id)),
        provider=row.provider,
        connector_id=row.connector_id,
        snapshot=snapshot,
        content_hash=row.content_hash,
        principal_count=int(row.principal_count or 0),
        resource_count=int(row.resource_count or 0),
        policy_count=int(row.policy_count or 0),
        partial=bool(row.partial),
        collection_notes=list(notes),
        collected_at=row.collected_at,
        valid_from=row.valid_from,
        valid_until=row.valid_until,
    )


_COLUMNS = """
    id, tenant_id, provider, connector_id, snapshot, content_hash,
    principal_count, resource_count, policy_count, partial, collection_notes,
    collected_at, valid_from, valid_until
"""


async def save_snapshot(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    provider: str,
    connector_id: str,
    snapshot: dict[str, Any],
    principal_count: int | None = None,
    resource_count: int | None = None,
    policy_count: int | None = None,
    partial: bool = False,
    collection_notes: list[str] | None = None,
    connector_instance_id: uuid.UUID | None = None,
    collection_ms: int | None = None,
) -> PostureSnapshot:
    """Record a collection, opening a new version only if something changed.

    An unchanged estate re-collected hourly must not write a version an hour,
    or the history stops being able to answer "when did this posture last
    change". So an identical ``content_hash`` leaves the live row in force and
    only refreshes ``collected_at`` — the row's interval is about when the
    posture was true, and it still is.

    A changed hash closes the live row and inserts the new one. Both
    statements run in the caller's transaction and the partial unique index
    would refuse the overlap, so a half-applied supersede cannot leave two
    live rows behind.
    """
    if provider not in PROVIDERS:
        raise ValueError(f"unknown provider {provider!r}; valid: {sorted(PROVIDERS)}")

    digest = content_hash(snapshot)
    notes = list(collection_notes or [])

    # Derived unless the caller measured them itself. Defaulting these to 0
    # would have let a caller that forgot them write "this estate has no
    # principals", which is the one value an operator reads as "our
    # credential lost its permissions".
    derived = counts(snapshot)
    principal_count = derived[0] if principal_count is None else principal_count
    resource_count = derived[1] if resource_count is None else resource_count
    policy_count = derived[2] if policy_count is None else policy_count

    live = await live_snapshot(db, tenant_id=tenant_id, provider=provider)
    if live is not None and live.content_hash == digest:
        # Same posture. Record that we looked — and that the partial state
        # and its reasons may have changed even when the content did not, as
        # a collection that newly lost read access to half the estate returns
        # exactly the snapshot it could still see.
        await db.execute(
            text(
                """
                UPDATE posture_snapshots
                   SET collected_at     = NOW(),
                       collection_ms    = :collection_ms,
                       partial          = :partial,
                       collection_notes = CAST(:collection_notes AS jsonb)
                 WHERE tenant_id = :tenant_id
                   AND id = :id
                """
            ),
            {
                "tenant_id": str(tenant_id),
                "id": str(live.id),
                "collection_ms": collection_ms,
                "partial": partial,
                "collection_notes": json.dumps(notes),
            },
        )
        refreshed = await live_snapshot(db, tenant_id=tenant_id, provider=provider)
        # The row was just updated inside this transaction, so it is there;
        # returning the pre-update object would hand back stale notes.
        return refreshed if refreshed is not None else live

    if live is not None:
        await db.execute(
            text(
                """
                UPDATE posture_snapshots
                   SET valid_until = NOW()
                 WHERE tenant_id = :tenant_id
                   AND id = :id
                   AND valid_until IS NULL
                """
            ),
            {"tenant_id": str(tenant_id), "id": str(live.id)},
        )

    result = await db.execute(
        text(
            f"""
            INSERT INTO posture_snapshots (
                tenant_id, provider, connector_id, connector_instance_id,
                snapshot, content_hash,
                principal_count, resource_count, policy_count,
                partial, collection_notes, collection_ms
            ) VALUES (
                :tenant_id, :provider, :connector_id, :connector_instance_id,
                CAST(:snapshot AS jsonb), :content_hash,
                :principal_count, :resource_count, :policy_count,
                :partial, CAST(:collection_notes AS jsonb), :collection_ms
            )
            RETURNING {_COLUMNS}
            """
        ),
        {
            "tenant_id": str(tenant_id),
            "provider": provider,
            "connector_id": connector_id,
            "connector_instance_id": str(connector_instance_id) if connector_instance_id else None,
            "snapshot": json.dumps(snapshot, default=str),
            "content_hash": digest,
            "principal_count": principal_count,
            "resource_count": resource_count,
            "policy_count": policy_count,
            "partial": partial,
            "collection_notes": json.dumps(notes),
            "collection_ms": collection_ms,
        },
    )
    return _row_to_snapshot(result.fetchone())


async def live_snapshot(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    provider: str,
) -> PostureSnapshot | None:
    """The version in force now, or ``None`` if this tenant has never collected."""
    result = await db.execute(
        text(
            f"""
            SELECT {_COLUMNS}
              FROM posture_snapshots
             WHERE tenant_id = :tenant_id
               AND provider = :provider
               AND valid_until IS NULL
             LIMIT 1
            """
        ),
        {"tenant_id": str(tenant_id), "provider": provider},
    )
    row = result.fetchone()
    return _row_to_snapshot(row) if row else None


async def snapshot_at(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    provider: str,
    at: datetime,
) -> PostureSnapshot | None:
    """The version that was in force at ``at``.

    This is the call a triage path should make. "What can this identity do"
    and "what could it do when it acted" are different questions, and on an
    alert raised before someone revoked a role they have different answers —
    the second being the one that explains the alert.

    Returns ``None`` when no version covers ``at``: an event predating the
    tenant's first collection has no posture, and saying so is the only
    honest answer. Falling back to the live snapshot would answer a question
    nobody asked, in a way no reader could detect.
    """
    result = await db.execute(
        text(
            f"""
            SELECT {_COLUMNS}
              FROM posture_snapshots
             WHERE tenant_id = :tenant_id
               AND provider = :provider
               AND valid_from <= :at
               AND (valid_until IS NULL OR valid_until > :at)
             ORDER BY valid_from DESC
             LIMIT 1
            """
        ),
        {"tenant_id": str(tenant_id), "provider": provider, "at": at},
    )
    row = result.fetchone()
    return _row_to_snapshot(row) if row else None


async def snapshot_history(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    provider: str,
    limit: int = 50,
) -> list[PostureSnapshot]:
    """Versions newest first — the drift view.

    Every row here is a real posture change, because an unchanged
    re-collection extends the live row instead of writing a new one.
    """
    result = await db.execute(
        text(
            f"""
            SELECT {_COLUMNS}
              FROM posture_snapshots
             WHERE tenant_id = :tenant_id
               AND provider = :provider
             ORDER BY valid_from DESC
             LIMIT :limit
            """
        ),
        {"tenant_id": str(tenant_id), "provider": provider, "limit": max(1, min(limit, 500))},
    )
    return [_row_to_snapshot(row) for row in result.fetchall()]
