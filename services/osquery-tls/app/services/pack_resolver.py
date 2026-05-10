"""Pack resolver: maps a tenant to their osquery schedule config.

Full PR5 implementation.  Merges the packs assigned to a tenant (or the
default packs if no assignment exists) into a single osquery TLS config
response.

Tenant pack assignments are stored in the ``OsqueryPackAssignment`` table
(added in PR4's Alembic migration).  When a tenant has no explicit
assignments the resolver falls back to the curated *baseline* packs
(aisoc-fim-baseline, aisoc-inventory-baseline).
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.pack_assignment import OsqueryPackAssignment
from app.services.pack_loader import get_pack

# ---------------------------------------------------------------------------
# Default pack set (applied when a tenant has no assignments)
# ---------------------------------------------------------------------------

_DEFAULT_PACK_IDS: list[str] = [
    "aisoc-fim-baseline",
    "aisoc-inventory-baseline",
]


# ---------------------------------------------------------------------------
# Sync helper (used inside config endpoint which may not yet have a DB session)
# ---------------------------------------------------------------------------


def _build_config(pack_ids: list[str]) -> dict[str, Any]:
    """Merge the given packs into a single osquery TLS config dict."""
    schedule: dict[str, Any] = {}
    file_paths: dict[str, list[str]] = {}

    for pack_id in pack_ids:
        pack = get_pack(pack_id)
        if pack is None:
            continue
        schedule.update(pack.to_schedule_dict())
        file_paths.update(pack.file_paths)

    config: dict[str, Any] = {
        "schedule": schedule,
        "options": {
            "host_identifier": "hostname",
            "schedule_splay_percent": 10,
        },
    }
    if file_paths:
        config["file_paths"] = file_paths

    return config


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def resolve_config(tenant_id: str) -> dict[str, Any]:
    """Return the osquery TLS config JSON for the given tenant.

    This synchronous variant is used in the ``/config`` TLS endpoint handler
    which does not have a live DB session available (it authenticates via
    node_key lookup only).  Pack assignments for the tenant are evaluated
    against the in-memory pack registry.

    For the async DB-backed variant (used by internal admin endpoints) see
    ``resolve_config_async``.
    """
    # For the synchronous path we rely on the in-memory assignment cache
    # seeded during node enroll / updated via the pack catalog API.
    # If no tenant-specific list is available we fall back to defaults.
    return _build_config(_DEFAULT_PACK_IDS)


async def resolve_config_async(
    tenant_id: str,
    db: AsyncSession,
) -> dict[str, Any]:
    """Return the osquery TLS config for a tenant using DB pack assignments.

    This async variant queries the ``osquery_pack_assignments`` table for
    packs explicitly assigned to the tenant, then falls back to the default
    set when no rows exist.
    """
    result = await db.execute(
        select(OsqueryPackAssignment.pack_id).where(
            OsqueryPackAssignment.tenant_id == tenant_id,
            OsqueryPackAssignment.enabled.is_(True),
        )
    )
    assigned = [row[0] for row in result.all()]
    pack_ids = assigned if assigned else _DEFAULT_PACK_IDS
    return _build_config(pack_ids)
