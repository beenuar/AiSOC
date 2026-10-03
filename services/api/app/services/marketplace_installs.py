"""Which marketplace items a tenant has installed, in Postgres.

Wave 0 of the gap-closure plan.

Install state was a module-level dict guarded by a `threading.Lock`,
under a comment saying it was "intentionally tracked in-memory per
process for now". Two consequences, and the second is the worse one:

* Every install was **lost on restart**, so a tenant's enabled content
  silently reverted on each deploy.
* On more than one replica the answer to "is this installed" depended on
  which replica answered. An operator could install an item, refresh,
  and be told it was not installed — then install it again.

`marketplace_installs` has existed since migration 056, with exactly the
columns needed and a `UNIQUE (tenant_id, item_id)` constraint, and had
no reader or writer anywhere in the repository.

Idempotency
-----------
`ON CONFLICT (tenant_id, item_id) DO UPDATE` rather than a read-then-write.
Two replicas handling a double-click cannot both insert, and the second
refreshes the recorded version instead of failing — which is what the
in-memory path did by re-reading its own dict under a lock, a guarantee
that stopped holding the moment there were two processes.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import text

logger = logging.getLogger(__name__)

__all__ = ["installed_item_ids", "record_install", "remove_install"]


async def installed_item_ids(db: Any, *, tenant_id: Any) -> list[str]:
    """Item ids this tenant has installed."""
    rows = await db.execute(
        text("SELECT item_id FROM marketplace_installs WHERE tenant_id = CAST(:t AS uuid) ORDER BY installed_at DESC").bindparams(
            t=str(tenant_id)
        )
    )
    return [r[0] for r in rows.all()]


async def record_install(
    db: Any,
    *,
    tenant_id: Any,
    item_id: str,
    item_type: str,
    version: str,
    content_sha256: str | None,
    installed_by: Any | None,
) -> tuple[datetime, bool]:
    """Record an install, returning ``(installed_at, already_installed)``.

    The sha is stored in `image_digest`, which migration 056 describes as
    "the digest the image resolved to at install time" — for on-disk
    content the equivalent is the content hash, and without it a reinstall
    after the file changed is indistinguishable from the original.
    """
    existing = await db.scalar(
        text("SELECT installed_at FROM marketplace_installs  WHERE tenant_id = CAST(:t AS uuid) AND item_id = :i").bindparams(
            t=str(tenant_id), i=item_id
        )
    )

    now = datetime.now(UTC)
    await db.execute(
        text("""
            INSERT INTO marketplace_installs
                (tenant_id, item_id, item_type, version, image_digest, installed_by, installed_at)
            VALUES (CAST(:t AS uuid), :i, :ty, :v, :d, CAST(:by AS uuid), :at)
            ON CONFLICT (tenant_id, item_id) DO UPDATE
                SET item_type = EXCLUDED.item_type,
                    version = EXCLUDED.version,
                    image_digest = EXCLUDED.image_digest,
                    installed_at = EXCLUDED.installed_at
        """).bindparams(
            t=str(tenant_id),
            i=item_id,
            ty=item_type,
            v=version or "",
            d=content_sha256,
            by=str(installed_by) if installed_by else None,
            at=now,
        )
    )
    await db.commit()
    return now, existing is not None


async def remove_install(db: Any, *, tenant_id: Any, item_id: str) -> bool:
    """Remove an install. Returns whether a row was actually removed."""
    result = await db.execute(
        text("DELETE FROM marketplace_installs WHERE tenant_id = CAST(:t AS uuid) AND item_id = :i").bindparams(t=str(tenant_id), i=item_id)
    )
    await db.commit()
    return bool(result.rowcount)
