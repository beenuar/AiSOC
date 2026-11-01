"""Fuse-time privilege stamp — what could the actor do *when it acted*?

Depth plan wave 2, Phase 1.1. The sibling of ``asset_context.py``: the alert
landed on something (that file) and was caused by somebody (this one).

Why a Postgres read and not a resolver call
-------------------------------------------
The resolver lives in ``services/api`` and takes an estate-sized policy
document. Running it per event is not an option on fusion's hot path, and
importing it is not an option at all — both services name their top-level
package ``app``, so importing one in a process shadows the other.

So the API derives a small row per principal once per posture version
(``identity_privilege_facts``, migration 124) and fusion reads it the way
``AssetContextResolver`` reads ``assets``: one indexed query, a short TTL
cache, and never an exception out of the hot path.

The point-in-time read is the whole feature
-------------------------------------------
The lookup is bounded by the **event's** timestamp, not ``now()``. An alert
is fused seconds after the event but triaged minutes to days later, and a
role revoked in between is exactly the case the posture table is versioned
for. A stamp that read the live row would answer "what can this identity do"
on a surface labelled "what could it do", which is the worse failure of the
two because the number looks right.

Unknown is a stamp, not a missing stamp
---------------------------------------
When no fact covers the event time the stamp is still written, with
``tier: "unknown"`` and all four tags ``None``. Writing nothing would make
the scorer's factor read like an absent signal, and an operator could not
tell "this account is ordinary" from "we have never collected this
provider's posture" — which is the difference between a quiet alert and a
blind spot.
"""

from __future__ import annotations

import os
import time
from datetime import datetime
from typing import Any

import structlog

from app.models.alert import RawAlert

logger = structlog.get_logger()

#: Shorter than the asset cache's 300 s. Posture changes on human timescales
#: too, but a privilege *grant* is the event an attacker creates and then
#: uses, so the window in which fusion would stamp the pre-grant tier is the
#: one worth keeping small.
_CACHE_TTL_SECONDS = 120.0
_QUERY_TIMEOUT_SECONDS = 2.0

#: The key fusion writes into ``fused.enrichments``. The confidence scorer
#: and the API's queue both read it by this name; there is no second spelling.
STAMP_KEY = "identity_privilege"

UNKNOWN_STAMP: dict[str, Any] = {
    "tier": "unknown",
    "measured": False,
    "tags": {"can_escalate": None, "data_access": None, "third_party": None, "cross_account": None},
    "tags_set": [],
    "reason": "no posture snapshot covers this event time for this principal",
}


def _asyncpg_dsn(url: str) -> str:
    return url.replace("postgresql+asyncpg://", "postgresql://", 1)


class IdentityPrivilegeResolver:
    """Resolve an alert's actor to the privilege it held at event time."""

    def __init__(self, database_url: str | None = None) -> None:
        url = (database_url or os.getenv("DATABASE_URL") or "").strip()
        self._dsn = _asyncpg_dsn(url) if url else ""
        self._pool: Any = None
        self._cache: dict[tuple[str, str, str], tuple[float, dict[str, Any]]] = {}

    @property
    def configured(self) -> bool:
        return bool(self._dsn)

    async def _ensure_pool(self) -> Any:
        if self._pool is None:
            import asyncpg  # noqa: PLC0415 — optional at import time

            self._pool = await asyncpg.create_pool(self._dsn, min_size=0, max_size=2, timeout=_QUERY_TIMEOUT_SECONDS)
        return self._pool

    async def close(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None

    async def resolve(self, alert: RawAlert) -> dict[str, Any]:
        """The privilege stamp for this alert. Never raises, never ``None``.

        Returns :data:`UNKNOWN_STAMP` for every reason it cannot answer — no
        actor on the alert, no database, no fact covering the time. The
        caller always writes the stamp, so "unknown" reaches the scorer and
        the queue as a value rather than as an absence.
        """
        principal = (alert.username or "").strip()
        if not principal or not self._dsn:
            return dict(UNKNOWN_STAMP)

        at = alert.timestamp or datetime.now(tz=_utc())
        # Bucketed to the minute so two alerts a second apart share a cache
        # entry. Posture intervals are hours to days long, so a minute of
        # granularity cannot select a different version in any case the
        # feature is for.
        bucket = at.replace(second=0, microsecond=0).isoformat()
        key = (str(alert.tenant_id), principal.lower(), bucket)

        now = time.monotonic()
        cached = self._cache.get(key)
        if cached is not None and now - cached[0] < _CACHE_TTL_SECONDS:
            return dict(cached[1])

        try:
            pool = await self._ensure_pool()
            row = await pool.fetchrow(
                """
                SELECT provider, principal_id, tier,
                       can_escalate, data_access, third_party, cross_account,
                       action_count, partial_source, valid_from
                  FROM identity_privilege_facts
                 WHERE tenant_id = $1
                   AND valid_from <= $2
                   AND (valid_until IS NULL OR valid_until > $2)
                   AND (principal_id = $3 OR lower(principal_label) = lower($3))
                 ORDER BY array_position(
                            ARRAY['unknown','standard','elevated','admin','domain_admin']::text[], tier
                          ) DESC,
                          valid_from DESC
                 LIMIT 1
                """,
                alert.tenant_id,
                at,
                principal,
                timeout=_QUERY_TIMEOUT_SECONDS,
            )
        except Exception as exc:  # noqa: BLE001 — never block fusion on posture
            logger.warning("identity_privilege.resolve_failed", error=str(exc))
            # Deliberately not cached. An outage would otherwise pin every
            # alert for this principal to "unknown" for the whole TTL, long
            # after the database came back.
            return dict(UNKNOWN_STAMP)

        stamp = _row_to_stamp(row) if row is not None else dict(UNKNOWN_STAMP)
        self._cache[key] = (now, stamp)
        return dict(stamp)


def _utc():  # noqa: ANN202 — tiny shim, typing it adds nothing
    from datetime import UTC  # noqa: PLC0415

    return UTC


def _row_to_stamp(row: Any) -> dict[str, Any]:
    tags = {
        "can_escalate": row["can_escalate"],
        "data_access": row["data_access"],
        "third_party": row["third_party"],
        "cross_account": row["cross_account"],
    }
    stamp: dict[str, Any] = {
        "tier": str(row["tier"] or "unknown"),
        # A stored row whose tier is 'unknown' is still a measured absence —
        # the provider was collected and this principal was not in it — which
        # is a different fact from never having collected. Both render as
        # unknown; only this one has a snapshot behind it.
        "measured": True,
        "provider": row["provider"],
        "principal_id": row["principal_id"],
        "tags": tags,
        "tags_set": [name for name, value in tags.items() if value is True],
        "action_count": int(row["action_count"] or 0),
        "snapshot_partial": bool(row["partial_source"]),
        "valid_from": row["valid_from"].isoformat() if row["valid_from"] else None,
    }
    if stamp["snapshot_partial"]:
        stamp["reason"] = "the posture snapshot behind this tier was incomplete; the real reach may be larger"
    return stamp
