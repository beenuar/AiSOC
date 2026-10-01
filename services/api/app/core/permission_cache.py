"""One permission model, read from the database, cached per replica.

The problem
-----------
Two permission models shipped side by side. 275 route dependencies called
the **synchronous** `require_permission`, which consults the hardcoded
`ROLE_PERMISSIONS` map in `app/core/security.py`; 27 called the **async**
`require_permission_db`, which consults the `user_roles` /
`role_permissions` tables. The console has a full RBAC administration
surface writing to those tables, so an operator could grant a permission,
watch it appear in the UI, and have 275 of 302 routes ignore it entirely.

The fix is not to edit 275 call sites. It is to make the one factory they
all already call read from the database, which changes every site at once
and leaves no second model to drift.

The fallback, and why its old shape was wrong
---------------------------------------------
`has_permission_db` fell back to the static map whenever a user had no rows
in `user_roles`. That is right for bootstrap — a fresh tenant has no RBAC
configured and must still work — and wrong for deprovisioning: **removing
every role from a user restored their static permissions** rather than
removing their access. The two cases look identical from the user's row
count alone, and the distinguishing fact is one level up: does the *tenant*
have any roles at all?

* tenant has no roles configured → static map (bootstrap, nothing to read)
* tenant has roles, this user has none → **deny** (they were deprovisioned)
* tenant has roles, this user has some → those, and only those

The cache
---------
A permission check on every request would mean a four-table join on every
request. Resolved sets are cached per replica, keyed by
`(tenant_id, user_id, version)`.

`version` is the point. A TTL alone means a revoked permission keeps
working for the length of the TTL on every replica that has it cached,
which for an access revocation is the wrong failure mode. The version is a
per-tenant counter in Redis, bumped whenever a grant changes, so a revoke
invalidates **every** replica on its next request rather than when their
clocks happen to expire.

Without Redis the version is unavailable and the cache falls back to a
short TTL, which is honest about what it can offer: a single-process
deployment is correct either way, and a multi-replica one without Redis
converges within the TTL. That degradation is logged once, not silently.
"""

from __future__ import annotations

import logging
import time
from functools import lru_cache
from dataclasses import dataclass, field
from typing import Any, Final

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger("aisoc.permissions")

#: How long a resolved set survives when no version counter is reachable.
#: Short, because this is the window in which a revoked permission still
#: works on a replica that has not noticed.
FALLBACK_TTL_SECONDS: Final[float] = 15.0

#: Bound on the number of cached principals per replica. A SOC has far
#: fewer concurrent operators than this; the cap exists so an attacker
#: cycling user ids cannot grow the map without limit.
MAX_ENTRIES: Final[int] = 4096

_REDIS_VERSION_KEY: Final[str] = "aisoc:rbac:version:{tenant_id}"


@dataclass
class _Entry:
    permissions: frozenset[str]
    version: str
    expires_at: float


@dataclass
class PermissionCache:
    """Per-replica cache of resolved permission sets."""

    _entries: dict[tuple[str, str], _Entry] = field(default_factory=dict)
    _warned_no_redis: bool = False

    hits: int = 0
    misses: int = 0

    def get(self, *, tenant_id: str, user_id: str, version: str) -> frozenset[str] | None:
        entry = self._entries.get((tenant_id, user_id))
        if entry is None:
            self.misses += 1
            return None
        # A version mismatch beats a live TTL: a grant changed, so whatever
        # is cached describes the world before that change.
        if entry.version != version or entry.expires_at <= time.monotonic():
            self._entries.pop((tenant_id, user_id), None)
            self.misses += 1
            return None
        self.hits += 1
        return entry.permissions

    def put(self, *, tenant_id: str, user_id: str, version: str, permissions: frozenset[str]) -> None:
        if len(self._entries) >= MAX_ENTRIES:
            # Oldest by expiry. Not an LRU: this bound is a safety valve for
            # a pathological key space, not a hot-path eviction policy, and
            # an LRU here would add bookkeeping to every read.
            oldest = min(self._entries, key=lambda k: self._entries[k].expires_at)
            self._entries.pop(oldest, None)
        self._entries[(tenant_id, user_id)] = _Entry(
            permissions=permissions,
            version=version,
            expires_at=time.monotonic() + FALLBACK_TTL_SECONDS,
        )

    def invalidate_tenant(self, tenant_id: str) -> int:
        """Drop this replica's entries for one tenant.

        Local only. Cross-replica invalidation is the version counter, not
        this — a method that dropped local entries and called itself
        "invalidation" would be the kind of control that looks complete and
        covers one process out of N.
        """
        doomed = [k for k in self._entries if k[0] == tenant_id]
        for key in doomed:
            self._entries.pop(key, None)
        return len(doomed)

    def clear(self) -> None:
        self._entries.clear()
        self.hits = 0
        self.misses = 0


#: Process-wide instance. One per replica by construction.
CACHE = PermissionCache()


@lru_cache(maxsize=1)
def _redis_client() -> Any | None:
    """Built once and reused.

    `from_url` is lazy, so this costs nothing until the first command, and
    rebuilding it per call would open a connection per permission check.

    Memoised rather than held in a pair of module globals. The first draft
    used `_CLIENT` plus a `_CLIENT_TRIED` flag to distinguish "no client"
    from "not asked yet", which CodeQL correctly flagged as a global whose
    only job was bookkeeping the cache already does — `lru_cache` caches a
    `None` return just as happily as a client.
    """
    try:
        from redis.asyncio import from_url  # noqa: PLC0415

        from app.core.config import settings  # noqa: PLC0415

        return from_url(str(settings.REDIS_URL), decode_responses=True)
    except Exception:  # noqa: BLE001 - absence is a supported configuration
        return None


def reset_for_tests() -> None:
    """Drop the cache and the client handle. Tests only."""
    _redis_client.cache_clear()
    CACHE.clear()
    CACHE._warned_no_redis = False


async def current_version(tenant_id: str) -> str:
    """The tenant's RBAC generation, or a TTL-only sentinel.

    Returning a constant when Redis is absent is deliberate: every entry
    then shares one version and expiry alone governs them, which is the
    documented degradation rather than a silent one.
    """
    client = _redis_client()
    if client is None:
        if not CACHE._warned_no_redis:
            CACHE._warned_no_redis = True
            logger.warning(
                "permission cache: no Redis, so a permission change reaches other replicas "
                "only after the %.0fs TTL rather than on their next request",
                FALLBACK_TTL_SECONDS,
            )
        return "ttl-only"
    try:
        raw = await client.get(_REDIS_VERSION_KEY.format(tenant_id=tenant_id))
        return (raw.decode() if isinstance(raw, bytes) else str(raw)) if raw else "0"
    except Exception:  # noqa: BLE001 - a Redis blip must not deny a request
        return "ttl-only"


async def bump_version(tenant_id: str) -> None:
    """Invalidate this tenant's cached permissions on every replica.

    Called after any write to `user_roles` or `role_permissions`. Failing
    soft on a Redis error is correct here and only here: the TTL still
    bounds the staleness, and refusing the *grant* because the cache could
    not be invalidated would make RBAC administration depend on Redis.
    """
    client = _redis_client()
    if client is None:
        CACHE.invalidate_tenant(tenant_id)
        return
    try:
        await client.incr(_REDIS_VERSION_KEY.format(tenant_id=tenant_id))
    except Exception as exc:  # noqa: BLE001
        logger.warning("permission cache: could not bump the RBAC version: %s", exc)
    CACHE.invalidate_tenant(tenant_id)


async def _tenant_has_rbac(db: AsyncSession, tenant_id: Any) -> bool:
    """Whether this tenant has configured any roles at all.

    The fact that separates bootstrap from deprovisioning, and the reason
    the old fallback was unsafe.
    """
    from app.models.rbac import Role  # noqa: PLC0415

    total = await db.scalar(select(func.count()).select_from(Role).where(Role.tenant_id == tenant_id))
    return bool(total)


async def resolve_permissions(db: AsyncSession, *, tenant_id: Any, user_id: Any, static_role: str) -> frozenset[str]:
    """This principal's effective permissions, database first.

    `static_role` is consulted only on the bootstrap path, where the tenant
    has no roles for the database to answer with.
    """
    from app.core.security import ROLE_PERMISSIONS  # noqa: PLC0415
    from app.models.rbac import Permission as PermModel  # noqa: PLC0415
    from app.models.rbac import Role, RolePermission, UserRole  # noqa: PLC0415

    tenant_key, user_key = str(tenant_id), str(user_id)
    version = await current_version(tenant_key)
    cached = CACHE.get(tenant_id=tenant_key, user_id=user_key, version=version)
    if cached is not None:
        return cached

    rows = await db.execute(
        select(PermModel.name)
        .join(RolePermission, RolePermission.permission_id == PermModel.id)
        .join(Role, Role.id == RolePermission.role_id)
        .join(UserRole, UserRole.role_id == Role.id)
        .where(UserRole.user_id == user_id, Role.tenant_id == tenant_id)
    )
    granted = {row[0] for row in rows.all()}

    if not granted and not await _tenant_has_rbac(db, tenant_id):
        # Bootstrap: nothing to read, so the static map is the only answer
        # there is. A tenant that *has* roles and gave this user none has
        # answered the question — with "none".
        granted = set(ROLE_PERMISSIONS.get(static_role, []))

    resolved = frozenset(granted)
    CACHE.put(tenant_id=tenant_key, user_id=user_key, version=version, permissions=resolved)
    return resolved


def grants(permissions: frozenset[str], wanted: str) -> bool:
    """Whether a resolved set covers *wanted*, including wildcards."""
    return "*" in permissions or wanted in permissions or f"{wanted.split(':')[0]}:*" in permissions
