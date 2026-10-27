"""Per-tenant, per-class closure policy, and the kill switch.

Parity plan 2.1 and 2.2.

What this replaces
------------------
Closure used a single process-wide threshold,
``AISOC_AUTO_CLOSE_THRESHOLD`` at 0.85, for every tenant and every alert
class. Two other mechanisms existed and governed nothing:

* an earned ``auto_close`` grant was read only by
  ``services/actions/app/services/tenant_policy.py``, which selects
  ``auto_execute`` on **action verbs**, so earning the grant in shadow mode
  changed nothing about closure;
* the console's per-action thresholds were read only by
  ``app.policy.guardrails``, which has no production importer at all.

Shape of the decision
---------------------
Additive, so a deployment that configures nothing behaves exactly as it did:

1. no row for the tenant, or closure not enabled for the class, means the
   process-wide threshold applies as before;
2. a row with a threshold raises or lowers the bar for that class alone;
3. ``require_grant`` additionally demands an earned ``auto_close`` grant, so
   a tenant can say "enabled, but only once shadow mode has earned it";
4. the kill switch, global or per tenant, refuses closure outright.

Order matters. The kill switch is checked **first** and separately from the
policy, because it is the thing somebody reaches for at 3am and it must not
depend on per-class rows being correct.

Failure mode
------------
This reads the database on the alert path, so it must not become a way for
a database blip to start closing alerts that policy would have held. Every
failure here is a **refusal**: an unreadable policy means no auto-close, not
a fallback to the permissive default.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Any

import structlog

from app.memory.institutional import POOL_READY, POOL_UNAVAILABLE, POOL_UNCONFIGURED

logger = structlog.get_logger()

__all__ = [
    "POOL_READY",
    "POOL_UNAVAILABLE",
    "POOL_UNCONFIGURED",
    "ClosureDecision",
    "decide",
    "kill_switch_engaged",
    "reset_cache",
    "resolve_closure_policy",
    "resolve_pool",
    "shared_pool",
]

#: Seconds a resolved policy or switch state is reused. Short, because the
#: plan requires the switch to take effect "within one poll interval,
#: without a restart", and a long cache would make that untrue.
_CACHE_TTL_SECONDS = float(os.getenv("AISOC_CLOSURE_POLICY_TTL_SECONDS", "10"))

_cache: dict[str, tuple[float, Any]] = {}

#: Reuses the institutional-memory pool rather than opening a second one.
#: Same database, same role, and the triage path already pays for that
#: connection on every alert.
_pool_factory = None


async def resolve_pool() -> tuple[Any | None, str]:
    """The pool, and why there is not one.

    The state matters more than the pool. ``None`` used to be the only
    answer, and this module read it as "nothing is configured, fall back to
    the process-wide threshold" — permissive. But ``None`` also meant "a
    database is configured and we could not reach it", which must refuse.
    Those two are now different values and the callers below branch on them.
    """
    global _pool_factory  # noqa: PLW0603
    if _pool_factory is None:
        from app.memory.institutional import connection_pool

        _pool_factory = connection_pool
    try:
        return await _pool_factory()
    except Exception as exc:  # noqa: BLE001
        logger.warning("closure.pool.unavailable", error=str(exc))
        return None, POOL_UNAVAILABLE


async def shared_pool() -> Any | None:
    """The pool this package reads, for callers that need their own query.

    Exported rather than left private, so a caller does not reach through
    the package into a name the type checker refuses and a refactor can
    silently move.
    """
    pool, _ = await resolve_pool()
    return pool


async def decide(
    *,
    tenant_id: str | None,
    alert_class: str | None,
    confidence: float,
    default_threshold: float,
) -> ClosureDecision:
    """The call the triage path makes. Resolves its own pool."""
    pool, state = await resolve_pool()
    return await resolve_closure_policy(
        pool,
        tenant_id=tenant_id,
        alert_class=alert_class,
        confidence=confidence,
        default_threshold=default_threshold,
        pool_state=state,
    )


def reset_cache() -> None:
    """Drop the cache. For tests, and for a forced reload."""
    _cache.clear()


@dataclass(frozen=True)
class ClosureDecision:
    """Whether this alert may be auto-closed, and why."""

    allowed: bool
    threshold: float
    #: Written into the ledger and the alert's findings. An operator asking
    #: "why was this not closed" gets an answer rather than silence.
    reason: str
    source: str = "default"

    def __bool__(self) -> bool:
        return self.allowed


def _cached(key: str) -> Any | None:
    hit = _cache.get(key)
    if hit is None:
        return None
    expires, value = hit
    if time.monotonic() >= expires:
        _cache.pop(key, None)
        return None
    return value


def _store(key: str, value: Any) -> None:
    _cache[key] = (time.monotonic() + _CACHE_TTL_SECONDS, value)


async def kill_switch_engaged(
    pool: Any,
    tenant_id: str | None,
    *,
    pool_state: str = POOL_READY,
) -> tuple[bool, str]:
    """Whether closure and dispatch are frozen, and the reason.

    Checks the global row and the tenant's row. Either engaged is enough:
    the platform operator can stop everything, and a tenant can stop their
    own, and neither needs the other's agreement.

    ``pool_state`` exists because ``pool is None`` returned ``(False, "")``
    here — the switch reporting itself *not engaged* on a database it could
    not read. A stop control that answers "no" when it cannot answer at all
    is worse than one that is missing, because an operator who pressed it
    believes it took effect.
    """
    key = f"kill:{tenant_id or '-'}"
    hit = _cached(key)
    if hit is not None:
        return hit

    if pool is None:
        if pool_state == POOL_UNCONFIGURED:
            # No database anywhere, so there is no switch and nothing durable
            # to close either. Not cached: a deployment that gains a database
            # must not keep answering from before it had one.
            return (False, "")
        return (True, "__unreadable__:kill-switch state unreadable, refusing to auto-close")

    try:
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT tenant_id, engaged, reason
                  FROM aisoc_kill_switch
                 WHERE engaged = TRUE
                   AND (tenant_id IS NULL OR tenant_id = $1::uuid)
                """,
                tenant_id,
            )
    except Exception as exc:  # noqa: BLE001
        # Refuse, do not permit. A database that cannot answer "is the stop
        # button pressed" must not be read as "no".
        logger.warning("closure.kill_switch.unreadable", error=str(exc), tenant_id=tenant_id)
        # Refuses, but says *why* it refused. Reporting this as "kill switch
        # engaged" would send an operator to look for a switch nobody
        # pressed, which is the failure mode where a diagnostic names the
        # wrong subsystem and is worse than a vague one.
        return (True, "__unreadable__:kill-switch state unreadable, refusing to auto-close")

    for row in rows:
        scope = "global" if row["tenant_id"] is None else "tenant"
        result = (True, f"kill switch engaged ({scope}): {row['reason']}")
        _store(key, result)
        return result

    result = (False, "")
    _store(key, result)
    return result


async def resolve_closure_policy(
    pool: Any,
    *,
    tenant_id: str | None,
    alert_class: str | None,
    confidence: float,
    default_threshold: float,
    pool_state: str = POOL_READY,
) -> ClosureDecision:
    """Decide whether this verdict may close the alert without a human."""
    engaged, why = await kill_switch_engaged(pool, tenant_id, pool_state=pool_state)
    if engaged:
        if why.startswith("__unreadable__:"):
            return ClosureDecision(False, default_threshold, why.split(":", 1)[1], source="error")
        return ClosureDecision(False, default_threshold, why, source="kill_switch")

    if pool is None:
        # Reached only for POOL_UNCONFIGURED; the unavailable case already
        # refused above, through the switch. Either way there is no recorded
        # authorization to read, and automatic closure requires one.
        return ClosureDecision(
            False,
            default_threshold,
            "no closure policy store is configured, so no tenant has authorized automatic closure",
            source="default_deny",
        )

    if not tenant_id:
        # A closure that cannot be attributed to a tenant cannot be
        # authorized by one. This used to fall through to the process-wide
        # threshold, which authorized it on behalf of nobody.
        return ClosureDecision(
            False,
            default_threshold,
            "no tenant on this verdict, so no policy can authorize closing it",
            source="default_deny",
        )

    key = f"policy:{tenant_id}:{alert_class or '-'}"
    row = _cached(key)
    if row is None:
        try:
            async with pool.acquire() as conn:
                row = await conn.fetchrow(
                    """
                    SELECT enabled, threshold, require_grant, alert_class
                      FROM aisoc_closure_policies
                     WHERE tenant_id = $1::uuid
                       AND (alert_class = $2 OR alert_class IS NULL)
                     -- The class-specific row wins over the tenant default.
                     ORDER BY alert_class NULLS LAST
                     LIMIT 1
                    """,
                    tenant_id,
                    alert_class,
                )
        except Exception as exc:  # noqa: BLE001
            logger.warning("closure.policy.unreadable", error=str(exc), tenant_id=tenant_id)
            return ClosureDecision(
                False,
                default_threshold,
                "closure policy unreadable, refusing to auto-close",
                source="error",
            )
        _store(key, row if row is not None else False)
    elif row is False:
        row = None

    if row is None:
        # No policy configured, and that is not consent.
        #
        # This used to apply the process-wide threshold, so every tenant
        # auto-closed from the first confident benign verdict — including one
        # that had never opened the screen. The absence of a row is the
        # absence of a decision, and inferring authorization from it is
        # exactly what this phase exists to stop. Nothing is inferred from a
        # tenant's history either: a tenant that was auto-closing yesterday
        # because of this default is not thereby authorized today.
        #
        # Migration 122 records, per tenant, which side of this change each
        # deployment fell on, so an operator can see who is affected and
        # re-authorize deliberately rather than discovering it from a queue
        # that stopped draining.
        return ClosureDecision(
            False,
            default_threshold,
            f"{alert_class or 'this tenant'} has no closure policy, and automatic closure requires an explicit one",
            source="default_deny",
        )

    if not row["enabled"]:
        return ClosureDecision(
            False,
            default_threshold,
            f"auto-close disabled for {alert_class or 'this tenant'} by policy",
            source="policy",
        )

    threshold = row["threshold"] if row["threshold"] is not None else default_threshold

    if row["require_grant"]:
        granted = await _has_auto_close_grant(pool, tenant_id=tenant_id, alert_class=alert_class)
        if not granted:
            return ClosureDecision(
                False,
                threshold,
                f"policy requires an earned auto_close grant for {alert_class or 'this class'}, and none is held",
                source="policy",
            )

    allowed = confidence >= threshold
    return ClosureDecision(
        allowed,
        threshold,
        f"tenant policy threshold {threshold:.2f} for {alert_class or 'default'}",
        source="policy",
    )


async def _has_auto_close_grant(pool: Any, *, tenant_id: str, alert_class: str | None) -> bool:
    """Whether shadow mode has earned an `auto_close` grant for this class.

    This is the reader that did not exist. The grant was written and earned
    and `apps/docs/docs/operations/shadow-mode.md` described it as letting
    the agent close alerts of that class, which parity 1.1 had to retract
    because nothing consulted it.

    Then the reader was written against the wrong table. It named
    `autonomy_grants`, which migration 067 spells `aisoc_autonomy_grants`, and
    filtered on `revoked_at` and `expires_at`, which that table does not have:
    its lifecycle is the `state` column, one of `shadow`, `granted` or
    `demoted`. Three names wrong in one statement, and because
    `require_grant` defaults to true, the effect was that a tenant which
    enabled a closure policy could never auto-close anything. The feature was
    off for exactly the tenants who turned it on.

    The `except` below is what made it invisible: it logged at warning and
    returned `False`, which is indistinguishable from "this tenant has not
    earned a grant". It stays, because a database blip must not close alerts,
    but the live suite now asserts the query itself works.
    """
    try:
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT 1
                  FROM aisoc_autonomy_grants
                 WHERE tenant_id = $1::uuid
                   AND capability = 'auto_close'
                   AND scope_kind = 'alert_class'
                   AND ($2::text IS NULL OR scope_key = $2)
                   AND state = 'granted'
                 LIMIT 1
                """,
                tenant_id,
                alert_class,
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning("closure.grant.unreadable", error=str(exc), tenant_id=tenant_id)
        return False
    return row is not None
