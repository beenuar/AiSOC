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

logger = structlog.get_logger()

#: Seconds a resolved policy or switch state is reused. Short, because the
#: plan requires the switch to take effect "within one poll interval,
#: without a restart", and a long cache would make that untrue.
_CACHE_TTL_SECONDS = float(os.getenv("AISOC_CLOSURE_POLICY_TTL_SECONDS", "10"))

_cache: dict[str, tuple[float, Any]] = {}

#: Reuses the institutional-memory pool rather than opening a second one.
#: Same database, same role, and the triage path already pays for that
#: connection on every alert.
_pool_factory = None


async def _pool() -> Any | None:
    global _pool_factory  # noqa: PLW0603
    if _pool_factory is None:
        from app.memory.institutional import _get_pool

        _pool_factory = _get_pool
    try:
        return await _pool_factory()
    except Exception as exc:  # noqa: BLE001
        logger.warning("closure.pool.unavailable", error=str(exc))
        return None


async def decide(
    *,
    tenant_id: str | None,
    alert_class: str | None,
    confidence: float,
    default_threshold: float,
) -> ClosureDecision:
    """The call the triage path makes. Resolves its own pool."""
    return await resolve_closure_policy(
        await _pool(),
        tenant_id=tenant_id,
        alert_class=alert_class,
        confidence=confidence,
        default_threshold=default_threshold,
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


async def kill_switch_engaged(pool: Any, tenant_id: str | None) -> tuple[bool, str]:
    """Whether closure and dispatch are frozen, and the reason.

    Checks the global row and the tenant's row. Either engaged is enough:
    the platform operator can stop everything, and a tenant can stop their
    own, and neither needs the other's agreement.
    """
    key = f"kill:{tenant_id or '-'}"
    hit = _cached(key)
    if hit is not None:
        return hit

    if pool is None:
        return (False, "")

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
) -> ClosureDecision:
    """Decide whether this verdict may close the alert without a human."""
    engaged, why = await kill_switch_engaged(pool, tenant_id)
    if engaged:
        if why.startswith("__unreadable__:"):
            return ClosureDecision(False, default_threshold, why.split(":", 1)[1], source="error")
        return ClosureDecision(False, default_threshold, why, source="kill_switch")

    if pool is None or not tenant_id:
        # No database and no tenant: the process-wide threshold, exactly as
        # before this module existed.
        allowed = confidence >= default_threshold
        return ClosureDecision(
            allowed,
            default_threshold,
            f"process-wide threshold {default_threshold:.2f}",
            source="env",
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
        # No policy configured. Additive: behave as before.
        allowed = confidence >= default_threshold
        return ClosureDecision(
            allowed,
            default_threshold,
            f"no tenant policy, process-wide threshold {default_threshold:.2f}",
            source="env",
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
    """
    try:
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT 1
                  FROM autonomy_grants
                 WHERE tenant_id = $1::uuid
                   AND capability = 'auto_close'
                   AND scope_kind = 'alert_class'
                   AND ($2::text IS NULL OR scope_key = $2)
                   AND revoked_at IS NULL
                   AND (expires_at IS NULL OR expires_at > NOW())
                 LIMIT 1
                """,
                tenant_id,
                alert_class,
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning("closure.grant.unreadable", error=str(exc), tenant_id=tenant_id)
        return False
    return row is not None
