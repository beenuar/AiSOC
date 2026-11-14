"""Is the stop button pressed, read from the service that touches vendors.

Parity plan 2.2 claimed the kill switch was "checked first and separately by
everything that acts: closure in the triage worker, the actions dispatcher,
playbook dispatch and the MCP write tools". Only the first was true. Until
this module existed, ``services/actions`` contained no reference to the
switch in any form, so an operator who engaged the platform-wide stop and
watched automatic closure halt was still dispatching isolations and account
disables at their vendors.

Why a second reader rather than importing the first
---------------------------------------------------
``services/agents/app/closure/policy.py`` reads the same two rows, and this
is not that module imported. It cannot be: both services name their
top-level package ``app``, so importing one into the other shadows it. The
duplication is the same shape as ``autonomy_evidence_rules``, which
``services/api`` carries byte-identical to this service, and it carries the
same risk — a safety control two services define differently is off in
whichever one is more generous. What stops the two drifting here is that
there is nothing to drift: both ask one question of one table, "is a row
engaged for the global scope or this tenant", and the SQL below is the whole
definition.

The DSN itself is genuinely shared, from :func:`tenant_policy.resolve_dsn`,
because "does this deployment have a database" is a question the autonomy
policy and the stop button must not answer differently.

What an unreadable switch means
-------------------------------
Dispatch fails **closed**, and the trade-off is deliberate rather than
assumed. A stop control that reads "I cannot tell" as "nobody pressed it"
is not a stop control: the operator engaged it, believes the platform is
frozen, and stops looking for another way to halt it. The cost is that a
database outage stops response actions on deployments that have a database.
That cost is bounded by three things:

* a deployment with **no** DSN configured is not affected at all. No
  database means no switch table, which is a configuration, not a failure —
  the same line ``resolve_tenant_policy`` already draws, and failing closed
  there would brick every single-tenant install to guard a row that cannot
  exist on it;
* a deployment that *has* a database is already degraded by the same
  outage. ``resolve_tenant_policy`` falls to its notify-only floor on an
  unreadable read, so unattended execution has stopped regardless;
* the refusal is :class:`LiveActionStatus.BLOCKED` with a reason naming the
  read failure, not the switch. Sending an operator to look for a switch
  nobody pressed is the failure mode where a diagnostic names the wrong
  subsystem, and that is worse than a vague one.

Analysts keep working through all of it: BLOCKED is a refusal to act
automatically, not an outage of the console.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Any

import structlog

from app.services.tenant_policy import resolve_dsn

logger = structlog.get_logger(__name__)

#: Seconds a resolved switch state is reused. Short on purpose: parity 2.2
#: requires the switch to take effect "within one poll interval, without a
#: restart", and a long cache would make that untrue. Only a *successful*
#: read is cached — caching a failure would turn one refused connection into
#: several seconds of refused dispatch after the database came back.
_CACHE_TTL_ENV = "AISOC_KILL_SWITCH_TTL_SECONDS"
_DEFAULT_TTL_SECONDS = 5.0

#: Bounded, because this sits in front of every dispatch. A database that
#: hangs must become a refusal quickly rather than a dispatch that never
#: returns.
_CONNECT_TIMEOUT_SECONDS = 5.0

_cache: dict[str, tuple[float, KillSwitchState]] = {}


@dataclass(frozen=True)
class KillSwitchState:
    """Whether to refuse, and the sentence an operator will read.

    ``unreadable`` is kept distinct from ``engaged`` rather than folded into
    one boolean. Both refuse; they are not the same event, and an operator
    told the wrong one debugs the wrong thing.
    """

    engaged: bool
    scope: str = ""
    reason: str = ""
    unreadable: bool = False

    def __bool__(self) -> bool:
        return self.engaged


_RELEASED = KillSwitchState(engaged=False)


def _ttl_seconds() -> float:
    raw = os.environ.get(_CACHE_TTL_ENV, "")
    if not raw.strip():
        return _DEFAULT_TTL_SECONDS
    try:
        return max(0.0, float(raw))
    except ValueError:
        logger.warning("kill_switch.bad_ttl_env", value=raw.strip()[:32])
        return _DEFAULT_TTL_SECONDS


def reset_cache() -> None:
    """Drop the cache. For tests, and for a forced reload."""
    _cache.clear()


def _cached(key: str) -> KillSwitchState | None:
    hit = _cache.get(key)
    if hit is None:
        return None
    expires, value = hit
    if time.monotonic() >= expires:
        _cache.pop(key, None)
        return None
    return value


async def _fetch(dsn: str, tenant_id: str | None) -> list[Any]:
    import asyncpg  # noqa: PLC0415 — optional at import time; only needed with a DSN

    conn = await asyncpg.connect(dsn, timeout=_CONNECT_TIMEOUT_SECONDS)
    try:
        return list(
            await conn.fetch(
                """
                SELECT tenant_id, reason
                  FROM aisoc_kill_switch
                 WHERE engaged = TRUE
                   AND (tenant_id IS NULL OR tenant_id = $1::uuid)
                 -- Global first: when both are engaged, the platform-wide
                 -- one is the one the tenant cannot release, so naming the
                 -- tenant's would send them to a switch that changes nothing.
                 ORDER BY tenant_id NULLS FIRST
                """,
                str(tenant_id) if tenant_id is not None else None,
            )
        )
    finally:
        await conn.close()


async def kill_switch_state(tenant_id: str | None) -> KillSwitchState:
    """Whether action dispatch is frozen for this tenant, and why.

    Either scope engaged is enough to refuse: the platform operator can stop
    everything and a tenant can stop their own, and neither needs the
    other's agreement.

    A ``tenant_id`` of ``None`` still consults the global row. An action with
    no tenant on it is not an action outside the platform-wide stop.
    """
    dsn = resolve_dsn()
    if dsn is None:
        # No database is a configuration, not a read failure. See the module
        # docstring: failing closed here stops deployments that cannot have
        # a switch at all.
        return _RELEASED

    key = f"kill:{tenant_id or '-'}"
    hit = _cached(key)
    if hit is not None:
        return hit

    try:
        rows = await _fetch(dsn, tenant_id)
    except Exception as exc:  # noqa: BLE001 — a database that cannot answer is not a "no"
        logger.warning(
            "kill_switch.unreadable",
            tenant_id=str(tenant_id),
            error=str(exc)[:300],
            refusing=True,
        )
        return KillSwitchState(
            engaged=True,
            scope="unknown",
            reason="kill-switch state unreadable, refusing to dispatch",
            unreadable=True,
        )

    for row in rows:
        scope = "global" if row["tenant_id"] is None else "tenant"
        state = KillSwitchState(engaged=True, scope=scope, reason=str(row["reason"]))
        _cache[key] = (time.monotonic() + _ttl_seconds(), state)
        return state

    _cache[key] = (time.monotonic() + _ttl_seconds(), _RELEASED)
    return _RELEASED
