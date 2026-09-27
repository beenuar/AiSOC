"""Per-tenant autonomy policy, read from the store the product already writes.

The console lets a tenant choose their L0–L4 automation tier, plus per-action
overrides and a HIGH-blast-radius whitelist. All three persist in Postgres
(`remediation_maturity`, `remediation_whitelist`) behind
`/api/v1/remediation/config`.

The live-action dispatcher never read any of it. It resolved autonomy from a
single deployment-wide `AISOC_MATURITY_TIER` environment variable, so every
tenant in a multi-tenant install shared one posture and a tenant who chose L2
in the UI got whatever the operator had exported. `evaluate_gate` — the
function that does understand per-tenant tiers, overrides and whitelists — had
no callers and no tests anywhere in the tree.

This module closes that gap. It reads the tenant's real policy and is the
source of truth `_govern` consults.

Safety posture when the policy cannot be read:

* **No database configured** — fall back to `AISOC_MATURITY_TIER`. That is an
  explicit operator choice and the documented single-tenant behaviour.
* **Database configured but unreadable** — fall back to a conservative floor
  (L1, notify-only), never to the environment value. If we know a per-tenant
  policy exists and cannot read it, inheriting a possibly-more-permissive
  default is how an install silently auto-executes containment the tenant
  never authorised.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import structlog

from app.services.maturity import MaturityTier

logger = structlog.get_logger(__name__)

#: Tier used when a configured database cannot be read. Notify-only: the
#: platform still surfaces everything, it just does not act unilaterally.
UNREADABLE_POLICY_FLOOR = MaturityTier.L1_NOTIFY

#: Policy changes are rare and the live-action path is latency-sensitive, so a
#: short TTL keeps the common case to zero database round trips while still
#: picking up a tier change within seconds.
_CACHE_TTL_SECONDS = 30.0

_cache: dict[str, tuple[float, TenantPolicy]] = {}


@dataclass(frozen=True)
class TenantPolicy:
    """A tenant's resolved autonomy posture."""

    tier: MaturityTier
    action_overrides: dict[str, Any] = field(default_factory=dict)
    whitelist: list[dict[str, Any]] = field(default_factory=list)
    #: True when this came from the tenant's stored policy, False when it came
    #: from the environment default or the conservative floor. Surfaced in the
    #: audit trail so an operator can tell a real tenant choice from a default.
    from_store: bool = False
    source: str = "environment"
    #: Gap-closure Phase 2.3. Response verbs this tenant has *earned* the right
    #: to run unattended, keyed by verb, with the source the grant carries.
    #: Read-only here: this service enforces grants and never issues them, and
    #: keeping the write path in one place is what stops a dispatch-time
    #: convenience from turning into a second way to become autonomous.
    earned_verbs: dict[str, str] = field(default_factory=dict)

    def earned_autonomy_for(self, action_type: str) -> str | None:
        """The grant source for this verb, or ``None`` when none is held.

        Returns the *source* rather than a boolean so a caller can put the
        distinction in a rationale. "Auto-executed on a measured track record"
        and "auto-executed because somebody overruled the gate" are the same
        action and very different sentences in an incident review.
        """
        return self.earned_verbs.get(action_type)

    def is_whitelisted(self, action_type: str, target: str | None) -> bool:
        """True when an unexpired whitelist entry covers this action/target.

        `autonomy_safety.decide` accepts a `whitelisted` flag that gates the
        L4 break-glass path for HIGH-blast-radius actions. The dispatcher never
        passed it, so it was always False and that path was unreachable.
        """
        now = datetime.now(UTC)
        for entry in self.whitelist:
            if entry.get("action_type") != action_type:
                continue
            expires_at = entry.get("expires_at")
            if expires_at is not None and _as_utc(expires_at) <= now:
                continue
            constraints = entry.get("constraints") or {}
            targets = constraints.get("targets")
            # No target constraint means the entry covers the action type
            # broadly; an explicit list must actually contain this target.
            if targets and target not in targets:
                continue
            return True
        return False


def _as_utc(value: Any) -> datetime:
    """Coerce a stored timestamp to an aware UTC datetime."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def _env_tier() -> MaturityTier:
    """Deployment-wide default. Conservative when unset or unparseable."""
    raw = os.environ.get("AISOC_MATURITY_TIER", "").strip().upper()
    if not raw:
        return MaturityTier.L1_NOTIFY
    for tier in MaturityTier:
        if raw in {tier.name, tier.name.split("_")[0], str(tier.value)}:
            return tier
    logger.warning("tenant_policy.bad_tier_env", value=raw)
    return MaturityTier.L1_NOTIFY


def _dsn() -> str | None:
    """Resolve an asyncpg-compatible DSN, or None when no database is set.

    Accepts the SQLAlchemy form the API uses (`postgresql+asyncpg://`) as well
    as the plain pgx form `services/ingest` uses, because both spellings are
    already present in deployed environments.
    """
    raw = os.environ.get("DATABASE_DSN") or os.environ.get("DATABASE_URL") or ""
    raw = raw.strip()
    if not raw:
        return None
    return raw.replace("postgresql+asyncpg://", "postgresql://").replace("postgres+asyncpg://", "postgresql://")


async def _load_from_store(tenant_id: str, dsn: str) -> TenantPolicy | None:
    """Read the tenant's tier, overrides and live whitelist entries.

    Returns None when the tenant has no stored policy row, which is different
    from a read failure: a tenant who has never configured anything should get
    the deployment default, not the conservative floor.
    """
    import asyncpg  # noqa: PLC0415 — optional at import time; only needed with a DSN

    conn = await asyncpg.connect(dsn, timeout=5.0)
    try:
        row = await conn.fetchrow(
            "SELECT maturity_tier, action_overrides FROM remediation_maturity WHERE tenant_id = $1",
            UUID(tenant_id),
        )
        if row is None:
            return None
        whitelist_rows = await conn.fetch(
            """
            SELECT action_type, blast_radius, constraints, expires_at
            FROM remediation_whitelist
            WHERE tenant_id = $1 AND (expires_at IS NULL OR expires_at > now())
            """,
            UUID(tenant_id),
        )
        # Read on the same connection, before it closes. A second connection
        # for three columns would double the round trips on a latency-
        # sensitive path, and the two reads have to describe the same instant
        # anyway: a tier read before a demotion and a grant list read after it
        # would compose into a posture neither half ever held.
        earned_verbs = await _load_earned_verbs(conn, tenant_id)
    finally:
        await conn.close()

    overrides = row["action_overrides"]
    if isinstance(overrides, str):
        import json  # noqa: PLC0415 — JSONB arrives as str on some driver versions

        overrides = json.loads(overrides)

    whitelist: list[dict[str, Any]] = []
    for wl in whitelist_rows:
        constraints = wl["constraints"]
        if isinstance(constraints, str):
            import json  # noqa: PLC0415

            constraints = json.loads(constraints)
        whitelist.append(
            {
                "action_type": wl["action_type"],
                "blast_radius": wl["blast_radius"],
                "constraints": constraints or {},
                "expires_at": wl["expires_at"],
            }
        )

    return TenantPolicy(
        tier=MaturityTier(int(row["maturity_tier"])),
        action_overrides=overrides or {},
        whitelist=whitelist,
        from_store=True,
        source="tenant_policy",
        earned_verbs=earned_verbs,
    )


async def _load_earned_verbs(conn: Any, tenant_id: str) -> dict[str, str]:
    """Which response verbs this tenant has earned the right to run unattended.

    Gap-closure Phase 2.3. Only rows in the ``granted`` state count; a demoted
    grant keeps its row so the history survives, and reading it as current is
    exactly the mistake that would let a revoked capability keep executing.

    A read failure returns nothing rather than raising. That is the safe
    direction here and it is the opposite of the choice made for the tier: an
    unreadable *tier* falls back to a conservative floor because the tier
    permits, while an unreadable *grant list* simply grants nothing, so the
    caller falls back to whatever the tier alone allows. Failing loudly would
    take the dispatch path down to avoid being too cautious.
    """
    try:
        rows = await conn.fetch(
            """
            SELECT scope_key, source
            FROM aisoc_autonomy_grants
            WHERE tenant_id = $1
              AND state = 'granted'
              AND scope_kind = 'action_verb'
              AND capability = 'auto_execute'
            """,
            UUID(tenant_id),
        )
    except Exception as exc:  # noqa: BLE001 - no grant is the safe answer
        logger.warning("tenant_policy.grants_unreadable", tenant_id=tenant_id, error=str(exc)[:300])
        return {}
    return {str(row["scope_key"]): str(row["source"]) for row in rows}


async def resolve_tenant_policy(tenant_id: str | UUID | None) -> TenantPolicy:
    """Resolve the autonomy policy that governs this tenant's actions."""
    dsn = _dsn()
    if tenant_id is None or dsn is None:
        # Single-tenant or no database: the environment value is the operator's
        # explicit, documented choice.
        return TenantPolicy(tier=_env_tier(), source="environment")

    key = str(tenant_id)
    cached = _cache.get(key)
    now = time.monotonic()
    if cached is not None and now - cached[0] < _CACHE_TTL_SECONDS:
        return cached[1]

    try:
        policy = await _load_from_store(key, dsn)
    except Exception as exc:  # noqa: BLE001 — never inherit a permissive default on error
        logger.error(
            "tenant_policy.read_failed",
            tenant_id=key,
            error=str(exc),
            falling_back_to=UNREADABLE_POLICY_FLOOR.name,
        )
        return TenantPolicy(tier=UNREADABLE_POLICY_FLOOR, source="unreadable_policy_floor")

    if policy is None:
        logger.info("tenant_policy.no_row", tenant_id=key)
        policy = TenantPolicy(tier=_env_tier(), source="environment")

    _cache[key] = (now, policy)
    return policy


def clear_cache() -> None:
    """Drop the policy cache. Used by tests and after a policy update."""
    _cache.clear()
