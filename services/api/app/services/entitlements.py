"""Per-tenant limits, and how much room is left under them.

A managed provider's most expensive failure is a quiet one. A tenant that
hits a cap does not raise an error anyone sees: alerts keep arriving and
simply stop being triaged, and the customer reports it as "the AI doesn't
work". Somebody then spends a day debugging a model that was never invoked.
So the point of this module is not enforcement — it is making exhaustion
*visible*, per tenant, across a whole portfolio, before anyone phones in.

Two rules govern the numbers it produces.

**Limits are only those an operator configured.** AiSOC ships uncapped. A
tenant with nothing in `tenants.limits` and no deployment default reports
``unlimited``, not a made-up ceiling — a headroom bar drawn against an
invented cap is a fabricated metric, and inventing one here would put a
fabrication on every tenant row in the portfolio view.

**Usage is measured, never estimated.** Every key below maps to a real
count over real rows. A key that cannot be counted honestly does not appear.

`tenants.limits` is a JSONB per-tenant override that wins over the
deployment default. The string ``"unlimited"`` and the integer ``-1`` both
mean no limit, matching what operators already write there.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Final

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings

logger = logging.getLogger("aisoc.entitlements")

# Values that mean "no ceiling", in the forms operators actually write.
_UNLIMITED: Final[frozenset[object]] = frozenset({-1, "-1", "unlimited", "none", ""})

# Fraction of a limit at which a tenant is called `warning` rather than `ok`.
WARN_AT: Final[float] = 0.8


@dataclass(frozen=True)
class LimitKey:
    """A measurable entitlement.

    ``usage_sql`` counts current usage for one tenant and must bind the
    tenant as a parameter — never format it into the string.
    """

    name: str
    label: str
    description: str
    usage_sql: str


LIMIT_KEYS: Final[tuple[LimitKey, ...]] = (
    LimitKey(
        "connectors",
        "Connectors",
        "Enabled data sources.",
        "SELECT count(*) FROM connectors WHERE tenant_id = :tenant_id AND is_enabled",
    ),
    LimitKey(
        "seats",
        "Seats",
        "Active user accounts.",
        "SELECT count(*) FROM users WHERE tenant_id = :tenant_id AND is_active",
    ),
    LimitKey(
        "alerts_per_day",
        "Alerts / day",
        "Alerts created in the trailing 24 hours.",
        "SELECT count(*) FROM alerts WHERE tenant_id = :tenant_id AND created_at >= :since",
    ),
    LimitKey(
        # Counted as alerts that carry AI output, because that is the row a
        # triage actually writes. There is no usage-metering table in this
        # build, and inventing a number for one would be worse than counting
        # the evidence that a triage happened.
        "triages_per_month",
        "AI triages / month",
        "Alerts with AI triage output this calendar month.",
        (
            "SELECT count(*) FROM alerts "
            "WHERE tenant_id = :tenant_id AND created_at >= :month_start "
            "AND (ai_summary IS NOT NULL OR ai_score IS NOT NULL)"
        ),
    ),
)

LIMIT_KEYS_BY_NAME: Final[dict[str, LimitKey]] = {k.name: k for k in LIMIT_KEYS}


@dataclass(frozen=True)
class Headroom:
    """How much of one limit a tenant has left.

    ``limit is None`` means uncapped; ``remaining`` and ``pct_used`` are then
    ``None`` too rather than a sentinel that a chart would plot.
    """

    key: str
    label: str
    used: int
    limit: int | None
    state: str  # unlimited | ok | warning | exhausted

    @property
    def remaining(self) -> int | None:
        if self.limit is None:
            return None
        return max(self.limit - self.used, 0)

    @property
    def pct_used(self) -> float | None:
        if self.limit is None or self.limit <= 0:
            return None
        return round(min(self.used / self.limit, 1.0) * 100, 1)

    def as_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "label": self.label,
            "used": self.used,
            "limit": self.limit,
            "remaining": self.remaining,
            "pct_used": self.pct_used,
            "state": self.state,
        }


def _coerce_limit(raw: object) -> int | None:
    """Normalise one configured value to an int ceiling, or ``None``."""
    if raw is None:
        return None
    if isinstance(raw, bool):
        return None
    if isinstance(raw, str):
        stripped = raw.strip().lower()
        if stripped in _UNLIMITED:
            return None
        try:
            raw = int(stripped)
        except ValueError:
            return None
    if isinstance(raw, int | float):
        value = int(raw)
        return None if value < 0 else value
    return None


def _deployment_defaults() -> dict[str, object]:
    """Deployment-wide caps, if the operator set any.

    Empty by default: an open-source install has no plan and no ceiling
    until someone chooses one.
    """
    configured = getattr(settings, "AISOC_DEFAULT_TENANT_LIMITS", None) or {}
    return configured if isinstance(configured, dict) else {}


def limit_for(tenant_limits: dict | None, key: str) -> int | None:
    """The effective ceiling for ``key``, or ``None`` when uncapped.

    The per-tenant override in `tenants.limits` wins over the deployment
    default, including when it raises the ceiling — that is the mechanism for
    sizing one customer differently without editing a shared config.
    """
    overrides = tenant_limits if isinstance(tenant_limits, dict) else {}
    if key in overrides:
        return _coerce_limit(overrides[key])
    defaults = _deployment_defaults()
    if key in defaults:
        return _coerce_limit(defaults[key])
    return None


def classify(used: int, limit: int | None) -> str:
    if limit is None:
        return "unlimited"
    if limit <= 0:
        # A configured ceiling of zero is a real state: the feature is off.
        return "exhausted"
    if used >= limit:
        return "exhausted"
    if used >= limit * WARN_AT:
        return "warning"
    return "ok"


async def measure_usage(db: AsyncSession, tenant_id: uuid.UUID) -> dict[str, int]:
    """Count current usage of every limit key for one tenant."""
    now = datetime.now(UTC)
    params = {
        "tenant_id": str(tenant_id),
        "since": now - timedelta(hours=24),
        "month_start": now.replace(day=1, hour=0, minute=0, second=0, microsecond=0),
    }
    usage: dict[str, int] = {}
    for key in LIMIT_KEYS:
        bound = {name: value for name, value in params.items() if f":{name}" in key.usage_sql}
        result = await db.execute(text(key.usage_sql), bound)
        usage[key.name] = int(result.scalar_one() or 0)
    return usage


async def headroom_for_tenant(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    tenant_limits: dict | None,
) -> list[Headroom]:
    """Per-key headroom for one tenant, with exhaustion logged loudly."""
    usage = await measure_usage(db, tenant_id)
    rows: list[Headroom] = []
    for key in LIMIT_KEYS:
        used = usage.get(key.name, 0)
        limit = limit_for(tenant_limits, key.name)
        state = classify(used, limit)
        if state == "exhausted":
            # A cap silently stopping work is the failure this module exists
            # to prevent, so it is never quieter than a warning.
            logger.warning(
                "entitlements.limit_exhausted tenant=%s key=%s used=%d limit=%s",
                tenant_id,
                key.name,
                used,
                limit,
            )
        rows.append(Headroom(key=key.name, label=key.label, used=used, limit=limit, state=state))
    return rows
