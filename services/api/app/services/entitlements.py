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

from sqlalchemy import DateTime, Uuid, bindparam, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.services.usage_metering import MODEL_RUNS

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
        # Counted from the run, not from the alert, and kept byte-identical
        # in intent to `usage_metering.triages_model` — a usage screen and a
        # quota screen that define "a triage" separately are two surfaces
        # that will eventually disagree in front of a customer.
        #
        # It used to read `alerts.ai_summary IS NOT NULL OR ai_score IS NOT
        # NULL`, and the deterministic triage path writes both of those, so
        # a tenant on a deployment with no model configured burned their
        # whole AI-triage quota on triages no model performed. That is the
        # expensive direction: the cap does not fail loudly, it just stops
        # triaging, and the customer reports it as "the AI doesn't work".
        "triages_per_month",
        "AI triages / month",
        "Auto-triage runs that reached a model this calendar month.",
        (
            "SELECT count(*) FROM investigation_runs "
            "WHERE tenant_id = :tenant_id AND created_at >= :month_start AND model_used IN :model_runs"
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


#: Bind types for the parameters the limit queries use.
#:
#: Declared rather than inferred, for the same reason
#: `usage_metering._statement` declares them: these are raw statements, so
#: without a type the driver is handed a value and has to guess. The tenant
#: was being bound as `str(uuid)` against a `UUID` column, which Postgres
#: resolves by inferring the parameter's type from the comparison and no
#: other driver does — so every one of these counts returned zero in any
#: harness that was not Postgres, and a quota that reads zero is the one
#: direction nobody investigates.
_BIND_TYPES: Final[dict[str, Any]] = {
    "tenant_id": Uuid(as_uuid=True),
    "since": DateTime(timezone=True),
    "month_start": DateTime(timezone=True),
}

#: Bound as a list, and imported rather than rebuilt here: a quota that
#: decides "which runs are AI triages" for itself is a second definition,
#: and the two drift in front of a customer who is being throttled.
_EXPANDING: Final[tuple[str, ...]] = ("model_runs",)


async def measure_usage(db: AsyncSession, tenant_id: uuid.UUID) -> dict[str, int]:
    """Count current usage of every limit key for one tenant."""
    now = datetime.now(UTC)
    params = {
        "tenant_id": tenant_id,
        "since": now - timedelta(hours=24),
        "month_start": now.replace(day=1, hour=0, minute=0, second=0, microsecond=0),
        # Imported rather than repeated, so "which runs are AI triages" has
        # one definition shared with the usage meters.
        "model_runs": list(MODEL_RUNS),
    }
    usage: dict[str, int] = {}
    for key in LIMIT_KEYS:
        present = [name for name in _BIND_TYPES if f":{name}" in key.usage_sql]
        expanding = [name for name in _EXPANDING if f":{name}" in key.usage_sql]
        statement = text(key.usage_sql).bindparams(
            *[bindparam(name, type_=_BIND_TYPES[name]) for name in present],
            *[bindparam(name, expanding=True) for name in expanding],
        )
        result = await db.execute(statement, {name: params[name] for name in (*present, *expanding)})
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


# ── Enforcement ─────────────────────────────────────────────────────────────
#
# Everything above reports. Parity 4.5 asks for the other half: a limit an
# operator configured should be able to actually stop work, with a clear
# over-limit state rather than a silent one.
#
# Three properties decide the shape, and each is a reaction to how this has
# gone wrong before.
#
# **Opt-in, per tenant, per key.** `tenants.limits` has been a *reporting*
# input since it existed, so the numbers already written there were never
# chosen as hard caps. Enforcement arriving switched on would turn every one
# of them into a refusal on upgrade. Absence of a row means not enforced, and
# migration `113` writes none.
#
# **A measurement failure does not refuse.** The fail-closed instinct is
# wrong here and the precedent is explicit: a safety control that gets stuck
# closed reads as working caution, and a quota that cannot count would stop a
# customer's SOC for a reason that has nothing to do with their usage. An
# unreadable count is logged at `error` and the work proceeds. The positive
# control in the test suite is what keeps that honest in the other direction.
#
# **The refusal says what to do.** `LimitExceeded` carries the key, the
# measured usage and the ceiling, because "quota exceeded" sends an operator
# to a support channel while "47 of 45 connectors" sends them to the setting.


class LimitExceeded(Exception):
    """A tenant is over an enforced ceiling.

    Raised only when an operator opted that key in. Carries the numbers
    rather than a bare message: the caller turns this into an HTTP 402 or
    409, and the operator reading it needs to know which limit, by how
    much, and what the ceiling is.
    """

    def __init__(self, key: str, label: str, used: int, limit: int) -> None:
        self.key = key
        self.label = label
        self.used = used
        self.limit = limit
        super().__init__(
            f"{label} is at {used} of a configured limit of {limit}. "
            f"Raise the limit for this tenant, or disable enforcement of '{key}', to continue."
        )


async def enforced_keys(db: AsyncSession, tenant_id: uuid.UUID) -> frozenset[str]:
    """The limit keys this tenant has opted in to enforcing.

    An unreadable table is an empty set, not an exception: enforcement is
    the opt-in half of this module and a storage fault must not become a
    refusal. Logged at `error`, because a deployment that wanted a ceiling
    applied and is not getting one should be visible.
    """
    try:
        result = await db.execute(
            text("SELECT limit_key FROM aisoc_tenant_entitlement_enforcement  WHERE tenant_id = :tenant_id AND enforce IS TRUE").bindparams(
                bindparam("tenant_id", type_=Uuid(as_uuid=True))
            ),
            {"tenant_id": tenant_id},
        )
    except Exception:
        logger.error(
            "entitlements.enforcement_unreadable tenant=%s — no limit is being enforced for this tenant",
            tenant_id,
            exc_info=True,
        )
        return frozenset()
    return frozenset(str(row[0]) for row in result.fetchall())


async def assert_within_limit(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    tenant_limits: dict | None,
    key: str,
) -> None:
    """Refuse the caller if *key* is enforced for this tenant and exhausted.

    Returns silently in every other case: the key is not opted in, no
    ceiling is configured, there is room left, or the usage could not be
    measured. Only the first of those is a policy decision; the rest are
    the absence of one.

    `classify` decides exhaustion, so the number a caller is refused on is
    the same one the console's headroom bar drew. Two definitions of "full"
    is how a customer gets refused by a screen that says they have room.
    """
    if key not in LIMIT_KEYS_BY_NAME:
        raise KeyError(f"unknown limit key: {key!r}")
    if key not in await enforced_keys(db, tenant_id):
        return

    limit = limit_for(tenant_limits, key)
    if limit is None:
        return

    try:
        used = (await measure_usage(db, tenant_id)).get(key, 0)
    except Exception:
        # Deliberately not a refusal. See the note above the class.
        logger.error(
            "entitlements.usage_unmeasurable tenant=%s key=%s — allowing the request rather than "
            "refusing on evidence that could not be read",
            tenant_id,
            key,
            exc_info=True,
        )
        return

    if classify(used, limit) == "exhausted":
        logger.warning(
            "entitlements.refused tenant=%s key=%s used=%d limit=%d",
            tenant_id,
            key,
            used,
            limit,
        )
        raise LimitExceeded(key, LIMIT_KEYS_BY_NAME[key].label, used, limit)
