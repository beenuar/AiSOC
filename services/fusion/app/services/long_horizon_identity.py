"""Depth 2 wave 2 item 2.2 — identity behaviour accumulated over weeks.

The windowed engine's longest window is one day, and it answers exactly one
question: *is a count high inside this window*. An attack spread deliberately
thin against a single account never accumulates there — one failed sign-in
per source per hour from a hundred networks crosses no hourly threshold, and
by the next day the window has forgotten the first ninety.

What separates that from a travelling employee is not the count. It is the
**shape**: an attack widens the set of networks that *fail* against one
account while the set that *succeeds* stays small or empty; a traveller
widens the set that succeeds, from a handful of networks, with the second
factor satisfied. So this module accumulates distinct source networks per
account per day, keeps thirty days of them, and publishes the breadth of
each side plus the ratio between them.

Why here and not the windowed engine
------------------------------------
The plan is explicit that this lands on the baseline store rather than the
windowed engine, and the reason is worth stating: the windowed engine
computes no sums, means or variances, and 24 rules were already refused
rather than shipped as weaker count rules under a stronger name. A distinct
*set* over thirty daily buckets is not a count in a window, so putting it
there would have meant either lying about what fires or quietly changing
what the windowed engine means.

Honest absence
--------------
Every method follows the rule the rest of this package follows: an
unreadable store, or an account with too little history to say anything,
contributes **no key at all**. A breadth of zero is a confident statement
that nothing has failed against this account, and publishing it for an
account nobody has observed would be a false negative wearing a number.

Bounded by construction
-----------------------
Source networks are attacker-chosen, so an unbounded set is a
memory-exhaustion primitive aimed at the detection path. Each day's set
stops admitting new members at `MAX_DISTINCT_PER_DAY`. Past the cap the day
is marked saturated and reported as *at least* that breadth, which is the
honest degradation: the account is being hit from more networks than we are
willing to enumerate, which is the finding anyway.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Any

import structlog

logger = structlog.get_logger()

#: Days of history the accumulation spans. Thirty rather than ninety because
#: the published thresholds below were derived over thirty, and a field whose
#: horizon differs from the horizon its threshold was measured on is a
#: threshold that means nothing.
HORIZON_DAYS = int(os.getenv("AISOC_LONG_HORIZON_DAYS", "30"))

#: Distinct values one account's one day will admit. Past it the day is
#: saturated and reported as a floor rather than dropped.
MAX_DISTINCT_PER_DAY = int(os.getenv("AISOC_LONG_HORIZON_MAX_PER_DAY", "256"))

#: Days an account must have been observed before any breadth is published.
#: Below this a new account's first week looks maximally broad because every
#: network is new, which is an artefact of the history's length rather than
#: a property of the account.
MIN_ACTIVE_DAYS = int(os.getenv("AISOC_LONG_HORIZON_MIN_DAYS", "3"))

_DAY = 86400

#: Fields naming the account under attack. Ordered: the explicit target of
#: an authentication event wins over the actor, because a failed sign-in
#: names the account being guessed at and an admin-initiated reset names the
#: admin as actor and the victim as target.
_PRINCIPAL_FIELDS: tuple[str, ...] = (
    "target_user",
    "target_user_email",
    "actor_email",
    "user_principal_name",
    "actor",
    "user_name",
    "username",
)

#: The network dimensions whose breadth is accumulated. An ASN is the most
#: meaningful of the three — a botnet spans many addresses inside few
#: autonomous systems, and a traveller spans few of both — so it leads.
_DIMENSIONS: dict[str, tuple[str, ...]] = {
    "asn": ("src_asn", "src_asn_org"),
    "country": ("src_country", "country"),
    "ip": ("src_ip", "ip_address", "client_ip"),
}

#: Values that mean "this authentication did not succeed", per source. The
#: outcome split is the whole discriminator, so it is read from fields the
#: connectors genuinely emit rather than inferred from a severity.
_FAILURE_OUTCOMES = frozenset({"failure", "failed", "denied", "deny", "false"})
_SUCCESS_OUTCOMES = frozenset({"success", "succeeded", "allow", "true"})


@dataclass(frozen=True)
class Breadth:
    """How many distinct values of one dimension were seen, and over what."""

    distinct: int
    active_days: int
    saturated: bool


def resolve_account(event: dict[str, Any]) -> str | None:
    for field in _PRINCIPAL_FIELDS:
        value = event.get(field)
        if isinstance(value, str) and value.strip():
            return value.strip().lower()
    return None


def classify_outcome(event: dict[str, Any]) -> str | None:
    """`"success"`, `"failure"`, or None when the event states neither.

    None is a real answer and not a default. An event that does not say
    whether authentication worked contributes to neither side, because
    guessing would put ordinary activity into the failure set and make
    every busy account look attacked.
    """
    is_success = event.get("is_success")
    if isinstance(is_success, bool):
        return "success" if is_success else "failure"
    for field in ("outcome", "outcome_result", "result", "result_status", "status"):
        value = event.get(field)
        if not isinstance(value, str):
            continue
        lowered = value.strip().lower()
        if lowered in _FAILURE_OUTCOMES:
            return "failure"
        if lowered in _SUCCESS_OUTCOMES:
            return "success"
    return None


class LongHorizonIdentityStore:
    """Distinct source networks per account per day, over `HORIZON_DAYS`.

    One Redis set per (account, outcome, dimension, day). Reading a breadth
    is a union across the live day keys, which Redis does server-side, so
    the cost is one round trip rather than thirty.
    """

    def __init__(
        self,
        redis: Any,
        *,
        key_prefix: str = "aisoc:lh",
        horizon_days: int | None = None,
        min_active_days: int | None = None,
    ) -> None:
        self._redis = redis
        self._prefix = key_prefix
        self._horizon = horizon_days if horizon_days is not None else HORIZON_DAYS
        self._min_active_days = min_active_days if min_active_days is not None else MIN_ACTIVE_DAYS

    def _key(self, tenant: str, account: str, outcome: str, dimension: str, day: int) -> str:
        return f"{self._prefix}:{tenant}:{account}:{outcome}:{dimension}:{day}"

    def _day_keys(self, tenant: str, account: str, outcome: str, dimension: str, today: int) -> list[str]:
        return [self._key(tenant, account, outcome, dimension, today - offset) for offset in range(self._horizon)]

    async def observe(self, tenant: str, account: str, outcome: str, dimension: str, value: str, *, now: float | None = None) -> bool:
        """Record one sighting into today's set. False when it was not recorded."""
        when = now if now is not None else time.time()
        day = int(when // _DAY)
        key = self._key(tenant, account, outcome, dimension, day)
        try:
            size = await self._redis.scard(key)
            if int(size or 0) >= MAX_DISTINCT_PER_DAY:
                # Saturated. Still refresh the expiry so the day does not
                # vanish mid-horizon and make the breadth read low.
                await self._redis.expire(key, self._horizon * _DAY)
                return False
            await self._redis.sadd(key, value)
            await self._redis.expire(key, self._horizon * _DAY)
        except Exception as exc:  # noqa: BLE001 — see the module docstring
            logger.debug("long_horizon.unavailable", dimension=dimension, error=str(exc))
            return False
        return True

    async def breadth(self, tenant: str, account: str, outcome: str, dimension: str, *, now: float | None = None) -> Breadth | None:
        """Distinct values across the horizon, or None when unanswerable."""
        when = now if now is not None else time.time()
        today = int(when // _DAY)
        keys = self._day_keys(tenant, account, outcome, dimension, today)
        try:
            members = await self._redis.sunion(*keys)
            active = 0
            saturated = False
            for key in keys:
                size = int(await self._redis.scard(key) or 0)
                if size:
                    active += 1
                if size >= MAX_DISTINCT_PER_DAY:
                    saturated = True
        except Exception as exc:  # noqa: BLE001
            logger.debug("long_horizon.unavailable", dimension=dimension, error=str(exc))
            return None
        if active < self._min_active_days:
            return None
        values = {m.decode() if isinstance(m, bytes) else str(m) for m in (members or [])}
        return Breadth(distinct=len(values), active_days=active, saturated=saturated)

    async def derived_fields(self, tenant: str, event: dict[str, Any], *, now: float | None = None) -> dict[str, Any]:
        """The long-horizon fields this event produces, for the detection engine.

        Shaped like `BaselineStore.derived_fields` and `FirstSeenStore`'s:
        one awaited call per event, every key optional, nothing raised into
        the pipeline.
        """
        if not tenant:
            return {}
        account = resolve_account(event)
        outcome = classify_outcome(event)
        if not account or outcome is None:
            return {}

        for dimension, candidates in _DIMENSIONS.items():
            for field in candidates:
                value = event.get(field)
                if value is None or value == "":
                    continue
                await self.observe(tenant, account, outcome, dimension, str(value), now=now)
                break

        out: dict[str, Any] = {}
        failed_asn: int | None = None
        success_asn: int | None = None
        for dimension in _DIMENSIONS:
            for side in ("failure", "success"):
                measured = await self.breadth(tenant, account, side, dimension, now=now)
                if measured is None:
                    continue
                prefix = "failed" if side == "failure" else "success"
                out[f"lh_distinct_{prefix}_{dimension}"] = measured.distinct
                if measured.saturated:
                    out[f"lh_{prefix}_{dimension}_saturated"] = True
                if dimension == "asn":
                    if side == "failure":
                        failed_asn = measured.distinct
                    else:
                        success_asn = measured.distinct

        # The ratio is the discriminator the plan names, and it is only
        # meaningful when both sides were measurable. A missing success side
        # is not a zero: an account with no observed successes in the window
        # has an undefined ratio, and publishing a very large number for it
        # would fire on every dormant account.
        if failed_asn is not None and success_asn is not None and success_asn > 0:
            out["lh_failed_to_success_asn_ratio"] = round(failed_asn / success_asn, 3)

        if out:
            # The span travels with the measurement. A breadth without the
            # window it was measured over is a number a reader cannot check.
            out["lh_horizon_days"] = self._horizon
        return out


#: Every key `derived_fields` can publish. `scripts/check_detection_fields.py`
#: pins this set, and `services/fusion/tests/test_long_horizon_identity.py`
#: asserts the two agree in both directions — the matcher's operator list
#: drifted from the gate's copy once and three shipped rules were dead.
DERIVED_FIELDS = frozenset(
    {
        "lh_distinct_failed_asn",
        "lh_distinct_failed_country",
        "lh_distinct_failed_ip",
        "lh_distinct_success_asn",
        "lh_distinct_success_country",
        "lh_distinct_success_ip",
        "lh_failed_asn_saturated",
        "lh_failed_country_saturated",
        "lh_failed_ip_saturated",
        "lh_success_asn_saturated",
        "lh_success_country_saturated",
        "lh_success_ip_saturated",
        "lh_failed_to_success_asn_ratio",
        "lh_horizon_days",
    }
)
