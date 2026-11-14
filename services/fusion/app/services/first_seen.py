"""Per-tenant first-seen store: has this tenant observed this value before?

Depth plan 3.3: *"first-seen and age from a per-tenant first-seen store keyed
by principal and attribute (country, ASN, device, client family, OAuth app,
action, resource), in Redis with a lake backstop."*

What it answers, and what it deliberately does not
--------------------------------------------------
It answers **"have we seen this before, and how long ago did we first see
it"**. It does not answer "how old is this thing". Those look alike and are
not the same question, and conflating them is the trap this module exists to
avoid: a rule about newly-registered domains (`domain_age_days`) wants the
domain's registration age from a registry, and substituting "the first time
this deployment happened to observe it" would make the rule fire on every
domain a quiet tenant has not seen yet — which is most of the internet. Those
rules stay unreachable with that reason recorded rather than being closed
with a plausible-looking number.

So the booleans and ages here are only the ones whose subject is *an
observation*: a publisher IP, a device fingerprint, a session.

Shape of the state
------------------
One Redis string per `(tenant, attribute, value)` holding the epoch seconds
of the first observation, set with `NX` so the first writer wins and every
later one reads it back. That is a single round trip for the common case
(`SET key now NX GET`), and it is correct under concurrency without a lock:
two replicas racing on the first sighting agree on whichever landed first.

**First sighting is reported as not-seen-before**, which is the whole point,
and the write happens on the same call — so a rule reading
`<attr>_seen_before: false` fires once per value per tenant and not again.

Fail-soft, in one direction
---------------------------
A Redis outage contributes **no key at all** rather than `False`. `False`
means "this tenant has never seen this", which is a confident statement that
would fire every first-seen rule on every event for the duration of the
outage. Absent means the clause does not match and the rule stays silent,
which is the safe direction for a detection that triggers on novelty.
"""

from __future__ import annotations

import os
import time
from typing import Any

import structlog

logger = structlog.get_logger()

#: How long a value stays "seen". A first-seen store with no horizon reports
#: an address seen once two years ago as familiar, which is not what an
#: analyst means by it. Ninety days matches the lake's default retention, so
#: the backstop below can answer for the same span the store remembers.
TTL_SECONDS = int(os.getenv("AISOC_FIRST_SEEN_TTL_SECONDS", str(90 * 86400)))

#: `<boolean a rule reads>` → the event field holding its subject.
#:
#: Only observation-shaped subjects appear here; see the module docstring for
#: why `domain_age_days` and friends are not in this table and are not going
#: to be.
SEEN_BEFORE_FIELDS: dict[str, str] = {
    "publisher_ip_seen_before": "publisher_ip",
    "device_fingerprint_seen_before": "device_fingerprint",
}

#: `<age field a rule reads>` → (event field holding its subject, divisor).
#: The age is measured from the first observation, which for a session is
#: exactly what "session age" means.
AGE_FIELDS: dict[str, tuple[str, int]] = {
    "session_age_hours": ("session_id", 3600),
}

#: Attributes the plan names for the store, beyond the ones a rule reads
#: today. Recorded so a rule author can see what is already keyed rather
#: than adding a parallel store, and asserted by the tests so the list
#: cannot quietly become aspirational.
TRACKED_ATTRIBUTES: tuple[str, ...] = (
    "publisher_ip",
    "device_fingerprint",
    "session_id",
    "src_country",
    "src_asn",
    "client_family",
    "oauth_app",
    "event_name",
    "resource",
)


class FirstSeenStore:
    """Redis-backed first-sighting memory, scoped per tenant."""

    def __init__(self, redis: Any, *, key_prefix: str = "aisoc:fs", ttl_seconds: int | None = None) -> None:
        self._redis = redis
        self._prefix = key_prefix
        self._ttl = ttl_seconds if ttl_seconds is not None else TTL_SECONDS

    def _key(self, tenant: str, attribute: str, value: str) -> str:
        return f"{self._prefix}:{tenant}:{attribute}:{value}"

    async def observe(self, tenant: str, attribute: str, value: str, *, now: float | None = None) -> float | None:
        """Record a sighting; return the first-sighting time, or None if unknown.

        Returns the *first* time this tenant saw the value, which is the new
        time on a first sighting. None means Redis could not answer, and the
        caller must treat that as "unknown" rather than as "new".
        """
        when = now if now is not None else time.time()
        key = self._key(tenant, attribute, value)
        try:
            # SET ... NX GET: write if absent, and return whatever was there.
            # One round trip, and correct when two replicas race, because
            # the loser reads the winner's value back.
            previous = await self._redis.set(key, str(when), nx=True, ex=self._ttl, get=True)
        except TypeError:
            # A client without `GET` support on SET. Fall back to a read
            # then a conditional write: one extra round trip, same answer,
            # and a race resolves to the earlier of the two writes.
            try:
                previous = await self._redis.get(key)
                if previous is None:
                    await self._redis.set(key, str(when), nx=True, ex=self._ttl)
            except Exception as exc:  # noqa: BLE001 — see the module docstring
                logger.debug("first_seen.unavailable", attribute=attribute, error=str(exc))
                return None
        except Exception as exc:  # noqa: BLE001
            logger.debug("first_seen.unavailable", attribute=attribute, error=str(exc))
            return None

        if previous is None:
            return when
        raw = previous.decode() if isinstance(previous, bytes | bytearray) else str(previous)
        try:
            return float(raw)
        except ValueError:
            return when

    async def derived_fields(self, tenant: str, event: dict[str, Any], *, now: float | None = None) -> dict[str, Any]:
        """The `<attr>_seen_before` and age booleans this event produces.

        An unreadable store contributes nothing, which keeps a novelty rule
        silent during an outage rather than firing it on everything.
        """
        if not tenant:
            return {}
        when = now if now is not None else time.time()
        out: dict[str, Any] = {}

        for boolean, source in SEEN_BEFORE_FIELDS.items():
            value = event.get(source)
            if value is None or value == "":
                continue
            first = await self.observe(tenant, source, str(value), now=when)
            if first is None:
                continue
            out[boolean] = first < when

        for age_field, (source, divisor) in AGE_FIELDS.items():
            value = event.get(source)
            if value is None or value == "":
                continue
            first = await self.observe(tenant, source, str(value), now=when)
            if first is None:
                continue
            out[age_field] = max(0.0, (when - first) / divisor)

        return out
