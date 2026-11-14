"""Leader election for the connector scheduler (parity 6.8 / depth 4.5).

Why it is needed
----------------
``ConnectorScheduler`` adds one APScheduler job per enabled connector
instance, in process. Two replicas therefore each run every job: every
vendor is polled twice on every cycle. On a rate-limited vendor API that
is worse than duplication, because the second replica's poll is what gets
throttled and a throttled connector looks identical to one whose
credentials have expired.

Without this, `connectors` has to be pinned to one replica — which the
Helm chart does — and a deployment that scales it for availability
silently doubles its vendor call volume.

The mechanism, and the one thing that makes it correct
------------------------------------------------------
``UPDATE scheduler_leases SET ... WHERE scope = :scope AND expires_at < now()``.

Postgres takes a row lock on the UPDATE, so a second challenger blocks
until the first commits and then re-evaluates the predicate against the
committed row — finding a fresh expiry, matching nothing, and learning
that it lost. A SELECT followed by an unconditional UPDATE has no such
re-evaluation: both challengers read an expired lease and both become
leader. That distinction is the whole of this module, and
``tests/isolation/test_scheduler_lease_live.py`` proves it with two
interleaved transactions rather than with a race, because a race between
two coroutines on one loop passes under the broken implementation as
well.

What a lost lease means
-----------------------
A follower does not poll. A leader that fails to renew **stops polling
before its lease expires**, not after: the renewal deadline is earlier
than the expiry by a margin, so there is a window in which the old leader
has stopped and no new one has started. That gap is deliberate. Polling
twice is worse than polling late — late costs one cycle, twice costs the
vendor's rate limit — and a design that overlaps instead would have to
assume the two clocks agree.
"""

from __future__ import annotations

import contextlib
import logging
import os
import socket
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

logger = logging.getLogger(__name__)

#: The scope this scheduler leads. One row per scope, so a future second
#: scheduler does not contend with this one.
CONNECTOR_SCHEDULER_SCOPE = "connector-scheduler"

#: How long a lease is valid once taken. Long enough that an ordinary
#: garbage-collection pause or a slow query does not lose it; short enough
#: that a replica which dies is replaced within a poll cycle. The default
#: poll cadence is five minutes, so a 90-second lease means at most one
#: missed cycle.
DEFAULT_LEASE_SECONDS = 90.0

#: How often the holder renews. A third of the lease, so two consecutive
#: renewals can fail before the lease is lost — one failed renewal is a
#: transient database blip and should not cause a leadership change.
#:
#: The relation is what matters, not either number: renewal must be
#: strictly less than the lease with room for at least two attempts. A
#: test asserts the relation rather than the values, because two constants
#: describing one budget and drifting apart is how this repository came to
#: have a retry capped at a sixth of its own window.
RENEW_FRACTION = 1.0 / 3.0

_ENABLED_ENV = "AISOC_SCHEDULER_LEADER_ELECTION"
_LEASE_ENV = "AISOC_SCHEDULER_LEASE_SECONDS"


def election_enabled() -> bool:
    """Whether to elect at all.

    Off by default. A single-replica deployment — which is every Compose
    install and the chart's own default — gains nothing from an election
    and would gain a new way to fail to start if Postgres is slow. The
    Helm values turn it on, because that is where a second replica is
    possible.
    """
    return os.environ.get(_ENABLED_ENV, "false").strip().lower() in {"1", "true", "yes"}


def lease_seconds() -> float:
    raw = os.environ.get(_LEASE_ENV, "").strip()
    if not raw:
        return DEFAULT_LEASE_SECONDS
    try:
        value = float(raw)
    except ValueError:
        logger.error("scheduler.lease.bad_duration value=%r using=%s", raw, DEFAULT_LEASE_SECONDS)
        return DEFAULT_LEASE_SECONDS
    # A lease shorter than two renewal intervals cannot survive one failed
    # renewal, which turns every database blip into a leadership change.
    if value < 10.0:
        logger.error("scheduler.lease.too_short value=%s using=%s", value, DEFAULT_LEASE_SECONDS)
        return DEFAULT_LEASE_SECONDS
    return value


def renew_interval(lease: float) -> float:
    return lease * RENEW_FRACTION


def holder_identity() -> str:
    """Who this process is, for the log.

    The pod name when Kubernetes supplies one, the hostname otherwise.
    Never compared for correctness except by the holder renewing its own
    lease; a lease is held by whoever last satisfied the predicate, not by
    whoever has the right name.
    """
    for env in ("POD_NAME", "HOSTNAME"):
        value = os.environ.get(env, "").strip()
        if value:
            return value
    with contextlib.suppress(OSError):
        return socket.gethostname()
    return "unknown"


@dataclass
class LeaseState:
    held: bool
    holder: str
    term: int
    expires_at: datetime | None


#: Taking a lease nobody holds, or one that has expired. `fenced_at`
#: increments only here, never on renewal, so the term counts leadership
#: changes rather than heartbeats.
_ACQUIRE_SQL = text(
    """
    INSERT INTO scheduler_leases (scope, holder, fenced_at, acquired_at, renewed_at, expires_at)
    VALUES (:scope, :holder, 1, now(), now(), now() + make_interval(secs => :lease))
    ON CONFLICT (scope) DO UPDATE
       SET holder      = EXCLUDED.holder,
           fenced_at   = scheduler_leases.fenced_at + 1,
           acquired_at = now(),
           renewed_at  = now(),
           expires_at  = now() + make_interval(secs => :lease)
     WHERE scheduler_leases.expires_at < now()
    RETURNING fenced_at, expires_at
    """
)

#: Renewing. Conditional on still being the holder *and* on the lease not
#: having already lapsed: a process that was paused past its expiry must
#: not resume and renew a lease someone else has taken.
_RENEW_SQL = text(
    """
    UPDATE scheduler_leases
       SET renewed_at = now(),
           expires_at = now() + make_interval(secs => :lease)
     WHERE scope = :scope
       AND holder = :holder
       AND expires_at >= now()
    RETURNING fenced_at, expires_at
    """
)

#: Releasing on a clean shutdown, so a rolling restart does not wait out
#: the whole lease with nobody polling.
_RELEASE_SQL = text(
    """
    UPDATE scheduler_leases
       SET expires_at = now()
     WHERE scope = :scope AND holder = :holder
    """
)


class LeaderLease:
    """Acquire, renew and release one scope's lease."""

    def __init__(
        self,
        engine: AsyncEngine,
        *,
        scope: str = CONNECTOR_SCHEDULER_SCOPE,
        holder: str | None = None,
        lease: float | None = None,
    ) -> None:
        self._engine = engine
        self._scope = scope
        self._holder = holder or holder_identity()
        self._lease = lease if lease is not None else lease_seconds()
        self._term = 0
        self._held = False

    @property
    def holder(self) -> str:
        return self._holder

    @property
    def lease_seconds(self) -> float:
        return self._lease

    @property
    def renew_after(self) -> float:
        return renew_interval(self._lease)

    @property
    def held(self) -> bool:
        return self._held

    @property
    def term(self) -> int:
        return self._term

    async def acquire(self) -> bool:
        """Try to become leader. Returns whether this process now leads."""
        async with self._engine.begin() as conn:
            row = (await conn.execute(_ACQUIRE_SQL, {"scope": self._scope, "holder": self._holder, "lease": self._lease})).first()
        if row is None:
            self._held = False
            return False
        self._term = int(row[0])
        self._held = True
        logger.info(
            "scheduler.lease.acquired scope=%s holder=%s term=%s expires=%s",
            self._scope,
            self._holder,
            self._term,
            row[1],
        )
        return True

    async def renew(self) -> bool:
        """Extend the lease. Returns whether it is still held.

        A ``False`` here is a leadership loss and the caller must stop
        scheduling. It is not an error to retry past: the lease has gone
        to someone else, or this process was paused past its own expiry,
        and continuing to poll in either case is the double-poll this
        exists to prevent.
        """
        async with self._engine.begin() as conn:
            row = (await conn.execute(_RENEW_SQL, {"scope": self._scope, "holder": self._holder, "lease": self._lease})).first()
        if row is None:
            if self._held:
                logger.warning(
                    "scheduler.lease.lost scope=%s holder=%s term=%s — stopping scheduling",
                    self._scope,
                    self._holder,
                    self._term,
                )
            self._held = False
            return False
        self._held = True
        return True

    async def release(self) -> None:
        """Give the lease up on a clean shutdown.

        Best effort and never raising: a shutdown path that can fail is a
        shutdown path that leaves a pod terminating. The worst case is the
        lease expiring on its own, which is the same outcome one lease
        period later.
        """
        try:
            async with self._engine.begin() as conn:
                await conn.execute(_RELEASE_SQL, {"scope": self._scope, "holder": self._holder})
        except Exception as exc:  # noqa: BLE001 — see the docstring
            logger.warning("scheduler.lease.release_failed scope=%s error=%s", self._scope, exc)
        finally:
            self._held = False

    async def state(self) -> LeaseState:
        """What readiness reports.

        A follower is healthy. The thing worth surfacing is *which* it is,
        because a deployment where every replica is a follower — which a
        clock skew or a stuck row can produce — is one where nothing is
        polling, and every replica reporting 200 is how that stays
        invisible.
        """
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    text("SELECT holder, fenced_at, expires_at FROM scheduler_leases WHERE scope = :scope"),
                    {"scope": self._scope},
                )
            ).first()
        if row is None:
            return LeaseState(held=False, holder="", term=0, expires_at=None)
        expires = row[2]
        if expires is not None and expires.tzinfo is None:
            expires = expires.replace(tzinfo=UTC)
        return LeaseState(
            held=row[0] == self._holder and expires is not None and expires > datetime.now(UTC),
            holder=str(row[0]),
            term=int(row[1]),
            expires_at=expires,
        )


def lease_is_longer_than_two_renewals(lease: float) -> bool:
    """The relation the two constants have to keep.

    Asserted by a test rather than left to the numbers: two constants
    describing one budget and drifting apart is how this repository came
    to have a documented retry capped at a sixth of its own window.
    """
    return lease > 2 * renew_interval(lease) + timedelta(seconds=0).total_seconds()
