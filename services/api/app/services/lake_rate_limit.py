"""Per-tenant token-bucket rate limiter for the lake API (Workstream 7).

The lake exposes ``POST /api/v1/lake/sql`` and ``GET /api/v1/lake/schema``,
both of which can be expensive — a single ClickHouse query against
``aisoc.raw_events`` can scan billions of rows. Without a per-tenant
soft cap, one noisy tenant or one runaway agent loop can starve every
other caller in the cluster.

Design choices
--------------

* **Token bucket, not fixed window.** Token buckets allow bursts (a
  human poking around the lake can fire five queries in five seconds
  and still be within budget) while smoothing sustained load. Fixed
  windows have ugly edge effects at the boundary and don't model
  "you've been quiet for a minute, here's some catch-up budget" the
  way operators expect.
* **In-memory, per-process.** The plan calls this a *soft* limit. The
  hard limits live downstream in ClickHouse query settings
  (``max_execution_time``, ``max_memory_usage``). With a single API
  pod the in-memory bucket is exact; with multiple pods it under-
  enforces by a factor of ``n_pods``, which is acceptable given the
  belt-and-braces ClickHouse caps. The class is intentionally written
  so the in-memory store can be swapped for a Redis-backed
  implementation later without changing callers.
* **No external dependencies on the hot path.** A Redis round-trip
  per query would be cheaper than ClickHouse, but it still adds
  network jitter to *every* request. The in-memory variant is O(1)
  per-call.
* **Costed acquisition.** Some calls (``schema`` lookup) are cheap;
  others (``SELECT *`` over a year of raw_events) aren't. We let the
  caller pass a token cost so the bucket reflects work done, not
  request count.
* **Asyncio-safe.** Each bucket has its own ``asyncio.Lock`` so
  concurrent acquisitions on the same tenant are serialised; we
  *don't* take a global lock because that would serialise the whole
  API across tenants.

Threat model
------------

The limiter sits in front of the rewriter (cheap CPU work) and the
ClickHouse client (expensive network/IO). An attacker who controls
one tenant can saturate that tenant's bucket; they can't drain
another tenant's budget because the bucket key is the tenant UUID.
The same applies to the agent: a misbehaving agent run can DoS its
own tenant but no one else.

Memory accounting
-----------------

We never evict bucket state — a tenant who hasn't queried for a week
holds a few hundred bytes in the dict. With ~10⁴ tenants that's a
few MB, which is fine. If we ever ship a free-tier with millions of
tenants we'll add an LRU eviction.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from uuid import UUID

# Default budget tuned to "human pokes around for a couple of minutes
# without thinking about it". 60 tokens at 1/sec means a steady ~1 RPS
# with bursts of 60. For agents, an outer loop should usually plan
# every few seconds, so this leaves plenty of headroom while still
# capping a runaway loop.
DEFAULT_CAPACITY: float = 60.0
DEFAULT_REFILL_PER_SECOND: float = 1.0


@dataclass
class _TokenBucket:
    """Single tenant's bucket.

    The bucket lazily refills on read: instead of running a background
    task that ticks every second across the entire tenant set, we
    compute the elapsed time since the last refill on each
    :meth:`acquire` and add that many tokens up to the capacity. This
    is both simpler and exact (no scheduler jitter).
    """

    capacity: float
    refill_per_second: float
    # We initialise the bucket full so a tenant's first request always
    # succeeds — the limiter exists to control sustained load, not to
    # gate cold-start traffic. ``field(default_factory=...)`` evaluates
    # at instance construction so it picks up changes to ``capacity``
    # via the dataclass keyword arg flow.
    tokens: float = field(default=DEFAULT_CAPACITY)
    last_refill: float = field(default_factory=time.monotonic)
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    def __post_init__(self) -> None:
        # ``tokens`` defaults to DEFAULT_CAPACITY; if the caller passed
        # a custom capacity we should start full at *that* capacity, not
        # the module default. This keeps tests deterministic.
        if self.tokens > self.capacity:
            self.tokens = self.capacity

    def _refill(self, now: float) -> None:
        """Top up the bucket based on elapsed wall time.

        Lazy refill is mathematically equivalent to a continuous
        leaky-bucket model when ``refill_per_second`` is constant.
        Capped at :attr:`capacity` so we don't accumulate unbounded
        burst budget across long idle periods.
        """
        elapsed = max(0.0, now - self.last_refill)
        if elapsed > 0.0:
            self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_per_second)
            self.last_refill = now


@dataclass(frozen=True)
class RateLimitDecision:
    """Outcome of an :meth:`acquire` attempt.

    The endpoint layer turns this into either a normal response with
    rate-limit headers (``X-RateLimit-Remaining``, ``Retry-After``) or
    an HTTP 429.
    """

    allowed: bool
    remaining: float
    capacity: float
    retry_after_seconds: float

    def to_headers(self) -> dict[str, str]:
        """Produce IETF-ish rate-limit headers.

        We use the de-facto standard ``X-RateLimit-*`` family rather
        than the newer ``RateLimit-*`` draft because most operator
        dashboards already speak the older names. ``Retry-After`` is
        an integer (seconds) because the RFC 7231 grammar requires it.
        """
        headers = {
            "X-RateLimit-Limit": f"{int(self.capacity)}",
            "X-RateLimit-Remaining": f"{max(0, int(self.remaining))}",
        }
        if not self.allowed:
            # ``Retry-After`` MUST be a non-negative integer per
            # RFC 7231 §7.1.3. Round up so the client doesn't retry
            # one millisecond too early and bounce off the bucket
            # again.
            headers["Retry-After"] = f"{max(1, int(self.retry_after_seconds + 0.999))}"
        return headers


class LakeRateLimiter:
    """Per-tenant token-bucket limiter for the lake API surface.

    Usage::

        limiter = LakeRateLimiter()
        decision = await limiter.acquire(tenant_id, cost=1.0)
        if not decision.allowed:
            raise HTTPException(status_code=429, headers=decision.to_headers())

    The class is safe to share across requests; it owns its own
    locking. Callers should construct it once at module import and
    reuse it via :func:`get_lake_rate_limiter`.
    """

    def __init__(
        self,
        *,
        capacity: float = DEFAULT_CAPACITY,
        refill_per_second: float = DEFAULT_REFILL_PER_SECOND,
    ) -> None:
        if capacity <= 0:
            raise ValueError("capacity must be positive")
        if refill_per_second <= 0:
            raise ValueError("refill_per_second must be positive")
        self._capacity = capacity
        self._refill_per_second = refill_per_second
        self._buckets: dict[str, _TokenBucket] = {}
        # Coarse-grained lock for the dict structure itself. We hold
        # it only long enough to look up / insert the per-bucket lock,
        # so it never serialises the actual rate-limit decisions.
        self._registry_lock = asyncio.Lock()

    async def acquire(
        self,
        tenant_id: UUID | str,
        *,
        cost: float = 1.0,
    ) -> RateLimitDecision:
        """Attempt to consume ``cost`` tokens for ``tenant_id``.

        ``cost`` lets the endpoint price different operations
        differently — schema reads cost 0.5, vanilla queries cost 1.0,
        and a future "expensive query" detection (e.g. unbounded
        ``SELECT *``) could charge 5.0. Cost > capacity is invalid.

        Returns a :class:`RateLimitDecision`. Never raises on the
        rate-limited path; the caller decides how to present the 429.
        """
        if cost <= 0:
            raise ValueError("cost must be positive")
        if cost > self._capacity:
            # A single request asking for more than the bucket can
            # ever hold is a programmer error, not a runtime
            # condition. Surfacing it as a denial would loop forever
            # because no amount of waiting could refill enough; it's
            # better to fail loudly here.
            raise ValueError(f"cost {cost} exceeds bucket capacity {self._capacity}; this would never succeed")

        key = str(tenant_id)
        bucket = await self._get_bucket(key)

        async with bucket.lock:
            now = time.monotonic()
            bucket._refill(now)

            if bucket.tokens >= cost:
                bucket.tokens -= cost
                return RateLimitDecision(
                    allowed=True,
                    remaining=bucket.tokens,
                    capacity=self._capacity,
                    retry_after_seconds=0.0,
                )

            # Compute the time the caller would need to wait for the
            # bucket to refill enough for *this* request. We don't
            # actually sleep here — the API layer prefers to return a
            # 429 with Retry-After so callers can back off
            # cooperatively rather than holding sockets open.
            shortfall = cost - bucket.tokens
            retry_after = shortfall / self._refill_per_second
            return RateLimitDecision(
                allowed=False,
                remaining=bucket.tokens,
                capacity=self._capacity,
                retry_after_seconds=retry_after,
            )

    async def peek(self, tenant_id: UUID | str) -> RateLimitDecision:
        """Inspect the current bucket without consuming tokens.

        Powers a future ``GET /api/v1/lake/quota`` endpoint and is
        useful in tests. Equivalent to ``acquire(cost=0)`` but with
        an explicit no-charge contract.
        """
        key = str(tenant_id)
        bucket = await self._get_bucket(key)
        async with bucket.lock:
            now = time.monotonic()
            bucket._refill(now)
            return RateLimitDecision(
                allowed=True,
                remaining=bucket.tokens,
                capacity=self._capacity,
                retry_after_seconds=0.0,
            )

    async def reset(self, tenant_id: UUID | str | None = None) -> None:
        """Forget bucket state.

        Drops one tenant's bucket if ``tenant_id`` is given, otherwise
        clears the entire registry. Used by tests; an operator-facing
        admin endpoint could expose the targeted variant for
        emergency relief, e.g. when a tenant has been throttled by a
        misconfigured cron job and we want to give them a clean
        budget.
        """
        async with self._registry_lock:
            if tenant_id is None:
                self._buckets.clear()
            else:
                self._buckets.pop(str(tenant_id), None)

    async def _get_bucket(self, key: str) -> _TokenBucket:
        """Fetch (or lazily create) the per-tenant bucket.

        Uses double-checked locking so the hot path (bucket already
        exists) is lock-free aside from the dict read, and the cold
        path (first ever request from a tenant) takes the registry
        lock only once.
        """
        bucket = self._buckets.get(key)
        if bucket is not None:
            return bucket
        async with self._registry_lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = _TokenBucket(
                    capacity=self._capacity,
                    refill_per_second=self._refill_per_second,
                    tokens=self._capacity,
                )
                self._buckets[key] = bucket
            return bucket


# Process-wide singleton. The endpoint module imports this directly so
# we don't have to plumb it through DI; tests reset state via
# :meth:`LakeRateLimiter.reset` rather than reconstructing the limiter.
_lake_rate_limiter = LakeRateLimiter()


def get_lake_rate_limiter() -> LakeRateLimiter:
    """Return the process-wide lake rate limiter.

    Wrapped in a getter (rather than re-exporting the module-level
    singleton) so a test can monkey-patch the function to inject a
    bespoke limiter without touching :data:`_lake_rate_limiter`. This
    matches the pattern used by other ``get_*`` factories in
    :mod:`app.services`.
    """
    return _lake_rate_limiter
