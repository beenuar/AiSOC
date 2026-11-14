"""Per-IP token-bucket rate limiter for the public waitlist signup endpoint.

The lake and explain endpoints already prove out the per-tenant variant
of this pattern; this module is the *unauthenticated* twin. The waitlist
signup form lives on a public marketing route — there is no tenant
context to limit against, so we limit per source IP instead.

Tuning
------
* **capacity = 20** — covers a small booth on conference day where ten
  people pass a laptop around a NAT and submit signups in a row.
* **refill = 10 / hour ≈ 0.00278 tokens/sec** — generous enough that a
  legitimate enterprise (multi-team signups from the same /29) never
  trips the limiter, tight enough that an unattended script gets capped
  inside two or three minutes.

Both are overridable via env vars so an operator running a marketing
push can widen the bucket without a redeploy:

* ``AISOC_WAITLIST_RATE_CAPACITY``  (default 20)
* ``AISOC_WAITLIST_RATE_REFILL_PER_HOUR``  (default 10)

The class is asyncio-safe and stores buckets in-process. A multi-replica
deploy will get per-replica buckets — for v1 of T6.1 that is fine
(``tryaisoc.com`` runs single-replica at start). When we scale to
multi-replica the limiter swaps to a Redis-backed implementation behind
the same interface; the endpoint never changes.
"""

from __future__ import annotations

import asyncio
import os
import time
from dataclasses import dataclass, field

_DEFAULT_CAPACITY: float = 20.0
# Refill rate in tokens/second. 10 tokens/hour = 10 / 3600.
_DEFAULT_REFILL_PER_HOUR: float = 10.0


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        return default
    return value if value > 0 else default


@dataclass
class _SignupBucket:
    """One source IP's bucket."""

    capacity: float
    refill_per_second: float
    tokens: float
    last_refill: float = field(default_factory=time.monotonic)
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    def __post_init__(self) -> None:
        if self.tokens > self.capacity:
            self.tokens = self.capacity

    def _refill(self, now: float) -> None:
        elapsed = max(0.0, now - self.last_refill)
        if elapsed > 0.0:
            self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_per_second)
            self.last_refill = now


@dataclass(frozen=True)
class SignupRateLimitDecision:
    """Outcome of an :meth:`SignupRateLimiter.acquire` attempt."""

    allowed: bool
    remaining: float
    capacity: float
    retry_after_seconds: float

    def to_headers(self) -> dict[str, str]:
        headers = {
            "X-RateLimit-Limit": f"{int(self.capacity)}",
            "X-RateLimit-Remaining": f"{max(0, int(self.remaining))}",
        }
        if not self.allowed:
            headers["Retry-After"] = f"{max(1, int(self.retry_after_seconds + 0.999))}"
        return headers


class SignupRateLimiter:
    """Per-source-IP token-bucket limiter for the signup endpoint.

    Source addresses can be anything string-shaped; the endpoint passes
    in the X-Forwarded-For-derived client IP (falling back to the raw
    socket address) so the limiter doesn't care about address format.
    """

    def __init__(
        self,
        *,
        capacity: float | None = None,
        refill_per_hour: float | None = None,
    ) -> None:
        cap = capacity if capacity is not None else _env_float("AISOC_WAITLIST_RATE_CAPACITY", _DEFAULT_CAPACITY)
        per_hour = (
            refill_per_hour if refill_per_hour is not None else _env_float("AISOC_WAITLIST_RATE_REFILL_PER_HOUR", _DEFAULT_REFILL_PER_HOUR)
        )
        if cap <= 0:
            raise ValueError("capacity must be positive")
        if per_hour <= 0:
            raise ValueError("refill_per_hour must be positive")
        self._capacity = cap
        self._refill_per_second = per_hour / 3600.0
        self._buckets: dict[str, _SignupBucket] = {}
        self._registry_lock = asyncio.Lock()

    async def acquire(self, source: str, *, cost: float = 1.0) -> SignupRateLimitDecision:
        """Attempt to consume ``cost`` tokens for ``source``."""
        if cost <= 0:
            raise ValueError("cost must be positive")
        if cost > self._capacity:
            raise ValueError(f"cost {cost} exceeds capacity {self._capacity}; would never succeed")

        bucket = await self._get_bucket(source)
        async with bucket.lock:
            now = time.monotonic()
            bucket._refill(now)
            if bucket.tokens >= cost:
                bucket.tokens -= cost
                return SignupRateLimitDecision(
                    allowed=True,
                    remaining=bucket.tokens,
                    capacity=self._capacity,
                    retry_after_seconds=0.0,
                )
            shortfall = cost - bucket.tokens
            return SignupRateLimitDecision(
                allowed=False,
                remaining=bucket.tokens,
                capacity=self._capacity,
                retry_after_seconds=shortfall / self._refill_per_second,
            )

    async def reset(self, source: str | None = None) -> None:
        """Drop bucket state. Used by tests."""
        async with self._registry_lock:
            if source is None:
                self._buckets.clear()
            else:
                self._buckets.pop(source, None)

    async def _get_bucket(self, key: str) -> _SignupBucket:
        bucket = self._buckets.get(key)
        if bucket is not None:
            return bucket
        async with self._registry_lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = _SignupBucket(
                    capacity=self._capacity,
                    refill_per_second=self._refill_per_second,
                    tokens=self._capacity,
                )
                self._buckets[key] = bucket
            return bucket


_signup_rate_limiter = SignupRateLimiter()


def get_signup_rate_limiter() -> SignupRateLimiter:
    """Return the process-wide signup rate limiter singleton."""
    return _signup_rate_limiter
