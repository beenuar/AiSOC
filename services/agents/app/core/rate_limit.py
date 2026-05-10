"""Per-key token-bucket rate limiter for the agents service.

This is a stripped-down sibling of ``services/api/app/services/lake_rate_limit.py``.
We can't share the module across services without inventing a shared
package, but we keep the algorithm and the public surface deliberately
identical so a future ``packages/sdk-py`` can consolidate them.

Why a token bucket here
-----------------------

The ``/api/v1/explain`` endpoint can fan out to an outbound LLM call per
request. A noisy frontend (or a hostile script) hammering Explain
against every alert in the grid would burn token budget and stall every
other analyst's drawer behind the queued LLM calls.

Token buckets give us:

* Fast cold-start behaviour — an analyst opening Explain ten times in
  ten seconds while triaging is still well under burst capacity.
* Smooth steady-state pressure — a runaway loop is throttled to the
  refill rate, not "the next minute window".
* O(1) per-request cost — no Redis round trip on the hot path.

In-memory, per-process. Acceptable for v1 because we ship a single
agents pod by default; documented in the PROGRESS log so that the day
we horizontally scale we either move to Redis or accept the under-
enforcement-by-N-pods factor.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field


@dataclass
class _TokenBucket:
    """One key's bucket. Refills lazily on each acquire."""

    capacity: float
    refill_per_second: float
    tokens: float = field(default=0.0)
    last_refill: float = field(default_factory=time.monotonic)
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    def __post_init__(self) -> None:
        # Start full so the first request from a key always succeeds —
        # we throttle sustained load, not cold starts.
        if self.tokens <= 0.0 or self.tokens > self.capacity:
            self.tokens = self.capacity

    def _refill(self, now: float) -> None:
        elapsed = max(0.0, now - self.last_refill)
        if elapsed > 0.0:
            self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_per_second)
            self.last_refill = now


@dataclass(frozen=True)
class RateLimitDecision:
    """Outcome of an :meth:`TokenBucketLimiter.acquire` attempt."""

    allowed: bool
    remaining: float
    capacity: float
    retry_after_seconds: float

    def to_headers(self) -> dict[str, str]:
        """Render the de-facto ``X-RateLimit-*`` family.

        Matches the lake limiter so operator dashboards parse one set
        of headers across services.
        """
        headers = {
            "X-RateLimit-Limit": f"{int(self.capacity)}",
            "X-RateLimit-Remaining": f"{max(0, int(self.remaining))}",
        }
        if not self.allowed:
            # RFC 7231 §7.1.3 — non-negative integer seconds. Round up
            # so a client that retries exactly at Retry-After doesn't
            # bounce off the bucket again.
            headers["Retry-After"] = f"{max(1, int(self.retry_after_seconds + 0.999))}"
        return headers


class TokenBucketLimiter:
    """Process-wide, key-scoped token-bucket limiter.

    The key is opaque — the explain endpoint uses ``tenant_id`` (or
    falls back to client IP for unauthenticated traffic). Other callers
    can use whatever scoping they need.
    """

    def __init__(self, *, capacity: float, refill_per_second: float) -> None:
        if capacity <= 0:
            raise ValueError("capacity must be positive")
        if refill_per_second <= 0:
            raise ValueError("refill_per_second must be positive")
        self._capacity = capacity
        self._refill_per_second = refill_per_second
        self._buckets: dict[str, _TokenBucket] = {}
        self._registry_lock = asyncio.Lock()

    async def acquire(self, key: str, *, cost: float = 1.0) -> RateLimitDecision:
        """Try to consume ``cost`` tokens for ``key``.

        Never raises on the rate-limited path; the caller decides how
        to surface the 429 (FastAPI ``HTTPException`` with headers, or
        a structured NDJSON error frame).
        """
        if cost <= 0:
            raise ValueError("cost must be positive")
        if cost > self._capacity:
            raise ValueError(f"cost {cost} exceeds bucket capacity {self._capacity}; this would never succeed")

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
            shortfall = cost - bucket.tokens
            return RateLimitDecision(
                allowed=False,
                remaining=bucket.tokens,
                capacity=self._capacity,
                retry_after_seconds=shortfall / self._refill_per_second,
            )

    async def reset(self, key: str | None = None) -> None:
        """Drop one bucket or the whole registry. Used by tests."""
        async with self._registry_lock:
            if key is None:
                self._buckets.clear()
            else:
                self._buckets.pop(key, None)

    async def _get_bucket(self, key: str) -> _TokenBucket:
        bucket = self._buckets.get(key)
        if bucket is not None:
            return bucket
        async with self._registry_lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = _TokenBucket(
                    capacity=self._capacity,
                    refill_per_second=self._refill_per_second,
                )
                self._buckets[key] = bucket
            return bucket
