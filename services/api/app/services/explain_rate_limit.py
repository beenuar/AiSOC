"""Per-tenant token-bucket rate limiter for the alert-explain endpoint.

The explain endpoint hits an LLM on every successful call and runs
two analytics queries (rule lineage + historical FP rate). Without a
per-tenant cap a runaway agent loop, a misconfigured frontend, or a
bored analyst clicking "explain" in a tight loop can:

  1. Burn LLM budget faster than the cost dashboard can update.
  2. Drive concurrency on the analytics queries through the floor.

The lake API already proved out a token-bucket limiter
(:mod:`app.services.lake_rate_limit`); we instantiate a second bucket
with explain-tuned defaults rather than refactoring that module
mid-flight. The class is identical in spirit (lazy-refill,
per-tenant, asyncio-safe) but the defaults are tighter to reflect
the cost profile:

  * **capacity = 20** — a human triaging an incident might explain a
    handful of related alerts in a row; 20 lets that happen without
    pause while still capping a runaway loop.
  * **refill = 0.2 / sec** — sustained 12 explains/minute. A
    well-behaved console will stay well under this even during a
    busy shift.

Operators can override both via env vars without code changes.
"""

from __future__ import annotations

import asyncio
import os
import time
from dataclasses import dataclass, field
from uuid import UUID

# Defaults tuned for explain-call cost profile.
_DEFAULT_CAPACITY: float = 20.0
_DEFAULT_REFILL: float = 0.2  # tokens / second → 12/minute sustained


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
class _ExplainBucket:
    """One tenant's bucket. Identical machinery to the lake limiter."""

    capacity: float
    refill_per_second: float
    tokens: float = field(default=_DEFAULT_CAPACITY)
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
class ExplainRateLimitDecision:
    """Outcome of an :meth:`acquire` attempt."""

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
            # RFC 7231 §7.1.3: integer seconds, non-negative.
            headers["Retry-After"] = f"{max(1, int(self.retry_after_seconds + 0.999))}"
        return headers


class ExplainRateLimiter:
    """Per-tenant token-bucket limiter for the explain endpoint.

    See module docstring for the design rationale and the rationale
    for the explain-specific defaults. The ``cost`` parameter exists
    so we can charge differently when (eventually) the explain payload
    grows a "deep" mode that triggers additional LLM calls.
    """

    def __init__(
        self,
        *,
        capacity: float | None = None,
        refill_per_second: float | None = None,
    ) -> None:
        cap = capacity if capacity is not None else _env_float("AISOC_EXPLAIN_RATE_CAPACITY", _DEFAULT_CAPACITY)
        ref = refill_per_second if refill_per_second is not None else _env_float("AISOC_EXPLAIN_RATE_REFILL", _DEFAULT_REFILL)
        if cap <= 0:
            raise ValueError("capacity must be positive")
        if ref <= 0:
            raise ValueError("refill_per_second must be positive")
        self._capacity = cap
        self._refill_per_second = ref
        self._buckets: dict[str, _ExplainBucket] = {}
        self._registry_lock = asyncio.Lock()

    async def acquire(
        self,
        tenant_id: UUID | str,
        *,
        cost: float = 1.0,
    ) -> ExplainRateLimitDecision:
        """Attempt to consume ``cost`` tokens for ``tenant_id``."""
        if cost <= 0:
            raise ValueError("cost must be positive")
        if cost > self._capacity:
            raise ValueError(f"cost {cost} exceeds capacity {self._capacity}; would never succeed")

        bucket = await self._get_bucket(str(tenant_id))
        async with bucket.lock:
            now = time.monotonic()
            bucket._refill(now)
            if bucket.tokens >= cost:
                bucket.tokens -= cost
                return ExplainRateLimitDecision(
                    allowed=True,
                    remaining=bucket.tokens,
                    capacity=self._capacity,
                    retry_after_seconds=0.0,
                )
            shortfall = cost - bucket.tokens
            return ExplainRateLimitDecision(
                allowed=False,
                remaining=bucket.tokens,
                capacity=self._capacity,
                retry_after_seconds=shortfall / self._refill_per_second,
            )

    async def reset(self, tenant_id: UUID | str | None = None) -> None:
        """Drop bucket state. Used by tests and (potentially) admins."""
        async with self._registry_lock:
            if tenant_id is None:
                self._buckets.clear()
            else:
                self._buckets.pop(str(tenant_id), None)

    async def _get_bucket(self, key: str) -> _ExplainBucket:
        bucket = self._buckets.get(key)
        if bucket is not None:
            return bucket
        async with self._registry_lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = _ExplainBucket(
                    capacity=self._capacity,
                    refill_per_second=self._refill_per_second,
                    tokens=self._capacity,
                )
                self._buckets[key] = bucket
            return bucket


# Process-wide singleton. Mirrors the lake-limiter convention: tests
# call ``reset`` on the singleton rather than reconstructing the
# limiter so they don't fight import-time wiring.
_explain_rate_limiter = ExplainRateLimiter()


def get_explain_rate_limiter() -> ExplainRateLimiter:
    """Return the process-wide explain rate limiter singleton."""
    return _explain_rate_limiter
