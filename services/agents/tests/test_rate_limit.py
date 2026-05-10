"""Unit tests for the per-key token-bucket limiter used by /api/v1/explain.

These tests exercise the limiter directly so we can prove the algorithm
without dragging in FastAPI, structlog, or the explain endpoint. Endpoint-
level assertions (correct headers, 429 status, NDJSON error frame) live in
``test_explain_endpoint.py``.

Time control
------------
Most assertions don't need a fake clock — the algorithm is deterministic
once the bucket is constructed. The refill test uses a *very* short real
sleep (≤25 ms) instead of monkeypatching ``time.monotonic`` because the
dataclass captures the real function in ``default_factory`` at class
definition, so patching the module's ``time`` symbol doesn't reach the
bucket's ``last_refill`` initialiser. Real-time sleeps keep the test
honest and avoid a brittle "patch everything" setup.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

_AGENTS_ROOT = Path(__file__).resolve().parents[1]
if str(_AGENTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_AGENTS_ROOT))

from app.core.rate_limit import (  # noqa: E402
    RateLimitDecision,
    TokenBucketLimiter,
    _TokenBucket,
)

# ---------------------------------------------------------------------------
# RateLimitDecision.to_headers
# ---------------------------------------------------------------------------


def test_to_headers_allowed_omits_retry_after() -> None:
    decision = RateLimitDecision(allowed=True, remaining=4.5, capacity=10.0, retry_after_seconds=0.0)
    headers = decision.to_headers()
    assert headers == {"X-RateLimit-Limit": "10", "X-RateLimit-Remaining": "4"}
    assert "Retry-After" not in headers


def test_to_headers_denied_rounds_retry_after_up() -> None:
    decision = RateLimitDecision(allowed=False, remaining=0.0, capacity=20.0, retry_after_seconds=0.001)
    headers = decision.to_headers()
    # 0.001s rounds up to 1 second so a client that retries at Retry-After
    # doesn't bounce off the bucket again.
    assert headers["Retry-After"] == "1"
    assert headers["X-RateLimit-Limit"] == "20"
    assert headers["X-RateLimit-Remaining"] == "0"


def test_to_headers_denied_retry_after_handles_partial_seconds() -> None:
    decision = RateLimitDecision(allowed=False, remaining=0.3, capacity=5.0, retry_after_seconds=2.4)
    headers = decision.to_headers()
    # 2.4 + 0.999 -> int -> 3
    assert headers["Retry-After"] == "3"


# ---------------------------------------------------------------------------
# Construction guards
# ---------------------------------------------------------------------------


def test_capacity_must_be_positive() -> None:
    with pytest.raises(ValueError, match="capacity must be positive"):
        TokenBucketLimiter(capacity=0, refill_per_second=1.0)
    with pytest.raises(ValueError, match="capacity must be positive"):
        TokenBucketLimiter(capacity=-1.0, refill_per_second=1.0)


def test_refill_must_be_positive() -> None:
    with pytest.raises(ValueError, match="refill_per_second must be positive"):
        TokenBucketLimiter(capacity=5.0, refill_per_second=0)
    with pytest.raises(ValueError, match="refill_per_second must be positive"):
        TokenBucketLimiter(capacity=5.0, refill_per_second=-1.0)


# ---------------------------------------------------------------------------
# acquire()
# ---------------------------------------------------------------------------


async def test_first_request_starts_full() -> None:
    """A fresh bucket starts full so cold-start UX is not punished."""
    limiter = TokenBucketLimiter(capacity=3.0, refill_per_second=1.0)
    decision = await limiter.acquire("tenant:a")
    assert decision.allowed is True
    assert decision.capacity == 3.0
    # Started at capacity 3, consumed 1 → 2 remaining.
    assert decision.remaining == pytest.approx(2.0)
    assert decision.retry_after_seconds == 0.0


async def test_each_acquire_decrements_one_token() -> None:
    # Use a near-zero refill so the natural sub-millisecond drift between
    # rapid acquires can't tip ``remaining`` above the integer we expect.
    limiter = TokenBucketLimiter(capacity=3.0, refill_per_second=0.0001)
    for expected_remaining in (2.0, 1.0, 0.0):
        decision = await limiter.acquire("tenant:a")
        assert decision.allowed is True
        assert decision.remaining == pytest.approx(expected_remaining, abs=1e-3)


async def test_exhausted_bucket_denies_with_retry_after() -> None:
    limiter = TokenBucketLimiter(capacity=2.0, refill_per_second=4.0)
    # Drain the bucket.
    await limiter.acquire("tenant:a")
    await limiter.acquire("tenant:a")
    # Third call is throttled.
    decision = await limiter.acquire("tenant:a")
    assert decision.allowed is False
    # remaining should be < 1.0 after two drains and barely-any-refill.
    assert decision.remaining < 1.0
    # shortfall=1-tokens, refill=4/s, so retry_after ≈ shortfall/4 ≤ 0.25s.
    assert 0.0 < decision.retry_after_seconds <= 0.25


async def test_independent_buckets_per_key() -> None:
    """Tenant A draining its bucket must not affect tenant B."""
    limiter = TokenBucketLimiter(capacity=1.0, refill_per_second=1.0)
    a1 = await limiter.acquire("tenant:a")
    a2 = await limiter.acquire("tenant:a")
    b1 = await limiter.acquire("tenant:b")
    assert a1.allowed is True
    assert a2.allowed is False  # tenant:a drained
    assert b1.allowed is True  # tenant:b is fresh


async def test_refill_after_real_time_passes() -> None:
    """Tokens refill at the configured rate.

    We use a high refill rate so the test stays quick. With 100 tokens/sec
    and a 30 ms sleep we expect ~3 tokens back, which is more than enough
    to flip the next acquire from denied to allowed.
    """
    limiter = TokenBucketLimiter(capacity=1.0, refill_per_second=100.0)
    first = await limiter.acquire("tenant:a")
    assert first.allowed is True
    second = await limiter.acquire("tenant:a")
    assert second.allowed is False
    # Wait long enough for the bucket to refill at least one token.
    await asyncio.sleep(0.03)
    third = await limiter.acquire("tenant:a")
    assert third.allowed is True


async def test_refill_caps_at_capacity() -> None:
    """A bucket sitting idle for a long time must not exceed its capacity."""
    limiter = TokenBucketLimiter(capacity=2.0, refill_per_second=1000.0)
    # Drain the bucket.
    await limiter.acquire("tenant:a")
    await limiter.acquire("tenant:a")
    # Sleep long enough to refill thousands of tokens at the configured
    # rate; remaining must still cap at capacity-1 after the next acquire.
    await asyncio.sleep(0.05)
    decision = await limiter.acquire("tenant:a")
    assert decision.allowed is True
    # After refill capping at 2 then consuming 1, ≤1 token is left.
    assert decision.remaining <= 1.0


async def test_acquire_with_zero_or_negative_cost_rejected() -> None:
    limiter = TokenBucketLimiter(capacity=5.0, refill_per_second=1.0)
    with pytest.raises(ValueError, match="cost must be positive"):
        await limiter.acquire("tenant:a", cost=0)
    with pytest.raises(ValueError, match="cost must be positive"):
        await limiter.acquire("tenant:a", cost=-1.0)


async def test_acquire_with_cost_above_capacity_rejected() -> None:
    """A request that could never succeed is a programming bug, not a 429."""
    limiter = TokenBucketLimiter(capacity=2.0, refill_per_second=1.0)
    with pytest.raises(ValueError, match="exceeds bucket capacity"):
        await limiter.acquire("tenant:a", cost=3.0)


async def test_custom_cost_drains_bucket() -> None:
    limiter = TokenBucketLimiter(capacity=10.0, refill_per_second=1.0)
    decision = await limiter.acquire("tenant:a", cost=4.0)
    assert decision.allowed is True
    assert decision.remaining == pytest.approx(6.0)


# ---------------------------------------------------------------------------
# reset()
# ---------------------------------------------------------------------------


async def test_reset_specific_key_only_clears_that_key() -> None:
    limiter = TokenBucketLimiter(capacity=1.0, refill_per_second=1.0)
    # Drain both keys.
    await limiter.acquire("tenant:a")
    await limiter.acquire("tenant:b")
    # Confirm both are throttled.
    assert (await limiter.acquire("tenant:a")).allowed is False
    assert (await limiter.acquire("tenant:b")).allowed is False
    # Reset only tenant:a.
    await limiter.reset("tenant:a")
    assert (await limiter.acquire("tenant:a")).allowed is True
    # tenant:b is still throttled (its bucket was not reset).
    assert (await limiter.acquire("tenant:b")).allowed is False


async def test_reset_all_clears_every_bucket() -> None:
    limiter = TokenBucketLimiter(capacity=1.0, refill_per_second=1.0)
    await limiter.acquire("tenant:a")
    await limiter.acquire("tenant:b")
    await limiter.reset()  # nuke everything
    assert (await limiter.acquire("tenant:a")).allowed is True
    assert (await limiter.acquire("tenant:b")).allowed is True


# ---------------------------------------------------------------------------
# Concurrency
# ---------------------------------------------------------------------------


async def test_concurrent_acquires_never_overdraw() -> None:
    """Per-key lock must prevent two coroutines double-spending a token."""
    limiter = TokenBucketLimiter(capacity=5.0, refill_per_second=0.5)
    # Fire 20 concurrent acquires against the same key.
    decisions = await asyncio.gather(*(limiter.acquire("tenant:a") for _ in range(20)))
    # Bucket starts at 5; refill at 0.5/s for sub-millisecond spread is
    # ~negligible, so we expect exactly 5 successes (with at most a
    # tiny epsilon worth of refill).
    allowed_count = sum(1 for d in decisions if d.allowed)
    assert 5 <= allowed_count <= 6, f"expected 5–6 allowed under high concurrency, got {allowed_count}"
    denied = [d for d in decisions if not d.allowed]
    assert all(d.retry_after_seconds > 0 for d in denied)


# ---------------------------------------------------------------------------
# _TokenBucket internal sanity (defensive — confirms the dataclass invariant)
# ---------------------------------------------------------------------------


def test_token_bucket_starts_full_even_when_field_default_is_zero() -> None:
    """The dataclass post-init normalises tokens to capacity on construction.

    This is what protects new keys from being throttled on their first
    request.
    """
    bucket = _TokenBucket(capacity=7.0, refill_per_second=1.0)
    assert bucket.tokens == 7.0
