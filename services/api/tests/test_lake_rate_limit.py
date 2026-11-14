"""Unit tests for the per-tenant token-bucket rate limiter (Workstream 7).

These tests exercise the limiter in isolation — no FastAPI, no
ClickHouse, no audit log. They focus on three properties:

1. **Soft cap, not hard cap.** The bucket allows bursts up to capacity
   and then degrades to the steady refill rate. This lets a human poke
   around the lake without getting 429'd while still capping a runaway
   agent loop.
2. **Tenant isolation.** A noisy tenant must not be able to drain
   another tenant's budget. This is the core security property the
   limiter exists to provide; if it fails, one tenant DoSing themselves
   would propagate to every other tenant in the same API pod.
3. **Refill correctness.** Lazy refill must be mathematically
   equivalent to a continuous leaky-bucket model. Off-by-one errors in
   the time math here are very common, so we use a controllable
   monotonic clock to make the assertions deterministic.

We deliberately do *not* sleep in tests; we patch ``time.monotonic`` so
each test runs in milliseconds. Sleeping in unit tests is the surest
way to get a flaky CI suite, and the limiter exposes its time source
implicitly through ``time.monotonic`` in :func:`_TokenBucket._refill`.

A wrinkle worth noting: ``_TokenBucket.last_refill`` is initialised via
``field(default_factory=time.monotonic)``, and ``default_factory``
captures the function reference at class-definition time. That
reference is never re-bound by ``unittest.mock.patch``, so a freshly
constructed bucket inside a patched block still records the *real*
monotonic clock as its ``last_refill``. When the patched clock is
smaller than the real one, ``_refill``'s ``max(0.0, now - last)``
guard keeps the bucket frozen at zero refill forever. The fix in
these tests is :func:`_seed_bucket`, which forces bucket creation
and snaps ``last_refill`` to the patched time before we exercise
the public API. Yes, this reaches into a private attribute — but
the alternative is asking the implementation to accept a clock
injection point purely for tests, which would muddy the production
hot path.
"""

from __future__ import annotations

from unittest.mock import patch
from uuid import UUID, uuid4

import pytest
from app.services.lake_rate_limit import (
    DEFAULT_CAPACITY,
    DEFAULT_REFILL_PER_SECOND,
    LakeRateLimiter,
    RateLimitDecision,
)


async def _seed_bucket(
    limiter: LakeRateLimiter,
    tenant: UUID | str,
    *,
    at_time: float,
) -> None:
    """Force-create a tenant bucket and align its ``last_refill`` clock.

    Required because the dataclass's ``default_factory=time.monotonic``
    binds the real clock at import time and ignores ``patch``. See
    module docstring for the gory details.
    """

    bucket = await limiter._get_bucket(str(tenant))  # noqa: SLF001
    bucket.last_refill = at_time


# ---------------------------------------------------------------------------
# Construction validation
# ---------------------------------------------------------------------------


class TestConstruction:
    """The constructor rejects nonsensical configurations early.

    We'd rather blow up at process boot than silently misbehave at
    request time — a zero-capacity bucket would deny every request,
    which is hard to diagnose from a single 429 in production logs.
    """

    def test_zero_capacity_rejected(self) -> None:
        with pytest.raises(ValueError, match="capacity must be positive"):
            LakeRateLimiter(capacity=0.0)

    def test_negative_capacity_rejected(self) -> None:
        with pytest.raises(ValueError, match="capacity must be positive"):
            LakeRateLimiter(capacity=-1.0)

    def test_zero_refill_rate_rejected(self) -> None:
        with pytest.raises(ValueError, match="refill_per_second must be positive"):
            LakeRateLimiter(refill_per_second=0.0)

    def test_negative_refill_rate_rejected(self) -> None:
        with pytest.raises(ValueError, match="refill_per_second must be positive"):
            LakeRateLimiter(refill_per_second=-0.5)


# ---------------------------------------------------------------------------
# Basic acquire semantics
# ---------------------------------------------------------------------------


class TestAcquire:
    """Single-tenant, single-bucket acquire behaviour."""

    @pytest.mark.asyncio
    async def test_first_request_succeeds(self) -> None:
        # The bucket starts full, so a fresh tenant's first request
        # should always succeed even before any refill has happened.
        # This matters for the "click and connect" UX: a user who just
        # finished onboarding shouldn't see a 429 on their very first
        # query.
        limiter = LakeRateLimiter(capacity=10.0, refill_per_second=1.0)
        decision = await limiter.acquire(uuid4())

        assert decision.allowed is True
        assert decision.remaining == pytest.approx(9.0)
        assert decision.capacity == 10.0
        assert decision.retry_after_seconds == 0.0

    @pytest.mark.asyncio
    async def test_burst_drains_bucket(self) -> None:
        # We can fire ``capacity`` requests in immediate succession and
        # the bucket should report the residual on each call. The 10th
        # request leaves remaining=0; an 11th would fail. We freeze time
        # so the lazy refill doesn't add fractional tokens between
        # acquires — without this the assertion against an exact
        # remaining count is racy on slow CI.
        limiter = LakeRateLimiter(capacity=10.0, refill_per_second=1.0)
        tenant = uuid4()

        with patch("app.services.lake_rate_limit.time.monotonic", return_value=1000.0):
            await _seed_bucket(limiter, tenant, at_time=1000.0)
            for expected_remaining in range(9, -1, -1):
                decision = await limiter.acquire(tenant)
                assert decision.allowed is True
                assert decision.remaining == pytest.approx(float(expected_remaining))

    @pytest.mark.asyncio
    async def test_request_after_burst_denied(self) -> None:
        # Once the bucket hits zero, the next acquisition must fail
        # *and* return a sensible Retry-After. Without it the client
        # has no signal for how long to back off and will likely
        # hammer us in a tight loop.
        limiter = LakeRateLimiter(capacity=2.0, refill_per_second=1.0)
        tenant = uuid4()

        # Drain the bucket. We freeze time so the lazy refill doesn't
        # add fractional tokens between acquires.
        with patch("app.services.lake_rate_limit.time.monotonic", return_value=1000.0):
            await limiter.acquire(tenant)
            await limiter.acquire(tenant)
            decision = await limiter.acquire(tenant)

        assert decision.allowed is False
        assert decision.remaining == pytest.approx(0.0)
        # 1 token short, refill rate 1/sec → 1 second wait. We assert
        # approx because float-math tends to leave a few epsilons
        # lying around even after we freeze the clock.
        assert decision.retry_after_seconds == pytest.approx(1.0)

    @pytest.mark.asyncio
    async def test_zero_cost_rejected(self) -> None:
        # A zero-cost acquire is meaningless: you either want to
        # consume budget or you want to peek. The dedicated
        # :meth:`peek` method is the right tool, and accepting cost=0
        # in :meth:`acquire` would invite a subtle code path where a
        # caller forgets to set cost and silently bypasses the
        # limiter.
        limiter = LakeRateLimiter()
        with pytest.raises(ValueError, match="cost must be positive"):
            await limiter.acquire(uuid4(), cost=0.0)

    @pytest.mark.asyncio
    async def test_negative_cost_rejected(self) -> None:
        limiter = LakeRateLimiter()
        with pytest.raises(ValueError, match="cost must be positive"):
            await limiter.acquire(uuid4(), cost=-1.0)

    @pytest.mark.asyncio
    async def test_cost_exceeding_capacity_raises(self) -> None:
        # A request asking for more than the bucket can ever hold is
        # a programmer error, not a runtime denial. If we returned a
        # plain "denied" the caller could loop forever and never
        # succeed. We surface it as a hard exception.
        limiter = LakeRateLimiter(capacity=10.0)
        with pytest.raises(ValueError, match="exceeds bucket capacity"):
            await limiter.acquire(uuid4(), cost=11.0)


# ---------------------------------------------------------------------------
# Tenant isolation
# ---------------------------------------------------------------------------


class TestTenantIsolation:
    """One tenant draining their bucket must not affect others.

    This is the property that distinguishes this limiter from a
    cluster-wide rate limit. If isolation breaks, the limiter has
    failed at its primary job.
    """

    @pytest.mark.asyncio
    async def test_separate_tenants_have_separate_buckets(self) -> None:
        limiter = LakeRateLimiter(capacity=2.0, refill_per_second=1.0)
        tenant_a = uuid4()
        tenant_b = uuid4()

        with patch("app.services.lake_rate_limit.time.monotonic", return_value=1000.0):
            # Drain A's bucket completely.
            await limiter.acquire(tenant_a)
            await limiter.acquire(tenant_a)
            denied = await limiter.acquire(tenant_a)
            assert denied.allowed is False

            # B should still have a full bucket; A's misbehaviour must
            # not bleed across.
            allowed = await limiter.acquire(tenant_b)
            assert allowed.allowed is True
            assert allowed.remaining == pytest.approx(1.0)

    @pytest.mark.asyncio
    async def test_uuid_and_string_keys_are_equivalent(self) -> None:
        # The endpoint passes ``UUID``; tests sometimes pass strings.
        # The same tenant identifier in either form must hit the same
        # bucket — otherwise an attacker could bypass their limit by
        # alternating between uuid form and stringified form (we
        # control both sides in practice, but defensive checks are
        # cheap).
        limiter = LakeRateLimiter(capacity=2.0, refill_per_second=1.0)
        tenant = uuid4()

        with patch("app.services.lake_rate_limit.time.monotonic", return_value=1000.0):
            await limiter.acquire(tenant)
            await limiter.acquire(str(tenant))
            decision = await limiter.acquire(tenant)

        # Both forms drained the same bucket, so the third request
        # must be denied.
        assert decision.allowed is False


# ---------------------------------------------------------------------------
# Refill behaviour
# ---------------------------------------------------------------------------


class TestRefill:
    """Lazy refill is the trickiest piece of the limiter.

    We need to confirm: tokens accumulate over time, the bucket caps
    at capacity (no infinite-burst credits for idle tenants), and the
    last-refill timestamp advances monotonically.
    """

    @pytest.mark.asyncio
    async def test_tokens_refill_after_wait(self) -> None:
        limiter = LakeRateLimiter(capacity=10.0, refill_per_second=2.0)
        tenant = uuid4()

        # Drain to zero at t=1000. Seed the bucket's clock first so
        # the first ``_refill`` call sees ``elapsed=0`` instead of a
        # bogus negative-then-clamped value.
        with patch("app.services.lake_rate_limit.time.monotonic", return_value=1000.0):
            await _seed_bucket(limiter, tenant, at_time=1000.0)
            for _ in range(10):
                await limiter.acquire(tenant)

        # 3 seconds later → 6 tokens refilled (2/sec * 3s).
        with patch("app.services.lake_rate_limit.time.monotonic", return_value=1003.0):
            decision = await limiter.acquire(tenant, cost=5.0)
            assert decision.allowed is True
            # 6 refilled - 5 consumed = 1 left.
            assert decision.remaining == pytest.approx(1.0)

    @pytest.mark.asyncio
    async def test_refill_caps_at_capacity(self) -> None:
        # If a tenant goes silent for an hour the bucket should still
        # only be ``capacity`` tokens, not ``elapsed * refill_rate``.
        # This prevents a long-idle tenant from suddenly being able
        # to fire thousands of queries in a burst.
        limiter = LakeRateLimiter(capacity=10.0, refill_per_second=1.0)
        tenant = uuid4()

        # Drain to zero at t=1000.
        with patch("app.services.lake_rate_limit.time.monotonic", return_value=1000.0):
            await _seed_bucket(limiter, tenant, at_time=1000.0)
            for _ in range(10):
                await limiter.acquire(tenant)

        # 1 hour later — well past full refill.
        with patch("app.services.lake_rate_limit.time.monotonic", return_value=4600.0):
            decision = await limiter.peek(tenant)
            # Capped at 10, not 3600.
            assert decision.remaining == pytest.approx(10.0)

    @pytest.mark.asyncio
    async def test_refill_handles_clock_going_backwards(self) -> None:
        # ``time.monotonic`` in CPython never goes backwards, but
        # mocks can — and so can poorly-virtualised hosts. The
        # ``elapsed = max(0.0, now - last)`` clamp in the
        # implementation is the only line that prevents an
        # accidental ``tokens -= negative`` from materialising free
        # budget. Worth pinning down with a test.
        limiter = LakeRateLimiter(capacity=10.0, refill_per_second=1.0)
        tenant = uuid4()

        with patch("app.services.lake_rate_limit.time.monotonic", return_value=1000.0):
            await _seed_bucket(limiter, tenant, at_time=1000.0)
            await limiter.acquire(tenant)  # 9 left.

        # Pretend the clock jumped backwards — no token should be
        # subtracted, no bonus refill should happen.
        with patch("app.services.lake_rate_limit.time.monotonic", return_value=999.0):
            decision = await limiter.peek(tenant)
            assert decision.remaining == pytest.approx(9.0)


# ---------------------------------------------------------------------------
# RateLimitDecision presentation
# ---------------------------------------------------------------------------


class TestDecisionHeaders:
    """Headers must be parseable by standard HTTP clients.

    We use the ``X-RateLimit-*`` family because most operator
    dashboards already speak it. Bugs in this layer are visible to
    every API caller, so we exercise both the allowed and denied
    code paths.
    """

    def test_allowed_decision_has_no_retry_after(self) -> None:
        decision = RateLimitDecision(
            allowed=True,
            remaining=4.5,
            capacity=10.0,
            retry_after_seconds=0.0,
        )
        headers = decision.to_headers()
        assert headers["X-RateLimit-Limit"] == "10"
        # Remaining is floored, not rounded — we never want to lie
        # *up* about budget.
        assert headers["X-RateLimit-Remaining"] == "4"
        assert "Retry-After" not in headers

    def test_denied_decision_has_retry_after(self) -> None:
        decision = RateLimitDecision(
            allowed=False,
            remaining=0.0,
            capacity=10.0,
            retry_after_seconds=2.3,
        )
        headers = decision.to_headers()
        assert headers["Retry-After"] == "3"  # ceil(2.3 + epsilon)

    def test_retry_after_minimum_one_second(self) -> None:
        # RFC 7231 §7.1.3 requires Retry-After to be a non-negative
        # integer; we floor to 1 so a sub-second wait still gives
        # the client *some* delay rather than a "retry now" loop.
        decision = RateLimitDecision(
            allowed=False,
            remaining=0.0,
            capacity=10.0,
            retry_after_seconds=0.1,
        )
        headers = decision.to_headers()
        assert headers["Retry-After"] == "1"

    def test_remaining_clamped_at_zero(self) -> None:
        # Floats can land at -1e-15 due to rounding; the header must
        # be ``0`` not ``-1``. Negative remaining headers break some
        # client SDKs that parse with ``unsigned int``.
        decision = RateLimitDecision(
            allowed=False,
            remaining=-1e-12,
            capacity=10.0,
            retry_after_seconds=0.5,
        )
        assert decision.to_headers()["X-RateLimit-Remaining"] == "0"


# ---------------------------------------------------------------------------
# Cost-weighted acquisition
# ---------------------------------------------------------------------------


class TestCostedAcquire:
    """Variable cost lets the endpoint price work-not-requests."""

    @pytest.mark.asyncio
    async def test_costed_acquire_consumes_proportionally(self) -> None:
        limiter = LakeRateLimiter(capacity=10.0, refill_per_second=1.0)
        tenant = uuid4()

        with patch("app.services.lake_rate_limit.time.monotonic", return_value=1000.0):
            decision = await limiter.acquire(tenant, cost=3.5)
            assert decision.allowed is True
            assert decision.remaining == pytest.approx(6.5)

    @pytest.mark.asyncio
    async def test_partial_balance_with_high_cost_denied(self) -> None:
        # Bucket has 5 tokens but caller wants 8; this must be
        # denied with a Retry-After computed from the shortfall.
        limiter = LakeRateLimiter(capacity=10.0, refill_per_second=1.0)
        tenant = uuid4()

        with patch("app.services.lake_rate_limit.time.monotonic", return_value=1000.0):
            await limiter.acquire(tenant, cost=5.0)  # 5 left.
            decision = await limiter.acquire(tenant, cost=8.0)

        assert decision.allowed is False
        # Shortfall = 3 tokens; refill 1/sec → 3 seconds wait.
        assert decision.retry_after_seconds == pytest.approx(3.0)


# ---------------------------------------------------------------------------
# Reset semantics
# ---------------------------------------------------------------------------


class TestReset:
    """Reset is used by tests and operator emergency procedures."""

    @pytest.mark.asyncio
    async def test_targeted_reset_only_clears_named_tenant(self) -> None:
        limiter = LakeRateLimiter(capacity=2.0, refill_per_second=1.0)
        tenant_a, tenant_b = uuid4(), uuid4()

        with patch("app.services.lake_rate_limit.time.monotonic", return_value=1000.0):
            await limiter.acquire(tenant_a)
            await limiter.acquire(tenant_a)
            await limiter.acquire(tenant_b)

            await limiter.reset(tenant_a)

            # A is fresh — full bucket again.
            decision_a = await limiter.peek(tenant_a)
            assert decision_a.remaining == pytest.approx(2.0)

            # B is untouched — still 1 token left.
            decision_b = await limiter.peek(tenant_b)
            assert decision_b.remaining == pytest.approx(1.0)

    @pytest.mark.asyncio
    async def test_global_reset_clears_everything(self) -> None:
        limiter = LakeRateLimiter(capacity=2.0, refill_per_second=1.0)
        tenant_a, tenant_b = uuid4(), uuid4()

        with patch("app.services.lake_rate_limit.time.monotonic", return_value=1000.0):
            await limiter.acquire(tenant_a)
            await limiter.acquire(tenant_b)
            await limiter.reset()

            assert (await limiter.peek(tenant_a)).remaining == pytest.approx(2.0)
            assert (await limiter.peek(tenant_b)).remaining == pytest.approx(2.0)


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------


class TestDefaults:
    """Sanity checks on the module-level defaults.

    The default capacity (60) and refill rate (1/sec) are tuned for
    "human pokes around the lake for a couple minutes without
    thinking about it". If we change those defaults, downstream
    operator runbooks need to be updated; pinning them in a test
    forces a deliberate decision.
    """

    def test_default_capacity_is_sixty(self) -> None:
        assert DEFAULT_CAPACITY == 60.0

    def test_default_refill_is_one_per_second(self) -> None:
        assert DEFAULT_REFILL_PER_SECOND == 1.0
