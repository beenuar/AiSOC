"""Repeated credential failures are throttled and eventually locked out.

Fifty wrong passwords for one account inside a minute all returned 401, with
no delay and no lockout, and `SECURITY.md` told readers rate limiting lived in
`services/api/app/middleware/` — a directory holding exactly two files,
neither of which is a limiter.

Four properties are asserted here, and three of them are the ones a throttle
usually gets wrong:

* the reply is identical for an account that exists and one that does not,
  because a throttle that only engages for real accounts is a
  user-enumeration oracle;
* a success clears the **account** counter and not the **source** counter, so
  an attacker who guesses one password out of a thousand attempts cannot
  reset their own budget with it;
* password spraying trips the source counter without ever tripping an account
  counter, which is the attack a single per-account limiter misses entirely;
* Redis being down degrades to per-replica counting rather than locking every
  operator out of their own console.
"""

from __future__ import annotations

import time

import pytest
from app.services import login_throttle
from app.services.login_throttle import LoginThrottle, ThrottleDecision


@pytest.fixture(autouse=True)
def _tight_thresholds(monkeypatch: pytest.MonkeyPatch) -> None:
    """Small numbers, so a test does not have to fail fifty times."""
    monkeypatch.setenv("AISOC_LOGIN_FAILURE_THRESHOLD", "3")
    monkeypatch.setenv("AISOC_LOGIN_LOCKOUT_THRESHOLD", "5")
    monkeypatch.setenv("AISOC_LOGIN_BASE_DELAY_SECONDS", "2")
    monkeypatch.setenv("AISOC_LOGIN_MAX_DELAY_SECONDS", "30")
    monkeypatch.setenv("AISOC_LOGIN_LOCKOUT_SECONDS", "600")
    monkeypatch.setenv("AISOC_LOGIN_WINDOW_SECONDS", "600")
    login_throttle.reset_login_throttle_for_tests()


def _throttle() -> LoginThrottle:
    """No Redis: the in-process store, which is the documented fallback."""
    return LoginThrottle(redis_client=None)


async def _fail(throttle: LoginThrottle, times: int, *, email: str, ip: str | None) -> None:
    for _ in range(times):
        await throttle.record_failure(email=email, source_ip=ip)


class TestTheDefect:
    @pytest.mark.asyncio
    async def test_repeated_failures_are_eventually_refused(self) -> None:
        """The assertion that fails on the pre-fix tree: nothing refused."""
        throttle = _throttle()
        assert (await throttle.check(email="a@example.com", source_ip="10.0.0.1")).allowed

        await _fail(throttle, 4, email="a@example.com", ip="10.0.0.1")

        decision = await throttle.check(email="a@example.com", source_ip="10.0.0.1")
        assert not decision.allowed
        assert decision.retry_after_seconds >= 1

    @pytest.mark.asyncio
    async def test_the_first_few_failures_are_not_refused(self) -> None:
        """Someone who mistypes twice must not be told to wait."""
        throttle = _throttle()
        await _fail(throttle, 2, email="a@example.com", ip="10.0.0.1")
        assert (await throttle.check(email="a@example.com", source_ip="10.0.0.1")).allowed

    @pytest.mark.asyncio
    async def test_the_delay_doubles(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Lockout is pushed out of the way, or it arrives before the second
        doubling step and the test measures one delay rather than a curve."""
        monkeypatch.setenv("AISOC_LOGIN_LOCKOUT_THRESHOLD", "99")
        throttle = _throttle()
        delays = []
        for _ in range(7):
            await throttle.record_failure(email="a@example.com", source_ip=None)
            decision = await throttle.check(email="a@example.com", source_ip=None)
            delays.append(decision.retry_after_seconds)
        refusals = [d for d in delays if d > 0]
        assert refusals == sorted(refusals), f"delays did not increase: {delays}"
        assert len(refusals) >= 3, f"expected several refusals, saw {delays}"
        assert refusals[-1] > refusals[0], f"the delay did not grow: {delays}"

    @pytest.mark.asyncio
    async def test_the_delay_is_capped(self) -> None:
        """Unbounded doubling would lock an account out for years by accident."""
        throttle = _throttle()
        await _fail(throttle, 3, email="a@example.com", ip=None)
        assert throttle._delay_for(40, 3) <= throttle.max_delay

    @pytest.mark.asyncio
    async def test_enough_failures_lock_the_account_out(self) -> None:
        throttle = _throttle()
        locked = ThrottleDecision(allowed=True)
        for _ in range(6):
            locked = await throttle.record_failure(email="a@example.com", source_ip=None)
        assert locked.locked_out
        assert locked.scope == "account"
        decision = await throttle.check(email="a@example.com", source_ip=None)
        assert decision.locked_out
        assert decision.retry_after_seconds > 60


class TestItIsNotAnEnumerationOracle:
    @pytest.mark.asyncio
    async def test_an_unknown_address_is_throttled_identically(self) -> None:
        """The throttle sees an address, not an account.

        It runs before the database is consulted, so it cannot know whether
        the account exists — which is the point. A throttle that engaged only
        for real accounts would answer 429 for those and 401 for the rest,
        and that difference is a user list.
        """
        throttle = _throttle()
        await _fail(throttle, 4, email="nobody@example.com", ip="10.0.0.1")
        refused = await throttle.check(email="nobody@example.com", source_ip="10.0.0.1")

        other = _throttle()
        await _fail(other, 4, email="real@example.com", ip="10.0.0.2")
        real = await other.check(email="real@example.com", source_ip="10.0.0.2")

        assert refused.allowed == real.allowed
        assert refused.locked_out == real.locked_out


class TestTheTwoCountersCatchDifferentAttacks:
    @pytest.mark.asyncio
    async def test_spraying_trips_the_source_counter(self) -> None:
        """One password against many accounts never trips an account counter.

        Each account sees exactly one failure, so a per-account limiter alone
        does not see this attack at all.
        """
        throttle = _throttle()
        for index in range(20):
            await throttle.record_failure(email=f"user{index}@example.com", source_ip="10.0.0.9")

        fresh_account = await throttle.check(email="user999@example.com", source_ip="10.0.0.9")
        assert not fresh_account.allowed, "a spraying source was not refused"
        assert fresh_account.scope == "source"

    @pytest.mark.asyncio
    async def test_one_sources_failures_do_not_refuse_another(self) -> None:
        throttle = _throttle()
        await _fail(throttle, 30, email="a@example.com", ip="10.0.0.9")
        assert (await throttle.check(email="b@example.com", source_ip="10.0.0.10")).allowed


class TestSuccessClearsTheAccountCounterOnly:
    @pytest.mark.asyncio
    async def test_a_success_clears_the_account(self) -> None:
        throttle = _throttle()
        await _fail(throttle, 4, email="a@example.com", ip="10.0.0.1")
        assert not (await throttle.check(email="a@example.com", source_ip=None)).allowed

        await throttle.record_success(email="a@example.com", source_ip="10.0.0.1")
        assert (await throttle.check(email="a@example.com", source_ip=None)).allowed

    @pytest.mark.asyncio
    async def test_a_success_does_not_clear_the_source(self) -> None:
        """The subtle half.

        An attacker who guesses one password out of a thousand attempts would
        otherwise reset their own source budget with it and carry on from
        zero, which turns a successful compromise into a free pass for the
        next nine hundred guesses.
        """
        throttle = _throttle()
        for index in range(20):
            await throttle.record_failure(email=f"user{index}@example.com", source_ip="10.0.0.9")

        await throttle.record_success(email="user3@example.com", source_ip="10.0.0.9")

        still_refused = await throttle.check(email="user999@example.com", source_ip="10.0.0.9")
        assert not still_refused.allowed, "one success reset the spraying source's budget"


class TestTheKeyspaceHoldsNoAddresses:
    def test_the_key_does_not_contain_the_email(self) -> None:
        """An email in a key is an email in `KEYS *` and in every backup."""
        key = login_throttle._principal_key("account", "someone@example.com")
        assert "someone" not in key
        assert "example.com" not in key
        assert key.startswith("aisoc:login:account:")

    def test_the_key_is_stable_across_case_and_whitespace(self) -> None:
        assert login_throttle._principal_key("account", " A@Example.COM ") == login_throttle._principal_key("account", "a@example.com")


class TestRedisFailureDegradesRatherThanLocksEveryoneOut:
    @pytest.mark.asyncio
    async def test_a_broken_client_falls_back_instead_of_refusing(self, caplog) -> None:
        class _Broken:
            async def hgetall(self, *_args, **_kwargs):
                raise ConnectionError("redis is down")

            async def hset(self, *_args, **_kwargs):
                raise ConnectionError("redis is down")

            async def expire(self, *_args, **_kwargs):
                raise ConnectionError("redis is down")

            async def delete(self, *_args, **_kwargs):
                raise ConnectionError("redis is down")

        throttle = LoginThrottle(redis_client=_Broken())
        with caplog.at_level("WARNING"):
            assert (await throttle.check(email="a@example.com", source_ip="10.0.0.1")).allowed
        assert any("Redis unavailable" in record.message for record in caplog.records)

    @pytest.mark.asyncio
    async def test_the_fallback_still_counts(self) -> None:
        """Weaker than shared counting is not the same as absent."""

        class _Broken:
            async def hgetall(self, *_args, **_kwargs):
                raise ConnectionError("redis is down")

            async def hset(self, *_args, **_kwargs):
                raise ConnectionError("redis is down")

            async def expire(self, *_args, **_kwargs):
                raise ConnectionError("redis is down")

            async def delete(self, *_args, **_kwargs):
                raise ConnectionError("redis is down")

        throttle = LoginThrottle(redis_client=_Broken())
        await _fail(throttle, 4, email="a@example.com", ip="10.0.0.1")
        assert not (await throttle.check(email="a@example.com", source_ip="10.0.0.1")).allowed


class TestTheClientAddressResolver:
    def test_it_prefers_the_forwarded_header(self) -> None:
        class _Request:
            headers = {"x-forwarded-for": "203.0.113.7, 10.0.0.1"}
            client = type("C", (), {"host": "10.0.0.1"})()

        assert login_throttle.client_ip(_Request()) == "203.0.113.7"

    def test_it_falls_back_to_the_socket(self) -> None:
        class _Request:
            headers: dict[str, str] = {}
            client = type("C", (), {"host": "10.0.0.1"})()

        assert login_throttle.client_ip(_Request()) == "10.0.0.1"

    def test_it_never_returns_empty(self) -> None:
        """An empty key would put every unattributable caller in one bucket."""

        class _Request:
            headers: dict[str, str] = {}
            client = None

        assert login_throttle.client_ip(_Request()) == "unknown"


class TestTheWindowExpires:
    @pytest.mark.asyncio
    async def test_failures_age_out(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """One typo a month must not eventually lock an unattacked account."""
        monkeypatch.setenv("AISOC_LOGIN_WINDOW_SECONDS", "1")
        throttle = _throttle()
        await _fail(throttle, 4, email="a@example.com", ip=None)
        assert not (await throttle.check(email="a@example.com", source_ip=None)).allowed

        time.sleep(1.2)
        assert (await throttle.check(email="a@example.com", source_ip=None)).allowed
