"""Throttle and lock out repeated credential failures.

Fifty wrong passwords for one account inside a minute all returned 401, with
no delay and no lockout. `SECURITY.md` pointed readers at
`services/api/app/middleware/` "for rate limiting, audit logging, and request
hardening", and that directory holds exactly two files, neither of which is a
limiter. Rate limiting did exist in this service, but only on three unrelated
surfaces: the explain endpoint, lake queries and the public waitlist form.

Two counters, not one
---------------------
An **account** counter and a **source** counter, because they catch different
attacks and a single counter cannot do both:

* one address guessing many passwords is caught by the account counter;
* one source spraying one common password across many accounts never trips an
  account counter at all, because each account sees a single failure.

A success clears the account counter and **not** the source counter. That is
deliberate and is the subtle half: an attacker who guesses one password out of
a thousand attempts would otherwise reset their own budget with it and carry
on from zero.

Backoff, then lockout
---------------------
Below the threshold, nothing. Past it, a refusal carrying `Retry-After` whose
delay doubles per failure up to a ceiling; past the lockout threshold, a fixed
cool-off. Doubling rather than a flat window because a flat window is a rate
an attacker can simply schedule around, and the early doubling steps are short
enough that someone who mistyped their password twice does not notice.

The reply is deliberately the same for an account that exists and one that
does not. A throttle that only engages for real accounts is a user-enumeration
oracle, which is a worse defect than the one it fixes.

When Redis is unavailable
-------------------------
Falls back to an in-process counter and says so at `warning`. Failing closed
would lock every operator out of their own console over a Redis blip, and
failing silently open would leave the control absent exactly when an attacker
is most likely to have caused the outage. Per-replica counting is weaker than
shared counting and is documented as such rather than described as equivalent.
"""

from __future__ import annotations

import hashlib
import logging
import os
import time
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

#: Failures before a refusal begins. Three is a mistyped password twice plus
#: one, which is where a person starts to think rather than keep typing.
DEFAULT_FAILURE_THRESHOLD = 5

#: Failures before the fixed cool-off replaces the doubling delay.
DEFAULT_LOCKOUT_THRESHOLD = 10

#: Seconds of delay at the first refusal; doubles per failure after that.
DEFAULT_BASE_DELAY_SECONDS = 2.0

#: Ceiling on the doubling, so the delay stays bounded before lockout.
DEFAULT_MAX_DELAY_SECONDS = 60.0

#: How long a lockout lasts.
DEFAULT_LOCKOUT_SECONDS = 900.0

#: How long a failure counts against a principal. Without expiry, one typo a
#: month would eventually lock an account that nobody is attacking.
DEFAULT_WINDOW_SECONDS = 900.0

#: A source may fail more than an account before it is throttled: an office
#: behind one NAT address is many people, and several of them mistype.
SOURCE_MULTIPLIER = 6


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        logger.warning("%s is not a number (%r); using %s", name, raw, default)
        return default
    if value <= 0:
        logger.warning("%s must be positive (%r); using %s", name, raw, default)
        return default
    return value


@dataclass(frozen=True)
class ThrottleDecision:
    """Whether this attempt may proceed, and what to tell the caller."""

    allowed: bool
    retry_after_seconds: int = 0
    locked_out: bool = False
    #: Which counter refused: "account" or "source". Named so an audit row
    #: distinguishes one account under attack from one source spraying many.
    scope: str = ""
    failures: int = 0

    @property
    def detail(self) -> str:
        if self.allowed:
            return ""
        if self.locked_out:
            return f"Too many failed sign-in attempts. This account is temporarily locked. Try again in {self.retry_after_seconds} seconds."
        return f"Too many failed sign-in attempts. Try again in {self.retry_after_seconds} seconds."


@dataclass
class _Counter:
    failures: int = 0
    first_seen: float = 0.0
    locked_until: float = 0.0


@dataclass
class _InProcessStore:
    """The fallback. Per-replica, which is weaker than shared and is said so."""

    counters: dict[str, _Counter] = field(default_factory=dict)

    def get(self, key: str, window: float, now: float) -> _Counter:
        counter = self.counters.get(key)
        if counter is None or (counter.locked_until <= now and now - counter.first_seen > window):
            counter = _Counter(first_seen=now)
            self.counters[key] = counter
        return counter

    def clear(self, key: str) -> None:
        self.counters.pop(key, None)


def client_ip(request: object) -> str:
    """The source address, trusting the proxy chain in front of the API.

    Mirrors the resolver the waitlist limiter uses, with one caveat that
    matters more here than it does there: where `X-Forwarded-For` is not
    stripped by a trusted proxy, an attacker can rotate it and give
    themselves a fresh source bucket per request. That does not let them
    exhaust somebody else's budget, but it does let them evade the source
    counter. Which is why the **account** counter is the primary control and
    the source counter is the one that catches password spraying, where the
    attacker has no reason to expect per-request rotation to be needed.
    """
    headers = getattr(request, "headers", {})
    forwarded = (headers.get("x-forwarded-for", "") if hasattr(headers, "get") else "").strip()
    if forwarded:
        first = forwarded.split(",", 1)[0].strip()
        if first:
            return first
    peer = getattr(request, "client", None)
    host = getattr(peer, "host", None)
    return host or "unknown"


def _principal_key(scope: str, value: str) -> str:
    """A Redis key that does not contain the address or the source itself.

    An email in a key is an email in `KEYS *`, in a memory dump and in any
    backup of that Redis. The counter needs identity, not the identifier.
    """
    digest = hashlib.sha256(value.strip().lower().encode("utf-8")).hexdigest()[:32]
    return f"aisoc:login:{scope}:{digest}"


class LoginThrottle:
    """Counts credential failures per account and per source."""

    def __init__(self, redis_client: object | None = None) -> None:
        self._redis = redis_client
        self._fallback = _InProcessStore()
        self._warned_about_fallback = False

    # ── tuning, read at call time so an operator can widen without a redeploy
    @property
    def failure_threshold(self) -> int:
        return int(_env_float("AISOC_LOGIN_FAILURE_THRESHOLD", DEFAULT_FAILURE_THRESHOLD))

    @property
    def lockout_threshold(self) -> int:
        return int(_env_float("AISOC_LOGIN_LOCKOUT_THRESHOLD", DEFAULT_LOCKOUT_THRESHOLD))

    @property
    def base_delay(self) -> float:
        return _env_float("AISOC_LOGIN_BASE_DELAY_SECONDS", DEFAULT_BASE_DELAY_SECONDS)

    @property
    def max_delay(self) -> float:
        return _env_float("AISOC_LOGIN_MAX_DELAY_SECONDS", DEFAULT_MAX_DELAY_SECONDS)

    @property
    def lockout_seconds(self) -> float:
        return _env_float("AISOC_LOGIN_LOCKOUT_SECONDS", DEFAULT_LOCKOUT_SECONDS)

    @property
    def window_seconds(self) -> float:
        return _env_float("AISOC_LOGIN_WINDOW_SECONDS", DEFAULT_WINDOW_SECONDS)

    def _delay_for(self, failures: int, threshold: int) -> float:
        """Doubling delay past the threshold, capped."""
        over = failures - threshold
        if over <= 0:
            return 0.0
        return min(self.base_delay * (2 ** (over - 1)), self.max_delay)

    async def _counter(self, key: str, now: float) -> _Counter:
        if self._redis is None:
            return self._fallback.get(key, self.window_seconds, now)
        try:
            raw = await self._redis.hgetall(key)  # type: ignore[attr-defined]
        except Exception as exc:  # noqa: BLE001 - any client error is a fallback
            self._warn_fallback(exc)
            self._redis = None
            return self._fallback.get(key, self.window_seconds, now)
        if not raw:
            return _Counter(first_seen=now)
        return _Counter(
            failures=int(raw.get("failures", 0)),
            first_seen=float(raw.get("first_seen", now)),
            locked_until=float(raw.get("locked_until", 0)),
        )

    async def _store(self, key: str, counter: _Counter) -> None:
        if self._redis is None:
            self._fallback.counters[key] = counter
            return
        try:
            await self._redis.hset(  # type: ignore[attr-defined]
                key,
                mapping={
                    "failures": counter.failures,
                    "first_seen": counter.first_seen,
                    "locked_until": counter.locked_until,
                },
            )
            # The key outlives the window by the lockout, so a lockout is not
            # cleared early by the window expiring underneath it.
            await self._redis.expire(key, int(self.window_seconds + self.lockout_seconds))  # type: ignore[attr-defined]
        except Exception as exc:  # noqa: BLE001
            self._warn_fallback(exc)
            self._redis = None
            self._fallback.counters[key] = counter

    async def _clear(self, key: str) -> None:
        if self._redis is None:
            self._fallback.clear(key)
            return
        try:
            await self._redis.delete(key)  # type: ignore[attr-defined]
        except Exception as exc:  # noqa: BLE001
            self._warn_fallback(exc)
            self._redis = None
            self._fallback.clear(key)

    def _warn_fallback(self, exc: Exception) -> None:
        if self._warned_about_fallback:
            return
        self._warned_about_fallback = True
        logger.warning(
            "login throttle: Redis unavailable (%s). Falling back to per-replica "
            "counting, which is weaker: an attacker spread across replicas gets "
            "one budget per replica. Sign-in stays available rather than failing "
            "closed, which would lock every operator out over a Redis blip.",
            exc,
        )

    async def check(self, *, email: str, source_ip: str | None) -> ThrottleDecision:
        """Whether this attempt may proceed. Call before verifying a password."""
        now = time.time()
        for scope, value, threshold in (
            ("account", email, self.failure_threshold),
            ("source", source_ip or "", self.failure_threshold * SOURCE_MULTIPLIER),
        ):
            if not value:
                continue
            counter = await self._counter(_principal_key(scope, value), now)
            if counter.locked_until > now:
                return ThrottleDecision(
                    allowed=False,
                    retry_after_seconds=max(1, int(counter.locked_until - now)),
                    locked_out=True,
                    scope=scope,
                    failures=counter.failures,
                )
            delay = self._delay_for(counter.failures, threshold)
            if delay > 0:
                waited = now - counter.first_seen
                # The delay is measured from the most recent failure, which is
                # what `first_seen` becomes once a refusal has been issued.
                if waited < delay:
                    return ThrottleDecision(
                        allowed=False,
                        retry_after_seconds=max(1, int(delay - waited)),
                        scope=scope,
                        failures=counter.failures,
                    )
        return ThrottleDecision(allowed=True)

    async def record_failure(self, *, email: str, source_ip: str | None) -> ThrottleDecision:
        """Count a failure against both principals, and lock out if warranted."""
        now = time.time()
        worst = ThrottleDecision(allowed=True)
        for scope, value, threshold in (
            ("account", email, self.lockout_threshold),
            ("source", source_ip or "", self.lockout_threshold * SOURCE_MULTIPLIER),
        ):
            if not value:
                continue
            key = _principal_key(scope, value)
            counter = await self._counter(key, now)
            counter.failures += 1
            counter.first_seen = now
            if counter.failures >= threshold:
                counter.locked_until = now + self.lockout_seconds
            await self._store(key, counter)
            if counter.locked_until > now and not worst.locked_out:
                worst = ThrottleDecision(
                    allowed=False,
                    retry_after_seconds=int(self.lockout_seconds),
                    locked_out=True,
                    scope=scope,
                    failures=counter.failures,
                )
        return worst

    async def record_success(self, *, email: str, source_ip: str | None) -> None:
        """Clear the account counter. Deliberately not the source counter.

        An attacker who guesses one password out of a thousand attempts would
        otherwise reset their own budget with it and carry on from zero. The
        source counter expires on its own window instead.
        """
        del source_ip  # named for symmetry, and to make the omission explicit
        if email:
            await self._clear(_principal_key("account", email))


_throttle: LoginThrottle | None = None


def get_login_throttle() -> LoginThrottle:
    global _throttle  # noqa: PLW0603 - one limiter per process, by design
    if _throttle is None:
        _throttle = LoginThrottle(_redis_client())
    return _throttle


def reset_login_throttle_for_tests() -> None:
    """Drop the process-wide limiter. Tests only."""
    global _throttle  # noqa: PLW0603
    _throttle = None


def _redis_client() -> object | None:
    try:
        from redis.asyncio import from_url

        from app.core.config import settings

        return from_url(str(settings.REDIS_URL), decode_responses=True)
    except Exception as exc:  # noqa: BLE001 - no Redis configured is not fatal
        logger.warning(
            "login throttle: no Redis client (%s). Counting per replica; see the module docstring for why this is not fail-closed.",
            exc,
        )
        return None
