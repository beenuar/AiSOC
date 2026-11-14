"""Per-case scratchpad — in-process by default, Redis when configured.

The scratchpad is short-term working memory: agents stash tool results,
half-formed plans, retry counters, etc. for a single case and pick them
up on the next turn. In a multi-process / multi-replica deployment the
in-memory dict obviously doesn't share state, so we layer in Redis.

Design notes:

* The Redis backend serializes values via JSON. Anything that isn't
  JSON-serializable will trigger a per-call fallback to the in-memory
  store (logged once) so individual exotic values don't crash a case.
* Each case key gets a TTL (default 1 day) so abandoned cases don't
  bloat Redis forever.
* If `redis` SDK isn't installed or the URL is unreachable at boot,
  we silently fall back to the in-memory backend and log a warning.
  The platform stays online; only horizontal scaling is degraded.

The public ``scratchpad`` singleton's API is intentionally unchanged so
existing agents keep working.
"""
from __future__ import annotations

import json
import logging
import threading
from collections import defaultdict
from typing import Any, Protocol

from app.config import settings

logger = logging.getLogger(__name__)


class _Backend(Protocol):
    """Minimal interface every backend must implement."""

    def set(self, case_id: int, key: str, value: Any) -> None: ...
    def get(self, case_id: int, key: str, default: Any = None) -> Any: ...
    def all(self, case_id: int) -> dict[str, Any]: ...
    def append(self, case_id: int, key: str, value: Any) -> None: ...
    def delete(self, case_id: int, key: str) -> bool: ...
    def clear(self, case_id: int) -> None: ...


# ── In-process backend (default, always works) ────────────────────────
class _InMemoryBackend:
    """Thread-safe in-process scratchpad."""

    def __init__(self) -> None:
        self._store: dict[int, dict[str, Any]] = defaultdict(dict)
        self._lock = threading.RLock()

    def set(self, case_id: int, key: str, value: Any) -> None:
        with self._lock:
            self._store[case_id][key] = value

    def get(self, case_id: int, key: str, default: Any = None) -> Any:
        with self._lock:
            return self._store[case_id].get(key, default)

    def all(self, case_id: int) -> dict[str, Any]:
        with self._lock:
            return dict(self._store[case_id])

    def append(self, case_id: int, key: str, value: Any) -> None:
        with self._lock:
            self._store[case_id].setdefault(key, []).append(value)

    def delete(self, case_id: int, key: str) -> bool:
        with self._lock:
            bucket = self._store.get(case_id)
            if bucket is None:
                return False
            existed = key in bucket
            bucket.pop(key, None)
            # Don't leave empty buckets behind — keeps `all()` and the
            # rollback path symmetric with `clear()`.
            if not bucket:
                self._store.pop(case_id, None)
            return existed

    def clear(self, case_id: int) -> None:
        with self._lock:
            self._store.pop(case_id, None)


# ── Redis backend ─────────────────────────────────────────────────────
class _RedisBackend:
    """Redis-backed scratchpad using a per-case hash with TTL.

    Layout:
        Key:    "aisoc:scratchpad:{case_id}"  (hash)
        Field:  "{key}"                       (JSON-encoded value)
        TTL:    scratchpad_ttl_seconds (refreshed on every write)
    """

    KEY_PREFIX = "aisoc:scratchpad:"

    def __init__(self, client: Any, ttl: int, fallback: _Backend) -> None:
        self._client = client
        self._ttl = ttl
        # Used when JSON round-tripping a single value fails; we still
        # honor the call locally so the case doesn't drop data.
        self._fallback = fallback

    def _key(self, case_id: int) -> str:
        return f"{self.KEY_PREFIX}{case_id}"

    def _refresh_ttl(self, key: str) -> None:
        try:
            self._client.expire(key, self._ttl)
        except Exception as exc:  # pragma: no cover - depends on env
            logger.debug("Failed to refresh TTL on %s: %s", key, exc)

    def set(self, case_id: int, key: str, value: Any) -> None:
        try:
            # No `default=str` on purpose: we'd rather keep exotic values
            # (datetimes, Pydantic models, custom objects) at full fidelity
            # in the local fallback than silently stringify them into Redis.
            payload = json.dumps(value)
        except (TypeError, ValueError) as exc:
            logger.warning(
                "scratchpad.set non-JSON value for case=%s key=%s (%s); using local fallback",
                case_id,
                key,
                exc,
            )
            self._fallback.set(case_id, key, value)
            return
        rkey = self._key(case_id)
        try:
            self._client.hset(rkey, key, payload)
            self._refresh_ttl(rkey)
        except Exception as exc:  # pragma: no cover - depends on env
            logger.warning("Redis set failed (%s); using local fallback", exc)
            self._fallback.set(case_id, key, value)

    def get(self, case_id: int, key: str, default: Any = None) -> Any:
        rkey = self._key(case_id)
        try:
            raw = self._client.hget(rkey, key)
        except Exception as exc:  # pragma: no cover - depends on env
            logger.warning("Redis get failed (%s); using local fallback", exc)
            return self._fallback.get(case_id, key, default)
        if raw is None:
            # Last-write-wins: check local fallback in case a previous
            # non-JSON value or Redis outage stashed something here.
            return self._fallback.get(case_id, key, default)
        try:
            return json.loads(raw)
        except (TypeError, ValueError):
            return default

    def all(self, case_id: int) -> dict[str, Any]:
        rkey = self._key(case_id)
        try:
            raw = self._client.hgetall(rkey) or {}
        except Exception as exc:  # pragma: no cover - depends on env
            logger.warning("Redis hgetall failed (%s); using local fallback", exc)
            return self._fallback.all(case_id)
        out: dict[str, Any] = {}
        for field, val in raw.items():
            # redis-py with decode_responses=True gives str; otherwise bytes.
            if isinstance(field, bytes):
                field = field.decode("utf-8", errors="replace")
            if isinstance(val, bytes):
                val = val.decode("utf-8", errors="replace")
            try:
                out[field] = json.loads(val)
            except (TypeError, ValueError):
                out[field] = val
        # Merge any local-only fallback entries (rare, but possible if a
        # write fell back) so the agent sees a unified view.
        for k, v in self._fallback.all(case_id).items():
            out.setdefault(k, v)
        return out

    def append(self, case_id: int, key: str, value: Any) -> None:
        # Read-modify-write. We accept that this isn't atomic across
        # processes; the scratchpad isn't a database. If two agents race
        # on the same key the loser overwrites — but agents within a
        # case run serially today.
        existing = self.get(case_id, key, default=None)
        if existing is None:
            existing = []
        if not isinstance(existing, list):
            existing = [existing]
        existing.append(value)
        self.set(case_id, key, existing)

    def delete(self, case_id: int, key: str) -> bool:
        rkey = self._key(case_id)
        existed_remote = False
        try:
            existed_remote = bool(self._client.hdel(rkey, key))
        except Exception as exc:  # pragma: no cover - depends on env
            logger.warning("Redis hdel failed (%s); using local fallback", exc)
        existed_local = self._fallback.delete(case_id, key)
        return existed_remote or existed_local

    def clear(self, case_id: int) -> None:
        rkey = self._key(case_id)
        try:
            self._client.delete(rkey)
        except Exception as exc:  # pragma: no cover - depends on env
            logger.warning("Redis delete failed (%s); using local fallback", exc)
        self._fallback.clear(case_id)


# ── Backend selection (lazy, one-shot) ────────────────────────────────
_backend: _Backend | None = None
_backend_name: str | None = None
_backend_lock = threading.Lock()


def _build_redis_backend(fallback: _Backend) -> _Backend | None:
    """Try to construct a Redis backend; return None on failure."""
    url = settings.redis_url
    if not url:
        logger.warning(
            "scratchpad_backend=redis but AISOC_REDIS_URL is unset; using in-memory fallback",
        )
        return None
    try:
        import redis  # type: ignore
    except ImportError:
        logger.warning(
            "scratchpad_backend=redis but `redis` SDK is not installed; using in-memory fallback",
        )
        return None
    try:
        client = redis.Redis.from_url(url, decode_responses=True, socket_timeout=2.0)
        # Probe so we fail loud at boot, not on the first write.
        client.ping()
    except Exception as exc:  # pragma: no cover - depends on env
        logger.warning(
            "Failed to connect to Redis at %s (%s); using in-memory fallback",
            url,
            exc,
        )
        return None
    logger.info("Scratchpad: using Redis backend (%s)", url)
    return _RedisBackend(client, settings.scratchpad_ttl_seconds, fallback)


def _resolve_backend() -> _Backend:
    global _backend, _backend_name
    if _backend is not None:
        return _backend
    with _backend_lock:
        if _backend is not None:
            return _backend
        configured = (settings.scratchpad_backend or "memory").lower()
        local = _InMemoryBackend()
        if configured == "redis":
            redis_backend = _build_redis_backend(local)
            if redis_backend is not None:
                _backend = redis_backend
                _backend_name = "redis"
                return _backend
        _backend = local
        _backend_name = "memory"
        return _backend


class Scratchpad:
    """Facade that dispatches to the configured backend.

    The public API is unchanged from the previous in-memory-only version,
    so existing call sites in the agents keep working.
    """

    def set(self, case_id: int, key: str, value: Any) -> None:
        _resolve_backend().set(case_id, key, value)

    def get(self, case_id: int, key: str, default: Any = None) -> Any:
        return _resolve_backend().get(case_id, key, default)

    def all(self, case_id: int) -> dict[str, Any]:
        return _resolve_backend().all(case_id)

    def append(self, case_id: int, key: str, value: Any) -> None:
        _resolve_backend().append(case_id, key, value)

    def delete(self, case_id: int, key: str) -> bool:
        return _resolve_backend().delete(case_id, key)

    def clear(self, case_id: int) -> None:
        _resolve_backend().clear(case_id)

    @property
    def backend_name(self) -> str:
        _resolve_backend()
        return _backend_name or "memory"


scratchpad = Scratchpad()
