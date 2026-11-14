"""Session-tier memory — in-process LRU, zero I/O, per-run lifetime.

Intentionally simple: a bounded dict keyed by (run_id, key).  The LRU
evicts the oldest entry when the cache exceeds *maxsize* (default 512).
Thread-safe via a lock; suitable for asyncio tasks sharing an event loop.
"""

from __future__ import annotations

import asyncio
from collections import OrderedDict
from typing import Any

_DEFAULT_MAXSIZE = 512
_session_caches: dict[str, _SessionCache] = {}
_registry_lock = asyncio.Lock()


class _SessionCache:
    def __init__(self, maxsize: int = _DEFAULT_MAXSIZE) -> None:
        self._store: OrderedDict[str, Any] = OrderedDict()
        self._maxsize = maxsize

    def get(self, key: str) -> Any | None:
        if key in self._store:
            self._store.move_to_end(key)
            return self._store[key]
        return None

    def set(self, key: str, value: Any) -> None:
        if key in self._store:
            self._store.move_to_end(key)
        self._store[key] = value
        if len(self._store) > self._maxsize:
            self._store.popitem(last=False)

    def delete(self, key: str) -> None:
        self._store.pop(key, None)

    def clear(self) -> None:
        self._store.clear()


async def _get_cache(run_id: str) -> _SessionCache:
    async with _registry_lock:
        if run_id not in _session_caches:
            _session_caches[run_id] = _SessionCache()
        return _session_caches[run_id]


async def session_get(run_id: str, key: str) -> Any | None:
    cache = await _get_cache(run_id)
    return cache.get(key)


async def session_set(run_id: str, key: str, value: Any) -> None:
    cache = await _get_cache(run_id)
    cache.set(key, value)


async def session_delete(run_id: str, key: str) -> None:
    cache = await _get_cache(run_id)
    cache.delete(key)


async def session_clear(run_id: str) -> None:
    """Evict all session entries for *run_id* (called at investigation end)."""
    async with _registry_lock:
        _session_caches.pop(run_id, None)
