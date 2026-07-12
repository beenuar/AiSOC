"""Content-addressed LLM response cache (Phase 8 — LLMOps).

Identical LLM requests (same model + same prompt + same input) should not be
paid for twice. This is a small, dependency-light, content-addressed cache
keyed by sha256(model + prompt + input). It complements the cost governor's
per-alert dedup: the governor stops a flood of identical *alerts*; this stops a
flood of identical *LLM calls* within and across investigations.

The default backend is an in-process LRU-ish dict with a size cap; a Redis-
backed backend implements the same `CacheBackend` protocol for multi-replica
deployments. Caching is keyed on content only, so it is safe under the
determinism contract — a cache hit is byte-identical to what the model returned.
"""

from __future__ import annotations

import hashlib
from collections import OrderedDict
from typing import Protocol, runtime_checkable


def cache_key(*, model: str, prompt: str, user_input: str) -> str:
    h = hashlib.sha256()
    for part in (model, prompt, user_input):
        h.update(part.encode("utf-8"))
        h.update(b"\x00")  # field separator so a||b != ab
    return h.hexdigest()


@runtime_checkable
class CacheBackend(Protocol):
    def get(self, key: str) -> str | None:
        """Return the cached value for ``key``, or None on a miss."""

    def set(self, key: str, value: str) -> None:
        """Store ``value`` under ``key``."""


class InMemoryResponseCache:
    """Bounded in-process cache. Evicts oldest on overflow."""

    def __init__(self, max_entries: int = 1024) -> None:
        self._max = max_entries
        self._store: OrderedDict[str, str] = OrderedDict()
        self.hits = 0
        self.misses = 0

    def get(self, key: str) -> str | None:
        if key in self._store:
            self._store.move_to_end(key)
            self.hits += 1
            return self._store[key]
        self.misses += 1
        return None

    def set(self, key: str, value: str) -> None:
        self._store[key] = value
        self._store.move_to_end(key)
        while len(self._store) > self._max:
            self._store.popitem(last=False)

    def __len__(self) -> int:
        return len(self._store)


class ResponseCache:
    """Front door over a backend. `lookup`/`store` take request components and
    hash them; callers never construct keys by hand."""

    def __init__(self, backend: CacheBackend | None = None) -> None:
        self._backend: CacheBackend = backend or InMemoryResponseCache()

    def lookup(self, *, model: str, prompt: str, user_input: str) -> str | None:
        return self._backend.get(cache_key(model=model, prompt=prompt, user_input=user_input))

    def store(self, *, model: str, prompt: str, user_input: str, response: str) -> None:
        self._backend.set(cache_key(model=model, prompt=prompt, user_input=user_input), response)
