"""One in-memory Redis stand-in for the windowed detection engine.

Six copies of this used to live in six test files, each implementing a
different subset of the commands: some had ``zrangebyscore`` and some did
not, none had ``eval``. The cost is not duplication, it is that a change to
the engine breaks a test for a reason that has nothing to do with the
behaviour under test -- a missing method raises inside the engine's
fail-soft per-rule handler, the rule silently produces no hit, and the test
fails with "the detection did not fire" when the real answer is "the double
cannot do what Redis does".

So there is one double, it implements everything the engine calls, and
adding a command to the engine means adding it here once.

``eval`` dispatches on the exact scripts :mod:`app.services.windowed_detection`
defines rather than interpreting Lua. Their real semantics -- in particular
that the owner check and the write are atomic -- are pinned against a live
server in ``tests/integration/test_windowed_detection_live.py``; a double
that guessed at atomicity would be the more-capable-than-reality kind this
repository keeps finding.
"""

from __future__ import annotations

from typing import Any


class FakeRedis:
    """Sorted sets, string keys with NX/EX, and the engine's two Lua scripts."""

    def __init__(self) -> None:
        self.zsets: dict[str, dict[str, float]] = {}
        self.strings: dict[str, str] = {}
        #: Set to make every command raise, for the fail-soft paths.
        self.failing = False

    def _check(self) -> None:
        if self.failing:
            raise ConnectionError("redis down")

    async def zadd(self, key: str, mapping: dict[str, float]) -> None:
        self._check()
        self.zsets.setdefault(key, {}).update(mapping)

    async def zremrangebyscore(self, key: str, min_s: float, max_s: float) -> None:
        self._check()
        members = self.zsets.get(key, {})
        for member in [m for m, score in list(members.items()) if min_s <= score <= max_s]:
            del members[member]

    async def zrangebyscore(self, key: str, min_s: float, max_s: float, withscores: bool = False) -> list[Any]:  # noqa: FBT001, FBT002
        self._check()
        ordered = sorted((score, member) for member, score in self.zsets.get(key, {}).items() if min_s <= score <= max_s)
        return [(member, score) for score, member in ordered] if withscores else [member for _, member in ordered]

    async def zcard(self, key: str) -> int:
        self._check()
        return len(self.zsets.get(key, {}))

    async def zcount(self, key: str, min_s: float, max_s: float) -> int:
        self._check()
        return sum(1 for score in self.zsets.get(key, {}).values() if min_s <= score <= max_s)

    async def expire(self, key: str, ttl: int) -> None:
        self._check()

    async def set(self, key: str, value: str, nx: bool = False, ex: int | None = None) -> Any:  # noqa: FBT001, FBT002
        self._check()
        if nx and key in self.strings:
            return None
        self.strings[key] = value
        return True

    async def get(self, key: str) -> Any:
        self._check()
        return self.strings.get(key)

    async def delete(self, key: str) -> int:
        self._check()
        return 1 if self.strings.pop(key, None) is not None else 0

    async def eval(self, script: str, numkeys: int, *args: Any) -> int:  # noqa: ARG002
        self._check()
        from app.services import windowed_detection as wd  # noqa: PLC0415 — avoids an import cycle at module load

        key, token = args[0], args[1]
        if script == wd._RELEASE_IF_OWNER:  # noqa: SLF001
            if self.strings.get(key) == token:
                del self.strings[key]
                return 1
            return 0
        if script == wd._CONFIRM_IF_OWNER:  # noqa: SLF001
            if self.strings.get(key) == token:
                self.strings[key] = args[2]
                return 1
            return 0
        raise AssertionError(f"the double does not implement this script: {script[:60]!r}")
