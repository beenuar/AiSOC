"""Chaos engine: scheduled, deterministic fault injection (t6-chaos).

The engine is a process-wide singleton with a small registration
API. Producers (the LLM client wrapper, the tool runner) call
``apply_*`` to ask the engine whether the call should fail; the
engine consults its scheduled faults, decrements counters, and
either lets the call proceed or raises the configured fault.

Determinism matters because chaos drills must be reproducible.
Faults are matched by ``target`` (an opaque string supplied by the
producer — e.g. ``"llm.complete:investigator"``,
``"tool.edr.isolate_host"``) and by a ``count`` budget. Once the
budget is spent the fault auto-deactivates.

The engine is opt-in. The default state is empty; production
deployments that don't schedule faults pay zero overhead because
the fast path is a single dict lookup.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from enum import Enum
from threading import RLock
from typing import Any, Callable, Optional


class ChaosKind(str, Enum):
    """The shape of fault to inject."""

    llm_outage = "llm_outage"
    llm_malformed = "llm_malformed"
    tool_timeout = "tool_timeout"
    tool_malformed = "tool_malformed"
    tool_slowness = "tool_slowness"


@dataclass
class ChaosFault:
    """One scheduled fault.

    ``target`` is an opaque match string the producer supplies
    (typically ``"llm.complete"`` or ``"tool.<tool_name>"``). The
    engine matches by exact string or by *prefix* if the registered
    target ends with ``*``.
    """

    kind: ChaosKind
    target: str
    remaining: int = 1
    delay_ms: int = 0
    message: str = "chaos: synthetic fault"
    payload: dict[str, Any] = field(default_factory=dict)
    fired: int = 0

    def matches(self, candidate: str) -> bool:
        if not self.target:
            return False
        if self.target.endswith("*"):
            return candidate.startswith(self.target[:-1])
        return candidate == self.target


@dataclass
class ChaosScenario:
    """A bundle of related faults that drill a particular surface."""

    name: str
    description: str
    faults: list[ChaosFault]


@dataclass
class ChaosResult:
    """Result returned by the engine when a producer consults it.

    ``triggered`` is True when a fault matched; ``raise_with`` is
    the exception the producer should raise (or None if the fault
    is non-raising, e.g. ``llm_malformed`` which expects the
    producer to substitute a malformed payload).
    """

    triggered: bool
    fault: Optional[ChaosFault] = None
    raise_with: Optional[BaseException] = None
    delay_ms: int = 0


class ChaosError(Exception):
    """Synthetic exception raised by injected outages."""


class ChaosTimeout(Exception):
    """Synthetic exception raised by injected timeouts."""


class ChaosEngine:
    """Process-wide singleton scheduler for fault injection."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._faults: list[ChaosFault] = []
        self._history: list[dict[str, Any]] = []
        self._listeners: list[Callable[[ChaosFault], None]] = []

    # ─── Scheduling ──────────────────────────────────────────────────

    def schedule(self, fault: ChaosFault) -> ChaosFault:
        """Register a fault. Returns the same instance for chaining."""
        with self._lock:
            self._faults.append(fault)
        return fault

    def schedule_scenario(self, scenario: ChaosScenario) -> ChaosScenario:
        for fault in scenario.faults:
            self.schedule(fault)
        return scenario

    def clear(self) -> None:
        with self._lock:
            self._faults.clear()
            self._history.clear()

    def active_faults(self) -> list[ChaosFault]:
        with self._lock:
            return [f for f in self._faults if f.remaining > 0]

    def history(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._history)

    # ─── Listeners ───────────────────────────────────────────────────

    def on_fire(self, cb: Callable[[ChaosFault], None]) -> None:
        with self._lock:
            self._listeners.append(cb)

    # ─── Apply (producer-facing) ─────────────────────────────────────

    def consult(self, target: str) -> ChaosResult:
        """Return the next fault that matches ``target``, decrementing its budget.

        Producers call this synchronously; the result tells them
        whether to raise (and what), inject latency, or pass-through.
        """

        with self._lock:
            for fault in self._faults:
                if fault.remaining <= 0:
                    continue
                if not fault.matches(target):
                    continue

                fault.remaining -= 1
                fault.fired += 1
                self._history.append(
                    {
                        "ts": time.time(),
                        "target": target,
                        "kind": fault.kind.value,
                        "fired": fault.fired,
                        "remaining": fault.remaining,
                    }
                )
                for listener in list(self._listeners):
                    try:
                        listener(fault)
                    except Exception:
                        # Listener problems must not perturb the
                        # producer.
                        pass

                # Raising vs. soft outcomes.
                if fault.kind == ChaosKind.llm_outage:
                    return ChaosResult(
                        triggered=True,
                        fault=fault,
                        raise_with=ChaosError(
                            f"chaos: LLM outage on {target}: {fault.message}"
                        ),
                        delay_ms=fault.delay_ms,
                    )
                if fault.kind == ChaosKind.tool_timeout:
                    return ChaosResult(
                        triggered=True,
                        fault=fault,
                        raise_with=ChaosTimeout(
                            f"chaos: tool {target} timed out: {fault.message}"
                        ),
                        delay_ms=fault.delay_ms,
                    )
                # Non-raising kinds: producer reads the fault and
                # substitutes a malformed payload itself.
                return ChaosResult(
                    triggered=True,
                    fault=fault,
                    raise_with=None,
                    delay_ms=fault.delay_ms,
                )
        return ChaosResult(triggered=False)

    # ─── Convenience wrappers used by producers ──────────────────────

    def maybe_raise_llm(self, target: str) -> Optional[dict[str, Any]]:
        """Producer-friendly wrapper for LLM call sites.

        Returns ``None`` if no fault is scheduled. Returns a
        malformed payload dict for ``llm_malformed``. Raises for
        ``llm_outage``.
        """

        result = self.consult(target)
        if not result.triggered:
            return None
        if result.delay_ms:
            time.sleep(result.delay_ms / 1000.0)
        if result.raise_with is not None:
            raise result.raise_with
        if result.fault and result.fault.kind == ChaosKind.llm_malformed:
            return dict(result.fault.payload or {"text": "MALFORMED-LLM-PAYLOAD"})
        return None

    async def maybe_raise_llm_async(self, target: str) -> Optional[dict[str, Any]]:
        """Async sibling of :meth:`maybe_raise_llm`."""

        result = self.consult(target)
        if not result.triggered:
            return None
        if result.delay_ms:
            await asyncio.sleep(result.delay_ms / 1000.0)
        if result.raise_with is not None:
            raise result.raise_with
        if result.fault and result.fault.kind == ChaosKind.llm_malformed:
            return dict(result.fault.payload or {"text": "MALFORMED-LLM-PAYLOAD"})
        return None

    def apply_tool(self, target: str) -> Optional[dict[str, Any]]:
        """Producer-friendly wrapper for tool invocations.

        Behaves analogously to :meth:`maybe_raise_llm` but for the
        tool side. Returns a substitute payload dict for
        ``tool_malformed`` cases; the producer is expected to use
        the substitute as if it were the tool's real response.
        """

        result = self.consult(target)
        if not result.triggered:
            return None
        if result.delay_ms:
            time.sleep(result.delay_ms / 1000.0)
        if result.raise_with is not None:
            raise result.raise_with
        if result.fault and result.fault.kind == ChaosKind.tool_malformed:
            return dict(result.fault.payload or {"error": "malformed", "schema_version": -1})
        if result.fault and result.fault.kind == ChaosKind.tool_slowness:
            # Slowness-only faults already burned their delay above.
            return None
        return None


chaos_engine = ChaosEngine()
