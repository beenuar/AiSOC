"""Decoupled tool-calling for the Hunter explorer.

`BaseAgent.call_tool` is the production tool entrypoint — it does HITL
gating, prompt-injection defense, provenance wrapping, scratchpad writes,
and audit logging. That is the right thing for an LLM tool-use loop, but
it returns a provenance-wrapped dict that is awkward to consume from
deterministic Python code, and it is hard to substitute in tests.

This module gives the Hunter explorer a narrow, well-typed seam:

- `HunterToolCaller` — a protocol with `await call(name, params)` that
  returns clean, unwrapped JSON.
- `BaseAgentToolCaller` — the production adapter that delegates to
  `BaseAgent.call_tool` and strips the provenance / `__llm_view__`
  wrappers added by `wrap_with_provenance`.
- `FakeToolCaller` — a test double the unit tests register handlers on.

All three speak the same protocol, so the explorer never imports a real
agent and stays trivially testable.
"""
from __future__ import annotations

import asyncio
import inspect
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Optional, Protocol


# ── Protocol ────────────────────────────────────────────────────────────


class HunterToolCaller(Protocol):
    """Narrow tool-execution seam used by the Hunter explorer."""

    async def call(
        self,
        name: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Run `name` with `params` and return the sanitized JSON result.

        The result MUST be a plain dict with the provenance / LLM-view
        markers (`__provenance__`, `__llm_view__`) stripped. Errors must
        be raised, not returned, so the explorer can catch them.
        """


# ── Helpers ─────────────────────────────────────────────────────────────


_PROVENANCE_KEYS = ("__provenance__", "__llm_view__")


def strip_provenance(payload: Any) -> dict[str, Any]:
    """Drop the provenance wrappers added by `wrap_with_provenance`.

    The Hunter explorer reads tool output as data, so the LLM-only
    annotations just add noise. We keep this lenient: non-dict payloads
    (e.g. an error string from a buggy tool) are coerced to `{"value": x}`.
    """
    if not isinstance(payload, dict):
        return {"value": payload}
    return {k: v for k, v in payload.items() if k not in _PROVENANCE_KEYS}


# ── Production adapter ──────────────────────────────────────────────────


class BaseAgentToolCaller:
    """Adapter: drive a real `BaseAgent.call_tool` through `HunterToolCaller`.

    Importing `BaseAgent` here would create a cycle (the agent imports the
    explorer which imports this module). We accept any object with an
    async `call_tool(name, params, ...)` — duck-typing is enough.
    """

    def __init__(self, agent: Any) -> None:
        if not hasattr(agent, "call_tool"):
            raise TypeError(
                "BaseAgentToolCaller requires an object with .call_tool(); "
                f"got {type(agent).__name__}"
            )
        self._agent = agent

    async def call(
        self,
        name: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        result = await self._agent.call_tool(
            name,
            params or {},
            rationale="hunter: hypothesis exploration",
        )
        return strip_provenance(result)


# ── Test double ─────────────────────────────────────────────────────────


ToolHandler = Callable[[dict[str, Any]], Any]
"""Handler for `FakeToolCaller`. Sync or async; returns the raw payload."""


@dataclass
class ToolInvocation:
    """One recorded `call()` against `FakeToolCaller`, for assertions."""

    name: str
    params: dict[str, Any]


class FakeToolCaller:
    """Deterministic, in-memory tool caller for unit tests.

    Register handlers with `register(name, handler)`. Each call is
    recorded on `.invocations` so tests can assert on order + parameters.
    Unknown tools raise `KeyError` so the explorer surfaces the bug
    instead of silently no-oping.
    """

    def __init__(
        self,
        *,
        default: Optional[ToolHandler] = None,
    ) -> None:
        self._handlers: dict[str, ToolHandler] = {}
        self._default = default
        self.invocations: list[ToolInvocation] = []

    def register(self, name: str, handler: ToolHandler) -> None:
        self._handlers[name] = handler

    def register_static(self, name: str, payload: dict[str, Any]) -> None:
        """Convenience: always return the same dict for `name`."""
        self.register(name, lambda _params: dict(payload))

    async def call(
        self,
        name: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        bound = dict(params or {})
        self.invocations.append(ToolInvocation(name=name, params=bound))

        handler = self._handlers.get(name) or self._default
        if handler is None:
            raise KeyError(f"FakeToolCaller has no handler for {name!r}")

        result = handler(bound)
        if inspect.isawaitable(result):
            result = await result
        return strip_provenance(result if isinstance(result, dict) else {"value": result})
