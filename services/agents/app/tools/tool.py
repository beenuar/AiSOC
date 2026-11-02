"""The ``Tool`` descriptor, in its own module so the registry can import tools.

Why this is not in ``registry.py``
----------------------------------
``Tool`` is a data shape; ``ToolRegistry`` is machinery that holds them. They
lived together, which was fine for as long as the registry only ever received
tools built elsewhere and never built any itself.

Depth 2 wave 2 changed that: ``default_registry`` now constructs the identity
tools, which live in ``customer_tools``, which imports ``Tool`` — and that is
an import cycle (``registry`` → ``customer_tools`` → ``registry``). CodeQL's
``py/cyclic-import`` flagged it on the first run.

A cycle that works today is still worth breaking: it works only because one
of the two imports is inside a function, so the first module-level import of
``customer_tools`` anywhere in the process would make the failure appear at a
completely unrelated call site. Splitting the data shape from the machinery
removes the cycle rather than deferring it.

``registry.py`` re-exports ``Tool``, so every existing
``from app.tools.registry import Tool`` keeps working.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

__all__ = ["Tool"]


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    parameters: dict[str, Any]  # JSON schema for the arguments
    fn: Callable[..., Any] | Callable[..., Awaitable[Any]]

    def openai_schema(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {"name": self.name, "description": self.description, "parameters": self.parameters},
        }
