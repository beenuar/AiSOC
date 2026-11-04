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

import jsonschema

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

    def argument_error(self, args: dict[str, Any]) -> str | None:
        """Why ``args`` does not satisfy this tool's schema, or ``None``.

        GHSA-4hxg-m5rw-gw3x. ``ToolRegistry.execute`` called ``fn(**args)``
        with whatever the model produced. The schema already existed and was
        already authoritative — it is what ``bind_tools`` sends the provider —
        and nothing compared the two. Python enforces no annotation, so a
        wrong type reached the body untouched: a tool declaring
        ``indicator: str`` ran on a list, a dict or an integer. The argument
        comes from a model whose context includes attacker-controlled alert
        text, which is the whole subject of that advisory.

        The check lives here rather than in the registry because it is a
        property of the tool's own contract, and a second definition of
        "valid arguments" somewhere else is the drift this repository keeps
        finding.

        Undeclared keys are rejected separately from the schema walk. The
        shipped schemas do not set ``additionalProperties: false``, and
        adding it to each of them would be seven places to forget; the
        function-calling contract is that the model sends declared properties
        only, so an undeclared key is out of contract wherever it came from.
        It matters most for a tool whose body takes ``**kwargs``, which
        swallows the extra argument rather than raising.

        Returns a sentence rather than raising: the loop's contract is that a
        tool failure reaches the model instead of aborting the run, and the
        model can act on "unexpected argument" by not sending it again.
        """
        schema = self.parameters if isinstance(self.parameters, dict) else {}
        declared = schema.get("properties")
        declared = declared if isinstance(declared, dict) else {}

        undeclared = sorted(set(args) - set(declared))
        if undeclared:
            return f"unexpected argument(s) {undeclared}; {self.name!r} declares {sorted(declared) or 'none'}"

        try:
            jsonschema.validate(instance=args, schema=schema)
        except jsonschema.ValidationError as exc:
            where = ".".join(str(part) for part in exc.absolute_path) or "(arguments)"
            return f"invalid argument {where}: {exc.message}"
        except jsonschema.SchemaError as exc:
            # The tool's own schema is malformed. Refusing is right — the
            # model was shown that schema — but the message must send a
            # reader to the tool definition rather than to the model.
            return f"tool {self.name!r} has an invalid parameter schema: {exc.message}"
        return None
