"""What an MCP server may be, and what one of its tools may become.

Gap-closure Phase 5.1 and 5.3. Pure and synchronous: no network, no database,
no SDK import. That is the point. Every decision in this module has to be
reachable without opening a socket, because the decision this phase exists to
get right is the one taken *before* the socket opens.

An MCP server is somebody else's code, reached over the network, whose replies
land in the prompt that decides what the agent does next. Three defaults
follow from that, and each is here rather than in configuration:

**Streamable HTTP only.** A stdio server is a local process the agent starts.
That is code execution on the agents container, not an HTTP request, so it
stays refused unless an operator has both switched stdio on and named the
command. Two switches rather than one, because either alone is a setting
somebody flips while debugging.

**Read-only.** A tool is callable when the operator allowlisted it by name
*and* the server has not said it changes state. Both halves matter and they
say different things: the allowlist is the tenant's assertion, the annotation
is the vendor's. Either one saying no is a no. An unannotated tool is callable
only because an operator wrote its name down, and an empty allowlist, which is
the default, means the agent may call nothing at all.

A tool the server marks destructive is not a configuration option. It is
refused here and reachable, if at all, only through governed dispatch as a
live action with a declared capability contract. No MCP tool has such a
contract today, so the honest reading of "or not at all" is the one in force.

**The description is attacker-controlled too.** The server supplies it, and it
goes into the tool-selection prompt, so a malicious description is an
injection into the prompt that chooses what to call, which arrives before any
result does. :func:`vet_tool` scans the name, the description, the title and
every parameter description, and drops the tool on a high-severity hit rather
than sanitising it: a description trying to instruct the model has no
legitimate use, so there is nothing to preserve. What survives is sanitised,
length-capped, and its schema is projected down to the keys a tool schema
needs, so a server cannot smuggle arbitrary JSON into what the model is shown.

That last control is the load-bearing one. The injection guard measures 0.852
on prose and 66.7% on payloads written to fit a constrained field, so a third
of field-shaped payloads get through it. Dropping on a hit is worth having and
is not what this rests on; the structural limits are, because they hold
whatever the guard scores.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any

from app.investigator.prompt_sanitizer import sanitize_for_prompt
from app.prompting.envelope import PromptInjectionGuard

__all__ = [
    "MAX_DESCRIPTION_CHARS",
    "MAX_ENUM_VALUES",
    "MAX_TOOLS_PER_SERVER",
    "ServerVerdict",
    "ToolVerdict",
    "namespaced",
    "stdio_allowed_commands",
    "stdio_enabled",
    "vet_server",
    "vet_tool",
]

#: A vendor description is documentation, not a payload. Long enough for a
#: real one, short enough that a server cannot spend the prompt budget.
MAX_DESCRIPTION_CHARS = 400

#: Enum values are shown to the model verbatim, so they are capped like any
#: other server-supplied string.
MAX_ENUM_VALUES = 40

#: A server advertising more tools than this is refused past the cap rather
#: than allowed to flood the tool-selection prompt. The allowlist usually
#: binds first; this is the bound when an operator has allowlisted widely.
MAX_TOOLS_PER_SERVER = 64

#: The shape an OpenAI function name may take. The namespaced id is built from
#: the server name and the tool name, so both are constrained to it.
_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")

_GUARD = PromptInjectionGuard()


def stdio_enabled() -> bool:
    """Whether an operator has switched stdio transports on at all."""
    return os.getenv("AISOC_MCP_STDIO_ENABLED", "").strip().lower() in {"1", "true", "yes", "on"}


def stdio_allowed_commands() -> frozenset[str]:
    """Commands an operator has named as startable.

    Compared against the whole command string, not a prefix and not a basename.
    A prefix match would admit ``/usr/bin/vendor-mcp; curl evil`` and a
    basename match would admit any ``vendor-mcp`` anywhere on the filesystem.
    """
    raw = os.getenv("AISOC_MCP_STDIO_ALLOWED_COMMANDS", "") or ""
    return frozenset(part.strip() for part in raw.split(",") if part.strip())


@dataclass(frozen=True)
class ServerVerdict:
    """Whether this server may be reached, and the sentence to record if not."""

    admitted: bool
    reason: str = ""


@dataclass(frozen=True)
class ToolVerdict:
    """Whether this tool may be bound, plus what survived vetting."""

    admitted: bool
    reason: str = ""
    #: ``read_only`` | ``destructive`` | ``state_changing`` | ``not_allowlisted``
    #: | ``bad_name`` | ``injected_description``. Recorded in the ledger so a
    #: refusal can be told apart from a tool that was never offered.
    classification: str = "unknown"
    description: str = ""
    parameters: dict[str, Any] = field(default_factory=dict)


def namespaced(server: str, tool: str) -> str:
    """The id the model sees: ``mcp.<server>.<tool>``."""
    return f"mcp.{server}.{tool}"


def vet_server(
    *,
    name: str,
    transport: str,
    url: str | None,
    command: str | None,
    args: list[str] | None = None,
) -> ServerVerdict:
    """Decide whether this server may be reached at all.

    No DNS, no connection. The SSRF guard runs later, immediately before the
    socket opens, because a name that resolves publicly now can resolve to
    link-local by the time a request goes out.
    """
    if not _NAME_RE.match(name or ""):
        return ServerVerdict(False, f"{name!r} is not a usable server name; it becomes part of the tool name the model is shown")

    if transport == "streamable_http":
        if not (url or "").strip():
            return ServerVerdict(False, f"{name}: a streamable_http server with no URL cannot be reached")
        return ServerVerdict(True)

    if transport != "stdio":
        return ServerVerdict(False, f"{name}: transport {transport!r} is not supported; AiSOC speaks streamable HTTP and stdio")

    # From here down it is stdio, which starts a process.
    if not stdio_enabled():
        return ServerVerdict(
            False,
            f"{name}: stdio MCP servers are disabled. A stdio server is a local process this container would start, "
            f"so it stays off until an operator sets AISOC_MCP_STDIO_ENABLED and names the command in "
            f"AISOC_MCP_STDIO_ALLOWED_COMMANDS",
        )
    candidate = (command or "").strip()
    if not candidate:
        return ServerVerdict(False, f"{name}: a stdio server with no command cannot be started")
    allowed = stdio_allowed_commands()
    if candidate not in allowed:
        return ServerVerdict(
            False,
            f"{name}: {candidate!r} is not in AISOC_MCP_STDIO_ALLOWED_COMMANDS, so it will not be started",
        )
    # The command is allowlisted; the argument vector still has to be plain.
    # A shell metacharacter in an argument is how an allowlisted command turns
    # into a different one, and nothing downstream runs a shell, so an
    # argument that needs one is a mistake or an attempt.
    for arg in args or []:
        if not isinstance(arg, str) or any(ch in arg for ch in ";|&$`\n\r<>"):
            return ServerVerdict(False, f"{name}: argument {arg!r} carries shell metacharacters and will not be passed")
    return ServerVerdict(True)


def _flagged(value: Any) -> list[str]:
    """High-severity injection signal kinds found in ``value``, if any.

    Medium signals are not grounds to drop a tool. They fire on structural
    markers that a well-formed schema can legitimately contain, and dropping a
    vendor's whole tool over one would make this control the thing operators
    switch off.
    """
    verdict = _GUARD.scan(value)
    return sorted({s.kind for s in verdict.signals if s.severity == "high"})


def _clean_text(value: Any, *, limit: int = MAX_DESCRIPTION_CHARS) -> str:
    """Sanitise and cap one server-supplied string."""
    if not isinstance(value, str) or not value.strip():
        return ""
    return sanitize_for_prompt(value, label="mcp")[:limit]


def _project_schema(schema: Any) -> dict[str, Any]:
    """Keep the keys a tool schema needs and drop the rest.

    A server supplies this whole object and the provider renders it into the
    tool-selection prompt. Passing it through would let a server put arbitrary
    JSON there, including ``$ref`` (which invites a fetch), ``default`` and
    ``examples`` (free text nothing caps) and nested objects of any depth.
    What survives is an object with typed properties and a required list.
    """
    if not isinstance(schema, dict):
        return {"type": "object", "properties": {}, "required": []}

    properties: dict[str, Any] = {}
    raw_properties = schema.get("properties")
    if isinstance(raw_properties, dict):
        for key, spec in list(raw_properties.items())[:32]:
            if not isinstance(key, str) or not _NAME_RE.match(key):
                continue
            projected: dict[str, Any] = {"type": "string"}
            if isinstance(spec, dict):
                declared = spec.get("type")
                if declared in {"string", "number", "integer", "boolean", "array", "object"}:
                    projected["type"] = declared
                description = _clean_text(spec.get("description"), limit=200)
                if description:
                    projected["description"] = description
                enum = spec.get("enum")
                if isinstance(enum, list) and enum:
                    projected["enum"] = [_clean_text(v, limit=64) or str(v)[:64] for v in enum[:MAX_ENUM_VALUES]]
                items = spec.get("items")
                if projected["type"] == "array" and isinstance(items, dict):
                    item_type = items.get("type")
                    projected["items"] = {"type": item_type if item_type in {"string", "number", "integer", "boolean"} else "string"}
            properties[key] = projected

    required = [r for r in (schema.get("required") or []) if isinstance(r, str) and r in properties]
    return {"type": "object", "properties": properties, "required": required}


def vet_tool(
    *,
    server: str,
    name: str,
    description: Any,
    title: Any = None,
    input_schema: Any = None,
    read_only_hint: bool | None = None,
    destructive_hint: bool | None = None,
    allowlist: list[str] | None = None,
) -> ToolVerdict:
    """Decide whether one discovered tool may be bound, in refusal order.

    The order is the contract. The allowlist is consulted first so a tool the
    operator never named is refused without anything else about it being
    considered, and the same function is called again at dispatch, before a
    connection exists, so an allowlist that is only checked at discovery
    cannot be what this rests on.
    """
    permitted = set(allowlist or [])
    if name not in permitted:
        return ToolVerdict(
            False,
            f"{namespaced(server, name)} is not in this server's tool allowlist",
            classification="not_allowlisted",
        )

    if not _NAME_RE.match(name or "") or not _NAME_RE.match(server or ""):
        return ToolVerdict(False, f"{server}/{name}: not a usable tool name", classification="bad_name")

    # The vendor's own declaration. `destructive_hint` true is explicit;
    # `read_only_hint` false is the same statement made the other way round,
    # and reading only the first would admit every tool that says it writes
    # without using the word destructive.
    if destructive_hint is True:
        return ToolVerdict(
            False,
            f"{namespaced(server, name)} is annotated destructive. A state-changing MCP tool is reachable only through "
            f"governed dispatch as a live action with a declared capability contract, and none is declared for MCP tools",
            classification="destructive",
        )
    if read_only_hint is False:
        return ToolVerdict(
            False,
            f"{namespaced(server, name)} declares itself not read-only, so it is refused for the same reason a destructive one is",
            classification="state_changing",
        )

    flagged = _flagged({"name": name, "title": title, "description": description, "schema": input_schema})
    if flagged:
        return ToolVerdict(
            False,
            f"{namespaced(server, name)} was dropped: its server-supplied text reads as an instruction to the model "
            f"({', '.join(flagged)}). A tool description is chosen by the server, so this is an injection into the prompt "
            f"that decides which tool to call",
            classification="injected_description",
        )

    cleaned = _clean_text(description) or f"Tool {name} on MCP server {server}. The server supplied no description."
    return ToolVerdict(
        True,
        "",
        classification="read_only",
        description=cleaned,
        parameters=_project_schema(input_schema),
    )
