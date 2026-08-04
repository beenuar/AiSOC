"""Self-service field-extraction / transform DSL (Wave 5, W5.3 + W5.2).

A small, safe, declarative pipeline that reshapes an inbound event before it is
normalised — so a tenant can map their own log schema onto OCSF, extract fields
out of a message string, and clean values, WITHOUT shipping code. This is the
engine behind the runtime custom parser (W5.2): a "parser" is just a named,
tenant-scoped list of these ops.

Deliberately NOT a general expression language — there is no ``eval``, no
arbitrary code, a bounded op count, and a bounded regex length. Every op is a
whitelisted verb over a flat/dotted-path event dict.

Supported ops (each a dict with an ``op`` key)::

    {"op": "rename",      "from": "src.field", "to": "dst.field"}
    {"op": "copy",        "from": "src", "to": "dst"}
    {"op": "set",         "field": "f", "value": <any>}
    {"op": "set_default", "field": "f", "value": <any>}   # only if missing/None
    {"op": "drop",        "field": "f"}
    {"op": "lowercase",   "field": "f"}
    {"op": "uppercase",   "field": "f"}
    {"op": "coalesce",    "fields": ["a", "b"], "to": "dst"}  # first non-None
    {"op": "extract",     "field": "msg", "template": "user=%{WORD:user} src=%{IP:src_ip}"}
        # grok-style: %{TOKEN:name} named captures become top-level fields.
        # Literal text is escaped and TOKENs come from a fixed, ReDoS-safe map
        # (WORD/NUMBER/INT/IP/EMAIL/HOST/NOTSPACE/GREEDY) — never raw regex.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

MAX_OPS = 64
MAX_TEMPLATE_LEN = 512
# Hard cap on the string an extract pattern is run against — a defence-in-depth
# bound even though the compiled pattern is ReDoS-safe by construction.
MAX_MATCH_INPUT = 2048
_VALID_OPS = frozenset({"rename", "copy", "set", "set_default", "drop", "lowercase", "uppercase", "coalesce", "extract"})

# Grok-style extraction. The user writes a TEMPLATE, not a raw regex — literal
# text is `re.escape`d and `%{TOKEN:name}` placeholders expand to a FIXED,
# vetted, linear-time token regex. No user data ever becomes regex
# metacharacters, so the op is ReDoS-proof by construction (and not a
# regex-injection sink).
_GROK_TOKENS: dict[str, str] = {
    "WORD": r"\w+",
    "NUMBER": r"\d+",
    "INT": r"-?\d+",
    "IP": r"\d{1,3}(?:\.\d{1,3}){3}",
    "EMAIL": r"[^\s@]+@[^\s@]+",
    "HOST": r"[\w.-]+",
    "NOTSPACE": r"\S+",
    "GREEDY": r".+",
}
_GROK_PLACEHOLDER = re.compile(r"%\{(\w+)(?::(\w+))?\}")


def compile_grok(template: str) -> str:
    """Compile a grok template into a regex built only from `re.escape`d
    literals + constant token patterns (never raw user regex)."""
    parts: list[str] = []
    last = 0
    for m in _GROK_PLACEHOLDER.finditer(template):
        parts.append(re.escape(template[last : m.start()]))
        token, name = m.group(1), m.group(2)
        base = _GROK_TOKENS.get(token.upper())
        if base is None:
            raise TransformError(f"unknown grok token %{{{token}}}; use one of {sorted(_GROK_TOKENS)}")
        parts.append(f"(?P<{name}>{base})" if name else f"(?:{base})")
        last = m.end()
    parts.append(re.escape(template[last:]))
    return "".join(parts)


class TransformError(Exception):
    """A transform pipeline is structurally invalid (rejected at validation)."""


@dataclass
class TransformResult:
    event: dict[str, Any]
    warnings: list[str] = field(default_factory=list)


def _get(obj: dict[str, Any], path: str) -> Any:
    cur: Any = obj
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _set(obj: dict[str, Any], path: str, value: Any) -> None:
    parts = path.split(".")
    cur = obj
    for part in parts[:-1]:
        nxt = cur.get(part)
        if not isinstance(nxt, dict):
            nxt = {}
            cur[part] = nxt
        cur = nxt
    cur[parts[-1]] = value


def _drop(obj: dict[str, Any], path: str) -> None:
    parts = path.split(".")
    cur = obj
    for part in parts[:-1]:
        cur = cur.get(part)
        if not isinstance(cur, dict):
            return
    cur.pop(parts[-1], None)


def validate_transforms(ops: list[dict[str, Any]]) -> None:
    """Reject a structurally-invalid pipeline up front (used by the API when a
    tenant registers a parser)."""
    if not isinstance(ops, list):
        raise TransformError("transforms must be a list")
    if len(ops) > MAX_OPS:
        raise TransformError(f"too many ops ({len(ops)} > {MAX_OPS})")
    for i, op in enumerate(ops):
        if not isinstance(op, dict) or "op" not in op:
            raise TransformError(f"op[{i}] must be a dict with an 'op' key")
        name = op["op"]
        if name not in _VALID_OPS:
            raise TransformError(f"op[{i}] unknown op '{name}'")
        if name == "extract":
            template = str(op.get("template", ""))
            if len(template) > MAX_TEMPLATE_LEN:
                raise TransformError(f"op[{i}] template too long")
            try:
                re.compile(compile_grok(template))
            except re.error as exc:
                raise TransformError(f"op[{i}] invalid extract template: {exc}") from exc


def apply_transforms(event: dict[str, Any], ops: list[dict[str, Any]]) -> TransformResult:
    """Apply a validated pipeline to a COPY of ``event``. Never raises on a
    single bad op at runtime — it records a warning and continues, so one
    malformed field can't drop the whole event."""
    result = TransformResult(event=dict(event))
    ev = result.event
    for i, op in enumerate(ops[:MAX_OPS]):
        name = op.get("op")
        try:
            if name == "rename":
                val = _get(ev, op["from"])
                if val is not None:
                    _set(ev, op["to"], val)
                _drop(ev, op["from"])
            elif name == "copy":
                val = _get(ev, op["from"])
                if val is not None:
                    _set(ev, op["to"], val)
            elif name == "set":
                _set(ev, op["field"], op.get("value"))
            elif name == "set_default":
                if _get(ev, op["field"]) is None:
                    _set(ev, op["field"], op.get("value"))
            elif name == "drop":
                _drop(ev, op["field"])
            elif name in ("lowercase", "uppercase"):
                val = _get(ev, op["field"])
                if isinstance(val, str):
                    _set(ev, op["field"], val.lower() if name == "lowercase" else val.upper())
            elif name == "coalesce":
                for src in op.get("fields", []):
                    val = _get(ev, src)
                    if val is not None:
                        _set(ev, op["to"], val)
                        break
            elif name == "extract":
                val = _get(ev, op["field"])
                if isinstance(val, str):
                    # The pattern is compiled from a grok template: literal text
                    # is re.escape'd and tokens come from a fixed linear-time
                    # map, so it is ReDoS-safe by construction (no raw user
                    # regex). Input is also hard-capped as defence in depth.
                    pattern = compile_grok(str(op.get("template", "")))
                    match = re.search(pattern, val[:MAX_MATCH_INPUT])
                    if match:
                        for key, group in match.groupdict().items():
                            if group is not None:
                                _set(ev, key, group)
        except Exception as exc:  # noqa: BLE001 — a bad op warns, never drops the event
            result.warnings.append(f"op[{i}] '{name}' failed: {type(exc).__name__}")
    return result
