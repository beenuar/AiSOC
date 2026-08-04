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
    {"op": "regex_extract", "field": "msg", "pattern": "user=(?P<user>\\w+)"}
        # named groups become top-level fields
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

MAX_OPS = 64
MAX_PATTERN_LEN = 512
# Hard cap on the string a user-supplied regex is run against. Bounding the
# input length bounds worst-case backtracking to a fixed constant, which is our
# primary ReDoS mitigation for the (tenant-admin-authored) regex_extract op.
MAX_MATCH_INPUT = 2048
_VALID_OPS = frozenset({"rename", "copy", "set", "set_default", "drop", "lowercase", "uppercase", "coalesce", "regex_extract"})
# Reject the classic catastrophic-backtracking shapes: a quantified group whose
# body itself contains a quantifier, e.g. (a+)+ / (a*)* / (a+)* .
_REDOS_SIGNATURE = re.compile(r"\([^)]*[+*][^)]*\)[+*]")


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
        if name == "regex_extract":
            pattern = str(op.get("pattern", ""))
            if len(pattern) > MAX_PATTERN_LEN:
                raise TransformError(f"op[{i}] pattern too long")
            if _REDOS_SIGNATURE.search(pattern):
                raise TransformError(f"op[{i}] pattern has a nested-quantifier (ReDoS) shape; rewrite it")
            try:
                re.compile(pattern)
            except re.error as exc:
                raise TransformError(f"op[{i}] invalid regex: {exc}") from exc


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
            elif name == "regex_extract":
                val = _get(ev, op["field"])
                if isinstance(val, str):
                    # Pattern is validated at registration time (compiles + no
                    # nested-quantifier ReDoS shape); the input is hard-capped so
                    # worst-case backtracking is bounded. The pattern is
                    # tenant-admin configuration (settings:write), not end-user
                    # input. See MAX_MATCH_INPUT / _REDOS_SIGNATURE.
                    match = re.search(str(op.get("pattern", "")), val[:MAX_MATCH_INPUT])
                    if match:
                        for key, group in match.groupdict().items():
                            if group is not None:
                                _set(ev, key, group)
        except Exception as exc:  # noqa: BLE001 — a bad op warns, never drops the event
            result.warnings.append(f"op[{i}] '{name}' failed: {type(exc).__name__}")
    return result
