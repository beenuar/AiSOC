"""Fail-closed structured-output validation for LLM responses (Phase 8).

LLMs are asked to return JSON; they routinely wrap it in ``` fences, add a
preamble, or emit a field that violates the contract. Passing a half-parsed
structured output downstream (into an autonomy decision, a ledger entry) is
worse than failing.

This module claimed to have replaced the agents' ad-hoc parsers. It had not:
until `auto_triage_agent` was wired to `extract_json_block`, nothing in
production imported it at all, and its tests were the only callers — a passing
test on an uncalled function looks exactly like a working feature.

`auto_triage_agent` now shares the extraction step. `cloud_agent`,
`identity_agent`, `insider_threat_agent` and `phishing_agent` each still carry
their own `_parse_llm_response`; that is a real remaining gap, recorded here
rather than described as done.

This module is the single, fail-closed parser: it extracts the JSON body,
validates it against a caller-supplied validator (typically a Pydantic model's
`model_validate`), and on ANY failure returns a structured error rather than a
partial object. `validate_or_fallback` gives callers a deterministic default so
a bad LLM reply degrades instead of crashing.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

_FENCE_RE = re.compile(r"^\s*```(?:json)?\s*|\s*```\s*$", re.IGNORECASE)


@dataclass(frozen=True)
class ParseResult:
    ok: bool
    value: Any = None
    error: str = ""


def extract_json_block(text: str) -> str:
    """Best-effort extraction of a JSON object/array from an LLM reply.

    Strips ``` fences and prose on *both* sides of the JSON body. Does NOT
    attempt to repair invalid JSON — a reply we can't parse cleanly is a
    failure, by design.

    Trailing prose used to defeat this: it trimmed everything before the first
    ``{`` and nothing after the last ``}``, so a model that answered correctly
    and then added "Hope that helps!" was scored as unparseable. Extraction and
    repair are different things — finding where the JSON ends is still reading
    what the model said, not guessing at what it meant.

    The scan is brace-balanced and string-aware, because a closing brace inside
    a string value ("rationale": "he typed }") is not the end of the object.
    """
    if not isinstance(text, str):
        return ""
    stripped = _FENCE_RE.sub("", text.strip())
    starts = [i for i in (stripped.find("{"), stripped.find("[")) if i != -1]
    if not starts:
        return stripped.strip()
    start = min(starts)
    end = _matching_close(stripped, start)
    return (stripped[start:end] if end is not None else stripped[start:]).strip()


def _matching_close(text: str, start: int) -> int | None:
    """Index just past the bracket that closes the one at ``start``.

    ``None`` when it is never closed, so the caller keeps the remainder and
    lets the JSON parser report the truncation rather than silently trimming.
    """
    opener = text[start]
    closer = {"{": "}", "[": "]"}[opener]
    depth = 0
    in_string = False
    escaped = False
    for idx in range(start, len(text)):
        char = text[idx]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == opener:
            depth += 1
        elif char == closer:
            depth -= 1
            if depth == 0:
                return idx + 1
    return None


def parse_structured(
    text: str,
    validator: Callable[[dict[str, Any]], Any] | None = None,
) -> ParseResult:
    """Parse + validate an LLM structured reply. Fail-closed.

    Returns ``ParseResult(ok=True, value=...)`` only when the text parses as
    JSON *and* (if a validator is given) passes it. Any failure yields
    ``ok=False`` with a reason — never a partial object.
    """
    body = extract_json_block(text)
    if not body:
        return ParseResult(ok=False, error="empty response")
    try:
        parsed = json.loads(body)
    except (json.JSONDecodeError, ValueError) as exc:
        return ParseResult(ok=False, error=f"invalid JSON: {exc}")
    if validator is None:
        return ParseResult(ok=True, value=parsed)
    try:
        validated = validator(parsed)
    except Exception as exc:  # noqa: BLE001 — any validator error is a failure
        return ParseResult(ok=False, error=f"schema validation failed: {exc}")
    return ParseResult(ok=True, value=validated)


def validate_or_fallback(
    text: str,
    fallback: Any,
    validator: Callable[[dict[str, Any]], Any] | None = None,
) -> tuple[Any, bool]:
    """Return ``(value, used_fallback)``. On any parse/validation failure the
    caller-supplied deterministic ``fallback`` is returned so the pipeline
    degrades instead of propagating a malformed structured output."""
    result = parse_structured(text, validator)
    if result.ok:
        return result.value, False
    return fallback, True
