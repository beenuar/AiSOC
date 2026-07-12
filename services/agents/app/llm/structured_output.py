"""Fail-closed structured-output validation for LLM responses (Phase 8).

LLMs are asked to return JSON; they routinely wrap it in ``` fences, add a
preamble, or emit a field that violates the contract. Before this, each agent
had its own ad-hoc `_parse_llm_response` that, on a malformed reply, tended to
guess or fall through with a partial object. Passing a half-parsed structured
output downstream (into an autonomy decision, a ledger entry) is worse than
failing.

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

    Strips ``` fences and any prose before the first `{`/`[`. Does NOT attempt
    to repair invalid JSON — a reply we can't parse cleanly is a failure, by
    design.
    """
    if not isinstance(text, str):
        return ""
    stripped = _FENCE_RE.sub("", text.strip())
    # Trim any leading prose before the first JSON opener.
    for opener in ("{", "["):
        idx = stripped.find(opener)
        if idx != -1:
            return stripped[idx:].strip()
    return stripped.strip()


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
