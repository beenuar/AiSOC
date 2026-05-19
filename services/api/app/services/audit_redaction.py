"""Sanitization of audit-log ``changes`` payloads.

The ``changes`` JSONB column on ``audit_log`` is fed directly from caller
code today. That is two distinct hazards:

* **Secret leakage.** Endpoints often hand the audit helper a dict that
  contains the same fields just persisted to disk — including
  ``password``, ``secret_key``, OAuth refresh tokens, raw API keys, and
  similar high-value fields. Anything written here ends up in the
  tamper-evident, immutable, RLS-scoped audit table; in plain text.
* **Unbounded size.** A poorly bounded import endpoint could attach an
  entire 50 MB payload to a single audit row, blow out Postgres TOAST
  pages, and make ``/api/v1/audit`` listings unusable.

This module exists so every audit write path goes through the same
deterministic sanitizer. The behaviour is intentionally simple:

1. Recursively redact any dict key (case-insensitive) that matches one
   of the patterns in :data:`SENSITIVE_KEY_PATTERNS`. The value is
   replaced with the sentinel string ``"[REDACTED]"`` so downstream
   readers can tell something was scrubbed (vs. a missing field).
2. Enforce a hard size cap by serialising the redacted payload to JSON
   and, if the result exceeds the configured limit, replacing it with a
   small ``{"_truncated": True, ...}`` placeholder that records the
   original byte count. We never silently drop fields.
3. Cap recursion depth and total node count to make sure a hostile
   caller cannot DOS the audit pipeline with a deeply nested or
   million-key payload.

The cap is read lazily from the ``AISOC_AUDIT_MAX_CHANGES_BYTES``
environment variable so operators can dial it without a redeploy.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any

# Substrings (case-insensitive, matched anywhere in the key) that flag a
# value as sensitive. Conservative on purpose — the audit trail is a
# compliance artefact, not a debug log. New patterns should be added
# proactively rather than waiting for a leak.
SENSITIVE_KEY_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"password",
        r"passwd",
        r"secret",
        r"token",
        r"api[_-]?key",
        r"private[_-]?key",
        r"credential",
        r"authorization",
        r"^auth$",
        r"client[_-]?secret",
        r"refresh[_-]?token",
        r"access[_-]?token",
        r"session[_-]?id",
        r"cookie",
        r"otp",
        r"mfa[_-]?code",
        r"recovery[_-]?code",
        r"webhook[_-]?secret",
        r"signing[_-]?key",
    )
)

REDACTED_SENTINEL = "[REDACTED]"

# Defaults — operators override via env. Numbers chosen so the average
# payload (a few hundred bytes of field deltas) fits comfortably while
# catching the genuine pathological cases.
_DEFAULT_MAX_BYTES = 16 * 1024  # 16 KB
_MAX_DEPTH = 8
_MAX_NODES = 2_000

_MAX_BYTES_ENV = "AISOC_AUDIT_MAX_CHANGES_BYTES"


def _max_bytes() -> int:
    """Resolve the configured size cap (bytes).

    Read at call-time so tests can monkeypatch via env. Falls back to the
    default on any parse error so the audit pipeline keeps working even
    if the env is misconfigured.
    """
    raw = os.getenv(_MAX_BYTES_ENV)
    if not raw:
        return _DEFAULT_MAX_BYTES
    try:
        value = int(raw)
    except ValueError:
        return _DEFAULT_MAX_BYTES
    # Guard against silly values; a 0/negative cap would tank every write.
    return max(value, 256)


def _is_sensitive_key(key: str) -> bool:
    if not isinstance(key, str):
        return False
    return any(pat.search(key) for pat in SENSITIVE_KEY_PATTERNS)


def _redact_node(value: Any, depth: int, counter: list[int]) -> Any:
    """Recursive walker — see :func:`redact_changes`."""
    counter[0] += 1
    if counter[0] > _MAX_NODES:
        return REDACTED_SENTINEL
    if depth > _MAX_DEPTH:
        return REDACTED_SENTINEL

    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            key = str(k)
            if _is_sensitive_key(key):
                out[key] = REDACTED_SENTINEL
            else:
                out[key] = _redact_node(v, depth + 1, counter)
        return out
    if isinstance(value, list | tuple):
        return [_redact_node(item, depth + 1, counter) for item in value]
    # Primitives pass through unchanged. We deliberately do NOT inspect
    # the value side for "looks like a token" heuristics — that creates
    # false positives that hide legitimate audit data. Sensitivity is
    # encoded in the key.
    return value


def redact_changes(changes: dict[str, Any] | None) -> dict[str, Any] | None:
    """Return a copy of ``changes`` with sensitive values masked and size-bounded.

    ``None`` and empty inputs pass through unchanged so callers can keep
    using ``changes=None`` as "no payload".
    """
    if not changes:
        return changes

    counter = [0]
    redacted = _redact_node(changes, depth=0, counter=counter)
    # ``_redact_node`` always returns a dict for a dict input.
    assert isinstance(redacted, dict)

    # Size-cap as a final post-processing pass. ``default=str`` ensures
    # exotic but JSON-incompatible values (e.g. ``datetime``) don't crash
    # the serialiser; the row would still be stored as JSONB.
    try:
        encoded = json.dumps(redacted, default=str, separators=(",", ":"))
    except (TypeError, ValueError):
        return {"_truncated": True, "_reason": "unserializable"}

    cap = _max_bytes()
    size = len(encoded.encode("utf-8"))
    if size <= cap:
        return redacted

    return {
        "_truncated": True,
        "_original_size_bytes": size,
        "_max_size_bytes": cap,
    }


__all__ = [
    "redact_changes",
    "REDACTED_SENTINEL",
    "SENSITIVE_KEY_PATTERNS",
]
