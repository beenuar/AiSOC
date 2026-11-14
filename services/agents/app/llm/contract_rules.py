"""The LLM input contract's rules, with no runtime dependencies (T2.3).

Split out of ``contract.py`` so the *same* classifier can run in
``services/api``. It previously could not: ``contract.py`` imports LangChain,
the cost-telemetry recorder and the response cache, none of which ship in the
API image — so the API service had no input contract at all while seven of its
endpoints POSTed untrusted input straight to a chat-completions API. One of
them (`phishing.py`) forwards an attacker-authored email body by definition.

This module is byte-identical to
``services/api/app/_vendor/llm_contract_rules.py``, kept in lockstep by
``scripts/sync_vendored_llm_contract.py --check`` in CI. Keep it dependency-free
(stdlib + structlog only) or the vendored copy stops importing and the API
silently loses the contract again.

``contract.py`` re-exports everything here, so existing agents callers and
tests are unaffected.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Iterable
from typing import Any

AGENTS_LLM_CONTRACT_ENFORCED_ENV = "AISOC_AGENTS_LLM_CONTRACT_ENFORCED"

_OCSF_KEYS = frozenset(
    {
        "class_uid",
        "category_uid",
        "activity_id",
        "type_uid",
        "metadata",
        "time_dt",
        "observables",
        "raw_data",
    }
)
_LOG_KEYS = frozenset(
    {
        "Event",
        "EventData",
        "Sysmon",
        "RecordID",
        "EventRecordID",
        "Channel",
        "Provider",
        "_raw",
        "_time",
        "punct",
    }
)

# Union of dict keys that must never appear in LLM-bound JSON strings
# (prompt serialization uses this to redact / shallow-summarize nested data).
CONTRACT_DICT_KEY_BLOCKLIST: frozenset[str] = frozenset(_OCSF_KEYS | _LOG_KEYS)

# Compact regex for the most common raw-log signatures we want to catch
# even when the payload is rendered as a string instead of a dict.
_LOG_SHAPE_PATTERNS = (
    re.compile(r'"class_uid"\s*:\s*\d+'),
    re.compile(r'"activity_id"\s*:\s*\d+'),
    re.compile(r'"EventID"\s*:\s*\d+'),
    re.compile(r'"EventRecordID"\s*:\s*\d+'),
    re.compile(r'<Event xmlns="http://schemas\.microsoft\.com/win/'),
    # Splunk / Sentinel "search head" envelope
    re.compile(r'"_raw"\s*:\s*"'),
    re.compile(r'"sourcetype"\s*:\s*"'),
)

# Loose secret patterns — caught only as a last-resort guard. The vault
# layer (T*.4) is the primary defence; this is belt-and-braces.
_SECRET_PATTERNS = (
    re.compile(r"(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
)

_MAX_MESSAGE_CHARS = int(os.getenv("AISOC_AGENTS_LLM_CONTRACT_MAX_CHARS", "60000"))
_MAX_JSON_LINE_KEYS = 6  # tuple-of-keys threshold for "looks like a log line"


class LLMContractViolation(RuntimeError):
    """Raised when a prompt about to be sent to an LLM violates the contract."""

    def __init__(self, reason: str, *, role: str | None = None, evidence: str | None = None) -> None:
        msg = f"[LLMInputContract] {reason}"
        if role:
            msg += f" (role={role})"
        if evidence:
            msg += f" — evidence: {evidence[:200]!r}"
        super().__init__(msg)
        self.reason = reason
        self.role = role
        self.evidence = evidence


# ---------------------------------------------------------------------------
# Enforcement toggle
# ---------------------------------------------------------------------------

# Module-level cache so callers can flip enforcement at runtime via
# :func:`set_contract_enforcement`. The env var is the source of truth on
# fresh process start.


def _env_default_enforced() -> bool:
    raw = os.getenv(AGENTS_LLM_CONTRACT_ENFORCED_ENV, "1").strip()
    return raw not in {"0", "false", "False", "no", "off"}


_ENFORCED: bool = _env_default_enforced()


def is_contract_enforced() -> bool:
    return _ENFORCED


def set_contract_enforcement(value: bool) -> bool:
    """Override enforcement at runtime. Returns the previous value."""
    global _ENFORCED  # noqa: PLW0603
    prev, _ENFORCED = _ENFORCED, bool(value)
    return prev


# ---------------------------------------------------------------------------
# Heuristic classifier — does this message look like raw log / OCSF?
# ---------------------------------------------------------------------------


def _looks_like_ocsf(payload: dict[str, Any]) -> str | None:
    matched = _OCSF_KEYS & set(payload.keys())
    if matched:
        return f"OCSF keys present: {sorted(matched)}"
    metadata = payload.get("metadata")
    if isinstance(metadata, dict) and {"product", "version"} <= set(metadata.keys()):
        return "OCSF-style metadata.product/version block"
    return None


def _looks_like_raw_log(payload: dict[str, Any]) -> str | None:
    matched = _LOG_KEYS & set(payload.keys())
    if matched:
        return f"raw-log keys present: {sorted(matched)}"
    if isinstance(payload.get("EventID"), int) and "Channel" in payload:
        return "Windows event-log shape (EventID + Channel)"
    return None


def _looks_like_log_string(text: str) -> str | None:
    head = text[:4000]
    for pattern in _LOG_SHAPE_PATTERNS:
        m = pattern.search(head)
        if m:
            return f"raw-log signature matched: {m.group(0)[:80]}"
    return None


def _looks_like_secret(text: str) -> str | None:
    head = text[:4000]
    for pattern in _SECRET_PATTERNS:
        m = pattern.search(head)
        if m:
            return f"secret-shaped value detected: {m.group(0)[:60]}"
    return None


def _try_load_json(text: str) -> Any | None:
    """Parse ``text`` as JSON if it looks like one; return ``None`` otherwise."""
    stripped = text.strip()
    if not stripped or stripped[0] not in "[{":
        return None
    try:
        return json.loads(stripped)
    except (json.JSONDecodeError, ValueError):
        return None


def classify_message(content: str, *, role: str = "user") -> str | None:
    """Return a violation reason if ``content`` breaches the contract, else None."""
    if not isinstance(content, str):
        # Multi-modal (list-of-parts) messages aren't supported by the
        # contract yet — reject them so we never leak them by accident.
        return f"non-string message content (type={type(content).__name__})"

    if len(content) > _MAX_MESSAGE_CHARS:
        return f"message exceeds size cap ({len(content)} > {_MAX_MESSAGE_CHARS} chars)"

    # 1) Substring scan — fastest path, catches log shapes embedded in prose.
    log_hit = _looks_like_log_string(content)
    if log_hit:
        return log_hit

    secret_hit = _looks_like_secret(content)
    if secret_hit:
        return secret_hit

    # 2) JSON inspection — only when the message *looks* like JSON we try
    # to parse it. Avoids paying parse cost on every prose message.
    parsed = _try_load_json(content)
    if isinstance(parsed, dict):
        ocsf = _looks_like_ocsf(parsed)
        if ocsf:
            return ocsf
        log = _looks_like_raw_log(parsed)
        if log:
            return log
    elif isinstance(parsed, list) and parsed:
        head = parsed[0]
        if isinstance(head, dict):
            if len(head) > _MAX_JSON_LINE_KEYS and (_looks_like_ocsf(head) or _looks_like_raw_log(head)):
                return "raw event array detected (looks like log batch)"

    return None


# ---------------------------------------------------------------------------
# Contract model
# ---------------------------------------------------------------------------


class LLMInputContract:
    """Validator for the message list handed to ``llm.ainvoke``.

    Implemented as a class with a ``validate`` classmethod (rather than a
    Pydantic ``BaseModel``) because LangChain's ``BaseMessage`` subclasses
    don't round-trip cleanly through Pydantic v2 validation. The contract
    invariants are enforced via :func:`classify_message` per element.
    """

    @classmethod
    def validate(cls, messages: Iterable[Any]) -> list[dict[str, Any]]:
        """Return the normalised view of ``messages`` if all pass the contract.

        Each returned dict has shape ``{"role": str, "content": str}``.
        Raises :class:`LLMContractViolation` on the first breach.
        """
        normalised: list[dict[str, Any]] = []
        for idx, msg in enumerate(messages):
            role, content = _coerce_message(msg)
            if is_contract_enforced():
                reason = classify_message(content, role=role)
                if reason:
                    raise LLMContractViolation(
                        f"message[{idx}] failed contract: {reason}",
                        role=role,
                        evidence=content[:200],
                    )
            normalised.append({"role": role, "content": content})
        return normalised


def _coerce_message(msg: Any) -> tuple[str, str]:
    """Best-effort extract (role, content) from a chat-message-shaped object.

    Supports plain dicts, LangChain ``BaseMessage`` subclasses, and tuples
    of ``(role, content)``. Falls back to ``("user", str(msg))`` so the
    contract still has *something* to validate.
    """
    if isinstance(msg, dict):
        role = str(msg.get("role") or "user")
        content = msg.get("content")
        return role, content if isinstance(content, str) else json.dumps(content, default=str)
    if hasattr(msg, "type") and hasattr(msg, "content"):
        # LangChain BaseMessage: ``.type`` is "system" / "human" / "ai" / "tool"
        type_to_role = {"human": "user", "ai": "assistant", "system": "system", "tool": "tool"}
        role = type_to_role.get(getattr(msg, "type", "user"), "user")
        content = getattr(msg, "content", "")
        return role, content if isinstance(content, str) else json.dumps(content, default=str)
    if isinstance(msg, tuple) and len(msg) == 2:
        role, content = msg
        return str(role), content if isinstance(content, str) else json.dumps(content, default=str)
    return "user", str(msg)


def validate_messages(messages: Iterable[Any]) -> list[dict[str, Any]]:
    """Module-level convenience for one-off validation."""
    return LLMInputContract.validate(messages)
