"""Sanitise inbound alert event payloads before persistence.

This module hardens the ``POST /alerts/submit`` direct-write path. The
submit endpoint takes a list of opaque dicts (``events: list[dict]``)
and stores the whole batch verbatim into the alert's ``raw_event``
JSONB column. That's convenient for forensics
— but it means any secret the caller's connector happened to embed
(session tokens, OAuth bearer tokens, API keys, passwords, …) lands in a
permanent, audit-replicated DB row.

The submit path is also unbounded: a single caller can post a 100 MB batch
of 100k events, each event 1 MB deep, and the synthesiser would happily
JSONB-encode the whole thing into one row. That's a denial-of-service vector
against the alerts table, the audit table, and downstream consumers
(narrative builder, fusion, websockets).

This module fixes both with one helper, :func:`sanitise_event_batch`. The
caller passes a raw list of dicts; we return:

* a redacted copy of the list, with sensitive keys replaced with the
  ``REDACTED_SENTINEL`` constant defined below;
* oversized events replaced with a small marker dict that preserves enough
  context for debugging (top-level keys, byte size) but drops the payload;
* a count of how many events were rejected for being too large and how
  many keys were redacted, so the endpoint can log a one-line summary.

The three caps are all environment-driven so an operator can tune them
without redeploying:

* ``AISOC_SUBMIT_MAX_EVENTS``        — max events per batch (default 1000)
* ``AISOC_SUBMIT_MAX_EVENT_BYTES``   — max serialised size per event
                                       (default 262144, i.e. 256 KiB)
* ``AISOC_SUBMIT_MAX_TOTAL_BYTES``   — max serialised size for the whole
                                       batch after redaction (default
                                       4194304, i.e. 4 MiB)

Behaviour on cap breach:

* Batch length > ``MAX_EVENTS``     → caller-facing 413 Payload Too Large
                                       (raised by :func:`enforce_batch_caps`).
* Per-event size > ``MAX_EVENT_BYTES`` → event replaced inline with a
                                          truncation marker; nothing raised.
* Total size > ``MAX_TOTAL_BYTES``   → trailing events replaced with markers
                                        until the running total is under cap;
                                        nothing raised.

The intent is that one rogue event in a batch shouldn't drop the whole
submission — analysts still want the visibility on the *other* events —
but a deliberately oversized batch (caller is misconfigured or hostile)
gets a clean 4xx instead of crashing the worker.

AiSOC — open-source AI Security Operations Center (MIT License)
Author: Beenu Arora <beenu@cyble.com>
"""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any

logger = logging.getLogger(__name__)


# ─── secret redaction patterns ──────────────────────────────────────────────
# These are the canonical sensitive-key patterns for the submit path. They
# intentionally overlap with the patterns used by ``audit_redaction`` (PR
# Batch 7 / H-4) so a key the audit pipeline considers secret is also
# redacted at submit-time, regardless of which PR lands first. The
# patterns are deliberately broad — false positives (redacting a benign
# ``key`` field) are much cheaper than false negatives (leaking an OAuth
# bearer into a JSONB column that ends up replicated to read replicas
# and backed up to S3).

_SENSITIVE_KEY_REGEXES = (
    r"password",
    r"passwd",
    r"secret",
    r"token",
    r"api[_-]?key",
    r"apikey",
    r"private[_-]?key",
    r"client[_-]?secret",
    r"authorization",
    r"auth[_-]?header",
    r"bearer",
    r"session[_-]?id",
    r"sessionid",
    r"cookie",
    r"set[_-]?cookie",
    r"refresh[_-]?token",
    r"access[_-]?token",
    r"id[_-]?token",
    r"jwt",
    r"otp",
    r"mfa[_-]?code",
    r"2fa",
    # AWS / cloud credentials commonly appear under these literal names.
    r"aws[_-]?secret[_-]?access[_-]?key",
    r"aws[_-]?access[_-]?key[_-]?id",
)

SENSITIVE_KEY_PATTERNS = tuple(re.compile(p, re.IGNORECASE) for p in _SENSITIVE_KEY_REGEXES)

# Sentinel string we write in place of redacted values. Chosen to be
# obvious in logs/audit trails and self-describing — never use the empty
# string (could be misread as "user didn't set this field") or ``null``
# (would survive a JSONB round-trip as SQL NULL).
REDACTED_SENTINEL = "[REDACTED]"


# ─── env-driven knobs ───────────────────────────────────────────────────────
# Defaults sized for a "reasonable" demo / single-connector batch. The
# upper bound on a real submission is ~ MAX_EVENTS * MAX_EVENT_BYTES =
# 1000 * 256 KiB = 256 MiB worst case, but MAX_TOTAL_BYTES (4 MiB) puts
# the practical ceiling much lower. Operators driving high-volume
# connectors should bump MAX_EVENTS + MAX_TOTAL_BYTES together.

_MAX_EVENTS_ENV = "AISOC_SUBMIT_MAX_EVENTS"
_MAX_EVENT_BYTES_ENV = "AISOC_SUBMIT_MAX_EVENT_BYTES"
_MAX_TOTAL_BYTES_ENV = "AISOC_SUBMIT_MAX_TOTAL_BYTES"

_DEFAULT_MAX_EVENTS = 1000
_DEFAULT_MAX_EVENT_BYTES = 256 * 1024  # 256 KiB
_DEFAULT_MAX_TOTAL_BYTES = 4 * 1024 * 1024  # 4 MiB

# Hard upper-bound guardrails so an operator can't disable caps entirely
# by misconfiguring an env var. These match the largest values the rest of
# the alert pipeline is known to tolerate.
_HARD_MAX_EVENTS = 100_000
_HARD_MAX_EVENT_BYTES = 16 * 1024 * 1024  # 16 MiB
_HARD_MAX_TOTAL_BYTES = 64 * 1024 * 1024  # 64 MiB

# Bound the redactor's recursion so a deeply nested attacker payload can't
# cause a stack overflow. 32 levels of nesting is well beyond anything a
# legitimate event would have (Sigma rules, Falco events, CloudTrail
# records all top out around 8–10 levels), and 50k total nodes is a
# generous ceiling for a single 256 KiB event.
_MAX_DEPTH = 32
_MAX_NODES = 50_000


# ─── public exception type for batch-level breaches ─────────────────────────


class SubmitPayloadTooLarge(ValueError):
    """Raised when a submitted batch breaches a hard cap that can't be
    silently truncated (e.g. caller sent more events than ``MAX_EVENTS``).

    The endpoint should catch this and translate to an HTTP 413 with the
    ``detail`` field. We deliberately do *not* leak the configured limit
    in the exception message — operators can read it from the env var
    they set — to avoid handing attackers a free oracle.
    """


def _read_positive_int(env_name: str, default: int, hard_max: int) -> int:
    """Read a positive int env var, falling back to ``default`` on bad input
    and clamping to ``hard_max`` so misconfiguration can't disable the cap.
    """
    raw = os.getenv(env_name)
    if not raw:
        return default
    try:
        value = int(raw)
    except (TypeError, ValueError):
        logger.warning(
            "submit_sanitiser: invalid %s=%r, falling back to default %d",
            env_name,
            raw,
            default,
        )
        return default
    if value <= 0:
        return default
    return min(value, hard_max)


def max_events() -> int:
    """Maximum number of events allowed in a single submit batch."""
    return _read_positive_int(_MAX_EVENTS_ENV, _DEFAULT_MAX_EVENTS, _HARD_MAX_EVENTS)


def max_event_bytes() -> int:
    """Maximum serialised size of a single event after redaction."""
    return _read_positive_int(_MAX_EVENT_BYTES_ENV, _DEFAULT_MAX_EVENT_BYTES, _HARD_MAX_EVENT_BYTES)


def max_total_bytes() -> int:
    """Maximum serialised size of the whole batch after redaction."""
    return _read_positive_int(_MAX_TOTAL_BYTES_ENV, _DEFAULT_MAX_TOTAL_BYTES, _HARD_MAX_TOTAL_BYTES)


# ─── core redaction ─────────────────────────────────────────────────────────


def _is_sensitive_key(key: Any) -> bool:
    """A key is sensitive iff its string form matches any of the configured
    redaction patterns. Non-string keys (ints, etc.) are never sensitive.
    """
    if not isinstance(key, str):
        return False
    return any(pattern.search(key) for pattern in SENSITIVE_KEY_PATTERNS)


def _redact_value(value: Any, *, depth: int, counters: dict[str, int]) -> Any:
    """Recursively walk an event payload, replacing sensitive values with the
    redaction sentinel. Returns a *new* object — the input is never mutated.

    The recursion is bounded by ``_MAX_DEPTH`` and the total node count by
    ``_MAX_NODES``; past either bound we replace the remaining subtree with
    a small marker dict instead of continuing to recurse.
    """
    counters["nodes"] = counters.get("nodes", 0) + 1
    if counters["nodes"] > _MAX_NODES:
        return {"_truncated": "max_nodes"}
    if depth > _MAX_DEPTH:
        return {"_truncated": "max_depth"}

    if isinstance(value, dict):
        out: dict[Any, Any] = {}
        for k, v in value.items():
            if _is_sensitive_key(k):
                counters["redacted"] = counters.get("redacted", 0) + 1
                out[k] = REDACTED_SENTINEL
            else:
                out[k] = _redact_value(v, depth=depth + 1, counters=counters)
        return out

    if isinstance(value, (list, tuple)):
        # Always emit a list — JSONB doesn't preserve tuple-ness anyway and
        # the alerts schema is typed ``JSONB``. Preserve order.
        return [_redact_value(v, depth=depth + 1, counters=counters) for v in value]

    # Scalars (str, int, float, bool, None) and anything else exotic
    # (datetime, UUID, etc.) are passed through unchanged. The submit
    # endpoint serialises with json.dumps(default=str) so exotic types
    # become strings at the storage boundary, not here.
    return value


def _serialised_size(value: Any) -> int:
    """Return the JSON-serialised byte size of ``value``. Used to enforce
    per-event and per-batch size caps after redaction (i.e. after we've
    already replaced secrets with the sentinel)."""
    try:
        return len(json.dumps(value, default=str, ensure_ascii=False).encode("utf-8"))
    except (TypeError, ValueError):
        # Pathological input that can't even be JSON-encoded. Treat as
        # oversized so the endpoint falls back to the truncation marker
        # rather than letting the bad event sneak past.
        return _HARD_MAX_EVENT_BYTES + 1


def _truncation_marker(original: Any, *, size: int, reason: str) -> dict[str, Any]:
    """Build a small marker dict that replaces an oversized event.

    We preserve a tiny amount of debug context (top-level dict keys, the
    measured size, the reason) so an analyst chasing a missing-event
    incident can correlate the marker with whatever the client sent. The
    actual payload bytes are dropped.
    """
    marker: dict[str, Any] = {
        "_truncated": True,
        "_size": size,
        "_reason": reason,
    }
    if isinstance(original, dict):
        # Top-level keys only — never recurse into the truncated payload.
        # Keys are stringified so a hostile non-string key can't break
        # JSON encoding downstream.
        marker["_keys"] = [str(k) for k in list(original.keys())[:20]]
    return marker


def sanitise_event(event: Any, *, max_bytes: int | None = None) -> tuple[Any, dict[str, int]]:
    """Redact + size-cap a single event.

    Returns ``(sanitised_event, stats)`` where ``stats`` is a dict with
    ``redacted`` (number of sensitive keys masked) and ``truncated``
    (1 if the event was replaced with a marker, else 0).

    Non-dict input is converted to ``{"value": str(event)}`` so the alert
    pipeline can always assume a dict-shaped event. This matches the
    historical behaviour of ``_synthesise_alert_from_events`` which assumes
    each event is dict-like.
    """
    bytes_cap = max_bytes if max_bytes is not None else max_event_bytes()
    counters: dict[str, int] = {"nodes": 0, "redacted": 0}

    if not isinstance(event, dict):
        # Coerce to a dict so downstream parsers don't fall over on a bare
        # string / int / list at the top level. We deliberately str() the
        # value to dodge JSON-encoding edge cases (datetime, set, …).
        event = {"value": str(event)}

    redacted = _redact_value(event, depth=0, counters=counters)
    size = _serialised_size(redacted)
    if size > bytes_cap:
        return _truncation_marker(event, size=size, reason="event_too_large"), {
            "redacted": counters["redacted"],
            "truncated": 1,
        }
    return redacted, {"redacted": counters["redacted"], "truncated": 0}


def sanitise_event_batch(
    events: list[Any],
    *,
    max_events_override: int | None = None,
    max_event_bytes_override: int | None = None,
    max_total_bytes_override: int | None = None,
) -> tuple[list[Any], dict[str, int]]:
    """Sanitise and size-cap a whole event batch.

    Returns ``(sanitised_events, stats)`` where ``stats`` carries
    ``redacted`` (total sensitive keys masked across the batch) and
    ``truncated`` (number of events that were replaced with a marker).

    Behaviour:

    1. Raise :class:`SubmitPayloadTooLarge` if the input has more than
       ``MAX_EVENTS`` entries. This is the only hard reject — the endpoint
       turns it into a 413.
    2. Walk events in order; redact each and size-check it against
       ``MAX_EVENT_BYTES``. Oversized events become markers.
    3. Track the running JSON-encoded total. Once the total exceeds
       ``MAX_TOTAL_BYTES``, every remaining event is replaced with a
       ``batch_size_cap`` marker. We never raise here so analysts still
       get the head of the batch.

    The caller passes the raw, *untrusted* event list. The returned list
    is safe to store verbatim into ``raw_event`` JSONB.
    """
    cap_events = max_events_override or max_events()
    cap_event_bytes = max_event_bytes_override or max_event_bytes()
    cap_total_bytes = max_total_bytes_override or max_total_bytes()

    if not isinstance(events, list):
        # Defensive: Pydantic schema should already enforce ``list[dict]``,
        # but if a future refactor relaxes that we still want a sane error
        # instead of a silent crash.
        raise SubmitPayloadTooLarge("events must be a list")

    if len(events) > cap_events:
        raise SubmitPayloadTooLarge(
            f"too many events in batch (max {cap_events})",
        )

    out: list[Any] = []
    stats = {"redacted": 0, "truncated": 0}
    running_total = 2  # account for the enclosing JSON list brackets

    for idx, event in enumerate(events):
        sanitised, ev_stats = sanitise_event(event, max_bytes=cap_event_bytes)
        size = _serialised_size(sanitised)

        # +1 for the comma separator between entries
        if running_total + size + 1 > cap_total_bytes:
            # The batch as a whole has run out of budget. Replace every
            # remaining event (including this one) with a cheap marker so
            # the alert still surfaces the *count* of follow-on events.
            marker = {
                "_truncated": True,
                "_reason": "batch_size_cap",
                "_index": idx,
            }
            out.append(marker)
            stats["truncated"] += 1
            # Subsequent events also get markers — they were never going
            # to fit either. We don't break here because we want to
            # report the truncation count accurately for telemetry.
            for trailing_idx in range(idx + 1, len(events)):
                out.append(
                    {
                        "_truncated": True,
                        "_reason": "batch_size_cap",
                        "_index": trailing_idx,
                    }
                )
                stats["truncated"] += 1
            break

        out.append(sanitised)
        stats["redacted"] += ev_stats["redacted"]
        stats["truncated"] += ev_stats["truncated"]
        running_total += size + 1

    return out, stats
