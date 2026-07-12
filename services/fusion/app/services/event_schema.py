"""Versioned event-schema registry for the fusion consumer (Phase 5).

The reality audit's spine work (Phase 3.1) proved raw events flow end-to-end.
Phase 5 makes that flow *correct under adversity*: a malformed, mis-versioned,
or mis-tenanted message must never (a) crash the consumer or (b) vanish
silently. This module is the schema half of that contract — it validates every
message against a versioned envelope schema before the promoter sees it, and
returns a structured verdict. The dead-letter queue (`dlq.py`) then captures
anything that fails, with the reason, instead of dropping it on the floor.

Two envelope schemas are registered, keyed by the topic they arrive on:

* ``aisoc.raw_events`` — ingest's normalized-event envelope. Must carry an
  ``ocsf_event`` object and resolve to a UUID tenant. ``schema_version``
  defaults to ``v1`` when absent (every event ingest emits today is v1); an
  unrecognised version is dead-lettered rather than mis-parsed.
* ``aisoc.alerts.raw`` — the vendor RawAlert envelope. Structural check here;
  the deep Pydantic validation stays in the consumer and its failure is also
  dead-lettered.

Adding a field to an envelope is backward-compatible (unknown fields are
ignored). Renaming/removing a required field, or bumping the wire format, must
add a new version string to :data:`KNOWN_SCHEMA_VERSIONS` — the drift test in
``test_event_schema.py`` fails if the registered set changes without a
conscious edit, so the wire contract can't move unnoticed.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

SCHEMA_VERSION_FIELD = "schema_version"
DEFAULT_SCHEMA_VERSION = "v1"

# The wire contract. Bump deliberately; the drift test guards this set.
KNOWN_SCHEMA_VERSIONS: dict[str, frozenset[str]] = {
    "aisoc.raw_events": frozenset({"v1"}),
    "aisoc.alerts.raw": frozenset({"v1"}),
}


@dataclass(frozen=True)
class EventValidation:
    """Verdict for one message. ``ok`` gates processing; the rest is for the
    DLQ record and lineage logging."""

    ok: bool
    schema_version: str
    reason: str = ""
    source_event_id: str | None = None
    tenant_id: str | None = None


def resolve_schema_version(payload: dict[str, Any]) -> str:
    v = payload.get(SCHEMA_VERSION_FIELD)
    return str(v) if isinstance(v, str | int) and str(v).strip() else DEFAULT_SCHEMA_VERSION


def _resolve_source_event_id(payload: dict[str, Any], ocsf: dict[str, Any] | None) -> str | None:
    for candidate in (payload.get("event_id"), payload.get("id")):
        if isinstance(candidate, str) and candidate:
            return candidate
    if ocsf is not None:
        meta = ocsf.get("metadata")
        if isinstance(meta, dict):
            uid = meta.get("uid")
            if isinstance(uid, str) and uid:
                return uid
    return None


def validate_raw_event(payload: Any, *, topic: str = "aisoc.raw_events") -> EventValidation:
    """Validate an ingest normalized-event envelope."""
    version = DEFAULT_SCHEMA_VERSION
    if not isinstance(payload, dict):
        return EventValidation(ok=False, schema_version=version, reason="payload is not a JSON object")

    version = resolve_schema_version(payload)
    known = KNOWN_SCHEMA_VERSIONS.get(topic, frozenset())
    if version not in known:
        return EventValidation(ok=False, schema_version=version, reason=f"unknown schema_version '{version}' for {topic}")

    ocsf = payload.get("ocsf_event")
    if not isinstance(ocsf, dict):
        return EventValidation(ok=False, schema_version=version, reason="missing or non-object 'ocsf_event'")

    tenant_raw = payload.get("tenant_id") or ocsf.get("tenant_uid")
    try:
        tenant_id = str(uuid.UUID(str(tenant_raw)))
    except (ValueError, TypeError):
        return EventValidation(
            ok=False,
            schema_version=version,
            reason="tenant_id is not a UUID (mis-configured connector)",
            source_event_id=_resolve_source_event_id(payload, ocsf),
        )

    return EventValidation(
        ok=True,
        schema_version=version,
        source_event_id=_resolve_source_event_id(payload, ocsf),
        tenant_id=tenant_id,
    )


def validate_raw_alert(payload: Any, *, topic: str = "aisoc.alerts.raw") -> EventValidation:
    """Structural check for a vendor RawAlert envelope.

    Deep field validation stays in the consumer (Pydantic); this catches the
    gross-shape failures (non-object, unknown version) so they are dead-lettered
    with a clear reason rather than raising deep in model construction.
    """
    version = DEFAULT_SCHEMA_VERSION
    if not isinstance(payload, dict):
        return EventValidation(ok=False, schema_version=version, reason="payload is not a JSON object")
    version = resolve_schema_version(payload)
    known = KNOWN_SCHEMA_VERSIONS.get(topic, frozenset())
    if version not in known:
        return EventValidation(ok=False, schema_version=version, reason=f"unknown schema_version '{version}' for {topic}")
    source_event_id = _resolve_source_event_id(payload, None)
    tenant = payload.get("tenant_id")
    return EventValidation(
        ok=True,
        schema_version=version,
        source_event_id=source_event_id,
        tenant_id=str(tenant) if tenant is not None else None,
    )


def validate_event(topic: str, payload: Any, *, raw_events_topic: str, alerts_raw_topic: str) -> EventValidation:
    """Dispatch validation by the topic a message arrived on."""
    if topic == raw_events_topic:
        return validate_raw_event(payload, topic="aisoc.raw_events")
    # Everything else is treated as a RawAlert envelope.
    return validate_raw_alert(payload, topic="aisoc.alerts.raw")
