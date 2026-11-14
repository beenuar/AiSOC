"""Turn an ingest-normalized OCSF event into something the scorer can score.

UEBA's scorer wants ``(entity_type, entity_id, event_type, features)`` where
``features`` is a flat map of numbers. Nothing in the platform produced that
shape. The consumer's default topic was ``security.events``, which no service
in this repository writes to, so the scorer never ran, ``ueba.anomalies``
never carried a message, and fusion's UEBA confidence boost — enabled by
default — could only ever be inert. This module is the missing translation
between the envelope ingest actually publishes on ``aisoc.raw_events`` and the
shape the scorer already knew how to consume.

Two rules govern what becomes a feature.

**It has to vary.** A z-score against a zero-variance baseline is undefined,
and the scorer reports those as ``features_unscoreable`` rather than as normal
behaviour. So a field that is constant for an entity is not a feature, however
numeric it looks. ``hour_of_day`` earns its place because when someone works
is genuinely characteristic of them; a per-event ``count`` of 1 does not.

**It has to be readable from one event.** Volumetric behaviour — *how many*
logins in ten minutes — is not visible here and is not faked: that is the
windowed detection engine's job, and inventing a per-event approximation of it
would produce a number that looks like a rate and is not one.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

#: Vendor payload fields that are behavioural when present. Each is a genuine
#: magnitude whose distribution per entity carries signal — transfer sizes,
#: session durations, response sizes. Keys are matched case-insensitively
#: against the recovered flat namespace.
_NUMERIC_FIELDS: tuple[str, ...] = (
    "bytes_in",
    "bytes_out",
    "bytes_sent",
    "bytes_received",
    "duration",
    "duration_ms",
    "file_size",
    "request_size",
    "response_size",
    "packets_in",
    "packets_out",
)

#: Outcome spellings that mean "this did not succeed". Failure rate per entity
#: is one of the strongest behavioural signals there is.
_FAILURE_VALUES = frozenset({"failure", "failed", "fail", "denied", "deny", "blocked", "error", "unsuccessful"})

#: Fields carrying the acting identity, most specific first.
_USER_FIELDS: tuple[str, ...] = ("user", "username", "user_name", "actor", "principal", "account")
_HOST_FIELDS: tuple[str, ...] = ("hostname", "host", "device", "device_name", "computer")
_IP_FIELDS: tuple[str, ...] = ("src_ip", "source_ip", "src_endpoint_ip", "client_ip")


@dataclass(frozen=True)
class ExtractedEvent:
    """What the scorer needs, recovered from an ingest envelope."""

    tenant_id: str
    entity_type: str
    entity_id: str
    event_type: str
    features: dict[str, float]
    source_event_id: str | None = None
    peer_group_id: str | None = None
    #: Present only on pre-extracted messages; the OCSF path never sets it.
    raw_features: dict[str, Any] = field(default_factory=dict)


def flat_fields(message: dict[str, Any]) -> dict[str, Any]:
    """Recover the flat field namespace from an ingest envelope.

    This mirrors ``WindowedDetectionEngine._fields`` and the stateless
    detection engine deliberately, and must keep mirroring them. Connectors
    nest the untouched vendor payload one level down under ``raw_event``, so a
    consumer reading the OCSF envelope flat sees ``None`` for every vendor
    field. Connector-normalized keys win on collision, because a connector
    that mapped a vendor's severity ladder onto AiSOC's five tiers must not
    have that undone by the raw vendor value underneath.
    """
    ocsf = message.get("ocsf_event")
    if not isinstance(ocsf, dict):
        return {}
    fields: dict[str, Any] = ocsf
    raw = ocsf.get("raw_data")
    if isinstance(raw, str) and raw.strip():
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                fields = parsed
        except (ValueError, TypeError):
            # `raw_data` is a vendor blob and is not guaranteed to be JSON —
            # some connectors put a plain log line there. Falling back to the
            # OCSF envelope is the right answer, and raising would drop an
            # event over a field this function is only opportunistically
            # reading.
            pass
    elif isinstance(raw, dict):
        fields = raw
    nested = fields.get("raw_event")
    if isinstance(nested, dict):
        merged = {k: v for k, v in nested.items() if isinstance(k, str)}
        merged.update(fields)
        return merged
    return fields


def _first_str(fields: dict[str, Any], names: tuple[str, ...]) -> str | None:
    for name in names:
        value = fields.get(name)
        if isinstance(value, str) and value.strip():
            return value.strip()
        if isinstance(value, dict):
            # OCSF nests identity as ``{"name": ...}`` / ``{"ip": ...}``.
            for key in ("name", "uid", "ip", "hostname"):
                inner = value.get(key)
                if isinstance(inner, str) and inner.strip():
                    return inner.strip()
    return None


def _coerce_float(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


def _parse_time(fields: dict[str, Any], message: dict[str, Any]) -> datetime | None:
    for source in (fields, message):
        for name in ("time", "timestamp", "ts", "event_time", "@timestamp"):
            value = source.get(name)
            if isinstance(value, int | float) and value > 0:
                # OCSF publishes epoch milliseconds; anything past year 2286 in
                # seconds is really milliseconds.
                seconds = value / 1000.0 if value > 10_000_000_000 else float(value)
                try:
                    return datetime.fromtimestamp(seconds, tz=UTC)
                except (OverflowError, OSError, ValueError):
                    continue
            if isinstance(value, str) and value.strip():
                try:
                    return datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
                except ValueError:
                    continue
    return None


def _entity(fields: dict[str, Any]) -> tuple[str, str] | None:
    """Pick the entity this event is about, most specific identity first.

    A user is preferred over a host and a host over an address because a
    behavioural baseline is only meaningful for something that behaves. An IP
    is the last resort, and the least stable: DHCP and NAT both make it a
    different subject over time.
    """
    user = _first_str(fields, _USER_FIELDS)
    if user:
        return "user", user
    host = _first_str(fields, _HOST_FIELDS)
    if host:
        return "device", host
    ip = _first_str(fields, _IP_FIELDS)
    if ip:
        return "ip", ip
    return None


def _event_type(fields: dict[str, Any], ocsf: dict[str, Any]) -> str:
    for name in ("event_type", "activity_name", "class_name", "category_name"):
        value = fields.get(name) or ocsf.get(name)
        if isinstance(value, str) and value.strip():
            return value.strip().lower()
    class_uid = ocsf.get("class_uid")
    if isinstance(class_uid, int):
        return f"class_{class_uid}"
    return "unknown"


def _features(fields: dict[str, Any], message: dict[str, Any]) -> dict[str, float]:
    features: dict[str, float] = {}

    when = _parse_time(fields, message)
    if when is not None:
        features["hour_of_day"] = float(when.hour)
        features["day_of_week"] = float(when.weekday())

    outcome = fields.get("outcome") or fields.get("status") or fields.get("result")
    if isinstance(outcome, str) and outcome.strip():
        features["is_failure"] = 1.0 if outcome.strip().lower() in _FAILURE_VALUES else 0.0

    severity = _coerce_float(fields.get("severity_id"))
    if severity is not None:
        features["severity_id"] = severity

    lowered = {k.lower(): v for k, v in fields.items() if isinstance(k, str)}
    for name in _NUMERIC_FIELDS:
        number = _coerce_float(lowered.get(name))
        if number is not None:
            features[name] = number

    return features


def _from_preextracted(message: dict[str, Any]) -> ExtractedEvent | None:
    """Accept the original ``security.events`` shape unchanged.

    Kept because it is a documented contract and an operator may already be
    producing it from their own pipeline. Nothing in this repository does, but
    silently rejecting a shape the module docstring advertises would replace
    one invisible failure with another.
    """
    tenant_id = message.get("tenant_id")
    entity_id = message.get("entity_id")
    raw_features = message.get("features")
    if not isinstance(tenant_id, str) or not isinstance(entity_id, str):
        return None
    if not entity_id.strip() or not isinstance(raw_features, dict):
        return None

    features: dict[str, float] = {}
    for key, value in raw_features.items():
        number = _coerce_float(value)
        if number is not None:
            features[str(key)] = number
    if not features:
        return None

    peer = message.get("peer_group_id")
    source_id = message.get("event_id")
    return ExtractedEvent(
        tenant_id=tenant_id,
        entity_type=str(message.get("entity_type") or "user"),
        entity_id=entity_id.strip(),
        event_type=str(message.get("event_type") or "unknown"),
        features=features,
        source_event_id=str(source_id) if isinstance(source_id, str) else None,
        peer_group_id=str(peer) if isinstance(peer, str) and peer.strip() else None,
        raw_features=dict(raw_features),
    )


def extract(message: dict[str, Any]) -> ExtractedEvent | None:
    """Recover a scoreable event, or ``None`` if this message carries none.

    ``None`` is a normal outcome, not an error: most telemetry names no
    identity, and an event with no entity has no baseline to deviate from.
    """
    if not isinstance(message, dict):
        return None

    # A pre-extracted message is recognised by carrying its own feature map.
    if isinstance(message.get("features"), dict):
        return _from_preextracted(message)

    ocsf = message.get("ocsf_event")
    if not isinstance(ocsf, dict):
        return None

    tenant_id = message.get("tenant_id") or ocsf.get("tenant_uid")
    if not isinstance(tenant_id, str) or not tenant_id.strip():
        return None

    fields = flat_fields(message)
    if not fields:
        return None

    entity = _entity(fields)
    if entity is None:
        return None
    entity_type, entity_id = entity

    features = _features(fields, message)
    if not features:
        return None

    source_id = message.get("event_id") or ocsf.get("uid") or fields.get("event_id")
    return ExtractedEvent(
        tenant_id=tenant_id.strip(),
        entity_type=entity_type,
        entity_id=entity_id,
        event_type=_event_type(fields, ocsf),
        features=features,
        source_event_id=str(source_id) if source_id else None,
    )
