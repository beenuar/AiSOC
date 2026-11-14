"""TAXII 2.1 collections over the tenant IOC store.

Depth plan 4.2 / parity 6.10.

This module holds the two things that are easy to get subtly wrong and
expensive to discover later: the STIX 2.1 projection of an indicator, and
the ``added_after`` pagination contract. The HTTP surface in
``app.api.v1.endpoints.taxii`` is deliberately thin over it.

What a TAXII client actually needs
----------------------------------
A client bookmarks a collection id, polls it, and remembers the ``X-TAXII-Date-Added-Last``
of what it saw. On the next poll it sends that back as ``added_after``. If the
server's ordering is not total and stable, the client silently loses
indicators: two rows with the same timestamp either both come back forever or
one is skipped, depending on which side of the boundary the cursor lands. So
the sort key here is ``(updated_at, id)`` and the ``added_after`` predicate is
a row-value comparison, not a bare ``>`` on the timestamp.

Why the server does not store STIX
----------------------------------
A collection is a filtered view over ``threat_intel_iocs``, never a copy. An
indicator edited in the console would otherwise have to be edited twice, and
the version a partner pulls would drift from the version this tenant's own
detections run on.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

#: The one media type TAXII 2.1 defines. A client sends it in Accept and a
#: server must answer with it; a plain ``application/json`` response is a
#: conformance failure and some clients refuse it outright.
TAXII_MEDIA_TYPE = "application/taxii+json;version=2.1"

#: The STIX 2.1 bundle media type collections advertise.
STIX_MEDIA_TYPE = "application/stix+json;version=2.1"

#: Namespace for deterministic STIX identifiers. A STIX id must be stable
#: across polls — a client deduplicates on it — so it is derived from the
#: IOC's own primary key rather than generated per response.
#: Fixed constant, not random: regenerating it would change every published
#: id and make every client re-ingest the whole collection.
_STIX_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")

#: Default and maximum page sizes. The maximum is a server-side cap on what
#: a client may ask for, because ``?limit=1000000`` on a large store is a
#: way to make the API service run out of memory from the outside.
DEFAULT_PAGE_LIMIT = 100
MAX_PAGE_LIMIT = 1000

#: Which IOC types this server is willing to publish, mapped onto the STIX
#: pattern each one becomes. A type with no mapping is not published at
#: all rather than published as a malformed pattern: a client that cannot
#: parse a pattern usually rejects the whole bundle, so one bad indicator
#: would cost the tenant every other one in the page.
_STIX_PATTERNS: dict[str, str] = {
    "ip": "[ipv4-addr:value = '{value}']",
    "cidr": "[ipv4-addr:value = '{value}']",
    "domain": "[domain-name:value = '{value}']",
    "url": "[url:value = '{value}']",
    "email": "[email-addr:value = '{value}']",
    "file_hash_md5": "[file:hashes.'MD5' = '{value}']",
    "file_hash_sha1": "[file:hashes.'SHA-1' = '{value}']",
    "file_hash_sha256": "[file:hashes.'SHA-256' = '{value}']",
    "asn": "[autonomous-system:number = '{value}']",
}

#: IOC types deliberately not published, each with the reason. Recorded
#: rather than left as an absence, so "why is my CVE not in the feed" has
#: an answer in the code.
UNPUBLISHED_IOC_TYPES: dict[str, str] = {
    "cve": (
        "a CVE is a vulnerability identifier, not an observable; STIX models it as a "
        "vulnerability object a TAXII indicator collection is the wrong carrier for"
    ),
}

#: Filter keys a collection may declare. An unknown key is refused at write
#: time: a filter that does not apply publishes more than the tenant asked
#: to publish, and it does so silently.
ALLOWED_FILTER_KEYS = frozenset({"ioc_type", "tlp", "min_confidence", "tags", "source", "severity"})

#: TLP marking-definition ids are fixed by the STIX specification. They are
#: quoted rather than derived, because a marking a partner's tooling does
#: not recognise is a sharing control that silently does nothing.
_TLP_MARKINGS = {
    "white": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "green": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
    "amber": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    "red": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
}

#: Severity is not a STIX field. It is published as a confidence number and
#: as a label, because dropping it would lose the only ranking a consumer
#: has, and inventing a STIX extension for it would be a dialect only this
#: product speaks.
_SEVERITY_LABELS = {
    "critical": "malicious-activity",
    "high": "malicious-activity",
    "medium": "suspicious-activity",
    "low": "anomalous-activity",
    "info": "benign",
}


class FilterError(ValueError):
    """A collection filter the server will not accept."""


def validate_filter(raw: Any) -> dict[str, Any]:
    """Check a collection's ``ioc_filter`` before it is stored.

    Refuses rather than normalises. A filter key this server does not
    understand would be ignored at read time, and an ignored restriction
    publishes more than the tenant asked to publish.
    """
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise FilterError("ioc_filter must be an object")
    unknown = sorted(set(raw) - ALLOWED_FILTER_KEYS)
    if unknown:
        raise FilterError(
            f"unknown filter keys {unknown}; this server understands "
            f"{sorted(ALLOWED_FILTER_KEYS)}. An ignored restriction would publish "
            "more than you asked to publish"
        )
    cleaned: dict[str, Any] = {}
    for key, value in raw.items():
        if key == "min_confidence":
            if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 100:
                raise FilterError("min_confidence must be an integer between 0 and 100")
            cleaned[key] = value
            continue
        if isinstance(value, str):
            value = [value]
        if not isinstance(value, list) or not value:
            raise FilterError(f"{key} must be a non-empty list of strings")
        if not all(isinstance(item, str) and item.strip() for item in value):
            raise FilterError(f"{key} must contain only non-empty strings")
        cleaned[key] = [item.strip() for item in value]
    return cleaned


def stix_id_for(ioc_id: uuid.UUID) -> str:
    """A stable STIX indicator id for one IOC row.

    Derived from the row's primary key so it does not move between polls.
    A client deduplicates on this id; a fresh uuid4 per response would make
    every poll look like a store full of new indicators.
    """
    derived = uuid.uuid5(_STIX_NAMESPACE, str(ioc_id))
    return f"indicator--{derived}"


def pattern_for(ioc_type: str, value: str) -> str | None:
    """The STIX pattern for an IOC, or None when this type is not published."""
    template = _STIX_PATTERNS.get(ioc_type)
    if template is None:
        return None
    # STIX patterns are single-quoted strings. A value containing a quote
    # would end the literal and produce a pattern the consumer's parser
    # rejects — taking the whole bundle with it — so the quote is escaped
    # the way the grammar defines rather than stripped.
    escaped = value.replace("\\", "\\\\").replace("'", "\\'")
    return template.format(value=escaped)


@dataclass(frozen=True)
class IndicatorRow:
    """The IOC fields the projection needs, decoupled from the ORM.

    A dataclass rather than the model so the projection can be driven in a
    test with no database, and so a column rename shows up here as a type
    error instead of as a silently absent STIX field.
    """

    id: uuid.UUID
    ioc_type: str
    value: str
    confidence: int
    severity: str
    tlp: str
    threat_actor: str | None
    campaign: str | None
    malware_family: str | None
    tags: list[str] | None
    source: str
    first_seen: datetime
    last_seen: datetime
    expires_at: datetime | None
    updated_at: datetime
    created_at: datetime


def _rfc3339(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    # STIX timestamps are RFC 3339 with millisecond precision and a literal
    # Z. `isoformat()` emits `+00:00`, which several consumers reject.
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def to_stix_indicator(row: IndicatorRow) -> dict[str, Any] | None:
    """Project one IOC as a STIX 2.1 indicator, or None if unpublishable."""
    pattern = pattern_for(row.ioc_type, row.value)
    if pattern is None:
        return None

    obj: dict[str, Any] = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": stix_id_for(row.id),
        "created": _rfc3339(row.created_at),
        "modified": _rfc3339(row.updated_at),
        "valid_from": _rfc3339(row.first_seen),
        "pattern": pattern,
        "pattern_type": "stix",
        "indicator_types": [_SEVERITY_LABELS.get(row.severity, "unknown")],
        "confidence": max(0, min(100, int(row.confidence))),
    }
    name_parts = [part for part in (row.threat_actor, row.malware_family, row.campaign) if part]
    obj["name"] = " / ".join(name_parts) if name_parts else f"{row.ioc_type} {row.value}"
    if row.expires_at is not None:
        obj["valid_until"] = _rfc3339(row.expires_at)
    labels = list(row.tags or [])
    if row.source:
        labels.append(f"source:{row.source}")
    labels.append(f"severity:{row.severity}")
    obj["labels"] = labels
    marking = _TLP_MARKINGS.get(row.tlp)
    if marking:
        obj["object_marking_refs"] = [marking]
    return obj


def manifest_entry(row: IndicatorRow) -> dict[str, Any]:
    """One entry in a collection's manifest.

    ``version`` is the STIX modified timestamp and ``date_added`` is when
    this server would have published it. They are the same value here
    because a collection is a view: there is no separate publication event
    to record, and inventing one would be a timestamp that means nothing.
    """
    return {
        "id": stix_id_for(row.id),
        "date_added": _rfc3339(row.updated_at),
        "version": _rfc3339(row.updated_at),
        "media_type": STIX_MEDIA_TYPE,
    }


def next_cursor(row: IndicatorRow) -> str:
    """An opaque pagination cursor for the last row of a page.

    Encodes ``(updated_at, id)``, which is the total order the query sorts
    by. A cursor on the timestamp alone would skip or repeat rows that
    share one, and indicators written by the same feed poll routinely do.

    Opaque by construction rather than by convention: a client that parsed
    it would couple itself to a sort key the server must be free to change.
    """
    raw = f"{row.updated_at.astimezone(UTC).isoformat()}|{row.id}"
    digest = hashlib.sha256(raw.encode()).hexdigest()[:8]
    return f"{raw}|{digest}"


def parse_cursor(cursor: str) -> tuple[datetime, uuid.UUID]:
    """Decode a cursor this server issued.

    Raises ``ValueError`` on anything else. The digest is not a security
    control — the cursor carries no privilege — it is there so a truncated
    or hand-edited cursor fails loudly instead of silently paging from a
    different point in the collection.
    """
    parts = cursor.split("|")
    if len(parts) != 3:
        raise ValueError("not a cursor this server issued")
    stamp, row_id, digest = parts
    expected = hashlib.sha256(f"{stamp}|{row_id}".encode()).hexdigest()[:8]
    if digest != expected:
        raise ValueError("cursor is corrupt or was not issued by this server")
    return datetime.fromisoformat(stamp), uuid.UUID(row_id)


def clamp_limit(requested: int | None) -> int:
    """Bound a client's page size.

    An unbounded limit is a way to exhaust this service's memory from the
    outside, and TAXII explicitly allows a server to return fewer objects
    than asked for.
    """
    if requested is None or requested <= 0:
        return DEFAULT_PAGE_LIMIT
    return min(requested, MAX_PAGE_LIMIT)
