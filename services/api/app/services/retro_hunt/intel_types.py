"""Translate a feed's own indicator vocabulary into the one AiSOC sweeps with.

Gap-closure Phase 8.1.

A ``NEW_IOC`` event carries whatever type name the feed that produced it uses,
and the four feeds in this repository do not agree on one. The STIX parser and
the OTX client emit STIX names (``ipv4-addr``, ``file-hash:SHA-256``), MISP
emits its own attribute types (``ip-src``, ``sha256``) passed through
unchanged, and the CISA KEV client emits ``vulnerability``. The sweep speaks
the Phase 4 vocabulary
(``app.services.agent_tools.indicators.INDICATOR_TYPES``), because that is the
set the federated SIEM search resolves fields for and the set an agent names.

Something has to sit between them, and the only question is what it does with
a name it does not recognise. Guessing is how this fails quietly: a type
mapped to the wrong indicator produces a real sweep with a wrong answer, and a
type silently dropped produces no sweep at all while the feed's own statistics
say thousands of indicators were ingested. Both read from the outside as "we
were not exposed".

So an unknown type is refused by name and counted, never defaulted.
``scripts/check_ioc_lake_mapping.py`` reads the three producing modules in
``services/threatintel`` and fails when any type they can emit is absent from
both tables below, so a feed that starts publishing a new type cannot become a
silent drop.

``vulnerability`` is the one type that is recognised and deliberately not
swept here. A CVE is not something that appears in event telemetry, so
sweeping the lake for the string "CVE-2024-1234" would match nothing on every
deployment forever. It is routed to the KEV exposure check instead, which asks
the asset and vulnerability inventory rather than the event lake.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = [
    "FEED_TYPE_TO_INDICATOR",
    "NOT_SWEEPABLE",
    "VULNERABILITY_TYPES",
    "TypeRouting",
    "route_feed_type",
]

#: Feed type name -> Phase 4 indicator type.
#:
#: Lower-cased on lookup, so a feed that shouts ``SHA256`` still resolves.
#: Both STIX and MISP spellings are present because both reach this module:
#: the STIX parser normalises OTX and TAXII to STIX names, and the MISP client
#: passes its attribute types through untouched.
FEED_TYPE_TO_INDICATOR: dict[str, str] = {
    # STIX / OTX / TAXII
    "ipv4-addr": "ip",
    "ipv6-addr": "ip",
    "domain-name": "domain",
    "url": "url",
    "file-hash:md5": "md5",
    "file-hash:sha-1": "sha1",
    "file-hash:sha-256": "sha256",
    # MISP attribute types. `ip-src` and `ip-dst` both become `ip` because the
    # sweep searches source and destination columns either way: which end a
    # feed observed the address at says nothing about which end a customer
    # will see it at.
    "ip-src": "ip",
    "ip-dst": "ip",
    "domain": "domain",
    "hostname": "hostname",
    "md5": "md5",
    "sha1": "sha1",
    "sha256": "sha256",
    "filename": "process_name",
    # Bare spellings some feeds use.
    "ip": "ip",
    "ipv4": "ip",
    "ipv6": "ip",
    "sha-1": "sha1",
    "sha-256": "sha256",
}

#: Types that are recognised, are not mistakes, and are not swept against
#: event telemetry. Each value is the reason, which is what a caller logs and
#: what an operator reads.
NOT_SWEEPABLE: dict[str, str] = {
    "email-addr": (
        "An email address is not recorded as a searchable column in the event lake, and the "
        "federated search has no field mapping for one. Mailbox search arrives with the "
        "mailbox remediation verbs."
    ),
    "autonomous-system": (
        "An AS number describes a range rather than an address, and the sweep matches exact "
        "values. Expanding it to its prefixes would be a different feature."
    ),
    "network-traffic": "A STIX network-traffic object is a flow description rather than a single indicator.",
    "email": "See email-addr.",
    "filepath": (
        "The lake records file_path, but a path published by a feed is rarely the path a "
        "customer's estate uses, so matching it exactly would be noise rather than signal."
    ),
    "yara": "A YARA rule is detection content rather than an indicator; it belongs in the detection corpus.",
    "mutex": "No connector in this deployment emits mutex names, so a sweep would return zero on every tenant.",
}

#: Types that mean "a CVE", routed to the KEV exposure check rather than to a
#: telemetry sweep.
VULNERABILITY_TYPES: frozenset[str] = frozenset({"vulnerability", "cve"})


@dataclass(frozen=True)
class TypeRouting:
    """Where one feed type goes.

    Exactly one of ``indicator_type``, ``is_vulnerability`` or ``reason`` is
    meaningful, and the three-way split is the point: "sweep it", "check
    exposure instead" and "do not sweep, here is why" are different answers
    and a boolean could only carry two of them.
    """

    #: Phase 4 indicator type, when the lake or a SIEM can be swept for it.
    indicator_type: str | None = None
    #: True when this is a CVE and belongs to the KEV exposure path.
    is_vulnerability: bool = False
    #: Why it is not swept. Set for every outcome that is not a sweep.
    reason: str | None = None
    #: True when the type is not one any feed in this repository is known to
    #: emit, which is a different problem from a known-but-unsweepable type.
    unknown: bool = False


def route_feed_type(feed_type: str) -> TypeRouting:
    """Decide what to do with one feed's type name."""
    key = str(feed_type or "").strip().lower()
    if not key:
        return TypeRouting(
            reason="The intel event carried no indicator type, so it could not be routed.",
            unknown=True,
        )

    if key in VULNERABILITY_TYPES:
        return TypeRouting(
            is_vulnerability=True,
            reason="A CVE is checked against asset and vulnerability inventory, not against event telemetry.",
        )

    indicator = FEED_TYPE_TO_INDICATOR.get(key)
    if indicator is not None:
        return TypeRouting(indicator_type=indicator)

    known_reason = NOT_SWEEPABLE.get(key)
    if known_reason is not None:
        return TypeRouting(reason=known_reason)

    return TypeRouting(
        reason=(
            f"{feed_type!r} is not an indicator type AiSOC knows how to route. It was NOT swept, "
            f"and this is a coverage gap rather than an absence of the indicator."
        ),
        unknown=True,
    )
