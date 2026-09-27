"""The typed vocabulary an agent may search a customer's SIEM with.

Gap-closure Phase 4.1. This module is the security boundary the phase turns
on, so it is worth stating what it is for before what it does.

Why the model cannot write the query
------------------------------------
Federated search already works: ``/federated/search`` fans a ``UnifiedQuery``
out to Splunk, Sentinel, Elastic and QRadar on per-tenant vault-encrypted
credentials. What it accepts is a free-text string plus a list of
``field <op> value`` triples, and the field name reaches each translator as an
*identifier*, interpolated into the query language unquoted, because no query
language quotes identifiers the way it quotes strings.

That is the right shape for a human with ``connectors:read``, who already
holds the SIEM credential and is typing into their own console. It is the
wrong shape to hand a model. The indicator a model passes was lifted out of a
process command line, a file name or a ticket body, all of which are
attacker-influenced, so a model relaying one into a query is one injected
instruction away from an arbitrary query against the customer's SIEM. A read
is not harmless at that scale: a SIEM query can exfiltrate an estate's worth
of telemetry, and an unbounded one can cost real money on a metered licence.

So an agent never names a field and never supplies query text. It names an
**indicator type** from the closed set below and gives a value, and this
module resolves the field. The resolution happens per connector type, which
is strictly better than what the console can express: a single shared field
name cannot be right for Splunk CIM and ECS at once.

What it refuses, and why each refusal is specific
-------------------------------------------------
* an indicator type outside the set: there is no default, because a default
  would answer a question nobody asked and the answer would look like
  evidence
* a value that does not have the *shape* of the type it claims: a "sha256"
  that is not 64 hex characters is not a hash, and searching for it wastes a
  SIEM round trip and returns a confident empty result
* free text of any kind: free text is the one field that lands in the
  backend's default search as a bare term, and there is no shape to validate
  it against, so it cannot be distinguished from query syntax

The value still passes through each translator's own quoting, so this is a
second layer rather than the only one. The first is
``Indicator.__post_init__`` refusing a field name that is not an identifier.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

__all__ = [
    "INDICATOR_TYPES",
    "IndicatorSpec",
    "IndicatorTypeError",
    "fields_for",
    "validate_value",
]


class IndicatorTypeError(ValueError):
    """The indicator type or its value was refused. Never a silent default."""


@dataclass(frozen=True)
class IndicatorSpec:
    """One searchable indicator type.

    ``fields`` maps a connector type to the field tokens to search. A tuple
    rather than a single token because an OR across two fields is often the
    honest query: an IP that appears in an event is a source *or* a
    destination, and picking one silently answers half the question. The
    ``UnifiedQuery`` the federated layer accepts AND-joins its indicators, so
    an OR is expressed by issuing one query per field and merging, which the
    search module does.

    Deliberately capped at two fields per backend. Three would be a fan-out
    multiplier on a metered SIEM licence for a diminishing amount of signal,
    and the tool description tells the model which fields were searched so a
    narrow answer is legible rather than mistaken for a broad one.
    """

    name: str
    description: str
    fields: dict[str, tuple[str, ...]]


#: Field tokens per backend, from each vendor's own normalized schema:
#: Splunk CIM, Microsoft Sentinel ASIM, Elastic Common Schema, and QRadar's
#: AQL column names. They are the schema a deployment following the vendor's
#: own guidance will have; a deployment that has not normalized will get
#: fewer hits, which is visible in the row count rather than silent, and an
#: operator can still use the console's free-form field entry.
#:
#: Not derived from anything. There is no machine-readable source in this
#: repository for "what does Splunk CIM call a source address", so this is a
#: reviewed table, and the alternative (letting the model guess a field name)
#: is the thing this module exists to prevent.
INDICATOR_TYPES: dict[str, IndicatorSpec] = {
    "ip": IndicatorSpec(
        name="ip",
        description="An IPv4 or IPv6 address, searched as both source and destination.",
        fields={
            "splunk": ("src_ip", "dest_ip"),
            "microsoft_sentinel": ("SrcIpAddr", "DstIpAddr"),
            "elastic": ("source.ip", "destination.ip"),
            "qradar": ("sourceip", "destinationip"),
        },
    ),
    "domain": IndicatorSpec(
        name="domain",
        description="A DNS name, searched against the queried or requested domain.",
        fields={
            "splunk": ("query", "dest_host"),
            "microsoft_sentinel": ("DnsQuery", "DstDomain"),
            "elastic": ("dns.question.name", "destination.domain"),
            "qradar": ("domainname",),
        },
    ),
    "url": IndicatorSpec(
        name="url",
        description="A full URL, searched against the requested URL.",
        fields={
            "splunk": ("url",),
            "microsoft_sentinel": ("Url",),
            "elastic": ("url.full",),
            "qradar": ("url",),
        },
    ),
    "sha256": IndicatorSpec(
        name="sha256",
        description="A SHA-256 file digest, 64 hexadecimal characters.",
        fields={
            "splunk": ("file_hash",),
            "microsoft_sentinel": ("SrcFileSHA256", "TargetFileSHA256"),
            "elastic": ("file.hash.sha256", "process.hash.sha256"),
            "qradar": ("filehash",),
        },
    ),
    "sha1": IndicatorSpec(
        name="sha1",
        description="A SHA-1 file digest, 40 hexadecimal characters.",
        fields={
            "splunk": ("file_hash",),
            "microsoft_sentinel": ("SrcFileSHA1",),
            "elastic": ("file.hash.sha1",),
            "qradar": ("filehash",),
        },
    ),
    "md5": IndicatorSpec(
        name="md5",
        description="An MD5 file digest, 32 hexadecimal characters.",
        fields={
            "splunk": ("file_hash",),
            "microsoft_sentinel": ("SrcFileMD5",),
            "elastic": ("file.hash.md5",),
            "qradar": ("filehash",),
        },
    ),
    "hostname": IndicatorSpec(
        name="hostname",
        description="A host or device name.",
        fields={
            "splunk": ("host", "dest"),
            "microsoft_sentinel": ("SrcHostname", "DstHostname"),
            "elastic": ("host.name",),
            "qradar": ("identityhostname",),
        },
    ),
    "username": IndicatorSpec(
        name="username",
        description="An account name or user principal name.",
        fields={
            "splunk": ("user",),
            "microsoft_sentinel": ("ActorUsername", "TargetUsername"),
            "elastic": ("user.name",),
            "qradar": ("username",),
        },
    ),
    "process_name": IndicatorSpec(
        name="process_name",
        description="An executable or image name, for example powershell.exe.",
        fields={
            "splunk": ("process_name",),
            "microsoft_sentinel": ("Process",),
            "elastic": ("process.name",),
            "qradar": ("processname",),
        },
    ),
}

_HEX = {"sha256": 64, "sha1": 40, "md5": 32}

#: A hostname, username or process name is a name, and these are the
#: characters names are made of. Refusing the rest is a shape check rather
#: than an escaping mechanism: the translators still quote, and this stops a
#: value that is obviously not the thing it claims to be from costing a SIEM
#: round trip and coming back as a confident zero.
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@:\\ /-]{0,253}$")
_DOMAIN = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$")

#: Bounded well below any real URL limit. A multi-kilobyte "URL" is a payload
#: rather than an indicator, and length is the cheapest thing to bound.
_MAX_URL = 2048


def validate_value(indicator_type: str, value: str) -> str:
    """Check a value has the shape of the type it claims, and return it.

    Raises ``IndicatorTypeError`` with a reason rather than coercing. A
    coerced value produces a real query with a wrong answer, which is worse
    than a refusal: the refusal reaches the model as "could not check" and the
    wrong answer reaches it as evidence.
    """
    if indicator_type not in INDICATOR_TYPES:
        raise IndicatorTypeError(
            f"{indicator_type!r} is not a searchable indicator type. Known types: {', '.join(sorted(INDICATOR_TYPES))}."
        )
    text = str(value).strip()
    if not text:
        raise IndicatorTypeError(f"an {indicator_type} value is required; an empty search would match the whole window")

    if indicator_type == "ip":
        try:
            ipaddress.ip_address(text)
        except ValueError as exc:
            raise IndicatorTypeError(f"{text!r} is not an IP address") from exc
        return text

    if indicator_type in _HEX:
        width = _HEX[indicator_type]
        if len(text) != width or not all(c in "0123456789abcdefABCDEF" for c in text):
            raise IndicatorTypeError(f"a {indicator_type} is {width} hexadecimal characters; got {len(text)} character(s)")
        return text.lower()

    if indicator_type == "domain":
        if not _DOMAIN.match(text):
            raise IndicatorTypeError(f"{text!r} is not a DNS name")
        return text.lower()

    if indicator_type == "url":
        if len(text) > _MAX_URL:
            raise IndicatorTypeError(f"a URL longer than {_MAX_URL} characters is a payload rather than an indicator")
        if not text.lower().startswith(("http://", "https://")):
            raise IndicatorTypeError("a url must start with http:// or https://")
        # No character-class check beyond the scheme and the length: a URL
        # legitimately carries almost anything after the authority, so a
        # pattern here would refuse real URLs. The translators quote it.
        return text

    if not _NAME.match(text):
        raise IndicatorTypeError(
            f"{text!r} does not have the shape of a {indicator_type}. Names are letters, digits and "
            f". _ @ : \\ / - and spaces, up to 254 characters."
        )
    return text


def fields_for(indicator_type: str, connector_type: str) -> tuple[str, ...]:
    """The field tokens to search on one backend for one indicator type.

    An empty tuple means this backend has no mapping for this indicator type,
    which the caller reports as a coverage gap for that source rather than as
    a search that found nothing.
    """
    spec = INDICATOR_TYPES.get(indicator_type)
    if spec is None:
        raise IndicatorTypeError(f"{indicator_type!r} is not a searchable indicator type")
    return spec.fields.get(connector_type, ())
