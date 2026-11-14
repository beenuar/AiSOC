"""Refuse connector egress to destinations inside the deployment.

GHSA-cq4g-g6wp-4m2w. The central SSRF guard (``validate_outbound_url``) was
applied across ``services/api`` and ``services/agents`` and nowhere in this
service — yet this is the service whose whole job is opening outbound HTTP to
tenant-controlled base URLs. Reproduced live: a **viewer-role** console JWT
posted ``POST /connectors/splunk/test`` with ``base_url`` pointing at a
loopback listener, and the service fetched ``/services/server/info`` from it
and reflected the parsed response — an authenticated tenant user could reach
cloud metadata (169.254.169.254), internal services, and loopback from this
service's network position, with the test response as an oracle.

What is validated
-----------------
Every **value** in the merged constructor kwargs that is an ``http(s)://``
URL, under whatever key the connector's schema chose (``base_url``,
``api_url``, ``instance_url``, ``gitlab_url``, ``spool_url``, …). Matching on
the value's shape rather than a list of key names is deliberate: the census
found 18 connectors declaring ``base_url`` and a dozen other spellings, and a
key-name list is the kind of one-directional check that silently misses the
next connector. Lists are walked for their string items.

Bare hostnames are validated too, under the same value-shape rule
(GHSA-32q9-5fvr-8wcx). That used to be a stated residual, on the reasoning
that a bare vendor subdomain is not a full destination — which was wrong in
both halves. Nine connectors interpolate a hostname straight into a URL
(``f"https://{self._host}{path}"`` in Duo, ``self._fqdn`` in Cortex XDR,
``tenant_fqdn`` in XSIAM, ``domain`` in Auth0), so ``api_hostname =
169.254.169.254`` reached cloud metadata under a guard that had looked at the
value. And a vendor suffix is not a boundary either: in
``f"https://{account}.lacework.net"`` a single ``/``, ``#``, ``?`` or ``@``
in the value ends the authority and the suffix lands in the path.

A value is treated as a destination when ``https://<value>`` parses to a
hostname that is **plausibly** one: an IP literal, ``localhost``, or a
dot-bearing name whose labels obey the DNS grammar. That is what keeps the
rule from refusing working connectors — an opaque token, a saved-search
name, a glob index pattern and a bare label like ``prod-splunk`` all fail the
grammar and are never looked up. The false-refusal floor is pinned by test,
because a guard that breaks a legitimate connector on upgrade is worse than
the bug it closes.

Two refusal classes, deliberately (same split as the outbound-webhook
delivery path): a *policy* refusal — metadata endpoint, loopback, private
range without ``AISOC_SSRF_ALLOW_PRIVATE``, bad scheme — raises
:class:`EgressRefused`, while a hostname that merely fails to resolve is let
through: the connector cannot connect to it either, and its own "DNS lookup
failed" diagnostic is the message the setup wizard should show.

``AISOC_SSRF_ALLOW_PRIVATE=1`` relaxes the private-range check for on-prem
deployments whose SIEM genuinely lives on RFC 1918 space; the cloud-metadata
blocklist holds regardless, exactly as it does for playbook HTTP steps.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from typing import Any
from urllib.parse import urlsplit

from app.security.ssrf_guard import SSRFError, validate_outbound_url

__all__ = ["EgressRefused", "refuse_internal_destinations"]

#: One DNS label: 1-63 chars, alphanumeric at both ends. Anything a resolver
#: would not accept is not a hostname, and a value that is not a hostname is
#: not a destination — that is the whole false-positive defence.
_LABEL = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")

#: Names that are destinations despite having no dot. ``localhost`` is the
#: one that matters; the others are how a resolver spells it.
_DOTLESS_DESTINATIONS = frozenset({"localhost", "localhost.localdomain"})


def _looks_like_a_destination(host: str) -> bool:
    """Is ``host`` a name or address something could actually connect to?

    Deliberately narrow. A connector's kwargs carry tokens, labels, regions,
    globs and version strings beside its hostname, and the cost of a loose
    rule is refusing one of those on a deployment that worked yesterday.
    """
    if not host or len(host) > 253:
        return False
    bare = host.strip("[]")
    try:
        ipaddress.ip_address(bare)
    except ValueError:
        pass
    else:
        return True
    lowered = host.lower().rstrip(".")
    if lowered in _DOTLESS_DESTINATIONS:
        return True
    labels = lowered.split(".")
    # A dotless label (``prod-splunk``, an opaque token) is not treated as a
    # destination: no connector addresses a vendor that way, and every such
    # value in the census was a label rather than a host.
    return len(labels) > 1 and all(_LABEL.match(label) for label in labels)


def _destination_candidate(value: str) -> str | None:
    """The URL to validate for ``value``, or ``None`` if it is not one.

    A value already carrying a scheme is validated as written. Otherwise it is
    read as an authority — ``https://<value>`` — which is exactly how the
    connectors that interpolate a hostname will assemble it, including the
    delimiter cases where the vendor suffix a format string appends never
    reaches the authority at all.

    The synthesized candidate is rebuilt from the parsed host and port rather
    than passed through, so only the part that decides where a socket would
    open is judged. A connector field holding ``soc@example.com`` is an email
    address, and the URL rule's blanket refusal of userinfo would reject it;
    what matters is that ``user@169.254.169.254`` still resolves to the
    metadata address, and after the rebuild it does.
    """
    if value.startswith(("http://", "https://")):
        return value
    if not value or any(ch.isspace() for ch in value):
        return None
    try:
        parts = urlsplit(f"https://{value}")
        host = parts.hostname
        port = parts.port
    except ValueError:
        # An unparseable authority (a stray ``[``, a port that is not a
        # number) is not a destination this guard can reason about; the
        # client will fail on it just as plainly.
        return None
    if host is None or not _looks_like_a_destination(host):
        return None
    authority = f"[{host}]" if ":" in host else host
    return f"https://{authority}:{port}" if port is not None else f"https://{authority}"


class EgressRefused(ValueError):
    """A connector config named a destination inside the deployment."""

    def __init__(self, field_name: str, reason: str) -> None:
        self.field_name = field_name
        self.reason = reason
        super().__init__(f"{field_name}: destination refused: {reason}")


def refuse_internal_destinations(kwargs: dict[str, Any]) -> None:
    """Validate every URL-shaped value in a connector's constructor kwargs.

    Raises :class:`EgressRefused` naming the offending field on a policy
    refusal. A resolution failure (the guard chains ``socket.gaierror``) is
    not a refusal — see the module docstring.
    """
    for field_name, value in kwargs.items():
        items = value if isinstance(value, list) else [value]
        for item in items:
            if not isinstance(item, str):
                continue
            candidate = _destination_candidate(item)
            if candidate is None:
                continue
            try:
                validate_outbound_url(candidate)
            except SSRFError as exc:
                if isinstance(exc.__cause__, socket.gaierror):
                    continue
                raise EgressRefused(field_name, str(exc)) from exc
