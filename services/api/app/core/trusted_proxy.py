"""Trusted-proxy resolution for audit-log IP attribution.

The audit subsystem records ``actor_ip`` for every mutating request.
Historically that value was lifted directly from ``X-Forwarded-For`` whenever
the header was present, which is unsafe behind any reverse proxy or load
balancer that does not strip client-supplied forwarding headers: a hostile
client could trivially spoof their source IP in the audit trail by attaching
``X-Forwarded-For: 10.0.0.1``.

This module gates the use of ``X-Forwarded-For`` on the presence of a
configured allow-list of trusted proxy CIDRs. The rules are:

* If ``AISOC_TRUSTED_PROXIES`` is empty (the default), ``X-Forwarded-For``
  is ignored entirely — we fall back to the direct TCP peer
  (``request.client.host``). This is the safe default: an untrusted edge
  cannot forge audit IPs.
* If it is set, the *immediate* peer (``request.client.host``) MUST itself
  be inside one of the configured CIDRs before we will consult
  ``X-Forwarded-For``. Otherwise the header is again ignored. This prevents
  a hostile client that bypasses the proxy from spoofing the chain.
* When we do consult the header we walk it right-to-left, skipping any
  hop that is itself trusted, and pick the first untrusted address — the
  closest the chain comes to the real originating client.

The module exposes a small surface so the audit service, audit middleware,
and any future code that needs source-IP attribution all converge on the
same algorithm.
"""

from __future__ import annotations

import ipaddress
import logging
import os
from collections.abc import Iterable, Sequence

from fastapi import Request

logger = logging.getLogger("aisoc.audit.trusted_proxy")

# Env var name. Read from os.environ at resolution time rather than pinning
# at import so tests can monkeypatch without re-importing the module.
TRUSTED_PROXIES_ENV = "AISOC_TRUSTED_PROXIES"


def _parse_cidrs(raw: str | None) -> list[ipaddress._BaseNetwork]:
    """Parse a comma-separated CIDR list into network objects.

    Bare IP addresses are accepted and treated as ``/32`` (or ``/128``).
    Invalid entries are dropped with a warning rather than raising — the
    audit pipeline must keep working even if one operator typos the env
    var. The empty string / unset case returns ``[]``.
    """
    if not raw:
        return []
    out: list[ipaddress._BaseNetwork] = []
    for entry in raw.split(","):
        token = entry.strip()
        if not token:
            continue
        try:
            out.append(ipaddress.ip_network(token, strict=False))
        except ValueError as exc:
            logger.warning("trusted_proxies: ignoring invalid CIDR %r: %s", token, exc)
    return out


def _load_trusted_networks() -> list[ipaddress._BaseNetwork]:
    """Resolve the current allow-list from the environment.

    Read lazily so tests can ``monkeypatch.setenv(...)`` between cases.
    """
    return _parse_cidrs(os.getenv(TRUSTED_PROXIES_ENV, ""))


def _ip_in_networks(addr: str, networks: Sequence[ipaddress._BaseNetwork]) -> bool:
    """Return ``True`` if ``addr`` parses as an IP inside any of ``networks``."""
    try:
        ip = ipaddress.ip_address(addr.strip())
    except ValueError:
        return False
    return any(ip in net for net in networks)


def _parse_forwarded_for(header: str | None) -> list[str]:
    """Split a raw ``X-Forwarded-For`` header into individual hops.

    Strips whitespace, drops empties, and tolerates the
    ``[2001:db8::1]:8080`` IPv6 syntax some proxies emit by chopping the
    bracketed host out before further parsing.
    """
    if not header:
        return []
    hops: list[str] = []
    for raw in header.split(","):
        token = raw.strip()
        if not token:
            continue
        # ``[ipv6]:port`` or ``ipv4:port``: drop the optional :port suffix.
        if token.startswith("[") and "]" in token:
            token = token[1 : token.index("]")]
        elif token.count(":") == 1 and "." in token:
            # IPv4 with port — split on the single ':'.
            token = token.split(":", 1)[0]
        hops.append(token)
    return hops


def resolve_client_ip(
    request: Request,
    *,
    trusted_networks: Iterable[ipaddress._BaseNetwork] | None = None,
) -> str | None:
    """Return the best-effort originating client IP for ``request``.

    Algorithm:

    1. ``peer_ip`` = direct TCP peer (``request.client.host``). If absent,
       we cannot attribute anything, return ``None``.
    2. If no trusted-proxy CIDRs are configured, return ``peer_ip``. This
       is the audit-safe default and means ``X-Forwarded-For`` is
       ignored even if present.
    3. If ``peer_ip`` itself is not in the allow-list, also return
       ``peer_ip``. An untrusted edge cannot dictate what we log.
    4. Otherwise walk ``X-Forwarded-For`` from right (closest to us) to
       left (closest to the originator), skipping any hop also in the
       allow-list, and return the first untrusted hop encountered. If
       every hop is trusted (unusual but well-formed for an all-internal
       chain), return the leftmost hop. If the header is missing or
       empty, return ``peer_ip``.

    The function never raises — malformed headers degrade to the direct
    peer.
    """
    client = request.client
    peer_ip = client.host if client else None
    if not peer_ip:
        return None

    nets = list(trusted_networks) if trusted_networks is not None else _load_trusted_networks()
    if not nets:
        # No trusted edge configured: X-Forwarded-For is untrusted noise.
        return peer_ip

    if not _ip_in_networks(peer_ip, nets):
        # Direct peer is not a trusted proxy: ignore any forwarded chain.
        return peer_ip

    hops = _parse_forwarded_for(request.headers.get("x-forwarded-for"))
    if not hops:
        return peer_ip

    for hop in reversed(hops):
        if not _ip_in_networks(hop, nets):
            # Sanity: must parse as an IP at all before we accept it.
            try:
                ipaddress.ip_address(hop)
            except ValueError:
                continue
            return hop

    # Whole chain is trusted — fall back to the outermost hop (the
    # leftmost value), which by convention is the original client.
    leftmost = hops[0]
    try:
        ipaddress.ip_address(leftmost)
    except ValueError:
        return peer_ip
    return leftmost


__all__ = [
    "TRUSTED_PROXIES_ENV",
    "resolve_client_ip",
]
