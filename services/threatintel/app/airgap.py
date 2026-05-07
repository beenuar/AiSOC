"""Air-gap egress enforcement for the threat-intel service.

Mirrors the policy implemented in ``services/api/app/core/airgap.py`` but
keeps the dependency surface small: this module reads from the local
``Settings`` and from ``os.environ`` so it can be imported from feed
handlers and the FeedScheduler without coupling them to the full API
service.

Design notes
------------
The threat-intel service is the single largest source of outbound HTTP
in the AiSOC stack — by default it polls AlienVault OTX, CISA KEV, one
or more TAXII servers, and (optionally) MISP / OpenCTI. In an
air-gapped deployment those public feeds must not be contacted at all,
not even to fail closed at request time, because (a) failed DNS to
``otx.alienvault.com`` still leaks the fact that an AiSOC instance
exists, and (b) repeated 30-minute polls produce a steady network
signal even if every request is rejected by an egress proxy.

So the contract here is intentionally stricter than the API service
contract: feeds whose configured URL is public are *refused at
registration time* when ``AISOC_AIRGAPPED=1``. Internal mirrors hosted
on private RFC1918 networks or on suffixes in ``AISOC_AIRGAP_ALLOWLIST``
are still allowed, so customers running an internal CISA KEV mirror or
their own MISP instance can use those without flipping any per-feed
flag.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

from app.config import settings


class AirgapViolation(RuntimeError):
    """Raised when an outbound HTTP request violates the air-gap policy."""


# Internal-looking suffixes; mirror services/api/app/core/airgap.py so
# that operators only need to maintain one mental model of "what counts
# as private". Lowercased; matched as a suffix on the hostname.
_PRIVATE_SUFFIXES: tuple[str, ...] = (
    ".local",
    ".internal",
    ".lan",
    ".intranet",
    ".corp",
    ".home",
    ".localdomain",
    "localhost",
)


def _is_private_address(host: str) -> bool:
    """Return True when ``host`` looks like a private/internal endpoint.

    Accepts both literal IPs (resolved syntactically; we deliberately do
    not perform DNS lookups here because the whole point of air-gap mode
    is to avoid network round-trips) and DNS names. For names we just
    check the suffix list above and treat unqualified single-label hosts
    (no dot) as private — those are virtually always Docker/K8s service
    names like ``opensearch`` or ``redpanda``.
    """

    if not host:
        return False

    candidate = host.strip().lower().rstrip(".")
    if not candidate:
        return False

    # Try IP literal first.
    try:
        ip = ipaddress.ip_address(candidate)
    except ValueError:
        ip = None

    if ip is not None:
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_unspecified
            or ip.is_reserved
        )

    # DNS-style host: unqualified single label is internal-by-default.
    if "." not in candidate:
        return True

    return any(candidate.endswith(suffix) for suffix in _PRIVATE_SUFFIXES)


def _allowlist() -> list[str]:
    """Return the configured allowlist, normalized to lowercase."""

    raw = settings.AISOC_AIRGAP_ALLOWLIST or []
    return [item.strip().lower().lstrip(".") for item in raw if item and item.strip()]


def is_host_allowed_for_airgap(host: str, allowlist: list[str] | None = None) -> bool:
    """Return True iff ``host`` may be contacted under air-gap policy.

    A host is allowed when *any* of the following hold:

    - air-gap mode is disabled entirely
    - the host is private (RFC1918, loopback, internal suffix, or single
      label)
    - the host matches an entry in the operator-supplied allowlist
      (entries are matched as exact host or as a suffix; this is the
      same semantics as the API service so an entry of ``example.com``
      covers ``mirror.example.com`` too)
    """

    if not settings.AISOC_AIRGAPPED:
        return True

    if not host:
        return False

    candidate = host.strip().lower().rstrip(".")
    if not candidate:
        return False

    if _is_private_address(candidate):
        return True

    entries = allowlist if allowlist is not None else _allowlist()
    for entry in entries:
        if not entry:
            continue
        if candidate == entry or candidate.endswith("." + entry):
            return True

    return False


def enforce_airgap_for_url(url: str) -> None:
    """Raise :class:`AirgapViolation` if ``url`` would breach policy.

    Called by feed handlers immediately before issuing an outbound HTTP
    request. Cheap (no DNS, no I/O) so it is safe to call inside hot
    polling loops.
    """

    if not settings.AISOC_AIRGAPPED:
        return

    parsed = urlparse(url)
    host = parsed.hostname or ""
    if not is_host_allowed_for_airgap(host):
        raise AirgapViolation(
            f"air-gap policy blocked outbound request to {host or url!r}"
        )


def airgap_status() -> dict[str, object]:
    """Return a JSON-serializable snapshot of the current air-gap policy.

    Surfaced through the threat-intel ``/healthz`` extension so an
    operator can confirm zero-egress mode is actually engaged on this
    pod, not just on the API.
    """

    return {
        "enabled": bool(settings.AISOC_AIRGAPPED),
        "allowlist": _allowlist(),
    }
