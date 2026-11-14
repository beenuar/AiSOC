"""
Air-gap egress enforcement (Tier 3.1 — air-gapped certification).

When ``AISOC_AIRGAPPED`` is True, every outbound HTTP call from the API
service must be validated against this module before the request is
issued. The contract is intentionally tiny so it can be wrapped around
``httpx.AsyncClient.post()`` / ``httpx.get()`` call sites without
restructuring them:

    from app.core.airgap import enforce_airgap_for_url

    enforce_airgap_for_url(base_url)              # raises AirgapViolation
    async with httpx.AsyncClient() as client:
        await client.post(base_url, ...)

The default policy is permissive: private addresses (RFC1918, loopback,
link-local), ``.local`` / ``.internal`` / ``.lan`` / ``.intranet`` TLDs,
and any host explicitly enumerated in ``AISOC_AIRGAP_ALLOWLIST`` pass.
Everything else (api.openai.com, api.anthropic.com, virustotal.com, …)
is blocked.

This is a defense-in-depth check, not a substitute for an actual
network policy at the egress firewall — but it's enough to (a) stop
accidental phone-home from a misconfigured ``.env`` and (b) earn the
"air-gap certified" claim in the docs.

The check is best-effort: when ``AISOC_AIRGAPPED`` is False (the
default) the helpers are no-ops. They log via ``structlog`` so SOC
operators can audit egress decisions in their existing log pipeline.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

import structlog

from app.core.config import settings

log = structlog.get_logger(__name__)


class AirgapViolation(RuntimeError):
    """Raised when an outbound HTTP request violates the air-gap policy.

    Callers should let this propagate so the request never leaves the
    process. The wrapping HTTP endpoint typically converts it into a 503
    with a structured ``airgap_violation`` body (see
    ``services/api/app/api/v1/endpoints/translation.py`` for the
    canonical pattern).
    """


# TLDs that are unambiguously internal-only per RFC 6762 / RFC 8375 / common
# enterprise convention. ``.local`` is mDNS, ``.internal`` is the new IETF
# reserved private-use TLD, and ``.lan`` / ``.intranet`` are de-facto
# enterprise conventions. Hosts ending in any of these always pass.
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
    """Return True when ``host`` resolves syntactically to a private endpoint.

    "Syntactically" matters: we deliberately do NOT issue a DNS lookup
    here. The point is to refuse anything whose name implies public
    routing, not to verify whether ``api.openai.com`` happens to
    currently resolve to a private CIDR for this customer's split-horizon
    DNS. (Operators who want to allow that exact host should add it to
    ``AISOC_AIRGAP_ALLOWLIST`` so the intent is auditable.)
    """
    if not host:
        return False
    host = host.lower().strip()

    # Bare hostname with no dots ("ollama", "vllm-gateway") is treated as
    # a docker-compose / k8s service name — internal by definition.
    if "." not in host:
        return True

    # Suffix match against known internal TLDs.
    for suffix in _PRIVATE_SUFFIXES:
        if host == suffix.lstrip(".") or host.endswith(suffix):
            return True

    # IP literal: classify with the stdlib so we get RFC1918, loopback,
    # link-local, ULAs, multicast, etc. all handled correctly without
    # rolling our own table.
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified


def is_host_allowed_for_airgap(host: str, allowlist: list[str] | None = None) -> bool:
    """Return True iff ``host`` may be contacted under air-gap policy.

    Used both at request time (via ``enforce_airgap_for_url``) and at
    boot (by the config warner) — that's why it's exported.
    """
    if not host:
        # Empty host means we couldn't parse a URL; treat as a violation
        # so we never accidentally send a request with no Host header.
        return False
    host = host.lower().strip()
    if _is_private_address(host):
        return True
    allowlist = allowlist if allowlist is not None else settings.AISOC_AIRGAP_ALLOWLIST
    for entry in allowlist or []:
        entry = entry.strip().lower()
        if not entry:
            continue
        # Strip optional port for the comparison.
        entry_host = entry.split(":", 1)[0]
        if entry_host == host or host.endswith("." + entry_host):
            return True
    return False


def enforce_airgap_for_url(url: str) -> None:
    """Raise :class:`AirgapViolation` if ``url`` would breach the air-gap policy.

    No-op when ``AISOC_AIRGAPPED`` is False. Safe to call unconditionally
    around every outbound HTTP request.
    """
    if not settings.AISOC_AIRGAPPED:
        return
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if is_host_allowed_for_airgap(host):
        log.debug("airgap.allow", host=host, url=url)
        return
    log.warning(
        "airgap.block",
        host=host,
        url=url,
        message="Outbound request refused by AISOC_AIRGAPPED policy",
    )
    raise AirgapViolation(
        f"Air-gapped mode is enabled and host '{host}' is not in AISOC_AIRGAP_ALLOWLIST. "
        "Point this integration at a local mirror or add the host to the allowlist."
    )


def airgap_status() -> dict[str, object]:
    """Return a JSON-serializable snapshot of the air-gap policy.

    Powers the ``GET /api/v1/airgap/status`` endpoint that the docs
    site embeds in the air-gap deployment guide so operators can verify
    their config end-to-end without parsing logs.
    """
    return {
        "enabled": settings.AISOC_AIRGAPPED,
        "allowlist": list(settings.AISOC_AIRGAP_ALLOWLIST or []),
        "implicit_private_suffixes": list(_PRIVATE_SUFFIXES),
        "policy": (
            "All outbound HTTP is blocked except to private/loopback/link-local "
            "addresses, hosts ending in known internal suffixes (.local, .internal, "
            ".lan, .intranet, .corp, .home, .localdomain, localhost), and hosts "
            "explicitly listed in AISOC_AIRGAP_ALLOWLIST."
            if settings.AISOC_AIRGAPPED
            else "Air-gapped mode is OFF — outbound HTTP is unrestricted."
        ),
    }
