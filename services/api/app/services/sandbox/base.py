"""The provider contract, and the outbound rules every provider obeys.

Five verbs, because five is what the callers need: look a hash up, submit a
file, submit a URL, poll, and describe yourself. Everything a provider knows
that is not one of those is its own business, and the interface never learns
it.

The asymmetry between :meth:`SandboxProvider.lookup_hash` and the two submit
verbs is the point rather than an accident. A hash lookup discloses a 32-byte
digest; a file submission discloses the file. They are separated so the upload
policy has something to sit between, and so a provider that can only do the
first is a complete implementation rather than a partial one.
"""

from __future__ import annotations

import abc
import ipaddress
import socket
from typing import Any, TypeAlias
from urllib.parse import urlsplit

from app.core.airgap import AirgapViolation, enforce_airgap_for_url
from app.services.sandbox.types import (
    AnalysisState,
    ProviderCapabilities,
    SandboxReport,
    SandboxUnavailable,
    SubmissionReceipt,
)

__all__ = ["SandboxProvider", "as_mapping", "guard_outbound_url"]


def as_mapping(value: object) -> dict[str, Any]:
    """``value`` if it is a JSON object, otherwise an empty one.

    Every adapter reads vendor JSON, where any key may be absent or the wrong
    shape, and the obvious inline spelling
    ``payload.get(k) if isinstance(payload.get(k), dict) else {}`` calls
    ``get`` twice, so a type checker cannot narrow the first result from the
    second's test. Doing it once here narrows properly and stops seven
    near-identical expressions drifting apart.
    """
    return value if isinstance(value, dict) else {}


#: Hosts that must never be reached whatever DNS says, matching the blocklist
#: in ``services/agents/app/playbook/ssrf_guard.py``. A sandbox provider is
#: operator-configured, and an operator who can set a base URL can point it at
#: the instance metadata service.
_METADATA_HOSTS: frozenset[str] = frozenset(
    {
        "169.254.169.254",
        "metadata.google.internal",
        "metadata",
        "metadata.azure.com",
        "100.100.100.200",
    }
)


#: The two concrete address types, rather than ``ipaddress._BaseAddress``:
#: the private base declares none of the ``is_*`` properties this function
#: reads, so annotating with it type-checks every one of them as an error.
_IPAddress: TypeAlias = ipaddress.IPv4Address | ipaddress.IPv6Address


def _refuse_address(ip: _IPAddress, *, allow_private: bool) -> str:
    """Empty string when ``ip`` may be contacted, otherwise the reason it may not."""
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return _refuse_address(ip.ipv4_mapped, allow_private=allow_private)
    if ip.is_loopback and not allow_private:
        return "loopback address"
    if ip.is_link_local:
        # Never relaxed. 169.254.0.0/16 is the cloud metadata range, which is
        # the one address a local sandbox has no reason to live on.
        return "link-local address (cloud metadata range)"
    if ip.is_unspecified:
        return "unspecified address"
    if ip.is_multicast:
        return "multicast address"
    if ip.is_reserved:
        return "reserved address"
    if ip.is_private and not allow_private:
        return "private address"
    return ""


def guard_outbound_url(url: str, *, provider: str, allow_private: bool = False) -> str:
    """Run a provider's outbound URL past the air-gap policy and an SSRF check.

    The two refuse different things, and both have to run: air-gap refuses a
    URL that leaves the deployment, and the SSRF check refuses one that points
    back into it. A self-hosted sandbox is the case where the second would fire
    and must not, so ``allow_private`` is set from the provider's own ``local``
    declaration rather than from an environment variable. Link-local stays
    refused either way, because relaxing "private" to reach a sandbox on
    ``10.0.0.0/8`` must not also open the metadata service.

    Returns the URL so a call site reads ``client.get(guard_outbound_url(...))``
    and cannot accidentally use the unchecked string.
    """
    try:
        enforce_airgap_for_url(url)
    except AirgapViolation as exc:
        raise SandboxUnavailable(provider, str(exc), kind="network") from exc

    parts = urlsplit(url.strip())
    if parts.scheme not in ("http", "https"):
        raise SandboxUnavailable(provider, f"scheme {parts.scheme or '(none)'!r} is not allowed", kind="network")
    if parts.username or parts.password:
        raise SandboxUnavailable(provider, "URL must not carry userinfo", kind="network")
    host = (parts.hostname or "").strip().lower()
    if not host:
        raise SandboxUnavailable(provider, "URL has no hostname", kind="network")
    if host in _METADATA_HOSTS:
        raise SandboxUnavailable(provider, f"host {host!r} is on the metadata blocklist", kind="network")

    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        if reason := _refuse_address(literal, allow_private=allow_private):
            raise SandboxUnavailable(provider, f"host {host!r} is blocked: {reason}", kind="network")
        return url

    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise SandboxUnavailable(provider, f"could not resolve {host!r}: {exc}", kind="network") from exc
    seen: set[str] = set()
    for info in infos:
        addr = str(info[4][0]).split("%", 1)[0]
        if not addr or addr in seen:
            continue
        seen.add(addr)
        # Every answer, not just the first: a record that mixes one public and
        # one private address would otherwise pass on whichever came back
        # first.
        if reason := _refuse_address(ipaddress.ip_address(addr), allow_private=allow_private):
            raise SandboxUnavailable(provider, f"{host!r} resolves to {addr} ({reason})", kind="network")
    if not seen:
        raise SandboxUnavailable(provider, f"{host!r} resolved to no usable address", kind="network")
    return url


class SandboxProvider(abc.ABC):
    """A file and URL analysis backend.

    Implementations must not raise for an ordinary negative answer. A hash the
    provider has never seen is ``None`` from :meth:`lookup_hash`, and an
    analysis that has not finished is a report whose state is
    :attr:`~app.services.sandbox.types.AnalysisState.PENDING`. Raising is
    reserved for "the question could not be asked", which is
    :class:`~app.services.sandbox.types.SandboxUnavailable`, so that a caller
    can tell a negative result from a failure without reading the message.
    """

    @property
    @abc.abstractmethod
    def capabilities(self) -> ProviderCapabilities:
        """What this provider can do and where it runs."""

    @property
    def name(self) -> str:
        return self.capabilities.name

    @property
    def local(self) -> bool:
        return self.capabilities.local

    @abc.abstractmethod
    async def lookup_hash(self, sha256: str) -> SandboxReport | None:
        """Report for a file the provider has already analysed, or ``None``.

        Discloses only the digest. This is the verb the upload policy makes
        callers try first, and the only one a tenant never has to consent to.
        """

    async def submit_file(self, content: bytes, file_name: str, *, visibility: str | None = None) -> SubmissionReceipt:
        """Send a file for analysis.

        Never called without an allowed
        :class:`~app.services.sandbox.policy.UploadDecision`. A provider that
        cannot accept files leaves this alone and declares
        ``supports_file_submission=False``.
        """
        raise SandboxUnavailable(self.name, "this provider does not accept file submissions", kind="bad_response")

    async def submit_url(self, url: str) -> SubmissionReceipt:
        """Send a URL for analysis."""
        raise SandboxUnavailable(self.name, "this provider does not accept URL submissions", kind="bad_response")

    @abc.abstractmethod
    async def poll(self, handle: str) -> SandboxReport:
        """Current state of a submission, by its :class:`SubmissionReceipt` handle."""

    async def aclose(self) -> None:
        """Release any transport the provider holds. Safe to call twice.

        Concrete rather than abstract: a provider that holds no transport has
        nothing to close, and forcing every adapter to write an empty override
        would make the one that *should* have closed a client harder to spot.
        """
        return None

    @staticmethod
    def _pending(provider: str, handle: str, state: AnalysisState = AnalysisState.PENDING) -> SandboxReport:
        """A report that carries no verdict, for an analysis still in flight."""
        return SandboxReport(
            provider=provider,
            state=state,
            unavailable_reasons={"verdict": f"analysis {handle} has not finished ({state.value})"},
        )
