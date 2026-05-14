"""Tests for ``app.core.trusted_proxy.resolve_client_ip``.

Why these matter
----------------
``actor_ip`` is one of the few audit columns that a hostile client can try
to influence *from outside* the application — by attaching their own
``X-Forwarded-For`` header. If we honour that blindly we let an attacker
write whatever source IP they like into a compliance-grade audit trail.

This suite pins the security contract:

1. Default (no ``AISOC_TRUSTED_PROXIES``) → never trust ``X-Forwarded-For``.
2. Direct peer not in trusted list → never trust ``X-Forwarded-For``.
3. Direct peer is a trusted proxy → walk the header right-to-left and
   return the first untrusted hop (the closest the chain comes to the
   real client).
4. Malformed input degrades gracefully to the direct TCP peer — audit
   must never crash on a weird header.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest
from app.core.trusted_proxy import (
    TRUSTED_PROXIES_ENV,
    _parse_cidrs,
    _parse_forwarded_for,
    resolve_client_ip,
)

# ---------------------------------------------------------------------------
# Minimal Request stub. We avoid pulling in starlette TestClient because we
# only need ``.client.host`` and ``.headers.get``.
# ---------------------------------------------------------------------------


class _StubClient:
    def __init__(self, host: str | None) -> None:
        self.host = host


class _StubHeaders(Mapping[str, str]):
    """Case-insensitive headers dict; mimics Starlette's Headers shape."""

    def __init__(self, data: dict[str, str] | None = None) -> None:
        # Normalize at construction so .get("X-Forwarded-For") and
        # .get("x-forwarded-for") both work.
        self._data = {k.lower(): v for k, v in (data or {}).items()}

    def __getitem__(self, key: str) -> str:
        return self._data[key.lower()]

    def __iter__(self):
        return iter(self._data)

    def __len__(self) -> int:
        return len(self._data)

    def get(self, key: str, default: Any = None) -> Any:  # type: ignore[override]
        return self._data.get(key.lower(), default)


class _StubRequest:
    def __init__(
        self,
        peer: str | None,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.client = _StubClient(peer) if peer is not None else None
        self.headers = _StubHeaders(headers)


# ---------------------------------------------------------------------------
# _parse_cidrs / _parse_forwarded_for — small but security-relevant helpers
# ---------------------------------------------------------------------------


class TestParseCidrs:
    def test_empty_returns_empty(self):
        assert _parse_cidrs("") == []
        assert _parse_cidrs(None) == []

    def test_accepts_ipv4_cidr_and_bare_address(self):
        nets = _parse_cidrs("10.0.0.0/8, 192.168.1.1")
        assert len(nets) == 2
        # Bare address is promoted to /32 by ipaddress.ip_network when
        # strict=False.
        assert any(str(n) == "192.168.1.1/32" for n in nets)

    def test_accepts_ipv6_cidr(self):
        nets = _parse_cidrs("2001:db8::/32")
        assert len(nets) == 1

    def test_skips_invalid_entries(self):
        """Operator typos must not break the audit pipeline."""
        nets = _parse_cidrs("10.0.0.0/8, not-a-cidr, 192.168.0.0/16")
        # 2 valid entries; the garbage in the middle is dropped silently.
        assert len(nets) == 2


class TestParseForwardedFor:
    def test_empty_inputs(self):
        assert _parse_forwarded_for(None) == []
        assert _parse_forwarded_for("") == []
        assert _parse_forwarded_for("   ") == []

    def test_strips_whitespace(self):
        assert _parse_forwarded_for("1.2.3.4 , 5.6.7.8") == ["1.2.3.4", "5.6.7.8"]

    def test_strips_ipv4_port(self):
        assert _parse_forwarded_for("1.2.3.4:5555") == ["1.2.3.4"]

    def test_strips_bracketed_ipv6_port(self):
        assert _parse_forwarded_for("[2001:db8::1]:8080") == ["2001:db8::1"]

    def test_preserves_bare_ipv6(self):
        # No port → no rewriting; bare colons in IPv6 must survive.
        assert _parse_forwarded_for("2001:db8::1") == ["2001:db8::1"]


# ---------------------------------------------------------------------------
# resolve_client_ip — the actual security boundary
# ---------------------------------------------------------------------------


class TestResolveClientIpDefaultDeny:
    """Without ``AISOC_TRUSTED_PROXIES`` we must NEVER trust XFF."""

    def test_no_env_ignores_xff(self, monkeypatch):
        monkeypatch.delenv(TRUSTED_PROXIES_ENV, raising=False)
        req = _StubRequest(
            peer="203.0.113.10",
            headers={"x-forwarded-for": "10.0.0.1"},
        )
        assert resolve_client_ip(req) == "203.0.113.10"

    def test_empty_env_ignores_xff(self, monkeypatch):
        monkeypatch.setenv(TRUSTED_PROXIES_ENV, "")
        req = _StubRequest(
            peer="203.0.113.10",
            headers={"x-forwarded-for": "evil-spoof"},
        )
        assert resolve_client_ip(req) == "203.0.113.10"

    def test_no_client_returns_none(self, monkeypatch):
        monkeypatch.delenv(TRUSTED_PROXIES_ENV, raising=False)
        req = _StubRequest(peer=None, headers={"x-forwarded-for": "1.2.3.4"})
        assert resolve_client_ip(req) is None


class TestResolveClientIpUntrustedPeer:
    """If the direct peer is not in the allow-list, XFF must be ignored
    even when other proxies are configured."""

    def test_untrusted_direct_peer_ignores_xff(self, monkeypatch):
        monkeypatch.setenv(TRUSTED_PROXIES_ENV, "10.0.0.0/8")
        # Peer is on the public internet; not in 10.0.0.0/8.
        req = _StubRequest(
            peer="198.51.100.7",
            headers={"x-forwarded-for": "1.1.1.1, 10.0.0.5"},
        )
        # Must NOT return 1.1.1.1 — that would be spoofable.
        assert resolve_client_ip(req) == "198.51.100.7"


class TestResolveClientIpTrustedPeer:
    """Direct peer is a trusted proxy → consult XFF safely."""

    def test_returns_rightmost_untrusted_hop(self, monkeypatch):
        # Allow our internal LB and an internal NAT range.
        monkeypatch.setenv(TRUSTED_PROXIES_ENV, "10.0.0.0/8, 192.168.0.0/16")
        # Chain reads left→right as "client → edge → LB":
        #   client_ip, edge_proxy, lb_proxy (peer)
        req = _StubRequest(
            peer="10.0.0.5",
            headers={"x-forwarded-for": "203.0.113.10, 192.168.1.20, 10.0.0.5"},
        )
        # Walking right→left we skip trusted hops 10.0.0.5 and 192.168.1.20,
        # and return 203.0.113.10 — the closest untrusted hop, i.e. the
        # real originating client.
        assert resolve_client_ip(req) == "203.0.113.10"

    def test_no_xff_falls_back_to_peer(self, monkeypatch):
        monkeypatch.setenv(TRUSTED_PROXIES_ENV, "10.0.0.0/8")
        req = _StubRequest(peer="10.0.0.5", headers={})
        assert resolve_client_ip(req) == "10.0.0.5"

    def test_all_hops_trusted_returns_leftmost(self, monkeypatch):
        """All-internal forwarding chain — the leftmost hop is the
        nearest thing to the originator we have."""
        monkeypatch.setenv(TRUSTED_PROXIES_ENV, "10.0.0.0/8")
        req = _StubRequest(
            peer="10.0.0.5",
            headers={"x-forwarded-for": "10.0.1.20, 10.0.0.5"},
        )
        assert resolve_client_ip(req) == "10.0.1.20"

    def test_garbage_hops_are_skipped(self, monkeypatch):
        """A malformed hop must not break the walk."""
        monkeypatch.setenv(TRUSTED_PROXIES_ENV, "10.0.0.0/8")
        req = _StubRequest(
            peer="10.0.0.5",
            headers={"x-forwarded-for": "not-an-ip, 203.0.113.10, 10.0.0.5"},
        )
        assert resolve_client_ip(req) == "203.0.113.10"

    def test_ipv6_chain(self, monkeypatch):
        monkeypatch.setenv(TRUSTED_PROXIES_ENV, "2001:db8::/32")
        req = _StubRequest(
            peer="2001:db8::1",
            headers={"x-forwarded-for": "2606:4700::1234, 2001:db8::abcd, 2001:db8::1"},
        )
        assert resolve_client_ip(req) == "2606:4700::1234"


class TestResolveClientIpRobustness:
    """The function must never raise — audit must keep working."""

    @pytest.mark.parametrize(
        "xff",
        [
            ",,,",
            "    ,  ,  ",
            "junk, more junk",
            "[::malformed",
        ],
    )
    def test_malformed_xff_falls_back_to_peer(self, monkeypatch, xff):
        monkeypatch.setenv(TRUSTED_PROXIES_ENV, "10.0.0.0/8")
        req = _StubRequest(peer="10.0.0.5", headers={"x-forwarded-for": xff})
        # Even hostile garbage must not throw.
        assert resolve_client_ip(req) == "10.0.0.5"

    def test_explicit_trusted_networks_argument_overrides_env(self, monkeypatch):
        """Callers may pass a pre-resolved network list (used in tests / batch jobs)."""
        # Env is empty — would normally mean "never trust XFF".
        monkeypatch.delenv(TRUSTED_PROXIES_ENV, raising=False)
        req = _StubRequest(
            peer="10.0.0.5",
            headers={"x-forwarded-for": "203.0.113.10, 10.0.0.5"},
        )
        nets = _parse_cidrs("10.0.0.0/8")
        assert resolve_client_ip(req, trusted_networks=nets) == "203.0.113.10"
