"""Tests for the playbook SSRF guard (services/agents/app/playbook/ssrf_guard.py)."""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Iterable
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.playbook.engine import _handle_http, _handle_notify
from app.playbook.models import PlaybookStep, StepType
from app.playbook.ssrf_guard import SSRFError, validate_outbound_url

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _addrinfo_for(*ips: str) -> list[tuple]:
    """Build a ``getaddrinfo``-shaped list for the given IP strings.

    Each tuple is ``(family, type, proto, canonname, sockaddr)``. Family is
    IPv4 unless the IP contains ``:``.
    """
    result: list[tuple] = []
    for ip in ips:
        if ":" in ip:
            family = socket.AF_INET6
            sockaddr: tuple = (ip, 0, 0, 0)
        else:
            family = socket.AF_INET
            sockaddr = (ip, 0)
        result.append((family, socket.SOCK_STREAM, 0, "", sockaddr))
    return result


def _patch_dns(monkeypatch: pytest.MonkeyPatch, mapping: dict[str, Iterable[str]]) -> None:
    """Patch ``socket.getaddrinfo`` inside the ssrf_guard module to return fixed answers."""

    def fake(host: str, *_args, **_kwargs):
        host = host.lower()
        if host in mapping:
            return _addrinfo_for(*mapping[host])
        raise socket.gaierror(-2, "Name or service not known")

    monkeypatch.setattr("app.playbook.ssrf_guard.socket.getaddrinfo", fake)


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


class TestValidateOutboundUrlPositive:
    def test_public_hostname_https(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_dns(monkeypatch, {"example.com": ["8.8.8.8"]})
        assert validate_outbound_url("https://example.com/webhook") == "https://example.com/webhook"

    def test_public_hostname_http(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_dns(monkeypatch, {"hooks.example.com": ["1.1.1.1"]})
        url = "http://hooks.example.com/path?x=1"
        assert validate_outbound_url(url) == url

    def test_public_ipv4_literal(self) -> None:
        url = "https://8.8.8.8/healthz"
        assert validate_outbound_url(url) == url

    def test_public_ipv6_literal(self) -> None:
        url = "https://[2001:4860:4860::8888]/"
        assert validate_outbound_url(url) == url

    def test_mixed_public_addresses_pass(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_dns(
            monkeypatch,
            {"multi.example.com": ["8.8.8.8", "2001:4860:4860::8888"]},
        )
        url = "https://multi.example.com/"
        assert validate_outbound_url(url) == url

    def test_port_is_preserved(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_dns(monkeypatch, {"hook.example.com": ["8.8.4.4"]})
        url = "https://hook.example.com:8443/incoming"
        assert validate_outbound_url(url) == url


# ---------------------------------------------------------------------------
# Empty / malformed input
# ---------------------------------------------------------------------------


class TestValidateOutboundUrlRejectsMalformed:
    @pytest.mark.parametrize("url", ["", "   ", None])
    def test_empty_or_whitespace(self, url: object) -> None:
        with pytest.raises(SSRFError):
            validate_outbound_url(url)  # type: ignore[arg-type]

    def test_non_http_scheme_file(self) -> None:
        with pytest.raises(SSRFError, match="scheme"):
            validate_outbound_url("file:///etc/passwd")

    def test_non_http_scheme_ftp(self) -> None:
        with pytest.raises(SSRFError, match="scheme"):
            validate_outbound_url("ftp://example.com/")

    def test_non_http_scheme_gopher(self) -> None:
        with pytest.raises(SSRFError, match="scheme"):
            validate_outbound_url("gopher://example.com/_")

    def test_non_http_scheme_data(self) -> None:
        with pytest.raises(SSRFError, match="scheme"):
            validate_outbound_url("data:text/plain,hello")

    def test_no_hostname(self) -> None:
        with pytest.raises(SSRFError):
            validate_outbound_url("http:///path")

    def test_userinfo_blocked(self) -> None:
        with pytest.raises(SSRFError, match="userinfo"):
            validate_outbound_url("http://user:pw@example.com/")

    def test_username_only_blocked(self) -> None:
        with pytest.raises(SSRFError, match="userinfo"):
            validate_outbound_url("http://user@example.com/")


# ---------------------------------------------------------------------------
# IP literal blocking
# ---------------------------------------------------------------------------


class TestIpLiteralBlocking:
    @pytest.mark.parametrize(
        "host",
        [
            "127.0.0.1",
            "127.5.5.5",
            "0.0.0.0",
            "10.0.0.1",
            "10.255.255.1",
            "192.168.1.1",
            "172.16.0.1",
            "172.31.255.255",
            "169.254.169.254",  # AWS IMDS
            "169.254.0.1",  # link-local
            "100.100.100.200",  # Alibaba IMDS
            "224.0.0.1",  # multicast
            "240.0.0.1",  # reserved
        ],
    )
    def test_blocked_ipv4_literals(self, host: str) -> None:
        with pytest.raises(SSRFError):
            validate_outbound_url(f"http://{host}/")

    @pytest.mark.parametrize(
        "host",
        [
            "[::1]",  # loopback
            "[::]",  # unspecified
            "[fe80::1]",  # link-local
            "[fc00::1]",  # unique-local
            "[fd00::1]",  # unique-local
            "[ff02::1]",  # multicast
            "[::ffff:127.0.0.1]",  # v4-mapped loopback
            "[::ffff:10.0.0.1]",  # v4-mapped private
        ],
    )
    def test_blocked_ipv6_literals(self, host: str) -> None:
        with pytest.raises(SSRFError):
            validate_outbound_url(f"http://{host}/")


# ---------------------------------------------------------------------------
# Hostname blocking via blocklist + DNS resolution
# ---------------------------------------------------------------------------


class TestHostnameBlocking:
    @pytest.mark.parametrize(
        "host",
        [
            "metadata.google.internal",
            "metadata",
            "metadata.azure.com",
            "169.254.169.254.nip.io",
        ],
    )
    def test_metadata_hostnames_blocked(self, host: str) -> None:
        with pytest.raises(SSRFError, match="blocklist"):
            validate_outbound_url(f"http://{host}/computeMetadata/v1/")

    def test_dns_to_loopback_blocked(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_dns(monkeypatch, {"evil.example": ["127.0.0.1"]})
        with pytest.raises(SSRFError, match="loopback"):
            validate_outbound_url("https://evil.example/")

    def test_dns_to_private_blocked(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_dns(monkeypatch, {"sneaky.example": ["10.0.0.5"]})
        with pytest.raises(SSRFError, match="private"):
            validate_outbound_url("https://sneaky.example/")

    def test_dns_to_link_local_blocked(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_dns(monkeypatch, {"meta.example": ["169.254.169.254"]})
        with pytest.raises(SSRFError, match="link-local"):
            validate_outbound_url("https://meta.example/latest/meta-data/")

    def test_dns_mixed_answers_blocked(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """If any returned address is unsafe, reject — defends against
        DNS-pinning bypasses where one record is public and another is private.
        """
        _patch_dns(
            monkeypatch,
            {"mixed.example": ["8.8.8.8", "10.0.0.1"]},
        )
        with pytest.raises(SSRFError):
            validate_outbound_url("https://mixed.example/")

    def test_unresolvable_hostname_blocked(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_dns(monkeypatch, {})  # nothing resolves
        with pytest.raises(SSRFError, match="could not resolve"):
            validate_outbound_url("https://nope.invalid/")


# ---------------------------------------------------------------------------
# allow_private toggle
# ---------------------------------------------------------------------------


class TestAllowPrivate:
    def test_allow_private_arg_permits_rfc1918(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_dns(monkeypatch, {"internal.example": ["10.0.0.5"]})
        url = "https://internal.example/health"
        assert validate_outbound_url(url, allow_private=True) == url

    def test_allow_private_arg_still_blocks_loopback(self) -> None:
        with pytest.raises(SSRFError, match="loopback"):
            validate_outbound_url("http://127.0.0.1/", allow_private=True)

    def test_allow_private_arg_still_blocks_metadata_hostname(self) -> None:
        with pytest.raises(SSRFError, match="blocklist"):
            validate_outbound_url("http://metadata.google.internal/", allow_private=True)

    def test_allow_private_env_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AISOC_SSRF_ALLOW_PRIVATE", "1")
        _patch_dns(monkeypatch, {"intra.example": ["192.168.1.10"]})
        url = "https://intra.example/"
        assert validate_outbound_url(url) == url

    def test_allow_private_env_var_off_blocks(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("AISOC_SSRF_ALLOW_PRIVATE", raising=False)
        _patch_dns(monkeypatch, {"intra.example": ["192.168.1.10"]})
        with pytest.raises(SSRFError, match="private"):
            validate_outbound_url("https://intra.example/")

    def test_allow_private_arg_overrides_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AISOC_SSRF_ALLOW_PRIVATE", "1")
        _patch_dns(monkeypatch, {"intra.example": ["192.168.1.10"]})
        # Caller explicitly disables, env should not win.
        with pytest.raises(SSRFError, match="private"):
            validate_outbound_url("https://intra.example/", allow_private=False)


# ---------------------------------------------------------------------------
# Operator extension via env var
# ---------------------------------------------------------------------------


class TestOperatorExtensions:
    def test_extra_blocked_hosts_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AISOC_SSRF_EXTRA_BLOCKED_HOSTS", "secrets.internal,vault.svc")
        _patch_dns(monkeypatch, {"secrets.internal": ["8.8.8.8"]})
        with pytest.raises(SSRFError, match="blocklist"):
            validate_outbound_url("https://secrets.internal/api/v1/secret")

    def test_allowed_schemes_env_extension(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Sanity check: operator can broaden allowed schemes if needed.
        monkeypatch.setenv("AISOC_SSRF_ALLOWED_SCHEMES", "https")
        with pytest.raises(SSRFError, match="scheme"):
            validate_outbound_url("http://example.com/")


# ---------------------------------------------------------------------------
# Engine integration
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestHandlerIntegration:
    async def test_handle_http_blocks_metadata(self) -> None:
        step = PlaybookStep(
            name="http-bad",
            type=StepType.HTTP,
            params={"url": "http://169.254.169.254/latest/meta-data/", "method": "GET"},
        )
        client = MagicMock()
        client.request = AsyncMock()
        with pytest.raises(SSRFError):
            await _handle_http(step, {}, client)
        client.request.assert_not_awaited()

    async def test_handle_http_blocks_empty_url(self) -> None:
        step = PlaybookStep(name="http-empty", type=StepType.HTTP, params={"url": ""})
        client = MagicMock()
        client.request = AsyncMock()
        with pytest.raises(SSRFError):
            await _handle_http(step, {}, client)
        client.request.assert_not_awaited()

    async def test_handle_http_blocks_loopback(self) -> None:
        step = PlaybookStep(
            name="http-loop",
            type=StepType.HTTP,
            params={"url": "http://127.0.0.1:8000/internal", "method": "POST"},
        )
        client = MagicMock()
        client.request = AsyncMock()
        with pytest.raises(SSRFError):
            await _handle_http(step, {}, client)
        client.request.assert_not_awaited()

    async def test_handle_http_passes_for_public(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_dns(monkeypatch, {"ok.example": ["8.8.8.8"]})
        step = PlaybookStep(
            name="http-good",
            type=StepType.HTTP,
            params={"url": "https://ok.example/api", "method": "POST", "body": {"a": 1}},
        )
        response = MagicMock()
        response.status_code = 202
        response.text = "ok"
        client = MagicMock()
        client.request = AsyncMock(return_value=response)
        out = await _handle_http(step, {}, client)
        assert out["status"] == 202
        client.request.assert_awaited_once()

    async def test_handle_notify_no_url_passthrough(self) -> None:
        step = PlaybookStep(
            name="notify-empty",
            type=StepType.NOTIFY,
            params={"channel": "webhook", "url": "", "message": "hi"},
        )
        client = MagicMock()
        client.post = AsyncMock()
        out = await _handle_notify(step, {}, client)
        # Empty URL → handler returns informational stub; never calls http.
        assert out["delivered"] is False
        client.post.assert_not_awaited()

    async def test_handle_notify_blocks_bad_webhook(self) -> None:
        step = PlaybookStep(
            name="notify-bad",
            type=StepType.NOTIFY,
            params={"channel": "webhook", "url": "http://10.0.0.1/hook", "message": "x"},
        )
        client = MagicMock()
        client.post = AsyncMock()
        with pytest.raises(SSRFError):
            await _handle_notify(step, {}, client)
        client.post.assert_not_awaited()

    async def test_handle_notify_passes_for_public(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_dns(monkeypatch, {"hooks.example": ["1.1.1.1"]})
        step = PlaybookStep(
            name="notify-good",
            type=StepType.NOTIFY,
            params={"channel": "webhook", "url": "https://hooks.example/x", "message": "hi"},
        )
        response = MagicMock()
        response.status_code = 200
        client = MagicMock()
        client.post = AsyncMock(return_value=response)
        out = await _handle_notify(step, {}, client)
        assert out["status"] == 200
        client.post.assert_awaited_once()


# ---------------------------------------------------------------------------
# Defence in depth: _is_disallowed_address direct tests
# ---------------------------------------------------------------------------


class TestIsDisallowedAddress:
    @pytest.mark.parametrize(
        "ip_str",
        [
            "127.0.0.1",
            "0.0.0.0",
            "169.254.1.1",
            "224.0.0.1",
            "240.0.0.1",
            "::1",
            "::",
            "fe80::1",
            "ff02::1",
        ],
    )
    def test_always_blocked_even_with_allow_private(self, ip_str: str) -> None:
        from app.playbook.ssrf_guard import _is_disallowed_address

        blocked, reason = _is_disallowed_address(ipaddress.ip_address(ip_str), allow_private=True)
        assert blocked is True
        assert reason  # non-empty reason string

    @pytest.mark.parametrize(
        "ip_str",
        [
            "10.0.0.1",
            "192.168.1.1",
            "172.16.0.1",
            "fc00::1",
        ],
    )
    def test_private_blocked_by_default_but_allowed_when_flag(self, ip_str: str) -> None:
        from app.playbook.ssrf_guard import _is_disallowed_address

        ip = ipaddress.ip_address(ip_str)
        blocked_default, _ = _is_disallowed_address(ip, allow_private=False)
        blocked_allowed, _ = _is_disallowed_address(ip, allow_private=True)
        assert blocked_default is True
        assert blocked_allowed is False

    @pytest.mark.parametrize("ip_str", ["8.8.8.8", "1.1.1.1", "2001:4860:4860::8888"])
    def test_public_addresses_pass(self, ip_str: str) -> None:
        from app.playbook.ssrf_guard import _is_disallowed_address

        blocked, _ = _is_disallowed_address(ipaddress.ip_address(ip_str), allow_private=False)
        assert blocked is False
