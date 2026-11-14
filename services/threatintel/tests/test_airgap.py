"""Tests for the threat-intel air-gap egress policy.

These pin the contract used by ``services/threatintel/app/main.py`` at
feed-registration time. The threat-intel service is the largest source
of outbound HTTP in the AiSOC stack (OTX, CISA KEV, TAXII, MISP/OpenCTI),
so the cost of a regression here is high: an air-gapped customer would
silently start phoning home as soon as the scheduler comes up.
"""

from __future__ import annotations

import pytest
from app import airgap
from app.airgap import (
    AirgapViolation,
    airgap_status,
    enforce_airgap_for_url,
    is_host_allowed_for_airgap,
)


@pytest.fixture
def airgapped(monkeypatch: pytest.MonkeyPatch):
    """Force-enable air-gap mode for the duration of a test."""
    monkeypatch.setattr(airgap.settings, "AISOC_AIRGAPPED", True)
    monkeypatch.setattr(airgap.settings, "AISOC_AIRGAP_ALLOWLIST", [])
    yield


@pytest.fixture
def airgap_off(monkeypatch: pytest.MonkeyPatch):
    """Pin air-gap mode OFF so disabled-mode invariants are tested."""
    monkeypatch.setattr(airgap.settings, "AISOC_AIRGAPPED", False)
    monkeypatch.setattr(airgap.settings, "AISOC_AIRGAP_ALLOWLIST", [])
    yield


class TestAirgapDisabled:
    def test_public_feed_is_noop(self, airgap_off):
        # Default deployment must keep working — no behavior change unless
        # the operator explicitly opts in.
        enforce_airgap_for_url("https://otx.alienvault.com/api/v1/pulses")

    def test_status_reports_disabled(self, airgap_off):
        assert airgap_status()["enabled"] is False

    def test_is_host_allowed_when_disabled(self, airgap_off):
        # When the flag is off, every host is allowed regardless of suffix.
        assert is_host_allowed_for_airgap("api.openai.com") is True
        assert is_host_allowed_for_airgap("otx.alienvault.com") is True


class TestPublicFeedsBlocked:
    """When AISOC_AIRGAPPED=1 the canonical public threat-intel feeds
    must all refuse to register."""

    @pytest.mark.parametrize(
        "url",
        [
            "https://otx.alienvault.com/api/v1/pulses/subscribed",
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            "https://misp.example-public.com/events/restSearch",
            "https://taxii.opencti.io/taxii2/",
            "https://feeds.example-public.net/stix",
        ],
    )
    def test_public_feed_is_blocked(self, airgapped, url):
        with pytest.raises(AirgapViolation):
            enforce_airgap_for_url(url)


class TestPrivateMirrorsAllowed:
    """Customers running an internal MISP/OpenCTI/CISA KEV mirror should
    not need any per-feed configuration to keep them working."""

    @pytest.mark.parametrize(
        "url",
        [
            "http://10.0.0.5/api/feeds/kev.json",
            "http://192.168.1.10:8080/taxii2/",
            "http://misp.internal/events/restSearch",
            "http://opencti.local:4000/graphql",
            "http://kev-mirror/feed.json",  # bare hostname, docker service
            "http://172.16.5.20/feed",
            "http://[::1]/health",
        ],
    )
    def test_private_mirror_is_allowed(self, airgapped, url):
        # Must not raise.
        enforce_airgap_for_url(url)


class TestAllowlist:
    def test_exact_host_match(self, airgapped, monkeypatch):
        monkeypatch.setattr(
            airgap.settings,
            "AISOC_AIRGAP_ALLOWLIST",
            ["mirror.example.com"],
        )
        # Exact host listed: must pass.
        enforce_airgap_for_url("https://mirror.example.com/feed")
        # Sibling host not listed: must still block.
        with pytest.raises(AirgapViolation):
            enforce_airgap_for_url("https://other.example.com/feed")

    def test_suffix_match_covers_subdomains(self, airgapped, monkeypatch):
        monkeypatch.setattr(
            airgap.settings,
            "AISOC_AIRGAP_ALLOWLIST",
            ["intel.example.com"],
        )
        # Same semantics as the API service: an entry covers itself and
        # any subdomain so operators don't have to enumerate every host.
        enforce_airgap_for_url("https://intel.example.com/")
        enforce_airgap_for_url("https://misp.intel.example.com/")
        # Parent domain still blocked — we don't widen the match upward.
        with pytest.raises(AirgapViolation):
            enforce_airgap_for_url("https://example.com/")

    def test_status_includes_allowlist(self, airgapped, monkeypatch):
        monkeypatch.setattr(
            airgap.settings,
            "AISOC_AIRGAP_ALLOWLIST",
            ["intel-mirror.example.com", "kev.example.org"],
        )
        status = airgap_status()
        assert status["enabled"] is True
        assert "intel-mirror.example.com" in status["allowlist"]
        assert "kev.example.org" in status["allowlist"]


class TestEdgeCases:
    def test_empty_url_blocks(self, airgapped):
        # Garbage URLs (typo'd config, missing scheme) must fail closed —
        # we never want to issue an HTTP request whose Host header would
        # be empty.
        with pytest.raises(AirgapViolation):
            enforce_airgap_for_url("")
        with pytest.raises(AirgapViolation):
            enforce_airgap_for_url("not-a-url")

    def test_case_insensitive_host(self, airgapped, monkeypatch):
        monkeypatch.setattr(
            airgap.settings,
            "AISOC_AIRGAP_ALLOWLIST",
            ["Mirror.Example.COM"],
        )
        # Allowlist entries and inbound URL hosts may differ in case;
        # comparison must be case-insensitive so an operator who typed
        # ``Mirror.Example.com`` in their .env file isn't surprised.
        enforce_airgap_for_url("https://MIRROR.example.com/")
