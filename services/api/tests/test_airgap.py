"""Tests for Tier 3.1 — air-gapped certification.

Pins the contract that ``enforce_airgap_for_url`` is a true egress
chokepoint when ``AISOC_AIRGAPPED=1``: it must let private/loopback/
internal-suffix hosts and explicit allowlist entries through, and it
must refuse everything else (api.openai.com, virustotal.com, …) so a
misconfigured integration can never accidentally phone home from an
air-gapped deployment.
"""

from __future__ import annotations

import pytest
from app.core import airgap
from app.core.airgap import (
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
    """When the flag is off, the helper is a no-op."""

    def test_public_host_is_noop(self, airgap_off):
        # Must not raise; the whole point of the disabled mode is that
        # operators who haven't opted in see no behavior change.
        enforce_airgap_for_url("https://api.openai.com/v1/chat/completions")

    def test_status_reports_disabled(self, airgap_off):
        status = airgap_status()
        assert status["enabled"] is False
        assert "OFF" in str(status["policy"])


class TestAirgapEnabled:
    """When AISOC_AIRGAPPED=1, the policy is enforced."""

    def test_blocks_public_llm_provider(self, airgapped):
        with pytest.raises(AirgapViolation):
            enforce_airgap_for_url("https://api.openai.com/v1/chat/completions")

    def test_blocks_public_threatintel(self, airgapped):
        with pytest.raises(AirgapViolation):
            enforce_airgap_for_url("https://otx.alienvault.com/api/v1/pulses")

    def test_allows_loopback(self, airgapped):
        # Local Ollama is the canonical air-gap inference target.
        enforce_airgap_for_url("http://127.0.0.1:11434/api/generate")
        enforce_airgap_for_url("http://localhost:11434/api/generate")

    def test_allows_rfc1918(self, airgapped):
        enforce_airgap_for_url("http://10.0.0.5:11434/api/generate")
        enforce_airgap_for_url("http://192.168.1.10:8000/v1/chat/completions")
        enforce_airgap_for_url("http://172.16.0.1/")

    def test_allows_internal_suffix(self, airgapped):
        # docker-compose / k8s service discovery names.
        enforce_airgap_for_url("http://ollama.local/api/generate")
        enforce_airgap_for_url("http://vllm.internal:8000/v1/chat/completions")
        enforce_airgap_for_url("http://gateway.lan/")

    def test_allows_unqualified_service_name(self, airgapped):
        # "ollama" with no dot — typical docker-compose service.
        enforce_airgap_for_url("http://ollama:11434/api/generate")

    def test_allowlist_exact_match(self, airgapped, monkeypatch):
        monkeypatch.setattr(
            airgap.settings,
            "AISOC_AIRGAP_ALLOWLIST",
            ["mirror.example.com"],
        )
        enforce_airgap_for_url("https://mirror.example.com/v1/chat")
        with pytest.raises(AirgapViolation):
            enforce_airgap_for_url("https://example.com/v1/chat")

    def test_allowlist_subdomain_match(self, airgapped, monkeypatch):
        # An entry of `example.com` should also cover any subdomain so
        # operators don't have to enumerate every hostname under their
        # internal mirror.
        monkeypatch.setattr(
            airgap.settings,
            "AISOC_AIRGAP_ALLOWLIST",
            ["example.com"],
        )
        enforce_airgap_for_url("https://mirror.example.com/")
        enforce_airgap_for_url("https://example.com/")

    def test_blocks_empty_host(self, airgapped):
        # urlparse on garbage gives an empty host. We must refuse rather
        # than silently allow — a request with no Host header is not
        # something an air-gapped deployment should ever issue.
        with pytest.raises(AirgapViolation):
            enforce_airgap_for_url("http://")

    def test_status_reports_enabled(self, airgapped, monkeypatch):
        monkeypatch.setattr(
            airgap.settings,
            "AISOC_AIRGAP_ALLOWLIST",
            ["internal-mirror.example.com"],
        )
        status = airgap_status()
        assert status["enabled"] is True
        assert "internal-mirror.example.com" in status["allowlist"]
        assert ".internal" in status["implicit_private_suffixes"]


class TestHostClassifier:
    """Direct tests of the syntactic host classifier."""

    @pytest.mark.parametrize(
        "host",
        [
            "127.0.0.1",
            "10.0.0.1",
            "192.168.1.1",
            "172.16.0.1",
            "::1",
            "fe80::1",
            "ollama",
            "ollama.local",
            "vllm.internal",
            "host.lan",
            "service.intranet",
            "app.corp",
            "node.home",
            "thing.localdomain",
            "localhost",
        ],
    )
    def test_private_hosts(self, host, airgapped):
        assert is_host_allowed_for_airgap(host)

    @pytest.mark.parametrize(
        "host",
        [
            "api.openai.com",
            "api.anthropic.com",
            "otx.alienvault.com",
            "www.virustotal.com",
            "8.8.8.8",
            "1.1.1.1",
        ],
    )
    def test_public_hosts(self, host, airgapped):
        assert not is_host_allowed_for_airgap(host)
