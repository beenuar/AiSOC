"""Tests for ``/api/v1/llm/status`` (WS-H2/H4 operator visibility).

Pins the contract the Settings → Deployment & AI panel relies on:

* Provider classification matches the operator's actual env vars,
  not a hard-coded default.
* The API key itself is *never* surfaced — only ``key_set: bool``.
* Air-gap compliance is computed from the same classifier the egress
  gate uses, so the badge in the UI cannot drift from what would
  actually happen at request time.
* When neither key nor base URL is set we report ``provider="none"``
  and ``effective_path="fallback"`` so operators don't see a
  misleading "OpenAI" indicator on the deterministic fallback path.
"""

from __future__ import annotations

import pytest
from app.api.v1.endpoints.llm_status import llm_status
from app.core import airgap as airgap_module


@pytest.fixture(autouse=True)
def _clear_llm_env(monkeypatch: pytest.MonkeyPatch):
    """Strip LLM-related env vars so each test starts from a known state.

    We have to clear *all* the aliases we read (LLM_* and OPENAI_*) so
    operator-side env contamination from a real shell doesn't bleed
    into the test.
    """
    for var in (
        "LLM_BASE_URL",
        "LLM_API_KEY",
        "LLM_MODEL",
        "OPENAI_BASE_URL",
        "OPENAI_API_KEY",
        "OPENAI_MODEL",
        "AISOC_LLM_MODEL",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(airgap_module.settings, "AISOC_AIRGAPPED", False)
    monkeypatch.setattr(airgap_module.settings, "AISOC_AIRGAP_ALLOWLIST", [])
    yield


class TestNoConfiguration:
    """No env at all → fallback path, never claim OpenAI is wired up."""

    def test_provider_none_when_nothing_set(self):
        snap = llm_status()
        assert snap["provider"] == "none"
        assert snap["effective_path"] == "fallback"
        assert snap["key_set"] is False
        assert snap["base_url"] == ""
        # Always compliant when no outbound call would happen.
        assert snap["airgap_compliant"] is True

    def test_policy_note_explains_fallback(self):
        snap = llm_status()
        assert "deterministic" in str(snap["policy_note"]).lower()


class TestKeyHandling:
    """The key itself must never leave the process."""

    def test_key_set_true_when_openai_api_key_present(self, monkeypatch: pytest.MonkeyPatch):
        # NB: the value is intentionally fake; the assertion is that
        # we report the *presence* of a key, not the value.
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-not-a-real-key")
        snap = llm_status()
        assert snap["key_set"] is True
        # And the value never appears anywhere in the snapshot.
        assert "sk-test-not-a-real-key" not in str(snap)

    def test_key_set_true_when_llm_api_key_alias_present(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("LLM_API_KEY", "anything")
        snap = llm_status()
        assert snap["key_set"] is True


class TestProviderClassification:
    """``provider`` should match what the operator set, not OpenAI by default."""

    def test_openai_default_when_key_set_no_base_url(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("OPENAI_API_KEY", "x")
        snap = llm_status()
        assert snap["provider"] == "openai"

    def test_explicit_openai_host(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("OPENAI_API_KEY", "x")
        monkeypatch.setenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
        snap = llm_status()
        assert snap["provider"] == "openai"

    def test_anthropic(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("OPENAI_API_KEY", "x")
        monkeypatch.setenv("OPENAI_BASE_URL", "https://api.anthropic.com")
        snap = llm_status()
        assert snap["provider"] == "anthropic"

    def test_azure_openai(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("OPENAI_API_KEY", "x")
        monkeypatch.setenv("OPENAI_BASE_URL", "https://my-resource.openai.azure.com/openai")
        snap = llm_status()
        assert snap["provider"] == "azure-openai"

    def test_local_ollama(self, monkeypatch: pytest.MonkeyPatch):
        # Local ollama: no key required by the backend, but the
        # operator may still have set one as a placeholder.
        monkeypatch.setenv("OPENAI_API_KEY", "ollama-placeholder")
        monkeypatch.setenv("OPENAI_BASE_URL", "http://ollama:11434/v1")
        snap = llm_status()
        assert snap["provider"] == "local-ollama"
        assert snap["is_local"] is True

    def test_local_vllm_with_localhost(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("OPENAI_API_KEY", "x")
        monkeypatch.setenv("OPENAI_BASE_URL", "http://localhost:8000/v1")
        snap = llm_status()
        # localhost without the "vllm" substring lands in custom; the
        # `is_local` badge is what we actually care about for the UI.
        assert snap["provider"] in {"custom", "local-vllm"}
        assert snap["is_local"] is True

    def test_local_vllm_with_explicit_hostname(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("OPENAI_API_KEY", "x")
        monkeypatch.setenv("OPENAI_BASE_URL", "http://vllm-gateway.local:8000/v1")
        snap = llm_status()
        assert snap["provider"] == "local-vllm"
        assert snap["is_local"] is True

    def test_lm_alias_takes_precedence_over_openai_alias(self, monkeypatch: pytest.MonkeyPatch):
        # If both are set, LLM_BASE_URL wins to match the precedence in
        # ``services/api/app/core/config.py``.
        monkeypatch.setenv("LLM_BASE_URL", "http://ollama:11434/v1")
        monkeypatch.setenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
        monkeypatch.setenv("LLM_API_KEY", "x")
        snap = llm_status()
        assert snap["provider"] == "local-ollama"
        assert snap["base_url"] == "http://ollama:11434/v1"


class TestAirgapCompliance:
    """The ``airgap_compliant`` flag must match the egress classifier."""

    def test_airgap_off_always_compliant(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("OPENAI_API_KEY", "x")
        monkeypatch.setenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
        snap = llm_status()
        assert snap["airgap_enabled"] is False
        assert snap["airgap_compliant"] is True

    def test_airgap_on_blocks_openai(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(airgap_module.settings, "AISOC_AIRGAPPED", True)
        monkeypatch.setenv("OPENAI_API_KEY", "x")
        monkeypatch.setenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
        snap = llm_status()
        assert snap["airgap_enabled"] is True
        assert snap["airgap_compliant"] is False
        assert snap["effective_path"] == "fallback"
        assert "AISOC_AIRGAP_ALLOWLIST" in str(snap["policy_note"])

    def test_airgap_on_allows_local_ollama(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(airgap_module.settings, "AISOC_AIRGAPPED", True)
        monkeypatch.setenv("OPENAI_API_KEY", "ollama")
        monkeypatch.setenv("OPENAI_BASE_URL", "http://ollama:11434/v1")
        snap = llm_status()
        assert snap["airgap_enabled"] is True
        assert snap["airgap_compliant"] is True
        assert snap["effective_path"] == "live"
        assert snap["is_local"] is True

    def test_airgap_on_allows_allowlisted_external_mirror(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(airgap_module.settings, "AISOC_AIRGAPPED", True)
        monkeypatch.setattr(
            airgap_module.settings,
            "AISOC_AIRGAP_ALLOWLIST",
            ["llm-mirror.acme-internal.example.com"],
        )
        monkeypatch.setenv("OPENAI_API_KEY", "x")
        monkeypatch.setenv("OPENAI_BASE_URL", "https://llm-mirror.acme-internal.example.com/v1")
        snap = llm_status()
        assert snap["airgap_compliant"] is True
        assert snap["effective_path"] == "live"
        # Not classified as "local" — it's an internal SaaS mirror.
        assert snap["is_local"] is False

    def test_airgap_on_no_config_is_compliant(self, monkeypatch: pytest.MonkeyPatch):
        # Air-gap on, no key, no base — fallback path is implicitly
        # compliant because nothing leaves the pod.
        monkeypatch.setattr(airgap_module.settings, "AISOC_AIRGAPPED", True)
        snap = llm_status()
        assert snap["airgap_enabled"] is True
        assert snap["airgap_compliant"] is True
        assert snap["provider"] == "none"
        assert snap["effective_path"] == "fallback"


class TestEffectivePath:
    """``effective_path`` must mirror the explain agent's _llm_allowed semantics."""

    def test_live_when_key_set_and_no_airgap(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("OPENAI_API_KEY", "x")
        snap = llm_status()
        assert snap["effective_path"] == "live"

    def test_fallback_when_key_unset(self, monkeypatch: pytest.MonkeyPatch):
        snap = llm_status()
        assert snap["effective_path"] == "fallback"

    def test_fallback_when_key_set_but_airgap_blocks(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(airgap_module.settings, "AISOC_AIRGAPPED", True)
        monkeypatch.setenv("OPENAI_API_KEY", "x")
        # No base_url + airgap on → would default to api.openai.com → blocked.
        snap = llm_status()
        assert snap["effective_path"] == "fallback"
        assert snap["airgap_compliant"] is False
