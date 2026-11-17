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

import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.api.v1.endpoints import llm_status as status_module
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
        # The gateway pair the default deployment supplies. The indicator now
        # reports the route the explain path would actually take, so leaving
        # these set would make "nothing configured" describe a live gateway.
        "LLM_GATEWAY_URL",
        "LITELLM_MASTER_KEY",
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

    def test_url_credentials_are_redacted_without_changing_the_configured_route(self, monkeypatch: pytest.MonkeyPatch):
        endpoint = "https://username:url-secret@proxy.example/v1?api_key=query-secret#fragment-secret"
        monkeypatch.setenv("OPENAI_BASE_URL", endpoint)
        monkeypatch.setenv("OPENAI_API_KEY", "key-secret")
        snap = llm_status()
        assert snap["base_url"] == "https://proxy.example/v1"
        assert status_module._env_baseline()[0] == endpoint
        for secret in ("username", "url-secret", "query-secret", "fragment-secret", "key-secret"):
            assert secret not in str(snap)


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

    def test_status_matches_runtime_openai_alias_precedence(self, monkeypatch: pytest.MonkeyPatch):
        # The resolver and role routing prefer OPENAI_BASE_URL when both
        # aliases are set. The status must describe the route actually used.
        monkeypatch.setenv("LLM_BASE_URL", "http://ollama:11434/v1")
        monkeypatch.setenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
        monkeypatch.setenv("LLM_API_KEY", "x")
        snap = llm_status()
        assert snap["provider"] == "openai"
        assert snap["base_url"] == "https://api.openai.com/v1"


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


class TestUnauthenticatedTenantStatus:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("provider", ["local-ollama", "local-vllm", "local-litellm", "custom"])
    async def test_explicit_endpoint_without_key_is_live(self, monkeypatch: pytest.MonkeyPatch, provider: str):
        monkeypatch.setenv("LLM_GATEWAY_URL", "http://litellm:4000/v1")
        monkeypatch.setenv("LITELLM_MASTER_KEY", "gateway-test-key")
        cred = SimpleNamespace(
            provider=provider,
            base_url="http://tenant-model.internal:11434/v1",
            model="tenant-model",
            api_key_vault=None,
            enabled=True,
        )
        result = MagicMock()
        result.scalar_one_or_none.return_value = cred
        db = MagicMock(execute=AsyncMock(return_value=result))

        snap = await status_module.tenant_llm_status(db, uuid.uuid4())

        assert snap["key_set"] is False
        assert snap["effective_path"] == "live"
        assert snap["base_url"] == cred.base_url
        assert snap["source"] == "tenant"
        assert "gateway-test-key" not in str(snap)
        assert "disabled" not in str(snap["policy_note"])

    @pytest.mark.asyncio
    async def test_corrupt_stored_key_is_not_treated_as_no_auth(self, monkeypatch: pytest.MonkeyPatch):
        cred = SimpleNamespace(
            provider="custom",
            base_url="http://tenant-model.internal:11434/v1",
            model="tenant-model",
            api_key_vault="vault-test-token",
            enabled=True,
        )
        result = MagicMock()
        result.scalar_one_or_none.return_value = cred
        db = MagicMock(execute=AsyncMock(return_value=result))
        vault = MagicMock()
        vault.decrypt.side_effect = status_module.CredentialVaultError("cannot decrypt")
        monkeypatch.setattr(status_module, "get_vault", lambda: vault)

        snap = await status_module.tenant_llm_status(db, uuid.uuid4())

        assert snap["key_set"] is False
        assert snap["effective_path"] == "fallback"
        assert "No usable credential" in str(snap["policy_note"])

    @pytest.mark.asyncio
    async def test_no_auth_endpoint_still_obeys_airgap(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(airgap_module.settings, "AISOC_AIRGAPPED", True)
        cred = SimpleNamespace(
            provider="custom",
            base_url="https://external-model.example/v1",
            model="tenant-model",
            api_key_vault=None,
            enabled=True,
        )
        result = MagicMock()
        result.scalar_one_or_none.return_value = cred
        db = MagicMock(execute=AsyncMock(return_value=result))

        snap = await status_module.tenant_llm_status(db, uuid.uuid4())

        assert snap["key_set"] is False
        assert snap["effective_path"] == "fallback"
        assert snap["airgap_compliant"] is False
