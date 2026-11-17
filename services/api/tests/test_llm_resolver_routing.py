"""BYOK runtime and status must agree on a provider's route and credential."""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.api.v1.endpoints import llm_status as status_module
from app.core import airgap as airgap_module
from app.services import llm_resolver
from app.services.llm_tenant_routing import airgap_host_allowed


@pytest.fixture(autouse=True)
def gateway_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "OPENAI_BASE_URL",
        "LLM_BASE_URL",
        "OPENAI_MODEL",
        "LLM_MODEL",
        "AISOC_LLM_MODEL",
        "OPENAI_API_KEY",
        "LLM_API_KEY",
        "AISOC_AIRGAPPED",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("LLM_GATEWAY_URL", "http://litellm:4000/v1")
    monkeypatch.setenv("LITELLM_MASTER_KEY", "gateway-test-key")
    monkeypatch.setattr(airgap_module.settings, "AISOC_AIRGAPPED", False)
    monkeypatch.setattr(airgap_module.settings, "AISOC_AIRGAP_ALLOWLIST", [])


def database(row: SimpleNamespace | None) -> MagicMock:
    result = MagicMock()
    result.scalar_one_or_none.return_value = row
    return MagicMock(execute=AsyncMock(return_value=result))


def credential(**fields: object) -> SimpleNamespace:
    return SimpleNamespace(
        **{
            "provider": "openai",
            "base_url": None,
            "model": None,
            "api_key_vault": "vault-test-token",
            "enabled": True,
            **fields,
        }
    )


def decrypt_as(monkeypatch: pytest.MonkeyPatch, key: str | None) -> None:
    monkeypatch.setattr(llm_resolver, "_decrypt_vault_token", lambda *_: key)
    vault = MagicMock()
    if key is None:
        vault.decrypt.side_effect = status_module.CredentialVaultError("cannot decrypt")
    else:
        vault.decrypt.return_value = key
    monkeypatch.setattr(status_module, "get_vault", lambda: vault)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("provider", "expected_base", "expected_model"),
    [
        ("openai", "https://api.openai.com/v1", "gpt-4o-mini"),
        ("anthropic", "https://api.anthropic.com/v1", "claude-haiku-4-5-20251001"),
    ],
)
async def test_hosted_key_only_uses_provider_defaults(
    monkeypatch: pytest.MonkeyPatch, provider: str, expected_base: str, expected_model: str
) -> None:
    decrypt_as(monkeypatch, "tenant-test-key")
    db = database(credential(provider=provider))
    tenant_id = uuid.uuid4()
    cfg = await llm_resolver.resolve_llm_config(db, tenant_id)
    snap = await status_module.tenant_llm_status(db, tenant_id)
    assert (cfg.base_url, cfg.model, cfg.api_key) == (expected_base, expected_model, "tenant-test-key")
    assert cfg.allowed and cfg.base_url_from_tenant and cfg.model_from_tenant
    assert cfg.api_key_from_tenant and cfg.source == "tenant"
    assert (snap["base_url"], snap["model"], snap["key_set"]) == (expected_base, expected_model, True)
    assert snap["source"] == "tenant"
    assert "tenant-test-key" not in str(snap)
    assert "gateway-test-key" not in str(snap)


@pytest.mark.asyncio
@pytest.mark.parametrize("vault_token", [None, "vault-test-token"])
async def test_foreign_endpoint_never_inherits_gateway_key(monkeypatch: pytest.MonkeyPatch, vault_token: str | None) -> None:
    decrypt_as(monkeypatch, None)
    db = database(credential(provider="custom", base_url="https://tenant.example/v1", model="tenant-model", api_key_vault=vault_token))
    tenant_id = uuid.uuid4()
    cfg = await llm_resolver.resolve_llm_config(db, tenant_id)
    snap = await status_module.tenant_llm_status(db, tenant_id)
    assert cfg.allowed is (vault_token is None) and cfg.api_key is None
    assert snap["key_set"] is False
    assert snap["effective_path"] == ("live" if vault_token is None else "fallback")
    assert "gateway-test-key" not in str(snap)


@pytest.mark.asyncio
async def test_same_gateway_can_inherit_its_key() -> None:
    db = database(credential(provider="local-litellm", base_url="http://litellm:4000/v1/", model="aisoc-triage", api_key_vault=None))
    tenant_id = uuid.uuid4()
    cfg = await llm_resolver.resolve_llm_config(db, tenant_id)
    snap = await status_module.tenant_llm_status(db, tenant_id)
    assert cfg.allowed and cfg.api_key == "gateway-test-key"
    assert snap["key_set"] is True


@pytest.mark.asyncio
@pytest.mark.parametrize("row", [None, credential(enabled=False)])
async def test_no_active_override_preserves_gateway(row: SimpleNamespace | None) -> None:
    db = database(row)
    tenant_id = uuid.uuid4()
    cfg = await llm_resolver.resolve_llm_config(db, tenant_id)
    snap = await status_module.tenant_llm_status(db, tenant_id)
    assert (cfg.base_url, cfg.model, cfg.api_key) == ("http://litellm:4000/v1", "aisoc-summary", "gateway-test-key")
    assert cfg.allowed and cfg.source == "environment"
    assert not (cfg.base_url_from_tenant or cfg.model_from_tenant or cfg.api_key_from_tenant)
    assert snap["source"] == "environment"


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", ["openai", "anthropic"])
async def test_hosted_defaults_remain_blocked_by_airgap(monkeypatch: pytest.MonkeyPatch, provider: str) -> None:
    decrypt_as(monkeypatch, "tenant-test-key")
    monkeypatch.setenv("AISOC_AIRGAPPED", "true")
    monkeypatch.setattr(airgap_module.settings, "AISOC_AIRGAPPED", True)
    monkeypatch.setattr(airgap_module.settings, "AISOC_AIRGAP_ALLOWLIST", [])
    db = database(credential(provider=provider))
    tenant_id = uuid.uuid4()
    cfg = await llm_resolver.resolve_llm_config(db, tenant_id)
    snap = await status_module.tenant_llm_status(db, tenant_id)
    assert cfg.allowed is False and cfg.api_key is None
    assert "AISOC_AIRGAPPED" in cfg.reason
    assert snap["effective_path"] == "fallback"
    assert snap["airgap_compliant"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize("provider", ["openai", "anthropic"])
async def test_allowlisted_host_is_consistent_for_runtime_status_and_probe_policy(monkeypatch: pytest.MonkeyPatch, provider: str) -> None:
    decrypt_as(monkeypatch, "tenant-test-key")
    host = f"api.{provider}.com"
    monkeypatch.setattr(airgap_module.settings, "AISOC_AIRGAPPED", True)
    monkeypatch.setattr(airgap_module.settings, "AISOC_AIRGAP_ALLOWLIST", [host])
    db = database(credential(provider=provider))
    tenant_id = uuid.uuid4()
    cfg = await llm_resolver.resolve_llm_config(db, tenant_id)
    snap = await status_module.tenant_llm_status(db, tenant_id)
    assert cfg.allowed and cfg.api_key == "tenant-test-key"
    assert snap["effective_path"] == "live" and snap["airgap_compliant"] is True
    # The probe's real policy entry point must admit the same route.
    airgap_module.enforce_airgap_for_url(cfg.base_url)


@pytest.mark.asyncio
async def test_implicit_openai_default_obeys_the_same_allowlist(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LLM_GATEWAY_URL")
    monkeypatch.setenv("OPENAI_API_KEY", "deployment-test-key")
    monkeypatch.setattr(airgap_module.settings, "AISOC_AIRGAPPED", True)
    monkeypatch.setattr(airgap_module.settings, "AISOC_AIRGAP_ALLOWLIST", ["api.openai.com"])
    cfg = await llm_resolver.resolve_llm_config(database(None), uuid.uuid4())
    assert cfg.allowed
    assert status_module.llm_status()["effective_path"] == "live"
    airgap_module.enforce_airgap_for_url(cfg.base_url)


@pytest.mark.parametrize("allowlist", [[], ["api.anthropic.com", "MODEL.EXAMPLE:443"]])
@pytest.mark.parametrize(
    "host",
    [
        "",
        "ollama",
        "localhost",
        "127.0.0.1",
        "10.0.0.1",
        "::1",
        "192.168.1.1",
        "gateway.internal",
        "api.anthropic.com",
        "api.openai.com",
        "sub.model.example",
        "unlisted.example",
    ],
)
def test_agents_host_policy_matches_canonical_api_egress(host: str, allowlist: list[str]) -> None:
    assert airgap_host_allowed(host, allowlist) == airgap_module.is_host_allowed_for_airgap(host, allowlist)
