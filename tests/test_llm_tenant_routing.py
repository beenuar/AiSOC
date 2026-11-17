"""Provider defaults and endpoint credential binding, with no service runtime."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AGENTS = ROOT / "services/agents/app/llm/tenant_routing.py"
API = ROOT / "services/api/app/services/llm_tenant_routing.py"
spec = importlib.util.spec_from_file_location("tenant_routing", AGENTS)
assert spec and spec.loader
routing = importlib.util.module_from_spec(spec)
spec.loader.exec_module(routing)


class TenantRouteTests(unittest.TestCase):
    def test_no_auth_requires_an_explicit_local_or_custom_endpoint_and_no_stored_key(self) -> None:
        for provider in ("local-ollama", "local-vllm", "local-litellm", "custom"):
            with self.subTest(provider=provider):
                self.assertTrue(routing.allows_unauthenticated(provider, "http://local.example/v1", False))
                self.assertFalse(routing.allows_unauthenticated(provider, "http://local.example/v1", True))
                self.assertFalse(routing.allows_unauthenticated(provider, None, False))
        for provider in ("openai", "anthropic", "azure-openai"):
            self.assertFalse(routing.allows_unauthenticated(provider, "https://provider.example/v1", False))

    def test_services_use_identical_rules(self) -> None:
        self.assertEqual(AGENTS.read_bytes(), API.read_bytes())

    def test_hosted_key_only_selects_provider_instead_of_gateway(self) -> None:
        for provider, expected in {
            "openai": ("https://api.openai.com/v1", "gpt-4o-mini"),
            "anthropic": ("https://api.anthropic.com/v1", "claude-haiku-4-5-20251001"),
        }.items():
            with self.subTest(provider=provider):
                route = routing.tenant_route(
                    provider=provider, base_url=None, model=None, env_base="http://litellm:4000/v1", env_model="aisoc-summary"
                )
                self.assertEqual(route, (*expected, True, True, False))

    def test_explicit_provider_route_and_model_win(self) -> None:
        route = routing.tenant_route(
            provider="openai",
            base_url="https://tenant.example/v1",
            model="tenant-model",
            env_base="http://litellm:4000/v1",
            env_model="aisoc-summary",
        )
        self.assertEqual(route, ("https://tenant.example/v1", "tenant-model", True, True, False))

    def test_same_gateway_can_keep_role_alias_and_credential(self) -> None:
        route = routing.tenant_route(
            provider="local-litellm",
            base_url="http://litellm:4000/v1/",
            model=None,
            env_base="http://litellm:4000/v1",
            env_model="aisoc-summary",
        )
        self.assertEqual(route, ("http://litellm:4000/v1/", "aisoc-summary", True, False, True))

    def test_default_openai_endpoint_matches_implicit_baseline(self) -> None:
        route = routing.tenant_route(provider="openai", base_url=None, model=None, env_base="", env_model="")
        self.assertTrue(route[-1])

    def test_credential_scope_includes_scheme_port_and_path(self) -> None:
        for other in [
            "https://other.example/v1",
            "http://gateway.example/v1",
            "https://gateway.example:444/v1",
            "https://gateway.example/other",
            "https://gateway.example/v1?tenant=other",
            "https://user:password@gateway.example/v1",
            "https://gateway.example/v1#other",
            "",
            "https://gateway.example:bad/v1",
        ]:
            with self.subTest(other=other):
                self.assertFalse(routing.same_endpoint("https://gateway.example/v1", other))

    def test_airgap_host_policy_requires_private_or_explicitly_allowed_destinations(self) -> None:
        for host in ("api.openai.com", "api.anthropic.com", "unlisted.example"):
            self.assertFalse(routing.airgap_host_allowed(host, []))
            self.assertTrue(routing.airgap_host_allowed(host, [host]))
        for host in ("ollama", "192.168.1.1", "gateway.internal", "localhost", "::1"):
            self.assertTrue(routing.airgap_host_allowed(host, []))
        self.assertFalse(routing.airgap_host_allowed("", []))

    def test_trailing_slash_and_host_case_do_not_change_destination(self) -> None:
        self.assertTrue(routing.same_endpoint("https://GATEWAY.example/v1/", "https://gateway.example/v1"))


if __name__ == "__main__":
    unittest.main()
