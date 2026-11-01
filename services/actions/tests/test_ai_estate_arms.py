"""AI-estate containment: signatures, dry-run behaviour and vendor shapes.

Wave-2 Phase 7.5. Same three properties ``test_cloud_saas_arms.py`` grades,
applied to every arm here, plus the one that is specific to this phase:
**the three providers give three different answers to "can this be
undone"**, and the contract has to carry each honestly.

OpenAI deletes a project key, so that arm declares no rollback. Anthropic
deactivates one, so it has a real platform rollback and is the reason
``restore_token`` exists as a verb. A gateway block is a documented pair.
Asserting that here is the point: a single ``revoke_token`` contract
claiming a platform rollback because one vendor can would give the rollback
path a route back it does not have on the other two.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import create_autospec

import httpx
import pytest
import respx
from app.clients import factories
from app.clients.ai_provider_clients import (
    AIGatewayClient,
    AnthropicAdminClient,
    OpenAIAdminClient,
)
from app.live_actions import ai_estate_arms
from app.live_actions.ai_estate_arms import AI_ESTATE_EXECUTORS
from app.live_actions.capability_contracts import CAPABILITY_CONTRACTS
from app.live_actions.models import LiveActionRequest, LiveActionStatus

#: executor name -> (factory attribute, client class, methods, extra params)
EXPECTED: dict[str, tuple[str, type, tuple[str, ...], dict[str, Any]]] = {
    "OpenAIRevokeToken": ("_openai_admin_client", OpenAIAdminClient, ("delete_project_api_key",), {"project_id": "proj_1"}),
    "OpenAIDemoteRole": ("_openai_admin_client", OpenAIAdminClient, ("set_project_user_role",), {"project_id": "proj_1"}),
    "OpenAIRemoveWorkspaceMember": ("_openai_admin_client", OpenAIAdminClient, ("remove_project_user",), {"project_id": "proj_1"}),
    "OpenAIGetCloudIdentity": ("_openai_admin_client", OpenAIAdminClient, ("get_project_user",), {"project_id": "proj_1"}),
    "AnthropicRevokeToken": ("_anthropic_admin_client", AnthropicAdminClient, ("set_api_key_status",), {}),
    "AnthropicRestoreToken": ("_anthropic_admin_client", AnthropicAdminClient, ("set_api_key_status",), {}),
    "AnthropicDemoteRole": ("_anthropic_admin_client", AnthropicAdminClient, ("set_user_role",), {}),
    "AnthropicRemoveWorkspaceMember": (
        "_anthropic_admin_client",
        AnthropicAdminClient,
        ("remove_workspace_member",),
        {"workspace_id": "wrkspc_1"},
    ),
    "AnthropicGetCloudIdentity": ("_anthropic_admin_client", AnthropicAdminClient, ("get_user",), {}),
    "AIGatewayRevokeToken": ("_ai_gateway_client", AIGatewayClient, ("block_key",), {}),
    "AIGatewayRestoreToken": ("_ai_gateway_client", AIGatewayClient, ("unblock_key",), {}),
    "AIGatewaySetSpendCap": ("_ai_gateway_client", AIGatewayClient, ("set_max_budget",), {"max_budget": 0}),
    "AIGatewayRestoreSpendCap": ("_ai_gateway_client", AIGatewayClient, ("set_max_budget",), {"max_budget": 250.0}),
    "AIGatewayGetCloudIdentity": ("_ai_gateway_client", AIGatewayClient, ("key_info",), {}),
}

FULL_CREDENTIALS: dict[str, Any] = {
    "openai_admin_key": "unit-test-placeholder",
    "anthropic_admin_key": "unit-test-placeholder",
    "ai_gateway_url": "https://gateway.example.invalid",
    "ai_gateway_master_key": "unit-test-placeholder",
}

FACTORY_KEY_TUPLES = {
    "_openai_admin_client": factories.OPENAI_ADMIN_CLIENT_PARAM_KEYS,
    "_anthropic_admin_client": factories.ANTHROPIC_ADMIN_CLIENT_PARAM_KEYS,
    "_ai_gateway_client": factories.AI_GATEWAY_CLIENT_PARAM_KEYS,
}


def _request(executor_cls) -> LiveActionRequest:
    params = dict(FULL_CREDENTIALS)
    params.update(EXPECTED[executor_cls.__name__][3])
    return LiveActionRequest(
        vendor_id=executor_cls.vendor_id,
        capability=executor_cls.capability,
        target="TARGET",
        params=params,
    )


class TestEveryArmIsGraded:
    def test_every_executor_has_a_row(self) -> None:
        assert {cls.__name__ for cls in AI_ESTATE_EXECUTORS} == set(EXPECTED)

    def test_no_ai_verb_is_automatic(self) -> None:
        """Unverifiable means not autonomous, and none of these is probed."""
        for cls in AI_ESTATE_EXECUTORS:
            contract = CAPABILITY_CONTRACTS[cls.capability]
            if contract.impact.value == "read_only":
                continue
            assert contract.approval.value != "automatic", f"{cls.__name__} would auto-execute with nothing checking the effect"

    def test_declared_key_tuples_match_what_the_factories_read(self) -> None:
        import ast
        import inspect

        for name, declared in FACTORY_KEY_TUPLES.items():
            tree = ast.parse(inspect.getsource(getattr(factories, name)).lstrip())
            read = {
                node.args[0].value
                for node in ast.walk(tree)
                if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "get"
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "params"
                and node.args
                and isinstance(node.args[0], ast.Constant)
            }
            assert read == set(declared), f"{name}: reads {sorted(read)}, declares {sorted(declared)}"

    @pytest.mark.parametrize("factory_name", sorted(FACTORY_KEY_TUPLES))
    def test_stripping_the_declared_keys_disables_the_factory(self, factory_name: str) -> None:
        factory = getattr(factories, factory_name)
        assert factory(dict(FULL_CREDENTIALS)) is not None
        stripped = {k: v for k, v in FULL_CREDENTIALS.items() if k not in FACTORY_KEY_TUPLES[factory_name]}
        assert factory(stripped) is None


class TestSignaturesAndDryRun:
    pytestmark = pytest.mark.asyncio

    @pytest.mark.parametrize("executor_cls", AI_ESTATE_EXECUTORS, ids=lambda c: c.__name__)
    async def test_arm_calls_its_client_method(self, executor_cls, monkeypatch) -> None:
        factory_name, client_cls, methods, _params = EXPECTED[executor_cls.__name__]
        double = create_autospec(client_cls, instance=True)
        for method in methods:
            getattr(double, method).return_value = {}
        monkeypatch.setattr(ai_estate_arms, factory_name, lambda _params: double)

        result = await executor_cls().execute(_request(executor_cls))

        assert result.status is LiveActionStatus.SUCCEEDED, result.error
        for method in methods:
            assert getattr(double, method).await_count >= 1

    @pytest.mark.parametrize("executor_cls", AI_ESTATE_EXECUTORS, ids=lambda c: c.__name__)
    async def test_dry_run_never_constructs_a_client(self, executor_cls, monkeypatch) -> None:
        factory_name, _client_cls, _methods, _params = EXPECTED[executor_cls.__name__]

        def _refuse(_params):
            raise AssertionError(f"{executor_cls.__name__}: dry run constructed a client")

        monkeypatch.setattr(ai_estate_arms, factory_name, _refuse)
        request = _request(executor_cls)
        result = await executor_cls().execute(request.model_copy(update={"dry_run": True}))

        assert result.status is LiveActionStatus.SIMULATED

    @pytest.mark.parametrize("executor_cls", AI_ESTATE_EXECUTORS, ids=lambda c: c.__name__)
    async def test_missing_credentials_say_so(self, executor_cls, monkeypatch) -> None:
        factory_name, _client_cls, _methods, _params = EXPECTED[executor_cls.__name__]
        monkeypatch.setattr(ai_estate_arms, factory_name, lambda _params: None)
        result = await executor_cls().execute(_request(executor_cls))
        assert result.status is LiveActionStatus.FAILED
        assert "credentials are not configured" in (result.error or "")


class TestThreeProvidersThreeAnswersAboutRollback:
    """The property this phase turns on.

    One ``revoke_token`` contract claiming a platform rollback because
    Anthropic can would give the rollback path a route back it does not
    have on OpenAI or on a deleted key.
    """

    pytestmark = pytest.mark.asyncio

    async def test_openai_deletes_and_offers_no_restore(self) -> None:
        with respx.mock:
            route = respx.delete("https://api.openai.com/v1/organization/projects/proj_1/api_keys/key_abc").respond(
                200, json={"deleted": True}
            )
            client = OpenAIAdminClient(admin_key="unit-test-placeholder")
            result = await client.delete_project_api_key(project_id="proj_1", key_id="key_abc")

        assert route.called
        assert result["deleted"] is True
        # No restore method exists on the client, and no arm declares one.
        assert not hasattr(client, "restore_project_api_key")
        assert not any(cls.vendor_id == "openai" and cls.capability == "restore_token" for cls in AI_ESTATE_EXECUTORS)

    async def test_anthropic_deactivates_and_the_reverse_is_the_same_field(self) -> None:
        bodies: list[str] = []

        async def _handler(request: httpx.Request) -> httpx.Response:
            bodies.append(request.read().decode())
            return httpx.Response(200, json={"id": "apikey_1", "name": "ci", "status": "inactive"})

        with respx.mock:
            respx.post("https://api.anthropic.com/v1/organizations/api_keys/apikey_1").mock(side_effect=_handler)
            client = AnthropicAdminClient(admin_key="unit-test-placeholder")
            await client.set_api_key_status(api_key_id="apikey_1", status="inactive")
            await client.set_api_key_status(api_key_id="apikey_1", status="active")

        assert '"status": "inactive"' in bodies[0] or '"status":"inactive"' in bodies[0]
        assert '"status": "active"' in bodies[1] or '"status":"active"' in bodies[1]
        # One method for both directions, so the containment and its
        # rollback cannot drift into different request shapes.
        assert any(cls.capability == "restore_token" and cls.vendor_id == "anthropic" for cls in AI_ESTATE_EXECUTORS)

    async def test_the_anthropic_version_header_is_pinned(self) -> None:
        """A default version that moves could change a response shape under
        a containment action without a commit here."""
        seen: dict[str, Any] = {}

        async def _handler(request: httpx.Request) -> httpx.Response:
            seen["version"] = request.headers.get("anthropic-version")
            seen["auth"] = request.headers.get("x-api-key")
            return httpx.Response(200, json={"id": "u1", "role": "user"})

        with respx.mock:
            respx.get("https://api.anthropic.com/v1/organizations/users/u1").mock(side_effect=_handler)
            await AnthropicAdminClient(admin_key="unit-test-placeholder").get_user(user_id="u1")

        assert seen["version"] == "2023-06-01"
        assert seen["auth"] == "unit-test-placeholder"

    async def test_the_gateway_block_and_unblock_are_a_pair(self) -> None:
        with respx.mock:
            block = respx.post("https://gateway.example.invalid/key/block").respond(200, json={"key": "sk-x", "blocked": True})
            unblock = respx.post("https://gateway.example.invalid/key/unblock").respond(200, json={"key": "sk-x", "blocked": False})
            client = AIGatewayClient(base_url="https://gateway.example.invalid", master_key="unit-test-placeholder")
            assert (await client.block_key("sk-x"))["blocked"] is True
            assert (await client.unblock_key("sk-x"))["blocked"] is False
        assert block.called and unblock.called

    async def test_a_negative_budget_is_refused_rather_than_sent(self) -> None:
        """The gateway's behaviour on one is undocumented, and an
        undocumented behaviour is not a control."""
        client = AIGatewayClient(base_url="https://gateway.example.invalid", master_key="unit-test-placeholder")
        with pytest.raises(ValueError, match="negative"):
            await client.set_max_budget("sk-x", max_budget=-1)

    async def test_a_provider_refusal_is_reported_with_its_own_message(self) -> None:
        with respx.mock:
            respx.delete("https://api.openai.com/v1/organization/projects/proj_1/api_keys/key_abc").respond(
                403, json={"error": {"message": "insufficient permissions for this project"}}
            )
            client = OpenAIAdminClient(admin_key="unit-test-placeholder")
            with pytest.raises(Exception, match="insufficient permissions"):
                await client.delete_project_api_key(project_id="proj_1", key_id="key_abc")


class TestWhatThisPhaseDeliberatelyDidNotAdd:
    def test_ai_oauth_grant_revocation_reuses_the_existing_arms(self) -> None:
        """An AI application's grant is an ordinary Workspace, Entra or Okta
        consent. A fourth arm here would be a second code path to the same
        vendor endpoint, which is how two implementations of one verb come
        to disagree."""
        from app.live_actions.builtins import _BUILTIN_ADAPTERS

        vendors = {cls.vendor_id for cls in _BUILTIN_ADAPTERS if cls.capability == "revoke_oauth_grant"}
        assert vendors == {"azure_entra", "google_workspace", "okta"}

    def test_agent_process_kill_reuses_the_edr_arms(self) -> None:
        """The agent is a process on a host, and the verb that kills one
        already works on three vendors."""
        from app.live_actions.builtins import _BUILTIN_ADAPTERS

        killers = {cls.vendor_id for cls in _BUILTIN_ADAPTERS if cls.capability == "kill_process"}
        assert len(killers) >= 2, f"the kill-switch playbook depends on these: {killers}"

    def test_no_spend_cap_arm_exists_for_a_provider_that_has_no_budget_api(self) -> None:
        """Recorded rather than shipped as a verb that quietly does
        nothing: neither OpenAI's nor Anthropic's public admin API exposes
        a budget this platform can set."""
        capped = {cls.vendor_id for cls in AI_ESTATE_EXECUTORS if cls.capability == "set_spend_cap"}
        assert capped == {"ai_gateway"}
