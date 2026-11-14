"""AI-estate response arms (wave-2 Phase 7.5 / depth 6.6).

The inventory knew which coding agents, MCP servers, IDE extensions and
provider keys existed and scored each one's exposure. Nothing could act on
any of it, so a provider key found in a public repository was a finding
with a recommendation and no verb.

Five things depth 6.6 asks for, and where each one is:

* **provider key revocation** — ``revoke_token`` on OpenAI and Anthropic
  below, with ``restore_token`` on Anthropic because that provider
  deactivates rather than deletes;
* **AI OAuth grant revocation** — the ``revoke_oauth_grant`` arms shipped
  in Phase 6.1. An AI application's grant is an ordinary Workspace, Entra
  or Okta consent, so a fourth arm here would be a second code path to the
  same vendor endpoint. Recorded rather than duplicated;
* **gateway key block** — ``revoke_token`` / ``restore_token`` on the
  gateway;
* **agent process kill** — the existing EDR ``kill_process`` arms. The
  agent is a process on a host and the verb that kills one already works
  on three vendors; a new one would be the same call behind a new name;
* **a kill-switch playbook that requires approval** —
  ``playbooks/packs/v1/ai-agent-kill-switch/``.

Plus what this plan adds: role demotion, workspace removal and spend caps
**where the provider API allows**. Only the gateway offers a budget; the
absence on the other two is recorded in ``ai_provider_clients.py`` rather
than shipped as a verb that quietly does nothing.
"""

from __future__ import annotations

import structlog

from app.clients.factories import (
    AI_GATEWAY_CLIENT_PARAM_KEYS,
    ANTHROPIC_ADMIN_CLIENT_PARAM_KEYS,
    OPENAI_ADMIN_CLIENT_PARAM_KEYS,
    _ai_gateway_client,
    _anthropic_admin_client,
    _openai_admin_client,
)
from app.live_actions.capability_contracts import apply_contract
from app.live_actions.cloud_saas_arms import _require, _run
from app.live_actions.executor import LiveActionExecutor
from app.live_actions.models import LiveActionRequest, LiveActionResult

logger = structlog.get_logger(__name__)


# ─── OpenAI ──────────────────────────────────────────────────────────────────


@apply_contract
class OpenAIRevokeToken(LiveActionExecutor):
    vendor_id = "openai"
    capability = "revoke_token"
    description = "Delete one OpenAI project API key. Irreversible: a replacement key is a different credential."
    requires_credentials = True
    _credential_keys = OPENAI_ADMIN_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "OpenAI",
            _openai_admin_client,
            lambda c, t, p: c.delete_project_api_key(project_id=_require(p, "project_id"), key_id=t),
            "project API key {target} deleted",
        )


@apply_contract
class OpenAIDemoteRole(LiveActionExecutor):
    vendor_id = "openai"
    capability = "demote_role"
    description = "Move a project member from owner to member, so they can no longer mint keys."
    requires_credentials = True
    _credential_keys = OPENAI_ADMIN_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "OpenAI",
            _openai_admin_client,
            lambda c, t, p: c.set_project_user_role(project_id=_require(p, "project_id"), user_id=t, role=p.get("role", "member")),
            "{target} demoted on the OpenAI project",
        )


@apply_contract
class OpenAIRemoveWorkspaceMember(LiveActionExecutor):
    vendor_id = "openai"
    capability = "remove_workspace_member"
    description = "Remove a member from an OpenAI project."
    requires_credentials = True
    _credential_keys = OPENAI_ADMIN_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "OpenAI",
            _openai_admin_client,
            lambda c, t, p: c.remove_project_user(project_id=_require(p, "project_id"), user_id=t),
            "{target} removed from the OpenAI project",
        )


@apply_contract
class OpenAIGetCloudIdentity(LiveActionExecutor):
    vendor_id = "openai"
    capability = "get_cloud_identity"
    description = "Project membership and role for one OpenAI user."
    requires_credentials = True
    _credential_keys = OPENAI_ADMIN_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "OpenAI",
            _openai_admin_client,
            lambda c, t, p: c.get_project_user(project_id=_require(p, "project_id"), user_id=t),
            "read OpenAI project membership for {target}",
        )


# ─── Anthropic ───────────────────────────────────────────────────────────────


@apply_contract
class AnthropicRevokeToken(LiveActionExecutor):
    vendor_id = "anthropic"
    capability = "revoke_token"
    description = "Deactivate one Anthropic API key. Deactivated rather than deleted, which is what makes the reverse exact."
    requires_credentials = True
    _credential_keys = ANTHROPIC_ADMIN_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "Anthropic",
            _anthropic_admin_client,
            lambda c, t, p: c.set_api_key_status(api_key_id=t, status="inactive"),
            "API key {target} deactivated",
        )


@apply_contract
class AnthropicRestoreToken(LiveActionExecutor):
    vendor_id = "anthropic"
    capability = "restore_token"
    description = "Reactivate an Anthropic API key the platform deactivated."
    requires_credentials = True
    _credential_keys = ANTHROPIC_ADMIN_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "Anthropic",
            _anthropic_admin_client,
            lambda c, t, p: c.set_api_key_status(api_key_id=t, status="active"),
            "API key {target} reactivated",
        )


@apply_contract
class AnthropicDemoteRole(LiveActionExecutor):
    vendor_id = "anthropic"
    capability = "demote_role"
    description = "Lower an Anthropic organisation member's role."
    requires_credentials = True
    _credential_keys = ANTHROPIC_ADMIN_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "Anthropic",
            _anthropic_admin_client,
            lambda c, t, p: c.set_user_role(user_id=t, role=p.get("role", "user")),
            "{target} demoted in the Anthropic organisation",
        )


@apply_contract
class AnthropicRemoveWorkspaceMember(LiveActionExecutor):
    vendor_id = "anthropic"
    capability = "remove_workspace_member"
    description = "Remove a member from an Anthropic workspace."
    requires_credentials = True
    _credential_keys = ANTHROPIC_ADMIN_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "Anthropic",
            _anthropic_admin_client,
            lambda c, t, p: c.remove_workspace_member(workspace_id=_require(p, "workspace_id"), user_id=t),
            "{target} removed from the Anthropic workspace",
        )


@apply_contract
class AnthropicGetCloudIdentity(LiveActionExecutor):
    vendor_id = "anthropic"
    capability = "get_cloud_identity"
    description = "Organisation record and role for one Anthropic user."
    requires_credentials = True
    _credential_keys = ANTHROPIC_ADMIN_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "Anthropic",
            _anthropic_admin_client,
            lambda c, t, p: c.get_user(user_id=t),
            "read Anthropic organisation record for {target}",
        )


# ─── AI gateway ──────────────────────────────────────────────────────────────


@apply_contract
class AIGatewayRevokeToken(LiveActionExecutor):
    vendor_id = "ai_gateway"
    capability = "revoke_token"
    description = "Block a virtual key at the gateway. The key survives; nothing it asks for is served."
    requires_credentials = True
    _credential_keys = AI_GATEWAY_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "AI gateway",
            _ai_gateway_client,
            lambda c, t, p: c.block_key(t),
            "gateway key blocked",
        )


@apply_contract
class AIGatewayRestoreToken(LiveActionExecutor):
    vendor_id = "ai_gateway"
    capability = "restore_token"
    description = "Unblock a virtual key at the gateway."
    requires_credentials = True
    _credential_keys = AI_GATEWAY_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "AI gateway",
            _ai_gateway_client,
            lambda c, t, p: c.unblock_key(t),
            "gateway key unblocked",
        )


@apply_contract
class AIGatewaySetSpendCap(LiveActionExecutor):
    vendor_id = "ai_gateway"
    capability = "set_spend_cap"
    description = (
        "Cap what one gateway key may spend. The softest containment here: it stops the bleeding without breaking a key that is behaving."
    )
    requires_credentials = True
    _credential_keys = AI_GATEWAY_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "AI gateway",
            _ai_gateway_client,
            lambda c, t, p: c.set_max_budget(t, max_budget=float(_require(p, "max_budget"))),
            "spend cap applied to the gateway key",
        )


@apply_contract
class AIGatewayRestoreSpendCap(LiveActionExecutor):
    vendor_id = "ai_gateway"
    capability = "restore_spend_cap"
    description = "Put a gateway key's budget back. The caller supplies the figure; this never guesses what a key used to be allowed."
    requires_credentials = True
    _credential_keys = AI_GATEWAY_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "AI gateway",
            _ai_gateway_client,
            lambda c, t, p: c.set_max_budget(t, max_budget=float(_require(p, "max_budget"))),
            "spend cap restored on the gateway key",
        )


@apply_contract
class AIGatewayGetCloudIdentity(LiveActionExecutor):
    vendor_id = "ai_gateway"
    capability = "get_cloud_identity"
    description = "Gateway key state: blocked, budget and spend to date."
    requires_credentials = True
    _credential_keys = AI_GATEWAY_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "AI gateway",
            _ai_gateway_client,
            lambda c, t, p: c.key_info(t),
            "read gateway key state",
        )


#: Every AI-estate arm, in the order the registry sees them.
AI_ESTATE_EXECUTORS: tuple[type[LiveActionExecutor], ...] = (
    OpenAIRevokeToken,
    OpenAIDemoteRole,
    OpenAIRemoveWorkspaceMember,
    OpenAIGetCloudIdentity,
    AnthropicRevokeToken,
    AnthropicRestoreToken,
    AnthropicDemoteRole,
    AnthropicRemoveWorkspaceMember,
    AnthropicGetCloudIdentity,
    AIGatewayRevokeToken,
    AIGatewayRestoreToken,
    AIGatewaySetSpendCap,
    AIGatewayRestoreSpendCap,
    AIGatewayGetCloudIdentity,
)
