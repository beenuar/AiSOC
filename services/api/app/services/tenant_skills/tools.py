"""What tools one tenant's agent can actually reach, and the refusal when a skill names another.

Gap-closure Phase 6.1's validation rule: "validation rejects any expected
pivot that names a tool the tenant does not have".

Three sources, and they are different kinds of fact
----------------------------------------------------
**Built-in pivots** are the lake-backed investigation tools every tenant's
agent binds, listed in ``BUILTIN_PIVOTS``. They are a property of the build,
not of the tenant, which is why they are a constant here rather than a query.

**Customer tools** are Phase 4's typed surface onto the tenant's own SIEM,
EDR, identity provider and cloud audit trail. They are per-tenant and the
answer comes from the same three reads ``GET /agent-tools/backends`` makes, so
the set a skill is validated against is the set the agent will actually bind
rather than a second opinion about it.

**MCP tools** are per-tenant and come from the Phase 5.2 registry: an enabled
server's ``tool_allowlist``, namespaced ``mcp.<server>.<tool>``.

Why the tool names are duplicated rather than imported
-------------------------------------------------------
``services/api`` and ``services/agents`` both package their code as top-level
``app``, so this service cannot import ``app.investigator.strategies`` or
``app.tools.customer_tools``. ``scripts/check_tenant_skill_contract.py``
parses both sides and compares them **in both directions**, because the
one-directional check is the failure shape this repository keeps finding in
its own gates: a tool added in agents and not here would make a legitimate
skill unauthorable, and a tool removed in agents and left here would let a
skill name one that no longer exists and fail at investigation time instead of
at save time. That gate has already earned its keep once, catching six
customer tools Phase 4 added to ``KNOWN_PIVOTS`` while this file was in
flight.

"Could not check" is not "you do not have it"
----------------------------------------------
When the action registry is unreachable, ``available_reads`` cannot say which
vendor verbs this tenant has. Refusing the skill then would tell an author
their EDR is not connected because a different service was briefly down, and
they would delete a correct line from their document. So a *known* customer
tool name is accepted while the registry is unknown and
:attr:`ToolInventory.customer_unknown` says so, which the console surfaces. A
name that is not a customer tool at all is still refused, because that is a
typo rather than an outage. This is the same distinction Phase 4.3 draws for
the prompt: unknown and absent send a reader to different places.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.mcp_server import McpServer
from app.services import actions_client
from app.services.agent_tools import siem_search, vendor_reads
from app.services.tenant_skills.models import SkillParseError, TenantSkill

logger = structlog.get_logger(__name__)

__all__ = [
    "BUILTIN_PIVOTS",
    "CUSTOMER_TOOL_CAPABILITIES",
    "MCP_PREFIX",
    "SIEM_SEARCH_TOOL",
    "ToolInventory",
    "tool_inventory_for_tenant",
    "validate_expected_pivots",
]

#: Every lake-backed investigation tool the agent binds for any tenant. Kept
#: in step with the lake half of ``KNOWN_PIVOTS`` in
#: ``services/agents/app/investigator/strategies.py`` by
#: ``scripts/check_tenant_skill_contract.py``.
BUILTIN_PIVOTS: frozenset[str] = frozenset(
    {
        "process_activity",
        "historical_execution",
        "network_connections",
        "authentication_events",
        "fleet_ioc_hunt",
        "entity_timeline",
        "technique_activity",
        "process_tree",
        "mailbox_activity",
        "oauth_grants",
        "persistence_mechanisms",
    }
)

#: The federated-SIEM tool, bound when the feature is on and the tenant has at
#: least one searchable SIEM connector. Mirrors ``SIEM_SEARCH_TOOL`` in
#: ``services/agents/app/tools/customer_tools.py``.
SIEM_SEARCH_TOOL = "siem_indicator_search"

#: Tool name to the capability the action registry advertises it under.
#: Mirrors ``VENDOR_READ_TOOLS`` in the agents service; the gate compares the
#: names **and** the capabilities in both directions, because a tool whose
#: capability drifted would validate against a verb the tenant does not have.
CUSTOMER_TOOL_CAPABILITIES: dict[str, str] = {
    "edr_host_details": "get_host",
    "edr_host_detections": "get_detections",
    "identity_user_activity": "get_user_activity",
    "cloud_audit_lookup": "lookup_cloud_audit",
    "endpoint_telemetry_sightings": "lookup_endpoint_telemetry",
}

#: The namespace ``app.mcp.policy.namespaced`` produces. A skill names an MCP
#: tool by its namespaced form, because that is the name the model is shown.
MCP_PREFIX = "mcp."


@dataclass(frozen=True)
class ToolInventory:
    """Everything this tenant's agent may be asked to call, by name."""

    builtin: frozenset[str] = BUILTIN_PIVOTS
    customer: frozenset[str] = field(default_factory=frozenset)
    mcp: frozenset[str] = field(default_factory=frozenset)

    #: The action registry could not be asked, so which vendor verbs this
    #: tenant has is unknown rather than empty. A known customer tool name is
    #: accepted while this is true; see the module docstring.
    customer_unknown: bool = False
    customer_unknown_reason: str = ""

    @property
    def names(self) -> frozenset[str]:
        return self.builtin | self.customer | self.mcp

    def as_dict(self) -> dict[str, object]:
        return {
            "builtin": sorted(self.builtin),
            "customer": sorted(self.customer),
            "mcp": sorted(self.mcp),
            "customer_unknown": self.customer_unknown,
            "customer_unknown_reason": self.customer_unknown_reason,
        }


def _namespaced(server: str, tool: str) -> str:
    return f"{MCP_PREFIX}{server}.{tool}"


async def _customer_tools(db: AsyncSession, tenant_id: uuid.UUID) -> tuple[frozenset[str], bool, str]:
    """Which Phase 4 customer tools this tenant has a backend for.

    The same three reads ``GET /agent-tools/backends`` makes, in the same
    order, so the set validated against and the set bound at investigation
    time come from one source rather than two that happen to agree.
    """
    names: set[str] = set()

    if siem_search.feature_enabled():
        # Imported here rather than at module scope: `endpoints.federated`
        # imports the v1 dependency stack, and a service module reaching back
        # into an endpoints module at import time is an import cycle waiting
        # for the next file that needs both. The backends route resolves it
        # the same way.
        from app.api.v1.endpoints.federated import _fetch_target_connectors

        if await _fetch_target_connectors(db, tenant_id, requested_ids=None):
            names.add(SIEM_SEARCH_TOOL)

    try:
        reads = await vendor_reads.available_reads(db, tenant_id=tenant_id)
    except actions_client.ActionsServiceError as exc:
        logger.warning("tenant_skills.registry_unreachable", tenant_id=str(tenant_id))
        return frozenset(names), True, exc.upstream_detail or "the action registry could not be reached"

    capabilities = {entry.as_dict().get("capability") for entry in reads}
    names |= {tool for tool, capability in CUSTOMER_TOOL_CAPABILITIES.items() if capability in capabilities}
    return frozenset(names), False, ""


async def tool_inventory_for_tenant(db: AsyncSession, tenant_id: uuid.UUID) -> ToolInventory:
    """The tenant's tool inventory, read from their own rows and their own registry.

    Only **enabled** MCP servers contribute, and only the tools on their
    allowlist. Both halves matter: a registered-but-disabled server offers
    nothing to an investigation, and an enabled server with an empty allowlist
    offers nothing either, which is the state every newly registered server is
    in. Validating against the registered set instead would let a skill name a
    tool the agent will never be handed.
    """
    rows = (
        await db.execute(
            select(McpServer.name, McpServer.tool_allowlist).where(
                McpServer.tenant_id == tenant_id,
                McpServer.enabled.is_(True),
            )
        )
    ).all()

    mcp: set[str] = set()
    for name, allowlist in rows:
        for tool in allowlist or []:
            if isinstance(tool, str) and tool.strip():
                mcp.add(_namespaced(str(name), tool.strip()))

    customer, unknown, reason = await _customer_tools(db, tenant_id)
    return ToolInventory(
        customer=customer,
        mcp=frozenset(mcp),
        customer_unknown=unknown,
        customer_unknown_reason=reason,
    )


#: Every customer tool name that exists in the build, whether or not any given
#: tenant has its backend. Used only to tell a typo from an outage.
_ALL_CUSTOMER_TOOLS: frozenset[str] = frozenset({SIEM_SEARCH_TOOL, *CUSTOMER_TOOL_CAPABILITIES})


def validate_expected_pivots(skill: TenantSkill, inventory: ToolInventory) -> None:
    """Refuse a skill naming a tool this tenant's agent cannot call.

    The message names the pivot and says which of the three reasons applies,
    because the author's next action differs completely between "you typed the
    name wrong", "you have to connect that product first" and "you have to
    allowlist that tool on that server first".
    """
    unknown = [p for p in skill.expected_pivots if p not in inventory.names]
    if not unknown:
        return

    lines: list[str] = []
    for pivot in unknown:
        if pivot.startswith(MCP_PREFIX):
            lines.append(
                f"{pivot!r}: no enabled MCP server in this tenant allowlists that tool. "
                f"Register the server, enable it, and add the tool to its allowlist first."
            )
        elif pivot in _ALL_CUSTOMER_TOOLS:
            if inventory.customer_unknown:
                # Reachable only if a caller built an inventory by hand; the
                # loop below skips these when the registry is unknown.
                continue
            lines.append(
                f"{pivot!r}: this tenant has no connected product behind that tool. "
                f"Connect the SIEM, EDR, identity provider or cloud audit source it reads, then save again."
            )
        else:
            lines.append(
                f"{pivot!r}: not a tool this deployment has. "
                f"Built-in tools are {', '.join(sorted(inventory.builtin))}. "
                f"The customer-product tools are {', '.join(sorted(_ALL_CUSTOMER_TOOLS))}. "
                f"A tool on a third-party MCP server is named 'mcp.<server>.<tool>'."
            )

    if not lines:
        return
    raise SkillParseError(
        "'expected_pivots' names "
        + ("a tool" if len(lines) == 1 else f"{len(lines)} tools")
        + " this tenant's agent cannot call:\n  "
        + "\n  ".join(lines)
    )
