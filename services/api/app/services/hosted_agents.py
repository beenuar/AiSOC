"""Inventory agents configured in a provider's own control plane.

Depth plan wave 2, Phase 7.2.

What a hosted agent is, and why it is a distinct asset kind
-----------------------------------------------------------
A reusable, versioned configuration held by the provider: a model, a system
prompt, a tool list, a set of MCP servers and a set of skills. It runs on the
provider's infrastructure, so there is no laptop to isolate and no process to
kill — which is exactly why it must not be scored as a coding agent with a
missing device. `DEVICELESS_KINDS` carries that distinction and `score_risk`
reads it, so the rule lives in one place.

It is also the asset most likely to be invisible to every other discovery
path this platform has. Endpoint telemetry never sees it. Gateway telemetry
sees its traffic without knowing what it was configured to do. The only way
to learn that an agent exists, holds `execute_command`, and points at three
MCP servers nobody reviewed, is to ask the provider's admin API.

Vendor reference
----------------
`GET /v1/agents`, beta header `managed-agents-2026-04-01`, query parameters
`limit`, `page`, `include_archived` and `created_at[gte]`. Configuration
fields `name`, `model`, `system`, `tools`, `mcp_servers`, `skills`,
`multiagent`, `description`, `metadata`. Read from pages that each returned
200 before this was written:

* https://platform.claude.com/docs/en/api/beta/agents/list
* https://platform.claude.com/docs/en/managed-agents/agent-setup

Read-only, which the plan requires of this phase
-------------------------------------------------
There is no create, update or archive method here. The vendor offers all
three; an inventory that can reconfigure a customer's agents is a different
risk conversation and nothing in Phase 7.2 needs it. Changing a hosted
agent's state belongs to the governed action path in `services/actions` with
a capability contract, which is Phase 7.5's work and not this module's.

The system prompt is read and not stored
-----------------------------------------
`system` is the agent's instructions, and it is attacker-reachable in
exactly the way a repository instruction file is: whoever can call the
provider's update endpoint can change what the agent is told. So it goes
through the same capture-time scan as a repository artefact and only the
matched *pattern names* are kept. Storing the prompt would put a copy of
somebody's instructions — potentially a payload — in a table the console
renders.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

import httpx
import structlog

from app._vendor.ai_instruction_rules import scan_instruction_text

logger = structlog.get_logger()

BASE_URL = "https://api.anthropic.com/v1"
API_VERSION = "2023-06-01"
BETA_HEADER = "managed-agents-2026-04-01"

_PAGE = 100


@dataclass(frozen=True)
class HostedAgent:
    """One provider-hosted agent, ready to become an AI asset."""

    external_id: str
    name: str
    model: str | None
    owner: str | None
    tools: tuple[str, ...]
    mcp_servers: tuple[dict[str, Any], ...]
    skills: tuple[dict[str, Any], ...]
    #: Pattern names only. Never the system prompt.
    injection_signals: tuple[str, ...]

    def attributes(self) -> dict[str, Any]:
        """The `attributes` blob for `aisoc_ai_assets`.

        Keys match what `score_risk` already reads — `tools`,
        `mcp_servers`, `skills`, `injection_signals` — so the single
        scorer needs no special case for this producer either.
        """
        out: dict[str, Any] = {"model": self.model} if self.model else {}
        if self.tools:
            out["tools"] = list(self.tools)
        if self.mcp_servers:
            out["mcp_servers"] = [dict(s) for s in self.mcp_servers]
        if self.skills:
            out["skills"] = [dict(s) for s in self.skills]
        if self.injection_signals:
            out["injection_signals"] = list(self.injection_signals)
        return out


def _model_id(value: Any) -> str | None:
    """`model` is a string or an object; the vendor documents both."""
    if isinstance(value, str):
        return value or None
    if isinstance(value, dict):
        ident = value.get("id")
        return str(ident) if ident else None
    return None


def _tool_names(value: Any) -> tuple[str, ...]:
    """Tool names out of a list that mixes strings and objects.

    The vendor's `tools` combines pre-built tools, MCP tools and custom
    tools, and they are not all the same shape. A reader that handled only
    strings would report an agent holding `execute_command` as holding
    nothing, which is the direction that matters.
    """
    names: set[str] = set()
    for entry in value if isinstance(value, list) else []:
        if isinstance(entry, str) and entry:
            names.add(entry)
        elif isinstance(entry, dict):
            name = entry.get("name") or entry.get("type")
            if name:
                names.add(str(name))
    return tuple(sorted(names))


#: Hosts whose MCP servers come from a reviewed origin. The provider's own
#: domain qualifies because the provider is already the trust root for the
#: agent; everything else is somebody's server until a human says otherwise,
#: and a server with no URL at all is the least reviewable of the three.
_VETTED_SERVER_HOSTS = frozenset({"api.anthropic.com", "mcp.anthropic.com"})


def _server_source(url: str) -> str:
    """The value `score_risk` compares against `VETTED_MCP_SOURCES`."""
    if not url:
        return "unknown"
    host = re.sub(r"^https?://", "", url).split("/")[0].split(":")[0].lower()
    return "vendor" if host in _VETTED_SERVER_HOSTS else "remote"


def _servers(value: Any) -> tuple[dict[str, Any], ...]:
    out: list[dict[str, Any]] = []
    for entry in value if isinstance(value, list) else []:
        if not isinstance(entry, dict):
            continue
        url = str(entry.get("url") or "")
        out.append(
            {
                "name": str(entry.get("name") or entry.get("server_label") or "unnamed")[:120],
                "url": url[:300] or None,
                "source": _server_source(url),
            }
        )
    return tuple(out)


def _skills(value: Any) -> tuple[dict[str, Any], ...]:
    out: list[dict[str, Any]] = []
    for entry in value if isinstance(value, list) else []:
        if isinstance(entry, str):
            out.append({"name": entry[:120], "pinned_revision": None})
        elif isinstance(entry, dict):
            out.append(
                {
                    "name": str(entry.get("name") or entry.get("skill_id") or "unnamed")[:120],
                    # A skill referenced without a version is one whose
                    # content can change under the agent with no review.
                    "pinned_revision": entry.get("version") or entry.get("revision"),
                }
            )
    return tuple(out)


def to_hosted_agent(record: dict[str, Any]) -> HostedAgent | None:
    """One `GET /v1/agents` record as an asset-ready value."""
    external_id = str(record.get("id") or "")
    if not external_id:
        return None
    raw_metadata = record.get("metadata")
    metadata: dict[str, Any] = raw_metadata if isinstance(raw_metadata, dict) else {}
    owner = metadata.get("owner") or metadata.get("owner_email") or record.get("created_by")
    return HostedAgent(
        external_id=external_id,
        name=str(record.get("name") or external_id)[:200],
        model=_model_id(record.get("model")),
        owner=str(owner)[:320] if owner else None,
        tools=_tool_names(record.get("tools")),
        mcp_servers=_servers(record.get("mcp_servers")),
        skills=_skills(record.get("skills")),
        injection_signals=scan_instruction_text(str(record.get("system") or "")),
    )


class HostedAgentClient:
    """Read-only list of a provider's hosted agents."""

    def __init__(
        self,
        admin_key: str,
        *,
        base_url: str = BASE_URL,
        timeout: float = 30.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._key = admin_key
        self._base = base_url.rstrip("/")
        self._timeout = timeout
        self._transport = transport

    def _headers(self) -> dict[str, str]:
        return {
            "x-api-key": self._key,
            "anthropic-version": API_VERSION,
            # Omitting this is a 4xx the vendor would return and a mock
            # would not, which is why the test asserts the header.
            "anthropic-beta": BETA_HEADER,
            "Accept": "application/json",
        }

    async def list_agents(self, *, include_archived: bool = False, pages: int = 10) -> list[HostedAgent]:
        """Every agent, following the cursor to a bound.

        Archived agents are excluded by default because they cannot run; an
        operator auditing what *could* act wants the live set, and the flag
        is there for the one who is auditing history instead.
        """
        out: list[HostedAgent] = []
        page: str | None = None
        async with httpx.AsyncClient(timeout=self._timeout, transport=self._transport) as client:
            for _ in range(pages):
                params: dict[str, Any] = {"limit": _PAGE}
                if include_archived:
                    params["include_archived"] = "true"
                if page:
                    params["page"] = page
                resp = await client.get(f"{self._base}/agents", headers=self._headers(), params=params)
                resp.raise_for_status()
                body = resp.json()
                if not isinstance(body, dict):
                    break
                for record in body.get("data") or []:
                    if isinstance(record, dict):
                        agent = to_hosted_agent(record)
                        if agent is not None:
                            out.append(agent)
                if not body.get("has_more"):
                    break
                page = body.get("next_page") or body.get("last_id")
                if not page:
                    break
        return out
