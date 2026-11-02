"""Tool registry for LLM tool-calling (Wave 4a).

Until now no agent used LLM tool-calling: tools were hardcoded Python calls the
code decided to make, and the model only returned a JSON verdict. This registry
exposes AiSOC's real tools (IOC enrichment, MITRE lookup, IOC/technique
extraction, graph blast-radius) as OpenAI-style function schemas so an LLM can
*choose* which to call, and executes the model's selected calls safely.

Design:
* Each ``Tool`` carries a JSON-schema ``parameters`` block (what ``bind_tools``
  ships to the provider) and a callable (sync or async).
* ``execute`` is fail-soft: an unknown tool or a raising tool returns a
  structured ``{"error": ...}`` the model can react to, never an exception that
  aborts the loop.
* ``execute`` is also the **one chokepoint every tool call passes through**,
  which is why wave-2 7.3 puts the scope check here rather than in each
  agent. A check an agent performs on itself is a check a steered agent can
  be talked out of.

Identity is required, not optional
----------------------------------
``execute`` refuses a call that names no identity. An optional identity
defaulting to "allow" would leave every existing call site working and the
control protecting nothing — which is exactly the shape of the eleven routes
that carried ``Annotated[Any, require_permission("x:write")]`` with no
``Depends()``, read as gated, and enforced nothing.
"""

from __future__ import annotations

import inspect
import logging
from collections.abc import Callable
from typing import Any

from app.security.agent_identity import AgentIdentity, ScopeDenied

# Re-exported so every existing `from app.tools.registry import Tool`
# keeps working. The dataclass moved to its own module to break the
# registry -> customer_tools -> registry import cycle; see tool.py.
from app.tools.tool import Tool

logger = logging.getLogger(__name__)

__all__ = ["Tool", "ToolRegistry", "default_registry"]


class ToolRegistry:
    def __init__(self, tools: list[Tool] | None = None) -> None:
        self._tools: dict[str, Tool] = {}
        #: Called with one row per tool call, allowed or denied. Settable so
        #: a deployment can route it at the ledger and a test can read it;
        #: defaults to the module logger so the rows exist on every
        #: deployment rather than only on the ones that wired a sink.
        self.audit_sink: Callable[[dict[str, Any]], None] = _log_audit_row
        for tool in tools or []:
            self.register(tool)

    def _audit(self, row: dict[str, Any]) -> None:
        """Record one call. A sink failure must not take the run with it.

        The inverse coupling — losing the tool result because the audit
        sink was down — turns an observability outage into an outage.
        """
        try:
            self.audit_sink(row)
        except Exception:  # noqa: BLE001 — see the docstring
            logger.warning("agent tool audit sink failed; the call itself was unaffected", exc_info=True)

    def register(self, tool: Tool) -> None:
        self._tools[tool.name] = tool

    def names(self) -> list[str]:
        return sorted(self._tools)

    def openai_schemas(self) -> list[dict[str, Any]]:
        return [t.openai_schema() for t in self._tools.values()]

    async def execute(self, name: str, args: dict[str, Any], *, identity: AgentIdentity | None = None) -> Any:
        """Run one tool for one identity, or refuse and say why.

        The refusals are structured errors rather than exceptions because
        the loop's contract is that a tool failure reaches the model
        instead of aborting the run. They are worded so an operator reading
        the ledger can tell a denial from a tool that broke — "outside the
        scope of agent 'triage'" and "TypeError" send you to different
        places.
        """
        if identity is None:
            # Default-deny. See the module docstring: an optional identity
            # that defaults to allow is a control that protects nothing.
            self._audit({"agent": None, "tool": name, "allowed": False, "reason": "no identity"})
            return {"error": f"refusing to run {name!r}: no agent identity was supplied"}
        # Existence before scope, deliberately. A tool nothing registered
        # cannot run either way, and "unknown tool" sends a reader to the
        # registration that is missing while "outside the scope of agent
        # 'investigation'" sends them to a scope table that is correct.
        #
        # The MCP path makes this concrete: `app/mcp/policy.py` refuses a
        # destructive tool by never registering it, so that refusal is the
        # one an operator should see. No oracle is leaked by the ordering —
        # the registry's schemas are shipped to the model already.
        tool = self._tools.get(name)
        if tool is None:
            self._audit(identity.audit_row(name, allowed=False, reason="unknown tool"))
            return {"error": f"unknown tool: {name}"}

        try:
            identity.require(name)
        except ScopeDenied as denied:
            self._audit(identity.audit_row(name, allowed=False, reason=str(denied)))
            return {"error": str(denied)}

        self._audit(identity.audit_row(name, allowed=True))
        try:
            result = tool.fn(**(args or {}))
            if inspect.isawaitable(result):
                result = await result
            return result
        except Exception as exc:  # noqa: BLE001 — surface tool failure to the model, don't abort
            return {"error": f"{type(exc).__name__}: {exc}"}


def _log_audit_row(row: dict[str, Any]) -> None:
    """Default sink: the service log, so the rows exist everywhere.

    A sink that defaulted to discarding would make "visible in the audit
    log" true only on deployments that wired one, which is the same as not
    true.
    """
    logger.info("agent tool call", extra={"agent_tool_call": row})


def _str_param(name: str, desc: str) -> dict[str, Any]:
    return {"type": "object", "properties": {name: {"type": "string", "description": desc}}, "required": [name]}


def default_registry(tenant_id: str = "") -> ToolRegistry:
    """Registry of AiSOC's real analyst tools, wrapped for LLM tool-calling.

    ``tenant_id`` is the run's own. The sandbox lookup reaches the API, which
    refuses a service credential that does not name the tenant it acts for.
    """
    from app.investigator.tools import enrich_ioc, extract_iocs, map_to_mitre
    from app.tools.customer_tools import (
        CHANGES_BEFORE_DESCRIPTION,
        CHANGES_BEFORE_PARAMETERS,
        CHANGES_BEFORE_TOOL,
        EFFECTIVE_PERMISSIONS_DESCRIPTION,
        EFFECTIVE_PERMISSIONS_PARAMETERS,
        EFFECTIVE_PERMISSIONS_TOOL,
        changes_before_alert,
        identity_effective_permissions,
    )
    from app.tools.mitre import lookup_technique
    from app.tools.sandbox import TOOL_DESCRIPTION, TOOL_NAME, TOOL_PARAMETERS, lookup_file_hash

    return ToolRegistry(
        [
            Tool(
                name=TOOL_NAME,
                description=TOOL_DESCRIPTION,
                parameters=TOOL_PARAMETERS,
                fn=lambda sha256: lookup_file_hash(sha256, tenant_id=tenant_id),
            ),
            # Registered unconditionally, unlike the customer tools in
            # `scoped_customer_tools`, which are bound only when the tenant
            # has a backend for them. The difference is deliberate: a
            # customer tool with no backend answers `no_integration` and is
            # noise, whereas this one answers "unknown, and here is why" —
            # which is a sentence the model needs to be able to reach.
            Tool(
                name=EFFECTIVE_PERMISSIONS_TOOL,
                description=EFFECTIVE_PERMISSIONS_DESCRIPTION,
                parameters=EFFECTIVE_PERMISSIONS_PARAMETERS,
                fn=lambda principal_id, at="", provider="": identity_effective_permissions(
                    principal_id, at=at, provider=provider, tenant_id=tenant_id
                ),
            ),
            # Depth 2 wave 2, 1.5. Registered beside the privilege tool
            # because the two answer halves of one question: what this
            # identity could do, and what changed shortly before it did.
            Tool(
                name=CHANGES_BEFORE_TOOL,
                description=CHANGES_BEFORE_DESCRIPTION,
                parameters=CHANGES_BEFORE_PARAMETERS,
                fn=lambda subjects, at="", days=7: changes_before_alert(subjects, at=at, days=days, tenant_id=tenant_id),
            ),
            Tool(
                name="extract_iocs",
                description="Extract IOCs (IPs, domains, hashes, URLs) from free text.",
                parameters=_str_param("text", "The text to scan for indicators of compromise."),
                fn=lambda text: extract_iocs(text),
            ),
            Tool(
                name="map_to_mitre",
                description="Map free text describing behaviour to MITRE ATT&CK technique IDs.",
                parameters=_str_param("text", "The behaviour description to map to ATT&CK techniques."),
                fn=lambda text: map_to_mitre(text),
            ),
            Tool(
                name="lookup_technique",
                description="Look up a MITRE ATT&CK technique by ID (e.g. T1110).",
                parameters=_str_param("technique_id", "The ATT&CK technique ID, e.g. T1059.001."),
                fn=lambda technique_id: lookup_technique(technique_id),
            ),
            Tool(
                name="enrich_ioc",
                description="Enrich a single IOC (ip|domain|hash|url) with threat intelligence.",
                parameters={
                    "type": "object",
                    "properties": {
                        "ioc_value": {"type": "string", "description": "The IOC value."},
                        "ioc_type": {"type": "string", "enum": ["ip", "domain", "hash", "url"]},
                    },
                    "required": ["ioc_value", "ioc_type"],
                },
                fn=lambda ioc_value, ioc_type: enrich_ioc(ioc_value, ioc_type),
            ),
        ]
    )
