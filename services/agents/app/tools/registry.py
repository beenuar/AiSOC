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
"""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    parameters: dict[str, Any]  # JSON schema for the arguments
    fn: Callable[..., Any] | Callable[..., Awaitable[Any]]

    def openai_schema(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {"name": self.name, "description": self.description, "parameters": self.parameters},
        }


class ToolRegistry:
    def __init__(self, tools: list[Tool] | None = None) -> None:
        self._tools: dict[str, Tool] = {}
        for tool in tools or []:
            self.register(tool)

    def register(self, tool: Tool) -> None:
        self._tools[tool.name] = tool

    def names(self) -> list[str]:
        return sorted(self._tools)

    def openai_schemas(self) -> list[dict[str, Any]]:
        return [t.openai_schema() for t in self._tools.values()]

    async def execute(self, name: str, args: dict[str, Any]) -> Any:
        tool = self._tools.get(name)
        if tool is None:
            return {"error": f"unknown tool: {name}"}
        try:
            result = tool.fn(**(args or {}))
            if inspect.isawaitable(result):
                result = await result
            return result
        except Exception as exc:  # noqa: BLE001 — surface tool failure to the model, don't abort
            return {"error": f"{type(exc).__name__}: {exc}"}


def _str_param(name: str, desc: str) -> dict[str, Any]:
    return {"type": "object", "properties": {name: {"type": "string", "description": desc}}, "required": [name]}


def default_registry() -> ToolRegistry:
    """Registry of AiSOC's real analyst tools, wrapped for LLM tool-calling."""
    from app.investigator.tools import enrich_ioc, extract_iocs, map_to_mitre
    from app.tools.mitre import lookup_technique

    return ToolRegistry(
        [
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
