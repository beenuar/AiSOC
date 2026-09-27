"""MCP client for the investigation agent.

Gap-closure Phase 5. An MCP server is third-party code, reached over the
network, whose replies land in the prompt that decides what the agent does
next, so the defaults matter more than the surface: streamable HTTP only, an
empty tool allowlist, a refusal for anything the server annotates as
state-changing, and every result fenced, capped and scanned.

Read ``app/mcp/policy.py`` first. It holds every decision that has to be
taken before a socket opens, which is all of them that matter.
"""

from app.mcp.config import McpServerConfig
from app.mcp.policy import ServerVerdict, ToolVerdict, namespaced, vet_server, vet_tool
from app.mcp.tools import McpToolset, build_mcp_toolset
from app.mcp.untrusted import UntrustedResult, contain_mcp_result

__all__ = [
    "McpServerConfig",
    "McpToolset",
    "ServerVerdict",
    "ToolVerdict",
    "UntrustedResult",
    "build_mcp_toolset",
    "contain_mcp_result",
    "namespaced",
    "vet_server",
    "vet_tool",
]
