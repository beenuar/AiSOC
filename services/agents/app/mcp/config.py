"""One resolved MCP server, as the agents service holds it.

Gap-closure Phase 5.2, agents half. The registry lives in ``services/api``
because that service owns the vault and the tenant session. This is the shape
that crosses the internal network, which is deliberately not the database row:
it carries no id for a table this service cannot write to, and it carries the
bounds rather than the defaults, so a tenant that narrowed a timeout is
narrowed here too.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

__all__ = ["McpServerConfig", "server_configs_from_payload"]

#: Clamped even though the API validates. Two services, two chances for the
#: shape to drift, and the one that opens the socket is the one that has to
#: hold the bound.
_MIN_TIMEOUT_S = 1.0
_MAX_TIMEOUT_S = 120.0
_MIN_RESPONSE_BYTES = 1024
_MAX_RESPONSE_BYTES = 1048576


@dataclass(frozen=True)
class McpServerConfig:
    name: str
    transport: str = "streamable_http"
    url: str | None = None
    command: str | None = None
    args: list[str] = field(default_factory=list)
    #: Header name to header value. Already decrypted; never logged.
    auth: dict[str, str] = field(default_factory=dict)
    tool_allowlist: list[str] = field(default_factory=list)
    timeout_seconds: float = 20.0
    max_response_bytes: int = 65536

    def headers(self) -> dict[str, str]:
        """Auth headers for the transport, with non-string values dropped.

        ``Authorization`` is the common case; a vendor wanting ``X-Api-Key``
        stores that key instead. Nothing here invents a scheme, because
        guessing ``Bearer`` for a value that already carried one produces
        ``Bearer Bearer abc`` and a 401 the operator cannot see the cause of.
        """
        return {str(k): str(v) for k, v in (self.auth or {}).items() if isinstance(v, str | int | float) and str(k).strip()}

    def redacted(self) -> dict[str, Any]:
        """Safe to log and safe to put in the ledger: names, never values."""
        return {
            "name": self.name,
            "transport": self.transport,
            "url": self.url,
            "command": self.command,
            "tool_allowlist": list(self.tool_allowlist),
            "timeout_seconds": self.timeout_seconds,
            "max_response_bytes": self.max_response_bytes,
            "auth_headers": sorted(self.headers()),
        }


def _clamp(value: Any, low: float, high: float, fallback: float) -> float:
    try:
        return max(low, min(high, float(value)))
    except (TypeError, ValueError):
        return fallback


def server_configs_from_payload(payload: Any) -> list[McpServerConfig]:
    """Parse the API's ``/mcp-servers/resolved`` body.

    A malformed entry is skipped rather than defaulted into existence: a
    server with no name is not a server, and inventing one would put a tool
    called ``mcp..something`` in front of the model.
    """
    servers = payload.get("servers") if isinstance(payload, dict) else None
    if not isinstance(servers, list):
        return []
    configs: list[McpServerConfig] = []
    for entry in servers:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name") or "").strip()
        if not name:
            continue
        auth = entry.get("auth")
        configs.append(
            McpServerConfig(
                name=name,
                transport=str(entry.get("transport") or "streamable_http"),
                url=(str(entry["url"]).strip() if entry.get("url") else None),
                command=(str(entry["command"]).strip() if entry.get("command") else None),
                args=[str(a) for a in (entry.get("args") or [])],
                auth={str(k): str(v) for k, v in auth.items()} if isinstance(auth, dict) else {},
                tool_allowlist=[str(t) for t in (entry.get("tool_allowlist") or [])],
                timeout_seconds=_clamp(entry.get("timeout_seconds"), _MIN_TIMEOUT_S, _MAX_TIMEOUT_S, 20.0),
                max_response_bytes=int(_clamp(entry.get("max_response_bytes"), _MIN_RESPONSE_BYTES, _MAX_RESPONSE_BYTES, 65536)),
            )
        )
    return configs
