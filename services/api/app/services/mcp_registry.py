"""The per-tenant MCP server registry: what is stored, and what is refused.

Gap-closure Phase 5.2. Read ``migrations/069_mcp_servers.sql`` for why each
bound exists; this module is the half that decides whether a row may be
written at all, and the half that hands a resolved configuration to the
agents service.

Two checks, two places, on purpose
----------------------------------
:func:`validate_target` runs here, at save time, and is **structural**:
scheme, userinfo, hostname shape, IP literals, the cloud-metadata blocklist,
and the air-gap policy. It deliberately does not resolve DNS.

The enforcing check is in the agents service, immediately before the socket
is opened, through ``app.playbook.ssrf_guard.validate_outbound_url``. That is
where it has to be: a name that resolved to a public address when an operator
pressed save can resolve to ``169.254.169.254`` an hour later, so a
resolution performed at save time proves nothing about the request that
eventually goes out. Doing it here as well would read like the real control
and would age into a false one.

So this is the fast, readable refusal an operator sees in the console, and
the agents service holds the control. ``test_mcp_registry.py`` asserts the
structural half; ``services/agents/tests/test_mcp_client.py`` asserts the
agents service refuses before connecting.

Credential storage
------------------
``auth_config`` is ``CredentialVault`` ciphertext under the same convention
connector credentials use. It is never returned to a console caller; only the
service-token path gets plaintext, and only for the tenant it named.
"""

from __future__ import annotations

import ipaddress
import re
import uuid
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.airgap import AirgapViolation, enforce_airgap_for_url
from app.models.mcp_server import MCP_TRANSPORTS, McpServer
from app.security.credential_vault import get_vault

logger = structlog.get_logger()

__all__ = [
    "DEFAULT_MAX_RESPONSE_BYTES",
    "DEFAULT_TIMEOUT_SECONDS",
    "MCP_TRANSPORTS",
    "McpRegistryError",
    "ResolvedMcpServer",
    "SERVER_NAME_RE",
    "TOOL_NAME_RE",
    "create_server",
    "delete_server",
    "list_servers",
    "resolve_servers_for_agent",
    "update_server",
    "validate_target",
]

#: Mirrors the CHECK constraint in 069. Kept here as well so the refusal is a
#: 422 naming the shape rather than a database error naming a constraint.
SERVER_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,38}[a-z0-9]$")

#: A tool name as an MCP server may publish it. Wider than the server name,
#: because this one is the vendor's choice rather than the operator's, and
#: narrow enough that it cannot carry a path separator or prompt punctuation
#: into the namespaced id the model is shown.
TOOL_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")

DEFAULT_TIMEOUT_SECONDS = 20
DEFAULT_MAX_RESPONSE_BYTES = 65536

#: Hosts an MCP server URL may never name, whatever DNS says. Same list the
#: playbook SSRF guard carries, duplicated rather than imported because the
#: API service cannot import the agents package: they ship as separate
#: containers. The agents-side guard is the enforcing copy.
_BLOCKED_HOSTS: frozenset[str] = frozenset(
    {
        "169.254.169.254",
        "metadata.google.internal",
        "metadata",
        "metadata.azure.com",
        "100.100.100.200",
        "169.254.169.254.nip.io",
    }
)


class McpRegistryError(ValueError):
    """A registry row was refused. The message is shown to the operator."""


@dataclass(frozen=True)
class ResolvedMcpServer:
    """One enabled server, with its credential decrypted, for the agents service.

    This crosses the internal network, so it carries exactly what the client
    needs and nothing else. In particular it carries no database id for a row
    the agents service cannot write to.
    """

    name: str
    transport: str
    url: str | None
    command: str | None
    args: list[str]
    auth: dict[str, Any]
    tool_allowlist: list[str]
    timeout_seconds: int
    max_response_bytes: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "transport": self.transport,
            "url": self.url,
            "command": self.command,
            "args": list(self.args),
            "auth": dict(self.auth),
            "tool_allowlist": list(self.tool_allowlist),
            "timeout_seconds": self.timeout_seconds,
            "max_response_bytes": self.max_response_bytes,
        }


def validate_target(
    *,
    transport: str,
    url: str | None,
    command: str | None,
) -> None:
    """Refuse a target that could never be safe, before it reaches the table.

    Structural only. See the module docstring for why DNS resolution is the
    agents service's job and not this one's.
    """
    if transport not in MCP_TRANSPORTS:
        raise McpRegistryError(f"transport must be one of {', '.join(MCP_TRANSPORTS)}")

    if transport == "stdio":
        if not (command or "").strip():
            raise McpRegistryError("a stdio server needs a command")
        if url:
            raise McpRegistryError("a stdio server has no URL; set transport to streamable_http to use one")
        # Nothing further is decided here. Whether this command may run at all
        # is the agents service's call, against an operator-supplied allowlist
        # that this service cannot see.
        return

    if command:
        raise McpRegistryError("a streamable_http server has no command; set transport to stdio to use one")
    candidate = (url or "").strip()
    if not candidate:
        raise McpRegistryError("a streamable_http server needs a URL")

    try:
        parts = urlsplit(candidate)
    except ValueError as exc:
        raise McpRegistryError(f"could not parse the URL: {exc}") from exc

    scheme = (parts.scheme or "").lower()
    if scheme not in {"http", "https"}:
        raise McpRegistryError(f"scheme {scheme or '(none)'!r} is not allowed; MCP servers are reached over http or https")
    if parts.username or parts.password:
        raise McpRegistryError("the URL must not carry userinfo (user:password@host); put the credential in the credential field")

    host = (parts.hostname or "").strip().lower()
    if not host:
        raise McpRegistryError("the URL has no hostname")
    if host in _BLOCKED_HOSTS:
        raise McpRegistryError(f"{host!r} is a cloud metadata endpoint and is never reachable from AiSOC")

    literal = _as_ip(host)
    if literal is not None and any(
        (literal.is_loopback, literal.is_link_local, literal.is_multicast, literal.is_reserved, literal.is_unspecified)
    ):
        raise McpRegistryError(f"{host} is not an address AiSOC will reach")

    try:
        enforce_airgap_for_url(candidate)
    except AirgapViolation as exc:
        raise McpRegistryError(str(exc)) from exc


def _as_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _validate_allowlist(tool_allowlist: list[str] | None) -> list[str]:
    """An allowlist entry names one tool on one server.

    Refused rather than trimmed: an entry that does not match is a typo, and a
    silently dropped typo is an allowlist an operator believes is wider than
    it is, which is the failure direction that matters here.
    """
    entries = list(tool_allowlist or [])
    if len(entries) > 200:
        raise McpRegistryError("a tool allowlist of more than 200 entries is a server, not a list")
    cleaned: list[str] = []
    for entry in entries:
        candidate = entry.strip() if isinstance(entry, str) else ""
        if not TOOL_NAME_RE.match(candidate):
            raise McpRegistryError(
                f"{entry!r} is not a tool name; names are up to 64 characters of letters, digits, dot, dash or underscore"
            )
        cleaned.append(candidate)
    # Order preserved, duplicates dropped. An allowlist is a set; keeping the
    # operator's order makes the console read back the way it was typed.
    seen: set[str] = set()
    unique: list[str] = []
    for entry_name in cleaned:
        if entry_name not in seen:
            seen.add(entry_name)
            unique.append(entry_name)
    return unique


def _validate_bounds(timeout_seconds: int, max_response_bytes: int) -> None:
    if not 1 <= timeout_seconds <= 120:
        raise McpRegistryError("timeout_seconds must be between 1 and 120")
    if not 1024 <= max_response_bytes <= 1048576:
        raise McpRegistryError("max_response_bytes must be between 1024 and 1048576")


async def list_servers(db: AsyncSession, tenant_id: uuid.UUID) -> list[McpServer]:
    """Every registered server for one tenant.

    The tenant predicate is in the WHERE clause as well as in RLS: the
    query layer is the control this repository enforces, and RLS is the
    defence in depth behind it.
    """
    result = await db.execute(select(McpServer).where(McpServer.tenant_id == tenant_id).order_by(McpServer.name))
    return list(result.scalars().all())


async def create_server(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    created_by: uuid.UUID | None,
    name: str,
    label: str | None = None,
    transport: str = "streamable_http",
    url: str | None = None,
    command: str | None = None,
    args: list[str] | None = None,
    credential: dict[str, Any] | None = None,
    tool_allowlist: list[str] | None = None,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    enabled: bool = False,
) -> McpServer:
    """Register a server. Disabled and with an empty allowlist unless asked otherwise."""
    slug = (name or "").strip().lower()
    if not SERVER_NAME_RE.match(slug):
        raise McpRegistryError(
            "name must be 2 to 40 characters of lowercase letters, digits, dash or underscore, "
            "starting and ending with a letter or digit: it becomes part of the tool name the model sees"
        )
    validate_target(transport=transport, url=url, command=command)
    allowlist = _validate_allowlist(tool_allowlist)
    _validate_bounds(timeout_seconds, max_response_bytes)

    existing = await db.execute(select(McpServer.id).where(McpServer.tenant_id == tenant_id, McpServer.name == slug))
    if existing.scalar_one_or_none() is not None:
        raise McpRegistryError(f"a server named {slug!r} is already registered for this tenant")

    row = McpServer(
        tenant_id=tenant_id,
        created_by=created_by,
        name=slug,
        label=(label or "").strip() or None,
        transport=transport,
        url=(url or "").strip() or None,
        command=(command or "").strip() or None,
        args=[str(a) for a in (args or [])],
        auth_config=get_vault().encrypt_dict(credential or {}),
        tool_allowlist=allowlist,
        timeout_seconds=timeout_seconds,
        max_response_bytes=max_response_bytes,
        enabled=enabled,
    )
    db.add(row)
    await db.flush()
    logger.info("mcp_registry.created", tenant_id=str(tenant_id), name=slug, transport=transport, enabled=enabled)
    return row


async def update_server(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    server_id: uuid.UUID,
    changes: dict[str, Any],
) -> McpServer:
    """Apply a partial update. Absent keys are left alone; ``credential`` re-encrypts."""
    result = await db.execute(select(McpServer).where(McpServer.id == server_id, McpServer.tenant_id == tenant_id))
    row = result.scalar_one_or_none()
    if row is None:
        raise McpRegistryError("no such MCP server for this tenant")

    transport = changes.get("transport", row.transport)
    url = changes.get("url", row.url)
    command = changes.get("command", row.command)
    # Switching transport clears the other transport's target rather than
    # leaving a stale one behind for the CHECK constraint to reject.
    if "transport" in changes and changes["transport"] != row.transport:
        if changes["transport"] == "stdio":
            url = changes.get("url")
        else:
            command = changes.get("command")
    validate_target(transport=transport, url=url, command=command)

    if "tool_allowlist" in changes:
        row.tool_allowlist = _validate_allowlist(changes["tool_allowlist"])
    timeout_seconds = int(changes.get("timeout_seconds", row.timeout_seconds))
    max_response_bytes = int(changes.get("max_response_bytes", row.max_response_bytes))
    _validate_bounds(timeout_seconds, max_response_bytes)

    row.transport = transport
    row.url = (url or "").strip() or None
    row.command = (command or "").strip() or None
    row.timeout_seconds = timeout_seconds
    row.max_response_bytes = max_response_bytes
    if "label" in changes:
        row.label = (changes["label"] or "").strip() or None
    if "args" in changes:
        row.args = [str(a) for a in (changes["args"] or [])]
    if "enabled" in changes:
        row.enabled = bool(changes["enabled"])
    if changes.get("credential") is not None:
        row.auth_config = get_vault().encrypt_dict(changes["credential"])

    await db.flush()
    logger.info("mcp_registry.updated", tenant_id=str(tenant_id), name=row.name, fields=sorted(changes))
    return row


async def delete_server(db: AsyncSession, *, tenant_id: uuid.UUID, server_id: uuid.UUID) -> bool:
    result = await db.execute(select(McpServer).where(McpServer.id == server_id, McpServer.tenant_id == tenant_id))
    row = result.scalar_one_or_none()
    if row is None:
        return False
    await db.delete(row)
    await db.flush()
    logger.info("mcp_registry.deleted", tenant_id=str(tenant_id), name=row.name)
    return True


async def resolve_servers_for_agent(db: AsyncSession, tenant_id: uuid.UUID) -> list[ResolvedMcpServer]:
    """Enabled servers, credentials decrypted, for the agents service.

    Only enabled rows. A registered-but-disabled server is a note an operator
    made, not a thing an investigation may reach, and returning it here would
    make ``enabled`` a console decoration.

    A row whose credential will not decrypt is **dropped with a warning**
    rather than returned with an empty credential. Returning it would produce
    an unauthenticated call to a third party that the operator believes is
    authenticated, and the vendor's 401 would read to the agent as "that tool
    is unavailable".
    """
    result = await db.execute(
        select(McpServer).where(McpServer.tenant_id == tenant_id, McpServer.enabled.is_(True)).order_by(McpServer.name)
    )
    resolved: list[ResolvedMcpServer] = []
    for row in result.scalars().all():
        try:
            auth = get_vault().decrypt_dict(row.auth_config or {})
        except Exception as exc:  # noqa: BLE001 - one unreadable row must not hide the rest
            logger.warning(
                "mcp_registry.credential_unreadable",
                tenant_id=str(tenant_id),
                name=row.name,
                error=type(exc).__name__,
                hint="re-save the server's credential; it was encrypted under a key this deployment no longer holds",
            )
            continue
        resolved.append(
            ResolvedMcpServer(
                name=row.name,
                transport=row.transport,
                url=row.url,
                command=row.command,
                args=[str(a) for a in (row.args or [])],
                auth=auth if isinstance(auth, dict) else {},
                tool_allowlist=[str(t) for t in (row.tool_allowlist or [])],
                timeout_seconds=int(row.timeout_seconds),
                max_response_bytes=int(row.max_response_bytes),
            )
        )
    return resolved
