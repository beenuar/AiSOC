"""Register the MCP servers one tenant trusts, and hand them to the agent.

Gap-closure Phase 5.2.

Five routes. Four are the console's: list, create, update and delete. The
fifth is internal, reached only by the agents service with the shared service
token, and it is the only one that ever returns a decrypted credential.

Why the internal route is service-token only, with no session fallback
----------------------------------------------------------------------
Every other dual-mode route in this service accepts either a session or the
service token, because the data behind them is the caller's own. This one
returns plaintext third-party credentials, so a session is not enough: a
console user who can read their tenant's alerts would otherwise be able to
read the bearer token their operator configured for a vendor's MCP server.
The console never needs plaintext; it needs ``has_credential``, which the
list route gives it.

Why the credential travels at all
---------------------------------
The client lives in ``services/agents`` (the plan says so, and that is where
the tool loop is), the vault and the tenant session live here, and neither
service can import the other: both package their code as top-level ``app``.
The same reasoning put SIEM writeback, organisation memory, connector
normalisation and shadow reconciliation behind internal HTTP calls. This is
that pattern with the direction reversed: the agent pulls rather than the API
pushing, because the agent is the one that knows an investigation has started.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

import structlog
from fastapi import APIRouter, Header, HTTPException, status
from pydantic import BaseModel, Field

from app.api.v1.deps import AuthUser, DBSession
from app.api.v1.endpoints.alert_writeback import service_token_valid
from app.db.rls import TenantDBSession, set_rls_context
from app.models.mcp_server import McpServer
from app.services.mcp_registry import (
    DEFAULT_MAX_RESPONSE_BYTES,
    DEFAULT_TIMEOUT_SECONDS,
    McpRegistryError,
    create_server,
    delete_server,
    list_servers,
    resolve_servers_for_agent,
    update_server,
)

logger = structlog.get_logger()

router = APIRouter(prefix="/mcp-servers", tags=["mcp-servers"])


# ---------------------------------------------------------------------------
# Wire models
# ---------------------------------------------------------------------------


class McpServerModel(BaseModel):
    """What the console sees. Never the credential."""

    id: str
    name: str
    label: str | None = None
    transport: str
    url: str | None = None
    command: str | None = None
    args: list[str] = Field(default_factory=list)
    tool_allowlist: list[str] = Field(default_factory=list)
    timeout_seconds: int
    max_response_bytes: int
    enabled: bool
    # The fact of a credential, never its value. `auth_config` is vault
    # ciphertext and returning it would hand an attacker the thing the vault
    # exists to keep out of responses.
    has_credential: bool
    created_at: str | None = None
    updated_at: str | None = None


class McpServerListResponse(BaseModel):
    servers: list[McpServerModel]
    # Stated rather than left for a reader to infer from an empty list: no
    # server is reachable until an operator both enables it and names the
    # tools the agent may call.
    read_only_by_default: bool = True


class McpServerCreate(BaseModel):
    name: str = Field(min_length=2, max_length=40)
    label: str | None = Field(default=None, max_length=200)
    transport: str = "streamable_http"
    url: str | None = Field(default=None, max_length=2048)
    command: str | None = Field(default=None, max_length=512)
    args: list[str] = Field(default_factory=list, max_length=32)
    credential: dict[str, Any] | None = None
    tool_allowlist: list[str] = Field(default_factory=list)
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES
    enabled: bool = False


class McpServerUpdate(BaseModel):
    label: str | None = Field(default=None, max_length=200)
    transport: str | None = None
    url: str | None = Field(default=None, max_length=2048)
    command: str | None = Field(default=None, max_length=512)
    args: list[str] | None = Field(default=None, max_length=32)
    credential: dict[str, Any] | None = None
    tool_allowlist: list[str] | None = None
    timeout_seconds: int | None = None
    max_response_bytes: int | None = None
    enabled: bool | None = None


class ResolvedServerModel(BaseModel):
    name: str
    transport: str
    url: str | None = None
    command: str | None = None
    args: list[str] = Field(default_factory=list)
    auth: dict[str, Any] = Field(default_factory=dict)
    tool_allowlist: list[str] = Field(default_factory=list)
    timeout_seconds: int
    max_response_bytes: int


class ResolvedServersResponse(BaseModel):
    tenant_id: str
    servers: list[ResolvedServerModel]


def _to_model(row: McpServer) -> McpServerModel:
    return McpServerModel(
        id=str(row.id),
        name=row.name,
        label=row.label,
        transport=row.transport,
        url=row.url,
        command=row.command,
        args=[str(a) for a in (row.args or [])],
        tool_allowlist=[str(t) for t in (row.tool_allowlist or [])],
        timeout_seconds=int(row.timeout_seconds),
        max_response_bytes=int(row.max_response_bytes),
        enabled=bool(row.enabled),
        has_credential=bool(row.auth_config),
        created_at=row.created_at.isoformat() if row.created_at else None,
        updated_at=row.updated_at.isoformat() if row.updated_at else None,
    )


# ---------------------------------------------------------------------------
# Console routes
# ---------------------------------------------------------------------------


@router.get("", response_model=McpServerListResponse)
async def list_mcp_servers(user: AuthUser, db: TenantDBSession) -> McpServerListResponse:
    """Every MCP server registered for the caller's tenant."""
    await user.require_permission_db("settings:read", db)
    rows = await list_servers(db, user.tenant_id)
    return McpServerListResponse(servers=[_to_model(r) for r in rows])


@router.post("", response_model=McpServerModel, status_code=status.HTTP_201_CREATED)
async def register_mcp_server(payload: McpServerCreate, user: AuthUser, db: TenantDBSession) -> McpServerModel:
    """Register a server for this tenant.

    The tenant comes from the credential. A refusal is a 422 naming what was
    wrong, because every refusal here is something an operator typed.
    """
    await user.require_permission_db("settings:write", db)
    try:
        row = await create_server(
            db,
            tenant_id=user.tenant_id,
            created_by=user.user_id,
            name=payload.name,
            label=payload.label,
            transport=payload.transport,
            url=payload.url,
            command=payload.command,
            args=payload.args,
            credential=payload.credential,
            tool_allowlist=payload.tool_allowlist,
            timeout_seconds=payload.timeout_seconds,
            max_response_bytes=payload.max_response_bytes,
            enabled=payload.enabled,
        )
    except McpRegistryError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    await db.commit()
    return _to_model(row)


@router.patch("/{server_id}", response_model=McpServerModel)
async def update_mcp_server(
    server_id: uuid.UUID,
    payload: McpServerUpdate,
    user: AuthUser,
    db: TenantDBSession,
) -> McpServerModel:
    """Change a registered server. Absent fields are left alone."""
    await user.require_permission_db("settings:write", db)
    changes = payload.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="no fields to update")
    try:
        row = await update_server(db, tenant_id=user.tenant_id, server_id=server_id, changes=changes)
    except McpRegistryError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    await db.commit()
    return _to_model(row)


@router.delete("/{server_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def remove_mcp_server(server_id: uuid.UUID, user: AuthUser, db: TenantDBSession) -> None:
    await user.require_permission_db("settings:write", db)
    removed = await delete_server(db, tenant_id=user.tenant_id, server_id=server_id)
    if not removed:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="no such MCP server for this tenant")
    await db.commit()


# ---------------------------------------------------------------------------
# Internal route: the agents service, and nothing else
# ---------------------------------------------------------------------------


@router.get("/resolved", response_model=ResolvedServersResponse, include_in_schema=False)
async def resolve_mcp_servers(
    db: DBSession,
    tenant_id: uuid.UUID,
    x_aisoc_service_token: Annotated[str | None, Header()] = None,
) -> ResolvedServersResponse:
    """Enabled servers with decrypted credentials, for the agents service.

    The credential is checked in-band rather than resolved by a bearer
    dependency, the same shape ``/alerts/{id}/source-writeback`` and
    ``/feedback/context-statements`` use, because the caller is a service with
    no session. ``service_token_valid`` compares in constant time and fails
    closed when the shared secret is unset, so an unconfigured deployment has
    this route shut rather than open.

    **No session fallback**, unlike those two. This route returns plaintext
    third-party credentials, and a console session is not a credential to read
    those: a user who can read their tenant's alerts must not thereby be able
    to read the bearer token their operator configured for a vendor.

    ``tenant_id`` is required rather than optional, and it is the scope rather
    than a narrowing of one: a service token carries no tenant of its own, so
    there is nothing to intersect it with, and defaulting an omitted parameter
    to "all tenants" on a route returning credentials is the widest possible
    reading of an absence.

    ``TenantDBSession`` cannot be used here because it resolves the tenant
    from a session this caller does not have, so the RLS context is set from
    the named tenant explicitly. The query layer filters on the same value, so
    the two agree by construction rather than by convention.

    Disabled rows are not returned. See ``resolve_servers_for_agent`` for why
    a row whose credential will not decrypt is dropped rather than downgraded.
    """
    if not service_token_valid(x_aisoc_service_token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="this route is reachable only by an AiSOC service holding the shared service token",
        )

    await set_rls_context(db, tenant_id)
    servers = await resolve_servers_for_agent(db, tenant_id)
    logger.info("mcp_registry.resolved_for_agent", tenant_id=str(tenant_id), servers=len(servers))
    return ResolvedServersResponse(
        tenant_id=str(tenant_id),
        servers=[ResolvedServerModel(**s.as_dict()) for s in servers],
    )
