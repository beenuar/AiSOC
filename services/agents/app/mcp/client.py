"""The MCP client: one session, bounded, validated immediately before it opens.

Gap-closure Phase 5.1 and 5.4. Built on the official MCP Python SDK, pinned
exactly in ``pyproject.toml``. Two things are worth reading here.

The SSRF guard runs here and not in the registry
------------------------------------------------
``services/api`` refuses an obviously unsafe URL at save time so an operator
gets an immediate answer, but the enforcing check is the one in this module,
called in :meth:`McpClient.session` after the configuration has been read and
before the transport is constructed. A hostname that resolved to a public
address when somebody pressed save can resolve to ``169.254.169.254`` an hour
later, so a check performed once at save time proves nothing about the request
that eventually goes out. The air-gap policy is applied at the same point and
for the same reason.

The byte cap is enforced on the socket, not on the way out
-----------------------------------------------------------
A cap applied to the parsed result bounds what reaches the prompt but not what
reaches memory, and an MCP server that answers with a gigabyte would take the
container down before the cap was consulted. :class:`_CappedTransport` counts
bytes as they arrive and aborts past the tenant's limit, so the bound holds at
the point where it costs something. The parsed result is capped again on the
way into the prompt, because those are two different budgets: the socket cap
protects the process, the prompt cap protects the context window.

Transport
---------
Streamable HTTP only. ``policy.vet_server`` refuses a stdio server unless an
operator has switched stdio on and allowlisted the command; this module raises
on one it is handed anyway, rather than quietly falling back to HTTP, because
a client that silently ignores the transport it was told to use is a client
nobody can reason about.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx
import structlog
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

from app.mcp.config import McpServerConfig
from app.mcp.policy import vet_server
from app.playbook.ssrf_guard import SSRFError, validate_outbound_url

logger = structlog.get_logger()

__all__ = ["McpCallError", "McpClient", "McpTransportRefused", "ResponseTooLarge"]


class McpTransportRefused(RuntimeError):
    """The server was refused before any connection was attempted."""


class ResponseTooLarge(RuntimeError):
    """The server sent more than this tenant allows."""


class McpCallError(RuntimeError):
    """A call failed. The message is written for an operator, not a model."""


def _airgap_blocked(url: str) -> str | None:
    """Return a refusal sentence when air-gap mode forbids this URL.

    The policy module lives in ``services/api`` and cannot be imported here,
    so the two environment variables it reads are read directly. The duplicate
    is three lines and the alternative is a network call to ask whether a
    network call is allowed.
    """
    if os.getenv("AISOC_AIRGAPPED", "").strip().lower() not in {"1", "true", "yes", "on"}:
        return None
    host = httpx.URL(url).host or ""
    allowlist = {h.strip().lower() for h in (os.getenv("AISOC_AIRGAP_ALLOWLIST", "") or "").split(",") if h.strip()}
    if host.lower() in allowlist:
        return None
    if host.lower().endswith((".local", ".internal", ".lan", ".intranet")):
        return None
    try:
        # A literal private address is the other legitimate on-prem case.
        import ipaddress  # noqa: PLC0415 - only needed on the air-gapped branch

        if ipaddress.ip_address(host).is_private:
            return None
    except ValueError:
        pass
    return f"air-gap mode is on and {host!r} is not an internal host or on AISOC_AIRGAP_ALLOWLIST"


class _CappedTransport(httpx.AsyncBaseTransport):
    """Wrap a transport so a response body cannot exceed ``limit`` bytes."""

    def __init__(self, inner: httpx.AsyncBaseTransport, limit: int) -> None:
        self._inner = inner
        self._limit = limit

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        response = await self._inner.handle_async_request(request)
        return httpx.Response(
            status_code=response.status_code,
            headers=response.headers,
            stream=_CappedStream(response.stream, self._limit),
            extensions=response.extensions,
            request=request,
        )

    async def aclose(self) -> None:
        await self._inner.aclose()


class _CappedStream:
    """An async byte stream that raises once the running total passes the cap."""

    def __init__(self, inner: Any, limit: int) -> None:
        self._inner = inner
        self._limit = limit

    async def __aiter__(self) -> AsyncIterator[bytes]:
        seen = 0
        async for chunk in self._inner:
            seen += len(chunk)
            if seen > self._limit:
                raise ResponseTooLarge(
                    f"the MCP server sent more than the configured {self._limit} bytes; the connection was closed mid-response"
                )
            yield chunk

    async def aclose(self) -> None:
        aclose = getattr(self._inner, "aclose", None)
        if aclose is not None:
            await aclose()


def _client_factory(limit: int):
    """An ``McpHttpClientFactory`` whose clients cannot over-read."""

    def factory(
        headers: dict[str, str] | None = None,
        timeout: httpx.Timeout | None = None,
        auth: httpx.Auth | None = None,
    ) -> httpx.AsyncClient:
        kwargs: dict[str, Any] = {"transport": _CappedTransport(httpx.AsyncHTTPTransport(), limit)}
        if timeout is not None:
            kwargs["timeout"] = timeout
        if headers is not None:
            kwargs["headers"] = headers
        if auth is not None:
            kwargs["auth"] = auth
        return httpx.AsyncClient(**kwargs)

    return factory


class McpClient:
    """A bounded client for one registered server.

    ``session_factory`` exists so tests drive a real MCP server in-process
    over memory streams rather than a mock of this class. A test that mocks
    the client proves the code around the client, which is the half that is
    already obvious.
    """

    def __init__(self, config: McpServerConfig, *, session_factory: Any | None = None) -> None:
        self.config = config
        self._session_factory = session_factory

    @asynccontextmanager
    async def session(self) -> AsyncIterator[ClientSession]:
        """Open a session, refusing before the transport exists if anything is wrong."""
        if self._session_factory is not None:
            async with self._session_factory(self.config) as session:
                yield session
            return

        verdict = vet_server(
            name=self.config.name,
            transport=self.config.transport,
            url=self.config.url,
            command=self.config.command,
            args=self.config.args,
        )
        if not verdict.admitted:
            raise McpTransportRefused(verdict.reason)
        if self.config.transport != "streamable_http":
            # Reached only when an operator has enabled stdio. Naming it is
            # better than a fallback: AiSOC has no stdio transport wired, and
            # silently using HTTP instead would talk to the wrong thing.
            raise McpTransportRefused(
                f"{self.config.name}: stdio transports are allowlisted by policy but AiSOC does not start local "
                f"processes for MCP servers, so this server is not reachable"
            )

        url = self.config.url or ""
        blocked = _airgap_blocked(url)
        if blocked is not None:
            raise McpTransportRefused(f"{self.config.name}: {blocked}")
        try:
            validate_outbound_url(url)
        except SSRFError as exc:
            raise McpTransportRefused(f"{self.config.name}: {exc}") from exc

        async with streamablehttp_client(
            url,
            headers=self.config.headers() or None,
            timeout=self.config.timeout_seconds,
            httpx_client_factory=_client_factory(self.config.max_response_bytes),
        ) as (read_stream, write_stream, _get_session_id):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                yield session

    async def list_tools(self) -> list[Any]:
        """Discover the server's tools, under the tenant's timeout."""
        async with self.session() as session:
            result = await asyncio.wait_for(session.list_tools(), timeout=self.config.timeout_seconds)
        return list(getattr(result, "tools", []) or [])

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        """Call one tool. The caller has already checked it may.

        This method does not consult the allowlist. It must not: a check here
        would be one a reader could mistake for the control, and the control
        has to happen before anything opens a socket. ``app.mcp.tools`` checks
        it, twice, on the way in.
        """
        async with self.session() as session:
            return await asyncio.wait_for(session.call_tool(name, arguments), timeout=self.config.timeout_seconds)
