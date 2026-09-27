"""Read the tenant's MCP servers from the service that owns the vault.

Gap-closure Phase 5.2, agents half.

``services/api`` and ``services/agents`` both package their code as top-level
``app``, so one Python process can hold one of them. The registry, the vault
and the tenant session are the API's; the MCP client is this service's,
because this is where the tool loop runs. So the configuration arrives over
HTTP, the same round trip that already carries organisation memory, SIEM
writeback, connector normalisation and shadow reconciliation.

Two things this module exists to get right
------------------------------------------
**The prefix.** ``AISOC_API_URL`` is a bare origin and the API mounts its v1
router under ``/api/v1``. Phase 1.2 shipped a route whose client omitted
exactly that, so every request would have 404'd and three green suites said
nothing, because the test asserted the URL the code produced rather than the
URL the service serves. ``test_mcp_registry_client.py`` parses the API's own
router with ``ast`` and asserts the requested path is one that service mounts.

**An unreachable registry is not an empty one.** A failed fetch returns a
failure, not ``[]``. Zero servers and "could not ask" send an operator to
entirely different places, and the second one silently removes every MCP tool
from an investigation that was configured to have them.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

import httpx
import structlog

from app.mcp.config import McpServerConfig, server_configs_from_payload

logger = structlog.get_logger()

__all__ = ["RegistryFetch", "fetch_servers"]

#: The API mounts its v1 router with ``prefix="/api/v1"`` in
#: ``app/api/v1/router.py``, and ``AISOC_API_URL`` is the bare origin. See the
#: module docstring for the defect this constant exists to prevent.
API_PREFIX = "/api/v1"

#: Short. This runs on the hot path of an investigation, and a registry that
#: is slow to answer must cost the investigation a second, not a minute.
_TIMEOUT_S = float(os.getenv("AISOC_MCP_REGISTRY_TIMEOUT_S", "5"))


#: Where the API answers when nothing says otherwise. The compose service
#: name, because that is what resolves inside the deployment.
DEFAULT_API_URL = "http://api:8000"


def registry_url(base: str | None = None) -> str:
    origin = (base or os.getenv("AISOC_API_URL") or DEFAULT_API_URL).rstrip("/")
    return f"{origin}{API_PREFIX}/mcp-servers/resolved"


@dataclass(frozen=True)
class RegistryFetch:
    """The outcome of asking. ``ok`` false means unknown, never none."""

    ok: bool
    servers: list[McpServerConfig]
    reason: str = ""


async def fetch_servers(tenant_id: str, *, base_url: str | None = None, client: httpx.AsyncClient | None = None) -> RegistryFetch:
    """The tenant's enabled MCP servers, credentials resolved.

    The service token is required. Without it the API refuses the route, which
    is the correct behaviour for a route that returns plaintext third-party
    credentials, so the absence is reported loudly here rather than turning
    into a quiet zero.
    """
    token = os.getenv("AISOC_AGENTS_SERVICE_TOKEN", "").strip() or os.getenv("AISOC_SERVICE_TOKEN", "").strip()
    if not token:
        reason = "AISOC_AGENTS_SERVICE_TOKEN is unset, so the API refuses the MCP registry route and no MCP tool can be offered"
        logger.warning("mcp_registry.no_service_token", reason=reason)
        return RegistryFetch(False, [], reason)

    url = registry_url(base_url)
    headers = {"X-AiSOC-Service-Token": token}
    params = {"tenant_id": tenant_id}
    try:
        if client is not None:
            response = await client.get(url, headers=headers, params=params, timeout=_TIMEOUT_S)
        else:
            async with httpx.AsyncClient(timeout=_TIMEOUT_S) as owned:
                response = await owned.get(url, headers=headers, params=params)
    except httpx.HTTPError as exc:
        reason = f"could not reach the MCP registry ({type(exc).__name__})"
        logger.warning("mcp_registry.unreachable", error=type(exc).__name__)
        return RegistryFetch(False, [], reason)

    if response.status_code >= 400:
        reason = f"the MCP registry refused the request with HTTP {response.status_code}"
        logger.warning("mcp_registry.refused", status_code=response.status_code)
        return RegistryFetch(False, [], reason)

    try:
        payload = response.json()
    except ValueError:
        logger.warning("mcp_registry.bad_response")
        return RegistryFetch(False, [], "the MCP registry returned a body that is not JSON")

    servers = server_configs_from_payload(payload)
    logger.info("mcp_registry.fetched", tenant_id=tenant_id, servers=len(servers))
    return RegistryFetch(True, servers)
