"""
Tool: knowledge-graph queries via the API service.

Wraps the `/api/v1/graph/*` endpoints exposed by `services/api`. The agents
service uses these to walk attack paths, compute blast-radius severity, and
discover the immediate neighbourhood of an entity during an investigation.
"""

from __future__ import annotations

import os
from typing import Any

import httpx
import structlog

logger = structlog.get_logger()

_API_URL = os.getenv("API_SERVICE_URL", "http://api:8000")
_TIMEOUT = float(os.getenv("AGENTS_API_TIMEOUT", "10.0"))


#: Whether the entity graph is part of this deployment. Neo4j is a `full`
#: profile service, so on CORE there is no graph to read and every call
#: below would fail regardless of credentials.
_GRAPH_ENABLED = os.getenv("AISOC_GRAPH_ENABLED", "").strip().lower() in ("1", "true", "yes")

_UNAVAILABLE_LOGGED = False


def graph_unavailable_reason(api_token: str | None) -> str | None:
    """Why a graph read cannot be made, or None if it can.

    Two reasons, and telling them apart matters to whoever reads the log.

    The graph routes on the API authenticate with `get_current_user`, which
    validates a **user** JWT. A background worker has no user, so a service
    token does not open them: before this, `ContextBundleBuilder()` was
    constructed with no token on the production path and every graph read
    during auto-triage answered 401, four warnings per alert, on every
    entity. That reads like a broken integration rather than a capability
    that is not present.

    And on CORE there is no graph at all. Neo4j runs in the `full` profile,
    so the honest answer there is "not in this deployment", not an
    authentication error.
    """
    if not _GRAPH_ENABLED:
        return "the entity graph runs in the `full` profile and is not part of this deployment"
    if not api_token:
        return "no user credential is available on this path; the graph routes authenticate a user and a background worker has none"
    return None


def _note_unavailable(reason: str) -> None:
    """Say it once per process, not once per entity per alert."""
    global _UNAVAILABLE_LOGGED  # noqa: PLW0603
    if _UNAVAILABLE_LOGGED:
        return
    _UNAVAILABLE_LOGGED = True
    logger.info("graph.unavailable", reason=reason)


def _headers(api_token: str | None) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_token}"} if api_token else {}


async def get_attack_path(
    case_id: str,
    api_token: str | None = None,
    max_depth: int = 6,
) -> dict[str, Any]:
    """Return the Case → Alert → Host/User → IOC → Technique attack path."""
    unavailable = graph_unavailable_reason(api_token)
    if unavailable:
        _note_unavailable(unavailable)
        # "could not check" with a reason, which is what the agent
        # prompt renders. An empty result would read to the model as
        # "this entity has no neighbours", which is a different and
        # much worse claim.
        return {"error": unavailable, "available": False}
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                f"{_API_URL}/api/v1/graph/attack-path/{case_id}",
                params={"max_depth": max_depth},
                headers=_headers(api_token),
            )
            resp.raise_for_status()
            return resp.json()
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            return {"case_id": case_id, "nodes": [], "edges": [], "node_count": 0, "edge_count": 0}
        logger.warning("attack_path query failed", case_id=case_id, error=str(exc))
        return {"error": str(exc), "case_id": case_id, "nodes": [], "edges": []}
    except Exception as exc:  # noqa: BLE001
        logger.warning("attack_path query failed", case_id=case_id, error=str(exc))
        return {"error": str(exc), "case_id": case_id, "nodes": [], "edges": []}


async def get_blast_radius(
    entity_type: str,
    entity_id: str,
    api_token: str | None = None,
    hops: int = 3,
) -> dict[str, Any]:
    """Compute the blast radius starting from a Host/User/IOC/Alert node."""
    unavailable = graph_unavailable_reason(api_token)
    if unavailable:
        _note_unavailable(unavailable)
        # "could not check" with a reason, which is what the agent
        # prompt renders. An empty result would read to the model as
        # "this entity has no neighbours", which is a different and
        # much worse claim.
        return {"error": unavailable, "available": False}
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                f"{_API_URL}/api/v1/graph/blast-radius/{entity_type}/{entity_id}",
                params={"hops": hops},
                headers=_headers(api_token),
            )
            resp.raise_for_status()
            return resp.json()
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "blast_radius query failed",
            entity_type=entity_type,
            entity_id=entity_id,
            error=str(exc),
        )
        return {
            "error": str(exc),
            "entity_id": entity_id,
            "entity_type": entity_type,
            "affected_nodes": [],
            "total_affected": 0,
            "type_breakdown": {},
            "blast_radius_score": 0.0,
        }


async def get_entity_neighbors(
    entity_type: str,
    entity_id: str,
    api_token: str | None = None,
) -> dict[str, Any]:
    """Return all nodes directly connected (depth 1) to the specified entity."""
    unavailable = graph_unavailable_reason(api_token)
    if unavailable:
        _note_unavailable(unavailable)
        # "could not check" with a reason, which is what the agent
        # prompt renders. An empty result would read to the model as
        # "this entity has no neighbours", which is a different and
        # much worse claim.
        return {"error": unavailable, "available": False}
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                f"{_API_URL}/api/v1/graph/neighbors/{entity_type}/{entity_id}",
                headers=_headers(api_token),
            )
            resp.raise_for_status()
            return resp.json()
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "entity_neighbors query failed",
            entity_type=entity_type,
            entity_id=entity_id,
            error=str(exc),
        )
        return {
            "error": str(exc),
            "entity_id": entity_id,
            "entity_type": entity_type,
            "neighbors": [],
            "neighbor_count": 0,
        }
