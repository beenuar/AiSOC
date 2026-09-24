"""
Fusion gateway / fallback for /api/v1/fusion/*.

The fusion microservice (services/fusion) owns Risk-Based Alerting (RBA) —
entity rollups, decayed risk scoring, and ML-assisted ranking. In a full
deployment the web tier proxies /api/v1/fusion/* directly to that service
(see apps/web/next.config.js → FUSION_HOST). When the fusion service is
not deployed (e.g. the demo Fly.io stack), the web rewrite still hits the
core API service via the catch-all, so we expose a thin gateway here that:

  1. Forwards to the upstream fusion service if FUSION_URL is set in the
     api environment, preserving full functionality.
  2. Otherwise returns graceful empty payloads so the console renders an
     empty queue instead of a 500.

Endpoint surface mirrors services/fusion/app/api/router.py:
    GET  /api/v1/fusion/health
    GET  /api/v1/fusion/metrics
    GET  /api/v1/fusion/entity-risk/queue
    GET  /api/v1/fusion/entity-risk/stats
    GET  /api/v1/fusion/entity-risk/{entity_type}/{entity_value}
    GET  /api/v1/fusion/ml/status
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any
from urllib.parse import quote
from uuid import UUID

import httpx
from fastapi import APIRouter, HTTPException, Query

from app.api.v1.deps import AuthUser
from app.core.logging import safe_log_value
from app.security.tenant_scope import scoped_tenant_or_403

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/fusion", tags=["fusion"])

# When set, requests are forwarded to the live fusion service. When unset,
# the gateway returns deterministic, empty fallbacks so the UI degrades
# gracefully instead of bubbling 5xx into the analyst console.
_FUSION_URL = (os.getenv("FUSION_SERVICE_URL") or os.getenv("FUSION_URL") or "").rstrip("/")

# Header the upstream fusion service reads to learn which tenant a trusted
# service is acting for. Must match ``TENANT_HEADER`` in
# services/fusion/app/security/tenant_scope.py.
_TENANT_HEADER = "X-AiSOC-Tenant-ID"


def _service_token() -> str:
    """Shared secret this gateway presents to the fusion service."""
    specific = (os.getenv("AISOC_FUSION_SERVICE_TOKEN") or "").strip()
    return specific or (os.getenv("AISOC_SERVICE_TOKEN") or "").strip()


def _upstream_headers(tenant_id: UUID) -> dict[str, str]:
    """Credential + tenant assertion for a proxied entity-risk call.

    The gateway has already authenticated the browser and resolved the tenant
    from the principal; upstream needs both facts. Without a configured
    service token we still send the tenant assertion, so a dev-mode fusion
    keeps working while a production fusion (which fails closed without a
    token) correctly refuses.
    """
    headers = {_TENANT_HEADER: str(tenant_id)}
    token = _service_token()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


# Tight allowlist for proxied request paths. We only ever proxy to a fixed
# upstream (`_FUSION_URL`) on a known set of routes, so the path must be a
# pure relative path with no scheme, host, control characters, or traversal
# sequences. This neutralises partial-SSRF (an attacker cannot redirect the
# request elsewhere) and log-injection (the path can never contain CR/LF).
_SAFE_PATH_RE = re.compile(r"^/[A-Za-z0-9_\-./%]*$")


def _validate_proxy_path(path: str) -> str:
    """Reject any proxied path that isn't a tightly constrained relative path."""
    if (
        not isinstance(path, str) or not _SAFE_PATH_RE.match(path) or ".." in path or path.startswith("//")  # protocol-relative URL
    ):
        raise HTTPException(status_code=400, detail="invalid_request_path")
    return path


async def _proxy_get(
    path: str,
    params: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
) -> dict[str, Any] | None:
    """Forward GET to fusion if configured. Return None on transport error."""
    if not _FUSION_URL:
        return None
    safe_path = _validate_proxy_path(path)
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(f"{_FUSION_URL}{safe_path}", params=params or {}, headers=headers or {})
        if resp.status_code >= 500:
            logger.warning(
                "fusion.upstream_error",
                extra={
                    "status_code": resp.status_code,
                    "path": safe_log_value(safe_path),
                },
            )
            return None
        if resp.status_code == 404:
            # Let caller surface 404 cleanly.
            raise HTTPException(status_code=404, detail="not_found")
        if resp.status_code >= 400:
            raise HTTPException(status_code=resp.status_code, detail=resp.text)
        return resp.json()
    except HTTPException:
        raise
    except httpx.HTTPError as exc:
        logger.warning(
            "fusion.unreachable",
            extra={"err": safe_log_value(str(exc))},
        )
        return None


# ─── Health / metrics ──────────────────────────────────────────────────────


@router.get("/health", summary="Fusion service health")
async def fusion_health() -> dict[str, Any]:
    upstream = await _proxy_get("/health")
    if upstream is not None:
        return upstream
    return {
        "status": "stub",
        "service": "aisoc-fusion-gateway",
        "upstream_configured": bool(_FUSION_URL),
    }


@router.get("/metrics", summary="Fusion worker metrics")
async def fusion_metrics() -> dict[str, Any]:
    upstream = await _proxy_get("/metrics")
    if upstream is not None:
        return upstream
    return {"status": "stub", "metrics": {}}


# ─── ML status ─────────────────────────────────────────────────────────────


@router.get("/ml/status", summary="Fusion ML model status")
async def ml_status() -> dict[str, Any]:
    upstream = await _proxy_get("/ml/status")
    if upstream is not None:
        return upstream
    return {
        "status": "stub",
        "model_version": None,
        "trained_at": None,
        "training_samples": 0,
        "feedback_count": 0,
    }


# ─── Entity risk (RBA) ─────────────────────────────────────────────────────

# The threshold here mirrors services/fusion/app/services/entity_risk.py
# default; the UI displays it as "promotion threshold".
_DEFAULT_THRESHOLD = 100.0


# These three routes used to take `tenant_id` as a required query parameter
# with no auth dependency at all, so any caller could read any tenant's
# entity-risk rollup by naming its UUID. The tenant now comes from the
# authenticated principal; the parameter survives only as an optional filter
# that is intersected with the caller's scope, so naming a foreign tenant is
# a 403 rather than a selector for someone else's data.


@router.get("/entity-risk/queue", summary="Top entities by risk score")
async def entity_risk_queue(
    user: AuthUser,
    tenant_id: UUID | None = None,
    limit: int = Query(default=25, ge=1, le=200),
    promoted_only: bool = False,
) -> dict[str, Any]:
    scoped = scoped_tenant_or_403(user, tenant_id)
    upstream = await _proxy_get(
        "/entity-risk/queue",
        params={
            "tenant_id": str(scoped),
            "limit": limit,
            "promoted_only": str(promoted_only).lower(),
        },
        headers=_upstream_headers(scoped),
    )
    if upstream is not None:
        return upstream
    return {
        "tenant_id": str(scoped),
        "threshold": _DEFAULT_THRESHOLD,
        "entities": [],
    }


@router.get("/entity-risk/stats", summary="Entity-risk queue stats")
async def entity_risk_stats(user: AuthUser, tenant_id: UUID | None = None) -> dict[str, Any]:
    scoped = scoped_tenant_or_403(user, tenant_id)
    upstream = await _proxy_get(
        "/entity-risk/stats",
        params={"tenant_id": str(scoped)},
        headers=_upstream_headers(scoped),
    )
    if upstream is not None:
        return upstream
    return {
        "tenant_id": str(scoped),
        "threshold": _DEFAULT_THRESHOLD,
        "total": 0,
        "promoted": 0,
        "bands": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "alerts_total": 0,
    }


@router.get(
    "/entity-risk/{entity_type}/{entity_value}",
    summary="Entity risk record detail",
)
async def entity_risk_detail(
    entity_type: str,
    entity_value: str,
    user: AuthUser,
    tenant_id: UUID | None = None,
) -> dict[str, Any]:
    scoped = scoped_tenant_or_403(user, tenant_id)
    if entity_type == "ip":
        entity_type = "src_ip"
    # URL-encode user-controlled path segments so they cannot inject `/`,
    # `?`, `#`, or other URL syntax into the proxied path.
    safe_type = quote(entity_type, safe="")
    safe_value = quote(entity_value, safe="")
    upstream = await _proxy_get(
        f"/entity-risk/{safe_type}/{safe_value}",
        params={"tenant_id": str(scoped)},
        headers=_upstream_headers(scoped),
    )
    if upstream is not None:
        return upstream
    # No fallback record exists when fusion is offline; surface 404 so the
    # drawer renders its empty state.
    raise HTTPException(status_code=404, detail="entity_not_found")
