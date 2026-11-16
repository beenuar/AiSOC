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
  2. Returns 503 for unavailable risk data rather than fabricating an empty
     queue, zero counts, or an absent entity. Health probes retain their stub status.

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
async def fusion_health(user: AuthUser) -> dict[str, Any]:
    upstream = await _proxy_get("/health")
    if upstream is not None:
        return upstream
    return {
        "status": "stub",
        "service": "aisoc-fusion-gateway",
        "upstream_configured": bool(_FUSION_URL),
    }


@router.get("/metrics", summary="Fusion worker metrics")
async def fusion_metrics(user: AuthUser) -> dict[str, Any]:
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

# ── Console-shape adapters (#1931) ──
#
# Fusion's wire shapes and the console's `EntityRiskRecord` /
# `EntityRiskStats` types (apps/web/src/lib/api.ts) had never met: fusion
# publishes `severities`/`contributors`/`tracked_entities`, the console reads
# `severity_histogram`/`contributions`/`total`, and the first deployment that
# wired this proxy up crashed the Alerts route on
# `severity_histogram.critical` of undefined. The gateway owns the
# translation because it already owns the credential and tenant assertion —
# fusion's own wire shape stays as other consumers know it.

#: The five-tier ladder, exactly (see AlertSeverity in the console types).
_SEVERITY_KEYS = ("critical", "high", "medium", "low", "info")

#: Queue header chips. Fusion computes all four; zero-fill is only a guard
#: against a sparse upstream, not a fabricated count.
_BAND_KEYS = ("critical", "high", "medium", "low")

#: Fusion's engine default (settings.rba_promotion_threshold). Used only when
#: an older fusion's detail response carries no threshold of its own.
_DEFAULT_RBA_THRESHOLD = 80.0


def _clean_iso(ts: Any) -> str | None:
    """Repair fusion's historical ``…+00:00Z`` stamps (offset *and* Z).

    Fixed at the source in services/fusion (same change set), but the
    gateway must also accept an unpatched upstream: a mixed-version
    deployment is the norm mid-upgrade.
    """
    if not isinstance(ts, str) or not ts:
        return None
    if ts.endswith("Z") and "+" in ts:
        head, _, _ = ts.rpartition("+")
        return head + "Z"
    return ts


def _adapt_record(record: dict[str, Any], threshold: float | None) -> dict[str, Any]:
    """Map one fusion entity-risk record onto the console's contract."""
    score = float(record.get("score", 0.0) or 0.0)
    if threshold is None:
        raw_threshold = record.get("threshold")
        threshold = float(raw_threshold) if isinstance(raw_threshold, int | float) else _DEFAULT_RBA_THRESHOLD

    raw_severities = record.get("severities")
    severities: dict[str, Any] = raw_severities if isinstance(raw_severities, dict) else {}
    histogram = {key: int(severities.get(key, 0) or 0) for key in _SEVERITY_KEYS}

    contributions: list[dict[str, Any]] = []
    for raw in record.get("contributors") or []:
        if not isinstance(raw, dict):
            continue
        contributions.append(
            {
                "alert_id": str(raw.get("alert_id", "")),
                "severity": raw.get("severity"),
                "raw_points": float(raw.get("points", 0.0) or 0.0),
                "observed_at": _clean_iso(raw.get("at")),
                "title": raw.get("detection") or None,
                # Fusion does not record the contributing alert's source;
                # the console types this nullable for exactly that reason.
                "source": None,
            }
        )

    last_seen = _clean_iso(record.get("last_seen"))
    observed = sorted(c["observed_at"] for c in contributions if c["observed_at"])
    promoted_at = _clean_iso(record.get("promoted_at"))

    entity_type = record.get("entity_type")
    if entity_type == "src_ip":
        entity_type = "ip"

    return {
        "tenant_id": record.get("tenant_id"),
        "entity_type": entity_type,
        "entity_value": record.get("entity_value"),
        "score": score,
        "display_score": round(score),
        "threshold": threshold,
        "promoted": bool(promoted_at) or score >= threshold,
        # Fusion's record has no incident linkage; null is the honest value
        # and the console types it optional.
        "promoted_incident_id": None,
        "last_seen": last_seen,
        # Oldest surviving contribution. Fusion keeps the newest 25, so this
        # is "first seen among retained evidence", and falls back to
        # last_seen when no contributor list survived — never an invented
        # earlier time.
        "first_seen": observed[0] if observed else last_seen,
        "contributions": contributions,
        "severity_histogram": histogram,
        "alert_count": int(record.get("alert_count", 0) or 0),
    }


def _adapt_queue(payload: dict[str, Any]) -> dict[str, Any]:
    raw_threshold = payload.get("threshold")
    threshold = float(raw_threshold) if isinstance(raw_threshold, int | float) else _DEFAULT_RBA_THRESHOLD
    entities = [_adapt_record(r, threshold) for r in payload.get("entities") or [] if isinstance(r, dict)]
    return {
        "tenant_id": payload.get("tenant_id"),
        "threshold": threshold,
        "entities": entities,
    }


def _adapt_stats(payload: dict[str, Any]) -> dict[str, Any]:
    raw_bands = payload.get("score_bands")
    bands: dict[str, Any] = raw_bands if isinstance(raw_bands, dict) else {}
    adapted: dict[str, Any] = {
        "tenant_id": payload.get("tenant_id"),
        "threshold": payload.get("threshold"),
        "total": int(payload.get("tracked_entities", 0) or 0),
        "promoted": int(payload.get("promoted_entities", 0) or 0),
        "bands": {key: int(bands.get(key, 0) or 0) for key in _BAND_KEYS},
    }
    # Deliberately no `alert_count`: fusion's stats do not publish one, and
    # the console computes it from the queue rows when the key is absent —
    # publishing 0 here would render a confident wrong number instead.
    return adapted


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
        return _adapt_queue(upstream)
    raise HTTPException(status_code=503, detail="Fusion risk data is unavailable; no risk assessment was made.")


@router.get("/entity-risk/stats", summary="Entity-risk queue stats")
async def entity_risk_stats(user: AuthUser, tenant_id: UUID | None = None) -> dict[str, Any]:
    scoped = scoped_tenant_or_403(user, tenant_id)
    upstream = await _proxy_get(
        "/entity-risk/stats",
        params={"tenant_id": str(scoped)},
        headers=_upstream_headers(scoped),
    )
    if upstream is not None:
        return _adapt_stats(upstream)
    raise HTTPException(status_code=503, detail="Fusion risk statistics are unavailable; counts are unknown.")


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
        # threshold=None: a current fusion sends it on the detail record; an
        # older one falls back to the engine default inside the adapter.
        return _adapt_record(upstream, threshold=None)
    raise HTTPException(status_code=503, detail="Fusion risk data is unavailable; the entity could not be checked.")
