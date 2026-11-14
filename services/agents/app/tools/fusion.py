"""
Tool: synchronous fusion-pipeline calls via the fusion service.

Wraps ``POST /process`` on the fusion service
(``http://fusion:8003/process`` inside the docker-compose network — the
fusion service mounts its router at the root path, not under
``/api/fusion``). The agents service's ``DetectAgent`` uses this to
drive the full fusion pipeline (deduplication, correlation, ML scoring,
confidence labelling, RBA) from a single HTTP call without standing up
a Kafka producer.

Contract note (Issue #190): unlike ``app.tools.graph`` — which is used
for *investigation* graph queries and intentionally degrades gracefully
(returns ``{"error": ..., "nodes": [], ...}``) so an in-flight
investigation can continue with partial data — this tool **raises** on
any transport or HTTP failure. Fusion is the primary detection
pipeline: if it fails, the caller MUST know, otherwise alerts disappear
silently and downstream consumers would treat a synthetic error
envelope as a real verdict.
"""

from __future__ import annotations

import os
from typing import Any

import httpx
import structlog

logger = structlog.get_logger()

_DEFAULT_FUSION_URL = "http://fusion:8003"
_DEFAULT_TIMEOUT = "15.0"


def _fusion_url() -> str:
    # Read at call time so tests (and dynamic redeploys) can override
    # ``FUSION_SERVICE_URL`` without reloading the module.
    return os.getenv("FUSION_SERVICE_URL", _DEFAULT_FUSION_URL)


def _timeout() -> float:
    return float(os.getenv("AGENTS_FUSION_TIMEOUT", _DEFAULT_TIMEOUT))


def _headers(api_token: str | None) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_token}"} if api_token else {}


async def process_alert(
    raw_alert: dict[str, Any],
    api_token: str | None = None,
) -> dict[str, Any]:
    """Run a raw alert through the fusion pipeline and return the fused alert.

    Args:
        raw_alert: A ``RawAlert``-shaped dict (matching the fusion service's
            Pydantic model). The fusion service validates the schema, so we
            keep the agent-side boundary as plain dicts to avoid coupling
            this service to the fusion service's Pydantic models.
        api_token: Optional bearer token forwarded to the fusion service.

    Returns:
        The ``FusedAlert``-shaped dict produced by the fusion engine.
        Includes ``fusion_decision`` (NEW/CORRELATED/DUPLICATE),
        ``incident_id``, ``priority_score``, ``confidence_label``, and the
        original alert envelope.

    Raises:
        httpx.HTTPStatusError: The fusion service returned a non-2xx
            response (e.g. 503 when the worker is not yet ready, 422 on a
            malformed payload).
        httpx.HTTPError: Any transport-level failure (timeout, connect
            error, etc.).
    """
    url = f"{_fusion_url()}/process"
    try:
        async with httpx.AsyncClient(timeout=_timeout()) as client:
            resp = await client.post(
                url,
                json=raw_alert,
                headers=_headers(api_token),
            )
            resp.raise_for_status()
            return resp.json()
    except httpx.HTTPStatusError as exc:
        logger.error(
            "fusion process_alert returned non-2xx",
            url=url,
            status_code=exc.response.status_code,
            body=exc.response.text[:500],
            alert_id=raw_alert.get("id"),
        )
        raise
    except httpx.HTTPError as exc:
        logger.error(
            "fusion process_alert transport failure",
            url=url,
            error=str(exc),
            alert_id=raw_alert.get("id"),
        )
        raise
