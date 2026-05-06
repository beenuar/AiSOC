"""Thin client for writing into the `services/api` case timeline.

The actions service needs to post two timeline events per ChatOps verify:

* on prompt — ``"chatops.verify.prompted"`` so analysts see the question
  was asked even before the user replies,
* on response — ``"chatops.verify.responded"`` carrying the user's choice
  and a short rationale.

We keep this client deliberately tiny: one POST, no retries beyond
``httpx``'s default. If the API service is unreachable, the executor
swallows the failure into ``ActionResult.error`` rather than aborting the
ChatOps message — losing a timeline write is recoverable, losing the
outbound prompt is not.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

import httpx
import structlog

from app.core.config import get_settings

logger = structlog.get_logger()


class TimelineClientError(RuntimeError):
    """Raised when the timeline write definitively fails (HTTP 4xx/5xx)."""


async def post_timeline_event(
    *,
    case_id: UUID,
    event_type: str,
    content: str,
    metadata: dict[str, Any] | None = None,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """Append an event to a case timeline via services/api.

    Returns the parsed response on success. The endpoint requires the
    ``cases:write`` permission, which is granted to the service token via
    its API-key scope set.
    """
    settings = get_settings()
    base = settings.AISOC_API_BASE_URL.rstrip("/")
    if not settings.AISOC_API_SERVICE_TOKEN:
        raise TimelineClientError(
            "AISOC_API_SERVICE_TOKEN is not configured; cannot write ChatOps responses to the case timeline"
        )

    url = f"{base}/api/v1/cases/{case_id}/timeline"
    payload = {
        "content": content,
        "event_type": event_type,
        "metadata": metadata or {},
    }
    headers = {
        "Authorization": f"Bearer {settings.AISOC_API_SERVICE_TOKEN}",
        "Content-Type": "application/json",
    }

    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.post(url, json=payload, headers=headers)

    if resp.status_code >= 400:
        logger.warning(
            "timeline write failed",
            case_id=str(case_id),
            event_type=event_type,
            status_code=resp.status_code,
            body=resp.text[:500],
        )
        raise TimelineClientError(
            f"timeline write failed: HTTP {resp.status_code} — {resp.text[:200]}"
        )

    return resp.json()
