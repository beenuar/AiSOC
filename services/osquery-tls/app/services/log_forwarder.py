"""Forward normalised osquery events to services/ingest /v1/ingest/batch."""

from __future__ import annotations

import logging

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)


async def forward_events(events: list[dict], tenant_id: str) -> None:
    """POST a batch of normalised events to the ingest service.

    Failures are logged but not re-raised so a single bad ingest call
    does not abort a log submission response to the osqueryd agent.
    """
    if not events:
        return
    url = f"{settings.ingest_url}/v1/ingest/batch"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                url,
                json={"events": events},
                headers={"X-Tenant-ID": tenant_id},
            )
            resp.raise_for_status()
    except Exception:
        logger.exception(
            "Failed to forward %d events to ingest service (tenant=%s, url=%s)",
            len(events),
            tenant_id,
            url,
        )
