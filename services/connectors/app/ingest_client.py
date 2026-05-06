"""HTTP client that forwards normalized events to the Go ingest service.

The connectors service polls each enabled connector instance and pushes the
normalized events here. The ingest service is in Go (services/ingest) and
exposes ``POST /v1/ingest`` and ``POST /v1/ingest/batch`` with the request
shape::

    {
      "connector_id": "...",
      "connector_type": "...",
      "source_format": "...",
      "events": [{...}, ...]
    }

with ``X-Tenant-ID`` header for tenant scoping.

We keep this layer **dumb on purpose**: no retries with exponential backoff
beyond a single retry, no circuit breaker, no batching across connectors.
The ingest service handles the queueing into Kafka — adding another buffer
layer in the connectors process would just move the failure point and add
state to a process we want to keep restartable. If the ingest service is
down, polls fail loudly and the scheduler records that in
``record_poll_failure``; the next poll cycle retries.
"""

from __future__ import annotations

import logging
import os
import uuid
from typing import Any

import httpx

logger = logging.getLogger("aisoc.connectors.ingest_client")

# 30s mirrors the ingest service's own ReadTimeout. We don't want the client
# to give up before the server has a chance to publish; we also don't want
# polls to hang the scheduler thread for minutes if Kafka is wedged.
_DEFAULT_TIMEOUT_S = 30.0


class IngestClientError(RuntimeError):
    """Raised when the ingest service rejects or fails the push."""


class IngestClient:
    """Push connector events to ``services/ingest``.

    One client per scheduler process is fine — ``httpx.AsyncClient`` pools
    connections internally. Construct via ``IngestClient.from_env`` so the
    URL stays configurable per deployment without threading config through
    every caller.
    """

    def __init__(self, base_url: str, *, timeout_seconds: float = _DEFAULT_TIMEOUT_S) -> None:
        # Strip trailing slash so we can append paths without doubling up.
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout_seconds
        self._client: httpx.AsyncClient | None = None

    @classmethod
    def from_env(cls) -> IngestClient:
        url = os.getenv("INGEST_SERVICE_URL", "http://ingest-worker:8080")
        timeout = float(os.getenv("INGEST_SERVICE_TIMEOUT_SECONDS", str(_DEFAULT_TIMEOUT_S)))
        return cls(url, timeout_seconds=timeout)

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self._timeout)
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def push_events(
        self,
        *,
        tenant_id: uuid.UUID | str,
        connector_id: uuid.UUID | str,
        connector_type: str,
        events: list[dict[str, Any]],
        source_format: str = "raw_json",
    ) -> dict[str, Any]:
        """Push a batch of events to the ingest service.

        Returns the response body (``{"accepted": N, "rejected": N, ...}``) so
        the scheduler can record how many events were accepted in
        ``connectors.events_ingested``.

        An empty event list short-circuits and returns ``{"accepted": 0,
        "rejected": 0}`` without making a network call — this is the common
        case (a poll cycle that found no new alerts).
        """
        if not events:
            return {"accepted": 0, "rejected": 0}

        client = await self._get_client()
        # Use the batch endpoint — the non-batch and batch endpoints are
        # actually the same handler in the Go service, but ``/ingest/batch``
        # documents intent for whoever's reading nginx logs.
        url = f"{self._base_url}/v1/ingest/batch"
        headers = {
            "Content-Type": "application/json",
            "X-Tenant-ID": str(tenant_id),
        }
        payload = {
            "connector_id": str(connector_id),
            "connector_type": connector_type,
            "source_format": source_format,
            "events": events,
        }

        try:
            resp = await client.post(url, headers=headers, json=payload)
        except httpx.HTTPError as exc:
            raise IngestClientError(f"ingest service unreachable at {url}: {exc}") from exc

        if resp.status_code >= 400:
            # Pull the body so logs show *why* — typically a missing tenant
            # header or oversized batch, both of which we want surfaced
            # rather than swallowed.
            body_preview = resp.text[:500]
            raise IngestClientError(f"ingest service returned {resp.status_code} for connector {connector_id}: {body_preview}")

        try:
            data = resp.json()
        except ValueError as err:
            raise IngestClientError("ingest service returned non-JSON response") from err
        return data


__all__ = ["IngestClient", "IngestClientError"]
