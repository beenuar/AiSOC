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

Authentication
--------------
``/v1/ingest`` requires a credential. This process pushes on behalf of every
tenant whose connectors it polls, so it cannot hold a per-tenant push token;
it presents the shared service token instead (``AISOC_SERVICE_TOKEN``, or
``AISOC_INGEST_SERVICE_TOKEN`` to override it for this hop only), which
identifies *a trusted service* rather than a tenant. ``X-Tenant-ID`` then
declares which tenant the push is for, and the ingest service checks that
tenant against the tenants table before it becomes a scope. That is the same
credential shape ``app.security.tenant_scope`` implements for the Python
services.

Without the token every push is refused with 401, which is a deliberate
configuration requirement rather than a soft failure — see
``apps/docs/docs/operations/ingest-authentication.md``. We say so once at construction
time so the cause is visible at startup rather than only in per-poll errors.

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

logger = logging.getLogger(__name__)

# 30s mirrors the ingest service's own ReadTimeout. We don't want the client
# to give up before the server has a chance to publish; we also don't want
# polls to hang the scheduler thread for minutes if Kafka is wedged.
_DEFAULT_TIMEOUT_S = 30.0


def resolve_service_token() -> str:
    """The shared secret this service presents to ``/v1/ingest``.

    Per-service override wins over the shared platform token, matching the
    precedence in ``app.security.tenant_scope.resolve_service_token`` and in
    the Go ingest service's own config.
    """
    specific = os.getenv("AISOC_INGEST_SERVICE_TOKEN", "").strip()
    if specific:
        return specific
    return os.getenv("AISOC_SERVICE_TOKEN", "").strip()


class IngestClientError(RuntimeError):
    """Raised when the ingest service rejects or fails the push."""


class IngestClient:
    """Push connector events to ``services/ingest``.

    One client per scheduler process is fine — ``httpx.AsyncClient`` pools
    connections internally. Construct via ``IngestClient.from_env`` so the
    URL stays configurable per deployment without threading config through
    every caller.
    """

    def __init__(
        self,
        base_url: str,
        *,
        timeout_seconds: float = _DEFAULT_TIMEOUT_S,
        service_token: str | None = None,
    ) -> None:
        # Strip trailing slash so we can append paths without doubling up.
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout_seconds
        self._service_token = (service_token if service_token is not None else resolve_service_token()).strip()
        self._client: httpx.AsyncClient | None = None
        if not self._service_token:
            # Warned once here rather than per poll. Every push will be
            # refused, and an operator reading the startup log should not
            # have to wait for the first poll cycle to learn why.
            logger.warning(
                "no ingest service token configured (AISOC_SERVICE_TOKEN / AISOC_INGEST_SERVICE_TOKEN); "
                "every push to %s will be refused with 401",
                self._base_url,
            )

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
            # Declares which tenant this trusted service is acting for. It
            # is not authority on its own — the ingest service intersects it
            # with what the credential authorises and validates it against
            # the tenants table.
            "X-Tenant-ID": str(tenant_id),
        }
        if self._service_token:
            headers["Authorization"] = f"Bearer {self._service_token}"
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
            # Pull the body so logs show *why* — typically a missing or
            # rejected credential, an undeclared tenant, or an oversized
            # batch, all of which we want surfaced rather than swallowed.
            body_preview = resp.text[:500]
            hint = ""
            if resp.status_code in (401, 403):
                hint = (
                    " — /v1/ingest requires a credential; set AISOC_SERVICE_TOKEN on both this service "
                    "and the ingest service (see apps/docs/docs/operations/ingest-authentication.md)"
                )
            raise IngestClientError(f"ingest service returned {resp.status_code} for connector {connector_id}: {body_preview}{hint}")

        try:
            data = resp.json()
        except ValueError as err:
            raise IngestClientError("ingest service returned non-JSON response") from err
        return data


__all__ = ["IngestClient", "IngestClientError"]
