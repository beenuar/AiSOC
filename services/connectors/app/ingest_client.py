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

# Maximum batch size the ingest service will accept in one request. This
# mirrors MAX_BATCH_SIZE in services/ingest/internal/config/config.go (default
# 1000). Declared here so IngestClient can chunk oversized polls before they
# reach the ingest service and are refused with HTTP 413.
#
# The two numbers are kept honest by
# ``test_max_batch_size_matches_ingest_service_config``, which reads the Go
# default out of config.go rather than trusting this comment.
MAX_BATCH_SIZE = 1000


def resolve_max_batch_size() -> int:
    """The per-request event ceiling this client chunks to.

    Reads the same ``MAX_BATCH_SIZE`` variable the Go ingest service reads, so
    a deployment that lowers the server's cap can lower the client's with it.
    The two run in separate containers, so alignment is the operator's job:
    set the variable for both, or leave it unset for both and they agree on
    the shared default. A value the client cannot parse, or one below 1, is
    ignored in favour of the default rather than disabling chunking — an
    unparseable override must not be the reason a poll is discarded whole.
    """
    raw = os.getenv("MAX_BATCH_SIZE", "").strip()
    if raw:
        try:
            parsed = int(raw)
        except ValueError:
            logger.warning("MAX_BATCH_SIZE=%r is not an integer; chunking at the default %d", raw, MAX_BATCH_SIZE)
            return MAX_BATCH_SIZE
        if parsed > 0:
            return parsed
        logger.warning("MAX_BATCH_SIZE=%d is not positive; chunking at the default %d", parsed, MAX_BATCH_SIZE)
    return MAX_BATCH_SIZE


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
        max_batch_size: int | None = None,
    ) -> None:
        # Strip trailing slash so we can append paths without doubling up.
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout_seconds
        self._service_token = (service_token if service_token is not None else resolve_service_token()).strip()
        resolved_batch_size = max_batch_size if max_batch_size is not None else resolve_max_batch_size()
        if resolved_batch_size < 1:
            raise ValueError(f"max_batch_size must be >= 1, got {resolved_batch_size}")
        self._max_batch_size = resolved_batch_size
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

        If the event list exceeds MAX_BATCH_SIZE, it is split into chunks and
        pushed separately. The returned counts are summed across all chunks.
        This prevents oversized polls from being refused with HTTP 413.
        """
        if not events:
            return {"accepted": 0, "rejected": 0}

        # Chunk the event list if it exceeds the ingest service's cap. Each
        # chunk is pushed separately and the accepted/rejected counts are
        # summed, so the scheduler's "advance only if everything was accepted"
        # rule continues to work unchanged.
        #
        # A chunk that is refused raises out of the loop, which is deliberate:
        # the remaining chunks are not attempted, and the scheduler withholds
        # both the checkpoint and the queue acknowledgements. Chunks already
        # accepted before the refusal are redelivered on the next poll, so the
        # cost of a mid-batch failure is duplicates, never a gap — the same
        # trade the scheduler already makes between its checkpoint write and
        # its acks.
        total_accepted = 0
        total_rejected = 0
        chunk_size = self._max_batch_size

        for i in range(0, len(events), chunk_size):
            chunk = events[i : i + chunk_size]
            result = await self._push_chunk(
                tenant_id=tenant_id,
                connector_id=connector_id,
                connector_type=connector_type,
                events=chunk,
                source_format=source_format,
            )
            total_accepted += int(result.get("accepted", 0) or 0)
            total_rejected += int(result.get("rejected", 0) or 0)

        return {"accepted": total_accepted, "rejected": total_rejected}

    async def _push_chunk(
        self,
        *,
        tenant_id: uuid.UUID | str,
        connector_id: uuid.UUID | str,
        connector_type: str,
        events: list[dict[str, Any]],
        source_format: str,
    ) -> dict[str, Any]:
        """Push one chunk of events (at most MAX_BATCH_SIZE) to ingest.

        This is the actual network call that push_events delegates to. It is
        split out so chunking logic can live in push_events while the HTTP
        shape stays here, testable independently.
        """
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
            # A 413 on a single chunk stays a hard error: chunking must not
            # make the ingest cap unreachable by retrying or dropping it.
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


__all__ = ["MAX_BATCH_SIZE", "IngestClient", "IngestClientError", "resolve_max_batch_size", "resolve_service_token"]
