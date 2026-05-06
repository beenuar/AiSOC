"""Federated SIEM search — query Splunk / Sentinel / Elastic in one call.

This endpoint is the API-side half of the ``w3-fed`` federated search
capability. It accepts a single ``UnifiedQuery`` (free-text + indicator
list + time window), fans it out in parallel to every enabled connector
instance whose backend speaks SPL / KQL / ES|QL, and merges the rows.

Why fan out from the API service rather than the agent?

* The credential vault lives in the API service. Decryption needs to
  happen here so the connectors microservice never sees ciphertext.
* The connector instances table is here, with tenant-scoped RLS. The
  agent shouldn't know which tenant has which SIEM — it just submits a
  ``UnifiedQuery`` to ``/api/v1/federated/search`` and gets merged rows
  back tagged with their source.
* Splunk / Sentinel / Elastic each have their own quirks (KQL needs a
  workspace id, SPL needs a search endpoint). Hiding all of that behind
  one endpoint is the whole point.

Trust boundary mirrors ``test_existing_connector``: stored
``auth_config`` is decrypted via the vault and forwarded to the
stateless ``services/connectors`` ``POST /connectors/{type}/query``
endpoint over the internal Docker / VPC network. Plaintext credentials
never round-trip back to the caller.

Per-source isolation: a single misbehaving SIEM (slow, 5xx, 401) must
not block the rest of the federated answer. We run each backend call
inside its own try/except and return a ``sources[]`` array describing
the verdict per backend so the UI can show "Splunk OK · Sentinel
timeout · Elastic OK" rather than a single 502.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from typing import Annotated, Any

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.api.v1.deps import AuthUser, DBSession, require_permission
from app.core.config import settings
from app.models.audit import AuditLog
from app.models.connector import Connector
from app.security.credential_vault import CredentialVaultError, get_vault

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/federated", tags=["federated-search"])


# Connector types whose ``BaseConnector.supports_federated_search`` is
# True in the connectors microservice today. We pre-filter on this set
# so we don't bother decrypting credentials for, say, an EDR connector
# that has nothing to do with SIEM search. The connectors microservice
# will still return 501 for any type that hasn't opted in, so this list
# is a performance hint, not a security boundary.
FEDERATED_CAPABLE_TYPES: frozenset[str] = frozenset(
    {
        "splunk",
        "microsoft_sentinel",
        "elastic",
    }
)


# ---------------------------------------------------------------- request/response


class IndicatorPayload(BaseModel):
    """One ``field <op> value`` triple in a federated query.

    Mirrors ``services.connectors.app.federated.query.Indicator`` but
    expressed as Pydantic so FastAPI can render OpenAPI for the wizard
    + the SDK. The connectors microservice re-validates with
    ``parse_unified_query`` before any translator runs, so this model
    is intentionally permissive on ``value``.
    """

    field: str = Field(min_length=1, max_length=200)
    operator: str = Field(min_length=1, max_length=20)
    value: Any


class FederatedSearchRequest(BaseModel):
    """Top-level federated search payload.

    ``connector_ids`` lets the caller scope the fan-out to specific
    instances (e.g. "only my prod Splunk, not the staging Sentinel").
    Omit it to query every federated-capable connector the tenant has
    enabled.

    ``per_backend_timeout_seconds`` caps how long any one SIEM gets
    before we move on. Default is half the configured connectors-service
    timeout — long enough for a real SIEM round-trip, short enough that
    a single dead backend doesn't block the merged answer.
    """

    free_text: str = Field(default="", max_length=2_000)
    indicators: list[IndicatorPayload] = Field(default_factory=list)
    since_seconds: int = Field(default=3600, gt=0, le=7 * 24 * 3600)
    limit: int = Field(default=100, gt=0, le=1000)
    connector_ids: list[uuid.UUID] | None = None
    per_backend_timeout_seconds: float | None = Field(default=None, gt=0, le=120)


class SourceVerdict(BaseModel):
    """Per-backend outcome for a federated call.

    ``status`` is one of:
      * ``ok`` — backend returned rows (possibly zero).
      * ``error`` — backend raised something we caught; ``error`` field
        carries the human message. Other backends may still have
        succeeded.
      * ``unsupported`` — connector type doesn't speak federated search
        (kept for forward-compat; today we pre-filter so this is rare).
    """

    connector_id: uuid.UUID
    connector_name: str
    connector_type: str
    status: str
    row_count: int = 0
    duration_ms: int = 0
    error: str | None = None


class FederatedSearchResponse(BaseModel):
    rows: list[dict[str, Any]]
    row_count: int
    sources: list[SourceVerdict]
    truncated: bool = Field(
        default=False,
        description="True when the merged row count was capped at ``limit`` after fan-out.",
    )


class FederatedBackend(BaseModel):
    """Read-only projection of a connector instance eligible for fan-out."""

    connector_id: uuid.UUID
    connector_type: str
    name: str
    health_status: str
    is_enabled: bool


class FederatedBackendsResponse(BaseModel):
    backends: list[FederatedBackend]


# ----------------------------------------------------------------------- helpers


def _connectors_query_url(connector_type: str) -> str:
    base = settings.CONNECTORS_SERVICE_URL.rstrip("/")
    return f"{base}/api/v1/connectors/{connector_type}/query"


def _ensure_feature_enabled() -> None:
    if not settings.AISOC_FEATURE_FED_SEARCH:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="federated search is disabled (AISOC_FEATURE_FED_SEARCH=false)",
        )


async def _fetch_target_connectors(
    db: DBSession,
    tenant_id: uuid.UUID,
    requested_ids: list[uuid.UUID] | None,
) -> list[Connector]:
    """Resolve which connector instances the request will fan out to.

    Filters: tenant-scoped, ``is_enabled=True``, and connector_type in
    the federated-capable set. If the caller passed ``connector_ids``,
    we further restrict to that subset and 404 the call if any of them
    is missing or ineligible (we don't silently drop, because a typo
    in a connector_id should be loud).
    """
    stmt = select(Connector).where(
        Connector.tenant_id == tenant_id,
        Connector.is_enabled.is_(True),
        Connector.connector_type.in_(FEDERATED_CAPABLE_TYPES),
    )
    if requested_ids:
        stmt = stmt.where(Connector.id.in_(requested_ids))

    result = await db.execute(stmt)
    rows = list(result.scalars().all())

    if requested_ids:
        # Loud failure on missing/ineligible IDs — see docstring.
        found_ids = {row.id for row in rows}
        missing = [str(rid) for rid in requested_ids if rid not in found_ids]
        if missing:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=("connector_ids not found, not enabled, or not federated-capable: " + ", ".join(missing)),
            )

    return rows


async def _query_one_backend(
    connector: Connector,
    query_payload: dict[str, Any],
    timeout: httpx.Timeout,
) -> tuple[SourceVerdict, list[dict[str, Any]]]:
    """Decrypt creds, POST to the connectors microservice, tag rows.

    Never raises — returns a verdict + (possibly empty) rows. The point
    is that one bad SIEM can't cancel the federated answer.
    """
    started = time.monotonic()

    try:
        decrypted_auth = get_vault().decrypt_dict(connector.auth_config or {})
    except CredentialVaultError as exc:
        return (
            SourceVerdict(
                connector_id=connector.id,
                connector_name=connector.name,
                connector_type=connector.connector_type,
                status="error",
                duration_ms=int((time.monotonic() - started) * 1000),
                error=f"credential decryption failed: {exc}",
            ),
            [],
        )

    payload = {
        "auth_config": decrypted_auth,
        "connector_config": connector.connector_config or {},
        "query": query_payload,
    }
    url = _connectors_query_url(connector.connector_type)

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(url, json=payload)
    except httpx.HTTPError as exc:
        logger.warning(
            "federated.query.unreachable connector=%s url=%s err=%s",
            connector.id,
            url,
            exc,
        )
        return (
            SourceVerdict(
                connector_id=connector.id,
                connector_name=connector.name,
                connector_type=connector.connector_type,
                status="error",
                duration_ms=int((time.monotonic() - started) * 1000),
                error=f"connectors service unreachable: {exc}",
            ),
            [],
        )

    if resp.status_code == status.HTTP_501_NOT_IMPLEMENTED:
        return (
            SourceVerdict(
                connector_id=connector.id,
                connector_name=connector.name,
                connector_type=connector.connector_type,
                status="unsupported",
                duration_ms=int((time.monotonic() - started) * 1000),
                error=resp.text or "connector does not support federated search",
            ),
            [],
        )

    if resp.status_code >= 400:
        # Bubble up the backend's diagnostic but keep status=error so
        # the rest of the federated answer survives.
        try:
            detail = resp.json().get("detail") or resp.text
        except ValueError:
            detail = resp.text
        return (
            SourceVerdict(
                connector_id=connector.id,
                connector_name=connector.name,
                connector_type=connector.connector_type,
                status="error",
                duration_ms=int((time.monotonic() - started) * 1000),
                error=f"backend {resp.status_code}: {detail}",
            ),
            [],
        )

    body = resp.json() if resp.content else {}
    raw_rows = body.get("rows") or []
    if not isinstance(raw_rows, list):
        raw_rows = []

    # Tag each row with its source so the merged response is unambiguous.
    # We use a leading underscore so the field is unlikely to collide
    # with anything the SIEM emitted.
    source_tag = {
        "connector_id": str(connector.id),
        "connector_name": connector.name,
        "connector_type": connector.connector_type,
    }
    tagged_rows = []
    for row in raw_rows:
        if isinstance(row, dict):
            # Don't overwrite a real ``_aisoc_source`` — extremely
            # unlikely in practice but cheap to guard.
            row.setdefault("_aisoc_source", source_tag)
            tagged_rows.append(row)
        else:
            # Defensive: wrap non-dict rows so the merge stays homogeneous.
            tagged_rows.append({"value": row, "_aisoc_source": source_tag})

    return (
        SourceVerdict(
            connector_id=connector.id,
            connector_name=connector.name,
            connector_type=connector.connector_type,
            status="ok",
            row_count=len(tagged_rows),
            duration_ms=int((time.monotonic() - started) * 1000),
        ),
        tagged_rows,
    )


def _audit_event(
    *,
    tenant_id: uuid.UUID,
    actor_id: uuid.UUID | None,
    actor_email: str | None,
    indicator_fields: list[str],
    sources: list[SourceVerdict],
    row_count: int,
    since_seconds: int,
) -> AuditLog:
    """Build an audit row for the search.

    We deliberately log only the *shape* of the query (which fields were
    filtered, which connectors were queried, how many rows came back),
    never the values. A federated query against a competitor's SaaS
    might contain regulated identifiers in the indicator values; the
    audit log is shared across the tenant and shouldn't carry them.
    """
    return AuditLog(
        tenant_id=tenant_id,
        actor_id=actor_id,
        actor_email=actor_email,
        action="federated_search",
        resource="federated",
        resource_id=None,
        changes=None,
        metadata_={
            "indicator_fields": indicator_fields,
            "since_seconds": since_seconds,
            "row_count": row_count,
            "sources": [
                {
                    "connector_id": str(s.connector_id),
                    "connector_type": s.connector_type,
                    "status": s.status,
                    "row_count": s.row_count,
                    "duration_ms": s.duration_ms,
                }
                for s in sources
            ],
        },
    )


# ---------------------------------------------------------------------- endpoints


@router.get("/backends", response_model=FederatedBackendsResponse)
async def list_federated_backends(
    current_user: Annotated[AuthUser, Depends(require_permission("connectors:read"))],
    db: DBSession,
) -> FederatedBackendsResponse:
    """List the connector instances that ``POST /search`` would fan out to.

    Useful for the wizard preview ("you'll search 1 Splunk + 1 Elastic")
    and for the SDK to build sensible default ``connector_ids`` lists.
    """
    _ensure_feature_enabled()

    rows = await _fetch_target_connectors(db, current_user.tenant_id, requested_ids=None)
    return FederatedBackendsResponse(
        backends=[
            FederatedBackend(
                connector_id=row.id,
                connector_type=row.connector_type,
                name=row.name,
                health_status=row.health_status,
                is_enabled=row.is_enabled,
            )
            for row in rows
        ]
    )


@router.post("/search", response_model=FederatedSearchResponse)
async def federated_search(
    request: FederatedSearchRequest,
    current_user: Annotated[AuthUser, Depends(require_permission("connectors:read"))],
    db: DBSession,
) -> FederatedSearchResponse:
    """Run a unified query across every federated-capable connector.

    Per-backend errors do not fail the call. The response always
    carries a ``sources[]`` array describing the verdict for each
    backend that was attempted; the merged ``rows[]`` only contains
    rows from the ``ok`` sources.
    """
    _ensure_feature_enabled()

    if not request.free_text.strip() and not request.indicators:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="query must include free_text or at least one indicator",
        )

    targets = await _fetch_target_connectors(db, current_user.tenant_id, request.connector_ids)
    if not targets:
        # No federated-capable connectors configured: don't 404, return
        # an empty merged result with empty sources[]. Lets the caller
        # treat "no SIEMs" the same as "no results" without a special
        # error path.
        return FederatedSearchResponse(rows=[], row_count=0, sources=[], truncated=False)

    query_payload = {
        "free_text": request.free_text,
        "indicators": [i.model_dump() for i in request.indicators],
        "since_seconds": request.since_seconds,
        "limit": request.limit,
    }

    timeout_seconds = (
        request.per_backend_timeout_seconds
        if request.per_backend_timeout_seconds is not None
        else settings.CONNECTORS_SERVICE_TIMEOUT_SECONDS
    )
    timeout = httpx.Timeout(
        timeout_seconds,
        connect=min(5.0, timeout_seconds),
    )

    fan_out = await asyncio.gather(
        *(_query_one_backend(connector, query_payload, timeout) for connector in targets),
        return_exceptions=False,
    )

    sources: list[SourceVerdict] = []
    merged: list[dict[str, Any]] = []
    for verdict, rows in fan_out:
        sources.append(verdict)
        merged.extend(rows)

    truncated = False
    if len(merged) > request.limit:
        merged = merged[: request.limit]
        truncated = True

    # Audit (best-effort: a logging failure shouldn't fail the search).
    try:
        db.add(
            _audit_event(
                tenant_id=current_user.tenant_id,
                actor_id=current_user.user_id,
                actor_email=current_user.email,
                indicator_fields=[i.field for i in request.indicators],
                sources=sources,
                row_count=len(merged),
                since_seconds=request.since_seconds,
            )
        )
        await db.commit()
    except Exception:
        logger.exception("federated.search.audit_log_failed tenant=%s", current_user.tenant_id)
        await db.rollback()

    logger.info(
        "federated.search.completed tenant=%s sources=%d rows=%d truncated=%s",
        current_user.tenant_id,
        len(sources),
        len(merged),
        truncated,
    )
    return FederatedSearchResponse(
        rows=merged,
        row_count=len(merged),
        sources=sources,
        truncated=truncated,
    )
