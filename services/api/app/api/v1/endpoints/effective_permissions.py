"""Effective-permissions API endpoint (T3.2).

Single read-side surface for the "what can this principal do?" query that
powers the Cytoscape UI at ``/identity/permissions``. The endpoint never
mutates state synchronously — it computes the resolver result, returns it,
and best-effort caches the materialised edges into Neo4j as a background
task so subsequent queries (and the realtime graph stream from T1.4) can
hop on the cached edges without re-running the resolver.

Routes
------

``GET /v1/identity/effective-permissions/providers``
    Return the supported provider list + per-provider coverage status. The
    UI uses this to render the provider switcher and grey-out the
    scaffolded providers.

``GET /v1/identity/{principal_id}/effective-permissions?provider=...``
    Return a :class:`ResolverResult` JSON envelope. Scaffolded providers
    (Azure, GCP, Okta, GWS) return HTTP 501 with the same envelope shape so
    the UI can still render the empty state.

The endpoint deliberately accepts an optional ``snapshot_b64`` query param
(base64-encoded JSON) so an analyst can dry-run the resolver against a
hypothetical policy bundle without touching the live snapshot store. The
helper is hidden behind a feature flag (``AISOC_ALLOW_INLINE_SNAPSHOT``) so
production deployments don't accept arbitrary policy JSON over the wire.
"""

from __future__ import annotations

import base64
import json
import logging
import os
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.endpoints.auth import get_current_user
from app.core.config import settings
from app.db.database import get_db
from app.models.connector import Connector
from app.models.tenant import User
from app.security.credential_vault import get_vault
from app.services.effective_permissions.base import ResolverError
from app.services.effective_permissions.posture_loader import (
    PROVIDER_CONNECTOR,
    HttpResourceConfigFetcher,
    collect_snapshot,
)
from app.services.effective_permissions.service import (
    SUPPORTED_PROVIDERS,
    cache_result_into_neo4j,
    resolve_effective_permissions,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/identity", tags=["identity-effective-permissions"])

# Sentinel for the "dry-run with inline snapshot" feature flag. Off by default.
_INLINE_SNAPSHOT_FLAG = "AISOC_ALLOW_INLINE_SNAPSHOT"
# Phase C2 — live posture collection via the connectors service. Off by default
# so a deployment without connectors keeps the prior 412 "no snapshot" behaviour.
_LIVE_POSTURE_FLAG = "AISOC_EFFECTIVE_PERMISSIONS_LIVE"


async def _maybe_live_snapshot(db: AsyncSession, tenant_id: Any, provider: str, principal_id: str) -> dict[str, Any] | None:
    """Collect a live posture snapshot from the tenant's connector, or None.

    Gated by ``AISOC_EFFECTIVE_PERMISSIONS_LIVE=1``. Looks up the enabled
    connector instance backing ``provider``, decrypts its ``auth_config`` via
    the vault, and asks the connectors service for the posture snapshot. Any
    failure returns None so the caller falls back to the 412 "no snapshot" path.
    """
    if os.getenv(_LIVE_POSTURE_FLAG, "0") != "1":
        return None
    connector_type = PROVIDER_CONNECTOR.get(provider)
    if connector_type is None:
        return None
    try:
        row = (
            await db.execute(
                select(Connector).where(
                    Connector.tenant_id == tenant_id,
                    Connector.connector_type == connector_type,
                    Connector.is_enabled.is_(True),
                )
            )
        ).scalar_one_or_none()
        if row is None:
            return None
        auth = get_vault().decrypt_dict(row.auth_config or {})
        fetcher = HttpResourceConfigFetcher(settings.CONNECTORS_SERVICE_URL, auth, row.connector_config or {})
        snapshot = await collect_snapshot(provider, principal_id, fetcher=fetcher)
        return snapshot or None
    except Exception as exc:  # noqa: BLE001 — live collection is best-effort
        logger.warning("effective_permissions.live_snapshot_failed: %s", str(exc).replace("\n", " ")[:200])
        return None


@router.get(
    "/effective-permissions/providers",
    summary="List supported effective-permissions providers",
)
async def list_providers(
    _user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Return ``{"providers": [{"name", "coverage"}, ...]}``.

    The UI calls this once on mount to render the provider switcher and to
    grey out scaffolded providers.
    """

    providers = []
    for name, cls in sorted(SUPPORTED_PROVIDERS.items()):
        providers.append({"name": name, "coverage": cls.coverage})
    return {"providers": providers}


@router.get(
    "/{principal_id}/effective-permissions",
    summary="Resolve effective permissions for a principal",
)
async def get_effective_permissions(
    principal_id: str,
    background_tasks: BackgroundTasks,
    provider: str = Query(
        ...,
        description="Provider to resolve against (aws|azure|gcp|okta|gws).",
    ),
    snapshot_b64: str | None = Query(
        None,
        description=(
            "Optional base64-encoded JSON snapshot for dry-run resolution. " "Only honoured when AISOC_ALLOW_INLINE_SNAPSHOT=1 is set."
        ),
    ),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Resolve and return the effective-permissions envelope.

    Cache write is dispatched as a FastAPI ``BackgroundTask`` so the request
    returns as soon as the resolver finishes — the UI never waits on Neo4j.
    """

    if provider not in SUPPORTED_PROVIDERS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(f"unknown provider {provider!r}; " f"supported: {sorted(SUPPORTED_PROVIDERS)}"),
        )

    snapshot: dict[str, Any] | None = None
    if snapshot_b64:
        if os.getenv(_INLINE_SNAPSHOT_FLAG, "0") != "1":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="inline snapshots are disabled; set " f"{_INLINE_SNAPSHOT_FLAG}=1 to dry-run.",
            )
        try:
            snapshot = json.loads(base64.b64decode(snapshot_b64).decode("utf-8"))
        except (ValueError, json.JSONDecodeError) as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"snapshot_b64 is not valid base64-encoded JSON: {exc}",
            ) from exc

    # Phase C2 — when no inline snapshot was supplied, try live posture
    # collection from the tenant's connector (gated by
    # AISOC_EFFECTIVE_PERMISSIONS_LIVE). Falls through to the 412 path on miss.
    if snapshot is None:
        snapshot = await _maybe_live_snapshot(db, current_user.tenant_id, provider, principal_id)

    try:
        result = resolve_effective_permissions(
            provider=provider,
            principal_id=principal_id,
            snapshot=snapshot,
        )
    except NotImplementedError as exc:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail={
                "message": str(exc),
                "provider": provider,
                "coverage": "scaffold",
            },
        ) from exc
    except ResolverError as exc:
        raise HTTPException(
            status_code=status.HTTP_412_PRECONDITION_FAILED,
            detail=f"resolver could not produce a result: {exc}",
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    if result.decisions:
        background_tasks.add_task(cache_result_into_neo4j, result)
    return result.to_dict()
