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
    Return the supported provider list + per-provider coverage status.
    The UI uses this to render the provider switcher.

``GET /v1/identity/{principal_id}/effective-permissions?provider=...``
    Return a :class:`ResolverResult` JSON envelope.

All five resolvers — AWS, Azure, GCP, Okta and Google Workspace — are
implemented and report ``coverage: "full"``. This docstring described Azure,
GCP, Okta and GWS as scaffolds returning HTTP 501 long after they stopped
being scaffolds, and the ``NotImplementedError`` branch below has been
unreachable for as long.

What *is* still limited is the **snapshot**, not the resolver. A resolver is a
pure function over a provider snapshot, and only Okta's is assembled from a
live connector today — the other four expect a connector to answer the
``__posture_snapshot__`` sentinel, and no connector implements it. With
``AISOC_EFFECTIVE_PERMISSIONS_LIVE=1`` those four therefore return **412**
("no policy snapshot ingested yet") rather than a fabricated snapshot. See
``app/services/effective_permissions/posture_loader.py``.

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
from typing import Annotated, Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import CurrentUser, require_permission
from app.api.v1.endpoints.auth import get_current_user
from app.core.config import settings
from app.db.database import get_db
from app.models.connector import Connector
from app.security.credential_vault import get_vault
from app.services.effective_permissions.base import ResolverError
from app.services.effective_permissions.posture_loader import (
    PROVIDER_CONNECTOR,
    CollectedSnapshot,
    HttpResourceConfigFetcher,
    collect_snapshot,
)
from app.services.effective_permissions.service import (
    SUPPORTED_PROVIDERS,
    cache_result_into_neo4j,
    resolve_effective_permissions,
)
from app.services.posture_store import save_snapshot

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/identity", tags=["identity-effective-permissions"])

#: A caller allowed to resolve an identity's authorization posture.
#:
#: Declared as a module-level alias rather than inline in the signature, which
#: is the idiom the rest of the endpoint package uses and the only form ruff's
#: B008 accepts — a ``Depends(require_permission(...))`` written as an argument
#: default is evaluated once at import either way, and naming it here keeps the
#: permission visible beside the router it guards.
IdentityReader = Annotated[CurrentUser, Depends(require_permission("identity:read"))]

# Sentinel for the "dry-run with inline snapshot" feature flag. Off by default.
_INLINE_SNAPSHOT_FLAG = "AISOC_ALLOW_INLINE_SNAPSHOT"
# Phase C2 — live posture collection via the connectors service. Off by default
# so a deployment without connectors keeps the prior 412 "no snapshot" behaviour.
_LIVE_POSTURE_FLAG = "AISOC_EFFECTIVE_PERMISSIONS_LIVE"


async def _record_snapshot(
    db: AsyncSession,
    tenant_id: Any,
    provider: str,
    connector_type: str,
    connector_instance_id: Any,
    collected: CollectedSnapshot,
) -> None:
    """Persist a collected posture as a version, best-effort.

    Deliberately swallowing: a tenant asking "what can this identity do"
    should get their answer even if the archive write fails. The failure is
    logged at ``warning`` with the provider named, because a store that has
    silently stopped accepting versions looks exactly like a tenant who has
    not collected yet, and the point-in-time read would then answer ``None``
    for a reason no reader could distinguish from the honest one.
    """
    try:
        await save_snapshot(
            db,
            tenant_id=tenant_id,
            provider=provider,
            connector_id=connector_type,
            connector_instance_id=connector_instance_id,
            snapshot=collected.snapshot,
            partial=collected.partial,
            collection_notes=list(collected.notes),
        )
        await db.commit()
    except Exception as exc:  # noqa: BLE001 — archiving must not fail the read
        await db.rollback()
        logger.warning(
            "effective_permissions.snapshot_not_recorded provider=%s: %s",
            # Caller-influenced; sanitised inline because the taint tracker
            # does not follow a helper (the py/log-injection house pattern).
            str(provider).replace("\r", "").replace("\n", " ")[:64],
            str(exc).replace("\r", "").replace("\n", " ")[:200],
        )


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
        collected = await collect_snapshot(provider, principal_id, fetcher=fetcher)
        if not collected:
            return None
        # Record the version. The resolver below answers from the snapshot in
        # hand, but an alert is triaged minutes to days after the event it
        # describes, and "what could this identity do **when it acted**" can
        # only be answered from a version that was stored while it was true.
        # Okta is excluded because its snapshot is assembled per principal
        # rather than per estate — storing one would make the live row mean
        # "the posture of whoever was looked up last".
        if provider != "okta":
            await _record_snapshot(db, tenant_id, provider, connector_type, row.id, collected)
        return collected.snapshot
    except Exception as exc:  # noqa: BLE001 — live collection is best-effort
        logger.warning("effective_permissions.live_snapshot_failed: %s", str(exc).replace("\n", " ")[:200])
        return None


@router.get(
    "/effective-permissions/providers",
    summary="List supported effective-permissions providers",
)
async def list_providers(
    _user: CurrentUser = Depends(get_current_user),
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
    current_user: IdentityReader,
    provider: str = Query(
        ...,
        description="Provider to resolve against (aws|azure|gcp|okta|gws).",
    ),
    snapshot_b64: str | None = Query(
        None,
        description=(
            "Optional base64-encoded JSON snapshot for dry-run resolution. Only honoured when AISOC_ALLOW_INLINE_SNAPSHOT=1 is set."
        ),
    ),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Resolve and return the effective-permissions envelope.

    Requires ``identity:read``. Cache write is dispatched as a FastAPI
    ``BackgroundTask`` so the request returns as soon as the resolver
    finishes — the UI never waits on Neo4j.
    """
    # Why the permission, and why not the check the report asked for.
    #
    # Kept out of the docstring because FastAPI publishes that verbatim into
    # docs/openapi.yaml, and a reader of the API reference does not need an
    # advisory's history — but the next reader of this function does.
    #
    # This bound `get_current_user` alone and made no authorization decision
    # (GHSA-q23c-9pj3-cw75). The tenant was always derived correctly from the
    # credential, so it was never a cross-tenant defect — but *every* role in
    # the tenant reached it, `viewer` included, and so did an API key scoped
    # to something unrelated, because a key's scopes are only ever read by
    # `require_permission` and this route never called it. What comes back is
    # an identity's allowed and denied actions, resource ids and ARNs, and the
    # policy chain behind them; with `AISOC_EFFECTIVE_PERMISSIONS_LIVE=1` the
    # server also spends the tenant's own stored connector credential to
    # collect it.
    #
    # The reporter recommended an object-level check — may this caller inspect
    # *that* `principal_id`. Deliberately not that: nothing in this product
    # relates a console user to a provider principal (`users` has no such
    # column, and `identity_links` relates two *provider* identifiers to each
    # other), so there is no relation to consult and the check would reduce to
    # "is this your own id", which no caller could satisfy. Inspecting any
    # identity in the tenant is the job; the control is who may do it at all.
    #
    # A refusal here is 403, not 404: no id is being probed, the caller is
    # authenticated inside the right tenant, and "you may not do this"
    # discloses nothing they did not already know. The 404 convention belongs
    # to the routes where the id itself is the secret.

    if provider not in SUPPORTED_PROVIDERS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(f"unknown provider {provider!r}; supported: {sorted(SUPPORTED_PROVIDERS)}"),
        )

    snapshot: dict[str, Any] | None = None
    if snapshot_b64:
        if os.getenv(_INLINE_SNAPSHOT_FLAG, "0") != "1":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"inline snapshots are disabled; set {_INLINE_SNAPSHOT_FLAG}=1 to dry-run.",
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
        # Kept as a guard, not as a documented behaviour. Every registered
        # resolver is implemented, so reaching this means a new provider was
        # added to SUPPORTED_PROVIDERS without one — which should surface
        # loudly rather than as an empty result the UI renders as "no access".
        logger.error(
            "effective_permissions.resolver_not_implemented provider=%s err=%s",
            str(provider).replace("\r", "").replace("\n", " ")[:64],
            str(exc).replace("\r", "").replace("\n", " ")[:200],
        )
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
