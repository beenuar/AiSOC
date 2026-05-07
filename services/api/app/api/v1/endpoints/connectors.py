"""Connector management endpoints.

This module is the **operator-facing** half of the click-and-connect
connector platform. It speaks to two parties:

* The frontend AddConnector wizard, which needs the catalog of available
  connectors, their configuration schemas, full CRUD over connector
  instances scoped to the current tenant, and a way to "Test connection"
  before saving.
* The stateless ``services/connectors`` microservice, which owns the
  catalog, schemas, and the actual ``test_connection()`` runtimes for
  every concrete connector class.

Why this lives in the API service rather than connectors microservice:

* The API service owns Postgres and tenant scoping. Storing connector
  instance rows next to other tenant resources is the obvious place.
* The API service owns the credential vault. Cleartext credentials must
  *never* leave this service except inbound to the connectors microservice
  for an active "test connection" call, and only over the internal
  Docker / VPC network.
* The connectors microservice should stay stateless so it can scale
  horizontally and be redeployed without touching the database.

Tenant scoping invariants enforced here:

* Every read query filters on ``Connector.tenant_id == current_user.tenant_id``.
* Every write goes through ``require_permission("connectors:write")``.
* The catalog endpoint is tenant-agnostic — it advertises the build's
  capabilities, not any specific tenant's instances — so it lives behind
  ``connectors:read`` so unauthenticated discovery is impossible.
"""

from __future__ import annotations

import logging
import re
import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

# Connector type IDs are restricted to alphanumeric, hyphens, and underscores.
# This prevents path-traversal / partial-SSRF via user-supplied connector_type.
_CONNECTOR_TYPE_RE = re.compile(r"^[a-zA-Z0-9_\-]{1,100}$")

# Strip ASCII control characters (incl. newlines) before writing to log
# records — prevents log-injection when values originate from user input.
_LOG_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")

# Inverse of _CONNECTOR_TYPE_RE — remove any character NOT in the safe set.
# Reconstructing the value this way breaks CodeQL's taint trace so the sanitised
# string is provably free of control characters and path-separator sequences.
_CONNECTOR_TYPE_UNSAFE_CHARS_RE = re.compile(r"[^a-zA-Z0-9_\-]")


def _safe_log_val(value: str) -> str:
    """Return *value* with ASCII control characters removed, safe for logging."""
    return _LOG_CTRL_RE.sub("", value)


def _safe_connector_type(value: str) -> str:
    """Reconstruct connector_type keeping only allowed chars; breaks taint trace."""
    return _CONNECTOR_TYPE_UNSAFE_CHARS_RE.sub("", value)[:100]

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select, update

from app.api.v1.deps import AuthUser, DBSession, require_permission
from app.core.config import settings
from app.models.connector import Connector
from app.security.credential_vault import CredentialVaultError, get_vault

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/connectors", tags=["connectors"])


# --------------------------------------------------------------- Pydantic schemas


class ConnectorResponse(BaseModel):
    """Public projection of a ``Connector`` row.

    ``auth_config`` is intentionally **omitted**. Even decrypted credentials
    should never round-trip back to the wizard — the user typed them once
    and they belong inside the vault from then on. Wizard-driven re-edit
    flows reset specific secret fields rather than reading the existing
    ones.

    ``connector_config`` *is* included because it holds non-secret runtime
    knobs (poll interval, region, log filters) that the wizard surfaces
    so an operator can tweak them without re-pasting credentials.
    """

    id: uuid.UUID
    tenant_id: uuid.UUID
    name: str
    connector_type: str
    category: str
    is_enabled: bool
    connector_config: dict[str, Any]
    health_status: str
    last_health_check: datetime | None
    last_sync: datetime | None
    events_ingested: int
    error_count: int
    tags: list
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class CreateConnectorRequest(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    connector_type: str = Field(min_length=1, max_length=100)
    category: str | None = Field(
        default=None,
        max_length=50,
        description="Optional override; defaults to the catalog entry's category.",
    )
    auth_config: dict[str, Any] = Field(default_factory=dict)
    connector_config: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)


class UpdateConnectorRequest(BaseModel):
    name: str | None = None
    is_enabled: bool | None = None
    auth_config: dict[str, Any] | None = None
    connector_config: dict[str, Any] | None = None
    tags: list[str] | None = None


class TestConnectionRequest(BaseModel):
    """Inline credential-test payload used by the wizard *before* saving.

    The wizard collects credentials in-browser, calls this endpoint, and
    only persists the connector if the test succeeds. We intentionally
    do *not* let the wizard test against an existing instance — that's
    a separate path (:func:`test_existing_connector`) that decrypts the
    stored creds first.
    """

    connector_type: str = Field(min_length=1, max_length=100)
    auth_config: dict[str, Any] = Field(default_factory=dict)
    connector_config: dict[str, Any] = Field(default_factory=dict)


# ------------------------------------------------------------- internal helpers


_CATALOG_TIMEOUT = httpx.Timeout(
    settings.CONNECTORS_SERVICE_TIMEOUT_SECONDS,
    connect=min(5.0, settings.CONNECTORS_SERVICE_TIMEOUT_SECONDS),
)


def _connectors_service_url(path: str) -> str:
    """Build a URL into the stateless connectors microservice."""
    base = settings.CONNECTORS_SERVICE_URL.rstrip("/")
    suffix = path if path.startswith("/") else f"/{path}"
    return f"{base}/api/v1{suffix}"


async def _fetch_catalog() -> list[dict[str, Any]]:
    """Pull the connector catalog from the connectors microservice.

    Raises a clear 503 if the microservice is unreachable. We don't cache
    here on purpose: catalog lookups are infrequent (a wizard open per
    operator), and a stale cache would make the "I just added a connector
    class and redeployed" feedback loop confusing.
    """
    url = _connectors_service_url("/connectors/schemas")
    try:
        async with httpx.AsyncClient(timeout=_CATALOG_TIMEOUT) as client:
            resp = await client.get(url)
            resp.raise_for_status()
    except httpx.HTTPError as exc:
        logger.warning("connectors_service.catalog.unreachable url=%s error_type=%s", url, type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="connectors service is unavailable; cannot list connector catalog",
        ) from exc

    body = resp.json()
    schemas = body.get("schemas") or []
    if not isinstance(schemas, list):
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="connectors service returned a malformed catalog",
        )
    return schemas


async def _validate_connector_type(connector_type: str) -> dict[str, Any]:
    """Return the catalog entry for ``connector_type`` or raise 422.

    Validating against the live catalog (rather than a hand-maintained
    enum) means a freshly-added connector is automatically usable as soon
    as the connectors microservice picks it up — no API-side allowlist to
    keep in sync.
    """
    catalog = await _fetch_catalog()
    for entry in catalog:
        if entry.get("connector_id") == connector_type:
            return entry
    known = sorted(e.get("connector_id", "?") for e in catalog)
    raise HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail=f"unknown connector_type '{connector_type}'. Known types: {', '.join(known) or '(none)'}",
    )


async def _proxy_test_connection(
    connector_type: str,
    auth_config: dict[str, Any],
    connector_config: dict[str, Any],
) -> dict[str, Any]:
    """POST plaintext credentials at the stateless test endpoint.

    The credentials cross the trust boundary between the API service and
    the connectors microservice **only here**. We expect that boundary to
    be a Docker / k8s internal network; if you're putting the connectors
    service on the public internet, terminate TLS in front of it and
    add a shared-secret header (mirroring how the realtime push proxy in
    this codebase does it).
    """
    if not _CONNECTOR_TYPE_RE.match(connector_type):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="connector_type contains invalid characters",
        )
    url = _connectors_service_url(f"/connectors/{connector_type}/test")
    payload = {
        "auth_config": auth_config,
        "connector_config": connector_config,
    }
    try:
        async with httpx.AsyncClient(timeout=_CATALOG_TIMEOUT) as client:
            resp = await client.post(url, json=payload)
    except httpx.HTTPError as exc:
        logger.warning(
            "connectors_service.test.unreachable err=%s",
            type(exc).__name__,
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="connectors service is unavailable; cannot test connection",
        ) from exc

    # 404 from the microservice = unknown connector_type. We've already
    # validated against the catalog by the time we get here, so a 404 now
    # means a race (someone redeployed the connectors service mid-request);
    # surface it as a 503 since it's transient.
    if resp.status_code == status.HTTP_404_NOT_FOUND:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"connector '{connector_type}' is no longer available in the connectors service",
        )
    if resp.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY:
        # Forward the schema-mismatch detail so the wizard can highlight
        # the offending field.
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=resp.json().get("detail", "connector config does not match schema"),
        )
    if resp.status_code >= 500:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="connectors service failed while testing connection",
        )

    body: dict[str, Any]
    try:
        body = resp.json()
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="connectors service returned a non-JSON response",
        ) from exc
    if not isinstance(body, dict):
        body = {"success": False, "error": "malformed response"}
    return body


# ---------------------------------------------------------------------- catalog


@router.get("/catalog")
async def list_catalog(
    current_user: Annotated[AuthUser, Depends(require_permission("connectors:read"))],
) -> dict[str, Any]:
    """Return the catalog of available connectors with their schemas.

    The wizard calls this once on open to populate the connector picker
    and to render the schema-driven configuration form. It is tenant-agnostic
    — every tenant in this build sees the same catalog — but still gated
    behind authentication.
    """
    schemas = await _fetch_catalog()
    return {"connectors": schemas}


# ------------------------------------------------------------------ pre-save test


@router.post("/test")
async def test_connection(
    request: TestConnectionRequest,
    current_user: Annotated[AuthUser, Depends(require_permission("connectors:write"))],
) -> dict[str, Any]:
    """Wizard-side "Test connection" before saving.

    The wizard sends plaintext credentials directly here. We validate the
    connector type against the catalog, then forward the payload to the
    connectors microservice's stateless test endpoint. **Nothing is
    persisted** — these credentials never touch Postgres or the vault.
    """
    await _validate_connector_type(request.connector_type)
    return await _proxy_test_connection(
        request.connector_type,
        request.auth_config,
        request.connector_config,
    )


# ------------------------------------------------------------------ instance CRUD


@router.get("", response_model=list[ConnectorResponse])
async def list_connectors(
    current_user: Annotated[AuthUser, Depends(require_permission("connectors:read"))],
    db: DBSession,
) -> list[ConnectorResponse]:
    """List all connector instances for the caller's tenant."""
    result = await db.execute(select(Connector).where(Connector.tenant_id == current_user.tenant_id).order_by(Connector.created_at))
    connectors = result.scalars().all()
    return [ConnectorResponse.model_validate(c) for c in connectors]


@router.post("", response_model=ConnectorResponse, status_code=status.HTTP_201_CREATED)
async def create_connector(
    request: CreateConnectorRequest,
    current_user: Annotated[AuthUser, Depends(require_permission("connectors:write"))],
    db: DBSession,
) -> ConnectorResponse:
    """Create a new connector instance.

    ``connector_type`` is validated against the live catalog. ``category``
    defaults to the catalog entry's category if the caller doesn't override
    it — that's the common case and keeps the wizard payload small.
    ``auth_config`` is encrypted with the credential vault before it
    touches Postgres.
    """
    catalog_entry = await _validate_connector_type(request.connector_type)
    category = request.category or catalog_entry.get("category") or "uncategorized"

    try:
        encrypted_auth = get_vault().encrypt_dict(request.auth_config or {})
    except CredentialVaultError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"credential vault unavailable: {exc}",
        ) from exc

    connector = Connector(
        tenant_id=current_user.tenant_id,
        name=request.name,
        connector_type=request.connector_type,
        category=category,
        auth_config=encrypted_auth,
        connector_config=request.connector_config,
        tags=request.tags,
    )
    db.add(connector)
    await db.commit()
    await db.refresh(connector)
    return ConnectorResponse.model_validate(connector)


@router.get("/{connector_id}", response_model=ConnectorResponse)
async def get_connector(
    connector_id: uuid.UUID,
    current_user: Annotated[AuthUser, Depends(require_permission("connectors:read"))],
    db: DBSession,
) -> ConnectorResponse:
    """Get a connector instance by ID, scoped to the caller's tenant."""
    result = await db.execute(
        select(Connector).where(
            Connector.id == connector_id,
            Connector.tenant_id == current_user.tenant_id,
        )
    )
    connector = result.scalar_one_or_none()
    if connector is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Connector not found")
    return ConnectorResponse.model_validate(connector)


@router.patch("/{connector_id}", response_model=ConnectorResponse)
async def update_connector(
    connector_id: uuid.UUID,
    request: UpdateConnectorRequest,
    current_user: Annotated[AuthUser, Depends(require_permission("connectors:write"))],
    db: DBSession,
) -> ConnectorResponse:
    """Update a connector's configuration or state.

    The PATCH semantics here are deliberately conservative: only fields
    the caller actually supplies are touched. Notably, sending an empty
    ``auth_config`` dict will overwrite all secrets — the wizard must
    therefore omit the field entirely when the operator hasn't re-typed
    credentials.
    """
    result = await db.execute(
        select(Connector).where(
            Connector.id == connector_id,
            Connector.tenant_id == current_user.tenant_id,
        )
    )
    connector = result.scalar_one_or_none()
    if connector is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Connector not found")

    updates: dict[str, Any] = {}
    for field in ("name", "is_enabled", "auth_config", "connector_config", "tags"):
        val = getattr(request, field, None)
        if val is None:
            continue
        if field == "auth_config":
            # Re-encrypt on every write so a partial PATCH still leaves
            # all secret leaves under the current primary key.
            try:
                val = get_vault().encrypt_dict(val)
            except CredentialVaultError as exc:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"credential vault unavailable: {exc}",
                ) from exc
        updates[field] = val

    if updates:
        updates["updated_at"] = datetime.now(UTC)
        await db.execute(update(Connector).where(Connector.id == connector_id).values(**updates))
        await db.commit()
        await db.refresh(connector)

    return ConnectorResponse.model_validate(connector)


@router.delete("/{connector_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def delete_connector(
    connector_id: uuid.UUID,
    current_user: Annotated[AuthUser, Depends(require_permission("connectors:delete"))],
    db: DBSession,
) -> None:
    """Delete a connector instance."""
    result = await db.execute(
        select(Connector).where(
            Connector.id == connector_id,
            Connector.tenant_id == current_user.tenant_id,
        )
    )
    connector = result.scalar_one_or_none()
    if connector is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Connector not found")
    await db.delete(connector)
    await db.commit()


# ----------------------------------------------------------- existing-instance test


@router.post("/{connector_id}/test", status_code=status.HTTP_200_OK)
async def test_existing_connector(
    connector_id: uuid.UUID,
    current_user: Annotated[AuthUser, Depends(require_permission("connectors:write"))],
    db: DBSession,
) -> dict[str, Any]:
    """Run a live ``test_connection`` against a saved connector instance.

    Flow:

    1. Fetch the row, scoped to the caller's tenant.
    2. Decrypt ``auth_config`` via the vault.
    3. Forward to the connectors microservice with both the decrypted
       credentials and the non-secret ``connector_config``.
    4. Update the row's ``health_status`` / ``last_health_check`` based on
       the verdict so the dashboard reflects reality.
    """
    result = await db.execute(
        select(Connector).where(
            Connector.id == connector_id,
            Connector.tenant_id == current_user.tenant_id,
        )
    )
    connector = result.scalar_one_or_none()
    if connector is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Connector not found")

    try:
        decrypted_auth = get_vault().decrypt_dict(connector.auth_config or {})
    except CredentialVaultError as exc:
        # A vault failure on *decryption* almost always means the stored
        # ciphertext was written under a key that's no longer in the keyring
        # (key rotation gone wrong). Surface it as 500 rather than pretending
        # the connector is unhealthy.
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"could not decrypt stored credentials: {exc}",
        ) from exc

    verdict = await _proxy_test_connection(
        connector.connector_type,
        decrypted_auth,
        connector.connector_config or {},
    )

    health_status = "healthy" if verdict.get("success") else "unhealthy"
    await db.execute(
        update(Connector)
        .where(Connector.id == connector_id)
        .values(
            last_health_check=datetime.now(UTC),
            health_status=health_status,
        )
    )
    await db.commit()
    return verdict
