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

import json
import logging
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path
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


import httpx  # noqa: E402
from fastapi import APIRouter, Depends, HTTPException, status  # noqa: E402
from pydantic import BaseModel, Field  # noqa: E402
from sqlalchemy import select, update  # noqa: E402

from app.api.v1.deps import AuthUser, DBSession, require_permission  # noqa: E402
from app.core.config import settings  # noqa: E402
from app.models.connector import Connector  # noqa: E402
from app.security.credential_vault import CredentialVaultError, get_vault  # noqa: E402
from app.services.connector_freshness import compute_freshness  # noqa: E402

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/connectors", tags=["connectors"])


# --------------------------------------------------------------- Pydantic schemas


class FreshnessSLOResponse(BaseModel):
    """Freshness verdict surfaced on every ``ConnectorResponse``.

    Driven by ``app.services.connector_freshness.compute_freshness``.
    The UI uses ``status`` to color the badge and ``seconds_since_last_event``
    + ``expected_cadence_seconds`` to render the tooltip ("expected within
    5 min, last event 12 min ago"). ``category`` is echoed back for
    client-side grouping without re-deriving it.
    """

    status: str  # unknown | green | yellow | red
    expected_cadence_seconds: int
    seconds_since_last_event: int | None
    category: str


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
    events_dropped: int = 0
    error_count: int
    # Schema-drift sentinel state surfaced to the wizard so the
    # connector card can show "schema changed at <ts>" without a
    # second round-trip. Both fields are nullable for connectors
    # that haven't drifted (the steady-state expectation).
    schema_fingerprint: str | None = None
    last_schema_drift_at: datetime | None = None
    last_drift_details: dict[str, Any] | None = None
    # Workstream 1: timestamp of last *actual* event ingested. Distinct
    # from `last_sync` because empty polls advance `last_sync` but not
    # this. `last_event_kind` lets the UI label the preview row.
    last_event_at: datetime | None = None
    last_event_kind: str | None = None
    # Workstream 2: True when this row was created via the hosted OAuth
    # one-click flow rather than by pasting an API token. Drives the
    # "Reconnect" action in the UI (re-runs OAuth instead of asking for
    # the credential again).
    oauth_provisioned: bool = False
    # Workstream 4: per-instance capability downscoping. ``None`` means
    # "use everything the class declares"; an explicit list narrows the
    # agent's verbs for *this instance only*.
    allowed_capabilities: list[str] | None = None
    # Workstream 5: freshness SLO badge driven by per-class cadence
    # (5 min EDR, 60 min vuln, etc). Computed on read against
    # ``last_event_at``; never persisted, so the verdict is always
    # current as of the request.
    freshness: FreshnessSLOResponse | None = None
    tags: list
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


def _build_connector_response(connector: Connector) -> ConnectorResponse:
    """Hydrate a ``ConnectorResponse`` and attach the live freshness SLO.

    Centralised so list/get/create/update/PUT-capabilities all return the
    same shape. Pure projection — no DB round-trips, ``compute_freshness``
    runs against the row's own ``last_event_at`` and ``category`` columns.
    Honors a per-instance cadence override at
    ``connector_config.expected_cadence_seconds`` so an operator can
    declare "this Splunk instance polls hourly, don't paint yellow"
    without changing the global table.
    """
    response = ConnectorResponse.model_validate(connector)
    override = None
    cfg = connector.connector_config or {}
    raw_override = cfg.get("expected_cadence_seconds") if isinstance(cfg, dict) else None
    if isinstance(raw_override, int | float):
        override = int(raw_override)
    verdict = compute_freshness(
        category=connector.category,
        last_event_at=connector.last_event_at,
        override_seconds=override,
    )
    response.freshness = FreshnessSLOResponse(**verdict.to_dict())
    return response


class LastEventResponse(BaseModel):
    """Lightweight payload for the verify-data-flowing screen.

    The onboarding flow polls this every few seconds while waiting for
    the first event to land. Keeping the shape minimal avoids paying
    the full ``ConnectorResponse`` cost on every poll tick.
    """

    connector_id: uuid.UUID
    last_event_at: datetime | None
    last_event_kind: str | None
    events_ingested: int
    last_sync: datetime | None
    health_status: str
    # Convenience: a server-side computed answer to "has data started
    # flowing yet?" so the client doesn't have to know the rule.
    data_flowing: bool


class TroubleshootRequest(BaseModel):
    """AI-troubleshooter input from the wizard's failure UX."""

    connector_type: str = Field(min_length=1, max_length=100)
    error: str = Field(min_length=1, max_length=4000)
    auth_config_keys: list[str] = Field(
        default_factory=list,
        description=(
            "Names of fields the operator filled in. Values are intentionally "
            "*not* sent — the troubleshooter doesn't need plaintext credentials "
            "to diagnose '401 Unauthorized'."
        ),
    )


class TroubleshootResponse(BaseModel):
    """Structured guidance the wizard renders next to a failed test."""

    likely_cause: str
    fix_steps: list[str]
    doc_link: str | None = None


class ConnectorHealthSummary(BaseModel):
    """Tenant-wide rollup of connector health for the dashboard.

    The web console shows a small "Connector Health" tile at the top
    of the Connectors page; this endpoint feeds that tile so the UI
    can render it without iterating the full list client-side.
    """

    total: int
    healthy: int
    unhealthy: int
    unknown: int
    drifted: int
    drifted_recently: int  # last 24 h
    last_drift_at: datetime | None
    total_events_ingested: int
    total_events_dropped: int


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


class UpdateCapabilitiesRequest(BaseModel):
    """Per-instance capability downscoping payload (Workstream 4).

    ``None`` removes the downscope ("agent may use every capability the
    connector class declares"). An explicit list — possibly empty —
    becomes the canonical allow-list. Validation against the connector
    class's declared capabilities happens server-side so a tampered
    request can't widen the agent's reach beyond what the connector
    code actually implements.
    """

    allowed_capabilities: list[str] | None = Field(
        default=None,
        description=(
            "Capability strings (e.g. ['pull_alerts','query_logs']) the agent "
            "is permitted to invoke against this instance. None = no downscope."
        ),
    )


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


# Fallback catalog shipped with the API image. Generated from the connectors
# microservice's registry and committed alongside the API source. Used when
# the connectors microservice is not deployed (single-tenant / demo) or
# temporarily unreachable so the AddConnector wizard still renders. Refresh:
#
#   cd services/connectors && python -c "import json; \\
#     from app.connectors import list_connector_schemas as l; \\
#     print(json.dumps(l(), indent=2))" \\
#     > ../api/app/data/connector_catalog_fallback.json
_FALLBACK_CATALOG_PATH = Path(__file__).resolve().parents[3] / "data" / "connector_catalog_fallback.json"


def _load_fallback_catalog() -> list[dict[str, Any]]:
    """Return the bundled connector catalog, or an empty list if missing."""
    try:
        with _FALLBACK_CATALOG_PATH.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as exc:
        logger.warning(
            "connectors_service.catalog.fallback_unavailable path=%s error=%s",
            _FALLBACK_CATALOG_PATH,
            type(exc).__name__,
        )
        return []
    return data if isinstance(data, list) else []


async def _fetch_catalog() -> list[dict[str, Any]]:
    """Pull the connector catalog from the connectors microservice, with fallback.

    Resolution order:
      1. If ``CONNECTORS_SERVICE_URL`` is set and reachable, use it (live source
         of truth — supports newly-added connectors without an API redeploy).
      2. Otherwise, fall back to the catalog bundled with the API image. This
         is what keeps demo / single-tenant deploys functional even when the
         dedicated connectors microservice is not deployed.
    """
    base_url = (getattr(settings, "CONNECTORS_SERVICE_URL", "") or "").strip()
    if not base_url:
        logger.info("connectors_service.catalog.using_fallback reason=no_url_configured")
        return _load_fallback_catalog()

    url = _connectors_service_url("/connectors/schemas")
    try:
        async with httpx.AsyncClient(timeout=_CATALOG_TIMEOUT) as client:
            resp = await client.get(url)
            resp.raise_for_status()
    except httpx.HTTPError as exc:
        logger.warning(
            "connectors_service.catalog.unreachable url=%s error_type=%s falling_back=true",
            url,
            type(exc).__name__,
        )
        fallback = _load_fallback_catalog()
        if fallback:
            return fallback
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


# ------------------------------------------------------------------ health summary


@router.get("/health", response_model=ConnectorHealthSummary)
async def connector_health_summary(
    current_user: Annotated[AuthUser, Depends(require_permission("connectors:read"))],
    db: DBSession,
) -> ConnectorHealthSummary:
    """Aggregate per-tenant connector health for the dashboard tile.

    Single SELECT scan; we deliberately do *not* group in SQL because
    Postgres' filter expressions over a few hundred rows are negligible
    compared to the round-trip, and the resulting Python is a lot easier
    to read than five COUNT(*) FILTER clauses.
    """
    result = await db.execute(select(Connector).where(Connector.tenant_id == current_user.tenant_id))
    connectors = list(result.scalars().all())

    now = datetime.now(UTC)
    twenty_four_hours_ago_seconds = 24 * 60 * 60

    total = len(connectors)
    healthy = 0
    unhealthy = 0
    unknown = 0
    drifted = 0
    drifted_recently = 0
    last_drift_at: datetime | None = None
    total_events_ingested = 0
    total_events_dropped = 0

    for c in connectors:
        if c.health_status == "healthy":
            healthy += 1
        elif c.health_status == "unhealthy":
            unhealthy += 1
        else:
            unknown += 1

        total_events_ingested += int(c.events_ingested or 0)
        total_events_dropped += int(getattr(c, "events_dropped", 0) or 0)

        drift_at = getattr(c, "last_schema_drift_at", None)
        if drift_at is not None:
            drifted += 1
            if last_drift_at is None or drift_at > last_drift_at:
                last_drift_at = drift_at
            # Compare in seconds so we don't depend on timedelta arithmetic
            # being available on every datetime variant Postgres can return.
            if (now - drift_at).total_seconds() <= twenty_four_hours_ago_seconds:
                drifted_recently += 1

    return ConnectorHealthSummary(
        total=total,
        healthy=healthy,
        unhealthy=unhealthy,
        unknown=unknown,
        drifted=drifted,
        drifted_recently=drifted_recently,
        last_drift_at=last_drift_at,
        total_events_ingested=total_events_ingested,
        total_events_dropped=total_events_dropped,
    )


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
    return [_build_connector_response(c) for c in connectors]


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
    return _build_connector_response(connector)


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
    return _build_connector_response(connector)


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

    return _build_connector_response(connector)


@router.put("/{connector_id}/capabilities", response_model=ConnectorResponse)
async def update_connector_capabilities(
    connector_id: uuid.UUID,
    request: UpdateCapabilitiesRequest,
    current_user: Annotated[AuthUser, Depends(require_permission("connectors:write"))],
    db: DBSession,
) -> ConnectorResponse:
    """Downscope which capabilities the agent may invoke against this instance.

    The contract:

    * ``allowed_capabilities = None`` clears the downscope. The agent reverts
      to the connector class's full ``capabilities()`` declaration.
    * ``allowed_capabilities = []`` is a *legitimate* operator action: it
      pins the agent to zero capabilities for this instance. Polling and
      data ingestion are unaffected — only agent-initiated actions are
      gated by this column.
    * Any string in the list MUST appear in the connector class's declared
      capabilities. We validate against the live catalog so a tampered
      request can't widen the agent's reach beyond what the connector code
      actually implements.

    The narrowing happens at the read path
    (``BaseConnector.effective_capabilities()``), not here, so the column
    is purely a per-instance allow-list — flipping it back to ``None``
    instantly restores the class default with no migration.
    """
    result = await db.execute(
        select(Connector).where(
            Connector.id == connector_id,
            Connector.tenant_id == current_user.tenant_id,
        )
    )
    connector = result.scalar_one_or_none()
    if connector is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Connector not found",
        )

    if request.allowed_capabilities is not None:
        # Validate every requested capability against the connector class's
        # declared set. We pull from the live catalog (rather than a hard-coded
        # enum on the API side) so newly-added capabilities are usable as soon
        # as the connectors microservice rolls them out, with no API redeploy.
        catalog_entry = await _validate_connector_type(connector.connector_type)
        declared_caps_raw = catalog_entry.get("capabilities") or []
        declared_caps = {str(c) for c in declared_caps_raw}
        requested_caps = {str(c) for c in request.allowed_capabilities}
        unknown = sorted(requested_caps - declared_caps)
        if unknown:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=(
                    f"Capabilities not declared by connector "
                    f"'{_safe_log_val(connector.connector_type)}': "
                    f"{', '.join(unknown)}. "
                    f"Declared: {', '.join(sorted(declared_caps)) or '(none)'}"
                ),
            )

    await db.execute(
        update(Connector)
        .where(Connector.id == connector_id)
        .values(
            allowed_capabilities=request.allowed_capabilities,
            updated_at=datetime.now(UTC),
        )
    )
    await db.commit()
    await db.refresh(connector)

    # Audit log: only emit fields with provably bounded shape.
    # ``request.allowed_capabilities`` is a list of caller-supplied strings
    # and would otherwise carry taint into the log record (CodeQL
    # py/log-injection). The capability *count* is sufficient for ops
    # forensics — the full set is already persisted on the row above and
    # can be recovered from the DB, which is the source of truth anyway.
    logger.info(
        "connector.capabilities.updated",
        extra={
            "tenant_id": current_user.tenant_id,
            "connector_id": str(connector_id),
            "connector_type": _safe_connector_type(connector.connector_type),
            "allowed_count": len(request.allowed_capabilities or []),
        },
    )

    return _build_connector_response(connector)


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


# ----------------------------------------------------------- verify-data-flowing


# Anything fresher than this counts as "data flowing" for the onboarding
# verify screen. Plenty wide to allow for batch poll cadences (the
# connectors service polls every 5 min by default) without flapping
# the green check.
_DATA_FLOWING_WINDOW_SECONDS = 30 * 60


@router.get("/{connector_id}/last_event_at", response_model=LastEventResponse)
async def get_last_event_at(
    connector_id: uuid.UUID,
    current_user: Annotated[AuthUser, Depends(require_permission("connectors:read"))],
    db: DBSession,
) -> LastEventResponse:
    """Return event-arrival watermark for the onboarding verify screen.

    Polled by the wizard's "verify data flowing" panel every few seconds
    after a connector is saved. Returns 200 with ``data_flowing=false``
    rather than a 404 so the polling loop has stable shape until the
    first event lands. The ``data_flowing`` boolean is computed server
    side from a fixed window (see ``_DATA_FLOWING_WINDOW_SECONDS``) so
    every client agrees on the rule.
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

    last_event_at = connector.last_event_at
    data_flowing = False
    if last_event_at is not None:
        # `last_event_at` is timezone-aware (DateTime(timezone=True)),
        # but be defensive against drivers that strip tzinfo.
        ts = last_event_at if last_event_at.tzinfo else last_event_at.replace(tzinfo=UTC)
        data_flowing = (datetime.now(UTC) - ts).total_seconds() <= _DATA_FLOWING_WINDOW_SECONDS

    return LastEventResponse(
        connector_id=connector.id,
        last_event_at=last_event_at,
        last_event_kind=connector.last_event_kind,
        events_ingested=int(connector.events_ingested or 0),
        last_sync=connector.last_sync,
        health_status=connector.health_status or "unknown",
        data_flowing=data_flowing,
    )


# ----------------------------------------------------------- AI troubleshooter


# Hand-rolled rules for the most common credential-test failures. We
# keep this deterministic for two reasons:
#
# * The plan calls for an LLM-backed sidekick, but in single-tenant /
#   air-gapped deployments there's no LLM endpoint to hit. A static
#   rule table covers the 80% case (auth headers, scope, network)
#   without requiring any external dependency.
# * Even when an LLM is wired in, the wizard has to render *something*
#   if the model is slow/unavailable. These rules are the fallback.
#
# Order matters — first regex match wins. Patterns are case-insensitive.
_TROUBLESHOOT_RULES: list[tuple[re.Pattern[str], str, list[str], str | None]] = [
    (
        re.compile(r"401|unauthor", re.IGNORECASE),
        "The credentials were rejected by the upstream API.",
        [
            "Verify the API key, client ID, or service-account password is correct.",
            "Check whether the credential has expired or was revoked in the source system.",
            "If you're using an OAuth client secret, regenerate it and retry.",
            "Confirm the account hasn't been disabled by an admin.",
        ],
        "/docs/connectors/auth-troubleshooting",
    ),
    (
        re.compile(r"403|forbidden|insufficient.*scope|missing.*permission", re.IGNORECASE),
        "Authentication succeeded but the credential is missing required scopes / permissions.",
        [
            "Open the upstream system and check the required role/scope listed in the connector docs.",
            "If using an OAuth scope list, re-authorize and tick all required scopes.",
            "For service accounts, grant the minimum read/audit role described in the connector reference.",
        ],
        "/docs/connectors/scopes",
    ),
    (
        re.compile(r"429|rate.?limit|too many requests", re.IGNORECASE),
        "The upstream API is rate-limiting the test request.",
        [
            "Wait 1-2 minutes and re-test — first-call rate limits are usually narrow.",
            "If you're using a shared API key, check whether another integration is hammering it.",
            "Configure a longer poll interval in the connector advanced settings if this persists.",
        ],
        None,
    ),
    (
        re.compile(r"timeout|timed out|context deadline", re.IGNORECASE),
        "The connector couldn't reach the upstream API in time.",
        [
            "Check that the API endpoint URL is correct and matches your tenant region.",
            "If the upstream is internal, confirm AiSOC has network connectivity / VPN routing.",
            "Try lowering the test payload size in connector_config (when applicable).",
        ],
        None,
    ),
    (
        re.compile(r"dns|name resolution|no such host|getaddrinfo", re.IGNORECASE),
        "DNS resolution for the configured endpoint failed.",
        [
            "Double-check the hostname for typos.",
            "If this is a private endpoint, confirm a private resolver / DNS forwarder is configured.",
        ],
        None,
    ),
    (
        re.compile(r"x509|certificate|tls|ssl", re.IGNORECASE),
        "TLS/certificate validation failed against the upstream endpoint.",
        [
            "Confirm the endpoint URL uses the correct hostname (cert SANs must match).",
            "If you're behind a proxy with custom CA, install the CA bundle on the connectors service.",
            "For self-signed certs, switch to a properly issued cert before going to production.",
        ],
        None,
    ),
    (
        re.compile(r"missing|required|invalid.*config|schema", re.IGNORECASE),
        "One or more required configuration fields are missing or invalid.",
        [
            "Re-check the wizard's required fields (marked with *).",
            "If you pasted a key, ensure no surrounding whitespace or quote characters were captured.",
            "Some fields require a specific format (e.g. region 'us-east-1' not 'US East'); see the connector docs.",
        ],
        None,
    ),
    (
        re.compile(r"5\d{2}|server error|bad gateway", re.IGNORECASE),
        "The upstream API returned a server-side error during the test.",
        [
            "Wait a minute and retry — most 5xx are transient.",
            "Check the upstream service's status page.",
            "If this persists, file a support ticket with the upstream vendor and include the error string.",
        ],
        None,
    ),
]

# Per-connector documentation links so the troubleshooter can offer a
# canonical "read the setup guide" link as a last resort.
_CONNECTOR_DOC_LINKS: dict[str, str] = {
    "okta": "/docs/connectors/okta",
    "azure_entra": "/docs/connectors/azure-entra",
    "google_workspace": "/docs/connectors/google-workspace",
    "github_audit": "/docs/connectors/github-audit",
    "atlassian_audit": "/docs/connectors/atlassian-audit",
    "slack_audit": "/docs/connectors/slack-audit",
    "microsoft_365": "/docs/connectors/microsoft-365",
    "crowdstrike": "/docs/connectors/crowdstrike",
    "sentinelone": "/docs/connectors/sentinelone",
    "carbon_black": "/docs/connectors/carbon-black",
    "trellix": "/docs/connectors/trellix",
    "trend_vision_one": "/docs/connectors/trend-vision-one",
    "cortex_xsiam": "/docs/connectors/cortex-xsiam",
    "rapid7_insightidr": "/docs/connectors/rapid7-insightidr",
    "sumo_logic": "/docs/connectors/sumo-logic",
    "chronicle": "/docs/connectors/chronicle",
    "datadog_cloud_siem": "/docs/connectors/datadog-cloud-siem",
    "lacework": "/docs/connectors/lacework",
    "tenable": "/docs/connectors/tenable",
    "mimecast": "/docs/connectors/mimecast",
    "salesforce": "/docs/connectors/salesforce",
    "auth0": "/docs/connectors/auth0",
    "cisco_umbrella": "/docs/connectors/cisco-umbrella",
}


def _troubleshoot(error: str, connector_type: str) -> TroubleshootResponse:
    """Map an error string + connector to a structured fix suggestion.

    Pure function (no I/O) so it's trivially unit-testable. Behaviour
    is intentionally deterministic; this is a *fallback* for when the
    LLM-backed troubleshooter is offline or not configured.
    """
    for pattern, cause, steps, doc in _TROUBLESHOOT_RULES:
        if pattern.search(error):
            return TroubleshootResponse(
                likely_cause=cause,
                fix_steps=list(steps),
                doc_link=doc or _CONNECTOR_DOC_LINKS.get(connector_type),
            )
    return TroubleshootResponse(
        likely_cause=(
            "We couldn't classify this error automatically. The most common "
            "causes are mistyped credentials, missing scopes, or a regional "
            "endpoint mismatch."
        ),
        fix_steps=[
            "Re-read the error string carefully — many vendor APIs include the actual problem in the body.",
            "Check the connector setup guide for the exact required permissions.",
            "Re-test with a fresh API key / re-authorized OAuth grant.",
        ],
        doc_link=_CONNECTOR_DOC_LINKS.get(connector_type),
    )


@router.post("/troubleshoot", response_model=TroubleshootResponse)
async def troubleshoot_connection(
    request: TroubleshootRequest,
    current_user: Annotated[AuthUser, Depends(require_permission("connectors:write"))],
) -> TroubleshootResponse:
    """Return structured fix suggestions for a failed connector test.

    The wizard calls this when ``test_connection`` returns ``success=false``.
    Auth-config keys (not values) are forwarded so future LLM-backed
    versions can hint about which field to revisit, while keeping the
    request safe to log.
    """
    if not _CONNECTOR_TYPE_RE.match(request.connector_type):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="connector_type contains invalid characters",
        )
    safe_type = _safe_connector_type(request.connector_type)
    # Diagnostics log: caller-supplied ``request.auth_config_keys`` is a
    # list of arbitrary strings and would carry taint into the log
    # record (CodeQL py/log-injection). For triage we only need the
    # *count* — the actual key names on a misconfigured connector are
    # available via the schema endpoint and don't add forensic value
    # here. ``safe_type`` is already reconstructed via
    # ``_safe_connector_type`` (whitelist regex) so it's a recognised
    # taint break. ``err_len`` is an int, not a string.
    logger.info(
        "connectors.troubleshoot",
        extra={
            "type": safe_type,
            "keys_count": len(request.auth_config_keys),
            "err_len": len(request.error),
        },
    )
    return _troubleshoot(request.error, safe_type)


# ----------------------------------------------------------------- push tokens


def _generate_ingest_token() -> str:
    """Generate an opaque, URL-safe token for the /v1/inbox/{token} push path.

    32 bytes of entropy = ~256 bits, which gives us collision resistance
    well past anything we'd ever see at tenant scale.
    """
    import secrets

    return f"ait_{secrets.token_urlsafe(32)}"


class IngestTokenResponse(BaseModel):
    """Push-token response. ``inbox_url`` is the absolute endpoint."""

    connector_id: uuid.UUID
    ingest_token: str
    inbox_url: str


@router.post("/{connector_id}/push/refresh", response_model=IngestTokenResponse)
async def refresh_ingest_token(
    connector_id: uuid.UUID,
    current_user: Annotated[AuthUser, Depends(require_permission("connectors:write"))],
    db: DBSession,
) -> IngestTokenResponse:
    """Generate (or rotate) the per-connector push-ingest token.

    Operators click "Reveal push URL" in the wizard, which calls this and
    renders the resulting curl example. Re-calling rotates the token and
    invalidates the old one — the typical use case is "I think this URL
    leaked into a Slack message, give me a new one".
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

    new_token = _generate_ingest_token()
    await db.execute(update(Connector).where(Connector.id == connector_id).values(ingest_token=new_token, updated_at=datetime.now(UTC)))
    await db.commit()

    base = (getattr(settings, "INGEST_PUBLIC_URL", "") or "").rstrip("/")
    inbox_url = f"{base}/v1/inbox/{new_token}" if base else f"/v1/inbox/{new_token}"
    return IngestTokenResponse(
        connector_id=connector_id,
        ingest_token=new_token,
        inbox_url=inbox_url,
    )
