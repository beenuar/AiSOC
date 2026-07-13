"""
Connectors service REST API.

Catalog and schema endpoints are now backed by the
``app.connectors`` registry so adding a connector requires zero changes
here — drop the class in, register it in ``connectors/__init__.py``, and
its schema flows through to the wizard automatically.

This service is a *stateless* microservice. It does not own connector
instance rows (those live in the API service's Postgres) and it does not
manage credentials at rest (that's the API's ``CredentialVault``). Its
job is twofold:

1. Catalog: tell the API service which connector classes this build
   ships and what configuration schema each one expects.
2. Test: instantiate a connector class with caller-supplied (already
   decrypted) credentials, run ``test_connection()``, and return the
   verdict. This lets the API service offer a "Test connection" button
   in the wizard without having to re-implement every vendor SDK.

Production connector polling and ingest happen elsewhere (the
``ConnectorScheduler`` + ``IngestClient`` modules wired into the
service's lifespan), not in this router.
"""

from __future__ import annotations

import re
from typing import Any

import structlog
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from pydantic import Field as PydField

from app.connectors import CONNECTOR_REGISTRY, list_connector_schemas
from app.connectors.base import Capability
from app.federated.query import QueryError, parse_unified_query

logger = structlog.get_logger()
router = APIRouter()

_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")


def _safe_log_val(value: str) -> str:
    """Strip ASCII control characters (incl. newlines) from a string before logging.

    Prevents log-injection attacks where a user-controlled value such as a
    connector_id could embed newline sequences that forge extra log lines.
    """
    return _CTRL_RE.sub("", value)


class TestConnectionRequest(BaseModel):
    """Stateless test-connection payload.

    The API service decrypts the stored ``auth_config`` before forwarding
    it here; this service never sees vault tokens. ``connector_config``
    carries non-secret runtime knobs (poll interval, region, etc.) that
    some connectors take in their constructor alongside credentials.
    """

    auth_config: dict[str, Any] = PydField(
        default_factory=dict,
        description="Plaintext credential fields for the connector.",
    )
    connector_config: dict[str, Any] = PydField(
        default_factory=dict,
        description="Non-secret runtime config that's passed to the connector constructor.",
    )


class ResourceConfigRequest(BaseModel):
    """Fetch one resource's live configuration (Phase C2).

    Same trust model as ``TestConnectionRequest``: the API service decrypts
    ``auth_config`` before forwarding here. ``resource_id`` is the vendor-native
    id (Okta group/app id, ARN, Azure object id, …); ``at_ts`` is an optional
    point-in-time (ISO-8601) — connectors that can't time-travel return their
    latest and mark ``snapshot_freshness``.
    """

    auth_config: dict[str, Any] = PydField(default_factory=dict)
    connector_config: dict[str, Any] = PydField(default_factory=dict)
    resource_id: str = PydField(..., description="Vendor-native resource id to fetch.")
    at_ts: str = PydField(default="", description="Optional ISO-8601 point-in-time.")


class FederatedQueryRequest(BaseModel):
    """Run a unified query against a single connector instance.

    Same trust model as ``TestConnectionRequest``: the API service
    decrypts ``auth_config`` before forwarding here. ``query`` is the
    JSON-shaped ``UnifiedQuery`` (see ``app.federated.query``).
    """

    auth_config: dict[str, Any] = PydField(default_factory=dict)
    connector_config: dict[str, Any] = PydField(default_factory=dict)
    query: dict[str, Any] = PydField(
        ...,
        description="UnifiedQuery payload: free_text, indicators[], since_seconds, limit.",
    )


# ---------------------------------------------------------------------------
# WS8: bidirectional ITSM push.
# ---------------------------------------------------------------------------
#
# These two payloads carry the AiSOC case (already serialized to a dict by
# the API layer) plus the same auth/runtime config envelope as the test and
# query endpoints. Trust model is identical: ``auth_config`` arrives in
# plaintext because the API service decrypted it via ``CredentialVault``
# before forwarding.


class PushCaseRequest(BaseModel):
    """Mint or update an external ticket from an AiSOC case.

    ``case`` is the dict the API layer assembled from the ``aisoc_cases``
    row (id, case_number, title, description, severity, status, plus any
    relevant joins). ``external_ref`` is optional and only set when the
    caller already has a ``case_external_refs`` row to update — the
    connector will treat it as "first-time push" otherwise.
    """

    auth_config: dict[str, Any] = PydField(default_factory=dict)
    connector_config: dict[str, Any] = PydField(default_factory=dict)
    case: dict[str, Any] = PydField(
        ...,
        description="AiSOC case payload to project onto the external ITSM.",
    )
    external_ref: dict[str, Any] | None = PydField(
        default=None,
        description="Existing case_external_refs row for idempotent updates.",
    )


class PushStatusChangeRequest(BaseModel):
    """Project an AiSOC status transition onto an external ticket."""

    auth_config: dict[str, Any] = PydField(default_factory=dict)
    connector_config: dict[str, Any] = PydField(default_factory=dict)
    case: dict[str, Any] = PydField(...)
    old_status: str = PydField(..., description="AiSOC status the case is moving from.")
    new_status: str = PydField(..., description="AiSOC status the case is moving to.")
    external_ref: dict[str, Any] | None = PydField(
        default=None,
        description="Existing case_external_refs row. None falls through to push_case.",
    )


def _instantiate_or_422(cls: type, kwargs: dict[str, Any]) -> Any:
    """Construct ``cls(**kwargs)`` and convert config errors to HTTP 422.

    Pulled out into a helper because four endpoints now share the exact
    same construction path; keeping it inline meant duplicating the
    ``TypeError`` handling four times.
    """
    try:
        return cls(**kwargs)
    except TypeError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"connector config does not match schema: {exc}",
        ) from exc


def _require_capability(cls: type, capability: Capability, connector_id: str) -> None:
    """Reject calls to a connector that doesn't declare ``capability``.

    ``BaseConnector`` already raises ``NotImplementedError`` from the
    default ``push_case`` / ``push_status_change`` bodies, but failing
    fast here gives a friendlier 501 with the connector_id pre-filled
    instead of bubbling an opaque exception out of the runtime.
    """
    if capability not in cls.capabilities():
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail=(f"connector '{connector_id}' does not declare capability '{capability.value}'"),
        )


@router.get("/connectors")
async def list_connectors():
    """List every connector registered with this build."""
    return {
        "connectors": [
            {
                "id": cls.connector_id,
                "name": cls.connector_name,
                "category": cls.connector_category,
            }
            for cls in CONNECTOR_REGISTRY.values()
        ]
    }


@router.get("/connectors/schemas")
async def list_schemas():
    """Bulk fetch every connector's configuration schema.

    Frontend uses this to populate the AddConnector wizard without firing
    one request per connector.
    """
    return {"schemas": list_connector_schemas()}


@router.get("/connectors/{connector_id}/schema")
async def get_connector_schema(connector_id: str):
    """Configuration schema for a single connector."""
    cls = CONNECTOR_REGISTRY.get(connector_id)
    if cls is None:
        raise HTTPException(status_code=404, detail=f"Connector '{connector_id}' not found")
    schema_dict = cls.schema().to_dict()
    # Backfill capabilities from the classmethod when ``schema()`` didn't
    # set them explicitly. See ``list_connector_schemas`` for rationale.
    if not schema_dict.get("capabilities"):
        schema_dict["capabilities"] = [c.value for c in cls.capabilities()]
    return schema_dict


@router.post("/connectors/{connector_id}/test")
async def test_connector_connection(connector_id: str, payload: TestConnectionRequest):
    """Run a stateless ``test_connection()`` for the given connector.

    The API service is expected to:

    1. Look up the stored connector instance row (or accept fresh creds
       from the wizard's "Test connection" button before the row exists).
    2. Decrypt ``auth_config`` via the credential vault.
    3. POST the resulting plaintext blob here, alongside ``connector_config``.

    We then construct the connector class with the merged keyword
    arguments and call its ``test_connection()`` coroutine. The connector
    is responsible for catching its own network errors and returning a
    structured ``{"success": bool, ...}`` payload — we do not synthesise
    that ourselves so the wizard surface always shows the connector's
    own diagnostic message (e.g. "401 Unauthorized" vs "DNS lookup
    failed").
    """
    cls = CONNECTOR_REGISTRY.get(connector_id)
    if cls is None:
        raise HTTPException(status_code=404, detail=f"Connector '{connector_id}' not found")

    # Merge auth + non-secret config into kwargs. We keep them in this order
    # because a malicious ``connector_config`` mustn't be able to overwrite
    # a legitimate ``auth_config`` field — but in practice the API service
    # validates both blobs against the schema before we ever see them, so
    # this ordering is defensive belt-and-braces rather than a real
    # boundary.
    kwargs = {**payload.auth_config, **payload.connector_config}

    try:
        connector = cls(**kwargs)
    except TypeError as exc:
        # Almost always "missing 1 required positional argument" or "got
        # unexpected keyword argument", i.e. caller passed a config that
        # doesn't match this connector's schema. Surface as 422 so the
        # frontend can highlight the offending field.
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"connector config does not match schema: {exc}",
        ) from exc
    except Exception as exc:  # pragma: no cover - last-ditch
        logger.exception("connector.test.constructor_error", connector_id=_safe_log_val(connector_id))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to construct connector. Check your configuration.",
        ) from exc

    try:
        result = await connector.test_connection()
    except Exception:  # pragma: no cover - connector misbehaving
        # A well-behaved connector swallows its own errors and returns
        # {"success": False, "error": ...}. If one raises anyway, we
        # convert to the same shape so the wizard UI doesn't have two
        # error formats to deal with.
        logger.exception("connector.test.runtime_error", connector_id=_safe_log_val(connector_id))
        result = {"success": False, "connector": connector_id, "error": "Connection test failed"}

    if not isinstance(result, dict):
        # Defensive: some connectors might return None on success. Coerce.
        result = {"success": bool(result), "connector": connector_id}
    return result


@router.post("/connectors/{connector_id}/resource_config")
async def get_resource_config(connector_id: str, payload: ResourceConfigRequest):
    """Fetch one resource's live configuration (Phase C2 posture collection).

    Trust boundary matches ``/test`` and ``/query``: the API service has
    already decrypted ``auth_config`` against the vault; the connector instance
    lives only for this request. Connectors that don't implement
    ``get_resource_config`` return 501.
    """
    cls = CONNECTOR_REGISTRY.get(connector_id)
    if cls is None:
        raise HTTPException(status_code=404, detail=f"Connector '{connector_id}' not found")

    kwargs = {**payload.auth_config, **payload.connector_config}
    try:
        connector = cls(**kwargs)
    except TypeError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"connector config does not match schema: {exc}",
        ) from exc

    try:
        config = await connector.get_resource_config(payload.resource_id, payload.at_ts)
    except NotImplementedError as exc:
        raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        logger.exception("connector.resource_config.runtime_error", connector_id=_safe_log_val(connector_id))
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Resource-config fetch failed. Check connector configuration and connectivity.",
        ) from exc

    return {"connector_id": connector_id, "resource_id": payload.resource_id, "config": config}


@router.post("/connectors/{connector_id}/query")
async def run_federated_query(connector_id: str, payload: FederatedQueryRequest):
    """Translate a ``UnifiedQuery`` and run it against the connector's backend.

    Trust boundary mirrors ``/connectors/{id}/test``: the API service has
    already decrypted ``auth_config`` against the credential vault before
    we see it, and the connector instance lives only for the duration of
    this request — we never persist credentials in the connectors
    microservice.

    Connectors that haven't opted into federated search return 501 via
    the ``NotImplementedError`` raised by ``BaseConnector.query``'s
    default. Translation failures (un-translatable operator, malformed
    payload) become 422 so the API layer can surface the offending field.
    """
    cls = CONNECTOR_REGISTRY.get(connector_id)
    if cls is None:
        raise HTTPException(status_code=404, detail=f"Connector '{connector_id}' not found")

    if not getattr(cls, "supports_federated_search", False):
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail=f"connector '{connector_id}' does not support federated search",
        )

    try:
        unified = parse_unified_query(payload.query)
    except QueryError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    kwargs = {**payload.auth_config, **payload.connector_config}
    try:
        connector = cls(**kwargs)
    except TypeError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"connector config does not match schema: {exc}",
        ) from exc

    try:
        rows = await connector.query(unified)
    except NotImplementedError as exc:
        # Defensive: a connector class can advertise supports_federated_search
        # but a future refactor could leave query() unimplemented. Map to
        # the same 501 we'd return up top.
        raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail=str(exc)) from exc
    except QueryError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("connector.query.runtime_error", connector_id=_safe_log_val(connector_id))
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Backend query failed. Check connector configuration and connectivity.",
        ) from exc

    return {
        "connector_id": connector_id,
        "row_count": len(rows),
        "rows": rows,
    }


@router.post("/connectors/{connector_id}/push_case")
async def push_case(connector_id: str, payload: PushCaseRequest):
    """Mint or upsert an external ITSM ticket from an AiSOC case.

    Idempotency is the connector's responsibility: when ``external_ref``
    is set, the connector should patch the existing ticket; when it's
    None, it should create one and return enough metadata for the caller
    to persist a ``case_external_refs`` row (``external_id``,
    ``external_url``, ``vendor``, ``external_status``).

    Returns the connector's ``{"external_id", "external_url", "vendor",
    "external_status"}`` envelope. The API service maps that into the
    ``case_external_refs`` table; we never persist anything here.
    """
    cls = CONNECTOR_REGISTRY.get(connector_id)
    if cls is None:
        raise HTTPException(status_code=404, detail=f"Connector '{connector_id}' not found")
    _require_capability(cls, Capability.PUSH_CASE, connector_id)

    kwargs = {**payload.auth_config, **payload.connector_config}
    connector = _instantiate_or_422(cls, kwargs)

    try:
        result = await connector.push_case(payload.case)
    except NotImplementedError as exc:
        raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail=str(exc)) from exc
    except Exception as exc:
        # Don't leak vendor errors verbatim — they sometimes echo request
        # headers / payload fragments. The connector logs the full detail
        # via structlog; the API service just sees a generic 502.
        logger.exception(
            "connector.push_case.runtime_error",
            connector_id=_safe_log_val(connector_id),
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Push to external ITSM failed. Check connector configuration and connectivity.",
        ) from exc

    if not isinstance(result, dict):
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"connector '{connector_id}' returned unexpected push_case payload",
        )
    return result


@router.post("/connectors/{connector_id}/push_status_change")
async def push_status_change(connector_id: str, payload: PushStatusChangeRequest):
    """Project an AiSOC status transition onto a previously-pushed ticket.

    If ``external_ref`` is None we delegate to ``push_case`` (i.e. the
    case is being reported to this ITSM for the first time as part of
    the same status update). Otherwise we patch the existing ticket.
    The connector decides which fields to map (state code, resolution,
    close notes, etc.).
    """
    cls = CONNECTOR_REGISTRY.get(connector_id)
    if cls is None:
        raise HTTPException(status_code=404, detail=f"Connector '{connector_id}' not found")
    _require_capability(cls, Capability.PUSH_STATUS, connector_id)

    kwargs = {**payload.auth_config, **payload.connector_config}
    connector = _instantiate_or_422(cls, kwargs)

    try:
        result = await connector.push_status_change(
            payload.case,
            payload.old_status,
            payload.new_status,
            external_ref=payload.external_ref,
        )
    except NotImplementedError as exc:
        raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail=str(exc)) from exc
    except ValueError as exc:
        # e.g. servicenow.push_status_change rejecting a missing sys_id.
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception(
            "connector.push_status_change.runtime_error",
            connector_id=_safe_log_val(connector_id),
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Status sync to external ITSM failed. Check connector configuration and connectivity.",
        ) from exc

    if not isinstance(result, dict):
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"connector '{connector_id}' returned unexpected push_status_change payload",
        )
    return result


@router.get("/health")
async def health():
    return {"status": "healthy", "service": "aisoc-connectors"}
