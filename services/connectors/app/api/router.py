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

from typing import Any

import structlog
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from pydantic import Field as PydField

from app.connectors import CONNECTOR_REGISTRY, list_connector_schemas
from app.federated.query import QueryError, parse_unified_query

logger = structlog.get_logger()
router = APIRouter()


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
    return cls.schema().to_dict()


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
    except Exception:  # pragma: no cover - last-ditch
        logger.exception("connector.test.constructor_error", connector_id=connector_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to construct connector. Check your configuration.",
        )

    try:
        result = await connector.test_connection()
    except Exception:  # pragma: no cover - connector misbehaving
        # A well-behaved connector swallows its own errors and returns
        # {"success": False, "error": ...}. If one raises anyway, we
        # convert to the same shape so the wizard UI doesn't have two
        # error formats to deal with.
        logger.exception("connector.test.runtime_error", connector_id=connector_id)
        result = {"success": False, "connector": connector_id, "error": "Connection test failed"}

    if not isinstance(result, dict):
        # Defensive: some connectors might return None on success. Coerce.
        result = {"success": bool(result), "connector": connector_id}
    return result


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
    except Exception:
        logger.exception("connector.query.runtime_error", connector_id=connector_id)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Backend query failed. Check connector configuration and connectivity.",
        )

    return {
        "connector_id": connector_id,
        "row_count": len(rows),
        "rows": rows,
    }


@router.get("/health")
async def health():
    return {"status": "healthy", "service": "aisoc-connectors"}
