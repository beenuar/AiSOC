"""Unit tests for the federated search API helpers.

The federated search endpoint is the API-side half of the ``w3-fed``
capability. Like ``test_connectors_endpoint``, we stay below the FastAPI
layer here — the endpoint's interesting logic lives in three helpers
that are pure-async and trivially mockable:

* ``_query_one_backend`` — decrypts creds via the vault, POSTs to the
  connectors microservice, and tags rows. Must never raise; instead it
  returns a per-source verdict so a single bad SIEM can't poison the
  merged response.
* ``_audit_event`` — builds the immutable audit row. We assert that
  indicator *values* never enter ``metadata_`` (a federated query may
  contain regulated identifiers; the audit log is tenant-shared).
* ``_connectors_query_url`` / ``_ensure_feature_enabled`` — small
  utilities, but they hold the URL contract with the connectors
  microservice and the feature-flag gate respectively.

We mock ``httpx.AsyncClient`` and the credential vault directly. Spinning
up a real DB / auth stack would add nothing — the proxy-and-merge layer
is already characterised by these unit tests, and the rest of the
endpoint is FastAPI dependency injection.
"""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from app.api.v1.endpoints.federated import (
    SourceVerdict,
    _audit_event,
    _connectors_query_url,
    _ensure_feature_enabled,
    _query_one_backend,
)
from app.models.connector import Connector
from app.security.credential_vault import CredentialVaultError
from fastapi import HTTPException

# ---------------------------------------------------------------- fixtures


def _make_connector(
    *,
    connector_type: str = "splunk",
    name: str = "Prod Splunk",
    auth_config: dict[str, Any] | None = None,
    connector_config: dict[str, Any] | None = None,
) -> Connector:
    """Build a ``Connector`` instance without touching the database.

    SQLAlchemy lets us instantiate ORM objects with kwargs and pass them
    around as plain Python objects so long as we never call ``flush`` /
    ``commit``. That's exactly what we want here — the helper under test
    only reads attributes.
    """
    return Connector(
        id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        name=name,
        connector_type=connector_type,
        category="siem",
        is_enabled=True,
        auth_config=auth_config or {"token": "vault:v1:abc"},
        connector_config=connector_config or {"base_url": "https://splunk.example.com"},
        health_status="healthy",
    )


def _mock_response(status_code: int, json_body: Any, *, content: bytes | None = None) -> MagicMock:
    """Build a MagicMock that quacks like an httpx.Response."""
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.json = MagicMock(return_value=json_body)
    resp.text = str(json_body) if not isinstance(json_body, str) else json_body
    # ``content`` controls the ``if resp.content`` truthiness branch.
    resp.content = content if content is not None else b'{"rows": []}'
    return resp


def _patched_post(post_resp: MagicMock | Exception):
    """Patch ``httpx.AsyncClient`` so its async ``post`` returns/raises as configured."""
    client_instance = MagicMock()
    if isinstance(post_resp, Exception):
        client_instance.post = AsyncMock(side_effect=post_resp)
    else:
        client_instance.post = AsyncMock(return_value=post_resp)
    client_cm = MagicMock()
    client_cm.__aenter__ = AsyncMock(return_value=client_instance)
    client_cm.__aexit__ = AsyncMock(return_value=None)
    return patch(
        "app.api.v1.endpoints.federated.httpx.AsyncClient",
        return_value=client_cm,
    )


def _patched_vault(decrypt_return: dict[str, Any] | None = None, *, raises: Exception | None = None):
    """Patch the credential vault so ``decrypt_dict`` is hermetic."""
    vault = MagicMock()
    if raises is not None:
        vault.decrypt_dict = MagicMock(side_effect=raises)
    else:
        vault.decrypt_dict = MagicMock(return_value=decrypt_return or {})
    return patch("app.api.v1.endpoints.federated.get_vault", return_value=vault)


# ----------------------------------------------------- _connectors_query_url


def test_connectors_query_url_uses_v1_prefix() -> None:
    """The connectors microservice mounts its router under ``/api/v1``;
    the federated endpoint must hit that exact path."""
    url = _connectors_query_url("splunk")
    assert url.endswith("/api/v1/connectors/splunk/query")


def test_connectors_query_url_strips_trailing_slash() -> None:
    """``CONNECTORS_SERVICE_URL`` may or may not end with ``/`` depending on
    how operators set the env var. The helper must normalise it so we never
    emit a double slash that some upstream proxies treat as a 404."""
    with patch("app.api.v1.endpoints.federated.settings") as mock_settings:
        mock_settings.CONNECTORS_SERVICE_URL = "http://connectors:8003/"
        url = _connectors_query_url("microsoft_sentinel")
    assert url == "http://connectors:8003/api/v1/connectors/microsoft_sentinel/query"


# ---------------------------------------------------- _ensure_feature_enabled


def test_ensure_feature_enabled_passthrough_when_on() -> None:
    """When the flag is on, the helper is a no-op. Anything else means
    the feature is silently broken."""
    with patch("app.api.v1.endpoints.federated.settings") as mock_settings:
        mock_settings.AISOC_FEATURE_FED_SEARCH = True
        # Should not raise.
        _ensure_feature_enabled()


def test_ensure_feature_enabled_404s_when_off() -> None:
    """Disabled feature → 404, not 403 or 500. We hide the route entirely
    rather than admitting it exists, which matches how the rest of the
    feature-flagged endpoints behave."""
    with patch("app.api.v1.endpoints.federated.settings") as mock_settings:
        mock_settings.AISOC_FEATURE_FED_SEARCH = False
        with pytest.raises(HTTPException) as exc_info:
            _ensure_feature_enabled()
    assert exc_info.value.status_code == 404
    assert "AISOC_FEATURE_FED_SEARCH" in exc_info.value.detail


# ---------------------------------------------------------- _query_one_backend


@pytest.mark.asyncio
async def test_query_one_backend_decrypt_failure_returns_error_verdict() -> None:
    """A vault failure must NOT raise — it returns a per-source verdict
    so the rest of the federated answer still gets through."""
    connector = _make_connector()
    with _patched_vault(raises=CredentialVaultError("bad ciphertext")):
        verdict, rows = await _query_one_backend(
            connector,
            query_payload={"free_text": "x"},
            timeout=httpx.Timeout(5.0),
        )
    assert verdict.status == "error"
    assert "credential decryption failed" in (verdict.error or "")
    assert rows == []


@pytest.mark.asyncio
async def test_query_one_backend_unreachable_returns_error_verdict() -> None:
    """Network failure on the connectors microservice → status=error,
    not a raised exception. Other backends get to keep running."""
    connector = _make_connector()
    with (
        _patched_vault(decrypt_return={"token": "plaintext"}),
        _patched_post(httpx.ConnectError("conn refused")),
    ):
        verdict, rows = await _query_one_backend(
            connector,
            query_payload={"free_text": "x"},
            timeout=httpx.Timeout(5.0),
        )
    assert verdict.status == "error"
    assert "unreachable" in (verdict.error or "")
    assert rows == []


@pytest.mark.asyncio
async def test_query_one_backend_501_marked_unsupported() -> None:
    """501 from the connectors microservice means the connector class
    hasn't opted into ``supports_federated_search``. We surface this as
    ``unsupported`` (not ``error``) so the UI can render it differently."""
    connector = _make_connector(connector_type="splunk")
    resp = _mock_response(501, {}, content=b"")
    resp.text = "no federated support"
    with (
        _patched_vault(decrypt_return={"token": "plaintext"}),
        _patched_post(resp),
    ):
        verdict, rows = await _query_one_backend(
            connector,
            query_payload={"free_text": "x"},
            timeout=httpx.Timeout(5.0),
        )
    assert verdict.status == "unsupported"
    assert verdict.error == "no federated support"
    assert rows == []


@pytest.mark.asyncio
async def test_query_one_backend_4xx_surfaces_detail() -> None:
    """A 4xx from the backend (e.g. 401 because creds expired) must come
    back as ``status=error`` carrying the upstream detail, not as a
    generic 500."""
    connector = _make_connector()
    resp = _mock_response(401, {"detail": "invalid token"})
    with (
        _patched_vault(decrypt_return={"token": "expired"}),
        _patched_post(resp),
    ):
        verdict, rows = await _query_one_backend(
            connector,
            query_payload={"free_text": "x"},
            timeout=httpx.Timeout(5.0),
        )
    assert verdict.status == "error"
    assert "401" in (verdict.error or "")
    assert "invalid token" in (verdict.error or "")
    assert rows == []


@pytest.mark.asyncio
async def test_query_one_backend_5xx_surfaces_status() -> None:
    """500 from the backend behaves the same way — ``status=error``,
    other backends still get to run."""
    connector = _make_connector()
    resp = _mock_response(500, {"detail": "splunk indexer down"})
    with (
        _patched_vault(decrypt_return={"token": "ok"}),
        _patched_post(resp),
    ):
        verdict, _ = await _query_one_backend(
            connector,
            query_payload={"free_text": "x"},
            timeout=httpx.Timeout(5.0),
        )
    assert verdict.status == "error"
    assert "500" in (verdict.error or "")


@pytest.mark.asyncio
async def test_query_one_backend_4xx_with_non_json_body_falls_back_to_text() -> None:
    """Some backends return text/html error pages on auth failures.
    The helper must not blow up trying to ``.json()`` such responses."""
    connector = _make_connector()
    resp = _mock_response(403, "<html>Forbidden</html>")
    resp.json = MagicMock(side_effect=ValueError("not json"))
    resp.text = "<html>Forbidden</html>"
    with (
        _patched_vault(decrypt_return={"token": "x"}),
        _patched_post(resp),
    ):
        verdict, _ = await _query_one_backend(
            connector,
            query_payload={"free_text": "x"},
            timeout=httpx.Timeout(5.0),
        )
    assert verdict.status == "error"
    assert "403" in (verdict.error or "")


@pytest.mark.asyncio
async def test_query_one_backend_success_tags_rows_with_source() -> None:
    """The merge step relies on every row carrying its origin so the UI
    can render "Splunk OK · Sentinel timeout · Elastic OK" with row-level
    provenance. Confirm the tag is added to dict rows."""
    connector = _make_connector(name="Prod Splunk", connector_type="splunk")
    upstream_rows = [
        {"_time": "2026-05-05T00:00:00Z", "user": "alice"},
        {"_time": "2026-05-05T00:01:00Z", "user": "bob"},
    ]
    resp = _mock_response(200, {"rows": upstream_rows}, content=b'{"rows": []}')
    with (
        _patched_vault(decrypt_return={"token": "ok"}),
        _patched_post(resp),
    ):
        verdict, rows = await _query_one_backend(
            connector,
            query_payload={"free_text": "x"},
            timeout=httpx.Timeout(5.0),
        )
    assert verdict.status == "ok"
    assert verdict.row_count == 2
    assert len(rows) == 2
    for row in rows:
        assert "_aisoc_source" in row
        assert row["_aisoc_source"]["connector_type"] == "splunk"
        assert row["_aisoc_source"]["connector_name"] == "Prod Splunk"
        assert row["_aisoc_source"]["connector_id"] == str(connector.id)


@pytest.mark.asyncio
async def test_query_one_backend_does_not_overwrite_existing_aisoc_source() -> None:
    """If a SIEM somehow returns a row that already has ``_aisoc_source``
    we keep the original — overwriting silently would mask a real
    upstream bug. ``setdefault`` is the right primitive here."""
    connector = _make_connector()
    pre_tagged = {"existing": True, "_aisoc_source": {"connector_type": "weird"}}
    resp = _mock_response(200, {"rows": [pre_tagged]})
    with (
        _patched_vault(decrypt_return={"token": "ok"}),
        _patched_post(resp),
    ):
        _, rows = await _query_one_backend(
            connector,
            query_payload={"free_text": "x"},
            timeout=httpx.Timeout(5.0),
        )
    assert rows[0]["_aisoc_source"] == {"connector_type": "weird"}


@pytest.mark.asyncio
async def test_query_one_backend_wraps_non_dict_rows() -> None:
    """If the connector returns scalars instead of dicts (a real
    historical Elastic quirk for single-column ES|QL), the merge layer
    needs every row to be a dict so its keys don't blow up downstream
    consumers. The helper wraps non-dict rows in ``{"value": ...}``."""
    connector = _make_connector()
    resp = _mock_response(200, {"rows": ["just-a-string", 42]})
    with (
        _patched_vault(decrypt_return={"token": "ok"}),
        _patched_post(resp),
    ):
        _, rows = await _query_one_backend(
            connector,
            query_payload={"free_text": "x"},
            timeout=httpx.Timeout(5.0),
        )
    assert len(rows) == 2
    assert all(isinstance(r, dict) for r in rows)
    assert rows[0]["value"] == "just-a-string"
    assert rows[1]["value"] == 42
    # Every wrapped row still gets the source tag.
    assert "_aisoc_source" in rows[0]


@pytest.mark.asyncio
async def test_query_one_backend_handles_missing_rows_key() -> None:
    """Defensive: a 200 with a body that omits ``rows`` is treated as zero
    results, not an exception."""
    connector = _make_connector()
    resp = _mock_response(200, {"warnings": ["no data"]})
    with (
        _patched_vault(decrypt_return={"token": "ok"}),
        _patched_post(resp),
    ):
        verdict, rows = await _query_one_backend(
            connector,
            query_payload={"free_text": "x"},
            timeout=httpx.Timeout(5.0),
        )
    assert verdict.status == "ok"
    assert verdict.row_count == 0
    assert rows == []


@pytest.mark.asyncio
async def test_query_one_backend_handles_non_list_rows_field() -> None:
    """If ``rows`` comes back as a string (some misconfigured plugin), we
    treat it as zero rows rather than crashing the iteration."""
    connector = _make_connector()
    resp = _mock_response(200, {"rows": "not-a-list"})
    with (
        _patched_vault(decrypt_return={"token": "ok"}),
        _patched_post(resp),
    ):
        verdict, rows = await _query_one_backend(
            connector,
            query_payload={"free_text": "x"},
            timeout=httpx.Timeout(5.0),
        )
    assert verdict.status == "ok"
    assert rows == []


# ----------------------------------------------------------------- _audit_event


def test_audit_event_records_only_field_names_not_values() -> None:
    """A federated query against a customer's SIEM may contain regulated
    identifiers in the indicator values (e.g. an email, a username, a
    hash). The audit log is tenant-shared — we record the *shape* of the
    query, never the values themselves."""
    tenant_id = uuid.uuid4()
    actor_id = uuid.uuid4()
    sources = [
        SourceVerdict(
            connector_id=uuid.uuid4(),
            connector_name="Prod Splunk",
            connector_type="splunk",
            status="ok",
            row_count=5,
            duration_ms=42,
        ),
        SourceVerdict(
            connector_id=uuid.uuid4(),
            connector_name="Prod Sentinel",
            connector_type="microsoft_sentinel",
            status="error",
            row_count=0,
            duration_ms=11,
            error="401 Unauthorized",
        ),
    ]

    event = _audit_event(
        tenant_id=tenant_id,
        actor_id=actor_id,
        actor_email="[email protected]",
        indicator_fields=["user.name", "src_ip"],
        sources=sources,
        row_count=5,
        since_seconds=3600,
    )

    assert event.action == "federated_search"
    assert event.resource == "federated"
    assert event.tenant_id == tenant_id
    assert event.actor_id == actor_id

    # Only field names are recorded; values would be a privacy leak.
    assert event.metadata_["indicator_fields"] == ["user.name", "src_ip"]
    assert event.metadata_["since_seconds"] == 3600
    assert event.metadata_["row_count"] == 5
    assert len(event.metadata_["sources"]) == 2
    # Verdict shape carries through intact.
    assert event.metadata_["sources"][0]["connector_type"] == "splunk"
    assert event.metadata_["sources"][0]["status"] == "ok"
    assert event.metadata_["sources"][1]["status"] == "error"


def test_audit_event_handles_empty_indicator_list() -> None:
    """A pure free-text federated query is still valid; the audit row
    must not blow up on an empty ``indicator_fields`` list."""
    event = _audit_event(
        tenant_id=uuid.uuid4(),
        actor_id=None,
        actor_email=None,
        indicator_fields=[],
        sources=[],
        row_count=0,
        since_seconds=600,
    )
    assert event.metadata_["indicator_fields"] == []
    assert event.metadata_["sources"] == []
    assert event.actor_id is None
    assert event.actor_email is None
