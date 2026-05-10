"""Unit tests for the case → ITSM fan-out service (Workstream 8).

The fan-out service projects AiSOC case lifecycle events onto external
ITSM systems via the connectors microservice. The behaviour we care
about most:

* ``_serialize_case_for_push`` — converts ORM rows / mappings into a
  bounded payload (no observable_graph, no evidence_chain) so a noisy
  Jira logger can't accidentally exfiltrate intra-tenant data.
* ``_post_to_connector_service`` — wraps every ``httpx`` failure mode
  into a tagged status string so the calling endpoint never has to
  catch transport errors itself.
* ``fanout_create_case`` — happy path, vault decrypt failure, 501
  unsupported, transport error, missing ``external_id`` in body.
* ``fanout_status_change`` — walks ``case_external_refs``, surfaces
  orphaned refs as ``skipped`` (FK is on case_id, not connector_id),
  and updates the persisted ``external_status``.

We mock the AsyncSession the same way ``test_inbox_itsm_endpoint`` does
— a ``MagicMock`` with ``execute`` as ``AsyncMock`` — and patch ``httpx``
+ the credential vault rather than booting the full FastAPI app. That
keeps each test focused on a single decision branch in the fan-out
state machine.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from app.services.case_fanout import (
    ITSM_PUSH_CAPABLE_TYPES,
    FanoutResult,
    _post_to_connector_service,
    _push_case_url,
    _push_status_url,
    _serialize_case_for_push,
    fanout_create_case,
    fanout_status_change,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_connector(
    *,
    connector_id: uuid.UUID | None = None,
    connector_type: str = "jira",
    name: str = "Jira (Prod)",
    auth_config: dict[str, Any] | None = None,
    connector_config: dict[str, Any] | None = None,
    is_enabled: bool = True,
    tenant_id: uuid.UUID | None = None,
) -> SimpleNamespace:
    """Build a minimal ORM-shaped Connector stub.

    SimpleNamespace mirrors the attribute access pattern the fan-out
    code uses (``connector.id``, ``connector.connector_type``, …) so we
    don't need to instantiate the real SQLAlchemy model and risk session
    binding side-effects.
    """
    return SimpleNamespace(
        id=connector_id or uuid.uuid4(),
        tenant_id=tenant_id or uuid.uuid4(),
        connector_type=connector_type,
        name=name,
        is_enabled=is_enabled,
        auth_config=auth_config or {"api_token": "vault:v1:zzz"},
        connector_config=connector_config or {"site_url": "https://example.atlassian.net"},
    )


def _make_case_row(
    *,
    case_id: uuid.UUID | None = None,
    status: str = "open",
    title: str = "Phishing wave from acme.bad",
    severity: str = "high",
) -> dict[str, Any]:
    """Build a case row with the columns ``_serialize_case_for_push`` reads.

    We return a plain dict because ``_serialize_case_for_push`` accepts
    ORM Row (with ``_mapping``) or dict — not raw SimpleNamespace. The
    serializer reads the ``id``/``status``/``title`` columns and ignores
    everything else, so we deliberately include ``observable_graph`` and
    ``evidence_chain`` as honeypots: if they ever appear in the output
    payload, the ``_serialize_case_for_push_drops_internal_fields`` test
    will fail.
    """
    return {
        "id": case_id or uuid.uuid4(),
        "case_number": "AISOC-1234",
        "title": title,
        "description": "Operator notes",
        "severity": severity,
        "status": status,
        "assignee": None,
        "tags": {"env": "prod"},
        "mitre_techniques": ["T1566"],
        # Honeypot fields — must NOT be in serialized payload.
        "observable_graph": {"nodes": ["leak"]},
        "evidence_chain": [{"hash": "secret"}],
    }


def _build_db_with_connectors(
    connectors: list[Any],
    refs: list[dict[str, Any]] | None = None,
) -> Any:
    """Build a MagicMock DB session that replays the queries fan-out runs.

    ``fanout_create_case`` issues exactly one ``select(Connector)``
    followed by zero-or-more ``_upsert_external_ref`` writes. We set up
    ``side_effect`` on ``execute`` so the ``select`` returns a result
    whose ``.scalars().all()`` matches ``connectors``, and subsequent
    INSERT calls just return a no-op MagicMock.

    ``fanout_status_change`` issues:
      1. a ``SELECT`` against ``case_external_refs`` returning ``refs``,
      2. a ``select(Connector)`` returning ``connectors``,
      3. one ``INSERT … ON CONFLICT`` per ref.

    We let any extra ``execute`` calls fall through to a plain MagicMock
    so writes don't blow up the test even if the count drifts by one.
    """
    db = MagicMock()
    select_result = MagicMock()
    select_result.scalars.return_value.all.return_value = list(connectors)

    refs_result = MagicMock()
    refs_result.fetchall.return_value = [SimpleNamespace(_mapping=ref) for ref in (refs or [])]

    side_effects: list[Any] = []
    if refs is not None:
        # Status-change path: refs first, connectors second, then writes.
        side_effects.append(refs_result)
    side_effects.append(select_result)
    # Pad out write responses; AsyncMock side_effect runs out → re-uses
    # the last entry only if it's a callable, so we explicitly pad.
    for _ in range(8):
        side_effects.append(MagicMock())

    db.execute = AsyncMock(side_effect=side_effects)
    return db


def _build_post_response(
    *,
    status_code: int = 200,
    json_body: dict[str, Any] | None = None,
    text_body: str | None = None,
) -> Any:
    """Build a fake httpx Response. Avoids the real Response constructor
    so we can drive ``resp.json()`` / ``resp.text`` shape directly."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.content = b"non-empty" if (json_body is not None or text_body) else b""
    if json_body is not None:
        resp.json.return_value = json_body
    else:
        resp.json.side_effect = ValueError("no json")
    resp.text = text_body or ""
    return resp


# ---------------------------------------------------------------------------
# URL helpers
# ---------------------------------------------------------------------------


def test_push_case_url_uses_connectors_service_base() -> None:
    url = _push_case_url("jira")
    assert url.endswith("/api/v1/connectors/jira/push_case")


def test_push_status_url_uses_connectors_service_base() -> None:
    url = _push_status_url("servicenow")
    assert url.endswith("/api/v1/connectors/servicenow/push_status_change")


def test_itsm_push_capable_types_is_locked_down() -> None:
    """The allow-list MUST stay tight. Adding a new connector here
    enables fan-out for that vendor; do not relax casually."""
    assert ITSM_PUSH_CAPABLE_TYPES == frozenset({"jira", "servicenow"})


# ---------------------------------------------------------------------------
# _serialize_case_for_push
# ---------------------------------------------------------------------------


def test_serialize_case_for_push_drops_internal_fields() -> None:
    """Observable graph + evidence chain must NEVER be in the outbound
    payload. A misconfigured Jira logger that dumps the request body
    would leak intra-tenant graph data otherwise."""
    case = _make_case_row()
    payload = _serialize_case_for_push(case)
    assert "observable_graph" not in payload
    assert "evidence_chain" not in payload
    assert payload["title"] == case["title"]
    assert payload["status"] == case["status"]
    assert payload["mitre_techniques"] == ["T1566"]
    assert payload["tags"] == {"env": "prod"}


def test_serialize_case_for_push_handles_dict_input() -> None:
    case_id = uuid.uuid4()
    payload = _serialize_case_for_push({"id": case_id, "title": "T", "status": "open", "severity": "low"})
    assert payload["id"] == str(case_id)
    assert payload["title"] == "T"
    # Defaults for unset list/dict columns.
    assert payload["tags"] == {}
    assert payload["mitre_techniques"] == []


def test_serialize_case_for_push_handles_row_with_mapping() -> None:
    """SQLAlchemy returns ``Row`` with ``_mapping`` for raw text() results.
    The serializer must accept both ORM-style attribute access and the
    Row mapping protocol."""
    case_id = uuid.uuid4()
    row = SimpleNamespace(_mapping={"id": case_id, "title": "from-row", "status": "closed"})
    payload = _serialize_case_for_push(row)
    assert payload["id"] == str(case_id)
    assert payload["title"] == "from-row"


# ---------------------------------------------------------------------------
# _post_to_connector_service
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_post_returns_ok_on_2xx() -> None:
    fake_resp = _build_post_response(
        status_code=200,
        json_body={"external_id": "AIS-1", "vendor": "jira"},
    )
    with patch("app.services.case_fanout.httpx.AsyncClient") as mock_client:
        mock_client.return_value.__aenter__.return_value.post = AsyncMock(return_value=fake_resp)
        status, body, err = await _post_to_connector_service(url="http://x/y", payload={}, timeout_seconds=5.0)
    assert status == "ok"
    assert body == {"external_id": "AIS-1", "vendor": "jira"}
    assert err is None


@pytest.mark.asyncio
async def test_post_returns_unsupported_on_501() -> None:
    fake_resp = _build_post_response(status_code=501, text_body="capability missing")
    with patch("app.services.case_fanout.httpx.AsyncClient") as mock_client:
        mock_client.return_value.__aenter__.return_value.post = AsyncMock(return_value=fake_resp)
        status, body, err = await _post_to_connector_service(url="http://x/y", payload={}, timeout_seconds=5.0)
    assert status == "unsupported"
    assert body is None
    assert err == "capability missing"


@pytest.mark.asyncio
async def test_post_returns_error_on_4xx_with_detail() -> None:
    fake_resp = _build_post_response(
        status_code=400,
        json_body={"detail": "missing project_key"},
    )
    with patch("app.services.case_fanout.httpx.AsyncClient") as mock_client:
        mock_client.return_value.__aenter__.return_value.post = AsyncMock(return_value=fake_resp)
        status, body, err = await _post_to_connector_service(url="http://x/y", payload={}, timeout_seconds=5.0)
    assert status == "error"
    assert body is None
    assert "missing project_key" in (err or "")


@pytest.mark.asyncio
async def test_post_returns_error_on_transport_failure() -> None:
    """``httpx.HTTPError`` (DNS, refused, timeout) must NOT escape.

    Fan-out is best-effort; a flaky Jira tenant must not 503 the case
    create endpoint."""
    with patch("app.services.case_fanout.httpx.AsyncClient") as mock_client:
        mock_client.return_value.__aenter__.return_value.post = AsyncMock(side_effect=httpx.ConnectError("dns failed"))
        status, body, err = await _post_to_connector_service(url="http://x/y", payload={}, timeout_seconds=5.0)
    assert status == "error"
    assert body is None
    assert "connectors service unreachable" in (err or "")


@pytest.mark.asyncio
async def test_post_returns_error_on_non_dict_body() -> None:
    """A connectors service that returns ``[1,2,3]`` is buggy. Surface
    that as an error rather than crashing further down with KeyError."""
    fake_resp = _build_post_response(status_code=200, json_body=[1, 2, 3])  # type: ignore[arg-type]
    with patch("app.services.case_fanout.httpx.AsyncClient") as mock_client:
        mock_client.return_value.__aenter__.return_value.post = AsyncMock(return_value=fake_resp)
        status, body, err = await _post_to_connector_service(url="http://x/y", payload={}, timeout_seconds=5.0)
    assert status == "error"
    assert "unexpected payload shape" in (err or "")


# ---------------------------------------------------------------------------
# fanout_create_case
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fanout_create_case_returns_empty_when_no_connectors() -> None:
    """Common case: operator created a case without selecting any
    connectors. We must NOT contact the connectors service at all."""
    db = MagicMock()
    db.execute = AsyncMock()
    case = _make_case_row()
    results = await fanout_create_case(
        db,
        case_row=case,
        tenant_id=uuid.uuid4(),
        connector_ids=[],
    )
    assert results == []
    assert db.execute.await_count == 0


@pytest.mark.asyncio
async def test_fanout_create_case_happy_path_persists_external_ref() -> None:
    """End-to-end: vault decrypts → connectors POST returns external_id
    → ``case_external_refs`` row gets upserted → ``FanoutResult`` carries
    the external linkage back to the caller."""
    tenant_id = uuid.uuid4()
    case = _make_case_row()
    connector = _make_connector(connector_type="jira", tenant_id=tenant_id)
    db = _build_db_with_connectors([connector])

    fake_resp = _build_post_response(
        status_code=200,
        json_body={
            "external_id": "AIS-42",
            "external_url": "https://example.atlassian.net/browse/AIS-42",
            "vendor": "jira",
            "external_status": "To Do",
        },
    )

    with (
        patch("app.services.case_fanout.get_vault") as mock_vault,
        patch("app.services.case_fanout.httpx.AsyncClient") as mock_client,
    ):
        mock_vault.return_value.decrypt_dict.return_value = {"api_token": "plain"}
        mock_client.return_value.__aenter__.return_value.post = AsyncMock(return_value=fake_resp)
        results = await fanout_create_case(
            db,
            case_row=case,
            tenant_id=tenant_id,
            connector_ids=[connector.id],
            pushed_by="operator@aisoc.dev",
        )

    assert len(results) == 1
    result = results[0]
    assert result.status == "ok"
    assert result.external_id == "AIS-42"
    assert result.external_url == "https://example.atlassian.net/browse/AIS-42"
    assert result.connector_type == "jira"
    # 1 select + 1 upsert.
    assert db.execute.await_count >= 2


@pytest.mark.asyncio
async def test_fanout_create_case_credential_vault_failure_short_circuits() -> None:
    """When vault decryption fails we MUST NOT POST to the connectors
    service — the auth_config dict in transit would still be ciphertext.
    Surface the failure as an ``error`` FanoutResult."""
    from app.security.credential_vault import CredentialVaultError

    tenant_id = uuid.uuid4()
    case = _make_case_row()
    connector = _make_connector(connector_type="jira", tenant_id=tenant_id)
    db = _build_db_with_connectors([connector])

    with (
        patch("app.services.case_fanout.get_vault") as mock_vault,
        patch("app.services.case_fanout.httpx.AsyncClient") as mock_client,
    ):
        mock_vault.return_value.decrypt_dict.side_effect = CredentialVaultError("key rotated")
        post_mock = AsyncMock()
        mock_client.return_value.__aenter__.return_value.post = post_mock
        results = await fanout_create_case(
            db,
            case_row=case,
            tenant_id=tenant_id,
            connector_ids=[connector.id],
        )

    assert len(results) == 1
    assert results[0].status == "error"
    assert "credential decryption failed" in (results[0].error or "")
    post_mock.assert_not_awaited()


@pytest.mark.asyncio
async def test_fanout_create_case_unsupported_capability_is_recorded() -> None:
    """A 501 from the connectors service means the connector type
    doesn't declare ``Capability.PUSH_CASE``. We surface ``unsupported``
    rather than treating that as a hard error."""
    tenant_id = uuid.uuid4()
    case = _make_case_row()
    connector = _make_connector(connector_type="jira", tenant_id=tenant_id)
    db = _build_db_with_connectors([connector])

    fake_resp = _build_post_response(status_code=501, text_body="not supported")
    with (
        patch("app.services.case_fanout.get_vault") as mock_vault,
        patch("app.services.case_fanout.httpx.AsyncClient") as mock_client,
    ):
        mock_vault.return_value.decrypt_dict.return_value = {"api_token": "plain"}
        mock_client.return_value.__aenter__.return_value.post = AsyncMock(return_value=fake_resp)
        results = await fanout_create_case(
            db,
            case_row=case,
            tenant_id=tenant_id,
            connector_ids=[connector.id],
        )

    assert len(results) == 1
    assert results[0].status == "unsupported"
    assert results[0].external_id is None


@pytest.mark.asyncio
async def test_fanout_create_case_missing_external_id_is_error() -> None:
    """If the connectors service returns 200 but no ``external_id``,
    we have nothing useful to persist. Don't write a malformed row to
    ``case_external_refs``; surface as an error instead."""
    tenant_id = uuid.uuid4()
    case = _make_case_row()
    connector = _make_connector(connector_type="jira", tenant_id=tenant_id)
    db = _build_db_with_connectors([connector])

    fake_resp = _build_post_response(
        status_code=200,
        json_body={"vendor": "jira"},  # no external_id!
    )
    with (
        patch("app.services.case_fanout.get_vault") as mock_vault,
        patch("app.services.case_fanout.httpx.AsyncClient") as mock_client,
    ):
        mock_vault.return_value.decrypt_dict.return_value = {"api_token": "plain"}
        mock_client.return_value.__aenter__.return_value.post = AsyncMock(return_value=fake_resp)
        results = await fanout_create_case(
            db,
            case_row=case,
            tenant_id=tenant_id,
            connector_ids=[connector.id],
        )

    assert len(results) == 1
    assert results[0].status == "error"
    assert "external_id" in (results[0].error or "")


# ---------------------------------------------------------------------------
# fanout_status_change
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fanout_status_change_no_refs_means_no_push() -> None:
    """Cases that were never pushed to any ITSM have no rows in
    ``case_external_refs``. The status change is a no-op for fan-out
    — the connectors service never gets called."""
    tenant_id = uuid.uuid4()
    case = _make_case_row()
    db = _build_db_with_connectors(connectors=[], refs=[])

    with patch("app.services.case_fanout.httpx.AsyncClient") as mock_client:
        post_mock = AsyncMock()
        mock_client.return_value.__aenter__.return_value.post = post_mock
        results = await fanout_status_change(
            db,
            case_row=case,
            tenant_id=tenant_id,
            old_status="open",
            new_status="resolved",
        )

    assert results == []
    post_mock.assert_not_awaited()


@pytest.mark.asyncio
async def test_fanout_status_change_orphaned_ref_is_skipped() -> None:
    """The connector instance was deleted but the external_ref row
    survived (FK is on case_id). Surface as ``skipped`` so operators
    can see the orphan and either re-link or clean up."""
    tenant_id = uuid.uuid4()
    case = _make_case_row()
    orphan_connector_id = uuid.uuid4()
    refs = [
        {
            "id": uuid.uuid4(),
            "case_id": case["id"],
            "connector_instance_id": orphan_connector_id,
            "vendor": "jira",
            "external_id": "AIS-99",
            "external_url": "https://example/browse/AIS-99",
            "external_status": "Done",
        }
    ]
    # No matching connector in the live ``connectors`` table.
    db = _build_db_with_connectors(connectors=[], refs=refs)

    results = await fanout_status_change(
        db,
        case_row=case,
        tenant_id=tenant_id,
        old_status="open",
        new_status="resolved",
    )

    assert len(results) == 1
    assert results[0].status == "skipped"
    assert results[0].external_id == "AIS-99"
    assert "no longer exists" in (results[0].error or "")


@pytest.mark.asyncio
async def test_fanout_status_change_happy_path_updates_external_status() -> None:
    """End-to-end: ref lookup → connector lookup → POST to
    ``push_status_change`` → upsert refreshed ``external_status``."""
    tenant_id = uuid.uuid4()
    case = _make_case_row(status="resolved")
    connector = _make_connector(connector_type="jira", tenant_id=tenant_id)
    refs = [
        {
            "id": uuid.uuid4(),
            "case_id": case["id"],
            "connector_instance_id": connector.id,
            "vendor": "jira",
            "external_id": "AIS-7",
            "external_url": "https://example/browse/AIS-7",
            "external_status": "In Progress",
        }
    ]
    db = _build_db_with_connectors([connector], refs=refs)

    fake_resp = _build_post_response(
        status_code=200,
        json_body={
            "external_id": "AIS-7",
            "vendor": "jira",
            "external_url": "https://example/browse/AIS-7",
            "external_status": "Done",
        },
    )

    with (
        patch("app.services.case_fanout.get_vault") as mock_vault,
        patch("app.services.case_fanout.httpx.AsyncClient") as mock_client,
    ):
        mock_vault.return_value.decrypt_dict.return_value = {"api_token": "plain"}
        mock_client.return_value.__aenter__.return_value.post = AsyncMock(return_value=fake_resp)
        results = await fanout_status_change(
            db,
            case_row=case,
            tenant_id=tenant_id,
            old_status="open",
            new_status="resolved",
            pushed_by="operator@aisoc.dev",
        )

    assert len(results) == 1
    assert results[0].status == "ok"
    assert results[0].external_id == "AIS-7"
    assert results[0].external_status == "Done"


@pytest.mark.asyncio
async def test_fanout_status_change_transport_error_records_failure() -> None:
    """A network error pushing the status change must surface as
    ``error`` with the external_id preserved, so the UI can show
    'Jira ✗ (timeout)' next to AIS-7 instead of dropping the linkage."""
    tenant_id = uuid.uuid4()
    case = _make_case_row(status="resolved")
    connector = _make_connector(connector_type="jira", tenant_id=tenant_id)
    refs = [
        {
            "id": uuid.uuid4(),
            "case_id": case["id"],
            "connector_instance_id": connector.id,
            "vendor": "jira",
            "external_id": "AIS-7",
            "external_url": "https://example/browse/AIS-7",
            "external_status": "In Progress",
        }
    ]
    db = _build_db_with_connectors([connector], refs=refs)

    with (
        patch("app.services.case_fanout.get_vault") as mock_vault,
        patch("app.services.case_fanout.httpx.AsyncClient") as mock_client,
    ):
        mock_vault.return_value.decrypt_dict.return_value = {"api_token": "plain"}
        mock_client.return_value.__aenter__.return_value.post = AsyncMock(side_effect=httpx.ReadTimeout("read timed out"))
        results = await fanout_status_change(
            db,
            case_row=case,
            tenant_id=tenant_id,
            old_status="open",
            new_status="resolved",
        )

    assert len(results) == 1
    assert results[0].status == "error"
    assert results[0].external_id == "AIS-7"
    assert "unreachable" in (results[0].error or "")


# ---------------------------------------------------------------------------
# FanoutResult contract
# ---------------------------------------------------------------------------


def test_fanout_result_serializable_for_api_response() -> None:
    """The Pydantic model has to round-trip through JSON because the
    create-case endpoint embeds ``ticket_refs`` directly into its 201
    response body. ``model_dump_json`` is the smoke test for that."""
    cid = uuid.uuid4()
    r = FanoutResult(
        connector_id=cid,
        connector_type="jira",
        connector_name="Jira (Prod)",
        status="ok",
        external_id="AIS-1",
        external_url="https://example/browse/AIS-1",
        external_status="To Do",
    )
    payload = r.model_dump_json()
    assert str(cid) in payload
    assert "AIS-1" in payload
    assert '"status":"ok"' in payload
