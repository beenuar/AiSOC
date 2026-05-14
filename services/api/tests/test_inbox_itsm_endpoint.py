"""Unit tests for the inbound ITSM webhook (Workstream 8).

The webhook at ``POST /api/v1/inbox/itsm/{tenant_token}/{connector_instance_id}``
is the *inbound* counterpart to ``case_fanout``. Vendor systems (Jira,
ServiceNow) hit it when a ticket transitions, and we mirror the new
status onto ``aisoc_cases``.

Like ``test_lake_endpoint.py`` we keep the assertions on the small
helpers that own the meaningful behaviour, and exercise the endpoint
itself via mocked DB sessions instead of spinning up the FastAPI app
+ Postgres harness:

* ``_verify_hmac`` — constant-time HMAC verification with both
  ``sha256=<hex>`` and bare ``<hex>`` styles. The auth model collapses
  to "URL token only" when no secret is configured, which is its own
  branch.
* ``_parse_jira_payload`` — defensive extraction of ``issue.key`` and
  ``issue.fields.status.name`` from a Jira webhook. Real-world payloads
  routinely omit fields we'd otherwise crash on.
* ``_parse_servicenow_payload`` — accepts both the canonical ``incident``
  shape and the ``{"current": {...}}`` wrapper that ServiceNow Business
  Rules emit when the operator forwards ``current`` directly.
* ``_map_inbound_status`` — vendor → AiSOC enum, intentionally lossy.
  Anything we can't map returns None and the caller treats that as
  "no status change".
* ``inbound_itsm_webhook`` — happy path, HMAC enforcement, JSON parse
  failures, unknown external IDs, idempotent redelivery, and the
  vendor-specific dispatch. Mocks ``DBSession`` directly because the
  endpoint is mostly orchestration and the SQL strings are already
  covered by the migration tests.
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
import json
import uuid
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.api.v1.endpoints.inbox_itsm import (
    _ITSM_TEMPLATE_ID,
    InboundResult,
    _apply_status_to_case,
    _fetch_token_and_connector,
    _map_inbound_status,
    _parse_jira_payload,
    _parse_servicenow_payload,
    _verify_hmac,
    inbound_itsm_webhook,
)
from fastapi import HTTPException

# ---------------------------------------------------------------------------
# _verify_hmac — auth glue. The biggest single attack surface for the
# whole module: a bug here is "anyone can set any case status", so the
# test list is intentionally adversarial.
# ---------------------------------------------------------------------------


def _expected_sig(secret: str, body: bytes) -> str:
    return _hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def test_verify_hmac_no_secret_is_noop() -> None:
    """Tokens minted without an HMAC secret authenticate via URL only.

    This is the correct behaviour for ServiceNow installs that don't
    expose the BR-side signing knob. We MUST NOT raise here — doing so
    would brick the most common webhook configuration.
    """
    _verify_hmac(secret=None, raw_body=b"anything", signature_header=None)
    _verify_hmac(secret=None, raw_body=b"anything", signature_header="sha256=garbage")


def test_verify_hmac_missing_signature_when_secret_set_raises_401() -> None:
    """A configured secret demands a signature; the absence is auth failure."""
    with pytest.raises(HTTPException) as exc:
        _verify_hmac(secret="topsecret", raw_body=b"{}", signature_header=None)
    assert exc.value.status_code == 401
    assert "HMAC signature required" in exc.value.detail


def test_verify_hmac_blank_signature_when_secret_set_raises_401() -> None:
    """An all-whitespace header is treated as missing.

    Vendors occasionally emit ``X-AiSOC-Signature: `` when their secret
    isn't templated correctly. We refuse it explicitly so the operator
    notices.
    """
    with pytest.raises(HTTPException):
        _verify_hmac(secret="topsecret", raw_body=b"{}", signature_header="   ")


def test_verify_hmac_accepts_sha256_prefixed_signature() -> None:
    """GitHub-style ``sha256=<hex>`` matches a hex digest."""
    body = b'{"hello":"world"}'
    sig = f"sha256={_expected_sig('seekret', body)}"
    _verify_hmac(secret="seekret", raw_body=body, signature_header=sig)


def test_verify_hmac_accepts_bare_hex_signature() -> None:
    """ServiceNow / bespoke proxies post bare hex without a prefix."""
    body = b'{"sys_id":"abc"}'
    sig = _expected_sig("seekret", body)
    _verify_hmac(secret="seekret", raw_body=body, signature_header=sig)


def test_verify_hmac_signature_mismatch_raises_401() -> None:
    """Tampered body invalidates the signature."""
    sig = _expected_sig("seekret", b"original")
    with pytest.raises(HTTPException) as exc:
        _verify_hmac(secret="seekret", raw_body=b"tampered", signature_header=sig)
    assert exc.value.status_code == 401
    assert "Invalid HMAC" in exc.value.detail


def test_verify_hmac_wrong_secret_raises_401() -> None:
    """A signature computed with a different secret must not pass.

    Defends against operator copy-paste error (rotated the inbox token
    secret server-side but forgot to update the vendor side).
    """
    body = b'{"a":1}'
    sig = f"sha256={_expected_sig('wrong-secret', body)}"
    with pytest.raises(HTTPException):
        _verify_hmac(secret="seekret", raw_body=body, signature_header=sig)


def test_verify_hmac_case_insensitive_hex_match() -> None:
    """Some vendors uppercase the hex digest. We accept either case."""
    body = b'{"foo":"bar"}'
    sig = _expected_sig("seekret", body).upper()
    _verify_hmac(secret="seekret", raw_body=body, signature_header=sig)


# ---------------------------------------------------------------------------
# _parse_jira_payload
# ---------------------------------------------------------------------------


def test_parse_jira_payload_happy_path() -> None:
    """Standard ``jira:issue_updated`` shape extracts issue key + status name."""
    payload: dict[str, Any] = {
        "webhookEvent": "jira:issue_updated",
        "issue": {
            "key": "AIS-1234",
            "fields": {"status": {"name": "In Progress"}},
        },
    }
    assert _parse_jira_payload(payload) == ("AIS-1234", "In Progress")


def test_parse_jira_payload_missing_issue_returns_none_pair() -> None:
    """Heartbeat / synthetic payloads skip the writes entirely."""
    assert _parse_jira_payload({"webhookEvent": "ping"}) == (None, None)


def test_parse_jira_payload_issue_not_dict_returns_none_pair() -> None:
    """Defensive: don't crash if Jira ever ships ``issue: null``."""
    assert _parse_jira_payload({"issue": None}) == (None, None)
    assert _parse_jira_payload({"issue": "AIS-1"}) == (None, None)


def test_parse_jira_payload_missing_key_returns_none_pair() -> None:
    """Empty issue.key means nothing to correlate."""
    assert _parse_jira_payload({"issue": {"key": ""}}) == (None, None)


def test_parse_jira_payload_missing_status_keeps_key() -> None:
    """A renamed-issue webhook has no status; we still return the key.

    The endpoint then treats ``raw_status=None`` as "no transition" and
    short-circuits. We need the key to bump ``last_synced_at`` even
    when the actual status didn't change.
    """
    payload = {"issue": {"key": "AIS-7", "fields": {}}}
    assert _parse_jira_payload(payload) == ("AIS-7", None)


def test_parse_jira_payload_status_not_dict_keeps_key() -> None:
    """``fields.status`` may be a string in odd custom workflows; ignore."""
    payload = {"issue": {"key": "AIS-7", "fields": {"status": "Done"}}}
    assert _parse_jira_payload(payload) == ("AIS-7", None)


def test_parse_jira_payload_fields_not_dict_keeps_key() -> None:
    """Defensive against Jira's ``fields: null`` on bare-bones webhooks."""
    payload = {"issue": {"key": "AIS-9", "fields": None}}
    assert _parse_jira_payload(payload) == ("AIS-9", None)


# ---------------------------------------------------------------------------
# _parse_servicenow_payload
# ---------------------------------------------------------------------------


def test_parse_servicenow_payload_canonical_shape() -> None:
    """REST-Table-API-shaped payload (top-level fields)."""
    payload = {"sys_id": "abc123", "state": "6", "short_description": "boom"}
    assert _parse_servicenow_payload(payload) == ("abc123", "6")


def test_parse_servicenow_payload_current_wrapper_shape() -> None:
    """Business Rule forwarding wraps the GlideRecord in ``current``.

    The two shapes look almost identical and operators routinely ship
    one when they meant the other. We accept both.
    """
    payload = {"current": {"sys_id": "abc123", "state": "7"}}
    assert _parse_servicenow_payload(payload) == ("abc123", "7")


def test_parse_servicenow_payload_state_int_normalised_to_string() -> None:
    """ServiceNow's ``state`` is numeric in some payloads; we string-ify."""
    payload = {"sys_id": "abc", "state": 6}
    assert _parse_servicenow_payload(payload) == ("abc", "6")


def test_parse_servicenow_payload_missing_sys_id_returns_none_pair() -> None:
    """sys_id is the correlation key — without it we can't find the case."""
    assert _parse_servicenow_payload({"state": 6}) == (None, None)


def test_parse_servicenow_payload_empty_sys_id_returns_none_pair() -> None:
    """Defensive against BRs that emit ``sys_id: ""`` on creation."""
    assert _parse_servicenow_payload({"sys_id": "", "state": "1"}) == (None, None)


def test_parse_servicenow_payload_missing_state_keeps_sys_id() -> None:
    """An assignment-only webhook has no state change. Same logic as Jira."""
    assert _parse_servicenow_payload({"sys_id": "abc"}) == ("abc", None)


def test_parse_servicenow_payload_current_not_dict_returns_none_pair() -> None:
    """Defensive: ``current: null`` happens on initial deploy."""
    assert _parse_servicenow_payload({"current": None}) == (None, None)


# ---------------------------------------------------------------------------
# _map_inbound_status — the canonicalisation table. We assert the
# specific mappings because they're load-bearing for case workflow:
# a wrong row here means an operator's "Done" silently doesn't close
# the case.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw_status,expected",
    [
        # Common Jira flows
        ("To Do", "triaged"),
        ("Open", "triaged"),
        ("Backlog", "triaged"),
        ("In Progress", "investigating"),
        ("In Review", "investigating"),
        ("Blocked", "contained"),
        ("On Hold", "contained"),
        ("Resolved", "resolved"),
        ("Done", "resolved"),
        ("Closed", "closed"),
        ("Cancelled", "closed"),
        ("Won't Fix", "closed"),
        # Case insensitive — Jira emits status.name as-configured by the
        # admin, which often lowercases.
        ("done", "resolved"),
        ("DONE", "resolved"),
        # American spelling collapses too.
        ("Canceled", "closed"),
    ],
)
def test_map_inbound_status_jira_known_states(raw_status: str, expected: str) -> None:
    assert _map_inbound_status("jira", raw_status) == expected


def test_map_inbound_status_jira_unknown_returns_none() -> None:
    """Unmapped Jira statuses are a no-op, not an error."""
    assert _map_inbound_status("jira", "Awaiting Customer") is None


@pytest.mark.parametrize(
    "raw_status,expected",
    [
        ("1", "triaged"),
        ("2", "investigating"),
        ("3", "contained"),
        ("6", "resolved"),
        ("7", "closed"),
        ("8", "closed"),
    ],
)
def test_map_inbound_status_servicenow_known_states(raw_status: str, expected: str) -> None:
    assert _map_inbound_status("servicenow", raw_status) == expected


def test_map_inbound_status_servicenow_unknown_returns_none() -> None:
    """ServiceNow custom states (e.g. 100, 200) are skipped."""
    assert _map_inbound_status("servicenow", "100") is None


def test_map_inbound_status_unknown_vendor_returns_none() -> None:
    """A bug in the dispatch shouldn't accidentally close cases."""
    assert _map_inbound_status("pagerduty", "resolved") is None


def test_map_inbound_status_none_status_returns_none() -> None:
    """Idempotent: ``None`` in, ``None`` out."""
    assert _map_inbound_status("jira", None) is None


# ---------------------------------------------------------------------------
# _fetch_token_and_connector — auth + tenancy boundary. Every branch
# here is a 401/403/404/409 — i.e. potential cross-tenant or
# unauthorised access — so the coverage list is the threat model.
#
# The DB is mocked because we're testing the resolution logic, not
# Postgres semantics. The actual SQL is covered by the integration
# tests that exercise migration 035.
# ---------------------------------------------------------------------------


def _mock_db(token_row: Any | None, connector_row: Any | None) -> AsyncMock:
    """Build an AsyncMock DB whose two ``execute`` calls return the
    rows we want.

    The real endpoint runs the token query first, then the connector
    query, so we drive the mock with a ``side_effect`` queue.
    """
    db = MagicMock()
    token_result = MagicMock()
    token_result.fetchone = MagicMock(return_value=token_row)
    connector_result = MagicMock()
    connector_result.fetchone = MagicMock(return_value=connector_row)
    db.execute = AsyncMock(side_effect=[token_result, connector_result])
    return db


@pytest.mark.asyncio
async def test_fetch_token_and_connector_happy_path() -> None:
    """Valid token + matching tenant + supported vendor returns both rows."""
    tenant_id = uuid.uuid4()
    connector_id = uuid.uuid4()
    token_row = SimpleNamespace(
        token="tok-xyz",
        tenant_id=tenant_id,
        template_id=_ITSM_TEMPLATE_ID,
        hmac_secret=None,
        revoked_at=None,
    )
    connector_row = SimpleNamespace(
        id=connector_id,
        tenant_id=tenant_id,
        connector_type="jira",
        is_enabled=True,
    )
    db = _mock_db(token_row, connector_row)
    tok, conn = await _fetch_token_and_connector(db, tenant_token="tok-xyz", connector_instance_id=connector_id)
    assert tok is token_row
    assert conn is connector_row


@pytest.mark.asyncio
async def test_fetch_token_and_connector_missing_token_raises_401() -> None:
    """Revoked / never-existed tokens are auth failures."""
    db = _mock_db(token_row=None, connector_row=None)
    with pytest.raises(HTTPException) as exc:
        await _fetch_token_and_connector(db, tenant_token="tok-revoked", connector_instance_id=uuid.uuid4())
    assert exc.value.status_code == 401
    # Don't echo the full token in the error — leakage minimisation.
    assert "tok-revoked" not in str(exc.value.detail)


@pytest.mark.asyncio
async def test_fetch_token_and_connector_wrong_template_raises_403() -> None:
    """Token minted for a different template (e.g. PagerDuty) is rejected.

    Critical for blast-radius limiting: a leaked PagerDuty inbox token
    must NOT be re-purposable as an ITSM webhook authenticator.
    """
    tenant_id = uuid.uuid4()
    token_row = SimpleNamespace(
        token="tok-pagerduty",
        tenant_id=tenant_id,
        template_id="pagerduty-events",
        hmac_secret=None,
        revoked_at=None,
    )
    db = _mock_db(token_row, None)
    with pytest.raises(HTTPException) as exc:
        await _fetch_token_and_connector(db, tenant_token="tok-pagerduty", connector_instance_id=uuid.uuid4())
    assert exc.value.status_code == 403
    assert "itsm-inbound" in exc.value.detail


@pytest.mark.asyncio
async def test_fetch_token_and_connector_missing_connector_raises_404() -> None:
    """Connector deleted but the vendor still pings the old webhook URL."""
    tenant_id = uuid.uuid4()
    token_row = SimpleNamespace(
        token="tok-xyz",
        tenant_id=tenant_id,
        template_id=_ITSM_TEMPLATE_ID,
        hmac_secret=None,
        revoked_at=None,
    )
    db = _mock_db(token_row, connector_row=None)
    with pytest.raises(HTTPException) as exc:
        await _fetch_token_and_connector(db, tenant_token="tok-xyz", connector_instance_id=uuid.uuid4())
    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_fetch_token_and_connector_cross_tenant_raises_403() -> None:
    """Token from tenant A paired with connector from tenant B is forbidden.

    This is the most important test in the file from a security
    posture standpoint — a missing tenant check here would let any
    tenant project status onto any other tenant's cases.
    """
    token_row = SimpleNamespace(
        token="tok-xyz",
        tenant_id=uuid.uuid4(),  # tenant A
        template_id=_ITSM_TEMPLATE_ID,
        hmac_secret=None,
        revoked_at=None,
    )
    connector_row = SimpleNamespace(
        id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),  # tenant B — different
        connector_type="jira",
        is_enabled=True,
    )
    db = _mock_db(token_row, connector_row)
    with pytest.raises(HTTPException) as exc:
        await _fetch_token_and_connector(db, tenant_token="tok-xyz", connector_instance_id=connector_row.id)
    assert exc.value.status_code == 403
    assert "different tenants" in exc.value.detail


@pytest.mark.asyncio
async def test_fetch_token_and_connector_disabled_connector_raises_409() -> None:
    """Disabled connector = ops intentionally paused this integration.

    409 (not 200) so the vendor's webhook delivery dashboard surfaces
    the issue and the operator notices, instead of events silently
    dropping into the void.
    """
    tenant_id = uuid.uuid4()
    token_row = SimpleNamespace(
        token="tok-xyz",
        tenant_id=tenant_id,
        template_id=_ITSM_TEMPLATE_ID,
        hmac_secret=None,
        revoked_at=None,
    )
    connector_row = SimpleNamespace(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        connector_type="jira",
        is_enabled=False,
    )
    db = _mock_db(token_row, connector_row)
    with pytest.raises(HTTPException) as exc:
        await _fetch_token_and_connector(db, tenant_token="tok-xyz", connector_instance_id=connector_row.id)
    assert exc.value.status_code == 409


@pytest.mark.asyncio
async def test_fetch_token_and_connector_unsupported_vendor_raises_422() -> None:
    """Splunk-typed connector pointed at the ITSM URL is a config error."""
    tenant_id = uuid.uuid4()
    token_row = SimpleNamespace(
        token="tok-xyz",
        tenant_id=tenant_id,
        template_id=_ITSM_TEMPLATE_ID,
        hmac_secret=None,
        revoked_at=None,
    )
    connector_row = SimpleNamespace(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        connector_type="splunk",
        is_enabled=True,
    )
    db = _mock_db(token_row, connector_row)
    with pytest.raises(HTTPException) as exc:
        await _fetch_token_and_connector(db, tenant_token="tok-xyz", connector_instance_id=connector_row.id)
    assert exc.value.status_code == 422
    assert "splunk" in exc.value.detail


# ---------------------------------------------------------------------------
# _apply_status_to_case — the writes that actually mutate AiSOC state.
#
# We verify the SHAPE of the writes (correct table + bound parameters)
# rather than running them against a real DB. The migration tests are
# the right place to exercise the SQL itself; here we want to know
# the endpoint hands the right values to the right tables in the right
# order.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_apply_status_to_case_writes_three_rows() -> None:
    """Three writes per status change: case, ref, system comment.

    Order matters: case row first (the source of truth for status),
    then the ref (so the NEXT outbound push short-circuits), then the
    audit comment (read-only, can fail-but-shouldn't but isn't on the
    hot path). The transaction is committed by the caller — this fn
    must NOT call ``db.commit``.
    """
    db = MagicMock()
    db.execute = AsyncMock()
    # Explicitly attach commit/rollback as AsyncMock so we can assert
    # _apply_status_to_case does NOT call them. Without this, MagicMock
    # auto-creates attributes on access and ``hasattr`` is always True.
    db.commit = AsyncMock()
    db.rollback = AsyncMock()

    case_id = uuid.uuid4()
    case_row = SimpleNamespace(id=case_id)

    await _apply_status_to_case(
        db,
        case_row=case_row,
        new_status="resolved",
        actor_label="jira-webhook",
        external_id="AIS-42",
        vendor="jira",
    )

    # Three writes — case, ref, comment.
    assert db.execute.await_count == 3
    # Transaction lifecycle is the caller's responsibility (the endpoint),
    # not this helper's. The helper must stay pure-write so callers can
    # batch it with other writes inside one transaction.
    assert db.commit.await_count == 0
    assert db.rollback.await_count == 0


@pytest.mark.asyncio
async def test_apply_status_to_case_resolved_sets_resolved_at() -> None:
    """The ``resolved`` transition stamps resolved_at via COALESCE.

    We assert the SQL string contains ``resolved_at`` because that's
    the contract with the timeline view. ``closed_at`` must NOT appear
    on a 'resolved' transition (preventing it from being prematurely
    set, which would break SLA reporting).
    """
    db = MagicMock()
    db.execute = AsyncMock()
    case_row = SimpleNamespace(id=uuid.uuid4())

    await _apply_status_to_case(
        db,
        case_row=case_row,
        new_status="resolved",
        actor_label="jira-webhook",
        external_id="AIS-42",
        vendor="jira",
    )

    # First call is the aisoc_cases UPDATE — verify the dynamic columns.
    update_sql = str(db.execute.await_args_list[0].args[0])
    assert "resolved_at" in update_sql
    assert "closed_at" not in update_sql
    assert "triaged_at" in update_sql  # transitive: resolved implies triaged


@pytest.mark.asyncio
async def test_apply_status_to_case_closed_sets_closed_at() -> None:
    """The ``closed`` transition stamps closed_at."""
    db = MagicMock()
    db.execute = AsyncMock()
    case_row = SimpleNamespace(id=uuid.uuid4())

    await _apply_status_to_case(
        db,
        case_row=case_row,
        new_status="closed",
        actor_label="snow-webhook",
        external_id="abc-sys-id",
        vendor="servicenow",
    )

    update_sql = str(db.execute.await_args_list[0].args[0])
    assert "closed_at" in update_sql


@pytest.mark.asyncio
async def test_apply_status_to_case_triaged_does_not_stamp_resolved_or_closed() -> None:
    """Triage transitions only stamp triaged_at, not later milestones."""
    db = MagicMock()
    db.execute = AsyncMock()
    case_row = SimpleNamespace(id=uuid.uuid4())

    await _apply_status_to_case(
        db,
        case_row=case_row,
        new_status="triaged",
        actor_label="jira-webhook",
        external_id="AIS-1",
        vendor="jira",
    )

    update_sql = str(db.execute.await_args_list[0].args[0])
    assert "triaged_at" in update_sql
    assert "resolved_at" not in update_sql
    assert "closed_at" not in update_sql


def _bind_params(clause: Any) -> dict[str, Any]:
    """Extract bound parameter values from a SQLAlchemy ``TextClause``.

    SQLAlchemy 2.x doesn't expose a stable public accessor for
    ``text(...).bindparams(...)`` values, but ``_bindparams`` is the
    canonical storage on TextClause and has been stable across the
    1.4 → 2.x migration. We prefer it over ``compile().params`` because
    ``compile()`` requires a dialect and silently rewrites our :name
    parameters into ``%s`` style on a default Postgres dialect.
    """
    return {name: bp.value for name, bp in clause._bindparams.items()}


@pytest.mark.asyncio
async def test_apply_status_to_case_writes_system_comment_with_provenance() -> None:
    """The audit comment names the vendor + external_id for the timeline."""
    db = MagicMock()
    db.execute = AsyncMock()
    case_row = SimpleNamespace(id=uuid.uuid4())

    await _apply_status_to_case(
        db,
        case_row=case_row,
        new_status="resolved",
        actor_label="jira-webhook",
        external_id="AIS-9000",
        vendor="jira",
    )

    # Third call is the comment INSERT.
    comment_call = db.execute.await_args_list[2]
    bound = _bind_params(comment_call.args[0])
    assert bound["body"] is not None
    assert "AIS-9000" in bound["body"]
    assert "Jira" in bound["body"]
    assert "resolved" in bound["body"]
    assert bound["author"] == "jira-webhook"


# ---------------------------------------------------------------------------
# inbound_itsm_webhook — endpoint orchestration. We mock _fetch_token,
# _apply_status, and the DB so we can assert the dispatch logic
# (vendor → parser, parsed status → mapper, mapped status → write or
# no-op) without spinning the FastAPI app up.
# ---------------------------------------------------------------------------


def _build_request(body: bytes) -> MagicMock:
    """Build a Request-like mock whose ``body()`` returns ``body``."""
    req = MagicMock()
    req.body = AsyncMock(return_value=body)
    return req


def _build_db_for_endpoint(
    *,
    token_row: Any,
    connector_row: Any,
    ref_row: Any | None,
    case_already_in_target_status: bool = False,
) -> MagicMock:
    """Build a MagicMock DB whose execute() chain covers the endpoint flow.

    Order of execute() calls in the endpoint when we get past auth:
    1. SELECT token row
    2. SELECT connector row
    3. SELECT case_external_refs JOIN aisoc_cases (the 'ref_row' here)
    4. UPDATE tenant_inbox_tokens.last_used_at
    5..N. _apply_status_to_case writes (when status actually changes)
       OR UPDATE last_synced_at on case_external_refs (when it doesn't)

    We just queue enough MagicMock results to cover the longest path.
    """
    results = []
    # Token + connector
    for row in (token_row, connector_row):
        r = MagicMock()
        r.fetchone = MagicMock(return_value=row)
        results.append(r)
    # case_external_refs JOIN
    r = MagicMock()
    r.fetchone = MagicMock(return_value=ref_row)
    results.append(r)
    # last_used_at update + any subsequent UPDATEs all just return a
    # noop result; we don't .fetchone() on them.
    for _ in range(8):
        results.append(MagicMock())

    db = MagicMock()
    db.execute = AsyncMock(side_effect=results)
    # The endpoint commits at the end of the happy path and rolls back on
    # exception — both must be awaitable on this mock.
    db.commit = AsyncMock()
    db.rollback = AsyncMock()
    return db


@pytest.mark.asyncio
async def test_endpoint_invalid_json_raises_400() -> None:
    """Garbage body → 400 Bad Request, not a 500."""
    tenant_id = uuid.uuid4()
    connector_id = uuid.uuid4()
    token_row = SimpleNamespace(
        token="t",
        tenant_id=tenant_id,
        template_id=_ITSM_TEMPLATE_ID,
        hmac_secret=None,
        revoked_at=None,
    )
    connector_row = SimpleNamespace(
        id=connector_id,
        tenant_id=tenant_id,
        connector_type="jira",
        is_enabled=True,
    )
    db = _build_db_for_endpoint(token_row=token_row, connector_row=connector_row, ref_row=None)
    request = _build_request(b"this is not json")

    with pytest.raises(HTTPException) as exc:
        await inbound_itsm_webhook(
            tenant_token="t",
            connector_instance_id=connector_id,
            request=request,
            db=db,
            x_aisoc_signature=None,
        )
    assert exc.value.status_code == 400
    assert "not valid JSON" in exc.value.detail


@pytest.mark.asyncio
async def test_endpoint_non_object_json_raises_400() -> None:
    """``[1,2,3]`` is valid JSON but we need an object."""
    tenant_id = uuid.uuid4()
    connector_id = uuid.uuid4()
    token_row = SimpleNamespace(
        token="t",
        tenant_id=tenant_id,
        template_id=_ITSM_TEMPLATE_ID,
        hmac_secret=None,
        revoked_at=None,
    )
    connector_row = SimpleNamespace(
        id=connector_id,
        tenant_id=tenant_id,
        connector_type="jira",
        is_enabled=True,
    )
    db = _build_db_for_endpoint(token_row=token_row, connector_row=connector_row, ref_row=None)
    request = _build_request(b"[1,2,3]")

    with pytest.raises(HTTPException) as exc:
        await inbound_itsm_webhook(
            tenant_token="t",
            connector_instance_id=connector_id,
            request=request,
            db=db,
            x_aisoc_signature=None,
        )
    assert exc.value.status_code == 400


@pytest.mark.asyncio
async def test_endpoint_missing_external_id_returns_200_with_note() -> None:
    """Heartbeat / malformed-payload Jira webhooks 200 with status_changed=False."""
    tenant_id = uuid.uuid4()
    connector_id = uuid.uuid4()
    token_row = SimpleNamespace(
        token="t",
        tenant_id=tenant_id,
        template_id=_ITSM_TEMPLATE_ID,
        hmac_secret=None,
        revoked_at=None,
    )
    connector_row = SimpleNamespace(
        id=connector_id,
        tenant_id=tenant_id,
        connector_type="jira",
        is_enabled=True,
    )
    db = _build_db_for_endpoint(token_row=token_row, connector_row=connector_row, ref_row=None)
    request = _build_request(json.dumps({"webhookEvent": "ping"}).encode())

    result = await inbound_itsm_webhook(
        tenant_token="t",
        connector_instance_id=connector_id,
        request=request,
        db=db,
        x_aisoc_signature=None,
    )

    assert isinstance(result, InboundResult)
    assert result.status_changed is False
    assert result.case_id is None
    assert result.external_id is None
    assert result.note is not None
    assert "missing required fields" in result.note


@pytest.mark.asyncio
async def test_endpoint_unlinked_external_id_returns_200_with_note() -> None:
    """ITSM ticket exists but isn't linked to any AiSOC case → soft-200."""
    tenant_id = uuid.uuid4()
    connector_id = uuid.uuid4()
    token_row = SimpleNamespace(
        token="t",
        tenant_id=tenant_id,
        template_id=_ITSM_TEMPLATE_ID,
        hmac_secret=None,
        revoked_at=None,
    )
    connector_row = SimpleNamespace(
        id=connector_id,
        tenant_id=tenant_id,
        connector_type="jira",
        is_enabled=True,
    )
    # ref_row=None means the JOIN found no AiSOC link.
    db = _build_db_for_endpoint(token_row=token_row, connector_row=connector_row, ref_row=None)
    body = json.dumps(
        {
            "issue": {
                "key": "AIS-99",
                "fields": {"status": {"name": "Done"}},
            }
        }
    ).encode()
    request = _build_request(body)

    result = await inbound_itsm_webhook(
        tenant_token="t",
        connector_instance_id=connector_id,
        request=request,
        db=db,
        x_aisoc_signature=None,
    )

    assert result.status_changed is False
    assert result.case_id is None
    assert result.external_id == "AIS-99"
    assert "AIS-99" in (result.note or "")


@pytest.mark.asyncio
async def test_endpoint_idempotent_when_case_already_in_target_status() -> None:
    """Re-delivered "Done" event when case is already 'resolved' → no rewrite.

    The vendor will hammer this URL on every retry, so the most common
    real-world execution is a redelivery. We must:
    * still 200 OK (so the vendor stops retrying),
    * still bump last_synced_at (so the operator knows the token is alive),
    * NOT rewrite ``aisoc_cases.status`` (no-op DB load),
    * NOT post a duplicate "Jira ticket transitioned" system comment
      (would spam the timeline view).
    """
    tenant_id = uuid.uuid4()
    connector_id = uuid.uuid4()
    case_id = uuid.uuid4()
    token_row = SimpleNamespace(
        token="t",
        tenant_id=tenant_id,
        template_id=_ITSM_TEMPLATE_ID,
        hmac_secret=None,
        revoked_at=None,
    )
    connector_row = SimpleNamespace(
        id=connector_id,
        tenant_id=tenant_id,
        connector_type="jira",
        is_enabled=True,
    )
    ref_row = SimpleNamespace(
        id=uuid.uuid4(),
        case_id=case_id,
        external_status="resolved",
        aisoc_case_id=case_id,
        case_number="CASE-1",
        status="resolved",  # already in the target state
    )
    db = _build_db_for_endpoint(token_row=token_row, connector_row=connector_row, ref_row=ref_row)
    body = json.dumps({"issue": {"key": "AIS-1", "fields": {"status": {"name": "Done"}}}}).encode()
    request = _build_request(body)

    result = await inbound_itsm_webhook(
        tenant_token="t",
        connector_instance_id=connector_id,
        request=request,
        db=db,
        x_aisoc_signature=None,
    )

    assert result.status_changed is False
    assert result.old_status == "resolved"
    assert result.new_status == "resolved"
    assert result.case_id == case_id
    assert result.case_number == "CASE-1"


@pytest.mark.asyncio
async def test_endpoint_unmapped_status_bumps_last_synced_only() -> None:
    """Vendor status that doesn't map to AiSOC → ``status_changed=False``.

    Operators occasionally configure custom Jira workflows with statuses
    we've never heard of ("Awaiting Customer", "Released to QA"). The
    contract: never lose data, never crash, always 200.
    """
    tenant_id = uuid.uuid4()
    connector_id = uuid.uuid4()
    case_id = uuid.uuid4()
    token_row = SimpleNamespace(
        token="t",
        tenant_id=tenant_id,
        template_id=_ITSM_TEMPLATE_ID,
        hmac_secret=None,
        revoked_at=None,
    )
    connector_row = SimpleNamespace(
        id=connector_id,
        tenant_id=tenant_id,
        connector_type="jira",
        is_enabled=True,
    )
    ref_row = SimpleNamespace(
        id=uuid.uuid4(),
        case_id=case_id,
        external_status="investigating",
        aisoc_case_id=case_id,
        case_number="CASE-2",
        status="investigating",
    )
    db = _build_db_for_endpoint(token_row=token_row, connector_row=connector_row, ref_row=ref_row)
    body = json.dumps(
        {
            "issue": {
                "key": "AIS-2",
                "fields": {"status": {"name": "Awaiting Customer"}},
            }
        }
    ).encode()
    request = _build_request(body)

    result = await inbound_itsm_webhook(
        tenant_token="t",
        connector_instance_id=connector_id,
        request=request,
        db=db,
        x_aisoc_signature=None,
    )

    assert result.status_changed is False
    assert result.old_status == "investigating"
    assert result.new_status == "investigating"
    assert "Awaiting Customer" in (result.note or "")


@pytest.mark.asyncio
async def test_endpoint_real_status_change_writes_and_returns_changed() -> None:
    """Vendor 'Done' → AiSOC 'resolved' mirrors the status onto the case."""
    tenant_id = uuid.uuid4()
    connector_id = uuid.uuid4()
    case_id = uuid.uuid4()
    token_row = SimpleNamespace(
        token="t",
        tenant_id=tenant_id,
        template_id=_ITSM_TEMPLATE_ID,
        hmac_secret=None,
        revoked_at=None,
    )
    connector_row = SimpleNamespace(
        id=connector_id,
        tenant_id=tenant_id,
        connector_type="jira",
        is_enabled=True,
    )
    ref_row = SimpleNamespace(
        id=uuid.uuid4(),
        case_id=case_id,
        external_status="investigating",
        aisoc_case_id=case_id,
        case_number="CASE-7",
        status="investigating",
    )
    db = _build_db_for_endpoint(token_row=token_row, connector_row=connector_row, ref_row=ref_row)
    body = json.dumps({"issue": {"key": "AIS-7", "fields": {"status": {"name": "Done"}}}}).encode()
    request = _build_request(body)

    result = await inbound_itsm_webhook(
        tenant_token="t",
        connector_instance_id=connector_id,
        request=request,
        db=db,
        x_aisoc_signature=None,
    )

    assert result.status_changed is True
    assert result.old_status == "investigating"
    assert result.new_status == "resolved"
    assert result.case_id == case_id
    assert result.case_number == "CASE-7"
    assert result.external_id == "AIS-7"


@pytest.mark.asyncio
async def test_endpoint_servicenow_dispatches_to_servicenow_parser() -> None:
    """A ServiceNow connector type routes through ``_parse_servicenow_payload``.

    Numeric state ``"6"`` → ``"resolved"`` confirms both the dispatch
    and the SNow-specific mapping.
    """
    tenant_id = uuid.uuid4()
    connector_id = uuid.uuid4()
    case_id = uuid.uuid4()
    token_row = SimpleNamespace(
        token="t",
        tenant_id=tenant_id,
        template_id=_ITSM_TEMPLATE_ID,
        hmac_secret=None,
        revoked_at=None,
    )
    connector_row = SimpleNamespace(
        id=connector_id,
        tenant_id=tenant_id,
        connector_type="servicenow",
        is_enabled=True,
    )
    ref_row = SimpleNamespace(
        id=uuid.uuid4(),
        case_id=case_id,
        external_status="investigating",
        aisoc_case_id=case_id,
        case_number="CASE-9",
        status="investigating",
    )
    db = _build_db_for_endpoint(token_row=token_row, connector_row=connector_row, ref_row=ref_row)
    body = json.dumps({"sys_id": "abc-1", "state": 6}).encode()
    request = _build_request(body)

    result = await inbound_itsm_webhook(
        tenant_token="t",
        connector_instance_id=connector_id,
        request=request,
        db=db,
        x_aisoc_signature=None,
    )

    assert result.status_changed is True
    assert result.new_status == "resolved"
    assert result.external_id == "abc-1"


@pytest.mark.asyncio
async def test_endpoint_hmac_required_but_missing_returns_401() -> None:
    """Token has hmac_secret but request omits the signature → 401.

    Verifies HMAC is enforced on the *real* endpoint, not just on
    ``_verify_hmac`` in isolation. The order of operations matters:
    HMAC must run *before* JSON parsing so a forged-but-valid-JSON
    body can't trigger any DB reads.
    """
    tenant_id = uuid.uuid4()
    connector_id = uuid.uuid4()
    token_row = SimpleNamespace(
        token="t",
        tenant_id=tenant_id,
        template_id=_ITSM_TEMPLATE_ID,
        hmac_secret="seekret",  # configured
        revoked_at=None,
    )
    connector_row = SimpleNamespace(
        id=connector_id,
        tenant_id=tenant_id,
        connector_type="jira",
        is_enabled=True,
    )
    db = _build_db_for_endpoint(token_row=token_row, connector_row=connector_row, ref_row=None)
    request = _build_request(b"{}")

    with pytest.raises(HTTPException) as exc:
        await inbound_itsm_webhook(
            tenant_token="t",
            connector_instance_id=connector_id,
            request=request,
            db=db,
            x_aisoc_signature=None,  # missing
        )
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_endpoint_hmac_valid_passes_through() -> None:
    """A correctly signed request authenticates and proceeds normally."""
    tenant_id = uuid.uuid4()
    connector_id = uuid.uuid4()
    case_id = uuid.uuid4()
    token_row = SimpleNamespace(
        token="t",
        tenant_id=tenant_id,
        template_id=_ITSM_TEMPLATE_ID,
        hmac_secret="seekret",
        revoked_at=None,
    )
    connector_row = SimpleNamespace(
        id=connector_id,
        tenant_id=tenant_id,
        connector_type="jira",
        is_enabled=True,
    )
    ref_row = SimpleNamespace(
        id=uuid.uuid4(),
        case_id=case_id,
        external_status="investigating",
        aisoc_case_id=case_id,
        case_number="CASE-5",
        status="investigating",
    )
    db = _build_db_for_endpoint(token_row=token_row, connector_row=connector_row, ref_row=ref_row)
    body = json.dumps({"issue": {"key": "AIS-5", "fields": {"status": {"name": "Done"}}}}).encode()
    sig = f"sha256={_expected_sig('seekret', body)}"
    request = _build_request(body)

    result = await inbound_itsm_webhook(
        tenant_token="t",
        connector_instance_id=connector_id,
        request=request,
        db=db,
        x_aisoc_signature=sig,
    )

    assert result.status_changed is True
    assert result.new_status == "resolved"
