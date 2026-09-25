"""The organisation-memory endpoints: both ends of a previously dead feature.

``app/services/analyst_feedback.py`` was tested, gated, and unreachable — not
just its read function. ``record_disagreement`` had no caller either, so
wiring only the read would have produced a query against a table nothing
populates.

These cover the two new seams in the endpoint layer: the context a compiled
statement is allowed to name (a thin one produces "PowerShell is expected",
which is a suppression waiting to hide an incident), and the dual-mode auth on
the read, which the agents triage worker depends on.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from app.api.v1.endpoints import feedback
from app.models.alert import Alert
from fastapi import HTTPException

TENANT = uuid.UUID("77777777-7777-7777-7777-777777777777")
OTHER_TENANT = uuid.UUID("99999999-9999-9999-9999-999999999999")


def alert(**kw: Any) -> Alert:
    """A transient `Alert`, not a stand-in for one.

    The first version of this helper was a hand-written fake carrying the five
    attributes `_statement_context` reads, which is exactly how the bug it
    tests got written: the API's `Alert` has no `hostname` or `username`
    columns — it denormalises into `affected_hosts` / `affected_users` and
    keeps process and hash only inside `raw_event` — and a fake that defines
    whatever the code asks for can never say so.
    """
    return Alert(**kw)


class FakeUser:
    def __init__(self, tenant_id: uuid.UUID) -> None:
        self.tenant_id = tenant_id
        self.user_id = uuid.uuid4()
        self.email = "analyst@example.test"


class TestStatementContext:
    def test_reads_host_and_user_from_the_denormalised_lists(self) -> None:
        # The API's Alert model has no `hostname`/`username` columns — it
        # denormalises into `affected_hosts` / `affected_users`. Reading
        # attributes that do not exist would have raised on every tagged
        # override.
        ctx = feedback._statement_context(alert(affected_hosts=["BACKUP01"], affected_users=["svc_backup"]))

        assert ctx["hostname"] == "BACKUP01"
        assert ctx["user_name"] == "svc_backup"

    def test_falls_back_to_the_raw_event_when_the_lists_are_empty(self) -> None:
        ctx = feedback._statement_context(alert(raw_event={"hostname": "WEB-02", "user": "root"}))

        assert ctx["hostname"] == "WEB-02"
        assert ctx["user_name"] == "root"

    def test_recovers_the_process_and_hash_a_binary_scope_needs(self) -> None:
        # `binary`-scoped reasons (known_admin_tool, business_application) key
        # on the process or hash, and neither is a column.
        ctx = feedback._statement_context(alert(raw_event={"process_name": "powershell.exe", "sha256": "a" * 64}))

        assert ctx["process_name"] == "powershell.exe"
        assert ctx["hash_sha256"] == "a" * 64

    def test_carries_the_rule_identity_a_rule_scope_needs(self) -> None:
        ctx = feedback._statement_context(alert(rule_id="RULE-1", rule_name="Suspicious PowerShell"))

        assert ctx["rule_id"] == "RULE-1"
        assert ctx["rule_name"] == "Suspicious PowerShell"

    def test_an_empty_alert_yields_nulls_rather_than_raising(self) -> None:
        ctx = feedback._statement_context(alert())

        assert set(ctx) == {
            "rule_id",
            "rule_name",
            "hostname",
            "user_name",
            "process_name",
            "hash_sha256",
        }
        assert all(v is None for v in ctx.values())

    def test_non_string_values_are_ignored_not_stringified(self) -> None:
        ctx = feedback._statement_context(alert(affected_hosts=[None, 42, "REAL-HOST"], raw_event={"process_name": {"x": 1}}))

        assert ctx["hostname"] == "REAL-HOST"
        assert ctx["process_name"] is None


class TestContextStatementsAuth:
    @pytest.fixture(autouse=True)
    def _stub_query(self, monkeypatch: pytest.MonkeyPatch) -> list[Any]:
        """Capture the tenant `active_statements` is actually called with."""
        seen: list[Any] = []

        async def _fake(_db: Any, tenant_id: Any) -> list[dict[str, Any]]:
            seen.append(tenant_id)
            return [
                {
                    "statement": "svc_backup on BACKUP01 is expected",
                    "reason_code": "expected_service_account",
                    "scope": "entity",
                    "scope_value": "svc_backup",
                    "observations": 2,
                    "expires_at": None,
                }
            ]

        monkeypatch.setattr(feedback, "active_statements", _fake)
        return seen

    async def test_a_session_scopes_to_its_own_tenant(self, _stub_query: list[Any]) -> None:
        out = await feedback.get_context_statements(user=FakeUser(TENANT), db=object(), tenant_id=None, x_aisoc_service_token=None)

        assert _stub_query == [TENANT]
        assert out.tenant_id == str(TENANT)
        assert out.statements[0].observations == 2

    async def test_a_session_naming_another_tenant_is_refused(self, _stub_query: list[Any]) -> None:
        # Refused rather than quietly scoped back to the caller's own tenant.
        # Returning this tenant's memory in response to a request for another
        # one is the "silently returns the wrong data" shape; a 403 is not.
        with pytest.raises(HTTPException) as exc:
            await feedback.get_context_statements(
                user=FakeUser(TENANT),
                db=object(),
                tenant_id=OTHER_TENANT,
                x_aisoc_service_token=None,
            )

        assert exc.value.status_code == 403
        assert _stub_query == []

    async def test_a_session_may_name_its_own_tenant(self, _stub_query: list[Any]) -> None:
        # An explicit tenant that matches the session is a legitimate narrowing
        # and must not be treated as an attack.
        await feedback.get_context_statements(user=FakeUser(TENANT), db=object(), tenant_id=TENANT, x_aisoc_service_token=None)

        assert _stub_query == [TENANT]

    async def test_no_session_and_no_token_is_refused(self) -> None:
        with pytest.raises(HTTPException) as exc:
            await feedback.get_context_statements(user=None, db=object(), tenant_id=TENANT, x_aisoc_service_token=None)

        assert exc.value.status_code == 401

    async def test_a_bad_service_token_is_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(feedback, "service_token_valid", lambda _t: False)

        with pytest.raises(HTTPException) as exc:
            await feedback.get_context_statements(user=None, db=object(), tenant_id=TENANT, x_aisoc_service_token="wrong")

        assert exc.value.status_code == 401

    async def test_a_service_caller_must_name_the_tenant(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # It has no session to imply one, and defaulting to "all tenants" or to
        # a first row is how cross-tenant reads happen.
        monkeypatch.setattr(feedback, "service_token_valid", lambda _t: True)

        with pytest.raises(HTTPException) as exc:
            await feedback.get_context_statements(user=None, db=object(), tenant_id=None, x_aisoc_service_token="right")

        assert exc.value.status_code == 400

    async def test_a_valid_service_caller_reads_the_named_tenant(self, monkeypatch: pytest.MonkeyPatch, _stub_query: list[Any]) -> None:
        monkeypatch.setattr(feedback, "service_token_valid", lambda _t: True)

        out = await feedback.get_context_statements(user=None, db=object(), tenant_id=OTHER_TENANT, x_aisoc_service_token="right")

        assert _stub_query == [OTHER_TENANT]
        assert out.tenant_id == str(OTHER_TENANT)


class TestReasonCodeValidation:
    def test_the_request_model_accepts_an_absent_reason_code(self) -> None:
        req = feedback.AlertOverrideRequest(
            alert_id=str(uuid.uuid4()),
            original_verdict="true_positive",
            corrected_verdict="false_positive",
        )

        assert req.reason_code is None

    def test_the_documented_codes_are_the_ones_that_exist(self) -> None:
        # The field description enumerates the vocabulary for API consumers.
        # If a code is added or renamed and the description is not, the docs
        # teach a value the endpoint rejects.
        described = feedback.AlertOverrideRequest.model_fields["reason_code"].description or ""
        for code in feedback.REASON_CODES:
            assert code in described, f"{code} is accepted but undocumented on the field"
