"""Analyst disagreement must generalise, and must not outlive its scope.

Overturning a verdict recorded the new disposition and discarded the only
part that generalises — why — so the next identical alert was triaged with
no knowledge that this one had been overturned. Free text did not help:
nobody queried it.

The tests that matter are about restraint rather than capture. One analyst
is an opinion, not a pattern. A pentest exclusion that outlives the pentest
is an attacker's best friend. And a broken rule is not fixed by remembering
that it is broken.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from app.services.analyst_feedback import (
    REASON_CODES,
    ContextStatement,
    compose_statement,
    record_disagreement,
)

TENANT = uuid.UUID("77777777-7777-7777-7777-777777777777")
ALERT = uuid.UUID("88888888-8888-8888-8888-888888888888")


class FakeScalar:
    def __init__(self, value: Any) -> None:
        self._value = value

    def scalar_one(self) -> Any:
        return self._value

    def mappings(self) -> list[dict[str, Any]]:
        return self._value if isinstance(self._value, list) else []


class FakeSession:
    """Answers the corroboration count with a fixed number of distinct analysts."""

    def __init__(self, distinct_analysts: int = 1) -> None:
        self.distinct = distinct_analysts
        self.statements: list[tuple[str, dict[str, Any]]] = []

    async def execute(self, stmt: Any, params: dict[str, Any] | None = None) -> Any:
        sql = " ".join(str(stmt).split())
        self.statements.append((sql, dict(params or {})))
        if "count(DISTINCT analyst_id)" in sql:
            return FakeScalar(self.distinct)
        return FakeScalar(None)

    def inserted_into(self, table: str) -> list[dict[str, Any]]:
        return [p for s, p in self.statements if f"INTO {table}" in s]


CONTEXT = {
    "process_name": "powershell.exe",
    "user_name": "svc_backup",
    "hostname": "BACKUP01",
    "time_window": "02:00 backup",
    "rule_id": "RULE-1",
    "rule_name": "Suspicious PowerShell",
}


class TestCorroboration:
    async def test_one_analyst_is_not_yet_a_pattern(self) -> None:
        """One person calling one alert benign is an opinion."""
        session = FakeSession(distinct_analysts=1)
        statement = await record_disagreement(
            session,
            tenant_id=TENANT,
            alert_id=ALERT,
            ai_disposition="malicious",
            analyst_disposition="benign",
            reason_code="known_admin_tool",  # needs 2
            analyst_id="analyst-a",
            context=CONTEXT,
        )
        assert statement is None
        assert session.inserted_into("aisoc_analyst_feedback")
        assert not session.inserted_into("aisoc_context_statements")

    async def test_the_second_analyst_makes_it_memory(self) -> None:
        session = FakeSession(distinct_analysts=2)
        statement = await record_disagreement(
            session,
            tenant_id=TENANT,
            alert_id=ALERT,
            ai_disposition="malicious",
            analyst_disposition="benign",
            reason_code="known_admin_tool",
            analyst_id="analyst-b",
            context=CONTEXT,
        )
        assert statement is not None
        assert session.inserted_into("aisoc_context_statements")

    async def test_corroboration_counts_analysts_not_rows(self) -> None:
        """One person clicking the same button ten times is one opinion."""
        session = FakeSession(distinct_analysts=1)
        await record_disagreement(
            session,
            tenant_id=TENANT,
            alert_id=ALERT,
            ai_disposition="malicious",
            analyst_disposition="benign",
            reason_code="known_admin_tool",
            analyst_id="analyst-a",
            context=CONTEXT,
        )
        count_sql = next(s for s, _ in session.statements if "count(" in s)
        assert "count(DISTINCT analyst_id)" in count_sql

    async def test_a_single_high_trust_reason_needs_no_corroboration(self) -> None:
        """An approved pentest is announced, not discovered."""
        session = FakeSession(distinct_analysts=1)
        statement = await record_disagreement(
            session,
            tenant_id=TENANT,
            alert_id=ALERT,
            ai_disposition="malicious",
            analyst_disposition="benign",
            reason_code="approved_pentest",
            analyst_id="analyst-a",
            context=CONTEXT,
        )
        assert statement is not None


class TestExpiry:
    async def test_a_pentest_statement_expires(self) -> None:
        """One that outlives the pentest is an attacker's best friend, and
        nobody remembers to remove it."""
        session = FakeSession(distinct_analysts=1)
        statement = await record_disagreement(
            session,
            tenant_id=TENANT,
            alert_id=ALERT,
            ai_disposition="malicious",
            analyst_disposition="benign",
            reason_code="approved_pentest",
            analyst_id="analyst-a",
            context=CONTEXT,
        )
        assert statement and statement.expires_at is not None
        days = (statement.expires_at - datetime.now(UTC)).days
        assert 0 < days <= 14

    async def test_a_permanent_reason_does_not_expire(self) -> None:
        session = FakeSession(distinct_analysts=2)
        statement = await record_disagreement(
            session,
            tenant_id=TENANT,
            alert_id=ALERT,
            ai_disposition="malicious",
            analyst_disposition="benign",
            reason_code="known_admin_tool",
            analyst_id="analyst-b",
            context=CONTEXT,
        )
        assert statement and statement.expires_at is None

    def test_every_temporary_code_has_a_bounded_ttl(self) -> None:
        for code in REASON_CODES.values():
            if code.ttl_days is not None:
                assert 0 < code.ttl_days <= 365, code.code


class TestRoutingRatherThanSuppressing:
    @pytest.mark.parametrize("code", ["bad_detection_logic", "missing_context"])
    async def test_rule_defects_route_to_detection_engineering(self, code: str) -> None:
        """Suppressing a broken rule's output hides the defect and keeps
        paying its cost on every future alert."""
        session = FakeSession(distinct_analysts=2)
        statement = await record_disagreement(
            session,
            tenant_id=TENANT,
            alert_id=ALERT,
            ai_disposition="malicious",
            analyst_disposition="benign",
            reason_code=code,
            analyst_id="analyst-a",
            context=CONTEXT,
        )
        assert statement and statement.routes_to_detection_engineering

    @pytest.mark.parametrize("code", ["known_admin_tool", "approved_pentest", "expected_service_account"])
    def test_environment_reasons_do_not_route(self, code: str) -> None:
        assert not REASON_CODES[code].routes_to_detection_engineering


class TestStatements:
    def test_the_worked_example_from_the_plan(self) -> None:
        """Specific by construction: 'PowerShell is expected' is a
        suppression waiting to hide an incident."""
        text = compose_statement(REASON_CODES["expected_service_account"], CONTEXT)
        assert "powershell.exe" in text
        assert "svc_backup" in text
        assert "BACKUP01" in text
        assert "02:00 backup" in text

    def test_a_statement_never_degrades_to_bare_process_name(self) -> None:
        text = compose_statement(REASON_CODES["known_admin_tool"], CONTEXT)
        assert text != "powershell.exe is sanctioned administrative tooling."
        assert "svc_backup" in text or "BACKUP01" in text

    def test_a_rule_scoped_statement_names_the_rule(self) -> None:
        text = compose_statement(REASON_CODES["bad_detection_logic"], CONTEXT)
        assert "Suspicious PowerShell" in text
        assert "rather than its output suppressing" in text

    def test_sparse_context_still_produces_a_sentence(self) -> None:
        text = compose_statement(REASON_CODES["known_scanner"], {"hostname": "scanner-1"})
        assert "scanner-1" in text and text.endswith(".")

    @pytest.mark.parametrize("code", list(REASON_CODES))
    def test_every_code_composes_something_readable(self, code: str) -> None:
        text = compose_statement(REASON_CODES[code], CONTEXT)
        assert len(text) > 20 and text.endswith(".")


class TestTaxonomy:
    async def test_the_vocabulary_is_closed(self) -> None:
        """Free text is why this data was useless before."""
        session = FakeSession()
        with pytest.raises(ValueError, match="unknown reason code"):
            await record_disagreement(
                session,
                tenant_id=TENANT,
                alert_id=ALERT,
                ai_disposition="malicious",
                analyst_disposition="benign",
                reason_code="it_seemed_fine",
                analyst_id="a",
            )

    def test_every_code_declares_a_scope_the_composer_handles(self) -> None:
        for code in REASON_CODES.values():
            assert code.scope in ("rule", "entity", "binary", "tenant"), code.code

    async def test_scope_determines_what_a_statement_is_about(self) -> None:
        """A binary-scoped reason must not silently become tenant-wide."""
        session = FakeSession(distinct_analysts=2)
        await record_disagreement(
            session,
            tenant_id=TENANT,
            alert_id=ALERT,
            ai_disposition="malicious",
            analyst_disposition="benign",
            reason_code="known_admin_tool",
            analyst_id="analyst-b",
            context=CONTEXT,
        )
        inserted = session.inserted_into("aisoc_context_statements")[0]
        assert inserted["scope"] == "binary"
        assert inserted["scope_value"] == "powershell.exe"


async def test_free_text_notes_are_kept_but_bounded() -> None:
    """Retained for a human reading the trail, never parsed."""
    session = FakeSession(distinct_analysts=1)
    await record_disagreement(
        session,
        tenant_id=TENANT,
        alert_id=ALERT,
        ai_disposition="malicious",
        analyst_disposition="benign",
        reason_code="approved_pentest",
        analyst_id="a",
        context=CONTEXT,
        note="x" * 9000,
    )
    inserted = session.inserted_into("aisoc_analyst_feedback")[0]
    assert len(inserted["note"]) == 2000


def test_statement_serialises_for_the_api() -> None:
    statement = ContextStatement(
        tenant_id=str(TENANT),
        statement="s",
        reason_code="known_admin_tool",
        scope="binary",
        scope_value="powershell.exe",
        observations=3,
        expires_at=None,
        routes_to_detection_engineering=False,
    )
    payload = statement.as_dict()
    assert payload["expires_at"] is None
    assert payload["observations"] == 3
