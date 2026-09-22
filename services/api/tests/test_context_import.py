"""Importing context must be safe to re-run and honest about what it dropped.

The v1.1 identity and business labels cannot come from events: an event can
say an account authenticated, not who holds it or what the host serves. So
they come from a directory, HR and CMDB import, which runs on a schedule
against sources that are frequently partial.

Three properties matter more than the happy path.

Re-running must not destroy anything. An import that replaced the tenant's
context with whatever one run produced would delete a department because an
export timed out.

A departed employee is recorded, not deleted — an account still
authenticating after someone's last day is the highest-signal finding this
data enables, and deleting the row destroys exactly that.

Rejections are named. A partially-applied import reporting success is worse
than a rejected one, because afterwards the gaps are invisible.
"""

from __future__ import annotations

from typing import Any

import pytest
from app.services.context_import import CRITICALITY, ImportReport, import_context

TENANT = "66666666-6666-6666-6666-666666666666"


class FakeRecord(dict):
    pass


class FakeResult:
    def __init__(self, row: dict[str, Any] | None) -> None:
        self._row = row

    async def single(self) -> dict[str, Any] | None:
        return self._row


class FakeSession:
    """Records every statement and answers link queries with a fixed count."""

    def __init__(self, *, links: int = 1) -> None:
        self.statements: list[tuple[str, dict[str, Any]]] = []
        self.links = links

    async def run(self, cypher: str, **params: Any) -> FakeResult:
        flat = " ".join(cypher.split())
        self.statements.append((flat, params))
        if "RETURN count(" in flat:
            return FakeResult(FakeRecord(linked=self.links))
        return FakeResult(None)

    def merges(self, label: str) -> list[tuple[str, dict[str, Any]]]:
        return [(s, p) for s, p in self.statements if f"MERGE ({label[0].lower()}:{label}" in s or f":{label} {{" in s]

    def matching(self, token: str) -> list[tuple[str, dict[str, Any]]]:
        return [(s, p) for s, p in self.statements if token in s]


class TestUpsertSemantics:
    async def test_nothing_is_ever_deleted(self) -> None:
        """An import against a partial export must not destroy context."""
        session = FakeSession()
        await import_context(
            TENANT,
            {"departments": [{"id": "d1", "name": "Platform"}]},
            session=session,
        )
        assert not any("DELETE" in s.upper() or "DETACH" in s.upper() for s, _ in session.statements)

    async def test_records_are_merged_not_created(self) -> None:
        session = FakeSession()
        await import_context(TENANT, {"departments": [{"id": "d1", "name": "Platform"}]}, session=session)
        assert any(s.startswith("MERGE (d:Department") for s, _ in session.statements)

    async def test_absent_fields_do_not_blank_existing_values(self) -> None:
        """A partial export must not null out what a fuller one wrote.

        coalesce keeps the stored value when the payload omits the field.
        """
        session = FakeSession()
        await import_context(TENANT, {"employees": [{"id": "e1"}]}, session=session)
        statement, _ = next(s for s in session.statements if "MERGE (e:Employee" in s[0])
        assert "coalesce($title, e.title)" in statement
        assert "coalesce($email, e.email)" in statement


class TestDepartedEmployees:
    async def test_an_end_date_marks_the_employee_inactive(self) -> None:
        session = FakeSession()
        await import_context(
            TENANT,
            {"employees": [{"id": "e1", "display_name": "Jo", "end_date": "2026-09-19"}]},
            session=session,
        )
        _, params = next(s for s in session.statements if "MERGE (e:Employee" in s[0])
        assert params["end_date"] == "2026-09-19"
        assert params["is_active"] is False

    async def test_is_active_is_derived_not_trusted(self) -> None:
        """An export claiming a departed employee is active would erase the
        one finding this data exists to enable."""
        session = FakeSession()
        await import_context(
            TENANT,
            {"employees": [{"id": "e1", "end_date": "2026-09-19", "is_active": True}]},
            session=session,
        )
        _, params = next(s for s in session.statements if "MERGE (e:Employee" in s[0])
        assert params["is_active"] is False

    async def test_no_end_date_means_active(self) -> None:
        session = FakeSession()
        await import_context(TENANT, {"employees": [{"id": "e1"}]}, session=session)
        _, params = next(s for s in session.statements if "MERGE (e:Employee" in s[0])
        assert params["is_active"] is True


class TestTenantScoping:
    async def test_ids_are_namespaced_by_tenant(self) -> None:
        """Two tenants with an employee id of 'e1' must not collide."""
        session = FakeSession()
        await import_context(TENANT, {"employees": [{"id": "e1"}]}, session=session)
        _, params = next(s for s in session.statements if "MERGE (e:Employee" in s[0])
        assert params["id"] == f"{TENANT}:e1"

    async def test_every_link_query_filters_by_tenant(self) -> None:
        session = FakeSession()
        await import_context(
            TENANT,
            {
                "departments": [{"id": "d1", "name": "Platform"}],
                "employees": [{"id": "e1", "department_id": "d1", "manager_id": "e0", "accounts": ["jo@x.com"]}],
                "applications": [{"id": "a1", "name": "Payments", "owner_employee_id": "e1", "hosts": ["web-1"]}],
            },
            session=session,
        )
        for statement, params in session.statements:
            if statement.startswith("MATCH"):
                assert "tenant_id = $tenant_id" in statement, statement
                assert params.get("tenant_id") == TENANT


class TestValidation:
    async def test_a_malformed_id_is_rejected_by_name(self) -> None:
        session = FakeSession()
        report = await import_context(TENANT, {"employees": [{"id": "has spaces and <html>"}]}, session=session)
        assert report.employees == 0
        assert report.rejected and "malformed id" in report.rejected[0]["reason"]

    async def test_an_unrecognised_criticality_is_rejected_not_coerced(self) -> None:
        """The autonomy policy reads this field, so a wrong value is a wrong
        decision rather than a cosmetic one."""
        session = FakeSession()
        report = await import_context(
            TENANT,
            {"applications": [{"id": "a1", "name": "Payments", "criticality": "very important"}]},
            session=session,
        )
        assert report.applications == 0
        assert "not one of" in report.rejected[0]["reason"]

    @pytest.mark.parametrize("value", CRITICALITY)
    async def test_valid_criticalities_are_accepted(self, value: str) -> None:
        session = FakeSession()
        report = await import_context(
            TENANT,
            {"applications": [{"id": "a1", "name": "P", "criticality": value}]},
            session=session,
        )
        assert report.applications == 1, report.rejected

    async def test_free_text_is_length_capped(self) -> None:
        """A CMDB description field is a common place to find a whole runbook,
        and these render in a UI and reach a prompt."""
        session = FakeSession()
        await import_context(TENANT, {"employees": [{"id": "e1", "title": "X" * 5000}]}, session=session)
        _, params = next(s for s in session.statements if "MERGE (e:Employee" in s[0])
        assert len(params["title"]) <= 500

    async def test_non_object_records_do_not_abort_the_import(self) -> None:
        session = FakeSession()
        report = await import_context(
            TENANT,
            {"employees": ["not an object", {"id": "e1"}, None]},
            session=session,
        )
        assert report.employees == 1
        assert len(report.rejected) == 2


class TestUnmatchedReferences:
    async def test_an_account_the_graph_has_never_seen_is_reported(self) -> None:
        """A typo and a system nothing ingests look identical otherwise."""
        session = FakeSession(links=0)
        report = await import_context(
            TENANT,
            {"employees": [{"id": "e1", "accounts": ["ghost@example.com"]}]},
            session=session,
        )
        assert report.employees == 1
        assert any("no Identity node matches" in r["reason"] for r in report.rejected)

    async def test_a_cmdb_host_with_no_events_is_reported(self) -> None:
        """A CMDB naming a host the platform has never ingested is a coverage
        gap, and must not become a node that looks monitored."""
        session = FakeSession(links=0)
        report = await import_context(
            TENANT,
            {"applications": [{"id": "a1", "name": "Payments", "hosts": ["nowhere-1"]}]},
            session=session,
        )
        assert report.applications == 1
        assert any("has not been seen in any ingested event" in r["reason"] for r in report.rejected)

    async def test_resources_and_identities_are_matched_never_created(self) -> None:
        session = FakeSession(links=0)
        await import_context(
            TENANT,
            {
                "employees": [{"id": "e1", "accounts": ["a@b.c"]}],
                "applications": [{"id": "a1", "name": "P", "hosts": ["h1"]}],
            },
            session=session,
        )
        for statement, _ in session.statements:
            assert "MERGE (i:Identity" not in statement
            assert "MERGE (r:Resource" not in statement


class TestOrdering:
    async def test_departments_are_written_before_employees(self) -> None:
        """Otherwise BELONGS_TO merges a bare Department whose name nobody set."""
        session = FakeSession()
        await import_context(
            TENANT,
            {
                "employees": [{"id": "e1", "department_id": "d1"}],
                "departments": [{"id": "d1", "name": "Platform"}],
            },
            session=session,
        )
        order = [s for s, _ in session.statements]
        dept = next(i for i, s in enumerate(order) if "MERGE (d:Department" in s)
        emp = next(i for i, s in enumerate(order) if "MERGE (e:Employee" in s)
        assert dept < emp


class TestReport:
    def test_rejections_are_bounded_in_the_response(self) -> None:
        """A malformed export can reject every row; a 50k error list is not
        a usable response."""
        report = ImportReport()
        for i in range(500):
            report.reject("employee", f"e{i}", "malformed")
        payload = report.as_dict()
        assert payload["rejected_count"] == 500
        assert len(payload["rejected"]) == 100
        assert payload["rejected_truncated"] is True

    async def test_counts_reflect_what_was_written(self) -> None:
        session = FakeSession()
        report = await import_context(
            TENANT,
            {
                "departments": [{"id": "d1", "name": "Platform"}, {"id": "d2", "name": "Finance"}],
                "employees": [{"id": "e1"}, {"id": "e2"}, {"id": "bad id!"}],
                "applications": [{"id": "a1", "name": "Payments"}],
                "cloud_accounts": [{"account_id": "123456789012", "provider": "aws"}],
            },
            session=session,
        )
        assert (report.departments, report.employees) == (2, 2)
        assert (report.applications, report.cloud_accounts) == (1, 1)
        assert report.total == 6
        assert len(report.rejected) == 1
