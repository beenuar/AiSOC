"""Case depth: merge keeps history, bulk triage has a preflight, fields validate.

Depth plan 9.3 (parity 5.6 remainder).

Two halves, and the split is deliberate rather than a convenience.

**Always run.** The validators and the refusals that happen before any SQL.
Those are pure functions and a database would prove nothing about them.

**Live PostgreSQL.** Everything else, through the shipped ASGI app with its
real auth dependencies. The statements here are Postgres-only by necessity —
``uuid[]`` parameters, ``jsonb_agg(DISTINCT …)``, ``count(*) FILTER``,
``EXTRACT(EPOCH FROM …)`` — so a SQLite stand-in would be a different query
than the one that runs in production, which is the "test double more capable
than the real thing" failure this repository keeps finding. Gated on the DSN
being present *and* something answering on it, with
``CASE_DEPTH_PROOF_REQUIRED`` turning the skip into a failure for the job
that is meant to run it.

Asserted by name below:

* a merge keeps every row and leaves a walkable chain;
* a merged alert cannot be re-merged, and a merge into a merged alert is
  refused — both would orphan or cycle the chain;
* merging alerts leaves the survivor on the case one of them was already on,
  which is the phase's "two alerts merge into one case with their history
  kept";
* merging cases repoints the alerts and keeps both case rows;
* bulk triage refuses a match larger than ``max_count`` **and writes
  nothing**;
* ``closed`` is unreachable through bulk triage, because the route that
  snapshots every row first owns that destination;
* workload counts what this query selected, and a mean over nothing is
  ``None`` rather than ``0.0``.
"""

from __future__ import annotations

import os
import socket
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlparse

import pytest
import pytest_asyncio
from app.services.case_depth import CaseDepthError, validate_custom_value
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

_DSN = os.environ.get("DATABASE_MIGRATION_URL", "").strip() or os.environ.get("DATABASE_URL", "")
_REQUIRED = os.environ.get("CASE_DEPTH_PROOF_REQUIRED", "").strip() not in ("", "0", "false")

_UNUSABLE_PASSWORD_HASH = "x"  # noqa: S105 - not a credential; no plaintext maps to it


def _postgres_is_listening() -> bool:
    """A DSN is a statement of intent, not a running server.

    The unit-test job exports a ``postgres://…localhost:5432`` URL with
    nothing behind it, so a string check alone decides these should run and
    they die on ``Connect call failed`` rather than skipping.
    """
    parsed = urlparse(_DSN.replace("postgresql+asyncpg://", "postgresql://"))
    if not parsed.hostname:
        return False
    try:
        with socket.create_connection((parsed.hostname, parsed.port or 5432), timeout=2):
            return True
    except OSError:
        return False


_LIVE = ("postgres" in _DSN and _postgres_is_listening()) or _REQUIRED

live_only = pytest.mark.skipif(
    not _LIVE,
    reason=(
        "needs a live PostgreSQL with the migration chain applied — uuid[] parameters, "
        "jsonb_agg(DISTINCT …), count(*) FILTER and EXTRACT(EPOCH …) have no SQLite "
        "equivalent, and a stand-in would be a different query than the one that ships"
    ),
)


# ---------------------------------------------------------------------------
# Always run: validators and pre-SQL refusals
# ---------------------------------------------------------------------------


class TestCustomFieldValidation:
    """Canonicalising on write is what makes one TEXT column safe."""

    def test_a_number_field_refuses_prose(self) -> None:
        field = {"key": "ticket_cost", "field_type": "number", "required": False, "choices": []}
        assert validate_custom_value(field, " 42.5 ") == "42.5"
        with pytest.raises(CaseDepthError, match="must be a number"):
            validate_custom_value(field, "about forty")

    def test_a_boolean_canonicalises_rather_than_storing_what_was_typed(self) -> None:
        field = {"key": "reportable", "field_type": "boolean", "required": False, "choices": []}
        assert validate_custom_value(field, "YES") == "true"
        assert validate_custom_value(field, "0") == "false"
        with pytest.raises(CaseDepthError, match="must be true or false"):
            validate_custom_value(field, "maybe")

    def test_a_date_is_stored_iso_whatever_was_typed(self) -> None:
        field = {"key": "notified_on", "field_type": "date", "required": False, "choices": []}
        assert validate_custom_value(field, "2026-03-01T09:00:00Z").startswith("2026-03-01T09:00:00")
        with pytest.raises(CaseDepthError, match="ISO-8601"):
            validate_custom_value(field, "first of March")

    def test_a_select_refuses_a_value_outside_its_choices(self) -> None:
        field = {"key": "business_unit", "field_type": "select", "required": False, "choices": ["payments", "retail"]}
        assert validate_custom_value(field, "payments") == "payments"
        with pytest.raises(CaseDepthError, match="must be one of"):
            validate_custom_value(field, "legal")

    def test_a_required_field_refuses_empty_and_an_optional_one_allows_it(self) -> None:
        required = {"key": "owner", "field_type": "text", "required": True, "choices": []}
        optional = {"key": "notes", "field_type": "text", "required": False, "choices": []}
        with pytest.raises(CaseDepthError, match="is required"):
            validate_custom_value(required, "   ")
        assert validate_custom_value(optional, "") == ""


# ---------------------------------------------------------------------------
# Live PostgreSQL
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture(autouse=True)
async def _release_the_app_pool():
    """Dispose the application's global pool between tests.

    ``app.db.database.engine`` is module-level and pytest-asyncio gives every
    test its own loop; a connection checked out under the first is unusable
    under the second, and the resulting asyncpg error reads like a defect in
    the code under test.
    """
    yield
    if _LIVE:
        from app.db.database import engine

        await engine.dispose()


@pytest_asyncio.fixture
async def world():
    """A scratch tenant with an admin, two alerts and two cases, on the real schema."""
    from app.core.security import create_access_token

    engine = create_async_engine(_DSN)
    maker = async_sessionmaker(engine, expire_on_commit=False)

    tenant_id = uuid.uuid4()
    user_id = uuid.uuid4()
    suffix = tenant_id.hex[:8]

    async with maker() as db:
        await db.execute(
            text("INSERT INTO tenants (id, name, slug) VALUES (:i, :n, :s)"),
            {"i": tenant_id, "n": f"case-depth-{suffix}", "s": f"case-depth-{suffix}"},
        )
        await db.execute(
            text(
                "INSERT INTO users (id, tenant_id, email, username, hashed_password, role, is_active, is_verified) "
                "VALUES (:i, :t, :e, :u, :h, 'admin', TRUE, TRUE)"
            ),
            {
                "i": user_id,
                "t": tenant_id,
                "e": f"lead-{suffix}@example.com",
                "u": f"lead-{suffix}",
                "h": _UNUSABLE_PASSWORD_HASH,
            },
        )
        await db.commit()

    token = create_access_token({"sub": str(user_id)})
    yield maker, tenant_id, user_id, token
    await engine.dispose()


async def _alert(maker, tenant_id: uuid.UUID, *, case_id: uuid.UUID | None = None) -> uuid.UUID:
    alert_id = uuid.uuid4()
    async with maker() as db:
        await db.execute(
            text(
                "INSERT INTO alerts (id, tenant_id, title, severity, status, priority, case_id, created_at, updated_at) "
                "VALUES (:i, :t, 'Repeated sign-in failures', 'high', 'new', 40, :c, NOW(), NOW())"
            ),
            {"i": alert_id, "t": tenant_id, "c": case_id},
        )
        await db.commit()
    return alert_id


async def _case(
    maker,
    tenant_id: uuid.UUID,
    *,
    assignee: str | None = None,
    status: str = "new",
    created_days_ago: int = 1,
    closed: bool = False,
) -> uuid.UUID:
    case_id = uuid.uuid4()
    created = datetime.now(UTC) - timedelta(days=created_days_ago)
    async with maker() as db:
        await db.execute(
            text(
                "INSERT INTO aisoc_cases (id, tenant_id, title, severity, status, assignee, "
                "created_at, updated_at, closed_at) "
                "VALUES (:i, :t, 'Suspected intrusion', 'high', :s, :a, :created, :created, :closed)"
            ),
            {
                "i": case_id,
                "t": tenant_id,
                "s": status,
                "a": assignee,
                "created": created,
                "closed": (created + timedelta(hours=4)) if closed else None,
            },
        )
        await db.commit()
    return case_id


async def _post(token: str, path: str, body: dict) -> tuple[int, dict]:
    from app.main import app

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post(path, json=body, headers={"Authorization": f"Bearer {token}"})
    try:
        return res.status_code, res.json()
    except ValueError:
        return res.status_code, {"raw": res.text}


async def _get(token: str, path: str) -> tuple[int, Any]:
    """``Any`` rather than ``object``: this returns a decoded JSON document,
    which is a list for the list routes and a mapping for the rest, and
    every caller below indexes into it. Typing it ``object`` made eight
    honest assertions type errors."""
    from app.main import app

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get(path, headers={"Authorization": f"Bearer {token}"})
    try:
        return res.status_code, res.json()
    except ValueError:
        return res.status_code, {"raw": res.text}


@live_only
@pytest.mark.asyncio
class TestAlertMerge:
    async def test_a_merge_keeps_every_row_and_leaves_a_walkable_chain(self, world) -> None:
        maker, tenant_id, _user, token = world
        primary = await _alert(maker, tenant_id)
        dup_a = await _alert(maker, tenant_id)
        dup_b = await _alert(maker, tenant_id)

        code, body = await _post(
            token,
            "/api/v1/case-depth/alerts/merge",
            {"primary_id": str(primary), "duplicate_ids": [str(dup_a), str(dup_b)], "reason": "same brute force"},
        )
        assert code == 200, body
        assert sorted(body["merged_ids"]) == sorted([str(dup_a), str(dup_b)])

        async with maker() as db:
            rows = (
                (
                    await db.execute(
                        text("SELECT id, is_merged, parent_alert_id, child_alert_ids, status FROM alerts WHERE tenant_id = :t ORDER BY id"),
                        {"t": tenant_id},
                    )
                )
                .mappings()
                .all()
            )
        by_id = {row["id"]: row for row in rows}
        # Nothing was deleted.
        assert len(rows) == 3
        assert by_id[dup_a]["is_merged"] and by_id[dup_a]["parent_alert_id"] == primary
        assert by_id[dup_b]["is_merged"] and by_id[dup_b]["parent_alert_id"] == primary
        assert not by_id[primary]["is_merged"]
        children = by_id[primary]["child_alert_ids"]
        assert set(children) == {str(dup_a), str(dup_b)}

    async def test_a_second_merge_appends_rather_than_replacing_the_children(self, world) -> None:
        maker, tenant_id, _user, token = world
        primary = await _alert(maker, tenant_id)
        first = await _alert(maker, tenant_id)
        second = await _alert(maker, tenant_id)

        await _post(token, "/api/v1/case-depth/alerts/merge", {"primary_id": str(primary), "duplicate_ids": [str(first)]})
        await _post(token, "/api/v1/case-depth/alerts/merge", {"primary_id": str(primary), "duplicate_ids": [str(second)]})

        async with maker() as db:
            children = (await db.execute(text("SELECT child_alert_ids FROM alerts WHERE id = :i"), {"i": primary})).scalar_one()
        # Replacing rather than appending would silently drop the first merge.
        assert set(children) == {str(first), str(second)}

    async def test_re_merging_is_refused_because_it_would_orphan_the_chain(self, world) -> None:
        maker, tenant_id, _user, token = world
        primary = await _alert(maker, tenant_id)
        other = await _alert(maker, tenant_id)
        dup = await _alert(maker, tenant_id)

        await _post(token, "/api/v1/case-depth/alerts/merge", {"primary_id": str(primary), "duplicate_ids": [str(dup)]})
        code, body = await _post(token, "/api/v1/case-depth/alerts/merge", {"primary_id": str(other), "duplicate_ids": [str(dup)]})
        assert code == 422
        assert "Already merged" in body["detail"]

    async def test_merging_into_a_merged_alert_is_refused_because_it_would_cycle(self, world) -> None:
        maker, tenant_id, _user, token = world
        primary = await _alert(maker, tenant_id)
        dup = await _alert(maker, tenant_id)
        third = await _alert(maker, tenant_id)

        await _post(token, "/api/v1/case-depth/alerts/merge", {"primary_id": str(primary), "duplicate_ids": [str(dup)]})
        code, body = await _post(token, "/api/v1/case-depth/alerts/merge", {"primary_id": str(dup), "duplicate_ids": [str(third)]})
        assert code == 422
        assert "itself merged" in body["detail"]

    async def test_two_alerts_merge_into_one_case_with_their_history_kept(self, world) -> None:
        """The phase's own "Done when", literally."""
        maker, tenant_id, _user, token = world
        case_id = await _case(maker, tenant_id)
        on_case = await _alert(maker, tenant_id, case_id=case_id)
        loose = await _alert(maker, tenant_id)

        code, body = await _post(
            token,
            "/api/v1/case-depth/alerts/merge",
            {"primary_id": str(loose), "duplicate_ids": [str(on_case)]},
        )
        assert code == 200, body
        # The survivor inherits the case rather than being left detached.
        assert body["case_id"] == str(case_id)

        async with maker() as db:
            rows = (
                (await db.execute(text("SELECT id, case_id, is_merged FROM alerts WHERE tenant_id = :t"), {"t": tenant_id}))
                .mappings()
                .all()
            )
        by_id = {row["id"]: row for row in rows}
        assert by_id[loose]["case_id"] == case_id
        # And the absorbed alert still exists, still on the case, marked merged.
        assert by_id[on_case]["is_merged"] is True
        assert by_id[on_case]["case_id"] == case_id


@live_only
@pytest.mark.asyncio
class TestCaseMerge:
    async def test_merging_cases_repoints_alerts_and_keeps_both_rows(self, world) -> None:
        maker, tenant_id, _user, token = world
        primary = await _case(maker, tenant_id)
        duplicate = await _case(maker, tenant_id)
        alert_id = await _alert(maker, tenant_id, case_id=duplicate)

        code, body = await _post(
            token,
            "/api/v1/case-depth/cases/merge",
            {"primary_id": str(primary), "duplicate_ids": [str(duplicate)], "reason": "same incident"},
        )
        assert code == 200, body

        async with maker() as db:
            case_rows = (
                (
                    await db.execute(
                        text("SELECT id, status, merged_into_id, merged_by, resolution FROM aisoc_cases WHERE tenant_id = :t"),
                        {"t": tenant_id},
                    )
                )
                .mappings()
                .all()
            )
            moved = (await db.execute(text("SELECT case_id FROM alerts WHERE id = :i"), {"i": alert_id})).scalar_one()

        by_id = {row["id"]: row for row in case_rows}
        assert len(case_rows) == 2, "a merge must not delete the absorbed case"
        assert by_id[duplicate]["merged_into_id"] == primary
        assert by_id[duplicate]["status"] == "closed"
        assert by_id[duplicate]["merged_by"]
        assert by_id[primary]["merged_into_id"] is None
        assert moved == primary


@live_only
@pytest.mark.asyncio
class TestBulkTriage:
    async def test_a_larger_match_than_max_count_writes_nothing(self, world) -> None:
        maker, tenant_id, _user, token = world
        ids = [await _alert(maker, tenant_id) for _ in range(3)]

        code, body = await _post(
            token,
            "/api/v1/case-depth/alerts/bulk-triage",
            {"alert_ids": [str(i) for i in ids], "set_status": "in_progress", "max_count": 2},
        )
        assert code == 409
        assert "3 alert(s) match" in body["detail"]

        async with maker() as db:
            statuses = (await db.execute(text("SELECT DISTINCT status FROM alerts WHERE tenant_id = :t"), {"t": tenant_id})).scalars().all()
        # The point of the preflight: nothing moved.
        assert set(statuses) == {"new"}

    async def test_raising_max_count_applies_it(self, world) -> None:
        maker, tenant_id, _user, token = world
        ids = [await _alert(maker, tenant_id) for _ in range(3)]

        code, body = await _post(
            token,
            "/api/v1/case-depth/alerts/bulk-triage",
            {"alert_ids": [str(i) for i in ids], "set_status": "in_progress", "set_severity": "low", "max_count": 3},
        )
        assert code == 200, body
        assert body["updated_count"] == 3

        async with maker() as db:
            rows = (await db.execute(text("SELECT status, severity FROM alerts WHERE tenant_id = :t"), {"t": tenant_id})).mappings().all()
        assert {(r["status"], r["severity"]) for r in rows} == {("in_progress", "low")}

    async def test_closed_is_not_reachable_here(self, world) -> None:
        """`bulk-close` snapshots every row first; a weaker second path to the
        same destination is how the weaker one becomes the one people use."""
        maker, tenant_id, _user, token = world
        alert_id = await _alert(maker, tenant_id)
        code, body = await _post(
            token,
            "/api/v1/case-depth/alerts/bulk-triage",
            {"alert_ids": [str(alert_id)], "set_status": "closed", "max_count": 1},
        )
        assert code == 422
        assert "bulk-close" in body["detail"]

    async def test_naming_no_change_is_refused(self, world) -> None:
        maker, tenant_id, _user, token = world
        alert_id = await _alert(maker, tenant_id)
        code, body = await _post(token, "/api/v1/case-depth/alerts/bulk-triage", {"alert_ids": [str(alert_id)], "max_count": 1})
        assert code == 422
        assert "at least one of" in body["detail"]


@live_only
@pytest.mark.asyncio
class TestWorkload:
    async def test_counts_come_from_rows_this_query_selected(self, world) -> None:
        maker, tenant_id, _user, token = world
        await _case(maker, tenant_id, assignee="ana@example.com", status="investigating")
        await _case(maker, tenant_id, assignee="ana@example.com", status="new")
        await _case(maker, tenant_id, assignee="ben@example.com", status="closed", closed=True)
        await _case(maker, tenant_id, assignee=None, status="new")

        code, body = await _get(token, "/api/v1/case-depth/workload?days=30")
        assert code == 200, body
        rows = {row["analyst"]: row for row in body["analysts"]}

        # Counted independently here rather than by calling the thing under
        # test a second time, which is how four usage meters came to agree
        # with themselves and not with the database.
        assert rows["ana@example.com"]["open_cases"] == 2
        assert rows["ana@example.com"]["closed_cases"] == 0
        assert rows["ben@example.com"]["closed_cases"] == 1
        assert body["unassigned"]["open_cases"] == 1

    async def test_a_mean_over_nothing_is_null_not_zero(self, world) -> None:
        maker, tenant_id, _user, token = world
        await _case(maker, tenant_id, assignee="ana@example.com", status="investigating")

        _code, body = await _get(token, "/api/v1/case-depth/workload?days=30")
        row = next(r for r in body["analysts"] if r["analyst"] == "ana@example.com")
        # 0.0 reads as "closed instantly", which is the opposite of "no data".
        assert row["mean_hours_to_close"] is None
        assert row["mean_over_cases"] == 0

    async def test_a_mean_travels_with_the_count_it_was_taken_over(self, world) -> None:
        maker, tenant_id, _user, token = world
        await _case(maker, tenant_id, assignee="ben@example.com", status="closed", closed=True, created_days_ago=2)
        await _case(maker, tenant_id, assignee="ben@example.com", status="closed", closed=True, created_days_ago=3)

        _code, body = await _get(token, "/api/v1/case-depth/workload?days=30")
        row = next(r for r in body["analysts"] if r["analyst"] == "ben@example.com")
        assert row["mean_over_cases"] == 2
        # Each fixture case closes four hours after it opens.
        assert row["mean_hours_to_close"] == pytest.approx(4.0, abs=0.1)

    async def test_a_case_absorbed_by_a_merge_is_not_counted_as_work(self, world) -> None:
        maker, tenant_id, _user, token = world
        primary = await _case(maker, tenant_id, assignee="ana@example.com", status="investigating")
        duplicate = await _case(maker, tenant_id, assignee="ana@example.com", status="investigating")

        before = (await _get(token, "/api/v1/case-depth/workload?days=30"))[1]
        assert next(r for r in before["analysts"] if r["analyst"] == "ana@example.com")["open_cases"] == 2

        await _post(token, "/api/v1/case-depth/cases/merge", {"primary_id": str(primary), "duplicate_ids": [str(duplicate)]})

        after = (await _get(token, "/api/v1/case-depth/workload?days=30"))[1]
        row = next(r for r in after["analysts"] if r["analyst"] == "ana@example.com")
        # Counting the absorbed case would make a merge look like throughput.
        assert row["open_cases"] == 1
        assert row["total"] == 1


@live_only
@pytest.mark.asyncio
class TestCustomFields:
    async def test_a_value_under_an_undefined_key_is_refused(self, world) -> None:
        maker, tenant_id, _user, token = world
        case_id = await _case(maker, tenant_id)
        from app.main import app

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            res = await client.put(
                f"/api/v1/case-depth/cases/{case_id}/custom-values",
                json={"values": {"business_unit": "payments"}},
                headers={"Authorization": f"Bearer {token}"},
            )
        assert res.status_code == 422
        assert "no such custom field" in res.text

    async def test_a_field_defined_after_the_case_still_renders_on_it(self, world) -> None:
        maker, tenant_id, _user, token = world
        case_id = await _case(maker, tenant_id)
        code, field = await _post(
            token,
            "/api/v1/case-depth/custom-fields",
            {"key": "business_unit", "label": "Business unit", "field_type": "select", "choices": ["payments", "retail"]},
        )
        assert code == 201, field

        code, values = await _get(token, f"/api/v1/case-depth/cases/{case_id}/custom-values")
        assert code == 200
        # The form returns the *fields*, not the stored rows, so a field added
        # after the case was created is not silently omitted.
        assert [v["key"] for v in values] == ["business_unit"]
        assert values[0]["value"] == ""

    async def test_retiring_a_field_keeps_the_values_written_against_it(self, world) -> None:
        maker, tenant_id, _user, token = world
        case_id = await _case(maker, tenant_id)
        _code, field = await _post(
            token,
            "/api/v1/case-depth/custom-fields",
            {"key": "owner_team", "label": "Owning team", "field_type": "text"},
        )
        from app.main import app

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            await client.put(
                f"/api/v1/case-depth/cases/{case_id}/custom-values",
                json={"values": {"owner_team": "payments-oncall"}},
                headers={"Authorization": f"Bearer {token}"},
            )
            await client.delete(
                f"/api/v1/case-depth/custom-fields/{field['id']}",
                headers={"Authorization": f"Bearer {token}"},
            )

        async with maker() as db:
            stored = (await db.execute(text("SELECT value FROM aisoc_case_custom_values WHERE case_id = :c"), {"c": case_id})).scalar_one()
        assert stored == "payments-oncall"

    async def test_a_select_with_no_choices_is_refused(self, world) -> None:
        _maker, _tenant_id, _user, token = world
        code, body = await _post(
            token,
            "/api/v1/case-depth/custom-fields",
            {"key": "empty_select", "label": "Empty", "field_type": "select", "choices": []},
        )
        assert code == 422
        assert "at least one choice" in body["detail"]
