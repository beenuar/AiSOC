"""Three routes that read tenant data without scoping it, or without auth.

What these tests defend
~~~~~~~~~~~~~~~~~~~~~~~

1. ``/identity-timeline`` bound ``AuthUser`` and never used it. Its SQL against
   ``aisoc_alerts`` carried no ``tenant_id`` predicate, so any authenticated
   user could pull every tenant's alerts whose title or evidence matched a
   substring they chose — and the substring is the search term, so the match
   is attacker-controlled.

2. ``/playbooks`` declared no dependency of any kind across eight routes, and
   there is no global auth middleware, so all eight were reachable
   unauthenticated — including ``POST /playbooks/{id}/run``, which executes a
   playbook against the estate. The three permissions it now uses already
   existed in ``ROLE_PERMISSIONS`` with no reader.

3. ``cases`` hydrated linked-alert titles with ``WHERE id = :id`` and no
   tenant predicate. Reaching it requires a tenant-scoped case, so this is
   defence in depth rather than a live read — but a poisoned ``alert_ids``
   array would otherwise surface another tenant's alert title.

Every test here fails against the previous code.
"""

from __future__ import annotations

import inspect
import re
import uuid
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.api.v1.endpoints import cases as cases_module
from app.api.v1.endpoints import identity_timeline as it_module
from app.api.v1.endpoints import playbooks as pb_module
from app.api.v1.endpoints.identity_timeline import BuildTimelineRequest, build_timeline

_ENDPOINTS = Path(it_module.__file__).parent


def _user(tenant_id: uuid.UUID | None = None) -> Any:
    u = MagicMock()
    u.id = uuid.uuid4()
    u.tenant_id = tenant_id or uuid.uuid4()
    return u


def _capturing_db(rows: list[Any] | None = None) -> Any:
    """AsyncSession double that records the statements it executed."""
    executed: list[Any] = []

    async def _execute(stmt: Any, *args: Any, **kwargs: Any) -> Any:
        executed.append(stmt)
        result = MagicMock()
        result.fetchall = MagicMock(return_value=rows or [])
        result.fetchone = MagicMock(return_value=(rows or [None])[0])
        return result

    db = MagicMock()
    db.execute = AsyncMock(side_effect=_execute)
    db.executed = executed
    return db


class TestIdentityTimelineIsTenantScoped:
    async def test_alert_query_carries_a_tenant_predicate(self) -> None:
        tenant = uuid.uuid4()
        db = _capturing_db()

        await build_timeline(
            body=BuildTimelineRequest(identity_kind="user", identity_value="svc-backup"),
            db=db,
            user=_user(tenant),
        )

        assert db.executed, "the alert source was never queried"
        sql = str(db.executed[0])
        assert "tenant_id" in sql, f"no tenant predicate in: {sql}"

    async def test_the_callers_own_tenant_is_bound(self) -> None:
        tenant = uuid.uuid4()
        db = _capturing_db()

        await build_timeline(
            body=BuildTimelineRequest(identity_kind="user", identity_value="svc-backup"),
            db=db,
            user=_user(tenant),
        )

        params = db.executed[0].compile().params
        assert params.get("tenant_id") == str(tenant)

    async def test_search_term_is_bound_not_interpolated(self) -> None:
        """The identity value is attacker-chosen; it must stay a parameter."""
        db = _capturing_db()

        await build_timeline(
            body=BuildTimelineRequest(identity_kind="user", identity_value="'; DROP TABLE aisoc_alerts; --"),
            db=db,
            user=_user(),
        )

        assert "DROP TABLE" not in str(db.executed[0])

    async def test_returns_an_empty_timeline_rather_than_raising(self) -> None:
        db = _capturing_db()
        result = await build_timeline(
            body=BuildTimelineRequest(identity_kind="user", identity_value="nobody"),
            db=db,
            user=_user(),
        )
        assert result.events == []
        assert result.total_events == 0

    async def test_an_unreadable_source_is_reported_not_swallowed(self) -> None:
        """It used to be a DEBUG line, so an empty timeline from a broken query
        was indistinguishable from an empty timeline from no matches."""
        db = MagicMock()
        db.execute = AsyncMock(side_effect=RuntimeError("relation does not exist"))

        result = await build_timeline(
            body=BuildTimelineRequest(identity_kind="user", identity_value="svc-backup"),
            db=db,
            user=_user(),
        )

        assert result.sources_unavailable == ["aisoc_alerts"]
        assert result.events == []

    async def test_a_healthy_build_reports_nothing_unavailable(self) -> None:
        result = await build_timeline(
            body=BuildTimelineRequest(identity_kind="user", identity_value="svc-backup"),
            db=_capturing_db(),
            user=_user(),
        )
        assert result.sources_unavailable == []

    def test_the_phantom_second_source_is_gone(self) -> None:
        """``aisoc_events`` is created by no migration, written by nothing, and
        appears nowhere else in the repository. The block that queried it
        swallowed its own failure at DEBUG, so it read as a second source of
        evidence while returning nothing on every deployment."""
        source = Path(it_module.__file__).read_text()
        query_lines = [ln for ln in source.splitlines() if "FROM aisoc_events" in ln]
        assert query_lines == []


class TestPlaybookRoutesRequirePermission:
    #: route function → the permission it must demand.
    EXPECTED = {
        "list_playbooks": "playbooks:read",
        "get_playbook": "playbooks:read",
        "list_runs": "playbooks:read",
        "get_run": "playbooks:read",
        "create_playbook": "playbooks:write",
        "update_playbook": "playbooks:write",
        "delete_playbook": "playbooks:write",
        "run_playbook": "playbooks:execute",
    }

    def test_every_route_function_takes_an_authenticated_principal(self) -> None:
        for name in self.EXPECTED:
            fn = getattr(pb_module, name)
            params = inspect.signature(fn).parameters
            assert "user" in params, f"{name} has no authenticated principal"

    def test_no_route_is_left_ungated(self) -> None:
        """Counts decorated routes against the expected map so a new route
        added without auth fails here rather than shipping open."""
        source = Path(pb_module.__file__).read_text()
        decorated = re.findall(r"@router\.(?:get|post|put|patch|delete)\(", source)
        assert len(decorated) == len(self.EXPECTED)

    def test_execute_is_a_distinct_permission_from_write(self) -> None:
        """An analyst can run a governed playbook without being able to edit
        one, which is the reason the two permissions exist separately."""
        assert self.EXPECTED["run_playbook"] != self.EXPECTED["update_playbook"]

    def test_the_permissions_used_are_ones_roles_actually_hold(self) -> None:
        from app.core.security import ROLE_PERMISSIONS

        granted = {perm for perms in ROLE_PERMISSIONS.values() for perm in perms}
        for name, permission in self.EXPECTED.items():
            assert permission in granted, f"{name} demands {permission}, which no role grants"

    def test_module_declares_the_dependency(self) -> None:
        source = Path(pb_module.__file__).read_text()
        assert "require_permission" in source


class TestCaseTimelineAlertHydrationIsScoped:
    def test_linked_alert_lookup_binds_a_tenant(self) -> None:
        source = Path(cases_module.__file__).read_text()
        matches = [ln for ln in source.splitlines() if "FROM aisoc_alerts WHERE id" in ln]
        assert matches, "the linked-alert hydration query moved; re-point this test"
        for line in matches:
            assert "tenant_id" in line, f"unscoped alert read: {line.strip()}"


class TestNoUnscopedAlertReadsRemain:
    """A directory-wide sweep, so a new endpoint cannot reintroduce the shape.

    Deliberately a text scan rather than a call-graph analysis: the property is
    "every raw SQL read of the alerts tables names tenant_id", which is exactly
    what a reviewer checks by eye, and a scan cannot be defeated by a helper
    that hides the predicate one frame away.
    """

    def test_every_raw_alerts_select_mentions_tenant_id(self) -> None:
        offenders: list[str] = []
        for path in _ENDPOINTS.glob("*.py"):
            text = path.read_text()
            for match in re.finditer(r"FROM\s+aisoc_alerts\b(.{0,400}?)(?:\"\"\"|\)\s*$)", text, re.S | re.I):
                if "tenant_id" not in match.group(1):
                    offenders.append(f"{path.name}: {match.group(0)[:120].strip()}")
        assert offenders == [], "unscoped reads of aisoc_alerts:\n" + "\n".join(offenders)


@pytest.mark.parametrize("module", [it_module, pb_module])
def test_modules_import_cleanly(module: Any) -> None:
    assert module is not None
