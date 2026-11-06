"""Nothing compared the applied migrations against the ones on disk.

``aisoc_schema_migrations`` was read in exactly one place —
``app/scripts/run_migrations.py``, by the runner that writes it — so a
deployment whose migration step failed, was skipped, or was rolled back ran
new code against an old schema while ``/health`` answered 200 and ``/readyz``
answered ready. The first symptom was an ``UndefinedColumnError`` on whichever
request happened to touch the missing column.

Three states, and the third is the point
----------------------------------------
``current`` and ``skewed`` are the easy half. The state that matters is
``unknown``: no database, no tracking table, or a query that raised. This
repository's recurring defect is a gate whose unknown bucket is a pass, so the
tests below drive each of those three failure routes separately and assert the
verdict is ``unknown`` — never ``current`` — in all of them.

Filenames, not parsed numbers
-----------------------------
``run_migrations.py`` tracks migrations by filename and applies them in
``sorted()`` filename order. ``scripts/check_migration_numbering.py`` exists
because duplicate numeric prefixes are a real occurrence here and thirteen
pre-existing collisions are deliberately frozen, so a comparison keyed on a
parsed number would fold two distinct migrations into one and report a
database that is missing one of them as current.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from app.main import app
from app.services import schema_skew as skew_module
from app.services.schema_skew import (
    MIGRATIONS_DIR,
    SchemaSkew,
    SchemaSkewed,
    SchemaStateUnknown,
    evaluate_skew,
    migrations_on_disk,
    probe_schema_current,
    readyz_probe,
)
from fastapi.testclient import TestClient


class TestMigrationsOnDisk:
    def test_reads_the_real_migration_directory(self) -> None:
        names = migrations_on_disk()
        assert names, "the api service ships SQL migrations; none were found"
        assert all(n.endswith(".sql") for n in names)
        assert names == sorted(names), "run_migrations applies in sorted() filename order"

    def test_matches_the_directory_run_migrations_uses(self) -> None:
        assert MIGRATIONS_DIR == Path(__file__).resolve().parents[1] / "migrations"

    def test_duplicate_numeric_prefixes_stay_distinct(self, tmp_path: Path) -> None:
        """Two migrations numbered 121 are two migrations, not one."""
        for name in ("121_a.sql", "121_b.sql", "122_c.sql"):
            (tmp_path / name).write_text("SELECT 1;", encoding="utf-8")
        assert migrations_on_disk(tmp_path) == ["121_a.sql", "121_b.sql", "122_c.sql"]

    def test_non_sql_files_are_not_migrations(self, tmp_path: Path) -> None:
        (tmp_path / "001_init.sql").write_text("SELECT 1;", encoding="utf-8")
        (tmp_path / "README.md").write_text("notes", encoding="utf-8")
        (tmp_path / "001_init.sql.bak").write_text("SELECT 1;", encoding="utf-8")
        assert migrations_on_disk(tmp_path) == ["001_init.sql"]


class TestEvaluateSkew:
    def test_exact_agreement_is_current(self) -> None:
        skew = evaluate_skew(applied={"001_a.sql", "002_b.sql"}, on_disk=["001_a.sql", "002_b.sql"])
        assert skew.state == "current"
        assert skew.pending == []
        assert skew.applied_not_on_disk == []
        assert skew.latest_applied == "002_b.sql"

    def test_a_migration_on_disk_that_was_never_applied_is_skewed(self) -> None:
        """The dangerous direction: new code, old schema."""
        skew = evaluate_skew(applied={"001_a.sql"}, on_disk=["001_a.sql", "002_b.sql"])
        assert skew.state == "skewed"
        assert skew.pending == ["002_b.sql"]
        assert "002_b.sql" in skew.detail

    def test_an_applied_migration_absent_from_the_tree_is_skewed(self) -> None:
        """The other direction: a rolled-back deploy, old code on a new schema.

        Reported as skew rather than as current because the two halves
        disagree, which is the whole question being asked. The payload names
        which direction it is, so the single verdict never hides it.
        """
        skew = evaluate_skew(applied={"001_a.sql", "002_b.sql"}, on_disk=["001_a.sql"])
        assert skew.state == "skewed"
        assert skew.pending == []
        assert skew.applied_not_on_disk == ["002_b.sql"]

    def test_pending_is_reported_in_apply_order(self) -> None:
        skew = evaluate_skew(applied=set(), on_disk=["002_b.sql", "001_a.sql", "003_c.sql"])
        assert skew.pending == ["001_a.sql", "002_b.sql", "003_c.sql"]

    def test_high_water_mark_is_the_last_applied_in_apply_order(self) -> None:
        skew = evaluate_skew(applied={"001_a.sql", "003_c.sql"}, on_disk=["001_a.sql", "002_b.sql", "003_c.sql"])
        assert skew.latest_applied == "003_c.sql"

    def test_unreadable_applied_set_is_unknown_not_current(self) -> None:
        """``applied=None`` means the question could not be answered."""
        skew = evaluate_skew(applied=None, on_disk=["001_a.sql"], reason="UndefinedTableError")
        assert skew.state == "unknown"
        assert skew.applied_count is None
        assert skew.latest_applied is None
        assert "UndefinedTableError" in skew.detail

    def test_unknown_is_not_reported_as_current_even_with_no_migrations(self) -> None:
        """An empty tree plus an unreadable database is still unknown.

        Both sides are empty-ish, so a set comparison alone would call this
        agreement. It is not: nothing was compared.
        """
        skew = evaluate_skew(applied=None, on_disk=[], reason="ConnectionRefusedError")
        assert skew.state == "unknown"

    def test_an_empty_database_against_a_populated_tree_is_skewed(self) -> None:
        skew = evaluate_skew(applied=set(), on_disk=["001_a.sql"])
        assert skew.state == "skewed"
        assert skew.applied_count == 0

    def test_healthy_is_true_only_for_current(self) -> None:
        """``/readyz`` reads this single boolean; unknown must not pass it."""
        assert evaluate_skew(applied={"a.sql"}, on_disk=["a.sql"]).healthy is True
        assert evaluate_skew(applied=set(), on_disk=["a.sql"]).healthy is False
        assert evaluate_skew(applied=None, on_disk=["a.sql"], reason="boom").healthy is False

    def test_detail_never_claims_a_count_it_did_not_read(self) -> None:
        skew = evaluate_skew(applied=None, on_disk=["a.sql", "b.sql"], reason="boom")
        assert "0 applied" not in skew.detail


class TestProbeAgainstAnUnreachableDatabase:
    """The probe must answer, and must answer ``unknown``."""

    async def test_no_database_is_unknown(self) -> None:
        skew = await probe_schema_current()
        assert isinstance(skew, SchemaSkew)
        assert skew.state == "unknown", f"expected unknown with no database, got {skew.state}: {skew.detail}"
        assert skew.healthy is False
        assert skew.detail, "an unknown verdict must say why it could not be established"

    async def test_the_probe_does_not_raise(self) -> None:
        """A readiness probe that raises takes the endpoint with it."""
        try:
            await probe_schema_current()
        except Exception as exc:  # noqa: BLE001 — that is precisely the assertion
            pytest.fail(f"probe_schema_current raised {type(exc).__name__}: {exc}")


class TestReadyzAdapter:
    """``/readyz``'s channel is a bool plus an exception name. Use both."""

    def _skew(self, state: str) -> SchemaSkew:
        return SchemaSkew(
            state=state,  # type: ignore[arg-type]
            detail=f"{state} for the test",
            on_disk_count=3,
            applied_count=None if state == "unknown" else 1,
            latest_applied=None,
        )

    async def test_current_returns_true(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(skew_module, "probe_schema_current", lambda: _async(self._skew("current")))
        assert await readyz_probe() is True

    async def test_skewed_and_unknown_raise_distinguishable_errors(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The two failure states must not collapse into one message.

        ``register_dependency`` reports ``type(exc).__name__``, so distinct
        classes are what keeps "the schema is behind" legible as something
        other than "nobody could tell".
        """
        monkeypatch.setattr(skew_module, "probe_schema_current", lambda: _async(self._skew("skewed")))
        with pytest.raises(SchemaSkewed):
            await readyz_probe()

        monkeypatch.setattr(skew_module, "probe_schema_current", lambda: _async(self._skew("unknown")))
        with pytest.raises(SchemaStateUnknown):
            await readyz_probe()

        assert SchemaSkewed.__name__ != SchemaStateUnknown.__name__

    async def test_a_truthy_verdict_object_would_have_passed(self) -> None:
        """Why the adapter exists, pinned so nobody 'simplifies' it away.

        Registering ``probe_schema_current`` directly would hand
        ``register_dependency`` a dataclass, and ``bool(dataclass)`` is
        ``True`` for every verdict including ``unknown`` — the probe would
        report healthy on a database it never reached.
        """
        assert bool(self._skew("unknown")) is True


class TestReadyzReportsSkewWithoutRefusingToServe:
    def test_readyz_names_the_schema_and_still_returns_200(self) -> None:
        """Report loudly; do not pull the console out of the load balancer.

        These tests run with no reachable database, so the verdict is
        ``unknown``. Readiness must say so — and must not 503, because an
        operator mid-incident losing their console over a schema check is a
        worse outcome than the skew.
        """
        with TestClient(app) as client:
            response = client.get("/readyz")
        body = response.json()
        assert "schema_migrations_current" in body, body
        assert body["schema_migrations_current"] is False
        assert body["dependency_errors"]["schema_migrations_current"] == "SchemaStateUnknown"
        assert body["status"] == "ready_degraded"
        assert response.status_code == 200, "a non-required dependency must not fail readiness"


async def _async(value):
    return value
