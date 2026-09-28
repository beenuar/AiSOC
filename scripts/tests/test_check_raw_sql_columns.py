"""The raw-SQL column gate detects what it claims, and only that.

Proven against the two shapes that reached `main` — a table named wrongly with
a name that *contains* the right one, and a column no migration creates — and
against the shapes that would make the gate a nuisance if it fired on them: a
correct statement, and SQL the source assembles at runtime and records why.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
GATE = REPO_ROOT / "scripts" / "check_raw_sql_columns.py"

MIGRATION = """
CREATE TABLE IF NOT EXISTS widgets (
    id          UUID PRIMARY KEY,
    -- a comment line, which the shared parser used to read as a column name
    tenant_id   UUID NOT NULL,
    name        VARCHAR(200) NOT NULL
);

ALTER TABLE widgets
    ADD COLUMN IF NOT EXISTS label   TEXT,
    ADD COLUMN IF NOT EXISTS retired BOOLEAN NOT NULL DEFAULT FALSE;
"""


def _load():
    spec = importlib.util.spec_from_file_location("check_raw_sql_columns", GATE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _tree(tmp_path: Path, statement: str, migration: str = MIGRATION) -> Path:
    """A one-service tree: a module holding `statement`, and `migration`."""
    root = tmp_path / "tree"
    service = root / "services" / "widgetry"
    (service / "app" / "api").mkdir(parents=True)
    (service / "app" / "api" / "widgets.py").write_text(statement, encoding="utf-8")
    (service / "migrations").mkdir(parents=True)
    (service / "migrations" / "001_init.sql").write_text(migration, encoding="utf-8")
    return root


def _kinds(result: dict) -> list[str]:
    return [f["kind_of_finding"] for f in result["findings"]]


def test_an_insert_naming_a_table_no_migration_creates_fails(tmp_path) -> None:
    """The defect, in the spelling it actually had.

    `aisoc_detection_rule_proposals` contains `detection_rule_proposals`, so
    the substring assertion this gate was written beside passed on it.
    """
    module = _load()
    statement = 'SQL = "INSERT INTO aisoc_widgets (id, tenant_id, name) VALUES (:id, :tid, :name)"\n'
    result = module.scan(_tree(tmp_path, statement))
    assert _kinds(result) == ["unknown-table"]
    assert result["findings"][0]["table"] == "aisoc_widgets"
    assert result["compared"] == 0


def test_an_insert_naming_a_column_no_migration_creates_fails(tmp_path) -> None:
    """`detection_rule_proposals.source`, reduced to its essentials."""
    module = _load()
    statement = 'SQL = "INSERT INTO widgets (id, tenant_id, source) VALUES (:id, :tid, :src)"\n'
    result = module.scan(_tree(tmp_path, statement))
    assert _kinds(result) == ["unknown-column"]
    assert result["findings"][0]["column"] == "source"
    # The statement is still credited: the table resolved and the other two
    # columns were compared, which is what `--credits` has to be able to show.
    assert result["compared"] == 1


def test_a_correct_insert_passes(tmp_path) -> None:
    module = _load()
    statement = 'SQL = "INSERT INTO widgets (id, tenant_id, name) VALUES (:id, :tid, :name)"\n'
    result = module.scan(_tree(tmp_path, statement))
    assert result["findings"] == []
    assert result["compared"] == 1


def test_a_column_added_by_a_multi_clause_alter_table_is_credited(tmp_path) -> None:
    """The parser gap that would have made this gate unusable.

    `ALTER TABLE t ADD COLUMN a, ADD COLUMN b` is one statement with two
    clauses. Reading only the first credited `alerts` with one of three new
    columns and `aisoc_run_costs` with one of five, so eleven perfectly
    ordinary writes read as naming columns that do not exist.
    """
    module = _load()
    statement = 'SQL = "INSERT INTO widgets (id, label, retired) VALUES (:id, :l, :r)"\n'
    result = module.scan(_tree(tmp_path, statement))
    assert result["findings"] == []


def test_an_update_naming_a_column_no_migration_creates_fails(tmp_path) -> None:
    module = _load()
    statement = 'SQL = "UPDATE widgets SET label = :l, ghost = :g WHERE id = :id"\n'
    result = module.scan(_tree(tmp_path, statement))
    assert _kinds(result) == ["unknown-column"]
    assert result["findings"][0]["column"] == "ghost"


def test_a_sql_comment_inside_a_set_clause_does_not_read_as_dynamic(tmp_path) -> None:
    """Three real upserts were reported as runtime-assembled for this reason."""
    module = _load()
    statement = 'SQL = """UPDATE widgets\n   SET label = :l,\n       -- a note, with a comma in it\n       name = :n\n WHERE id = :id"""\n'
    result = module.scan(_tree(tmp_path, statement))
    assert result["findings"] == []
    assert result["compared"] == 1


def test_a_runtime_assembled_statement_is_a_finding_until_it_is_recorded(tmp_path) -> None:
    module = _load()
    statement = 'SQL = f"UPDATE widgets SET {assignments} WHERE id = :id"\n'
    result = module.scan(_tree(tmp_path, statement))
    assert _kinds(result) == ["unparsed-statement"]


def test_the_allow_list_suppresses_a_named_dynamic_statement(tmp_path) -> None:
    module = _load()
    statement = 'SQL = f"UPDATE widgets SET {assignments} WHERE id = :id"\n'
    module.DYNAMIC_SQL = {("services/widgetry/app/api/widgets.py", "widgets"): "assembled from the request body"}
    result = module.scan(_tree(tmp_path, statement))
    assert result["findings"] == []
    assert result["recorded"] == 1


def test_the_allow_list_does_not_forgive_a_readable_statement_beside_a_dynamic_one(tmp_path) -> None:
    """An entry excuses the statement it names, not the file it lives in.

    Keyed on (file, table), a blanket exemption would have covered every
    other write in the same module against the same table — which is how an
    allow-list stops being a record and becomes a hole.
    """
    module = _load()
    statement = 'ONE = f"UPDATE widgets SET {assignments} WHERE id = :id"\nTWO = "INSERT INTO widgets (id, ghost) VALUES (:id, :g)"\n'
    module.DYNAMIC_SQL = {("services/widgetry/app/api/widgets.py", "widgets"): "assembled from the request body"}
    result = module.scan(_tree(tmp_path, statement))
    assert _kinds(result) == ["unknown-column"]
    assert result["findings"][0]["column"] == "ghost"


def test_an_allow_list_entry_nothing_needs_is_itself_a_finding(tmp_path) -> None:
    """The list only shrinks, so it is verified in both directions."""
    module = _load()
    statement = 'SQL = "INSERT INTO widgets (id, tenant_id, name) VALUES (:id, :tid, :name)"\n'
    module.DYNAMIC_SQL = {("services/widgetry/app/api/nowhere.py", "widgets"): "no longer true"}
    module.UNMIGRATED_TABLES = {"sprockets": "another store, once"}
    result = module.scan(_tree(tmp_path, statement))
    assert result["findings"] == []
    assert len(result["stale"]) == 2


def test_a_tree_the_gate_parses_no_sql_out_of_is_refused(tmp_path) -> None:
    """A gate that reads nothing finds nothing, so `main()` has to refuse it.

    The shape that actually happens: `services/` is there, the modules are
    there, and the extraction has stopped matching. Nothing removes
    `services/`.
    """
    module = _load()
    root = _tree(tmp_path, "VALUE = 1\n")
    assert module.scan(root)["statements"] == []
    assert module.main(["--repo-root", str(root)]) != 0


def test_a_missing_services_directory_is_refused_rather_than_called_clean(tmp_path) -> None:
    module = _load()
    root = tmp_path / "bare"
    root.mkdir()
    assert "error" in module.scan(root)
    assert module.main(["--repo-root", str(root)]) == 2


def test_the_gate_answers_the_self_test_flag() -> None:
    result = subprocess.run([sys.executable, str(GATE), "--self-test"], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr


def test_the_live_repository_is_clean() -> None:
    """The regression this gate exists for, asserted against the real tree."""
    result = subprocess.run([sys.executable, str(GATE)], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
