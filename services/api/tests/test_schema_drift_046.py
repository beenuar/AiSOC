"""Regression guard for issue #492 — migration/model schema drift.

A fresh compose install builds Postgres from ``services/api/migrations/*.sql``
(mounted into ``/docker-entrypoint-initdb.d``). That lineage created
``detection_rules`` in its pre-refactor shape and ``cases`` without
``resolution``/``lessons_learned``, while the current ORM models query the
refactored columns — so every install served 500s out of the box until
``046_detection_rules_cases_schema_drift_fix.sql`` reconciled the two.

These tests are pure text/parse checks (no app import, so they run without the
full API dependency set). They pin two things:

  1. Migration 046 adds the specific columns named in #492, idempotently.
  2. The *whole* migration lineage now defines every column the DetectionRule
     and Case models declare — the invariant whose violation caused the bug.
     If someone refactors either model again without a reconciling migration,
     this fails instead of shipping another out-of-the-box 500.
"""

from __future__ import annotations

import re
from pathlib import Path

_API_ROOT = Path(__file__).resolve().parents[1]
_MIGRATIONS = _API_ROOT / "migrations"
_MODELS = _API_ROOT / "app" / "models"

MIGRATION_046 = _MIGRATIONS / "046_detection_rules_cases_schema_drift_fix.sql"

# Columns the current models query that the 001_init lineage never created.
_EXPECTED_046_DETECTION_COLUMNS = {
    "rule_language",
    "rule_body",
    "category",
    "status",
    "confidence",
    "fp_rate",
    "suppression_config",
    "threshold_config",
    "total_hits",
    "last_triggered",
    "is_builtin",
    "created_by_id",
}
_EXPECTED_046_CASE_COLUMNS = {"resolution", "lessons_learned"}


def _model_columns(model_file: str, class_name: str) -> set[str]:
    """Column names declared on ``class_name`` in ``model_file``.

    Parses the class body for ``mapped_column`` declarations. When a column is
    remapped to a different DB name (``mapped_column("db_name", ...)``) the
    string literal wins; otherwise the attribute name is the column name.
    ``relationship(...)`` attributes are ignored.
    """
    text = (_MODELS / model_file).read_text(encoding="utf-8")
    # Slice from the class declaration to the next top-level ``class`` (or EOF).
    start = text.index(f"class {class_name}")
    rest = text[start + 1 :]
    nxt = re.search(r"\nclass \w", rest)
    body = rest[: nxt.start()] if nxt else rest

    columns: set[str] = set()
    for attr, first_arg in re.findall(
        r"^\s*(\w+):\s*Mapped\[[^\]]*\]\s*=\s*mapped_column\(\s*(\"[^\"]*\")?",
        body,
        flags=re.MULTILINE,
    ):
        columns.add(first_arg.strip('"') if first_arg else attr)
    return columns


def _lineage_columns(table: str) -> set[str]:
    """Every column the SQL migration lineage defines for ``table``.

    Scans ``CREATE TABLE`` bodies and ``ALTER TABLE ... ADD COLUMN`` clauses
    scoped to ``table`` across all migration files (statements split on ``;``).
    """
    columns: set[str] = set()
    create_re = re.compile(
        rf"CREATE TABLE(?:\s+IF NOT EXISTS)?\s+{table}\s*\((?P<body>.*)",
        re.IGNORECASE | re.DOTALL,
    )
    alter_re = re.compile(rf"ALTER TABLE\s+(?:ONLY\s+)?{table}\b", re.IGNORECASE)
    add_col_re = re.compile(r"ADD COLUMN(?:\s+IF NOT EXISTS)?\s+(\w+)", re.IGNORECASE)
    # A column definition line inside CREATE TABLE: leading identifier that is
    # not a table-level constraint keyword.
    coldef_re = re.compile(r"^\s*(\w+)\s", re.MULTILINE)
    _skip = {
        "constraint",
        "primary",
        "foreign",
        "unique",
        "check",
        "like",
        "exclude",
    }

    for sql_file in sorted(_MIGRATIONS.glob("*.sql")):
        text = sql_file.read_text(encoding="utf-8")
        for stmt in text.split(";"):
            m = create_re.search(stmt)
            if m:
                # Trim to the matching close paren of the column list.
                body = m.group("body")
                depth = 1
                cut = len(body)
                for i, ch in enumerate(body):
                    if ch == "(":
                        depth += 1
                    elif ch == ")":
                        depth -= 1
                        if depth == 0:
                            cut = i
                            break
                for col in coldef_re.findall(body[:cut]):
                    if col.lower() not in _skip:
                        columns.add(col)
            if alter_re.search(stmt):
                columns.update(add_col_re.findall(stmt))
    return columns


def test_migration_046_exists_and_is_transactional():
    assert MIGRATION_046.exists(), "046 schema-drift migration is missing"
    sql = MIGRATION_046.read_text(encoding="utf-8")
    assert "BEGIN;" in sql and "COMMIT;" in sql


def test_migration_046_adds_expected_columns_idempotently():
    sql = MIGRATION_046.read_text(encoding="utf-8")
    added = {c.lower() for c in re.findall(r"ADD COLUMN\s+IF NOT EXISTS\s+(\w+)", sql, re.IGNORECASE)}
    missing = (_EXPECTED_046_DETECTION_COLUMNS | _EXPECTED_046_CASE_COLUMNS) - added
    assert not missing, f"046 does not add (IF NOT EXISTS): {sorted(missing)}"

    # Every ADD COLUMN in this drift-fix must be idempotent.
    plain = re.findall(r"ADD COLUMN\s+(?!IF NOT EXISTS)(\w+)", sql, re.IGNORECASE)
    assert not plain, f"046 has non-idempotent ADD COLUMN clauses: {plain}"


def test_migration_046_drops_legacy_rule_content_not_null_guarded():
    sql = MIGRATION_046.read_text(encoding="utf-8")
    assert re.search(
        r"ALTER COLUMN\s+rule_content\s+DROP NOT NULL", sql, re.IGNORECASE
    ), "046 must drop the legacy rule_content NOT NULL so ORM inserts succeed"
    # Guarded so the create_all lineage (no rule_content column) doesn't error.
    assert "information_schema.columns" in sql


def test_detection_rules_lineage_covers_model():
    model_cols = _model_columns("detection_rule.py", "DetectionRule")
    lineage_cols = _lineage_columns("detection_rules")
    missing = model_cols - lineage_cols
    assert not missing, (
        "detection_rules migration lineage is missing model columns " f"{sorted(missing)} — a reconciling migration is required (see #492)"
    )


def test_cases_lineage_covers_model():
    model_cols = _model_columns("case.py", "Case")
    lineage_cols = _lineage_columns("cases")
    missing = model_cols - lineage_cols
    assert not missing, (
        "cases migration lineage is missing model columns " f"{sorted(missing)} — a reconciling migration is required (see #492)"
    )
