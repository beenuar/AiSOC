"""The #1888 carry shipped migration 161 and stamped the column from both
writers, but the Alert model never declared ``disposition_source`` — every
POST /feedback/alert-override died in SQLAlchemy compilation with
``CompileError: Unconsumed column names: disposition_source`` (issue #1894).

These tests pin the two halves of the contract:
  1. the model maps every column migration 161 adds (compile-time), and
  2. the exact UPDATE the feedback endpoint issues compiles to SQL that
     writes both columns (the statement that used to 500).
"""

import pathlib

from app.models.alert import Alert
from sqlalchemy import update

MIGRATION = pathlib.Path(__file__).resolve().parents[1] / "migrations" / "161_disposition_source.sql"


def _migration_added_columns() -> set[str]:
    """Column names migration 161 adds via ALTER TABLE ... ADD COLUMN."""
    cols: set[str] = set()
    for stmt in MIGRATION.read_text().split(";"):
        head = " ".join(stmt.split())
        if "ADD COLUMN" in head.upper():
            tokens = head.split()
            idx = [i for i, t in enumerate(tokens) if t.upper() == "EXISTS"]
            assert idx, f"ADD COLUMN IF NOT EXISTS form expected: {head!r}"
            cols.add(tokens[idx[0] + 1])
    return cols


def test_model_declares_every_column_migration_161_adds() -> None:
    added = _migration_added_columns()
    assert "disposition_source" in added  # sanity: migration is what we think it is
    mapped = set(Alert.__table__.columns.keys())
    missing = added - mapped
    assert not missing, f"Alert model is missing migration-161 columns: {sorted(missing)}"


def test_feedback_endpoint_update_compiles() -> None:
    """The statement feedback.py issues must compile (it raised CompileError before)."""
    stmt = (
        update(Alert)
        .where(Alert.tenant_id == "00000000-0000-0000-0000-000000000001")
        .values(disposition="false_positive", disposition_source="analyst")
    )
    sql = str(stmt.compile())
    assert "disposition_source" in sql


def test_disposition_source_is_nullable_and_string() -> None:
    col = Alert.__table__.columns["disposition_source"]
    assert col.nullable is True  # NULL = unknown/never provenance (safe default)
    assert col.type.length == 50
