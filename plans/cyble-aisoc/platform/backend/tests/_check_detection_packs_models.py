"""Smoke check for detection-packs SQLModel tables (t3d-models).

The durable side of vertical packs lives in three tables:

  * ``verticalpack``        — catalog of shippable packs
  * ``tenantpackassignment``— which packs a tenant has opted into
  * ``packrulecalibration`` — per-rule overrides for a tenant

This test pins down the invariants the rest of the system assumes:

  1. ``init_db()`` actually creates all three tables (they're imported
     via ``app.db`` so SQLModel's metadata knows about them).
  2. The natural-key UNIQUE constraints exist and are enforced:
       * (tenant_id, vertical_pack_id) for assignments
       * (tenant_id, rule_id)          for calibrations
     Without these, a concurrent second writer can sneak a duplicate
     past the app-layer upsert in ``calibration.py``.
  3. The calibration service's upsert path works end-to-end and is
     idempotent — calling ``assign_pack`` / ``set_calibration`` twice
     yields exactly one row (no IntegrityError) and the latest values
     win.
  4. Reading back through ``list_assignments`` / ``list_calibrations``
     returns detached, fully-loaded rows safe to use after the session
     closes (no DetachedInstanceError on attribute access).

Run from ``platform/backend/``::

    PYTHONPATH=. python tests/_check_detection_packs_models.py
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path


def _bootstrap_env() -> Path:
    tmpdir = Path(tempfile.mkdtemp(prefix="aisoc-packs-models-"))
    db_path = tmpdir / "aisoc.db"
    os.environ["AISOC_DB_PATH"] = str(db_path)
    os.environ["AISOC_LLM_PROVIDER"] = "mock"
    return db_path


DB_PATH = _bootstrap_env()
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import inspect  # noqa: E402
from sqlalchemy.exc import IntegrityError  # noqa: E402
from sqlmodel import select  # noqa: E402

from app.db import engine, init_db, session_scope  # noqa: E402
from app.detections import calibration, registry  # noqa: E402
from app.models.detection_packs import (  # noqa: E402
    PackRuleCalibration,
    TenantPackAssignment,
    VerticalPack,
)


TENANT = "tenant-models-smoke"
RULE = "rule-models-smoke-001"


def _fail(msg: str) -> None:
    print(f"FAIL: {msg}")
    sys.exit(1)


def _ok(msg: str) -> None:
    print(f"ok   {msg}")


def check_tables_exist() -> None:
    inspector = inspect(engine)
    tables = set(inspector.get_table_names())
    for expected in ("verticalpack", "tenantpackassignment", "packrulecalibration"):
        if expected not in tables:
            _fail(f"table {expected!r} missing from {sorted(tables)}")
    _ok("all three detection_packs tables created by init_db")


def check_unique_constraints_declared() -> None:
    """Check the metadata-level UniqueConstraint is wired up."""
    inspector = inspect(engine)
    for table, expected in (
        ("tenantpackassignment", {"tenant_id", "vertical_pack_id"}),
        ("packrulecalibration", {"tenant_id", "rule_id"}),
    ):
        constraints = inspector.get_unique_constraints(table)
        matches = [c for c in constraints if set(c["column_names"]) == expected]
        if not matches:
            _fail(
                f"unique constraint on {sorted(expected)} missing from "
                f"{table}; found: {constraints}"
            )
    _ok("unique constraints declared on natural keys")


def check_assignment_unique_enforced() -> None:
    """Inserting two raw rows for the same (tenant, pack) MUST fail."""
    pack_id = _pack_id("finserv")
    # First insert via raw ORM (no upsert) should succeed.
    with session_scope() as session:
        session.add(
            TenantPackAssignment(
                tenant_id=TENANT,
                vertical_pack_id=pack_id,
                enabled=True,
                assigned_by="models-smoke",
            )
        )
        session.commit()

    # Second insert with identical natural key MUST raise IntegrityError.
    raised = False
    try:
        with session_scope() as session:
            session.add(
                TenantPackAssignment(
                    tenant_id=TENANT,
                    vertical_pack_id=pack_id,
                    enabled=True,
                    assigned_by="models-smoke-duplicate",
                )
            )
            session.commit()
    except IntegrityError:
        raised = True

    if not raised:
        _fail(
            "duplicate (tenant_id, vertical_pack_id) insert did not raise "
            "IntegrityError — unique constraint not enforced"
        )
    _ok("duplicate assignment rejected by DB unique constraint")

    # Clean up so subsequent checks operate on a single row.
    with session_scope() as session:
        row = session.exec(
            select(TenantPackAssignment).where(
                TenantPackAssignment.tenant_id == TENANT,
                TenantPackAssignment.vertical_pack_id == pack_id,
            )
        ).first()
        if row is not None:
            session.delete(row)
            session.commit()


def check_calibration_unique_enforced() -> None:
    pack_id = _pack_id("finserv")
    with session_scope() as session:
        session.add(
            PackRuleCalibration(
                tenant_id=TENANT,
                vertical_pack_id=pack_id,
                rule_id=RULE,
                enabled=True,
            )
        )
        session.commit()

    raised = False
    try:
        with session_scope() as session:
            session.add(
                PackRuleCalibration(
                    tenant_id=TENANT,
                    vertical_pack_id=pack_id,
                    rule_id=RULE,
                    enabled=False,
                )
            )
            session.commit()
    except IntegrityError:
        raised = True

    if not raised:
        _fail(
            "duplicate (tenant_id, rule_id) insert did not raise "
            "IntegrityError — unique constraint not enforced"
        )
    _ok("duplicate calibration rejected by DB unique constraint")

    with session_scope() as session:
        row = session.exec(
            select(PackRuleCalibration).where(
                PackRuleCalibration.tenant_id == TENANT,
                PackRuleCalibration.rule_id == RULE,
            )
        ).first()
        if row is not None:
            session.delete(row)
            session.commit()


def check_calibration_service_upsert_is_idempotent() -> None:
    """assign_pack twice + set_calibration twice = one row each, no errors."""
    # Idempotent assignment.
    a1 = calibration.assign_pack(tenant_id=TENANT, pack="finserv", notes="first")
    a2 = calibration.assign_pack(tenant_id=TENANT, pack="finserv", notes="second")
    if a1.id != a2.id:
        _fail(
            f"assign_pack created two rows (ids {a1.id} != {a2.id}) — "
            f"upsert is not idempotent"
        )
    if a2.notes != "second":
        _fail(f"assign_pack didn't apply update; notes={a2.notes!r}")
    assignments = calibration.list_assignments(TENANT)
    finserv_rows = [
        r for r in assignments if r.vertical_pack_id == a1.vertical_pack_id
    ]
    if len(finserv_rows) != 1:
        _fail(
            f"after two assign_pack calls, expected 1 row, "
            f"got {len(finserv_rows)}"
        )
    _ok("assign_pack is idempotent and applies updates")

    # Idempotent calibration.
    c1 = calibration.set_calibration(
        tenant_id=TENANT,
        pack="finserv",
        rule_id=RULE,
        severity_override="high",
        baseline={"threshold": 100},
        notes="first",
    )
    c2 = calibration.set_calibration(
        tenant_id=TENANT,
        pack="finserv",
        rule_id=RULE,
        severity_override="critical",
        baseline={"threshold": 200},
        notes="second",
    )
    if c1.id != c2.id:
        _fail(
            f"set_calibration created two rows (ids {c1.id} != {c2.id})"
        )
    if c2.severity_override != "critical":
        _fail(
            f"set_calibration didn't apply severity update; "
            f"got {c2.severity_override!r}"
        )
    if c2.baseline != {"threshold": 200}:
        _fail(f"set_calibration didn't apply baseline update; got {c2.baseline!r}")

    cals = calibration.list_calibrations(TENANT, pack="finserv")
    if len([c for c in cals if c.rule_id == RULE]) != 1:
        _fail("after two set_calibration calls, expected 1 row")
    _ok("set_calibration is idempotent and applies updates")


def check_severity_override_validation() -> None:
    raised = False
    try:
        calibration.set_calibration(
            tenant_id=TENANT,
            pack="finserv",
            rule_id=RULE + "-bogus",
            severity_override="catastrophic",  # not a valid Severity
        )
    except ValueError:
        raised = True
    if not raised:
        _fail("set_calibration accepted an invalid severity_override")
    _ok("set_calibration rejects unknown severity_override values")


def check_detached_reads_safe() -> None:
    """Rows returned by service helpers must be safe to read post-session."""
    assignments = calibration.list_assignments(TENANT)
    if not assignments:
        _fail("list_assignments returned empty after assign_pack")
    a = assignments[0]
    # Touch every column — if expunge() didn't fire, this will raise
    # DetachedInstanceError or stale-data warnings.
    _ = (
        a.id,
        a.tenant_id,
        a.vertical_pack_id,
        a.enabled,
        a.assigned_by,
        a.notes,
        a.created_at,
        a.updated_at,
    )
    cals = calibration.list_calibrations(TENANT)
    if not cals:
        _fail("list_calibrations returned empty after set_calibration")
    c = cals[0]
    _ = (
        c.id,
        c.tenant_id,
        c.vertical_pack_id,
        c.rule_id,
        c.enabled,
        c.severity_override,
        c.baseline,
        c.notes,
        c.created_at,
        c.updated_at,
    )
    _ok("list_assignments and list_calibrations return detached, readable rows")


def check_delete_paths() -> None:
    assert calibration.delete_calibration(tenant_id=TENANT, rule_id=RULE) is True
    if calibration.get_calibration(tenant_id=TENANT, rule_id=RULE) is not None:
        _fail("delete_calibration didn't remove the row")
    assert calibration.delete_calibration(tenant_id=TENANT, rule_id=RULE) is False
    _ok("delete_calibration is idempotent (True then False)")

    assert calibration.unassign_pack(tenant_id=TENANT, pack="finserv") is True
    if calibration.list_assignments(TENANT):
        _fail("unassign_pack didn't remove the row")
    assert calibration.unassign_pack(tenant_id=TENANT, pack="finserv") is False
    _ok("unassign_pack is idempotent (True then False)")


def _pack_id(slug: str) -> int:
    with session_scope() as session:
        row = session.exec(
            select(VerticalPack).where(VerticalPack.slug == slug)
        ).first()
        if row is None:
            _fail(f"pack {slug!r} not in catalog — registry.reload_registry() didn't run")
        return row.id  # type: ignore[union-attr]


def main() -> None:
    init_db()
    _ok(f"isolated DB initialized at {DB_PATH}")

    registry.reload_registry()
    _ok("registry reconciled with disk")

    check_tables_exist()
    check_unique_constraints_declared()
    check_assignment_unique_enforced()
    check_calibration_unique_enforced()
    check_calibration_service_upsert_is_idempotent()
    check_severity_override_validation()
    check_detached_reads_safe()
    check_delete_paths()

    print("PASS detection_packs models smoke test")


if __name__ == "__main__":
    main()
