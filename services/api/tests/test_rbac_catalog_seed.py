"""Pin the seeded RBAC catalog: migration 092 and rbac_catalog.py agree.

``app.core.rbac_catalog`` and ``migrations/092_rbac_catalog_seed.sql`` carry
the same role/permission vocabulary in two places by design (the migration
seeds the primary tenant at deploy time; the module seeds other tenants at
runtime). This test is the pin that stops them drifting: the permission
names, the system role names, and every role→grant set must match exactly.

Static-only test — no database, no FastAPI app. Runs under plain pytest.
"""

from __future__ import annotations

import re
from pathlib import Path

from app.core.rbac_catalog import (
    PERMISSIONS,
    ROLE_GRANTS,
    SYSTEM_ROLE_LABELS,
    SYSTEM_ROLES,
)

MIGRATIONS_DIR = Path(__file__).resolve().parents[1] / "migrations"
MIGRATION = MIGRATIONS_DIR / "092_rbac_catalog_seed.sql"


def _migration_sql() -> str:
    return MIGRATION.read_text(encoding="utf-8")


#: Rows a migration seeds that ``rbac_catalog.PERMISSIONS`` deliberately
#: does not claim, each with the reason. An entry here is a finding, not an
#: exception: the row exists in every deployment's ``permissions`` table and
#: is enforced by nothing.
#:
#: Widening this test from one migration to all of them is what found it.
#: Reconciling it is a product decision — delete the row, or give the verb a
#: route — and absorbing it silently into the module's vocabulary would have
#: made the catalog claim a permission the product does not enforce.
PRE_CATALOG_ORPHANS: dict[str, str] = {
    "playbooks:delete": (
        "seeded by 003_rbac.sql, before app/core/rbac_catalog.py existed. No route in the "
        "tree enforces it, so the row is catalog-only. Recorded rather than adopted."
    ),
}


def _seeding_migrations() -> list[str]:
    """Every migration that seeds the permission catalog, oldest first.

    092 has already run on every deployment and the runner tracks applied
    files, so a permission added to the module can only reach an existing
    deployment through a *new* migration. Pinning against 092 alone would
    make the only correct way to add one fail this test, and the tempting
    fix — editing an applied migration — seeds the row on fresh installs
    and on nobody else.

    Derived from the tree rather than from a list, so the next addition
    does not have to remember this function exists.
    """
    seeding = [
        sql for sql in (p.read_text(encoding="utf-8") for p in sorted(MIGRATIONS_DIR.glob("*.sql"))) if "INSERT INTO permissions" in sql
    ]
    assert seeding, "no migration seeds the permission catalog, so the pin below would be vacuous"
    return seeding


def test_migration_exists() -> None:
    assert MIGRATION.exists(), f"missing migration: {MIGRATION}"


def _migration_permission_rows(sql: str) -> set[str]:
    """Names from the `INSERT INTO permissions ... VALUES (...)` block —
    the first element of each ('name', 'description', 'category') tuple."""
    block = sql.split("INSERT INTO permissions", 1)[1].split(";", 1)[0]
    return set(re.findall(r"\(\s*'([^']+)'\s*,", block))


def test_permission_names_pinned() -> None:
    """The permission rows the migrations insert must exactly equal the
    module's PERMISSIONS vocabulary."""
    in_migration: set[str] = set()
    for sql in _seeding_migrations():
        in_migration |= _migration_permission_rows(sql)
    in_module = {name for name, _desc, _cat in PERMISSIONS}

    assert in_migration - in_module == set(PRE_CATALOG_ORPHANS), (
        "permission vocabulary drifted; a migration seeds a permission the module does not declare: "
        f"{sorted((in_migration - in_module) - set(PRE_CATALOG_ORPHANS))}. "
        f"Stale orphan entries (seeded nowhere any more): {sorted(set(PRE_CATALOG_ORPHANS) - in_migration)}"
    )
    assert not in_module - in_migration, (
        "the module declares a permission no migration seeds, so an existing deployment's catalog "
        f"has no row for it and the console renders it blank: {sorted(in_module - in_migration)}"
    )


def test_system_role_names_pinned() -> None:
    sql = _migration_sql()
    module_roles = {name for name, _desc in SYSTEM_ROLES}
    assert {"viewer", "infosec", "admin"} == module_roles
    for role in module_roles:
        assert re.search(rf"r\.name\s*=\s*'{role}'", sql) or f"'{role}'" in sql, f"role '{role}' not referenced in migration 092"


def test_role_grants_pinned() -> None:
    """The migrations' inline viewer/infosec IN-lists must equal the
    module's ROLE_GRANTS sets; admin is the wildcard in both.

    Unioned across migrations for the same reason the permission names
    are: a grant added to the module reaches an existing deployment only
    through a new file.
    """
    assert ROLE_GRANTS["admin"] == frozenset({"*"}), "admin wildcard grant drifted"
    assert "'admin' AND p.name = '*'" in _migration_sql(), "migration no longer grants admin the wildcard"

    for role in ("viewer", "infosec"):
        in_migration: set[str] = set()
        for sql in _seeding_migrations():
            for block in re.findall(
                rf"r\.name\s*=\s*'{role}'\s+AND\s+p\.name\s+IN\s*\((.*?)\)\s*\)",
                sql,
                re.DOTALL,
            ):
                in_migration |= set(re.findall(r"'([a-z_]+:[a-z_]+|\*)'", block))
        assert in_migration, f"could not locate any grant IN-list for role '{role}'"
        in_module = set(ROLE_GRANTS[role])
        assert in_migration == in_module, (
            f"grants drifted for role '{role}': "
            f"only-in-migration={sorted(in_migration - in_module)}, "
            f"only-in-module={sorted(in_module - in_migration)}"
        )


def test_labels_pinned() -> None:
    assert set(SYSTEM_ROLE_LABELS) == {name for name, _desc in SYSTEM_ROLES}
