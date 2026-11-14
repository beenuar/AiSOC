"""The six `mssp_*` tables that had no row-level security now have it.

`mssp_tenant_metrics` carried a policy; the other six did not, so the only
thing between one MSSP's portfolio and another's was the query layer. That
is not hypothetical here: `POST /mssp/overrides` with `action: "exclude"`
wrote a caller-supplied child tenant id onto a row the effective-rule
resolver then read back filtered on the *victim's* tenant id, so any
authenticated user could silently delete a critical detection from another
tenant. The route guard was fixed; this is the layer that would have
contained it had the guard been wrong.

Two things make these rows unlike the rest of the schema.

They join **two** tenants — the parent that manages and the child that is
managed — and both have a legitimate read. A policy naming only the parent
would hide from a customer the overrides applied to their own detections,
which is the transparency the adoption flow was rebuilt around.

And the obvious way to write that produced **mutually recursive policies**:
a pack visible to anyone with an assignment, an assignment visible to the
owning pack's parent. Postgres answers `infinite recursion detected in
policy for relation "mssp_rule_packs"` on the first SELECT, and no static
check caught it — `check_rls_policy_shape.py` passed, because the shape was
right. It took running the policies against a real Postgres with two seeded
MSSPs to see at all.

The structural cases below run without a database. The isolation itself is
measured by `tests/isolation/`, which runs against a container; recorded
here is what that measurement showed:

    two rows per table, and each of four tenants saw exactly its own one,
    an unrelated fifth saw zero in all six, and the composite foreign key
    refused an assignment claiming a parent that does not own the pack.
"""

from __future__ import annotations

import pathlib
import re

import pytest

MIGRATION = pathlib.Path(__file__).resolve().parents[1] / "migrations" / "077_mssp_row_level_security.sql"

#: Every `mssp_*` table that holds tenant-scoped rows.
TABLES = (
    "mssp_delegations",
    "mssp_rule_overrides",
    "mssp_tenant_notes",
    "mssp_rule_packs",
    "mssp_rule_pack_assignments",
    "mssp_rule_pack_rules",
)


@pytest.fixture(scope="module")
def sql() -> str:
    return MIGRATION.read_text(encoding="utf-8")


@pytest.mark.parametrize("table", TABLES)
def test_the_table_has_forced_row_level_security(sql: str, table: str) -> None:
    assert f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY" in sql
    # FORCE matters: without it the table owner bypasses the policy, and
    # migrations run as the owner.
    assert f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY" in sql


@pytest.mark.parametrize("table", TABLES)
def test_the_table_has_exactly_one_policy(sql: str, table: str) -> None:
    created = re.findall(rf"CREATE POLICY (\w+) ON {table}\b", sql)
    assert len(created) == 1, f"{table} has {len(created)} policies: {created}"


def test_no_policy_is_mutually_recursive(sql: str) -> None:
    """The defect a real database found and the shape gate did not.

    Builds the graph of which policy reads which table and looks for a
    cycle. `mssp_rule_packs` may read `mssp_rule_pack_assignments`; the
    reverse would close the loop and make every SELECT on either raise.
    """
    reads: dict[str, set[str]] = {}
    for match in re.finditer(r"CREATE POLICY \w+ ON (\w+)\s*\n\s*USING \((.*?)\n    \);", sql, re.S):
        table, body = match.group(1), match.group(2)
        reads[table] = {t for t in TABLES if re.search(rf"\bFROM {t}\b", body)} - {table}

    assert reads, "no policies parsed; the regex no longer matches the migration"

    def reaches(start: str, target: str, seen: frozenset[str] = frozenset()) -> bool:
        if start in seen:
            return False
        for nxt in reads.get(start, ()):
            if nxt == target or reaches(nxt, target, seen | {start}):
                return True
        return False

    cycles = [t for t in reads if reaches(t, t)]
    assert not cycles, (
        f"policies on {cycles} read a table whose policy reads back into them. Postgres "
        "answers 'infinite recursion detected' on the first SELECT"
    )


def test_the_assignment_policy_needs_no_subquery(sql: str) -> None:
    """Because it is what breaks the cycle.

    If a future edit reintroduces an EXISTS here, the graph check above
    catches the cycle — but this says *why* the column exists, so the
    column is not deleted as redundant denormalisation.
    """
    policy = re.search(
        r"CREATE POLICY mssp_rule_pack_assignments_tenant ON mssp_rule_pack_assignments\s*\n\s*USING \((.*?)\n    \);",
        sql,
        re.S,
    )
    assert policy is not None
    assert "SELECT" not in policy.group(1).upper()
    assert "parent_tenant_id = current_tenant_id()" in policy.group(1)


def test_the_denormalised_parent_cannot_drift(sql: str) -> None:
    """A composite foreign key, not a trigger and not application code.

    `(pack_id, parent_tenant_id)` must exist in `mssp_rule_packs`, so a row
    naming the wrong parent cannot be inserted. Measured against a real
    Postgres: the insert is refused with
    `violates foreign key constraint "mssp_rule_pack_assignments_pack_parent_fk"`.
    """
    assert "ADD CONSTRAINT mssp_rule_packs_id_parent_key UNIQUE (id, parent_tenant_id)" in sql
    assert "FOREIGN KEY (pack_id, parent_tenant_id)" in sql
    assert "REFERENCES mssp_rule_packs (id, parent_tenant_id)" in sql


def test_existing_rows_are_backfilled_before_the_constraint(sql: str) -> None:
    """Or a deployment with assignments already in it cannot migrate."""
    backfill = sql.index("UPDATE mssp_rule_pack_assignments")
    not_null = sql.index("ALTER COLUMN parent_tenant_id SET NOT NULL")
    assert backfill < not_null, "the NOT NULL lands before the backfill that satisfies it"


def test_both_sides_of_the_relationship_can_read(sql: str) -> None:
    """A parent-only policy hides from a customer what is done to them.

    Asserted per table rather than globally, because getting this right on
    five of six is the failure mode: the one that is missed is invisible
    until a customer asks why a page is empty.
    """
    for table, parent, child in (
        ("mssp_delegations", "parent_tenant_id", "child_tenant_id"),
        ("mssp_rule_overrides", "parent_tenant_id", "child_tenant_id"),
        ("mssp_tenant_notes", "parent_id", "child_id"),
        ("mssp_rule_pack_assignments", "parent_tenant_id", "child_tenant_id"),
    ):
        policy = re.search(rf"CREATE POLICY \w+ ON {table}\s*\n\s*USING \((.*?)\n    \);", sql, re.S)
        assert policy is not None, f"no policy parsed for {table}"
        body = policy.group(1)
        assert f"{parent} = current_tenant_id()" in body, f"{table} hides the row from the parent"
        assert f"{child} = current_tenant_id()" in body, f"{table} hides the row from the child"


def test_the_subquerying_policies_grant_select_to_the_app_role(sql: str) -> None:
    """A policy subquery runs as the querying role.

    Without the grant the EXISTS raises a permission error rather than
    returning false — which fails closed, but sends an operator looking for
    a missing grant on the wrong table.
    """
    assert "GRANT SELECT ON mssp_rule_packs, mssp_rule_pack_assignments TO aisoc_app" in sql


def test_the_orm_model_carries_the_column() -> None:
    """Or every insert fails the NOT NULL the migration adds."""
    from app.models.mssp import MSSPRulePackAssignment

    assert "parent_tenant_id" in MSSPRulePackAssignment.__table__.columns
    assert not MSSPRulePackAssignment.__table__.columns["parent_tenant_id"].nullable


def test_the_handler_reads_the_parent_from_the_pack_not_the_request() -> None:
    """The foreign key would reject a forged parent anyway.

    Reading it from the already-ownership-checked pack means the rejection
    never has to happen, and a caller cannot probe which packs exist by
    watching which inserts are refused.
    """
    import inspect

    from app.api.v1.endpoints.mssp import assign_pack_to_child

    source = inspect.getsource(assign_pack_to_child)
    assert "parent_tenant_id=pack.parent_tenant_id" in source
    assert "parent_tenant_id=body." not in source
