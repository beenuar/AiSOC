#!/usr/bin/env python3
"""Fail if an RLS policy would make a cross-tenant worker silently see nothing.

The arm this is about
---------------------
Every policy in this schema is written::

    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)

The second clause is not decoration. Ingest, fusion, the retention purge, the
hunt scheduler's sweep and tenant deletion all read across every tenant on a
connection that never binds one, and the ``IS NULL`` arm is what lets them.
Drop it from one policy and that table quietly returns zero rows to those
workers — no error, no log line, just a purge that purges nothing and a
scheduler that fires nothing.

That mattered less while the services connected as a superuser, because a
superuser ignores policies entirely. ``061_runtime_app_role.sql`` moves them
onto a role the policies apply to, which makes the arm load-bearing in
production rather than in theory. **A worker that silently stops seeing data is
a worse failure than the bypass that change closes**, so the arm is now a gate.

The second bug class, kept closed
---------------------------------
``060_rls_coverage.sql`` repaired seven policies that could never engage: five
read ``app.tenant_id`` or ``app.current_tenant`` — GUCs no code path sets, so
they returned zero rows forever — and two called ``current_setting`` without
``missing_ok``, so an unbound session raised ``unrecognized configuration
parameter`` instead of returning anything. Both are invisible behind a
superuser. ``tests/isolation/test_postgres_rls.py`` catches them in a live
database; this catches them in the four schema chains that live database never
sees, because CI applies only the API chain.

Supersession is followed, not ignored
-------------------------------------
The broken definitions are still in the tree — 005, 007, 024 and 049 contain
them, and 060 drops and recreates each one. A scanner that read every
``CREATE POLICY`` in the repository would report seven findings that were
already fixed, and would then be silenced with an ignore list that outlives
its reason. So the chain is replayed in order: ``DROP POLICY`` removes an
entry, ``CREATE POLICY`` adds one, and only the surviving set is judged.

Both directions
---------------
* forward — a live policy with no fail-open arm fails.
* reverse — a live policy reading a GUC nothing sets, or omitting
  ``missing_ok``, fails. Same class from the other side: one returns nothing
  to a worker, the other returns nothing to a tenant.
* reverse — a schema file that enables row-level security but from which no
  policy could be parsed fails as a **blind spot**. The failure mode of a
  scanner is silence.
* reverse — a table with a policy but no ``FORCE`` fails: without it the owner
  walks past, and the owner is the role that runs migrations.

Empty input is a failure. A run that parsed no schema file has verified
nothing, and a probe recently found five wired gates reporting OK against an
empty repository.

Checked against a real database
-------------------------------
The surviving set this produces for the API chain was compared against
``pg_policies`` on a ``postgres:16`` with that chain applied: 84 here, 82
there, and the difference is fully accounted for. ``002_rls.sql`` guards two
policies behind ``IF EXISTS (SELECT 1 FROM information_schema.tables …)``, and
neither table existed when 002 ran — ``playbooks`` is never created by any
migration, and ``audit_log`` arrives in 004 and gets its policy there under a
different name. A text replay cannot evaluate a runtime condition, so the
static set is a **superset** of the live one. That is the safe direction: it
judges the shape of a policy that may not exist, rather than missing one that
does. ``tests/isolation/test_postgres_rls.py`` is what checks the live set.
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

# `scripts/` is on sys.path when this file is run as a program, but not when a
# test loads it by path with importlib. gate_toolkit sits beside it either way.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_main  # noqa: E402

#: Where the five schema chains live. Same three globs the predicate gate uses,
#: derived from the tree rather than listed, so a sixth chain is picked up by
#: existing somewhere conventional rather than by being added here.
SCHEMA_GLOBS: tuple[str, ...] = (
    "services/*/migrations/*.sql",
    "services/*/alembic/versions/*.py",
    "services/*/app/db/versions/*.py",
)

#: The only session variable any policy may read. ``002_rls.sql`` defines
#: ``current_tenant_id()`` over it and every binding path in the tree sets it.
CANONICAL_GUC = "app.current_tenant_id"

#: ``CREATE POLICY name ON table ... ;`` — the body runs to the statement
#: terminator. Quotes may be doubled because four of these are built inside an
#: ``EXECUTE format(...)``.
_CREATE_RE = re.compile(r"CREATE\s+POLICY\s+\"?(?P<name>\w+)\"?\s+ON\s+\"?(?P<table>[\w.]+)\"?(?P<body>.*?);", re.S | re.I)
_DROP_RE = re.compile(r"DROP\s+POLICY\s+(?:IF\s+EXISTS\s+)?\"?(?P<name>\w+)\"?\s+ON\s+\"?(?P<table>[\w.]+)\"?", re.I)
_ENABLE_RE = re.compile(r"ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?\"?(?P<table>[\w.]+)\"?\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY", re.I)
_FORCE_RE = re.compile(r"ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?\"?(?P<table>[\w.]+)\"?\s+FORCE\s+ROW\s+LEVEL\s+SECURITY", re.I)
_NOFORCE_RE = re.compile(r"ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?\"?(?P<table>[\w.]+)\"?\s+NO\s+FORCE\s+ROW\s+LEVEL\s+SECURITY", re.I)
_DISABLE_RE = re.compile(r"ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?\"?(?P<table>[\w.]+)\"?\s+DISABLE\s+ROW\s+LEVEL\s+SECURITY", re.I)

#: ``current_setting('name'[, true])``, tolerating the doubled quotes that
#: appear inside a dollar-quoted ``EXECUTE format(...)``.
_SETTING_RE = re.compile(r"current_setting\(\s*'{1,2}(?P<name>[^']+)'{1,2}\s*(?P<rest>[^)]*)\)", re.I)

#: The helper 002_rls.sql defines. It reads the canonical GUC and returns NULL
#: when unset, so a policy calling it inherits both properties.
_HELPER = "current_tenant_id()"


@dataclass
class Policy:
    table: str
    name: str
    body: str
    source: str


@dataclass
class Schema:
    policies: dict[tuple[str, str], Policy] = field(default_factory=dict)
    forced: set[str] = field(default_factory=set)
    rls_tables: set[str] = field(default_factory=set)
    files: list[str] = field(default_factory=list)
    blind_spots: list[str] = field(default_factory=list)


def _bare(table: str) -> str:
    return table.split(".")[-1].strip('"')


def strip_comments(sql: str) -> str:
    """Drop ``--`` and ``/* */`` comments, leaving string literals alone.

    Every migration in this chain documents itself, and 060 in particular
    spells the canonical predicate out in prose and names the policies it
    replaces. Parsed as SQL, that prose becomes statements: a fixture with a
    commented-out ``CREATE POLICY`` produced a finding against a table that
    does not exist, and a commented-out ``DROP POLICY`` would have deleted a
    real policy from the replay — a comment silently switching the gate off
    for one table.

    Found by giving the parser a file whose comments disagreed with its SQL
    and reading what it *credited*, which was two policies where there is one.
    """
    out: list[str] = []
    i = 0
    n = len(sql)
    while i < n:
        ch = sql[i]
        if ch == "'":
            # A string literal, including the doubled-quote escape.
            out.append(ch)
            i += 1
            while i < n:
                out.append(sql[i])
                if sql[i] == "'":
                    if i + 1 < n and sql[i + 1] == "'":
                        out.append(sql[i + 1])
                        i += 2
                        continue
                    i += 1
                    break
                i += 1
            continue
        if ch == "-" and sql.startswith("--", i):
            while i < n and sql[i] != "\n":
                i += 1
            continue
        if ch == "/" and sql.startswith("/*", i):
            end = sql.find("*/", i + 2)
            i = n if end == -1 else end + 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def sql_view(name: str, text: str) -> str:
    """The SQL a schema file contains, whatever language wraps it.

    ``.sql`` files are SQL. The four alembic chains are Python that passes SQL
    to ``op.execute`` as implicitly-concatenated string literals across several
    source lines and with **no trailing semicolon** — so a statement regex
    anchored on ``;`` matched none of them and the four revisions covering
    twelve tenant-scoped tables were read as containing no policy at all.

    That was caught by this gate's own blind-spot clause rather than by review,
    which is the argument for having one. Python folds adjacent literals into a
    single constant at parse time, so walking the AST recovers each statement
    whole; they are re-emitted in source order with terminators so the replay
    below sees a normal chain.
    """
    if not name.endswith(".py"):
        return strip_comments(text)
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return text
    # Only ``upgrade()``. An alembic revision's ``downgrade()`` is a mirror
    # image — every CREATE POLICY has a DROP POLICY facing it — so replaying
    # both in source order cancels the file out to nothing. The first version
    # of this function did exactly that, and the give-away was that removing a
    # blind spot over four files left the policy count unchanged: the gate
    # started reading them and immediately un-read them. Counting what a parser
    # *credits* is how that surfaced; the failure list looked fine.
    scope: ast.AST = tree
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == "upgrade":
            scope = node
            break

    # (line, column, text) rather than the nodes themselves: ``Constant.value``
    # is a union over every literal type, so joining the nodes' values needs a
    # narrowing the comprehension has already done but the type does not carry.
    literals: list[tuple[int, int, str]] = [
        (node.lineno, node.col_offset, node.value)
        for node in ast.walk(scope)
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value.strip()
    ]
    literals.sort()
    return strip_comments(";\n".join(text for _line, _col, text in literals) + ";")


def replay(files: list[tuple[str, str]]) -> Schema:
    """Apply the chain in order and return the surviving policy set."""
    schema = Schema()
    for name, raw in files:
        schema.files.append(name)
        text = sql_view(name, raw)
        enabled = {_bare(m.group("table")) for m in _ENABLE_RE.finditer(text)}
        creates = list(_CREATE_RE.finditer(text))
        schema.rls_tables |= enabled

        # A file that switches RLS on but from which no policy parsed has not
        # been read, whatever it says. Enabling without a policy is also a
        # deny-all, so it is worth a human either way.
        if enabled and not creates and "CREATE POLICY" in text.upper():
            schema.blind_spots.append(name)

        for drop in _DROP_RE.finditer(text):
            schema.policies.pop((_bare(drop.group("table")), drop.group("name")), None)
        for create in creates:
            table = _bare(create.group("table"))
            schema.policies[(table, create.group("name"))] = Policy(
                table=table, name=create.group("name"), body=create.group("body"), source=name
            )
        for force in _FORCE_RE.finditer(text):
            schema.forced.add(_bare(force.group("table")))
        for unforce in _NOFORCE_RE.finditer(text):
            schema.forced.discard(_bare(unforce.group("table")))
        for disable in _DISABLE_RE.finditer(text):
            table = _bare(disable.group("table"))
            schema.rls_tables.discard(table)
            for key in [k for k in schema.policies if k[0] == table]:
                schema.policies.pop(key)
    return schema


def judge(schema: Schema) -> list[str]:
    """Both directions over the surviving policies."""
    problems: list[str] = []

    for (table, name), policy in sorted(schema.policies.items()):
        body = policy.body
        where = f"{policy.source}: {table}.{name}"

        settings = list(_SETTING_RE.finditer(body))
        uses_helper = _HELPER.lower() in body.lower()

        for setting in settings:
            guc = setting.group("name")
            if guc != CANONICAL_GUC:
                problems.append(
                    f"{where} reads {guc!r}; nothing in the tree sets that, so the policy returns zero rows forever"
                )
            elif "true" not in setting.group("rest").lower():
                problems.append(
                    f"{where} calls current_setting({guc!r}) without missing_ok, so an unbound session raises "
                    "'unrecognized configuration parameter' instead of returning rows"
                )

        if not settings and not uses_helper:
            problems.append(
                f"{where} references neither current_tenant_id() nor current_setting({CANONICAL_GUC!r}); "
                "the gate cannot tell what it is scoped by"
            )
            continue

        # The forward direction: the fail-open arm.
        if not re.search(r"\bIS\s+NULL\b", body, re.I):
            problems.append(
                f"{where} has no 'OR <tenant context> IS NULL' arm. Ingest, fusion, the retention purge and the "
                "schedulers read this table on a connection that binds no tenant; without the arm they see zero "
                "rows and report success."
            )

    for table in sorted(schema.rls_tables):
        if table not in schema.forced:
            problems.append(
                f"{table}: row-level security is enabled but not FORCEd, so the table owner — which is the role "
                "that runs migrations — walks straight past the policy"
            )
        if not any(t == table for t, _ in schema.policies):
            problems.append(f"{table}: row-level security is enabled with no surviving policy, which denies every row")

    return problems


# ---------------------------------------------------------------------------
# Self-test — runs first, every time
# ---------------------------------------------------------------------------

_GOOD = (
    "ALTER TABLE t ENABLE ROW LEVEL SECURITY;\n"
    "ALTER TABLE t FORCE ROW LEVEL SECURITY;\n"
    "CREATE POLICY t_tenant ON t USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);"
)

_FIXTURES: tuple[tuple[str, str, bool], ...] = (
    ("the canonical shape passes", _GOOD, True),
    (
        "a commented-out policy is prose, not a statement",
        "-- CREATE POLICY ghost_tenant ON ghost USING (tenant_id = current_tenant_id());\n"
        "/* DROP POLICY IF EXISTS t_tenant ON t; */\n" + _GOOD,
        True,
    ),
    (
        "no fail-open arm — cross-tenant workers would see nothing",
        "ALTER TABLE t ENABLE ROW LEVEL SECURITY;\nALTER TABLE t FORCE ROW LEVEL SECURITY;\n"
        "CREATE POLICY t_tenant ON t USING (tenant_id = current_tenant_id());",
        False,
    ),
    (
        "a GUC nothing sets",
        "ALTER TABLE t ENABLE ROW LEVEL SECURITY;\nALTER TABLE t FORCE ROW LEVEL SECURITY;\n"
        "CREATE POLICY t_tenant ON t USING (tenant_id = current_setting('app.tenant_id', true)::uuid "
        "OR current_setting('app.tenant_id', true) IS NULL);",
        False,
    ),
    (
        "current_setting without missing_ok raises on an unbound session",
        "ALTER TABLE t ENABLE ROW LEVEL SECURITY;\nALTER TABLE t FORCE ROW LEVEL SECURITY;\n"
        "CREATE POLICY t_tenant ON t USING (tenant_id = current_setting('app.current_tenant_id')::uuid "
        "OR current_setting('app.current_tenant_id')::uuid IS NULL);",
        False,
    ),
    (
        "ENABLE without FORCE lets the owner past",
        "ALTER TABLE t ENABLE ROW LEVEL SECURITY;\n"
        "CREATE POLICY t_tenant ON t USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);",
        False,
    ),
    (
        "ENABLE with no policy denies every row",
        "ALTER TABLE t ENABLE ROW LEVEL SECURITY;\nALTER TABLE t FORCE ROW LEVEL SECURITY;",
        False,
    ),
    (
        "a later migration repairing an earlier one is not a finding",
        "ALTER TABLE t ENABLE ROW LEVEL SECURITY;\nALTER TABLE t FORCE ROW LEVEL SECURITY;\n"
        "CREATE POLICY t_old ON t USING (tenant_id = current_setting('app.tenant_id', true)::uuid);\n"
        "DROP POLICY IF EXISTS t_old ON t;\n"
        "CREATE POLICY t_tenant ON t USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);",
        False,  # still fails: the *fixture* is one file, and the repair is judged — see below
    ),
    (
        "doubled quotes inside EXECUTE format() are read, not skipped",
        "ALTER TABLE t ENABLE ROW LEVEL SECURITY;\nALTER TABLE t FORCE ROW LEVEL SECURITY;\n"
        "EXECUTE 'CREATE POLICY t_tenant ON t USING (tenant_id = current_setting(''app.tenant_id'', true)::uuid)';",
        False,
    ),
)


#: The alembic shape, as a Python source fixture. Kept separate from _FIXTURES
#: because it exercises :func:`sql_view` rather than :func:`judge`, and because
#: the bug it pins had two halves: not reading the file at all, then reading it
#: and its ``downgrade()`` mirror so the two cancelled.
_ALEMBIC_GOOD = '''
"""A revision docstring, which is a string constant and must not be read as SQL."""

def upgrade():
    op.execute("ALTER TABLE t ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE t FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY t_tenant ON t "
        "USING (tenant_id = (NULLIF(current_setting('app.current_tenant_id', true), ''))::uuid "
        "OR (NULLIF(current_setting('app.current_tenant_id', true), '')) IS NULL)"
    )

def downgrade():
    op.execute("DROP POLICY IF EXISTS t_tenant ON t")
    op.execute("ALTER TABLE t DISABLE ROW LEVEL SECURITY")
'''

_ALEMBIC_BAD = _ALEMBIC_GOOD.replace(
    "OR (NULLIF(current_setting('app.current_tenant_id', true), '')) IS NULL)", ")"
)


def self_test() -> list[str]:
    failures: list[str] = []

    # An alembic revision must be read, must yield its policy, and must not be
    # cancelled out by its own downgrade().
    good = replay([("0002_tenant_rls.py", _ALEMBIC_GOOD)])
    if not good.policies:
        failures.append("an alembic revision yielded no policy — sql_view is not reading op.execute() literals")
    if judge(good):
        failures.append(f"a well-formed alembic revision was rejected: {judge(good)[0]}")
    if not judge(replay([("0002_tenant_rls.py", _ALEMBIC_BAD)])):
        failures.append("an alembic revision missing the fail-open arm was accepted")
    for label, sql, should_pass in _FIXTURES:
        if label.startswith("a later migration"):
            continue  # handled by the two-file case below
        problems = judge(replay([(f"<self-test: {label}>", sql)]))
        passed = not problems
        if passed is not should_pass:
            failures.append(
                f"{label}: judge {'accepted' if passed else 'rejected (' + problems[0] + ')'}, "
                f"expected it to {'accept' if should_pass else 'reject'}"
            )

    # Supersession across two files, which is the real shape in this tree.
    broken = (
        "ALTER TABLE t ENABLE ROW LEVEL SECURITY;\nALTER TABLE t FORCE ROW LEVEL SECURITY;\n"
        "CREATE POLICY t_old ON t USING (tenant_id = current_setting('app.tenant_id', true)::uuid);"
    )
    repair = "DROP POLICY IF EXISTS t_old ON t;\n" + _GOOD
    if judge(replay([("007_broken.sql", broken)])) == []:
        failures.append("the pre-repair definition was accepted, so the chain replay proves nothing")
    if judge(replay([("007_broken.sql", broken), ("060_repair.sql", repair)])):
        failures.append("a repaired policy is still reported, so the chain replay does not follow DROP POLICY")

    # Empty input must not pass.
    if not _empty_findings(Schema()):
        failures.append("an empty schema produced no finding — the gate would pass over an empty tree")
    if _empty_findings(replay([("x.sql", _GOOD)])):
        failures.append("a populated schema was reported as empty — the empty-input rule is over-tight")
    return failures


def _empty_findings(schema: Schema) -> list[str]:
    if not schema.files:
        return [f"no schema file matched any of the {len(SCHEMA_GLOBS)} globs — nothing was verified"]
    if not schema.policies:
        return [f"{len(schema.files)} schema files were read and not one policy parsed out of them — the parser is broken"]
    return []


def collect(root: Path) -> list[tuple[str, str]]:
    """Schema files in chain order: per directory, sorted by filename."""
    paths: list[Path] = []
    for pattern in SCHEMA_GLOBS:
        paths.extend(sorted(root.glob(pattern)))
    seen: set[Path] = set()
    out: list[tuple[str, str]] = []
    for path in sorted(paths, key=lambda p: (str(p.parent), p.name)):
        if path in seen:
            continue
        seen.add(path)
        out.append((str(path.relative_to(root)), path.read_text(encoding="utf-8", errors="ignore")))
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", type=Path, default=None)
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="prove the judge still discriminates and that the gate refuses an empty tree, then stop",
    )
    args = parser.parse_args(argv)

    failures = self_test()
    if args.self_test:
        return self_test_main(
            Path(__file__).name,
            args=[],
            extra=[
                (
                    f"{len(_FIXTURES) - 1} shape fixtures + alembic shape + supersession + 2 empty-input cases",
                    not failures,
                )
            ]
            + [(f"self-test detail: {f}", False) for f in failures],
        )
    if failures:
        print("check_rls_policy_shape: SELF-TEST FAILED — the gate cannot be trusted this run")
        for failure in failures:
            print(f"  [FAIL] {failure}")
        return 1
    print(f"check_rls_policy_shape: self-test OK ({len(_FIXTURES) - 1} shape fixtures + supersession + 2 empty-input cases)")

    root = (args.root or repo_root()).resolve()
    files = collect(root)
    schema = replay(files)
    problems = judge(schema) + _empty_findings(schema)
    problems += [f"{name}: enables row-level security but no policy could be parsed out of it" for name in schema.blind_spots]

    chains = sorted({str(Path(name).parent) for name in schema.files})
    print(f"check_rls_policy_shape: replayed {len(schema.files)} schema files under {root}")
    print(f"  chains: {', '.join(chains)}")
    print(f"  {len(schema.policies)} surviving policies over {len({t for t, _ in schema.policies})} tables; {len(schema.forced)} FORCEd")

    if problems:
        print(f"\nFAIL: {len(problems)} finding(s)")
        for problem in problems:
            print(f"  [FAIL] {problem}")
        return 1
    print("OK: every surviving policy admits an unbound session and reads the one GUC the tree sets.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
