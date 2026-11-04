#!/usr/bin/env python3
"""
Gate: no ORM column claims to be nullable where the database refuses NULL.

Why this exists
---------------
`tenants.mssp_role` has been ``NOT NULL DEFAULT 'standalone'`` since migration
012. The ORM declared it ``nullable=True`` with no default. Those two
statements look compatible and are not, because of one SQLAlchemy behaviour:

    a column the ORM believes is nullable is **named in the INSERT with an
    explicit NULL**, and a column named in an INSERT does not receive the
    column DEFAULT.

So the database's own default could never fire, and every caller that
constructed a ``Tenant`` without naming ``mssp_role`` got

    NotNullViolationError: null value in column "mssp_role" ...

On a brand-new database that is `pnpm aisoc:demo` failing its seed step
(issue #1693). It is not a seed bug: the seed is the first thing to insert a
tenant, so it is merely the first caller to find out.

The shape is worth gating rather than fixing once. Nothing in the tree
compares a model against the migration that creates its table, so the two
drift silently and the symptom appears at the first insert on a fresh
database — which is the one environment contributors and evaluators use and
maintainers rarely do.

What counts as a finding
------------------------
All three must hold, because each on its own is legitimate:

* the migrations declare the column ``NOT NULL`` — the database will refuse;
* the ORM declares it nullable — so SQLAlchemy sends an explicit NULL; and
* the ORM supplies neither ``default=`` nor ``server_default=`` — so nothing
  fills it in before the statement is built.

A nullable ORM column over a nullable database column is fine. A non-null
ORM column is fine whatever the database says — the ORM is then the stricter
of the two and inserts carry a value. An ORM default is fine, because the
value is supplied before the INSERT is built.

Why the DDL is parsed rather than read from a live database
-----------------------------------------------------------
`check_orm_migration_parity.py` already reads these migrations, and this
is deliberately not folded into it: its per-column store is
``(type_name, length)``, and threading a third axis through it changes a
signature `check_raw_sql_columns.py` imports. Two readers of one DDL is a
drift risk, so both are held to the same live schema by the mode below.

A gate that needs a container runs in one workflow; this one runs everywhere
the Python tests do. The cost is a parser, and a parser nobody checks is its
own defect — so ``--verify-against-dsn`` compares this module's reading of
the DDL against ``information_schema`` on a database with the real chain
applied, and fails if they disagree. That is how the four statement shapes
below were established rather than guessed.

Usage:
    python3 scripts/check_orm_nullability.py
    python3 scripts/check_orm_nullability.py --json
    python3 scripts/check_orm_nullability.py --self-test
    python3 scripts/check_orm_nullability.py --verify-against-dsn postgresql://...

Exit codes: 0 clean · 1 a model and its table disagree · 2 the gate could not
read its inputs (never reported as clean).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gate_toolkit import repo_root  # noqa: E402 — the path must be set first

#: Resolved through git, not from `__file__`. Two levels above this script is
#: whatever happens to be there, so a gate copied into a bare tree would read
#: the real repository and report it clean — the vacuous pass
#: `check_gate_contract.py` exists to refuse.
REPO_ROOT = repo_root()
MIGRATIONS = REPO_ROOT / "services" / "api" / "migrations"
API_ROOT = REPO_ROOT / "services" / "api"

#: Columns that are genuinely mismatched, each with the reason it is not
#: being corrected here and what would close it. This is a debt balance, not
#: a target: entries come out, they do not go in without a reason.
KNOWN: dict[tuple[str, str], str] = {
    ("detection_rules", "tenant_id"): (
        "NOT NULL in 001_init.sql and no migration drops it, while the ORM says "
        "nullable with the comment 'NULL = platform-wide rule' and three readers "
        "(mssp_rule_resolver, sigma_import, detection_catalogue) query `tenant_id "
        "IS NULL AND is_builtin`. Those queries cannot match a row, which is a "
        "known defect already worked around behaviourally — built-ins are read "
        "from the synced artefact and merged with stored tuning rather than "
        "seeded into Postgres. Correcting the declaration means retiring three "
        "dead predicates and belongs in that change, not this one. Returns to "
        "clean when the readers stop asking for a row the schema forbids."
    ),
}

# The four statement shapes that decide a column's nullability in this tree.
# Established by diffing this parser against `information_schema` on a
# database with every migration applied; see --verify-against-dsn.
#: One `ALTER TABLE <t> ...;` statement. The ADD COLUMN clauses inside are
#: found separately, because a single statement may carry several —
#: `ALTER TABLE tenants ADD COLUMN a ..., ADD COLUMN b ...;` is how
#: `tenants.mssp_role` is declared, and a pattern anchored on `ALTER TABLE`
#: sees only the first clause. This gate missed the very column it was
#: written for until the negative control said so.
_ALTER_TABLE_STMT = re.compile(
    r"ALTER\s+TABLE\s+(?:ONLY\s+)?(?:public\.)?\"?(\w+)\"?\b([^;]*);",
    re.I | re.S,
)
_ADD_COLUMN_CLAUSE = re.compile(
    r"ADD\s+COLUMN\s+(IF\s+NOT\s+EXISTS\s+)?\"?(\w+)\"?\b",
    re.I,
)
_SET_NOT_NULL = re.compile(
    r"ALTER\s+TABLE\s+(?:ONLY\s+)?(?:public\.)?\"?(\w+)\"?\s+"
    r"ALTER\s+(?:COLUMN\s+)?\"?(\w+)\"?\s+SET\s+NOT\s+NULL",
    re.I,
)
_DROP_NOT_NULL = re.compile(
    r"ALTER\s+TABLE\s+(?:ONLY\s+)?(?:public\.)?\"?(\w+)\"?\s+"
    r"ALTER\s+(?:COLUMN\s+)?\"?(\w+)\"?\s+DROP\s+NOT\s+NULL",
    re.I,
)
#: Only the header. The body is taken by scanning to the matching paren,
#: because a regex has to guess where that is: a non-greedy `\)` stops at the
#: first `NUMERIC(10, 2)`, and requiring a newline before it silently skips
#: every single-line `CREATE TABLE` — which the self-test's first case is.
_CREATE_TABLE_HEAD = re.compile(
    r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:public\.)?\"?(\w+)\"?\s*\(",
    re.I,
)
_DROP_TABLE = re.compile(r"DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:public\.)?\"?(\w+)\"?", re.I)

#: Clause keywords that end a column definition's type, so "NOT NULL" that
#: belongs to a later table constraint is not read as this column's.
_CONSTRAINT_START = re.compile(r"^\s*(PRIMARY\s+KEY|FOREIGN\s+KEY|UNIQUE|CHECK|CONSTRAINT|EXCLUDE)\b", re.I)


def _strip_sql_comments(sql: str) -> str:
    sql = re.sub(r"/\*.*?\*/", " ", sql, flags=re.S)
    return re.sub(r"--[^\n]*", " ", sql)


def _split_columns(body: str) -> list[str]:
    """Top-level comma-separated parts of a CREATE TABLE body."""
    parts: list[str] = []
    cur: list[str] = []
    depth = 0
    for ch in body:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
            continue
        cur.append(ch)
    if cur:
        parts.append("".join(cur))
    return parts


def parse_not_null(migrations_dir: Path) -> dict[tuple[str, str], bool]:
    """``{(table, column): refuses_null}`` as the migration chain leaves it."""
    state: dict[tuple[str, str], bool] = {}
    files = sorted(migrations_dir.glob("*.sql"), key=lambda p: p.name)
    if not files:
        print(f"ERROR: no migrations under {migrations_dir} — refusing to report a result", file=sys.stderr)
        raise SystemExit(2)

    for path in files:
        sql = _strip_sql_comments(path.read_text(encoding="utf-8"))

        for match in _CREATE_TABLE_HEAD.finditer(sql):
            table = match.group(1)
            depth, i = 1, match.end()
            while i < len(sql) and depth:
                if sql[i] == "(":
                    depth += 1
                elif sql[i] == ")":
                    depth -= 1
                i += 1
            if depth:
                continue  # unterminated; another statement shape will decide it
            body = sql[match.end() : i - 1]
            pk_columns: set[str] = set()
            for part in _split_columns(body):
                part = part.strip()
                if not part:
                    continue
                if _CONSTRAINT_START.match(part):
                    # A table-level `PRIMARY KEY (a, b)` makes a and b NOT
                    # NULL, which `information_schema` reports and the DDL
                    # never spells out. Verifying the parse against a live
                    # schema is what surfaced this; 40-odd `id` columns read
                    # as nullable without it.
                    pk = re.search(r"PRIMARY\s+KEY\s*\(([^)]*)\)", part, re.I)
                    if pk:
                        pk_columns.update(c.strip().strip('"').lower() for c in pk.group(1).split(","))
                    continue
                name = re.match(r'"?(\w+)"?', part)
                if not name:
                    continue
                column = name.group(1).lower()
                inline_pk = re.search(r"\bPRIMARY\s+KEY\b", part, re.I) is not None
                state[(table.lower(), column)] = inline_pk or bool(re.search(r"\bNOT\s+NULL\b", part, re.I))
            for column in pk_columns:
                state[(table.lower(), column)] = True

        for table, stmt in _ALTER_TABLE_STMT.findall(sql):
            clauses = list(_ADD_COLUMN_CLAUSE.finditer(stmt))
            for i, clause in enumerate(clauses):
                if_not_exists, column = clause.group(1), clause.group(2)
                # This clause runs to the next ADD COLUMN, or to the end of
                # the statement — so a trailing CHECK or DEFAULT belongs to
                # it and a sibling clause's NOT NULL does not.
                stop = clauses[i + 1].start() if i + 1 < len(clauses) else len(stmt)
                body = stmt[clause.end() : stop]
                key = (table.lower(), column.lower())
                if if_not_exists and key in state:
                    # `ADD COLUMN IF NOT EXISTS` on a column that already
                    # exists does nothing — it does not re-type it and does
                    # not relax its constraints. Treating it as a
                    # redefinition is how this parser read
                    # `detection_rules.status` as nullable: migration 023
                    # adds it NOT NULL, and 046 re-adds it without, which
                    # never runs. Caught by --verify-against-dsn.
                    continue
                state[key] = bool(re.search(r"\bNOT\s+NULL\b", body, re.I))

        for table, column in _SET_NOT_NULL.findall(sql):
            state[(table.lower(), column.lower())] = True
        for table, column in _DROP_NOT_NULL.findall(sql):
            state[(table.lower(), column.lower())] = False
        for table in _DROP_TABLE.findall(sql):
            for key in [k for k in state if k[0] == table.lower()]:
                del state[key]

    return state


def orm_columns() -> list[tuple[str, str, bool, bool]]:
    """``(table, column, orm_nullable, has_default)`` for every mapped column."""
    import importlib
    import pkgutil

    sys.path.insert(0, str(API_ROOT))
    import app.models as models_pkg  # noqa: PLC0415 — the path must be set first
    from app.db.database import Base  # noqa: PLC0415

    for mod in pkgutil.iter_modules(models_pkg.__path__):
        try:
            importlib.import_module(f"app.models.{mod.name}")
        except Exception as exc:  # noqa: BLE001
            print(f"ERROR: could not import app.models.{mod.name}: {exc}", file=sys.stderr)
            raise SystemExit(2) from exc

    out: list[tuple[str, str, bool, bool]] = []
    for table in Base.metadata.sorted_tables:
        for col in table.columns:
            out.append(
                (
                    table.name.lower(),
                    col.name.lower(),
                    bool(col.nullable),
                    col.default is not None or col.server_default is not None,
                )
            )
    if not out:
        print("ERROR: no mapped columns found — the models did not import", file=sys.stderr)
        raise SystemExit(2)
    return out


def findings() -> tuple[list[dict], int, int]:
    not_null = parse_not_null(MIGRATIONS)
    cols = orm_columns()
    out = []
    compared = 0
    for table, column, nullable, has_default in cols:
        refuses = not_null.get((table, column))
        if refuses is None:
            continue  # the migrations do not create this column (another engine, or a view)
        compared += 1
        if refuses and nullable and not has_default:
            out.append({"table": table, "column": column, "known": (table, column) in KNOWN})
    return out, compared, len(cols)


def _verify_against_dsn(dsn: str) -> int:
    """Check this module's DDL reading against a live, migrated database."""
    try:
        import psycopg  # noqa: PLC0415

        conn = psycopg.connect(dsn)
    except Exception:  # noqa: BLE001
        try:
            import psycopg2 as psycopg  # noqa: PLC0415

            conn = psycopg.connect(dsn)
        except Exception as exc:  # noqa: BLE001
            print(f"ERROR: could not connect for verification: {exc}", file=sys.stderr)
            return 2
    with conn, conn.cursor() as cur:
        cur.execute("SELECT table_name, column_name, is_nullable FROM information_schema.columns WHERE table_schema='public'")
        live = {(r[0].lower(), r[1].lower()): (r[2] == "NO") for r in cur.fetchall()}
    parsed = parse_not_null(MIGRATIONS)
    shared = sorted(set(parsed) & set(live))
    wrong = [(t, c, parsed[(t, c)], live[(t, c)]) for t, c in shared if parsed[(t, c)] != live[(t, c)]]
    print(f"columns in both the parse and the live schema: {len(shared)}")
    if not shared:
        print("ERROR: nothing to compare — the database has no migrated tables", file=sys.stderr)
        return 2
    if wrong:
        print(f"PARSER DISAGREES WITH THE DATABASE on {len(wrong)} column(s):")
        for t, c, got, want in wrong[:40]:
            print(f"  {t}.{c}: parsed not_null={got}, database says not_null={want}")
        return 1
    print("OK — the DDL parse matches information_schema on every shared column.")
    return 0


def _self_test() -> int:
    import tempfile

    cases = [
        ("CREATE TABLE t (a TEXT NOT NULL, b TEXT);", {("t", "a"): True, ("t", "b"): False}),
        ("ALTER TABLE t ADD COLUMN IF NOT EXISTS c TEXT NOT NULL DEFAULT 'x';", {("t", "c"): True}),
        # Several ADD COLUMN clauses in one statement: the second is how
        # `tenants.mssp_role` is declared, and a pattern anchored on
        # `ALTER TABLE` reads only the first.
        (
            "ALTER TABLE t\n  ADD COLUMN IF NOT EXISTS p UUID REFERENCES t(id),\n"
            "  ADD COLUMN IF NOT EXISTS q TEXT NOT NULL DEFAULT 'standalone'\n"
            "    CHECK (q IN ('a','b'));",
            {("t", "p"): False, ("t", "q"): True},
        ),
        # The first clause must not inherit the second's NOT NULL.
        (
            "ALTER TABLE t ADD COLUMN m TEXT, ADD COLUMN n TEXT NOT NULL;",
            {("t", "m"): False, ("t", "n"): True},
        ),
        # A re-add of an existing column is a no-op and must not relax it.
        (
            "ALTER TABLE t ADD COLUMN s TEXT NOT NULL DEFAULT 'active';\n"
            "ALTER TABLE t ADD COLUMN IF NOT EXISTS s VARCHAR(20) DEFAULT 'testing';",
            {("t", "s"): True},
        ),
        ("ALTER TABLE t ADD COLUMN d TEXT;", {("t", "d"): False}),
        ("CREATE TABLE t (a TEXT);\nALTER TABLE t ALTER COLUMN a SET NOT NULL;", {("t", "a"): True}),
        ("CREATE TABLE t (a TEXT NOT NULL);\nALTER TABLE t ALTER COLUMN a DROP NOT NULL;", {("t", "a"): False}),
        # A table constraint's NOT NULL must not attach to the last column.
        ("CREATE TABLE t (\n  a TEXT,\n  CONSTRAINT ck CHECK (a IS NOT NULL)\n);", {("t", "a"): False}),
        # A type with a comma inside parentheses must not split the column.
        ("CREATE TABLE t (\n  a NUMERIC(10, 2) NOT NULL,\n  b TEXT\n);", {("t", "a"): True, ("t", "b"): False}),
        # A comment mentioning NOT NULL must not count.
        ("CREATE TABLE t (\n  a TEXT, -- NOT NULL one day\n  b TEXT\n);", {("t", "a"): False}),
    ]
    failures = 0
    for i, (sql, expected) in enumerate(cases, 1):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "001_x.sql").write_text(sql)
            got = parse_not_null(Path(d))
        for key, want in expected.items():
            actual = got.get(key)
            mark = "PASS" if actual == want else "FAIL"
            if actual != want:
                failures += 1
            print(f"  [{mark}] case {i} {key[0]}.{key[1]} -> {actual} (want {want})")
    print(f"check_orm_nullability.py: self-test {'OK' if not failures else 'FAILED'}")
    return 1 if failures else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--verify-against-dsn", metavar="DSN", default=None)
    args = ap.parse_args()

    if args.self_test:
        return _self_test()
    if args.verify_against_dsn:
        return _verify_against_dsn(args.verify_against_dsn)

    found, compared, total = findings()
    if args.json:
        print(json.dumps({"compared": compared, "mapped_columns": total, "findings": found}, indent=2))

    unexpected = [f for f in found if not f["known"]]
    stale = [k for k in KNOWN if not any((f["table"], f["column"]) == k for f in found)]

    print(f"mapped columns   {total}")
    print(f"compared         {compared} (the rest are not created by services/api/migrations)")
    print(f"known debt       {len(KNOWN)}")

    if stale:
        print("\nFAIL: a KNOWN entry no longer matches anything. Delete it rather than carrying it:")
        for t, c in stale:
            print(f"  {t}.{c}")
        return 1

    if unexpected:
        print(f"\nFAIL: {len(unexpected)} column(s) the database refuses NULL on, declared nullable with no default.")
        print("SQLAlchemy names such a column in the INSERT with an explicit NULL, and a named")
        print("column does not receive the column DEFAULT — so every insert that omits it fails.")
        for f in unexpected:
            print(f"  {f['table']}.{f['column']}")
        return 1

    print("\nOK — every mapped column the migrations declare NOT NULL is either non-null in the model or has a default.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
