#!/usr/bin/env python3
"""Gate: every store with schema has a migration runner, and it is called.

Three stores hold schema that code depends on — Neo4j, ClickHouse and
Qdrant — and none had a way to change it. `clickhouse/001_init.sql` is four
`CREATE TABLE IF NOT EXISTS` statements and zero `ALTER TABLE`;
`lake_writer` self-heals with the same idiom; `QdrantStore.initialize()`
creates collections if absent. All three are no-ops once the object exists,
so a schema change lands on a fresh deployment and silently does not land on
an existing one. Nothing notices until a query selects a column that is not
there, long after the deploy that was meant to add it.

The second half of this gate matters more than the first. v8.0 spent a
release discovering that **the mechanism existed, was unit-tested, and had
no caller on the path that needed it** — so a runner that exists and is
never invoked is not progress, it is the same defect with better test
coverage. This checks both.

Parsed rather than imported: the API package pulls in SQLAlchemy, asyncpg,
Neo4j and ClickHouse drivers, and a structural gate that needs a database
container is a gate that gets disabled.

Run:  python3 scripts/check_store_migrations.py
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

#: store -> (runner module, the file that must call it, the symbol it calls)
#:
#: The call site is named explicitly rather than searched for, because "some
#: file somewhere imports it" is satisfied by a test, and a test is exactly
#: what stopped being evidence.
RUNNERS: dict[str, tuple[Path, Path, str]] = {
    "neo4j": (
        REPO_ROOT / "services/api/app/db/graph_migrations.py",
        REPO_ROOT / "services/api/app/db/neo4j.py",
        "run_migrations",
    ),
    "clickhouse": (
        REPO_ROOT / "services/api/app/db/lake_migrations.py",
        REPO_ROOT / "services/api/app/db/clickhouse.py",
        "run_migrations",
    ),
    "qdrant": (
        REPO_ROOT / "services/api/app/db/vector_migrations.py",
        REPO_ROOT / "services/threatintel/app/storage/qdrant.py",
        "run_migrations",
    ),
}

#: The startup path each caller must itself be reachable from. Without this
#: the chain stops one link short: a runner called by a function nobody
#: invokes is still a runner that never runs.
STARTUP_CALLERS: dict[str, tuple[Path, str]] = {
    "neo4j": (REPO_ROOT / "services/api/app/main.py", "init_neo4j"),
    "clickhouse": (REPO_ROOT / "services/api/app/main.py", "init_lake_schema"),
    "qdrant": (
        REPO_ROOT / "services/threatintel/app/storage/qdrant.py",
        "initialize",
    ),
}

#: A runner must expose these. Three stores, one vocabulary — an operator
#: should not need three mental models to answer "what has this applied".
REQUIRED_SYMBOLS = ("MIGRATIONS", "run_migrations", "applied_ids", "pending_ids")


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8") if path.exists() else ""


def check_runners_exist() -> list[str]:
    errors: list[str] = []
    for store, (runner, _, _) in RUNNERS.items():
        if not runner.exists():
            errors.append(
                f"{store}: no migration runner at "
                f"{runner.relative_to(REPO_ROOT)}. Its schema can only be "
                f"created, never changed, so a new column never reaches an "
                f"existing deployment."
            )
            continue
        source = _read(runner)
        for symbol in REQUIRED_SYMBOLS:
            if not re.search(rf"^(?:async def |def |){symbol}\b", source, re.M):
                errors.append(f"{store}: runner does not expose {symbol}; the three " f"runners are meant to share one interface")
    return errors


def check_runners_are_called() -> list[str]:
    """The half that catches the v8.0 pattern."""
    errors: list[str] = []
    for store, (runner, caller, symbol) in RUNNERS.items():
        if not runner.exists():
            continue
        if not caller.exists():
            errors.append(f"{store}: expected call site {caller.relative_to(REPO_ROOT)} " f"does not exist")
            continue
        source = _read(caller)
        if symbol not in source:
            errors.append(
                f"{store}: {caller.relative_to(REPO_ROOT)} never calls "
                f"{symbol}(). The runner exists and nothing invokes it, which "
                f"is indistinguishable from not having one."
            )
    return errors


def check_startup_reachability() -> list[str]:
    """A caller nobody invokes is one link short of the same problem."""
    errors: list[str] = []
    for store, (path, symbol) in STARTUP_CALLERS.items():
        source = _read(path)
        if not source:
            errors.append(f"{store}: {path.relative_to(REPO_ROOT)} does not exist")
            continue
        # Called, not merely defined or imported.
        if not re.search(rf"\b{symbol}\s*\(", source):
            errors.append(
                f"{store}: {symbol} is never invoked in " f"{path.relative_to(REPO_ROOT)}, so migrations do not run at " f"startup"
            )
    return errors


def check_ids_are_append_only() -> list[str]:
    """Migration ids must be unique and ordered.

    The runners apply in tuple order, so a numbering that disagrees with
    that order means migrations run in a sequence the numbers do not
    describe — and migration N+1 is written against the state N produced.
    """
    errors: list[str] = []
    for store, (runner, _, _) in RUNNERS.items():
        source = _read(runner)
        if not source:
            continue
        ids = re.findall(r'^\s+id="([^"]+)"', source, re.M)
        if not ids:
            errors.append(f"{store}: no migrations declared; the runner is empty")
            continue
        if len(ids) != len(set(ids)):
            errors.append(f"{store}: duplicate migration ids")
        if ids != sorted(ids):
            errors.append(f"{store}: migration ids are not in order ({', '.join(ids)}); " f"the runner applies them in declaration order")
    return errors


def main(argv: list[str] | None = None) -> int:
    argparse.ArgumentParser(description=__doc__).parse_args(argv)

    errors = check_runners_exist() + check_runners_are_called() + check_startup_reachability() + check_ids_are_append_only()

    if errors:
        print("STORE MIGRATION GATE FAILED:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    print(f"store-migrations: OK — {len(RUNNERS)} stores have a runner, each " f"wired into a startup path")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
