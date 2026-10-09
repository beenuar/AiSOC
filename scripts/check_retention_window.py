#!/usr/bin/env python3
"""A tenant's retention setting has to be the thing that decides.

Depth plan 4.3. Three ways a retention promise can be false, and the tree
had all three.

**The lake deletes on its own schedule.** ``aisoc.raw_events`` carries a
``TTL ... + INTERVAL 90 DAY`` written into the table. ClickHouse enforces
that during merges, with no reference to any per-tenant setting — so a
tenant who chose 400 days in the console, and whose policy row says 400,
loses every event at day 90. Nothing errors. The console keeps saying 400.
The table TTL therefore has to be a *ceiling* at least as long as the
longest window a tenant may choose, with the per-tenant window enforced
above it by the purge worker.

**A legal hold that nothing consults.** ``retention.alerts_under_legal_hold``
and ``retention.may_purge`` were written, tested, and reachable from no
production caller — so "a hold outranks retention unconditionally", which
the migration's own comment states, was true of a function and false of the
system. The purge worker must read holds and must skip what they cover.

**A purge that cannot say it was blocked.** A hold that silently stops a
purge and a purge that silently did nothing look the same in a log. The run
summary has to carry the count it withheld.

These are read out of the source rather than exercised, because the lake
TTL lives in DDL and the worker needs Postgres and ClickHouse. The
behavioural half is `services/api/tests/test_retention_legal_hold.py`,
which drives the worker against recording doubles — including the positive
control, because a purge stuck closed passes every "did it withhold"
assertion perfectly.

Usage:
    python3 scripts/check_retention_window.py
    python3 scripts/check_retention_window.py --self-test
"""

from __future__ import annotations

import argparse
import ast
import re
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import TREE_SHAPES, refuses_an_empty_tree, repo_root  # noqa: E402

REPO_ROOT = repo_root()

INIT_SQL = Path("services/api/clickhouse/001_init.sql")
TIERING_SQL = Path("services/api/clickhouse/tiering/002_tiering.sql")
RETENTION_PY = Path("services/api/app/services/retention.py")
WORKER_PY = Path("services/api/app/workers/retention_purge.py")
LAKE_MIGRATIONS = Path("services/api/app/db/lake_migrations.py")

#: The floor the plan names. A deployment that cannot keep a year and a bit
#: cannot answer "show me this account's activity over the last audit
#: period", which is the question retention exists for.
MINIMUM_CEILING_DAYS = 400


def _read(root: Path, rel: Path) -> str:
    try:
        return (root / rel).read_text(encoding="utf-8")
    except OSError:
        return ""


def _sql_ttl_days(sql: str, table: str = "aisoc.raw_events") -> list[int]:
    """Every ``INTERVAL n DAY`` in a TTL clause that can DELETE.

    A ``TO VOLUME`` move is not a deletion and must not be read as one: the
    tiering file moves at 30 days and deletes at 90, and a reader that
    counted the first would report a 30-day retention window for a
    deployment that keeps 90.
    """
    out: list[int] = []
    # Scoped to the named table. The init file also creates `alert_metrics`
    # (365 days) and `ioc_enrichments` (30), and a reader that took the
    # minimum across the file would report a 30-day lake and be confidently
    # wrong about the table that holds the events.
    flat = re.sub(r"\s+", " ", sql)
    blocks = [b for b in re.split(r"(?=CREATE TABLE)", flat, flags=re.I) if table.lower() in b.lower()]
    if blocks:
        flat = " ".join(blocks)
    elif "CREATE TABLE" in flat.upper():
        # The table this is asked about is not in this file at all, so
        # answering from whatever else is here would describe the wrong one.
        return []
    for clause in re.findall(r"TTL (.+?)(?:SETTINGS|;|$)", flat, flags=re.I):
        for piece in clause.split(","):
            if re.search(r"TO\s+(VOLUME|DISK)", piece, flags=re.I):
                continue
            match = re.search(r"INTERVAL\s+(\d+)\s+DAY", piece, flags=re.I)
            if match:
                out.append(int(match.group(1)))
    return out


#: The constant that bounds the *lake* window specifically. Separate from
#: ``MAX_DAYS``, which bounds Postgres-resident classes: the two stores cost
#: very different amounts and holding them to one number would either make
#: the lake unaffordable or cap an audit trail at the lake's ceiling.
LAKE_CEILING_CONST = "MAX_LAKE_DAYS"


def _constant(source: str, name: str) -> int | None:
    """An int module constant, read rather than assumed."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            targets: list[ast.expr] = list(node.targets)
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        else:
            continue
        for target in targets:
            if isinstance(target, ast.Name) and target.id == name and isinstance(node.value, ast.Constant):
                value = node.value.value
                if isinstance(value, int) and not isinstance(value, bool):
                    return value
    return None


def _max_configurable_days(source: str) -> int | None:
    """The longest lake window a tenant may choose."""
    return _constant(source, LAKE_CEILING_CONST)


def _strip_py_comments(source: str) -> str:
    """Comments and docstrings out, so a gate does not match its own rationale.

    The worker's module docstring will name the functions this gate requires
    it to call, which is exactly how a check comes to pass over a module that
    only *describes* the wiring.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return source
    spans: list[tuple[int, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            if node.lineno and node.end_lineno:
                spans.append((node.lineno, node.end_lineno))
    lines = source.splitlines()
    keep = []
    for number, line in enumerate(lines, start=1):
        if any(start <= number <= end for start, end in spans):
            continue
        keep.append(re.sub(r"#.*$", "", line))
    return "\n".join(keep)


def evaluate(root: Path) -> list[str]:
    failures: list[str] = []

    retention_src = _read(root, RETENTION_PY)
    if not retention_src:
        failures.append(f"{RETENTION_PY} is missing; there is no per-tenant retention policy to enforce.")
        return failures

    max_days = _max_configurable_days(retention_src)
    if max_days is None:
        failures.append(
            f"{RETENTION_PY} declares no {LAKE_CEILING_CONST}, so nothing states the longest lake window a tenant "
            f"may choose and the table TTL has nothing to be compared against."
        )
    elif max_days < MINIMUM_CEILING_DAYS:
        failures.append(f"{RETENTION_PY} caps a tenant at {max_days} days; the plan requires at least {MINIMUM_CEILING_DAYS}.")

    # 1. The lake's own TTL must not delete before the longest window a
    #    tenant may choose.
    init_sql = _read(root, INIT_SQL)
    if not init_sql:
        failures.append(f"{INIT_SQL} is missing, so nothing states the lake's retention ceiling.")
    else:
        ttls = _sql_ttl_days(init_sql)
        if not ttls:
            failures.append(f"{INIT_SQL} declares no deleting TTL on aisoc.raw_events; the lake would grow without bound.")
        else:
            ceiling = min(ttls)
            if max_days is not None and ceiling < max_days:
                failures.append(
                    f"{INIT_SQL} deletes lake rows at {ceiling} days while a tenant may choose up to {max_days}. "
                    f"A tenant who chose more loses rows at day {ceiling} with nothing erroring and the console "
                    f"still showing their setting. The table TTL has to be the ceiling; the per-tenant window is "
                    f"enforced above it by the purge worker."
                )
            elif ceiling < MINIMUM_CEILING_DAYS:
                failures.append(f"{INIT_SQL} deletes lake rows at {ceiling} days, below the {MINIMUM_CEILING_DAYS}-day floor.")

    # The init file only runs in the container entrypoint on a fresh volume,
    # so a TTL changed there alone lands on new deployments and silently not
    # on existing ones — the exact failure lake_migrations.py exists for.
    migrations = _read(root, LAKE_MIGRATIONS)
    if migrations and "MODIFY TTL" not in migrations:
        failures.append(
            f"{LAKE_MIGRATIONS} carries no MODIFY TTL migration, so an existing deployment keeps whatever TTL its "
            f"volume was created with. {INIT_SQL} runs only on a fresh volume."
        )

    tiering = _read(root, TIERING_SQL)
    if tiering:
        tier_ttls = _sql_ttl_days(tiering)
        if tier_ttls and max_days is not None and min(tier_ttls) < max_days:
            failures.append(
                f"{TIERING_SQL} deletes at {min(tier_ttls)} days while a tenant may choose up to {max_days}. "
                f"Tiering is a storage decision and must not shorten retention."
            )

    # 2 and 3. The worker reads holds, withholds what they cover, and says so.
    worker_src = _read(root, WORKER_PY)
    if not worker_src:
        failures.append(f"{WORKER_PY} is missing, so no per-tenant window is enforced at all.")
    else:
        worker = _strip_py_comments(worker_src)
        if not re.search(r"\balerts_under_legal_hold\s*\(", worker):
            failures.append(
                f"{WORKER_PY} never calls alerts_under_legal_hold. The function, its tests and the migration's "
                f"own comment all say a hold outranks retention unconditionally — which is true of a function and "
                f"false of the system until the worker reads it."
            )
        if not re.search(r"\bmay_purge\s*\(", worker):
            failures.append(f"{WORKER_PY} never calls may_purge, so nothing compares a row against the holds in force.")
        if not re.search(r"held", worker):
            failures.append(
                f"{WORKER_PY} does not report what a hold withheld. A hold that silently stops a purge and a purge "
                f"that silently did nothing look identical in a log, and only one of them is working."
            )

    return failures


def _self_test() -> int:
    results: list[tuple[str, bool]] = []

    baseline = evaluate(REPO_ROOT)
    results.append(("the undisturbed tree is clean, so a caught case means something", not baseline))
    for line in baseline[:8]:
        print(f"        {line}")

    cases = (
        ("a lake TTL shorter than the window a tenant may choose", "SHORT_TTL"),
        ("a lake with no deleting TTL at all", "NO_TTL"),
        ("a per-tenant cap below the plan's floor", "LOW_CAP"),
        ("a TTL changed only where a fresh volume would see it", "NO_MIGRATION"),
        ("a tiering policy that shortens retention", "TIER_SHORTENS"),
        ("a purge that never reads the holds in force", "NO_HOLD_READ"),
        ("a purge that reads holds and never compares a row against them", "NO_DECISION"),
        ("a purge that cannot report what a hold withheld", "SILENT_HOLD"),
    )

    for label, kind in cases:
        tmp = Path(tempfile.mkdtemp(prefix="aisoc-retention-selftest-"))
        try:
            for rel in (INIT_SQL, TIERING_SQL, RETENTION_PY, WORKER_PY, LAKE_MIGRATIONS):
                src = REPO_ROOT / rel
                if src.is_file():
                    (tmp / rel).parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(src, tmp / rel)

            init = tmp / INIT_SQL
            worker = tmp / WORKER_PY
            if kind == "SHORT_TTL" and init.is_file():
                text = init.read_text(encoding="utf-8")
                init.write_text(re.sub(r"INTERVAL \d+ DAY", "INTERVAL 90 DAY", text, count=1), encoding="utf-8")
            elif kind == "NO_TTL" and init.is_file():
                # Anchored to the start of a line: the header comment above
                # the table talks *about* the TTL, and an unanchored pattern
                # deletes the prose while leaving the clause in place — an
                # injection that changes nothing, which reads as a gate that
                # does not work.
                init.write_text(
                    re.sub(r"(?m)^TTL [^\n]*\n", "", init.read_text(encoding="utf-8"), count=1),
                    encoding="utf-8",
                )
            elif kind == "LOW_CAP":
                path = tmp / RETENTION_PY
                path.write_text(
                    re.sub(rf"{LAKE_CEILING_CONST} = \d+", f"{LAKE_CEILING_CONST} = 90", path.read_text(encoding="utf-8"), count=1),
                    encoding="utf-8",
                )
            elif kind == "NO_MIGRATION":
                path = tmp / LAKE_MIGRATIONS
                path.write_text(path.read_text(encoding="utf-8").replace("MODIFY TTL", "MODIFY SETTING"), encoding="utf-8")
            elif kind == "TIER_SHORTENS":
                path = tmp / TIERING_SQL
                text = path.read_text(encoding="utf-8")
                path.write_text(re.sub(r"INTERVAL \d+ DAY DELETE", "INTERVAL 90 DAY DELETE", text, count=1), encoding="utf-8")
            elif kind == "NO_HOLD_READ" and worker.is_file():
                worker.write_text(
                    worker.read_text(encoding="utf-8").replace("alerts_under_legal_hold(", "_skipped_holds("), encoding="utf-8"
                )
            elif kind == "NO_DECISION" and worker.is_file():
                worker.write_text(worker.read_text(encoding="utf-8").replace("may_purge(", "_unused_decision("), encoding="utf-8")
            elif kind == "SILENT_HOLD" and worker.is_file():
                worker.write_text(re.sub(r"held", "skipped", worker.read_text(encoding="utf-8")), encoding="utf-8")

            results.append((f"catches {label}", bool(evaluate(tmp))))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    details: list[str] = []
    for shape in TREE_SHAPES:
        refused, detail = refuses_an_empty_tree(Path(__file__).name, shape=shape)
        results.append((f"refuses a {shape} tree rather than reporting it clean", refused))
        details.append(f"{shape}: {detail}")

    ok = True
    for description, passed in results:
        ok &= passed
        print(f"  {'PASS' if passed else 'FAIL'}  {description}")
    for line in "\n".join(details).splitlines():
        print(f"        {line}")
    print()
    if not ok:
        print(f"{Path(__file__).name}: self-test FAILED")
        return 1
    print(f"{Path(__file__).name}: self-test OK")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--self-test", action="store_true", help="inject one violation per rule and require each to be caught")
    args = parser.parse_args()
    if args.self_test:
        return _self_test()

    if not (REPO_ROOT / INIT_SQL).is_file():
        print(f"check_retention_window: {INIT_SQL} is not there — nothing to render a verdict about.", file=sys.stderr)
        return 2

    failures = evaluate(REPO_ROOT)
    if failures:
        print("Per-tenant retention (depth plan 4.3) is not what the tenant chose:\n", file=sys.stderr)
        for line in failures:
            print(f"  - {line}", file=sys.stderr)
        print(f"\n{len(failures)} problem(s).", file=sys.stderr)
        return 1

    max_days = _max_configurable_days(_read(REPO_ROOT, RETENTION_PY))
    ceiling = min(_sql_ttl_days(_read(REPO_ROOT, INIT_SQL)))
    print(
        f"OK — the lake keeps rows for up to {ceiling} days, a tenant may choose up to {max_days}, "
        f"an existing deployment is migrated onto it, and the purge reads the holds in force and reports what they withheld."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
