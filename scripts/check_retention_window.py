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

**A cold read with no cost and no progress.** The plan's third bullet. A
query over the cold volume either returned inside the published
30-second synchronous bound or raised a bare timeout, which tells an
analyst nothing about whether a longer deadline would have helped or how
much data was involved — and the ``cost`` ``/lake/sql`` did report was
the rate limiter's token price, a number about how often you may ask.
The estimate must come from ClickHouse's own planner and parts, the
money figure must be absent rather than invented when no retrieval price
is configured, the job must be claimed with a predicate that two
replicas cannot both satisfy, and a progress ratio with no denominator
must be null rather than zero.

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
COLD_QUERY_PY = Path("services/api/app/services/lake_cold_query.py")
JOB_RUNNER_PY = Path("services/api/app/services/lake_query_runner.py")
LAKE_ENDPOINT = Path("services/api/app/api/v1/endpoints/lake.py")
JOB_MIGRATION = Path("services/api/migrations/114_lake_query_jobs.sql")

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

    failures.extend(_evaluate_cold_query(root))
    return failures


def _evaluate_cold_query(root: Path) -> list[str]:
    """The plan's third bullet: cost and progress instead of a silent timeout."""
    failures: list[str] = []

    cold_src = _read(root, COLD_QUERY_PY)
    if not cold_src:
        failures.append(
            f"{COLD_QUERY_PY} is missing, so a query over the cold volume still either returns inside the "
            f"synchronous bound or raises a bare timeout with no indication of how much data was involved."
        )
        return failures
    cold = _strip_py_comments(cold_src)

    # The estimate has to be the server's, not ours.
    if "EXPLAIN ESTIMATE" not in cold:
        failures.append(
            f"{COLD_QUERY_PY} does not ask ClickHouse for an estimate. A row count this code derived itself is a "
            f"guess presented as a measurement."
        )
    if "system.parts" not in cold:
        failures.append(
            f"{COLD_QUERY_PY} does not read system.parts, so nothing says which of the scan is on the cold volume "
            f"- which is the half that costs."
        )
    if "system.processes" not in cold:
        failures.append(
            f"{COLD_QUERY_PY} does not read system.processes, so a running scan has no progress to report and the "
            f"only honest alternative is deriving one from elapsed time, which over a cold read is proportional "
            f"to nothing."
        )

    # No invented money. This is the rule the repository cares about most.
    if "RETRIEVAL_PRICE_ENV" not in cold:
        failures.append(
            f"{COLD_QUERY_PY} declares no configurable retrieval price, so any money figure it reports is either "
            f"invented or taken from the storage rate card, which prices residency rather than reads."
        )
    if "storage-cost-model.json" not in cold_src:
        failures.append(
            f"{COLD_QUERY_PY} does not say why docs/decisions/storage-cost-model.json is the wrong source for a "
            f"read price. The next person to want a dollar figure will reach for it."
        )

    # Progress that admits it does not know.
    if not re.search(r"total_rows_approx\s*<=\s*0", cold):
        failures.append(
            f"{COLD_QUERY_PY} does not guard the progress denominator. ClickHouse publishes total_rows_approx "
            f"best-effort, so a ratio computed without the guard renders 100% whenever the server has not "
            f"published a total."
        )

    runner_src = _read(root, JOB_RUNNER_PY)
    if not runner_src:
        failures.append(f"{JOB_RUNNER_PY} is missing, so there is no job to carry a progress state.")
    else:
        runner = _strip_py_comments(runner_src)
        if 'LakeQueryJob.status == "queued"' not in runner:
            failures.append(
                f"{JOB_RUNNER_PY} claims a job without re-checking its status in the same statement. Two API "
                f"replicas would then both start one cold scan, which is two reads of the cold volume for one "
                f"analyst's question."
            )
        # Matched as the *pair* rather than as the status string alone.
        # list_stuck_jobs legitimately selects on status == "running", so
        # a rule looking for the bare string passes a runner whose writes
        # have lost their guard entirely - measured, by removing it and
        # watching the first version of this rule stay green.
        if 'LakeQueryJob.id == job_id, LakeQueryJob.status == "running"' not in runner:
            failures.append(
                f"{JOB_RUNNER_PY} writes to a job without checking it is still running, so a scan that completes "
                f"after an operator cancelled it reports success, and a late progress read resurrects a finished "
                f"job."
            )

    endpoint = _strip_py_comments(_read(root, LAKE_ENDPOINT))
    if not endpoint:
        failures.append(f"{LAKE_ENDPOINT} is missing; there is no surface for any of this.")
    else:
        # The *branch*, not the field name. LakeEstimateResponse
        # declares a touches_cold field, so a rule looking for the bare
        # name passes an endpoint that reports the flag and ignores it -
        # which is the regression that matters, because the response
        # still looks right.
        if not re.search(r"estimate\.touches_cold", endpoint):
            failures.append(
                f"{LAKE_ENDPOINT} never branches on the estimate, so a cold query still goes down the "
                f"synchronous path and still times out silently - while the estimate field in the response "
                f"makes it look handled."
            )
        if '"/query-jobs"' not in endpoint:
            failures.append(f"{LAKE_ENDPOINT} exposes no job surface, so a long scan has nowhere to report progress to.")
        if "/estimate" not in endpoint:
            failures.append(
                f"{LAKE_ENDPOINT} offers no way to ask what a query would read without running it, so the only "
                f"way to find out the cost is to pay it."
            )

    if not (root / JOB_MIGRATION).is_file():
        failures.append(
            f"{JOB_MIGRATION} is missing, so lake_query_jobs exists in the ORM and in no database - and an "
            f"in-process registry loses every job on a restart and 404s half of them on a second replica."
        )
    else:
        migration = _read(root, JOB_MIGRATION)
        if "ENABLE ROW LEVEL SECURITY" not in migration:
            failures.append(f"{JOB_MIGRATION} creates lake_query_jobs with no row-level security.")
        if "progress_ratio  DOUBLE PRECISION" not in migration and "progress_ratio DOUBLE PRECISION" not in migration:
            failures.append(
                f"{JOB_MIGRATION} does not declare progress_ratio as a nullable double. NOT NULL would force a "
                f"zero where the honest answer is unknown."
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
        ("a cold-query estimator that is absent entirely", "NO_COLD_ESTIMATOR"),
        ("an estimate this code derives instead of asking the planner", "OWN_ESTIMATE"),
        ("a scan with no warm/cold split, so nothing says what costs", "NO_PARTS_READ"),
        ("a progress ratio with no denominator guard", "UNGUARDED_RATIO"),
        ("a job claim two replicas can both win", "RACY_CLAIM"),
        ("a terminal state a late finish can overwrite", "OVERWRITABLE_FINISH"),
        ("a cold query still routed down the synchronous path", "NO_ROUTING"),
        ("jobs that exist in the ORM and in no database", "NO_JOB_TABLE"),
    )

    for label, kind in cases:
        tmp = Path(tempfile.mkdtemp(prefix="aisoc-retention-selftest-"))
        try:
            for rel in (
                INIT_SQL,
                TIERING_SQL,
                RETENTION_PY,
                WORKER_PY,
                LAKE_MIGRATIONS,
                COLD_QUERY_PY,
                JOB_RUNNER_PY,
                LAKE_ENDPOINT,
                JOB_MIGRATION,
            ):
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
            elif kind == "NO_COLD_ESTIMATOR":
                (tmp / COLD_QUERY_PY).unlink(missing_ok=True)
            elif kind == "OWN_ESTIMATE":
                path = tmp / COLD_QUERY_PY
                path.write_text(
                    path.read_text(encoding="utf-8").replace("EXPLAIN ESTIMATE", "SELECT count() FROM"),
                    encoding="utf-8",
                )
            elif kind == "NO_PARTS_READ":
                path = tmp / COLD_QUERY_PY
                path.write_text(path.read_text(encoding="utf-8").replace("system.parts", "system.tables"), encoding="utf-8")
            elif kind == "UNGUARDED_RATIO":
                path = tmp / COLD_QUERY_PY
                path.write_text(
                    path.read_text(encoding="utf-8").replace("if self.total_rows_approx <= 0:", "if False:"),
                    encoding="utf-8",
                )
            elif kind == "RACY_CLAIM":
                path = tmp / JOB_RUNNER_PY
                path.write_text(
                    path.read_text(encoding="utf-8").replace(
                        'LakeQueryJob.id == job_id, LakeQueryJob.status == "queued"',
                        "LakeQueryJob.id == job_id",
                    ),
                    encoding="utf-8",
                )
            elif kind == "OVERWRITABLE_FINISH":
                path = tmp / JOB_RUNNER_PY
                path.write_text(
                    path.read_text(encoding="utf-8").replace(
                        'LakeQueryJob.id == job_id, LakeQueryJob.status == "running"',
                        "LakeQueryJob.id == job_id",
                    ),
                    encoding="utf-8",
                )
            elif kind == "NO_ROUTING":
                path = tmp / LAKE_ENDPOINT
                path.write_text(path.read_text(encoding="utf-8").replace("estimate.touches_cold", "False"), encoding="utf-8")
            elif kind == "NO_JOB_TABLE":
                (tmp / JOB_MIGRATION).unlink(missing_ok=True)

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
