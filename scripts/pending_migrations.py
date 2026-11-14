#!/usr/bin/env python3
"""Is this database's schema behind the code that is about to run against it?

Why this exists
---------------
``services/api/app/main.py`` applies the SQL migration chain only when
``AISOC_DEMO_MODE`` is set or ``ENVIRONMENT`` is dev-class. ``ENVIRONMENT``
defaults to ``production`` in both ``docker-compose.yml`` and ``.env.example``;
the Postgres initdb hook fires only on an *empty* data directory and says so in
its own comment; and the ``api`` service has no ``command:`` override, so it
runs uvicorn and nothing else. The comment above that branch excluded
production because "it uses a managed migration pipeline" — there is no managed
migration pipeline in compose or in the Helm chart.

The result was silent: ``docker compose pull && docker compose up -d`` on an
existing deployment started new code against the previous release's schema,
every healthcheck passed, and nothing anywhere said the schema had not moved.
The first symptom is an endpoint failing on a column that does not exist, hours
or days later, with no indication that an upgrade is the cause.

This answers the one question that makes that visible, and nothing else. It
does not migrate: the owner's decision is that AiSOC never updates itself, so
applying DDL is ``make upgrade``'s job, where the operator has asked for it.

Four answers, and the two that are not "fine" are distinguishable
----------------------------------------------------------------
``fresh`` (exit 0)
    No schema at all. The initdb hook owns this case and applies the whole
    chain as the data directory is created. Reporting it as behind would
    refuse every first run, which is a worse defect than the one being fixed.

``up to date`` (exit 0)
    Every migration on disk is recorded as applied.

``behind`` (exit 3)
    Migrations exist on disk that the database has not applied, listed by
    name. This is the case that reached operators.

``unknown`` (exit 4)
    The database could not be read. Deliberately not folded into any of the
    above: "unknown counted as clean" is the most-repeated gate defect in this
    repository, and here it would restore exactly the silence this file exists
    to remove.

Exit 2 is a refusal to answer — no migrations directory, or a usage error. A
check that credits a tree it never opened credits every tree.

One comparison, two policies
----------------------------
``services/api/app/services/schema_skew.py`` asks the same question for
``/readyz`` and ``GET /api/v1/system/version``, and this file used to answer
it with its own copy of the set arithmetic. Two implementations of one
comparison is how the two case tables and the two ``playbook.schema.json``
files happened in this repository, and the copies had already drifted: the
service skipped a directory named ``*.sql`` and this file counted it.

So the comparison is no longer duplicated. ``migrations_on_disk`` and
``evaluate_skew`` are imported from that module — loaded by path, because
``scripts/`` and ``services/api`` do not share a Python path and the API's
package name is ``app``, which four services claim. Everything this file
needs from it is standard-library-only by construction, and a test pins that.

What stays different is the *verdict on one case*, and it stays different
deliberately. A migration applied in the database and absent from the tree
means the deployment is running **older code than its schema**. The service
calls that ``skewed``, correctly: it is asked whether the schema matches the
build, and it does not. This file is asked a narrower question — *should the
operator run ``make upgrade``* — and the answer there is no, because
``make upgrade`` applies migrations forward and cannot fix a rollback.
Reporting ``behind`` would send an operator to run a command that changes
nothing. It is one branch in :func:`exit_code_for`, named, and
``tests/test_upgrade_path.py`` asserts it is the only case on which the two
disagree.

Reading the database
--------------------
The probe command is ``AISOC_PG_PSQL``, so the Makefile can point it at its own
compose invocation (which carries ``-f docker-compose.ports.yml`` when a port
had to be remapped) and a test can point it at a plain ``docker exec``.

It connects over **TCP to 127.0.0.1 inside the container**, not over the unix
socket, and that is load-bearing rather than incidental. The official Postgres
image runs its initdb hooks against a temporary server started with
``listen_addresses=''``; a socket connection reaches that server and would read
a half-populated migration table mid-initialisation, so a first run would be
reported as behind. A TCP connection cannot succeed until the real server is
up, which makes the race impossible rather than unlikely.
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_if_requested  # noqa: E402

self_test_if_requested(__file__)

#: Exit statuses. Named because the Makefile branches on them and a bare
#: integer in two files is two chances to disagree.
OK = 0
REFUSED = 2
BEHIND = 3
UNKNOWN = 4

#: The table ``app.scripts.run_migrations`` records applied migrations in.
TRACKING_TABLE = "aisoc_schema_migrations"

DEFAULT_PROBE = "docker compose exec -T postgres psql -h 127.0.0.1 -U aisoc -d aisoc"

#: The one implementation of the comparison, relative to *this* script's
#: repository rather than to the tree being probed. The migrations directory
#: is the tree under test's; the arithmetic over it is this build's, which is
#: also what keeps the gate-contract harness able to run this inside a bare
#: repository and watch it refuse.
_SKEW_MODULE = Path(__file__).resolve().parents[1] / "services/api/app/services/schema_skew.py"


def _schema_skew() -> Any | None:
    """Load the shared comparison by path, or ``None`` when it is not there.

    Under a private alias: the real dotted name is ``app.services.schema_skew``
    and ``app`` is claimed by four services, so registering it would shadow
    whichever one a caller already imported.

    ``None`` rather than an exception because the gate-contract harness runs
    this script inside a bare tree, where the module is genuinely absent and
    the right answer is a named refusal rather than a traceback.
    """
    if not _SKEW_MODULE.is_file():
        return None
    spec = importlib.util.spec_from_file_location("_aisoc_schema_skew", _SKEW_MODULE)
    if spec is None or spec.loader is None:  # pragma: no cover - the path is checked above
        return None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(spec.name, None)
    return module


def exit_code_for(verdict: Any) -> int:
    """Map one :class:`SchemaSkew` onto this script's exit statuses.

    The whole difference between the two callers of the shared comparison is
    the ``ahead`` branch below, and it is here rather than spread through
    ``main`` so that a test can drive it directly over a corpus of verdicts
    and assert it is the only disagreement.
    """
    if verdict.state == "unknown":
        return UNKNOWN
    if verdict.pending:
        return BEHIND
    # `current`, or `skewed` with nothing pending — which means migrations are
    # applied that this tree does not carry. The service calls that skewed and
    # is right to; this script is answering "run `make upgrade`?" and the
    # answer is no, because upgrading applies migrations forward and a
    # rollback is not something it can fix.
    return OK


def tree_under_test() -> Path:
    """The tree to read, which is not necessarily this file's own.

    ``AISOC_REPO_ROOT`` wins, then a working directory that is itself a
    repository, then git. The middle rule is what lets the gate-contract
    harness run this inside a bare repository and see it refuse, instead of
    walking back to the real checkout and reporting it clean.
    """
    override = os.environ.get("AISOC_REPO_ROOT")
    if override:
        return Path(override)
    cwd = Path.cwd()
    if (cwd / ".git").exists():
        return cwd
    return repo_root()


def _list(names: list[str], limit: int = 10) -> None:
    """Print migration names, bounded, with the remainder counted."""
    for name in names[:limit]:
        print(f"    {name}")
    if len(names) > limit:
        print(f"    … and {len(names) - limit} more")


def _probe(command: str, sql: str) -> tuple[bool, str]:
    """Run one query. Returns (reachable, stdout). Never raises."""
    try:
        result = subprocess.run(
            [*shlex.split(command), "-tAc", sql],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)
    if result.returncode != 0:
        return False, (result.stderr or result.stdout).strip()
    return True, result.stdout.strip()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Report whether the database's schema is behind the migrations on disk.",
    )
    parser.add_argument(
        "--migrations-dir",
        type=Path,
        default=None,
        help="default: <repo>/services/api/migrations",
    )
    parser.add_argument(
        "--probe",
        default=None,
        help=f"psql invocation to read the database with (default: $AISOC_PG_PSQL, else {DEFAULT_PROBE!r})",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="print the verdict only, for a caller that renders its own message",
    )
    args = parser.parse_args(argv)

    root = tree_under_test()
    migrations_dir = args.migrations_dir or root / "services" / "api" / "migrations"

    # The chain is checked before the comparison is loaded, so a tree with no
    # migrations refuses for the reason that is true of it rather than for a
    # missing module one directory over — which is what a bare tree is, and
    # what the gate-contract harness runs this against.
    if not migrations_dir.is_dir():
        print(
            f"pending_migrations: no migrations directory at {migrations_dir} — "
            "refusing to report a database up to date against a chain it never read",
            file=sys.stderr,
        )
        return REFUSED

    skew = _schema_skew()
    if skew is None:  # pragma: no cover - a tree with migrations but no API service
        print(
            f"pending_migrations: the shared comparison is missing at {_SKEW_MODULE} — "
            "refusing rather than answering with a second copy of it",
            file=sys.stderr,
        )
        return REFUSED

    on_disk = skew.migrations_on_disk(migrations_dir)
    if not on_disk:
        # Refuses rather than reporting "up to date". With no chain to compare
        # against, every database is trivially current, and a wrong root or a
        # renamed directory would read as a clean bill of health.
        print(
            f"pending_migrations: no .sql migrations under {migrations_dir} — "
            "refusing to report a database up to date against a chain it never read",
            file=sys.stderr,
        )
        return REFUSED

    probe = args.probe or os.environ.get("AISOC_PG_PSQL") or DEFAULT_PROBE

    reachable, table = _probe(probe, f"SELECT to_regclass('public.{TRACKING_TABLE}')")
    if not reachable:
        print("pending_migrations: unknown — could not read the database.")
        print(f"  probe: {probe}")
        print(f"  error: {table}")
        print("  This is reported as unknown, not as up to date: a schema nobody")
        print("  could read is not a schema anybody has checked.")
        return UNKNOWN

    if not table or table == "":
        # No tracking table. Either a brand-new database (the initdb hook has
        # not run or there is nothing here yet) or one that predates tracking.
        # The two are told apart by whether anything else exists.
        _, count = _probe(probe, "SELECT count(*) FROM pg_tables WHERE schemaname = 'public'")
        if count.strip() in {"", "0"}:
            if not args.quiet:
                print("pending_migrations: fresh — empty database; the initdb hook applies the chain on creation.")
            return OK
        # A database that answered and has applied nothing is an empty set,
        # not an unknown — so the shared comparison decides this case too,
        # rather than this file hand-rolling "everything is pending".
        verdict = skew.evaluate_skew(applied=set(), on_disk=on_disk)
        print(f"pending_migrations: behind — {len(verdict.pending)} migration(s) pending.")
        print(f"  This database has tables but no {TRACKING_TABLE}, so none of the")
        print("  chain is recorded as applied.")
        _list(verdict.pending)
        return exit_code_for(verdict)

    reachable, rows = _probe(probe, f"SELECT name FROM {TRACKING_TABLE}")
    if not reachable:
        print("pending_migrations: unknown — the tracking table exists but could not be read.")
        print(f"  error: {rows}")
        return UNKNOWN

    applied = {line.strip() for line in rows.splitlines() if line.strip()}
    verdict = skew.evaluate_skew(applied=applied, on_disk=on_disk)
    code = exit_code_for(verdict)

    if code == OK:
        if not args.quiet:
            print(f"pending_migrations: up to date — {verdict.applied_count} migration(s) applied, none pending.")
            if verdict.applied_not_on_disk:
                # Not a failure here, though the service calls the same state
                # skewed — see the module docstring. The operator is running
                # older code than their schema, which `make upgrade` cannot
                # fix and should not claim to.
                print(f"  note: {len(verdict.applied_not_on_disk)} migration(s) are applied that this tree does not carry,")
                print("  so this deployment's code is older than its database.")
        return code

    print(f"pending_migrations: behind — {len(verdict.pending)} migration(s) on disk are not applied.")
    _list(verdict.pending)
    return code


if __name__ == "__main__":
    sys.exit(main())
