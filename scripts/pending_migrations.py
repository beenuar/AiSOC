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
import os
import shlex
import subprocess
import sys
from pathlib import Path

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


def migrations_on_disk(migrations_dir: Path) -> list[str]:
    """The chain, in the order and under the names the runner uses.

    ``run_migrations.py`` does ``sorted(p for p in MIGRATIONS_DIR.iterdir() if
    p.suffix == ".sql")`` and records ``path.name``. Both halves are copied
    here deliberately: a different ordering or a different key would make this
    answer a question about a chain nobody applies.
    """
    if not migrations_dir.is_dir():
        return []
    return sorted(p.name for p in migrations_dir.iterdir() if p.suffix == ".sql")


def pending(applied: set[str], on_disk: list[str]) -> list[str]:
    """Migrations present on disk and absent from the database, in chain order.

    Set difference in one direction only. A name in the database and not on
    disk means the deployment is running *older* code than its schema, which
    is a rollback rather than a pending upgrade — it is reported separately by
    the caller rather than counted here, because telling an operator to
    upgrade would be the wrong instruction.
    """
    return [name for name in on_disk if name not in applied]


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
    on_disk = migrations_on_disk(migrations_dir)

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
        print(f"pending_migrations: behind — {len(on_disk)} migration(s) pending.")
        print(f"  This database has tables but no {TRACKING_TABLE}, so none of the")
        print("  chain is recorded as applied.")
        for name in on_disk[:10]:
            print(f"    {name}")
        if len(on_disk) > 10:
            print(f"    … and {len(on_disk) - 10} more")
        return BEHIND

    reachable, rows = _probe(probe, f"SELECT name FROM {TRACKING_TABLE}")
    if not reachable:
        print("pending_migrations: unknown — the tracking table exists but could not be read.")
        print(f"  error: {rows}")
        return UNKNOWN

    applied = {line.strip() for line in rows.splitlines() if line.strip()}
    missing = pending(applied, on_disk)
    ahead = sorted(applied - set(on_disk))

    if not missing:
        if not args.quiet:
            print(f"pending_migrations: up to date — {len(applied)} migration(s) applied, none pending.")
            if ahead:
                # Not a failure. The operator is running older code than their
                # schema, which `make upgrade` cannot fix and should not claim to.
                print(f"  note: {len(ahead)} migration(s) are applied that this tree does not carry,")
                print("  so this deployment's code is older than its database.")
        return OK

    print(f"pending_migrations: behind — {len(missing)} migration(s) on disk are not applied.")
    for name in missing[:10]:
        print(f"    {name}")
    if len(missing) > 10:
        print(f"    … and {len(missing) - 10} more")
    return BEHIND


if __name__ == "__main__":
    sys.exit(main())
