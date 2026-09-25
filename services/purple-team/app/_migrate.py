"""Apply this service's alembic chain, then exec what comes after it.

Why this exists
---------------

Four services in this repository own their schema through alembic —
``ueba``, ``honeytokens``, ``purple-team`` and ``osquery-tls`` — and **no
compose path invoked any of them**. Their container command was a plain
``uvicorn``, so on the documented quickstart they booted healthy against
empty schemas with none of their row-level-security policies installed. The
only documented invocation was a manual step in a docs-portal quickstart
whose own "start the stack" step does not start three of the four services,
and whose first line failed outright.

That is how two services shipped with no tables while every command
reported success. The API does not have this problem because its chain runs
from its own process on the way up; this is the same idea for the four that
use alembic.

What it guarantees
------------------

**Idempotent.** ``alembic upgrade head`` on a database already at head
applies nothing. Running this on every container start is the point: there
is no separate "have you migrated yet" state for an operator to get wrong.

**Race-free.** Four chains start at once against one database. The chains
take a shared transaction-scoped advisory lock (``MIGRATION_LOCK_KEY`` in
each ``env.py``), so they queue instead of deadlocking on catalog locks.
This wrapper deliberately holds no lock of its own — a lock held here would
be a second mechanism to reason about, and it would not cover the window
that actually matters.

**Loud.** The service does not start unless the chain reached head. Not "the
command exited 0": alembic exits 0 when it applies *nothing*, which is
exactly what happened when four chains shared one ``alembic_version`` table
and the second one to run believed it was already done. So ``current`` is
read back and compared to ``heads``, and a mismatch — or an empty
``current``, meaning the chain never ran — stops the container with the
reason on stderr. A service booting on an empty schema is the failure this
replaces, and it must not be reachable by a wrapper that only checks an exit
code.

Why the owner credential, and why a subprocess
----------------------------------------------

Alembic issues DDL. The runtime role every service serves requests as holds
no ``CREATE`` on schema public, by design — that is what stops it turning
row-level security off — so the chain must be applied as the owner. Each
``env.py`` already resolves that (its own ``*_DATABASE_MIGRATION_URL``
first, then ``DATABASE_MIGRATION_URL``), and this runs alembic as a
subprocess precisely so ``env.py`` stays the single answer to "which
credential". A second resolution here would be a second thing to keep in
step, and the two would disagree the first time either changed.

This module is vendored per service because services do not share a Python
path. ``scripts/check_service_migration_bootstrap.py`` is the gate that each
of the four ships a copy, keeps them identical, and runs one on the way up.

Usage
-----

::

    python -m app._migrate                       # apply the chain, exit
    python -m app._migrate -- uvicorn app.main:app --port 8004
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

#: Where ``alembic.ini`` sits relative to the working directory in every one
#: of the four images (``WORKDIR /app``, and the ini is copied to ``/app``).
ALEMBIC_INI = "alembic.ini"

#: Suffix that marks a DSN as the migration (owner) credential. Matches the
#: convention each ``env.py`` documents and ``scripts/check_runtime_db_role.py``
#: enforces on the deployment surfaces: a service-prefixed
#: ``<SVC>_DATABASE_MIGRATION_URL`` wins over the bare form.
MIGRATION_URL_SUFFIX = "DATABASE_MIGRATION_URL"


def migration_credential_present(env: dict[str, str] | None = None) -> bool:
    """Whether an owner DSN is configured.

    Used only for the warning below. The chain is applied either way — a
    deployment that has not split the roles yet behaves as it did before —
    but it is announced, because a chain silently applied as the runtime
    credential fails on the first ``CREATE TABLE`` and the message names a
    permission rather than a configuration.
    """
    source = os.environ if env is None else env
    return any(name.endswith(MIGRATION_URL_SUFFIX) and value.strip() for name, value in source.items())


def _alembic(args: list[str], *, capture: bool) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 — fixed argv, no shell
        [sys.executable, "-m", "alembic", "-c", ALEMBIC_INI, *args],
        capture_output=capture,
        text=True,
        check=False,
    )


def _revisions(output: str) -> set[str]:
    """Revision ids in ``alembic current`` / ``alembic heads`` output.

    Both print ``<rev> (head)`` or ``<rev>``, one per line, with informational
    lines alembic sends to stderr. An empty set means the version table holds
    nothing — the chain has not run — which is the case this exists to catch
    and is therefore never treated as agreement.
    """
    found: set[str] = set()
    for line in output.splitlines():
        token = line.strip().split(" ")[0].strip()
        if token and not token.startswith(("INFO", "WARNING", "ERROR", "alembic:")):
            found.add(token)
    return found


def apply_chain() -> int:
    """Apply the chain and verify it reached head. Returns an exit code."""
    if not Path(ALEMBIC_INI).is_file():
        print(
            f"migrate: {ALEMBIC_INI} not found in {Path.cwd()}. This service's image must "
            f"copy its alembic config and chain; see its Dockerfile.",
            file=sys.stderr,
        )
        return 1

    if not migration_credential_present():
        print(
            f"migrate: no *{MIGRATION_URL_SUFFIX} is set, so the chain will be applied as "
            f"the runtime credential. That works only while the two are the same role; "
            f"under the DML-only runtime role the first CREATE TABLE fails with "
            f"'permission denied for schema public'.",
            file=sys.stderr,
        )

    upgrade = _alembic(["upgrade", "head"], capture=False)
    if upgrade.returncode != 0:
        print(
            f"migrate: 'alembic upgrade head' failed (exit {upgrade.returncode}). Refusing to "
            f"start: this service would serve requests against whatever schema is there now.",
            file=sys.stderr,
        )
        return upgrade.returncode

    # Read back rather than trusting the exit code. `alembic upgrade head`
    # exits 0 having applied nothing when it believes the database is already
    # at head, and believing that wrongly is the documented way these four
    # services ended up with no tables.
    current = _alembic(["current"], capture=True)
    heads = _alembic(["heads"], capture=True)
    if current.returncode != 0 or heads.returncode != 0:
        print(
            "migrate: could not read back the applied revision "
            f"(current exit {current.returncode}, heads exit {heads.returncode}). "
            "Refusing to start: an unverified migration is the state this check exists "
            "to reject.\n"
            f"{(current.stderr or '') + (heads.stderr or '')}",
            file=sys.stderr,
        )
        return 1

    applied = _revisions(current.stdout)
    expected = _revisions(heads.stdout)

    if not expected:
        print(
            "migrate: this chain declares no head revision, so there is nothing to verify "
            "against. Refusing to start rather than reporting an empty chain as applied.",
            file=sys.stderr,
        )
        return 1

    if not applied:
        print(
            f"migrate: 'alembic upgrade head' reported success but the version table is "
            f"empty — the chain never ran. Expected {sorted(expected)}. Refusing to start "
            f"on an unmigrated schema.",
            file=sys.stderr,
        )
        return 1

    if not expected.issubset(applied):
        print(
            f"migrate: chain did not reach head. At {sorted(applied)}, head is {sorted(expected)}. Refusing to start.",
            file=sys.stderr,
        )
        return 1

    print(f"migrate: schema at head {sorted(expected)}", file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)

    # Everything after `--` is the real service command. Exec'd rather than
    # spawned so the server keeps PID 1 and receives SIGTERM directly — a
    # Python parent waiting on a child swallows the orchestrator's stop
    # signal and turns every shutdown into a ten-second kill.
    command: list[str] = []
    if "--" in args:
        split = args.index("--")
        command = args[split + 1 :]
        args = args[:split]

    if args:
        print(f"migrate: unexpected arguments {args}; usage: python -m app._migrate [-- CMD ...]", file=sys.stderr)
        return 2

    code = apply_chain()
    if code != 0:
        return code

    if command:
        os.execvp(command[0], command)  # noqa: S606 — replaces this process by design
    return 0


if __name__ == "__main__":
    sys.exit(main())
