"""The documented upgrade path applies migrations, and `make up` says when it has not.

The defect this exists to prevent
---------------------------------
`services/api/app/main.py` runs the SQL migration chain only when
`AISOC_DEMO_MODE` is set or `ENVIRONMENT` is dev-class. Both
`docker-compose.yml` and `.env.example` default `ENVIRONMENT` to `production`,
the Postgres initdb hook fires only on an empty data directory, and the `api`
service has no `command:` override — so `docker compose pull && up -d` on an
existing deployment booted new code against the old schema, reported healthy,
and said nothing. The comment above that branch blamed "a managed migration
pipeline" that exists in neither compose nor Helm.

The three properties below are what closes it, and each is written so that
removing the fix fails it:

1. a populated database sitting at an older point in the chain is *detected*
   as behind, by name, over a real Postgres (`test_live_*`);
2. `make up` consults that detector before it starts anything, so the silent
   boot cannot happen;
3. every path that applies migrations sets `AISOC_MIGRATIONS_STRICT`, because
   the runner's default is to log a failure and `return` — exit 0 with a
   partially-applied schema.

The live tests talk to a real Postgres because the detector's whole job is to
read one. A fake connection that answers any query would pass against a
detector that never looked, which is the failure mode this repository has
measured more than any other.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import time
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MAKEFILE = ROOT / "Makefile"
DETECTOR = ROOT / "scripts/pending_migrations.py"
MIGRATIONS = ROOT / "services" / "api" / "migrations"
CLI_MAIN = ROOT / "packages" / "aisoc-cli" / "src" / "aisoc_cli" / "main.py"

#: The name the runner checks before it does anything a strict mode could
#: catch. Spelled once so a rename has to come through here.
STRICT = "AISOC_MIGRATIONS_STRICT"


# ── helpers ──────────────────────────────────────────────────────────────────


def _own_recipe(target: str) -> str:
    """One target's prerequisites and recipe lines, verbatim."""
    text = MAKEFILE.read_text(encoding="utf-8")
    match = re.search(rf"^{re.escape(target)}:([^\n]*)\n((?:\t[^\n]*\n|\n)*)", text, re.MULTILINE)
    assert match, f"no `{target}:` target in the Makefile"
    return match.group(1) + "\n" + match.group(2)


def _recipe(target: str, _seen: frozenset[str] = frozenset()) -> str:
    """A target's recipe with its prerequisites and `$(MAKE)` delegations inlined.

    The first draft of this read one target's text, which asserted on a proxy
    rather than on the property: `upgrade` delegates the migration to
    `_migrate`, so "does the upgrade path run migrations with strict mode on"
    is a question about the whole path and not about one recipe. Splitting a
    target in two would otherwise silently empty the assertion.

    Parsed rather than executed, so this runs on a machine with no Docker and
    no stack — which is where the lint job is.
    """
    assert target not in _seen, f"recursive Makefile target: {target}"
    body = _own_recipe(target)
    seen = _seen | {target}
    out = []
    for line in body.splitlines(keepends=True):
        out.append(line)
        for sub in re.findall(r"\$\(MAKE\)(?:\s+--no-print-directory)?\s+([A-Za-z0-9_.-]+)", line):
            try:
                out.append(_recipe(sub, seen))
            except AssertionError:
                # A delegation to a target defined elsewhere (or a variable).
                # Leave the call site in place; the caller still sees the name.
                pass
    prereqs = body.split("\n", 1)[0]
    for sub in prereqs.split():
        if sub.startswith("_"):
            try:
                out.append(_recipe(sub, seen))
            except AssertionError:
                # Deliberate, and the same case as above: a prerequisite that
                # resolves to no target in this file (a variable, or one
                # defined by an include) contributes nothing to inline. The
                # comment lives inside the clause because `py/empty-except`
                # cannot see one placed after the block.
                pass
    return "".join(out)


def _docker() -> str | None:
    if not shutil.which("docker"):
        return None
    probe = subprocess.run(
        ["docker", "version", "--format", "{{.Server.Version}}"],
        capture_output=True,
        text=True,
    )
    return shutil.which("docker") if probe.returncode == 0 else None


requires_docker = pytest.mark.skipif(
    _docker() is None,
    reason="needs a reachable Docker daemon; the static assertions above still run",
)


# ── 1. detection, against a real populated database ──────────────────────────


@pytest.fixture(scope="module")
def live_pg() -> Iterator[str]:
    """A throwaway Postgres, reached only through `docker exec`.

    No published port on purpose. Several worktrees run against this daemon
    at once and a host port is a first-come namespace — the first draft of
    this fixture picked 55433 and lost it to a lane that had already taken
    it. Nothing here needs a port: psql runs inside the container.
    """
    name = f"aisoc-updinfra-pg-{uuid.uuid4().hex[:8]}"
    subprocess.run(
        [
            "docker",
            "run",
            "-d",
            "--rm",
            "--name",
            name,
            "-e",
            "POSTGRES_PASSWORD=probe",
            "-e",
            "POSTGRES_USER=aisoc",
            "-e",
            "POSTGRES_DB=aisoc",
            "postgres:16-alpine",
        ],
        check=True,
        capture_output=True,
    )
    try:
        for _ in range(60):
            ready = subprocess.run(
                ["docker", "exec", name, "pg_isready", "-h", "127.0.0.1", "-U", "aisoc"],
                capture_output=True,
            )
            if ready.returncode == 0:
                break
            time.sleep(1)
        else:
            pytest.fail("Postgres never became ready")
        yield name
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)


def _psql(container: str, sql: str) -> str:
    out = subprocess.run(
        ["docker", "exec", "-i", container, "psql", "-h", "127.0.0.1", "-U", "aisoc", "-d", "aisoc", "-tAc", sql],
        capture_output=True,
        text=True,
    )
    assert out.returncode == 0, out.stderr
    return out.stdout.strip()


def _detect(container: str) -> subprocess.CompletedProcess[str]:
    """Run the detector against the live container.

    `AISOC_PG_PSQL` is the seam: the Makefile points it at `docker compose
    exec postgres psql`, and a test points it at a plain `docker exec`. The
    detector still does the reading and the comparison, so what is under test
    is the detector and not a stand-in for it.
    """
    env = dict(os.environ)
    env["AISOC_PG_PSQL"] = f"docker exec -i {container} psql -h 127.0.0.1 -U aisoc -d aisoc"
    return subprocess.run(
        [sys.executable, str(DETECTOR)],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(ROOT),
    )


def _on_disk() -> list[str]:
    # The same ordering and the same name the runner records:
    # `sorted(... if p.suffix == ".sql")`, keyed on `path.name`.
    return sorted(p.name for p in MIGRATIONS.iterdir() if p.suffix == ".sql")


@requires_docker
def test_live_empty_database_is_fresh_not_behind(live_pg: str) -> None:
    """An empty database is the initdb hook's job, not the upgrade path's.

    Reporting `behind` here would refuse every first run, which is a worse
    defect than the one being fixed.
    """
    result = _detect(live_pg)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "fresh" in result.stdout.lower(), result.stdout


@requires_docker
def test_live_populated_database_behind_the_chain_is_named(live_pg: str) -> None:
    """The case that reaches operators: data present, schema older than the code.

    This is the shape `docker compose pull && up -d` produced silently. The
    detector has to notice *and* say which migrations are missing, because
    "something is wrong" sends an operator to read logs that say nothing.
    """
    on_disk = _on_disk()
    assert len(on_disk) > 10, "guard: the chain should be long enough for this to mean something"
    applied, pending = on_disk[:-3], on_disk[-3:]

    _psql(live_pg, "CREATE TABLE IF NOT EXISTS aisoc_schema_migrations (name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ DEFAULT now())")
    # Populated: the whole point is that this is not an empty schema the
    # operator could simply drop and recreate.
    _psql(live_pg, "CREATE TABLE IF NOT EXISTS alerts (id BIGSERIAL PRIMARY KEY, title TEXT)")
    _psql(live_pg, "INSERT INTO alerts (title) VALUES ('an alert the operator cannot lose')")
    values = ",".join("('" + name.replace("'", "''") + "')" for name in applied)
    _psql(live_pg, f"INSERT INTO aisoc_schema_migrations(name) VALUES {values} ON CONFLICT DO NOTHING")

    result = _detect(live_pg)
    assert result.returncode == 3, f"expected exit 3 (behind); got {result.returncode}\n{result.stdout}\n{result.stderr}"
    for name in pending:
        assert name in result.stdout, f"{name} missing from:\n{result.stdout}"
    # And it must not cry wolf about the ones that are applied.
    assert applied[-1] not in result.stdout

    # The row survives being looked at. A detector that drops the database to
    # answer the question would pass every assertion above.
    assert _psql(live_pg, "SELECT count(*) FROM alerts") == "1"


@requires_docker
def test_live_fully_applied_database_is_current(live_pg: str) -> None:
    """Ordering matters: this runs after the previous test has populated the
    table, and completes the chain. A detector that reported `behind`
    unconditionally would pass the test above and fail here."""
    _psql(live_pg, "CREATE TABLE IF NOT EXISTS aisoc_schema_migrations (name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ DEFAULT now())")
    values = ",".join("('" + name.replace("'", "''") + "')" for name in _on_disk())
    _psql(live_pg, f"INSERT INTO aisoc_schema_migrations(name) VALUES {values} ON CONFLICT DO NOTHING")

    result = _detect(live_pg)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "up to date" in result.stdout.lower(), result.stdout


@requires_docker
def test_live_unreadable_database_is_unknown_never_current(live_pg: str) -> None:
    """An unreachable store is not a clean one.

    "Unknown counted as clean" is the most-repeated gate defect in this
    repository, and a migration guard is exactly where it would do the most
    damage: it would restore the silence it exists to remove.
    """
    env = dict(os.environ)
    env["AISOC_PG_PSQL"] = "docker exec -i aisoc-updinfra-no-such-container psql -U aisoc"
    result = subprocess.run([sys.executable, str(DETECTOR)], capture_output=True, text=True, env=env, cwd=str(ROOT))
    assert result.returncode == 4, f"expected exit 4 (unknown); got {result.returncode}\n{result.stdout}\n{result.stderr}"


def test_detector_refuses_a_tree_with_no_migrations(tmp_path: Path) -> None:
    """A gate that credits an empty tree credits every tree.

    The `DETECTOR.is_file()` line is not decoration: without it this test
    passed against the pre-fix tree, because `python3 <missing file>` also
    exits 2. A test that cannot tell "refused correctly" from "was never
    written" is not evidence of either.
    """
    assert DETECTOR.is_file(), f"{DETECTOR} does not exist"
    (tmp_path / ".git").mkdir()
    result = subprocess.run(
        [sys.executable, str(DETECTOR)],
        capture_output=True,
        text=True,
        cwd=str(tmp_path),
        env={**os.environ, "AISOC_REPO_ROOT": str(tmp_path)},
    )
    assert result.returncode == 2, result.stdout + result.stderr


# ── 2. `make up` consults it; `make upgrade` is the consenting path ──────────


def test_make_up_checks_the_schema_before_starting_anything() -> None:
    """`make up` has to look before it leaps.

    Pre-fix this target went straight to `compose up -d`, which is how a
    stack came up healthy on last release's schema.
    """
    recipe = _recipe("up")
    assert "_schema_guard" in recipe, (
        "`make up` does not consult the schema guard; an existing database whose "
        f"schema is behind the code would start silently.\nrecipe was:\n{recipe}"
    )


def test_schema_guard_runs_before_compose_up() -> None:
    """Order is the property, not presence.

    A guard that runs after `compose up -d` reports a problem the operator
    already has.
    """
    recipe = _recipe("up")
    guard = recipe.index("_schema_guard")
    body = recipe[guard:]
    assert "up -d" not in recipe[:guard], "the stack is started before the schema is checked:\n" + recipe
    assert body  # the guard is a prerequisite, so everything after it is the recipe


def test_upgrade_target_exists_and_is_ordered() -> None:
    """backup -> migrate -> start, in that order, in one documented command."""
    text = MAKEFILE.read_text(encoding="utf-8")
    assert re.search(r"^upgrade:", text, re.MULTILINE), "no `make upgrade` target"
    recipe = _recipe("upgrade")
    for token in ("preflight_upgrade.py", "run_migrations"):
        assert token in recipe, f"`make upgrade` never runs {token}:\n{recipe}"
    assert recipe.index("preflight_upgrade.py") < recipe.index("run_migrations"), (
        "the preflight runs after the migration, which is too late to refuse"
    )


def test_upgrade_is_declared_phony_and_advertised() -> None:
    """An undocumented command is one nobody runs. `make help` is the index."""
    text = MAKEFILE.read_text(encoding="utf-8")
    phony = re.search(r"^\.PHONY:((?:[^\n]*\\\n)*[^\n]*)", text, re.MULTILINE)
    assert phony and "upgrade" in phony.group(1), "`upgrade` is not in .PHONY"
    assert "make upgrade" in text, "`make upgrade` is never named in the help output"


# ── 3. strict mode, everywhere migrations are applied ────────────────────────


def test_make_upgrade_sets_strict_mode() -> None:
    """Without it the runner logs the failure and returns: exit 0 over a
    partially-applied schema, which is the worst of both outcomes."""
    recipe = _recipe("upgrade")
    assert STRICT in recipe, (
        f"`make upgrade` applies migrations without {STRICT}; a failed migration "
        f"would exit 0 and the upgrade would report success.\n{recipe}"
    )


def test_cli_db_upgrade_sets_strict_mode_inside_the_container() -> None:
    """`docker compose exec` inherits the *container's* environment.

    Setting the variable in the operator's shell does nothing, which is why
    the warning in the upgrade documentation was unreachable through the
    documented command. It has to be passed with `-e`.
    """
    source = CLI_MAIN.read_text(encoding="utf-8")
    block = source[source.index('@db.command("upgrade")') : source.index("# ── mcp group")]
    assert STRICT in block, f"`aisoc db upgrade` never sets {STRICT}"

    # The command list only. Asserting against the whole function body matched
    # the docstring's own mention of `app.scripts.run_migrations`, so the
    # ordering check compared a position in prose against one in code and
    # failed on a correct fix.
    # Ends at the list's own closing bracket at statement indentation, not at
    # the first `]` in the text — the conditional `*([...] if strict else [])`
    # carries two of its own and slicing to the first one cut the list in half.
    start = block.index("cmd = [")
    end = block.index("\n    ]", start)
    # Comments stripped, for the same reason the docstring is excluded above:
    # an ordering assertion that can match a word in prose is comparing the
    # position of an explanation against the position of a flag. The comment
    # explaining why `-e` precedes the service name contains "service", and
    # that alone failed this test against a correct fix.
    cmd = "\n".join(line.split("#", 1)[0] for line in block[start:end].splitlines() if line.strip())
    assert '"-e"' in cmd, (
        "the variable is named but not passed to `docker compose exec` with "
        "`-e`, so it stays in the caller's shell and never reaches the "
        f"container:\n{cmd}"
    )
    assert cmd.index('"-e"') < cmd.index("run_migrations"), (
        f"`-e` appears after the module argument, where docker treats it as an argument to the command rather than as an exec flag:\n{cmd}"
    )
    assert cmd.index('"-e"') < cmd.index("service"), f"`-e` appears after the service name, where docker stops parsing exec flags:\n{cmd}"
