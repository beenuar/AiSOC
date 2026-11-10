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

import ast
import importlib.util
import os
import re
import shutil
import subprocess
import sys
import time
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
MAKEFILE = ROOT / "Makefile"
DETECTOR = ROOT / "scripts/pending_migrations.py"
#: The one implementation of the on-disk-versus-applied comparison. Section 4
#: is what keeps it the only one.
SKEW_MODULE = ROOT / "services/api/app/services/schema_skew.py"
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


@pytest.fixture(scope="module")
def live_pg_initdb() -> Iterator[str]:
    """A throwaway Postgres built the way `make up` builds one.

    The repository's own initdb hooks are mounted, so the migration chain is
    applied by `infra/postgres/initdb/10_apply_migrations.sh` as the data
    directory is created — the exact state the detector reads on the first
    run of a fresh install. The plain `live_pg` fixture above cannot stand in
    for this: it starts empty, and the defect this exists to catch lives in
    what the hook does and does not leave behind.
    """
    name = f"aisoc-updinfra-initdb-pg-{uuid.uuid4().hex[:8]}"
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
            "-v",
            f"{ROOT / 'infra' / 'postgres' / 'initdb'}:/docker-entrypoint-initdb.d:ro",
            "-v",
            f"{MIGRATIONS}:/aisoc/migrations:ro",
            "postgres:16-alpine",
        ],
        check=True,
        capture_output=True,
    )
    try:
        # The hook applies the whole chain before the real server starts, and
        # `pg_isready` over TCP cannot succeed against the temporary initdb
        # server (`listen_addresses=''`) — same reasoning as the Makefile's
        # `_wait_postgres`. So readiness here means "installed", not merely
        # "booted", which is why the deadline is generous: it waits out ~160
        # migration files, not a container start.
        for _ in range(240):
            ready = subprocess.run(
                ["docker", "exec", name, "pg_isready", "-h", "127.0.0.1", "-U", "aisoc"],
                capture_output=True,
            )
            if ready.returncode == 0:
                break
            time.sleep(1)
        else:
            logs = subprocess.run(["docker", "logs", name], capture_output=True, text=True)
            pytest.fail(f"initdb Postgres never became ready; container logs:\n{logs.stdout}\n{logs.stderr}")
        yield name
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)


@requires_docker
def test_live_initdb_installed_database_is_current(live_pg_initdb: str) -> None:
    """A database the initdb hook has just fully built must read as current.

    Before the hook recorded what it applied, this state — every table
    present, no `aisoc_schema_migrations` — read as *behind the entire
    chain*, so the very first `make up` built the schema and then refused to
    start the stack it had just built, and the `make upgrade` it suggested
    re-applied all ~160 files under strict mode. Reported by a community
    contributor on #353.
    """
    # Guard: the hook really ran. Without this, an image that silently skipped
    # its init hooks would turn the assertion below into the `fresh` case,
    # which passes for the wrong reason.
    tables = int(_psql(live_pg_initdb, "SELECT count(*) FROM pg_tables WHERE schemaname = 'public'"))
    assert tables > 50, f"initdb hook does not appear to have applied the chain ({tables} tables)"

    result = _detect(live_pg_initdb)
    assert result.returncode == 0, f"expected exit 0 (up to date); got {result.returncode}\n{result.stdout}\n{result.stderr}"
    assert "up to date" in result.stdout.lower(), result.stdout

    # And the record matches the chain exactly, by name — the same names the
    # runtime runner would have recorded, so an upgrade in place starts from
    # the truth rather than from zero.
    recorded = {line.strip() for line in _psql(live_pg_initdb, "SELECT name FROM aisoc_schema_migrations").splitlines() if line.strip()}
    assert recorded == set(_on_disk())


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


# ── 4. one comparison, two policies ──────────────────────────────────────────
#
# `scripts/pending_migrations.py` and `services/api/app/services/schema_skew.py`
# ask the same question of the same two sets. They used to answer it with two
# copies of the set arithmetic, which had already drifted — the service
# skipped a directory named `*.sql` and the script counted it — and this
# repository has shipped that shape twice before, as two case tables and two
# `playbook.schema.json` files.
#
# The arithmetic is now one implementation. What stays different is the
# verdict on exactly one case, and these tests are what stop a second
# difference appearing without anyone deciding on it.


def _detector_module() -> Any:
    """`scripts/pending_migrations.py`, imported rather than run."""
    spec = importlib.util.spec_from_file_location("_aisoc_pending_migrations_under_test", DETECTOR)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_detector_reads_the_services_comparison_rather_than_keeping_a_copy() -> None:
    """There is one implementation, and the script is pointed at it."""
    detector = _detector_module()

    assert detector._SKEW_MODULE == SKEW_MODULE, "the detector is pointed at some other file"
    assert SKEW_MODULE.is_file(), "the shared comparison is not where the detector looks for it"

    skew = detector._schema_skew()
    assert skew is not None, "the detector could not load the shared comparison"
    assert Path(skew.__file__).resolve() == SKEW_MODULE

    for name in ("migrations_on_disk", "pending"):
        assert not hasattr(detector, name), (
            f"`{name}` is defined in the detector again. The comparison belongs in "
            f"{SKEW_MODULE.name}; a second copy here is the drift this section exists to stop."
        )


def test_the_shared_comparison_stays_importable_from_a_script() -> None:
    """Its pure half imports nothing but the standard library.

    This is the property that lets one implementation serve both callers:
    `scripts/` and `services/api` share no Python path and no dependency set,
    so a module-scope `from sqlalchemy import ...` would force the script
    back to a copy of its own. The database read defers its imports for
    exactly this reason.
    """
    tree = ast.parse(SKEW_MODULE.read_text(encoding="utf-8"))
    roots: set[str] = set()
    for node in tree.body:  # top level only; deferred imports live inside functions
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".")[0])
    third_party = sorted(r for r in roots if r not in sys.stdlib_module_names)
    assert third_party == [], (
        f"{SKEW_MODULE.name} imports {third_party} at module scope, so a script cannot "
        "load it and the comparison has to be duplicated again. Defer the import into "
        "the function that needs it."
    )


#: Every shape the two callers can be handed. `applied=None` is the database
#: that could not be read, which is not the same as one that has applied
#: nothing.
_SKEW_CASES: tuple[tuple[str, set[str] | None, list[str]], ...] = (
    ("nothing anywhere", set(), []),
    ("fully applied", {"001_a.sql", "002_b.sql"}, ["001_a.sql", "002_b.sql"]),
    ("one pending", {"001_a.sql"}, ["001_a.sql", "002_b.sql"]),
    ("all pending", set(), ["001_a.sql", "002_b.sql"]),
    ("applied but not on disk", {"001_a.sql", "009_rolled_back.sql"}, ["001_a.sql"]),
    ("both directions at once", {"001_a.sql", "009_rolled_back.sql"}, ["001_a.sql", "002_b.sql"]),
    ("unreadable database", None, ["001_a.sql"]),
)

#: The one case the two are allowed to disagree on, named so that a second
#: one cannot appear silently.
_DECLARED_DIVERGENCE = "applied but not on disk"


@pytest.mark.parametrize(("label", "applied", "on_disk"), _SKEW_CASES, ids=[c[0] for c in _SKEW_CASES])
def test_the_two_callers_agree_except_on_the_declared_case(label: str, applied: set[str] | None, on_disk: list[str]) -> None:
    """`/readyz` healthy and `pending_migrations` exit 0 mean the same thing — once."""
    detector = _detector_module()
    skew = detector._schema_skew()
    verdict = skew.evaluate_skew(applied=applied, on_disk=on_disk)
    code = detector.exit_code_for(verdict)

    if label == _DECLARED_DIVERGENCE:
        assert verdict.state == "skewed" and not verdict.pending and verdict.applied_not_on_disk
        assert verdict.healthy is False, "the service must still call a rollback skew"
        assert code == detector.OK, (
            "the detector must still exit 0: it answers 'run `make upgrade`?', and "
            "upgrading applies migrations forward, so it cannot fix a rollback"
        )
        return

    assert verdict.healthy == (code == detector.OK), (
        f"{label}: the service says healthy={verdict.healthy} and the detector exits {code}. "
        f"Only '{_DECLARED_DIVERGENCE}' is allowed to disagree, and that difference is "
        "stated in the detector's docstring and implemented in one branch of `exit_code_for`."
    )


def test_an_unreadable_database_is_never_a_pass_on_either_side() -> None:
    """The unknown bucket is not a clean bill of health for either caller."""
    detector = _detector_module()
    skew = detector._schema_skew()
    verdict = skew.evaluate_skew(applied=None, on_disk=["001_a.sql"], reason="probe failed")
    assert verdict.state == "unknown"
    assert verdict.healthy is False
    assert detector.exit_code_for(verdict) == detector.UNKNOWN
