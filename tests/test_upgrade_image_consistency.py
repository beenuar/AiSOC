"""An upgrade must migrate the checkout it claims to have upgraded.

The subprocess tests execute the real Makefile and the image-side Python
command. A small Compose adapter supplies an isolated filesystem in place of
a container; its runner is an execution marker, not a database implementation.
These tests prove refusal and orchestration, not Docker or PostgreSQL behavior.
"""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_upgrade_helper_self_test_refuses_empty_tree() -> None:
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/upgrade_migrations.py"), "--self-test"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "refuses" in result.stdout


def _upgrade_fixture(tmp_path: Path) -> tuple[Path, Path, Path, str]:
    checkout = tmp_path / "checkout"
    image = tmp_path / "image"
    scripts = checkout / "scripts"
    scripts.mkdir(parents=True)
    migrations = checkout / "services/api/migrations"
    migrations.mkdir(parents=True)
    (migrations / "001_initial.sql").write_text("SELECT 1;\n", encoding="utf-8")
    (migrations / "002_next.sql").write_text("SELECT 2;\n", encoding="utf-8")
    (image / "migrations").mkdir(parents=True)
    shutil.copy(migrations / "001_initial.sql", image / "migrations/001_initial.sql")
    package = image / "app/scripts"
    package.mkdir(parents=True)
    (image / "app/__init__.py").write_text("", encoding="utf-8")
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "run_migrations.py").write_text(
        "import os\nfrom pathlib import Path\n"
        "MIGRATIONS_DIR = Path(__file__).resolve().parents[2] / 'migrations'\n"
        "if __name__ == '__main__':\n"
        "    Path(os.environ['RUNNER_MARKER']).write_text(os.environ.get('AISOC_MIGRATIONS_STRICT', ''))\n"
        "    raise SystemExit(int(os.environ.get('RUNNER_EXIT', '0')))\n",
        encoding="utf-8",
    )
    (scripts / "preflight_upgrade.py").write_text("", encoding="utf-8")
    for name in ("upgrade_migrations.py", "pending_migrations.py", "gate_toolkit.py"):
        source = ROOT / "scripts" / name
        if source.is_file():
            shutil.copy(source, scripts / name)
    service = checkout / "services/api/app/services"
    service.mkdir(parents=True)
    shutil.copy(ROOT / "services/api/app/services/schema_skew.py", service / "schema_skew.py")
    # Unrelated prerequisites are outside this migration-path regression.
    overrides = "\n".join(f"{target}:\n\t@true\n" for target in ("_upgrade_backup", "_refresh", "_ports", "_wait", "_wait_postgres"))
    (checkout / "Makefile").write_text((ROOT / "Makefile").read_text(encoding="utf-8") + "\n" + overrides, encoding="utf-8")
    adapter = tmp_path / "compose adapter.py"
    adapter.write_text(
        "import json, os, subprocess, sys\n"
        "from pathlib import Path\n"
        "args = sys.argv[1:]\n"
        "with open(os.environ['COMPOSE_CALLS'], 'a') as out:\n"
        "    out.write(json.dumps(args) + '\\n')\n"
        "if 'run' in args:\n"
        "    split = args.index('api')\n"
        "    command = args[split + 1:]\n"
        "    assert command[0] == 'python', command\n"
        "    env = dict(os.environ)\n"
        "    for i, arg in enumerate(args[:split]):\n"
        "        if arg == '-e':\n"
        "            key, _, value = args[i + 1].partition('=')\n"
        "            env[key] = value\n"
        "    raise SystemExit(subprocess.run([sys.executable, *command[1:]], cwd=os.environ['IMAGE_ROOT'], env=env).returncode)\n",
        encoding="utf-8",
    )
    # The detector contract cases use explicit psql responses; the live tests
    # below exercise those queries against PostgreSQL instead.
    with adapter.open("a", encoding="utf-8") as output:
        output.write(
            "if 'exec' in args and 'psql' in args:\n"
            "    mode = os.environ.get('LEDGER_MODE', 'current')\n"
            "    if mode == 'unknown':\n"
            "        raise SystemExit(19)\n"
            "    sql = args[-1]\n"
            "    if sql.startswith('SELECT to_regclass('):\n"
            "        if mode != 'empty_database':\n"
            "            print('aisoc_schema_migrations')\n"
            "    elif sql == 'SELECT name FROM aisoc_schema_migrations':\n"
            "        print('001_initial.sql')\n"
            "        if mode == 'current':\n"
            "            print('002_next.sql')\n"
            "    elif sql == \"SELECT count(*) FROM pg_tables WHERE schemaname = 'public'\":\n"
            "        print('0')\n"
            "    else:\n"
            "        raise AssertionError('unexpected SQL: ' + sql)\n"
        )
    compose = f"{shlex.quote(sys.executable)} {shlex.quote(str(adapter))} -f base.yml -f 'provider config.yml'"
    return checkout, image, tmp_path / "runner-started", compose


def _run_upgrade(
    tmp_path: Path,
    checkout: Path,
    image: Path,
    marker: Path,
    compose: str,
    *,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["make", "--no-print-directory", "upgrade", f"COMPOSE={compose}", f"PYTHON={sys.executable}"],
        cwd=checkout,
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "AISOC_REPO_ROOT": str(checkout),
            "IMAGE_ROOT": str(image),
            "RUNNER_MARKER": str(marker),
            "COMPOSE_CALLS": str(tmp_path / "compose.jsonl"),
            **(extra_env or {}),
        },
    )


def test_missing_image_migration_prevents_upgrade_success(tmp_path: Path) -> None:
    checkout, image, marker, compose = _upgrade_fixture(tmp_path)
    result = _run_upgrade(tmp_path, checkout, image, marker, compose)
    assert result.returncode != 0, result.stdout + result.stderr
    assert "002_next.sql" in result.stdout + result.stderr
    assert not marker.exists(), "the stale image ran migrations before its missing SQL was detected"
    calls = [json.loads(line) for line in (tmp_path / "compose.jsonl").read_text(encoding="utf-8").splitlines()]
    assert not any(call[-2:] == ["up", "-d"] for call in calls)
    assert "Upgrade complete" not in result.stdout


def _compose_calls(tmp_path: Path) -> list[list[str]]:
    log = tmp_path / "compose.jsonl"
    return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()] if log.exists() else []


@pytest.mark.parametrize("mismatch", ["extra", "changed", "empty", "missing_directory"])
def test_image_mismatch_never_reaches_migration_runner(tmp_path: Path, mismatch: str) -> None:
    checkout, image, marker, compose = _upgrade_fixture(tmp_path)
    shutil.copy(checkout / "services/api/migrations/002_next.sql", image / "migrations/002_next.sql")
    if mismatch == "extra":
        (image / "migrations/003_future.sql").write_text("SELECT 3;\n", encoding="utf-8")
    elif mismatch == "changed":
        (image / "migrations/001_initial.sql").write_text("SELECT 99;\n", encoding="utf-8")
    else:
        for sql in (image / "migrations").iterdir():
            sql.unlink()
        if mismatch == "missing_directory":
            (image / "migrations").rmdir()
    result = _run_upgrade(tmp_path, checkout, image, marker, compose)
    assert result.returncode != 0, result.stdout + result.stderr
    assert not marker.exists()
    if mismatch == "extra":
        assert "003_future.sql" in result.stdout + result.stderr
    elif mismatch == "changed":
        assert "001_initial.sql" in result.stdout + result.stderr
    assert "Upgrade complete" not in result.stdout
    assert not any(call[-2:] == ["up", "-d"] for call in _compose_calls(tmp_path))


@pytest.mark.parametrize("remove_directory", [False, True])
def test_empty_checkout_is_not_compared_as_current(tmp_path: Path, remove_directory: bool) -> None:
    checkout, image, marker, compose = _upgrade_fixture(tmp_path)
    migrations = checkout / "services/api/migrations"
    for sql in migrations.iterdir():
        sql.unlink()
    if remove_directory:
        migrations.rmdir()
    result = _run_upgrade(tmp_path, checkout, image, marker, compose)
    assert result.returncode != 0, result.stdout + result.stderr
    assert not marker.exists()
    assert not any("run" in call for call in _compose_calls(tmp_path))
    assert "Upgrade complete" not in result.stdout


def test_matching_migrations_run_once_with_compose_options_and_strict_mode(tmp_path: Path) -> None:
    checkout, image, marker, compose = _upgrade_fixture(tmp_path)
    shutil.copy(checkout / "services/api/migrations/002_next.sql", image / "migrations/002_next.sql")
    result = _run_upgrade(tmp_path, checkout, image, marker, compose)
    assert result.returncode == 0, result.stdout + result.stderr
    assert marker.read_text(encoding="utf-8") == "1"
    calls = _compose_calls(tmp_path)
    runs = [call for call in calls if "run" in call]
    assert len(runs) == 1, "comparison and migration must use the same one-off container"
    assert runs[0][:4] == ["-f", "base.yml", "-f", "provider config.yml"]
    assert all(flag in runs[0] for flag in ("--rm", "--no-deps", "-T"))
    assert runs[0].index("AISOC_MIGRATIONS_STRICT=1") < runs[0].index("api")
    postcheck = next(call for call in calls if "SELECT name FROM aisoc_schema_migrations" in call)
    startup = next(call for call in calls if call[-2:] == ["up", "-d"])
    assert calls.index(runs[0]) < calls.index(postcheck) < calls.index(startup)
    assert "Upgrade complete" in result.stdout


@pytest.mark.parametrize("newline_side", ["checkout", "image"])
def test_line_endings_match_the_sql_executed_by_the_runner(tmp_path: Path, newline_side: str) -> None:
    checkout, image, marker, compose = _upgrade_fixture(tmp_path)
    shutil.copy(checkout / "services/api/migrations/002_next.sql", image / "migrations/002_next.sql")
    directory = checkout / "services/api/migrations" if newline_side == "checkout" else image / "migrations"
    for sql in directory.iterdir():
        sql.write_bytes(sql.read_bytes().replace(b"\n", b"\r\n"))
    result = _run_upgrade(tmp_path, checkout, image, marker, compose)
    assert result.returncode == 0, result.stdout + result.stderr
    assert marker.is_file()
    assert "Upgrade complete" in result.stdout


@pytest.mark.parametrize("invalid_side", ["checkout", "image", "both"])
def test_invalid_utf8_is_refused_before_migration(tmp_path: Path, invalid_side: str) -> None:
    checkout, image, marker, compose = _upgrade_fixture(tmp_path)
    shutil.copy(checkout / "services/api/migrations/002_next.sql", image / "migrations/002_next.sql")
    if invalid_side in {"checkout", "both"}:
        (checkout / "services/api/migrations/001_initial.sql").write_bytes(b"SELECT '\xff';\n")
    if invalid_side in {"image", "both"}:
        (image / "migrations/001_initial.sql").write_bytes(b"SELECT '\xff';\n")
    result = _run_upgrade(tmp_path, checkout, image, marker, compose)
    assert result.returncode != 0, result.stdout + result.stderr
    assert not marker.exists()
    assert "Upgrade complete" not in result.stdout


@pytest.mark.parametrize("ledger_mode", ["behind", "unknown", "empty_database"])
def test_upgrade_does_not_start_when_migration_postcondition_fails(tmp_path: Path, ledger_mode: str) -> None:
    checkout, image, marker, compose = _upgrade_fixture(tmp_path)
    shutil.copy(checkout / "services/api/migrations/002_next.sql", image / "migrations/002_next.sql")
    result = _run_upgrade(tmp_path, checkout, image, marker, compose, extra_env={"LEDGER_MODE": ledger_mode})
    assert marker.is_file(), "this regression must get past image verification and the runner"
    assert result.returncode != 0, result.stdout + result.stderr
    assert "Upgrade complete" not in result.stdout
    assert not any(call[-2:] == ["up", "-d"] for call in _compose_calls(tmp_path))
    if ledger_mode != "unknown":
        assert "002_next.sql" in result.stdout + result.stderr


def test_runner_failure_is_not_hidden_by_postcheck(tmp_path: Path) -> None:
    checkout, image, marker, compose = _upgrade_fixture(tmp_path)
    shutil.copy(checkout / "services/api/migrations/002_next.sql", image / "migrations/002_next.sql")
    result = _run_upgrade(tmp_path, checkout, image, marker, compose, extra_env={"RUNNER_EXIT": "23"})
    assert marker.is_file()
    assert result.returncode != 0, result.stdout + result.stderr
    assert "Upgrade complete" not in result.stdout
    assert not any("psql" in call for call in _compose_calls(tmp_path))


def test_normal_start_still_accepts_fresh_database(tmp_path: Path) -> None:
    checkout, image, marker, compose = _upgrade_fixture(tmp_path)
    probe = f"{compose} exec -T postgres psql -h 127.0.0.1 -U aisoc -d aisoc"
    env = {
        **os.environ,
        "AISOC_REPO_ROOT": str(checkout),
        "AISOC_PG_PSQL": probe,
        "LEDGER_MODE": "empty_database",
        "COMPOSE_CALLS": str(tmp_path / "compose.jsonl"),
    }
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/pending_migrations.py")],
        cwd=checkout,
        capture_output=True,
        text=True,
        env=env,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "fresh" in result.stdout
    assert not marker.exists()


# The live cases keep the API image's actual runner and locked dependencies.
# Only the SQL chain is replaced with a small fixture so the regression does
# not depend on unrelated service tables. CI builds services/api/Dockerfile
# and names that local image in AISOC_UPGRADE_TEST_IMAGE before running this.
LIVE_SQL = {
    "001_initial.sql": "CREATE TABLE aisoc_upgrade_existing (value TEXT); INSERT INTO aisoc_upgrade_existing VALUES ('keep');\n",
    "002_next.sql": "CREATE TABLE aisoc_upgrade_added (id BIGINT PRIMARY KEY);\n",
}


@pytest.fixture(scope="module")
def live_api_images(tmp_path_factory: pytest.TempPathFactory) -> Iterator[dict[str, str]]:
    base = os.environ.get("AISOC_UPGRADE_TEST_IMAGE")
    if not base:
        pytest.skip("set AISOC_UPGRADE_TEST_IMAGE to a locally built services/api image for the Docker regressions")
    assert base is not None
    assert shutil.which("docker"), "AISOC_UPGRADE_TEST_IMAGE is set but Docker is unavailable"
    inspect = subprocess.run(["docker", "image", "inspect", base], capture_output=True, text=True)
    assert inspect.returncode == 0, inspect.stderr
    build_root = tmp_path_factory.mktemp("upgrade-images")
    images = {state: f"aisoc-upgrade-regression:{uuid.uuid4().hex}-{state}" for state in ("stale", "matching")}
    try:
        for state, image in images.items():
            context = build_root / state
            migrations = context / "migrations"
            migrations.mkdir(parents=True)
            for name, sql in LIVE_SQL.items():
                if state == "matching" or name == "001_initial.sql":
                    (migrations / name).write_text(sql, encoding="utf-8")
            (context / "Dockerfile").write_text(
                "ARG API_IMAGE\nFROM ${API_IMAGE}\nRUN rm -rf /app/migrations\nCOPY migrations /app/migrations\n",
                encoding="utf-8",
            )
            build = subprocess.run(
                ["docker", "build", "--build-arg", f"API_IMAGE={base}", "-t", image, str(context)],
                capture_output=True,
                text=True,
                timeout=180,
            )
            assert build.returncode == 0, build.stdout + build.stderr
        yield images
    finally:
        subprocess.run(["docker", "image", "rm", "-f", *images.values()], capture_output=True)


@dataclass
class LiveUpgrade:
    checkout: Path
    compose: list[str]
    env: dict[str, str]
    images: dict[str, str]

    def psql(self, sql: str) -> str:
        result = subprocess.run(
            [*self.compose, "exec", "-T", "postgres", "psql", "-h", "127.0.0.1", "-U", "aisoc", "-d", "aisoc", "-tAc", sql],
            cwd=self.checkout,
            env=self.env,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        return result.stdout.strip()

    def migrate(self, image_state: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["make", "--no-print-directory", "_migrate", f"COMPOSE={shlex.join(self.compose)}", f"PYTHON={sys.executable}"],
            cwd=self.checkout,
            env={**self.env, "AISOC_UPGRADE_CASE_IMAGE": self.images[image_state]},
            capture_output=True,
            text=True,
            timeout=180,
        )


@pytest.fixture
def live_upgrade(tmp_path: Path, live_api_images: dict[str, str]) -> Iterator[LiveUpgrade]:
    checkout = tmp_path / "live checkout"
    scripts = checkout / "scripts"
    scripts.mkdir(parents=True)
    for name in ("upgrade_migrations.py", "pending_migrations.py", "gate_toolkit.py"):
        shutil.copy(ROOT / "scripts" / name, scripts / name)
    service = checkout / "services/api/app/services"
    service.mkdir(parents=True)
    shutil.copy(ROOT / "services/api/app/services/schema_skew.py", service / "schema_skew.py")
    migrations = checkout / "services/api/migrations"
    migrations.mkdir(parents=True)
    for name, sql in LIVE_SQL.items():
        (migrations / name).write_text(sql, encoding="utf-8")
    shutil.copy(ROOT / "Makefile", checkout / "Makefile")
    compose_file = checkout / "compose.yml"
    compose_file.write_text(
        "services:\n"
        "  postgres:\n"
        "    image: postgres:16-alpine\n"
        "    environment:\n"
        "      POSTGRES_USER: aisoc\n"
        "      POSTGRES_DB: aisoc\n"
        "      POSTGRES_PASSWORD: probe\n"
        "  api:\n"
        "    image: ${AISOC_UPGRADE_CASE_IMAGE}\n"
        "    environment:\n"
        "      ENVIRONMENT: production\n"
        "      DATABASE_URL: postgresql+asyncpg://aisoc:probe@postgres:5432/aisoc\n"
        "      DATABASE_MIGRATION_URL: postgresql+asyncpg://aisoc:probe@postgres:5432/aisoc\n"
        "      AISOC_APP_DB_PASSWORD: ''\n",
        encoding="utf-8",
    )
    compose = ["docker", "compose", "-p", f"aisoc-upgrade-{uuid.uuid4().hex[:12]}", "-f", str(compose_file)]
    env = {
        **os.environ,
        "AISOC_REPO_ROOT": str(checkout),
        "AISOC_UPGRADE_CASE_IMAGE": live_api_images["matching"],
    }
    deployment = LiveUpgrade(checkout, compose, env, live_api_images)
    try:
        start = subprocess.run([*compose, "up", "-d", "postgres"], env=env, capture_output=True, text=True)
        assert start.returncode == 0, start.stdout + start.stderr
        wait = subprocess.run(
            ["make", "--no-print-directory", "_wait_postgres", f"COMPOSE={shlex.join(compose)}"],
            cwd=checkout,
            env=env,
            capture_output=True,
            text=True,
            timeout=150,
        )
        assert wait.returncode == 0, wait.stdout + wait.stderr
        yield deployment
    finally:
        subprocess.run([*compose, "down", "-v", "--remove-orphans"], env=env, capture_output=True)


def _install_old_chain(deployment: LiveUpgrade) -> None:
    deployment.psql(LIVE_SQL["001_initial.sql"])
    deployment.psql(
        "CREATE TABLE aisoc_schema_migrations (name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ DEFAULT now());"
        " INSERT INTO aisoc_schema_migrations(name) VALUES ('001_initial.sql');"
    )


def test_live_stale_image_cannot_complete_upgrade(live_upgrade: LiveUpgrade) -> None:
    """The measured failure: old image says zero pending against an old ledger."""
    _install_old_chain(live_upgrade)
    result = live_upgrade.migrate("stale")
    assert result.returncode != 0, result.stdout + result.stderr
    assert "002_next.sql" in result.stdout + result.stderr
    assert "API image migrations do not match" in result.stdout + result.stderr
    assert live_upgrade.psql("SELECT name FROM aisoc_schema_migrations") == "001_initial.sql"
    assert live_upgrade.psql("SELECT to_regclass('aisoc_upgrade_added')") == ""
    assert live_upgrade.psql("SELECT value FROM aisoc_upgrade_existing") == "keep"


def test_live_matching_image_applies_and_verifies_checkout(live_upgrade: LiveUpgrade) -> None:
    _install_old_chain(live_upgrade)
    result = live_upgrade.migrate("matching")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "verified 2 migration files" in result.stdout
    assert "up to date" in result.stdout
    assert live_upgrade.psql("SELECT name FROM aisoc_schema_migrations ORDER BY name") == "001_initial.sql\n002_next.sql"
    assert live_upgrade.psql("SELECT to_regclass('aisoc_upgrade_added')") == "aisoc_upgrade_added"
    assert live_upgrade.psql("SELECT value FROM aisoc_upgrade_existing") == "keep"


def test_live_postcondition_rejects_empty_database(live_upgrade: LiveUpgrade) -> None:
    probe = shlex.join([*live_upgrade.compose, "exec", "-T", "postgres", "psql", "-h", "127.0.0.1", "-U", "aisoc", "-d", "aisoc"])
    command = [sys.executable, str(live_upgrade.checkout / "scripts/pending_migrations.py"), "--probe", probe]
    normal = subprocess.run(command, env=live_upgrade.env, cwd=live_upgrade.checkout, capture_output=True, text=True)
    assert normal.returncode == 0 and "fresh" in normal.stdout, normal.stdout + normal.stderr
    strict = subprocess.run(
        [*command, "--require-applied"], env=live_upgrade.env, cwd=live_upgrade.checkout, capture_output=True, text=True
    )
    assert strict.returncode == 3, strict.stdout + strict.stderr
    assert "001_initial.sql" in strict.stdout and "002_next.sql" in strict.stdout
