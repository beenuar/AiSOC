"""CLI surface tests for the operator subcommands (serve, db, mcp).

These commands shell out to long-running processes (``docker compose``,
``node services/mcp/dist/index.js``) so we don't actually execute them.
Instead we verify:

* The new subcommands are registered on the ``cli`` group and discoverable
  via ``--help``.
* They construct the right argv before delegating to ``subprocess.run`` or
  ``os.execvp``, so the demo script stays a thin shell over docker compose
  and the MCP node binary.

If these tests break, the founder-style quickstart in the video script will
desync from the CLI — that's exactly the regression we want to catch.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from aisoc_cli import main as cli_main
from aisoc_cli.main import cli


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def fake_repo(tmp_path: Path) -> Path:
    """A minimal repo root with both compose files and a built MCP dist."""
    (tmp_path / "docker-compose.yml").write_text("services: {}\n")
    (tmp_path / "docker-compose.dev.yml").write_text(
        "include:\n  - path: docker-compose.yml\n"
    )
    mcp_dist = tmp_path / "services" / "mcp" / "dist"
    mcp_dist.mkdir(parents=True)
    (mcp_dist / "index.js").write_text("#!/usr/bin/env node\n")
    return tmp_path


# ── help / discovery ──────────────────────────────────────────────────────────

def test_top_level_help_lists_new_groups(runner: CliRunner) -> None:
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0, result.output
    # All four entrypoints must surface under `aisoc --help`.
    assert "serve" in result.output
    assert "db" in result.output
    assert "mcp" in result.output


def test_db_group_lists_upgrade(runner: CliRunner) -> None:
    result = runner.invoke(cli, ["db", "--help"])
    assert result.exit_code == 0, result.output
    assert "upgrade" in result.output


def test_mcp_group_lists_serve_and_install(runner: CliRunner) -> None:
    result = runner.invoke(cli, ["mcp", "--help"])
    assert result.exit_code == 0, result.output
    assert "serve" in result.output
    assert "install" in result.output


# ── serve ─────────────────────────────────────────────────────────────────────

def test_serve_invokes_docker_compose_up(
    monkeypatch: pytest.MonkeyPatch, runner: CliRunner, fake_repo: Path
) -> None:
    """``aisoc serve`` shells out to ``docker compose -f <file> up -d``."""
    captured: dict[str, object] = {}

    def fake_run(cmd: list[str], cwd: str | None = None, **_: object):
        captured["cmd"] = cmd
        captured["cwd"] = cwd

        class _Result:
            returncode = 0

        return _Result()

    monkeypatch.setattr(cli_main.shutil, "which", lambda _name: "/usr/bin/docker")
    monkeypatch.setattr(cli_main, "_find_repo_root", lambda start=None: fake_repo)
    monkeypatch.setattr(cli_main.subprocess, "run", fake_run)

    result = runner.invoke(cli, ["serve"])
    assert result.exit_code == 0, result.output

    cmd = captured["cmd"]
    assert cmd[:2] == ["docker", "compose"]
    assert "-f" in cmd
    assert "docker-compose.dev.yml" in " ".join(cmd)
    assert cmd[-2:] == ["up", "-d"]
    assert captured["cwd"] == str(fake_repo)


def test_serve_no_detach_drops_minus_d(
    monkeypatch: pytest.MonkeyPatch, runner: CliRunner, fake_repo: Path
) -> None:
    captured: dict[str, object] = {}

    def fake_run(cmd: list[str], cwd: str | None = None, **_: object):
        captured["cmd"] = cmd

        class _Result:
            returncode = 0

        return _Result()

    monkeypatch.setattr(cli_main.shutil, "which", lambda _name: "/usr/bin/docker")
    monkeypatch.setattr(cli_main, "_find_repo_root", lambda start=None: fake_repo)
    monkeypatch.setattr(cli_main.subprocess, "run", fake_run)

    result = runner.invoke(cli, ["serve", "--no-detach"])
    assert result.exit_code == 0, result.output
    cmd = captured["cmd"]
    assert cmd[-1] == "up"
    assert "-d" not in cmd


def test_serve_fails_without_docker(
    monkeypatch: pytest.MonkeyPatch, runner: CliRunner
) -> None:
    monkeypatch.setattr(cli_main.shutil, "which", lambda _name: None)
    result = runner.invoke(cli, ["serve"])
    assert result.exit_code != 0
    assert "docker not found" in result.output.lower()


# ── db upgrade ────────────────────────────────────────────────────────────────

def test_db_upgrade_invokes_run_migrations(
    monkeypatch: pytest.MonkeyPatch, runner: CliRunner, fake_repo: Path
) -> None:
    """``aisoc db upgrade`` execs the custom forward-only migration runner."""
    captured: dict[str, object] = {}

    def fake_run(cmd: list[str], cwd: str | None = None, **_: object):
        captured["cmd"] = cmd

        class _Result:
            returncode = 0

        return _Result()

    monkeypatch.setattr(cli_main.shutil, "which", lambda _name: "/usr/bin/docker")
    monkeypatch.setattr(cli_main, "_find_repo_root", lambda start=None: fake_repo)
    monkeypatch.setattr(cli_main.subprocess, "run", fake_run)

    result = runner.invoke(cli, ["db", "upgrade"])
    assert result.exit_code == 0, result.output

    cmd = captured["cmd"]
    # docker compose -f <file> exec -T api python -m app.scripts.run_migrations
    assert cmd[:2] == ["docker", "compose"]
    assert "exec" in cmd
    assert "-T" in cmd
    assert "api" in cmd
    assert cmd[-3:] == ["-m", "app.scripts.run_migrations"][-3:] or cmd[-2:] == [
        "-m",
        "app.scripts.run_migrations",
    ]
    # Final form: python -m app.scripts.run_migrations
    assert "python" in cmd
    assert "app.scripts.run_migrations" in cmd


def test_db_upgrade_non_zero_exits_with_hint(
    monkeypatch: pytest.MonkeyPatch, runner: CliRunner, fake_repo: Path
) -> None:
    def fake_run(cmd: list[str], cwd: str | None = None, **_: object):
        class _Result:
            returncode = 1

        return _Result()

    monkeypatch.setattr(cli_main.shutil, "which", lambda _name: "/usr/bin/docker")
    monkeypatch.setattr(cli_main, "_find_repo_root", lambda start=None: fake_repo)
    monkeypatch.setattr(cli_main.subprocess, "run", fake_run)

    result = runner.invoke(cli, ["db", "upgrade"])
    assert result.exit_code == 1
    assert "aisoc serve" in result.output


# ── mcp serve ─────────────────────────────────────────────────────────────────

def test_mcp_serve_uses_local_dist(
    monkeypatch: pytest.MonkeyPatch, runner: CliRunner, fake_repo: Path
) -> None:
    """When ``services/mcp/dist/index.js`` exists, we exec node on it."""
    captured: dict[str, object] = {}

    def fake_execvp(file: str, args: list[str]) -> None:
        captured["file"] = file
        captured["args"] = args
        # os.execvp would replace the process; in tests we just need to stop.
        raise SystemExit(0)

    monkeypatch.setattr(cli_main.shutil, "which", lambda _name: "/usr/bin/node")
    monkeypatch.setattr(cli_main, "_find_repo_root", lambda start=None: fake_repo)
    monkeypatch.setattr(cli_main.os, "execvp", fake_execvp)

    result = runner.invoke(cli, ["mcp", "serve", "--transport", "stdio"])
    assert result.exit_code == 0, result.output

    args = captured["args"]
    assert args[0] == "/usr/bin/node"
    assert str(fake_repo / "services" / "mcp" / "dist" / "index.js") in args
    assert "serve" in args
    assert "--transport" in args
    assert "stdio" in args


def test_mcp_serve_falls_back_to_npx(
    monkeypatch: pytest.MonkeyPatch, runner: CliRunner, tmp_path: Path
) -> None:
    """When no dist build exists, the CLI uses ``npx @aisoc/mcp``."""
    # Build a repo root that has compose but no MCP dist.
    (tmp_path / "docker-compose.yml").write_text("services: {}\n")
    captured: dict[str, object] = {}

    def fake_execvp(file: str, args: list[str]) -> None:
        captured["args"] = args
        raise SystemExit(0)

    monkeypatch.setattr(cli_main.shutil, "which", lambda _name: f"/usr/bin/{_name}")
    monkeypatch.setattr(cli_main, "_find_repo_root", lambda start=None: tmp_path)
    monkeypatch.setattr(cli_main.os, "execvp", fake_execvp)

    result = runner.invoke(cli, ["mcp", "serve"])
    assert result.exit_code == 0, result.output

    args = captured["args"]
    assert args[0] == "/usr/bin/npx"
    assert "@aisoc/mcp" in args
    assert "serve" in args


# ── mcp install ───────────────────────────────────────────────────────────────

def test_mcp_install_invokes_host(
    monkeypatch: pytest.MonkeyPatch, runner: CliRunner, fake_repo: Path
) -> None:
    captured: dict[str, object] = {}

    def fake_run(cmd: list[str], cwd: str | None = None, **_: object):
        captured["cmd"] = cmd

        class _Result:
            returncode = 0

        return _Result()

    monkeypatch.setattr(cli_main.shutil, "which", lambda _name: f"/usr/bin/{_name}")
    monkeypatch.setattr(cli_main, "_find_repo_root", lambda start=None: fake_repo)
    monkeypatch.setattr(cli_main.subprocess, "run", fake_run)

    result = runner.invoke(cli, ["mcp", "install", "--host", "claude"])
    assert result.exit_code == 0, result.output

    cmd = captured["cmd"]
    assert "install" in cmd
    assert "--host" in cmd
    assert "claude" in cmd


def test_mcp_install_rejects_unknown_host(runner: CliRunner) -> None:
    result = runner.invoke(cli, ["mcp", "install", "--host", "notahost"])
    assert result.exit_code != 0
    # Click writes invalid-choice errors to stderr/stdout.
    assert "notahost" in result.output or "Invalid value" in result.output
