"""The shared registry pull helper retries, falls back, and still fails loudly.

Why this exists
---------------
`.github/actions/start-postgres` has carried a retry-and-mirror-fallback pull
loop for a long time, and it earned its keep: on 2026-11-26 and again on
2026-11-28 ECR Public answered `Data limit exceeded` during the migrations job
on `main`, the postgres pull rode it out, and the LocalStack pull three steps
later — a bare `docker run` — took the build down. The loop now lives in
`scripts/ci/pull_image.sh` so every container-starting step shares it.

A shared helper that nothing tests is a worse bet than the inline copy it
replaced, because every caller inherits its defects at once. These tests drive
the real script with a stub `docker` on PATH, so they assert the loop's actual
behaviour — attempt counts, ordering, what lands on stdout, and what happens
when no registry answers — without a network or a daemon.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
HELPER = REPO / "scripts" / "ci" / "pull_image.sh"

#: Keep all three rounds and their backoff inside a second. The helper reads
#: both from the environment precisely so this suite can do that rather than
#: assert the loop by reading the source.
FAST = {"PULL_IMAGE_ATTEMPT_SECONDS": "5", "PULL_IMAGE_BACKOFF_SECONDS": "0"}


def _stub_docker(tmp_path: Path, refuse: str) -> Path:
    """A `docker` that logs every pull and refuses the references it is told to.

    `refuse` is a grep pattern. A reference matching it fails the way a
    registry denial does; anything else succeeds. The log is the evidence —
    how many attempts were made, against what, in what order.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    stub = bin_dir / "docker"
    stub.write_text(
        "#!/usr/bin/env bash\n"
        f'printf "%s\\n" "$2" >> "{tmp_path}/attempts.log"\n'
        f'if printf "%s" "$2" | grep -Eq {refuse!r}; then\n'
        '  echo "Error response from daemon: error from registry: Data limit exceeded" >&2\n'
        "  exit 1\n"
        "fi\n"
        'echo "Status: Downloaded newer image for $2"\n',
        encoding="utf-8",
    )
    stub.chmod(0o755)
    return bin_dir


def _run(tmp_path: Path, *refs: str, refuse: str = "^$", run_id: str = "0"):
    bin_dir = _stub_docker(tmp_path, refuse)
    env = {
        **os.environ,
        **FAST,
        "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        "GITHUB_RUN_ID": run_id,
    }
    proc = subprocess.run([str(HELPER), *refs], capture_output=True, text=True, env=env, timeout=120)
    log = tmp_path / "attempts.log"
    attempts = log.read_text().split() if log.exists() else []
    return proc, attempts


def test_the_helper_is_executable_because_every_caller_invokes_it_by_path() -> None:
    assert HELPER.is_file(), f"{HELPER} is missing"
    assert os.access(HELPER, os.X_OK), (
        f"{HELPER} is not executable; the workflows run it as a command, so a lost mode bit breaks every caller at once"
    )


def test_the_winning_reference_is_the_only_thing_on_stdout(tmp_path: Path) -> None:
    """Callers capture stdout with `$( )`. Anything else there corrupts the run."""
    proc, attempts = _run(tmp_path, "registry.example/app:1")
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == "registry.example/app:1\n"
    assert attempts == ["registry.example/app:1"], "a reachable registry should be pulled once"


def test_a_refused_registry_falls_back_to_the_mirror(tmp_path: Path) -> None:
    """The defect this exists for: one registry denies, the build carries on."""
    proc, attempts = _run(
        tmp_path,
        "public.ecr.aws/localstack/localstack:3",
        "docker.io/localstack/localstack:3",
        refuse="^public[.]ecr[.]aws/",
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == "docker.io/localstack/localstack:3\n"
    assert attempts == [
        "public.ecr.aws/localstack/localstack:3",
        "docker.io/localstack/localstack:3",
    ]
    assert "round 1/3" in proc.stderr
    assert "::warning::Could not pull public.ecr.aws/localstack/localstack:3" in proc.stderr


def test_one_reference_still_gets_its_retries(tmp_path: Path) -> None:
    """ClickHouse, versitygw and our own GHCR images have no second registry."""
    proc, attempts = _run(tmp_path, "docker.io/clickhouse/clickhouse-server:23.8", refuse="nope")
    assert proc.returncode == 0, proc.stderr
    assert attempts == ["docker.io/clickhouse/clickhouse-server:23.8"]


def test_a_missing_image_still_fails_loudly_after_every_round(tmp_path: Path) -> None:
    """Surviving a transient limit is the point; hiding a bad reference is not."""
    proc, attempts = _run(tmp_path, "registry.example/a:1", "registry.example/b:1", refuse="registry[.]example")
    assert proc.returncode == 1
    assert proc.stdout == "", "a failed pull must not emit a reference a caller would run"
    assert attempts == ["registry.example/a:1", "registry.example/b:1"] * 3, "three rounds over both references"
    assert "::error::" in proc.stderr
    for ref in ("registry.example/a:1", "registry.example/b:1"):
        assert ref in proc.stderr.rsplit("::error::", 1)[-1], "the final error has to name what was tried, or the log says nothing useful"


def test_the_first_attempt_rotates_with_the_run_id(tmp_path: Path) -> None:
    """Concurrent jobs must not all open on the same anonymous quota."""
    even, _ = _run(tmp_path / "even", "registry.example/a:1", "registry.example/b:1", run_id="2")
    odd, _ = _run(tmp_path / "odd", "registry.example/a:1", "registry.example/b:1", run_id="3")
    assert even.stdout == "registry.example/a:1\n"
    assert odd.stdout == "registry.example/b:1\n"


def test_no_reference_is_a_usage_error_rather_than_a_silent_pass(tmp_path: Path) -> None:
    proc, _ = _run(tmp_path)
    assert proc.returncode == 2
    assert proc.stdout == ""
    assert "::error::" in proc.stderr


@pytest.mark.skipif(shutil.which("shellcheck") is None, reason="shellcheck is not installed")
def test_the_helper_passes_shellcheck() -> None:
    proc = subprocess.run(["shellcheck", str(HELPER)], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_the_postgres_action_has_no_second_copy_of_the_loop() -> None:
    """One implementation. Two would drift, and the drift is invisible until CI reds."""
    action = (REPO / ".github" / "actions" / "start-postgres" / "action.yml").read_text(encoding="utf-8")
    assert "scripts/ci/pull_image.sh" in action, "the PostgreSQL action must pull through the shared helper"
    assert "for round in 1 2 3" not in action, "the retry loop was factored out; a copy here is a second thing to rot"
