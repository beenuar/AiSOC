"""Back up the vault key, restore it, and check what actually happened on disk.

Why this is separate from the source-text assertions
----------------------------------------------------
`test_backup_credential_key.py` reads both scripts and asserts on their text.
Every one of those assertions passed against a `restore_credential_key` that
**overwrote a different key and reported success** — the exact outcome it is
written to prevent.

The cause was one character class. The "what key is configured right now"
read used `sed` with `\\+` and `\\?`, which BSD sed — macOS's `sed` — does not
accept in a basic regex, so it matched nothing and returned empty. Empty reads
as "no key is configured", which is the branch that writes. A static test
cannot see that; only running the script can, which is why these do.

They run both scripts for real against a stub `aws` and a temporary bucket.
Nothing is mocked inside either script: the same `seal_artifact`,
`backup_crypt.py`, manifest write, digest verification and decrypt run that an
operator's backup runs.
"""

from __future__ import annotations

import base64
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
BACKUP = ROOT / "scripts" / "backup.sh"
RESTORE = ROOT / "scripts" / "restore.sh"
CRYPT = ROOT / "scripts" / "backup_crypt.py"

#: A stand-in for the AWS CLI. `s3 cp` moves bytes between the local
#: filesystem and a directory standing in for the bucket; `s3 ls` answers
#: whether a key exists. Nothing else is needed, and nothing inside the two
#: scripts under test is replaced.
FAKE_AWS = """#!/usr/bin/env bash
args=(); for a in "$@"; do [ "$a" = "--endpoint-url" ] && continue; args+=("$a"); done
set -- "${args[@]}"
if [ "$1" = "s3" ] && [ "$2" = "cp" ]; then
  s="$3"; d="$4"
  case "$s" in s3://*) s="$FAKE_BUCKET/${s#s3://}";; esac
  case "$d" in s3://*) d="$FAKE_BUCKET/${d#s3://}";; esac
  mkdir -p "$(dirname "$d")"; cp "$s" "$d" 2>/dev/null; exit $?
fi
if [ "$1" = "s3" ] && [ "$2" = "ls" ]; then
  p="${3#s3://}"; [ -e "$FAKE_BUCKET/$p" ] && { echo "x x x $(basename "$p")"; exit 0; }; exit 1
fi
exit 0
"""


def _key() -> str:
    return base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")


requires_bash = pytest.mark.skipif(
    shutil.which("bash") is None or shutil.which("pg_dump") is None,
    reason="backup.sh requires bash and pg_dump on PATH",
)


@pytest.fixture
def harness(tmp_path: Path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    aws = bindir / "aws"
    aws.write_text(FAKE_AWS, encoding="utf-8")
    aws.chmod(0o755)

    backup_key = (
        subprocess.run([sys.executable, str(CRYPT), "keygen"], capture_output=True, text=True, check=True).stdout.strip().splitlines()[-1]
    )

    env = dict(os.environ)
    env.update(
        {
            "PATH": f"{bindir}{os.pathsep}{os.environ['PATH']}",
            "FAKE_BUCKET": str(tmp_path / "bucket"),
            "BACKUP_S3_BUCKET": "s3://probe",
            "BACKUP_S3_PREFIX": "p",
            "BACKUP_ENCRYPTION_KEY": backup_key,
        }
    )
    env.pop("AISOC_CREDENTIAL_KEY", None)
    (tmp_path / "bucket").mkdir()
    return tmp_path, env


def _backup(env: dict[str, str], vault_key: str) -> str:
    """Take a real backup of `vault_key`; return its timestamp."""
    run = subprocess.run(
        ["bash", str(BACKUP), "--component", "credential_key"],
        capture_output=True,
        text=True,
        env={**env, "AISOC_CREDENTIAL_KEY": vault_key},
    )
    assert run.returncode == 0, run.stdout + run.stderr
    found = list(Path(env["FAKE_BUCKET"]).rglob("credential-key-*.json.enc"))
    assert found, f"nothing uploaded:\n{run.stdout}\n{run.stderr}"
    return found[0].name[len("credential-key-") : -len(".json.enc")]


def _restore(env: dict[str, str], ts: str, env_file: Path, *extra: str):
    return subprocess.run(
        ["bash", str(RESTORE), "--timestamp", ts, "--component", "credential_key", *extra],
        capture_output=True,
        text=True,
        env={**env, "AISOC_ENV_FILE": str(env_file)},
    )


@requires_bash
def test_the_key_never_appears_in_the_bucket_in_plaintext(harness) -> None:
    tmp_path, env = harness
    vault = _key()
    _backup(env, vault)
    for path in Path(env["FAKE_BUCKET"]).rglob("*"):
        if path.is_file():
            assert vault not in path.read_bytes().decode("utf-8", "replace"), f"plaintext key in {path}"


@requires_bash
def test_an_empty_key_in_env_is_filled_in(harness) -> None:
    """The recovery case: a fresh host, a restored dump, and no key yet."""
    tmp_path, env = harness
    vault = _key()
    ts = _backup(env, vault)
    env_file = tmp_path / ".env.target"
    env_file.write_text("ENVIRONMENT=production\nAISOC_CREDENTIAL_KEY=\n", encoding="utf-8")

    run = _restore(env, ts, env_file)
    assert run.returncode == 0, run.stdout + run.stderr
    assert f"AISOC_CREDENTIAL_KEY={vault}" in env_file.read_text(encoding="utf-8")
    assert env_file.stat().st_mode & 0o777 == 0o600, "the file now holds a secret"


@requires_bash
def test_a_different_key_already_present_is_not_overwritten(harness) -> None:
    """The assertion that failed in practice while its static twin passed.

    Overwriting here orphans everything the running deployment has encrypted
    under its current key — the same failure this component exists to
    prevent, pointed the other way.
    """
    tmp_path, env = harness
    backed_up, in_place = _key(), _key()
    ts = _backup(env, backed_up)
    env_file = tmp_path / ".env.target"
    env_file.write_text(f"AISOC_CREDENTIAL_KEY={in_place}\n", encoding="utf-8")

    run = _restore(env, ts, env_file)
    body = env_file.read_text(encoding="utf-8")
    assert run.returncode != 0, f"restore did not refuse:\n{run.stdout}\n{run.stderr}"
    assert in_place in body, "the running deployment's key was destroyed"
    assert backed_up not in body, "the backup's key was written over a conflicting one"
    # And it must not print either secret while refusing.
    assert in_place not in run.stdout + run.stderr
    assert backed_up not in run.stdout + run.stderr


@requires_bash
def test_the_same_key_again_is_a_no_op(harness) -> None:
    tmp_path, env = harness
    vault = _key()
    ts = _backup(env, vault)
    env_file = tmp_path / ".env.target"
    env_file.write_text(f"AISOC_CREDENTIAL_KEY={vault}\n", encoding="utf-8")

    run = _restore(env, ts, env_file)
    assert run.returncode == 0, run.stdout + run.stderr
    assert "already holds" in run.stdout, run.stdout
    assert env_file.read_text(encoding="utf-8").count("AISOC_CREDENTIAL_KEY") == 1


@requires_bash
def test_a_dry_run_writes_nothing(harness) -> None:
    """`DRY_RUN` was read by three restore functions and set by none, so this
    path was an unbound-variable crash under `set -u`."""
    tmp_path, env = harness
    vault = _key()
    ts = _backup(env, vault)
    env_file = tmp_path / ".env.target"
    env_file.write_text("AISOC_CREDENTIAL_KEY=\n", encoding="utf-8")

    run = _restore(env, ts, env_file, "--dry-run")
    assert run.returncode == 0, run.stdout + run.stderr
    assert "unbound variable" not in run.stderr, run.stderr
    assert vault not in env_file.read_text(encoding="utf-8")


@requires_bash
def test_an_export_prefixed_assignment_is_read(harness) -> None:
    """`.env` files in the wild carry `export FOO=bar`.

    This is the shape the `sed` version was trying to handle with `\\?` and
    `\\+`, and the shape that made it return empty on macOS.
    """
    tmp_path, env = harness
    backed_up, in_place = _key(), _key()
    ts = _backup(env, backed_up)
    env_file = tmp_path / ".env.target"
    env_file.write_text(f"export AISOC_CREDENTIAL_KEY={in_place}\n", encoding="utf-8")

    run = _restore(env, ts, env_file)
    assert run.returncode != 0, (
        f"an `export`-prefixed key was not seen, so the conflicting value was treated as absent:\n{run.stdout}\n{run.stderr}"
    )
    assert in_place in env_file.read_text(encoding="utf-8")


@requires_bash
def test_plaintext_is_a_live_failure_and_a_dry_run_skip(harness) -> None:
    """`BACKUP_ENCRYPTION=off` means two different things in the two modes,
    and collapsing them breaks one of the two.

    A live run must fail: the operator asked for a backup and this component
    cannot be taken safely, so reporting success would hand them a backup
    that silently omits the only thing that makes the dump usable.

    A dry run must not: nothing was going to be uploaded either way, so
    exiting 1 would make `--dry-run` useless as the configuration check it
    exists to be — which is exactly what it broke, in `terraform-ci.yml`'s
    "Backup script must accept every component the chart can request" step.
    Reported either way; the difference is the exit code, never the silence.
    """
    tmp_path, env = harness
    off = {**env, "BACKUP_ENCRYPTION": "off", "AISOC_CREDENTIAL_KEY": _key()}

    live = subprocess.run(
        ["bash", str(BACKUP), "--component", "credential_key"],
        capture_output=True,
        text=True,
        env=off,
    )
    assert live.returncode != 0, f"a live run uploaded, or claimed to:\n{live.stdout}"
    assert not list(Path(env["FAKE_BUCKET"]).rglob("credential-key-*")), "something was uploaded"

    rehearsal = subprocess.run(
        ["bash", str(BACKUP), "--dry-run", "--component", "all"],
        capture_output=True,
        text=True,
        env=off,
    )
    assert rehearsal.returncode == 0, (
        f"`--dry-run` failed, so it cannot serve as a configuration check:\n{rehearsal.stdout}\n{rehearsal.stderr}"
    )
    assert "BACKUP_ENCRYPTION=off" in rehearsal.stderr, (
        "the dry run passed silently; an operator would not learn that the credential key is being left out of their backups"
    )


@requires_bash
def test_backup_falls_back_to_dot_env_when_the_variable_is_unset(harness) -> None:
    """A cron-driven backup does not inherit the operator's shell, so reading
    `.env` is the normal path rather than the fallback."""
    tmp_path, env = harness
    vault = _key()
    (ROOT / ".env").exists()  # not used; the script reads its own repo root
    # Point the script at a repo root we control by running it from a copy.
    staged = tmp_path / "repo"
    (staged / "scripts").mkdir(parents=True)
    shutil.copy(BACKUP, staged / "scripts" / "backup.sh")
    shutil.copy(CRYPT, staged / "scripts" / "backup_crypt.py")
    (staged / ".env").write_text(f"AISOC_CREDENTIAL_KEY={vault}\n", encoding="utf-8")

    run = subprocess.run(
        ["bash", str(staged / "scripts" / "backup.sh"), "--component", "credential_key"],
        capture_output=True,
        text=True,
        env=env,  # AISOC_CREDENTIAL_KEY deliberately absent
    )
    assert run.returncode == 0, run.stdout + run.stderr
    assert "Nothing to capture" not in run.stdout, f"the key in .env was not found, so a cron backup would silently skip it:\n{run.stdout}"
    assert list(Path(env["FAKE_BUCKET"]).rglob("credential-key-*.json.enc"))
