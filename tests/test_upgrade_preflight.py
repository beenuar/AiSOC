"""An upgrade refuses to start when a restore could not put the deployment back.

The defect this exists to prevent
---------------------------------
`scripts/backup.sh` covers six stores with AES-256-GCM and a SHA-256
manifest, and never captured `AISOC_CREDENTIAL_KEY`. A complete, verified,
restorable Postgres dump is useless for connector credentials without it:
every `vault:v1:` token fails its integrity check against a different key and
`CredentialVault` raises "ciphertext failed integrity check (key rotated
without re-encrypt?)". The restore reports success and every connector is
dead.

`scripts/ensure_env.py` is the specific way that key goes missing. It is a
good citizen about an *existing* `.env` — it never overwrites a secret that
already has a value — but when `.env` is **absent** it copies the example and
generates a brand-new Fernet key. On an existing deployment that orphans
every stored credential in one step, silently, as a side effect of a command
whose job is to be helpful.

So the preflight refuses on the four conditions that each mean "a restore
would not bring this deployment back", and `make upgrade` runs it before
anything — including before anything that could call `ensure_env.py`.
"""

from __future__ import annotations

import base64
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PREFLIGHT = ROOT / "scripts/preflight_upgrade.py"
MAKEFILE = ROOT / "Makefile"

#: What `ensure_env.py` writes: `base64.urlsafe_b64encode(os.urandom(32))`.
GOOD_KEY = base64.urlsafe_b64encode(b"k" * 32).decode("ascii")


def _run(tmp: Path, *args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    environ = {k: v for k, v in os.environ.items() if k != "AISOC_CREDENTIAL_KEY"}
    environ["AISOC_REPO_ROOT"] = str(tmp)
    environ.update(env or {})
    return subprocess.run(
        [sys.executable, str(PREFLIGHT), *args],
        capture_output=True,
        text=True,
        cwd=str(tmp),
        env=environ,
    )


def _deployment(tmp: Path, *, env_file: bool = True, key: str | None = GOOD_KEY, backup: bool = True) -> Path:
    (tmp / ".git").mkdir(exist_ok=True)
    if env_file:
        body = "ENVIRONMENT=production\n"
        if key is not None:
            body += f"AISOC_CREDENTIAL_KEY={key}\n"
        (tmp / ".env").write_text(body, encoding="utf-8")
    if backup:
        backups = tmp / "backups"
        backups.mkdir(exist_ok=True)
        dump = backups / "pre-upgrade-20260101T000000Z.sql.gz"
        dump.write_bytes(b"\x1f\x8b" + b"0" * 64)
        os.utime(dump, (time.time(), time.time()))
    return tmp


# ── the four refusals ────────────────────────────────────────────────────────


def test_refuses_when_env_file_is_absent(tmp_path: Path) -> None:
    """The condition `ensure_env.py` turns into a silent new key.

    This is the one that matters most, because the operator's next instinct
    on seeing a missing `.env` is to run the command that creates one.
    """
    _deployment(tmp_path, env_file=False)
    result = _run(tmp_path)
    assert result.returncode != 0, result.stdout
    assert ".env" in result.stdout
    # It has to say *why*, or the operator does the destructive thing next.
    assert "ensure_env" in result.stdout or "new key" in result.stdout.lower(), result.stdout


def test_refuses_when_the_credential_key_is_empty(tmp_path: Path) -> None:
    """`.env.example` ships it empty, so an operator who copied the example
    and never generated one is in exactly this state."""
    _deployment(tmp_path, key="")
    result = _run(tmp_path)
    assert result.returncode != 0, result.stdout
    assert "AISOC_CREDENTIAL_KEY" in result.stdout


def test_refuses_when_the_credential_key_is_unreadable(tmp_path: Path) -> None:
    """Present but not a Fernet key.

    A value that is set and wrong is worse than one that is missing: compose
    interpolates it, the API starts, and every decrypt fails at the first
    connector poll rather than at boot.
    """
    _deployment(tmp_path, key="not-a-fernet-key")
    result = _run(tmp_path)
    assert result.returncode != 0, result.stdout
    assert "AISOC_CREDENTIAL_KEY" in result.stdout


def test_refuses_when_no_recent_backup_exists(tmp_path: Path) -> None:
    _deployment(tmp_path, backup=False)
    result = _run(tmp_path)
    assert result.returncode != 0, result.stdout
    assert "backup" in result.stdout.lower()


def test_refuses_a_backup_that_is_too_old(tmp_path: Path) -> None:
    """Recency is the property. A dump from the previous upgrade restores the
    deployment to the previous upgrade, which is not what the operator thinks
    they are protected by."""
    _deployment(tmp_path)
    stale = tmp_path / "backups" / "pre-upgrade-20260101T000000Z.sql.gz"
    old = time.time() - 60 * 60 * 24 * 9
    os.utime(stale, (old, old))
    result = _run(tmp_path)
    assert result.returncode != 0, result.stdout
    assert "backup" in result.stdout.lower()


def test_refuses_an_empty_backup_file(tmp_path: Path) -> None:
    """`pg_dump | gzip` to a full disk exits 0 and leaves a file.

    The second preflight invocation in `make upgrade` exists for this case,
    so it has to actually look at the size.
    """
    _deployment(tmp_path)
    (tmp_path / "backups" / "pre-upgrade-20260101T000000Z.sql.gz").write_bytes(b"")
    result = _run(tmp_path)
    assert result.returncode != 0, result.stdout
    assert "backup" in result.stdout.lower()


# ── and the positive control ─────────────────────────────────────────────────


def test_accepts_a_deployment_that_could_be_restored(tmp_path: Path) -> None:
    """The control without which every assertion above passes on a preflight
    that refuses unconditionally.

    A stuck-closed safety check reads as working caution, and this repository
    has shipped one: a credential-grant guard that withheld every verb on
    every deployment passed its drifted-tenant test perfectly, and only the
    positive control caught it.
    """
    _deployment(tmp_path)
    result = _run(tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr


def test_key_from_the_process_environment_is_accepted(tmp_path: Path) -> None:
    """Compose reads the shell environment as well as `.env`, so a key
    exported by the operator is a real deployment and not a broken one."""
    _deployment(tmp_path, key=None)
    result = _run(tmp_path, env={"AISOC_CREDENTIAL_KEY": GOOD_KEY})
    assert result.returncode == 0, result.stdout + result.stderr


def test_skip_backup_check_still_enforces_the_credential_key(tmp_path: Path) -> None:
    """`make upgrade` runs the first phase with `--skip-backup-check`, before
    a backup could possibly exist. That phase must not become a no-op."""
    _deployment(tmp_path, key="", backup=False)
    result = _run(tmp_path, "--skip-backup-check")
    assert result.returncode != 0, result.stdout
    assert "AISOC_CREDENTIAL_KEY" in result.stdout

    _deployment(tmp_path, backup=False)
    ok = _run(tmp_path, "--skip-backup-check")
    assert ok.returncode == 0, ok.stdout + ok.stderr


def test_never_prints_the_key(tmp_path: Path) -> None:
    """A preflight that echoes the secret into CI logs and terminal
    scrollback has created a second copy of it in the worst place.

    The `is_file` line stops this passing against a tree where the script
    does not exist: an absent script prints nothing, and "printed no secret"
    and "printed nothing at all" are not the same result.
    """
    assert PREFLIGHT.is_file(), f"{PREFLIGHT} does not exist"
    _deployment(tmp_path)
    result = _run(tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert GOOD_KEY not in result.stdout + result.stderr


def test_make_upgrade_runs_the_preflight_before_ensure_env(tmp_path: Path) -> None:
    """`upgrade` must not depend on `env`.

    Depending on it would run `ensure_env.py` first, which on a deployment
    with no `.env` generates the new key the preflight exists to refuse —
    making the refusal unreachable through the command that needs it.
    """
    text = MAKEFILE.read_text(encoding="utf-8")
    header = [line for line in text.splitlines() if line.startswith("upgrade:")]
    assert header, "no `upgrade:` target"
    prereqs = header[0].split(":", 1)[1].split()
    assert "env" not in prereqs, (
        "`make upgrade` depends on `env`, so ensure_env.py runs before the "
        "preflight and mints a new credential key on exactly the deployment "
        f"the preflight exists to protect. Prerequisites were: {prereqs}"
    )
