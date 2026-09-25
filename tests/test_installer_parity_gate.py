"""The two installers must start the same product and prove it the same way.

`install.sh` was changed to bring up the real stack with `make up`, create an
administrator and run the golden pipeline. `install.ps1` was not, and nothing
noticed for a release: it kept handing off to `pnpm aisoc:demo`, a compose
file with no ingest service, no fusion service and Kafka disabled, whose only
content came from a seed script writing rows straight into Postgres — and
then printed "AiSOC is up and running." A Windows evaluator saw a populated
console and concluded the platform worked, having never run the platform.

Nothing could catch that, because the two installers share no code and the
Windows one exercised no path CI ran. The checks below are file-content
assertions for exactly that reason: the defect lived in the gap between two
files that are supposed to agree and have no mechanism forcing them to.

Windows has no `make`, so install.ps1 cannot call the Makefile and the
comparison cannot be "does it run the same command line". What it can be, and
is, is "does it run the same *underlying* commands" — the ones the Makefile's
`up`, `bootstrap` and `smoke` targets run — plus the narrower class of bug
that shipped alongside: a script telling the user to run a file that is not
in the repository.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]

INSTALL_PS1 = REPO / "install.ps1"
INSTALL_SH = REPO / "install.sh"
UNINSTALL_PS1 = REPO / "uninstall.ps1"
MAKEFILE = REPO / "Makefile"

# The stack a user is entitled to get from either installer. Anything else is
# a preview of the interface rather than a deployment of the product.
DEMO_HANDOFF = "pnpm aisoc:demo"


def _read(path: Path) -> str:
    assert path.is_file(), f"{path.relative_to(REPO)} is missing"
    return path.read_text(encoding="utf-8")


def _code_lines(text: str) -> list[str]:
    """Lines that are not PowerShell comments.

    Every assertion here is about what the script *does*. The comment blocks
    deliberately name the wrong thing in order to explain why it is wrong, so
    scanning raw text would fail the file for documenting its own history.
    """
    out = []
    in_block_comment = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("<#"):
            in_block_comment = True
        if in_block_comment:
            if "#>" in stripped:
                in_block_comment = False
            continue
        if stripped.startswith("#"):
            continue
        out.append(line)
    return out


# ── What the installer starts ───────────────────────────────────────────────


def test_windows_installer_does_not_hand_off_to_the_demo_stack() -> None:
    """install.ps1 must not execute `pnpm aisoc:demo`.

    It may still *name* it in a comment explaining why it does not, which is
    why this reads code lines only.
    """
    offenders = [line for line in _code_lines(_read(INSTALL_PS1)) if DEMO_HANDOFF in line]
    assert not offenders, (
        "install.ps1 executes the demo stack:\n  "
        + "\n  ".join(o.strip() for o in offenders)
        + "\nThat compose file has no ingest and no fusion service; it cannot "
        "answer whether AiSOC works."
    )


def test_windows_installer_starts_the_real_stack() -> None:
    code = "\n".join(_code_lines(_read(INSTALL_PS1)))
    assert "'compose', 'up', '-d'" in code or "docker compose up -d" in code, (
        "install.ps1 must start the deployment defined by the root "
        "docker-compose.yml, the same one `make up` starts."
    )


def test_windows_installer_waits_for_containers_to_be_healthy() -> None:
    """`docker compose up -d` returning 0 is not the stack being up."""
    code = "\n".join(_code_lines(_read(INSTALL_PS1)))
    assert "docker compose ps -a" in code, (
        "install.ps1 must poll `docker compose ps -a` before declaring the "
        "stack up. Without `-a` an exited container is absent from the "
        "listing entirely and a crash-looping service reads as success."
    )
    for state in ("exited", "restarting", "unhealthy"):
        assert state in code, f"install.ps1's wait loop does not treat {state!r} as a failure"


# ── Parity with the Makefile targets install.sh reaches through `make` ──────


def _makefile_recipe(target: str) -> str:
    text = _read(MAKEFILE)
    match = re.search(rf"^{re.escape(target)}:.*?\n((?:\t.*\n|\n)*)", text, re.MULTILINE)
    assert match, f"Makefile has no `{target}` target"
    return match.group(1)


def test_windows_installer_creates_the_first_administrator() -> None:
    """The Windows installer must run the module `make bootstrap` runs.

    Without it no administrator exists, and a Windows user either cannot sign
    in at all or signs in to a seeded database and evaluates that as the
    product.
    """
    module = "app.scripts.bootstrap_admin"
    assert module in _makefile_recipe("bootstrap"), (
        f"`make bootstrap` no longer runs {module}; update this gate and install.ps1 together"
    )
    code = "\n".join(_code_lines(_read(INSTALL_PS1)))
    assert module in code, f"install.ps1 never runs {module}, so no administrator is created"
    assert "docker compose run --rm -T api" in code, (
        "install.ps1 must create the administrator the same way `make bootstrap` "
        "does — a one-shot `docker compose run --rm -T api`"
    )


def test_windows_installer_runs_the_golden_pipeline() -> None:
    """"The containers started" is not "the application works"."""
    runner = "tests/e2e/golden_pipeline/run_golden_pipeline.py"
    assert runner in _makefile_recipe("smoke"), (
        f"`make smoke` no longer runs {runner}; update this gate and install.ps1 together"
    )
    code = "\n".join(_code_lines(_read(INSTALL_PS1)))
    windows_runner = runner.replace("/", "\\")
    assert (runner in code) or (windows_runner in code), (
        "install.ps1 never runs the golden pipeline, so it cannot tell a working "
        "deployment from a broken one before printing a success banner."
    )


def test_both_installers_use_a_frozen_lockfile() -> None:
    """A self-hoster must not silently resolve a dependency set nobody tested."""
    for path in (INSTALL_SH, INSTALL_PS1):
        text = _read(path)
        assert "--frozen-lockfile" in text, f"{path.name} does not pass --frozen-lockfile to pnpm install"
        assert "--no-frozen-lockfile" not in text, f"{path.name} still passes --no-frozen-lockfile"


def test_both_installers_require_the_same_node_major() -> None:
    """A different runtime from the one the project builds and tests against
    is a difference no user asked for and none can see."""
    sh_majors = {int(m) for m in re.findall(r"version_at_least node (\d+)", _read(INSTALL_SH))}
    assert len(sh_majors) == 1, f"install.sh checks inconsistent Node majors: {sorted(sh_majors)}"

    ps1 = _read(INSTALL_PS1)
    install_node = re.search(r"function Install-Node \{(.*?)\n\}", ps1, re.DOTALL)
    assert install_node, "install.ps1 has no Install-Node function"
    ps1_majors = {int(m) for m in re.findall(r"\$major -ge (\d+)", install_node.group(1))}
    assert ps1_majors == sh_majors, (
        f"install.sh requires Node {sorted(sh_majors)} and install.ps1 requires {sorted(ps1_majors)}"
    )


# ── Paths the scripts tell a user to run ────────────────────────────────────

# `.\scripts\install\uninstall.ps1` was printed by the closing banner for a
# release. The file is `uninstall.ps1`, at the repository root, and has never
# been anywhere else — so the last thing the installer told a Windows user to
# do could not work.
_PS1_PATH = re.compile(r"\.\\([A-Za-z0-9_\\\-./]+\.ps1)")


@pytest.mark.parametrize("script", [INSTALL_PS1, UNINSTALL_PS1], ids=lambda p: p.name)
def test_referenced_powershell_paths_exist(script: Path) -> None:
    text = _read(script)
    missing = sorted(
        {
            candidate
            for candidate in _PS1_PATH.findall(text)
            if not (REPO / candidate.replace("\\", "/")).is_file()
        }
    )
    assert not missing, (
        f"{script.name} tells the user to run files that are not in the repository: {missing}"
    )


def test_windows_uninstaller_tears_down_the_stack_the_installer_starts() -> None:
    """Tearing down only the demo project left every CORE container running,
    Postgres still holding 5432, under a banner saying the uninstall was
    complete."""
    code = "\n".join(_code_lines(_read(UNINSTALL_PS1)))
    assert "'docker-compose.yml'" in code or '"docker-compose.yml"' in code, (
        "uninstall.ps1 never brings down the root docker-compose.yml project, "
        "which is the one install.ps1 starts."
    )
