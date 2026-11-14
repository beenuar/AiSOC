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
    # utf-8-sig, not utf-8: install.ps1 is committed **with** a BOM on
    # purpose, because Windows PowerShell 5.1 parses a BOM-less script as
    # ANSI and mangles every non-ASCII character in it. Read as plain utf-8
    # the BOM survives as a leading \ufeff, so the first line is
    # "\ufeff<#" rather than "<#", `_code_lines` never enters the block
    # comment, and the whole header is scanned as if it were code — which
    # made this gate report that the installer *executes* the demo stack
    # while reading a comment saying it does not.
    return path.read_text(encoding="utf-8-sig")


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


# Lines that *print* rather than *do*. A banner telling the operator what to
# run later contains the same command text as the invocation that runs it,
# and that near-miss is not hypothetical here: the installer's `-NoLaunch`
# help prints `docker compose up -d`, `docker compose ps -a` and
# `docker compose run --rm -T api …` verbatim, so three assertions below
# would have passed on a script that only ever *mentioned* those commands.
_OUTPUT_CMDLET = re.compile(r"^\s*Write-(Host|Info|Ok|Warn|Err|Log|Section)\b", re.IGNORECASE)


def _action_lines(text: str) -> str:
    """Code lines with the output cmdlets removed — what the script executes."""
    return "\n".join(line for line in _code_lines(text) if not _OUTPUT_CMDLET.match(line))


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
    actions = _action_lines(_read(INSTALL_PS1))
    assert ("'up', '-d'" in actions) or ("'compose', 'up', '-d'" in actions) or ("docker compose up -d" in actions), (
        "install.ps1 must start the deployment defined by the root docker-compose.yml, the same one `make up` starts."
    )


def test_windows_installer_waits_for_containers_to_be_healthy() -> None:
    """`docker compose up -d` returning 0 is not the stack being up."""
    actions = _action_lines(_read(INSTALL_PS1))
    assert ("'ps', '-a'" in actions) or ("docker compose ps -a" in actions), (
        "install.ps1 must poll `docker compose ps -a` before declaring the "
        "stack up. Without `-a` an exited container is absent from the "
        "listing entirely and a crash-looping service reads as success."
    )
    for state in ("exited", "restarting", "unhealthy"):
        assert state in actions, f"install.ps1's wait loop does not treat {state!r} as a failure"


# ── No on-ramp may point an evaluator at the demo stack ────────────────────

#: Surfaces a first-time user meets. Each one has, at some point, told
#: somebody to run `pnpm aisoc:demo` as their way into the product:
#: install.sh and install.ps1 by handing off to it, the devcontainer in its
#: attach banner, and the sandbox README in its "when you're ready for the
#: real stack" line. The compose file behind that command has no ingest
#: service, no fusion service and Kafka disabled — its own header says it
#: "does NOT run the AiSOC pipeline" and must not be used to evaluate
#: whether AiSOC works — so each of those sent an evaluator to a populated
#: console that had never run the product.
#:
#: Fixing the installers did not fix the class; the other two were found
#: still doing it afterwards. This checks all of them at once.
ONRAMP_SURFACES = (
    "install.sh",
    "install.ps1",
    ".devcontainer/devcontainer.json",
    "packages/aisoc-sandbox/README.md",
    "apps/docs/docs/quickstart.md",
    "apps/docs/docs/installation.md",
    "docs/QUICK_INSTALL.md",
    "README.md",
)


def _instructional_lines(path: Path, text: str) -> list[str]:
    """Lines that tell a reader to do something, minus the ones explaining
    what we deliberately do *not* do.

    Every one of these files is entitled to name the demo stack while
    warning readers off it — several now do, at length, and a gate that
    could not tell a warning from an instruction would force those
    warnings to be deleted. That would be the wrong direction: the warning
    is the thing keeping an evaluator out of a console that proves nothing.

    So the exemptions are the three shapes commentary actually takes here:
    a source-code comment, a Markdown blockquote, and a Docusaurus
    admonition (`:::caution` … `:::`). Everything else counts.
    """
    if path.suffix == ".ps1":
        return _code_lines(text)
    if path.suffix in {".sh", ".json"}:
        return [line for line in text.splitlines() if not line.strip().startswith(("#", "//"))]

    out: list[str] = []
    in_admonition = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith(":::"):
            # `:::caution Title` opens, a bare `:::` closes.
            in_admonition = len(stripped) > 3
            continue
        if in_admonition or stripped.startswith(">"):
            continue
        out.append(line)
    return out


@pytest.mark.parametrize("rel", ONRAMP_SURFACES)
def test_no_onramp_offers_the_demo_stack_as_a_way_in(rel: str) -> None:
    path = REPO / rel
    if not path.is_file():
        pytest.skip(f"{rel} is not in this checkout")
    offenders = [line.strip() for line in _instructional_lines(path, _read(path)) if DEMO_HANDOFF in line]
    assert not offenders, (
        f"{rel} points a first-time user at the demo stack:\n  "
        + "\n  ".join(offenders)
        + f"\n`{DEMO_HANDOFF}` starts a compose file with no ingest and no fusion service. "
        "It cannot answer whether AiSOC works, so it must not be anybody's way in — "
        "use `make up`. Explaining in a comment why it is not used is fine; telling "
        "somebody to run it is not."
    )


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
    assert module in _makefile_recipe("bootstrap"), f"`make bootstrap` no longer runs {module}; update this gate and install.ps1 together"
    actions = _action_lines(_read(INSTALL_PS1))
    assert module in actions, f"install.ps1 never runs {module}, so no administrator is created"
    assert ("'run', '--rm', '-T', 'api'" in actions) or ("docker compose run --rm -T api" in actions), (
        "install.ps1 must create the administrator the same way `make bootstrap` does — a one-shot `docker compose run --rm -T api`"
    )


def test_windows_installer_runs_the_golden_pipeline() -> None:
    """ "The containers started" is not "the application works"."""
    runner = "tests/e2e/golden_pipeline/run_golden_pipeline.py"
    assert runner in _makefile_recipe("smoke"), f"`make smoke` no longer runs {runner}; update this gate and install.ps1 together"
    code = "\n".join(_code_lines(_read(INSTALL_PS1)))
    windows_runner = runner.replace("/", "\\")
    assert (runner in code) or (windows_runner in code), (
        "install.ps1 never runs the golden pipeline, so it cannot tell a working "
        "deployment from a broken one before printing a success banner."
    )


# ── Setup steps that are Python programs on both paths ─────────────────────
#
# Both of these shipped broken on Windows, and this gate is why they could.
# It asserted compose/bootstrap/smoke/lockfile parity and said nothing about
# how `.env` is produced or what happens when a port is taken — so
# install.ps1 plain-copied `.env.example` (ENVIRONMENT=production with the
# secrets empty, which `enforce_secure_defaults` refuses to boot on) and
# exited 3 on a busy port, for as long as both existed.


def test_both_installers_generate_the_env_secrets() -> None:
    """A copied `.env.example` is not a usable environment.

    `.env.example` ships `ENVIRONMENT=production` with `SECRET_KEY`,
    `JWT_SECRET`, `METRICS_TOKEN` and `AISOC_CREDENTIAL_KEY` empty.
    `scripts/ensure_env.py` is what fills them, `make env` runs it, and an
    installer that only copies the template hands the operator a stack whose
    API crash-loops on its first boot with nothing pointing back at the copy.
    """
    generator = "ensure_env.py"
    assert generator in _makefile_recipe("env"), f"`make env` no longer runs {generator}; update this gate and both installers together"
    for path in (INSTALL_SH, INSTALL_PS1):
        text = _read(path)
        body = _action_lines(text) if path is INSTALL_PS1 else text
        assert generator in body, (
            f"{path.name} never runs scripts/{generator}, so the `.env` it writes carries "
            "empty secrets and the API refuses to start in production."
        )


def test_windows_installer_resolves_port_conflicts_rather_than_refusing() -> None:
    """A busy port must move the publication, not stop the install.

    `make up` runs `scripts/resolve_port_conflicts.py`, which republishes the
    conflicting port and writes `docker-compose.ports.yml`. install.ps1 used
    to `exit 3` and tell the operator to edit `docker-compose.yml` by hand —
    on the two conditions most likely in this audience's environment, an
    existing Postgres on 5432 or an Ollama on 11434 — while README.md
    promises "a port already in use does not stop the install".
    """
    resolver = "resolve_port_conflicts.py"
    assert resolver in _makefile_recipe("_ports"), f"`make up` no longer runs {resolver}; update this gate and install.ps1 together"
    actions = _action_lines(_read(INSTALL_PS1))
    assert resolver in actions, (
        f"install.ps1 never runs scripts/{resolver}, so a port already in use is a hard stop on Windows "
        "while the same condition is resolved automatically on the `make up` path."
    )


def test_windows_installer_passes_the_port_overlay_to_every_compose_call() -> None:
    """Starting a remapped stack and then addressing the base composition is
    two different stacks: `ps` reports nothing to wait for and
    `bootstrap_admin` runs against a project the operator is not using. The
    Makefile funnels every call through its `COMPOSE` variable for this
    reason; install.ps1 funnels them through `Get-ComposeArgs`."""
    overlay = "docker-compose.ports.yml"
    assert overlay in _read(MAKEFILE), f"the Makefile no longer builds {overlay}; update this gate and install.ps1 together"
    actions = _action_lines(_read(INSTALL_PS1))
    assert overlay in actions, f"install.ps1 never references {overlay}, so a remapped stack is addressed inconsistently"

    # Every `& docker` invocation that speaks to the project must go through
    # the helper. A raw `docker compose …` would silently target the base
    # composition.
    raw = [line.strip() for line in actions.splitlines() if re.search(r"&\s*docker\s+compose\b", line) and "version" not in line]
    assert not raw, "install.ps1 calls compose without the port overlay:\n  " + "\n  ".join(raw)


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
    assert ps1_majors == sh_majors, f"install.sh requires Node {sorted(sh_majors)} and install.ps1 requires {sorted(ps1_majors)}"


# ── Paths the scripts tell a user to run ────────────────────────────────────

# `.\scripts\install\uninstall.ps1` was printed by the closing banner for a
# release. The file is `uninstall.ps1`, at the repository root, and has never
# been anywhere else — so the last thing the installer told a Windows user to
# do could not work.
_PS1_PATH = re.compile(r"\.\\([A-Za-z0-9_\\\-./]+\.ps1)")


@pytest.mark.parametrize("script", [INSTALL_PS1, UNINSTALL_PS1], ids=lambda p: p.name)
def test_referenced_powershell_paths_exist(script: Path) -> None:
    text = _read(script)
    missing = sorted({candidate for candidate in _PS1_PATH.findall(text) if not (REPO / candidate.replace("\\", "/")).is_file()})
    assert not missing, f"{script.name} tells the user to run files that are not in the repository: {missing}"


def test_windows_uninstaller_tears_down_the_stack_the_installer_starts() -> None:
    """Tearing down only the demo project left every CORE container running,
    Postgres still holding 5432, under a banner saying the uninstall was
    complete."""
    code = "\n".join(_code_lines(_read(UNINSTALL_PS1)))
    assert "'docker-compose.yml'" in code or '"docker-compose.yml"' in code, (
        "uninstall.ps1 never brings down the root docker-compose.yml project, which is the one install.ps1 starts."
    )
