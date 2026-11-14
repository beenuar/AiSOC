"""Every command `make doctor` prints must be the command the Makefile runs.

The damage
----------
`scripts/resolve_port_conflicts.py` writes `docker-compose.ports.yml` when a
host port AiSOC publishes is already taken, and the Makefile passes it as a
second `-f` for every compose invocation. The doctor printed remediations as
a bare `docker compose up -d <svc>`.

On a host with its own Postgres, that is not merely incomplete advice — it is
destructive. Following it recreated `aisoc-postgres` *without* the remap, the
bind failed with "Bind for 0.0.0.0:5432 failed: port is already allocated",
and a healthy container was left in `Created`. The stack was worse after
taking the doctor's advice than before it.

The invariant
-------------
There is exactly one place in `doctor.sh` that may name compose: the marked
block that resolves `$COMPOSE` and `$COMPOSE_HINT`, including the overlay
when it exists. Everywhere else uses those variables, so a remediation cannot
drift from what the Makefile actually runs.

Prose is not a command. "docker compose v2 is not available" names the tool,
and `docker compose version` asks it which version it is — neither acts on
this project, and substituting a variable into them would make the message
worse. So the rule is scoped to subcommands that touch the project, which is
the set that can do harm.
"""

from __future__ import annotations

import pathlib
import re

DOCTOR = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "doctor.sh"
MAKEFILE = pathlib.Path(__file__).resolve().parents[1] / "Makefile"

_BLOCK_OPEN = "# doctor:compose-command"
_BLOCK_CLOSE = "# }"

#: Subcommands that act on this deployment. `version` and `--help` do not.
_PROJECT_SUBCOMMANDS = (
    "up",
    "down",
    "restart",
    "logs",
    "ps",
    "run",
    "exec",
    "build",
    "pull",
    "port",
    "stop",
    "start",
    "kill",
    "rm",
    "config",
    "--profile",
    "-f",
)

_NAMES_COMPOSE = re.compile(r"docker\s+compose\s+(" + "|".join(re.escape(s) for s in _PROJECT_SUBCOMMANDS) + r")\b")


def _body_outside_the_marked_block() -> list[tuple[int, str]]:
    """Every non-comment line of `doctor.sh` that is not inside the block."""
    out: list[tuple[int, str]] = []
    inside = False
    for number, line in enumerate(DOCTOR.read_text(encoding="utf-8").splitlines(), start=1):
        if line.strip().startswith(_BLOCK_OPEN):
            inside = True
            continue
        if inside and line.strip() == _BLOCK_CLOSE:
            inside = False
            continue
        if inside or line.lstrip().startswith("#"):
            continue
        out.append((number, line))
    return out


def test_the_marked_block_exists_and_is_closed() -> None:
    """Without it this whole test passes over a file it never read properly."""
    text = DOCTOR.read_text(encoding="utf-8")
    assert _BLOCK_OPEN in text, f"{DOCTOR.name} no longer carries the {_BLOCK_OPEN} marker"
    assert f"\n{_BLOCK_CLOSE}\n" in text, f"the {_BLOCK_OPEN} block is not closed with a `{_BLOCK_CLOSE}` line"
    assert _body_outside_the_marked_block(), "nothing outside the block was scanned, so this test proves nothing"


def test_no_remediation_names_compose_directly() -> None:
    offenders = [(n, line.strip()) for n, line in _body_outside_the_marked_block() if _NAMES_COMPOSE.search(line)]
    assert not offenders, (
        "these lines name compose directly, so the command they print or run omits the\n"
        "`-f docker-compose.ports.yml` overlay the Makefile passes. Following one of them\n"
        "recreates a container without its port remap and can destroy a working datastore.\n"
        "Use $COMPOSE (to run) or $COMPOSE_HINT (to print) instead:\n" + "\n".join(f"  {n}: {line}" for n, line in offenders)
    )


def test_the_block_actually_adds_the_overlay() -> None:
    """The variables are only worth anything if one of them carries the flags."""
    text = DOCTOR.read_text(encoding="utf-8")
    block = text[text.index(_BLOCK_OPEN) : text.index(f"\n{_BLOCK_CLOSE}\n")]

    assert "docker-compose.ports.yml" in block, "the compose block does not mention the port overlay at all"
    assert "-f docker-compose.yml -f docker-compose.ports.yml" in block, (
        "the overlay must be a *second* -f: compose replaces the default file list when any -f is given, "
        "so `-f docker-compose.ports.yml` alone would start nothing"
    )
    assert "COMPOSE_HINT=" in block, "no COMPOSE_HINT is defined, so remediations have nothing to print"


def test_the_overlay_name_matches_the_makefile() -> None:
    """Two files naming one generated artefact is how this drifts back apart."""
    overlay = "docker-compose.ports.yml"
    assert overlay in MAKEFILE.read_text(encoding="utf-8"), (
        f"the Makefile no longer mentions {overlay}; doctor is pointing at an artefact nothing generates"
    )
