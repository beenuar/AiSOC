"""A CI step must not hard-code a value first run now generates.

What happened
-------------
`.env.example` shipped `CLICKHOUSE_PASSWORD=clickhouse_dev_secret` and the
integration job's lake assertion connected with that literal. When the
datastore passwords moved into `scripts/ensure_env.py::GENERATED` — so a
production guard could not be satisfied by a published credential — the job
kept using the literal while the server it was talking to had a freshly
generated one.

The failure named the wrong subsystem. The query was wrapped in
`2>/dev/null || echo 0`, so "wrong password" and "empty table" produced the
same number, and the step reported:

    ::error::ClickHouse lake was never populated from the raw-events stream

against a fusion worker that had written to it correctly.

What is asserted
----------------
Any workflow that runs `scripts/ensure_env.py` is in a world where every
`GENERATED` value is random. Such a workflow must not also contain the
literal that variable used to ship as. The literals are read from git
history's `.env.example`? No — they are read from the compose defaults,
which is where they still live, so this stays true as those move.

Unaffected workflows are not scanned: `upgrade-test.yml` provisions its own
Postgres with its own password and never runs the generator, and a value it
chooses for itself is not a stale copy of anything.
"""

from __future__ import annotations

import importlib.util
import pathlib
import re
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
WORKFLOWS = REPO / ".github" / "workflows"
SCRIPTS = REPO / "scripts"

sys.path.insert(0, str(SCRIPTS))


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ensure_env = _load("ensure_env")
check_published_secrets = _load("check_published_secrets")

#: `${VAR:-literal}` in `docker-compose.yml`, which is where the value a
#: variable used to ship as still lives.
_DEFAULT_RE = re.compile(r"\$\{([A-Z0-9_]+):-([^}]+)\}")


def _former_literals() -> dict[str, str]:
    """`variable -> the compose default`, for the variables first run generates."""
    text = (REPO / "docker-compose.yml").read_text(encoding="utf-8")
    defaults = dict(_DEFAULT_RE.findall(text))
    return {name: value for name, value in defaults.items() if name in ensure_env.GENERATED and value.strip()}


def _workflows_running_the_generator() -> list[pathlib.Path]:
    return [p for p in sorted(WORKFLOWS.glob("*.yml")) if "ensure_env.py" in p.read_text(encoding="utf-8")]


def test_the_inputs_are_not_empty() -> None:
    """Both halves. With no generated secret carrying a compose default, or
    no workflow running the generator, the check below passes over nothing."""
    assert _former_literals(), "no generated secret has a compose default — the harvest is wrong"
    assert _workflows_running_the_generator(), "no workflow runs ensure_env.py — the scan would cover nothing"


@pytest.mark.parametrize("workflow", _workflows_running_the_generator(), ids=lambda p: p.name)
def test_no_step_uses_a_literal_the_generator_replaces(workflow: pathlib.Path) -> None:
    text = workflow.read_text(encoding="utf-8")
    # Comments explain the defect and are allowed to name the literal; a
    # command that uses one is the thing being caught.
    live = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))

    found = [f"  {name}'s former default {literal!r}" for name, literal in sorted(_former_literals().items()) if literal in live]
    assert not found, (
        f"{workflow.name} runs scripts/ensure_env.py, so these are random at run time, "
        "and it also contains the literal they used to ship as:\n"
        + "\n".join(found)
        + "\n\nRead the value out of `.env` instead — `sed -n 's/^NAME=//p' .env | tail -1`."
    )


def test_the_checker_agrees_these_are_published_values() -> None:
    """Cross-check against the other direction: every literal this test
    forbids in a generator-running workflow is one `check_published_secrets`
    refuses in a production environment. If the two lists diverged, one of
    them would be describing a value that no longer exists."""
    published = check_published_secrets.published_literals(REPO)
    unknown = sorted(v for v in _former_literals().values() if v not in published)
    assert not unknown, f"these compose defaults are not harvested as published values: {unknown}"
