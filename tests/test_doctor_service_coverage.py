"""`make doctor` must check every service CORE actually starts.

The failure this pins
---------------------
A `make up` aborted by a failed model pull left ten services in `Created`.
The doctor reported `api is not running` and `fusion is not running — events
will never become alerts`, and never once mentioned `ollama-pull`, `litellm`
or the model — the thing that had actually failed. Both lines it printed were
true, and both sent an operator to debug a service that was fine.

Part of that was coverage: its Services section checked six of the sixteen
services CORE starts, so `litellm`, `ollama`, `connectors`, `actions`,
`threatintel`, `qdrant` and `zookeeper` could all be dead while the section
reported clean.

Two-directional, like `test_doctor_port_coverage.py` and for the same
reason: a one-directional check is how a hand-kept list goes stale. Every
CORE service must be checked, and every service the doctor checks must still
be in CORE, so an entry does not linger after a service is removed.

Out of scope, deliberately
--------------------------
`full`-profile services. `make doctor` does not read the profile by default,
and reporting a service that is not starting as missing would fail a correct
deployment.
"""

from __future__ import annotations

import pathlib
import re

import pytest
import yaml

REPO = pathlib.Path(__file__).resolve().parents[1]
DOCTOR = REPO / "scripts" / "doctor.sh"
COMPOSE = REPO / "docker-compose.yml"

#: One-shots. They run, exit and are gone, so "is it running" is the wrong
#: question for them — the "Containers that exited" section is where they are
#: accounted for, and `ollama-pull` additionally gets the "Local model"
#: section, which asks whether the model is there rather than whether the
#: container succeeded.
ONE_SHOTS = frozenset({"ollama-pull"})


def _core_services() -> set[str]:
    document = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    services = document.get("services") or {}
    assert services, "docker-compose.yml declares no services"
    return {name for name, spec in services.items() if not (spec or {}).get("profiles")}


def _checked_services() -> set[str]:
    """Every service name the doctor probes, however it probes it.

    Read as `svc_running <name>` calls, which is the one thing every check in
    the file goes through, plus the fixed four-field specs the HTTP loop
    splits. Reading the specs alone would miss postgres, redis and kafka,
    which are checked by shelling into them.
    """
    text = DOCTOR.read_text(encoding="utf-8")

    names = set(re.findall(r"svc_running\s+([a-z0-9][a-z0-9-]*)", text))
    names |= set(re.findall(r'"\d+\s+([a-z0-9][a-z0-9-]*)\s+\d+\s+\S+"', text))
    names |= set(re.findall(r"check_http_service\s+([a-z0-9][a-z0-9-]*)", text))
    # `svc_running "$1"` inside a helper resolves at runtime; the loop specs
    # above are what name those services, so the quoted-variable form is not
    # a service name and is dropped.
    return {n for n in names if not n.startswith("$")}


def test_the_reader_found_something() -> None:
    """A regex that matched nothing would make every assertion below vacuous.

    Deliberately a low bar. "Is coverage adequate" is the next two tests'
    question; this one only asks whether the two readers read anything, so a
    tree with genuinely poor coverage fails there — naming the services — and
    not here with a message about a regex.
    """
    assert len(_core_services()) >= 5, "the CORE profile reader found implausibly few services"
    assert len(_checked_services()) >= 5, "the doctor reader found implausibly few checked services"


@pytest.mark.parametrize("service", sorted(_core_services() - ONE_SHOTS))
def test_every_core_service_is_checked(service: str) -> None:
    assert service in _checked_services(), (
        f"{service} starts in CORE and `make doctor` never looks at it, so it can be dead while the "
        f"Services section reports clean. Add it to the HTTP probe loop in scripts/doctor.sh, or give it "
        f"a check of its own if it speaks no HTTP."
    )


@pytest.mark.parametrize("service", sorted(_checked_services()))
def test_every_checked_service_is_still_real(service: str) -> None:
    document = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    declared = set(document.get("services") or {})
    assert service in declared, (
        f"`make doctor` checks {service}, which docker-compose.yml no longer declares. A check for a "
        f"service that cannot exist reports a failure nobody can fix."
    )


def test_the_model_is_checked_by_asking_ollama_not_by_the_pull_exit_code() -> None:
    """`ollama-pull` exits 0 on a failed download, by design.

    That is what stops a registry outage aborting the stack — and it means
    the pull's exit code carries no information about the model. So the check
    has to ask Ollama what it has.
    """
    text = DOCTOR.read_text(encoding="utf-8")

    assert "/api/tags" in text, "the doctor does not ask Ollama which models it holds"
    assert "AISOC_LLM_LOCAL_MODEL" in text, "the doctor does not know which model this deployment expects"
    assert "ollama-pull" in text, "a missing model must name the container that was supposed to fetch it"


def test_a_container_that_exited_non_zero_is_reported() -> None:
    """There was no check for this at all, which is why the wrong service was named."""
    text = DOCTOR.read_text(encoding="utf-8")

    assert "ps -a" in text, "the doctor reads `ps`, which omits containers that have exited — the state the failing one was in"
    assert "ExitCode" in text, "the doctor never reads an exit code, so a crashed container reads as absent"
