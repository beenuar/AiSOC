"""`make doctor` must pre-flight every port CORE actually publishes.

`up` runs `doctor.sh --ports-only` before compose for one reason, written in
the Makefile: compose reports a conflict as ``Bind for 127.0.0.1:5432 failed:
port is already allocated`` against whichever container lost the race, which
names neither the process holding the port nor what to do about it, and by
then half the stack is running.

A pre-flight that covers some of the ports still lets that happen, and it did.
The list held six entries and CORE publishes sixteen. The missing one that
matters most was **11434**: CORE gained a bundled Ollama, and the single most
likely conflict for a product whose pitch is "runs a local model" is an
operator who already has Ollama installed. Measured on a host in exactly that
state, `make up` passed the port check and the model the stack pulled was not
the model answering on that port.

So the gate is two-directional, because a one-directional one is how the list
went stale in the first place:

* every CORE-published host port must appear in the doctor's list, and
* every port in the doctor's list must still be published by CORE, so an
  entry does not linger after a service is removed or remapped.

`make doctor` does not read the profile, so `full`-profile ports are out of
scope here — checking a port for a service that is not starting would fail a
deployment over a conflict that cannot occur.
"""

from __future__ import annotations

import pathlib
import re

import pytest
import yaml

REPO = pathlib.Path(__file__).resolve().parents[1]
DOCTOR = REPO / "scripts" / "doctor.sh"
COMPOSE = REPO / "docker-compose.yml"

#: `"<host> <service> <container>"`, the three-field spec the shell loop splits.
_SPEC = re.compile(r'"(\d+)\s+([a-z0-9-]+)\s+(\d+)"')

def _host_port(entry: str) -> str | None:
    """The host port of a `ports:` entry, or None when it publishes none.

    Split from the right rather than matched, because the bind address is an
    interpolation and the console's nests one inside another —
    `${AISOC_CONSOLE_BIND_ADDR:-${AISOC_BIND_ADDR:-127.0.0.1}}:3000:3000`.
    A leading `\\$\\{[^}]*\\}` stops at the first `}` and silently skips that
    line, which would have excused the console from this gate entirely.
    """
    fields = entry.rsplit(":", 2)
    if len(fields) == 3 and fields[1].isdigit():
        return fields[1]
    # `"9092:9092"` — published on every interface, no bind address.
    if len(fields) == 2 and fields[0].isdigit() and fields[1].split("/")[0].isdigit():
        return fields[0]
    return None


def _doctor_specs() -> set[tuple[str, str]]:
    """`(host_port, service)` pairs the port pre-flight checks."""
    text = DOCTOR.read_text(encoding="utf-8")
    start = text.index("# host-port service container-port")
    end = text.index("done", start)
    return {(host, service) for host, service, _ in _SPEC.findall(text[start:end])}


def _core_published() -> set[tuple[str, str]]:
    """`(host_port, service)` pairs CORE publishes, from the compose file.

    CORE is "has no `profiles:` key" — the same rule `docker compose up` with
    no `--profile` applies.
    """
    services = (yaml.safe_load(COMPOSE.read_text(encoding="utf-8")) or {}).get("services") or {}
    published: set[tuple[str, str]] = set()
    for name, service in services.items():
        if (service or {}).get("profiles"):
            continue
        for entry in (service or {}).get("ports") or []:
            host = _host_port(str(entry))
            if host:
                published.add((host, name))
    return published


@pytest.fixture(scope="module")
def specs() -> set[tuple[str, str]]:
    return _doctor_specs()


@pytest.fixture(scope="module")
def core() -> set[tuple[str, str]]:
    return _core_published()


def test_the_fixtures_found_something(specs: set, core: set) -> None:
    """Both parsers must actually parse, or the comparisons below are vacuous."""
    assert len(specs) >= 6, f"parsed {len(specs)} specs out of doctor.sh"
    assert len(core) >= 6, f"parsed {len(core)} published CORE ports out of docker-compose.yml"


def test_every_core_port_is_pre_flighted(specs: set, core: set) -> None:
    missing = sorted(core - specs, key=lambda pair: int(pair[0]))
    assert not missing, (
        "these CORE services publish a host port that `make up` does not check first, so a conflict "
        f"on one arrives as a compose bind failure mid-start: {missing}"
    )


def test_no_pre_flighted_port_has_stopped_being_published(specs: set, core: set) -> None:
    """The other direction: a stale entry fails a start over an impossible conflict."""
    stale = sorted(specs - core, key=lambda pair: int(pair[0]))
    assert not stale, f"doctor.sh checks these, but CORE no longer publishes them: {stale}"


def test_the_bundled_model_port_is_covered(specs: set) -> None:
    """Named explicitly because it is the conflict this audience actually hits.

    An operator evaluating a self-hosted AI SOC is unusually likely to have
    Ollama already listening on 11434. Docker Desktop does not always fail the
    bind, so the symptom is not an error — it is the gateway talking to the
    wrong model.
    """
    assert ("11434", "ollama") in specs
