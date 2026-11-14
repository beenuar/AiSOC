#!/usr/bin/env python3
"""The local model is optional, and nothing about it may stop the stack booting.

What went wrong
---------------
`make up` from a clean worktree exited 2 after 62 seconds with **10 of the 16
CORE services still in `Created` and never started** — no console, no API, no
pipeline, no administrator account. The cause was one line:

    litellm:
      depends_on:
        ollama-pull:
          condition: service_completed_successfully

Compose aborts the *entire* `up` when a `service_completed_successfully`
dependency exits non-zero, and it collects every service it has not started
yet. So a 2 GB model that would not download stopped `api`, `web`, `fusion`,
`ingest`, `agents`, `connectors`, `actions`, `realtime` and `threatintel`,
none of which has any relationship to a model. The trigger that day was TLS
interception on the host; a registry outage, a rate limit, a full disk, no
network, or an upstream tag deletion — which has happened to this stack
before — all land in the same place.

What this gate enforces
-----------------------
1. **Nothing may depend on `ollama-pull`.** Not with
   `service_completed_successfully`, and not with anything else: there is no
   ordering benefit worth "the product does not start".
2. **`ollama-pull` may not block on a health condition.** A
   `service_healthy` edge that never passes aborts `up` the same way, one
   layer up. The wait belongs inside the container, where timing out is a
   message rather than an abort.
3. **The pull program must be non-fatal**, declared by the
   `aisoc: model-pull-is-not-fatal` marker and proved behaviourally by
   `tests/test_model_pull_is_not_fatal.py`. A non-zero exit here would fail
   `make up` even with the dependencies gone, because `_wait` in the Makefile
   reads `exited` with a non-zero code as broken.
4. **No service outside the model subsystem may block on a member of it**, so
   a future edge cannot reintroduce the coupling under a different name.

Why a gate rather than a comment
--------------------------------
The `depends_on` edge carried a comment explaining why it was there, and the
reasoning was locally sound ("a gateway up before the weights exist answers
the first triage request with model not found"). It was about one request and
it cost the whole stack. A reader restoring it would write the same comment.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_if_requested  # noqa: E402

self_test_if_requested(__file__)

try:
    import yaml
except ImportError:  # pragma: no cover - the gate jobs all install PyYAML
    print("check_llm_optional_at_boot: PyYAML is required", file=sys.stderr)
    raise SystemExit(2) from None

REPO = repo_root()
COMPOSE = REPO / "docker-compose.yml"

#: The local-model path. Everything here is a convenience: AiSOC's
#: deterministic triage runs without any of it.
MODEL_SUBSYSTEM = frozenset({"ollama", "ollama-pull", "litellm"})

#: The one-shot whose exit code used to be load-bearing.
PULL = "ollama-pull"

#: Conditions compose *waits* on, and therefore conditions whose failure
#: aborts the `up`. `service_started` only orders container creation.
BLOCKING = frozenset({"service_healthy", "service_completed_successfully"})

#: Declared in the compose file beside the pull program.
NOT_FATAL_MARKER = "aisoc: model-pull-is-not-fatal"


class GateError(RuntimeError):
    """The gate could not run, which is not the same as a clean result."""


def _services(document: dict) -> dict[str, dict]:
    services = document.get("services")
    if not isinstance(services, dict) or not services:
        raise GateError("docker-compose.yml declares no services; finding nothing and reading nothing print the same word")
    return services


def _depends_on(service: dict) -> dict[str, str]:
    """`{dependency: condition}`, for both compose spellings.

    The short form (`depends_on: [a, b]`) carries no condition and is
    equivalent to `service_started`.
    """
    raw = service.get("depends_on")
    if raw is None:
        return {}
    if isinstance(raw, list):
        return dict.fromkeys(raw, "service_started")
    if isinstance(raw, dict):
        return {name: (spec or {}).get("condition", "service_started") for name, spec in raw.items()}
    raise GateError(f"unrecognised depends_on shape: {type(raw).__name__}")


def findings(text: str) -> list[str]:
    """Every violation in a compose document, as readable sentences."""
    document = yaml.safe_load(text)
    if not isinstance(document, dict):
        raise GateError("docker-compose.yml did not parse as a mapping")
    services = _services(document)

    out: list[str] = []

    if PULL not in services:
        raise GateError(f"{PULL} is not declared; this gate is about a service that does not exist")

    for name, service in sorted(services.items()):
        if not isinstance(service, dict):
            continue
        for dependency, condition in sorted(_depends_on(service).items()):
            if dependency == PULL:
                out.append(
                    f"{name} depends on {PULL} ({condition}). Compose aborts the whole `up` when a one-shot's "
                    f"condition fails and leaves every service it had not started in `Created`; a failed model "
                    f"download must not be able to stop {name}."
                )
                continue
            if dependency in MODEL_SUBSYSTEM and name not in MODEL_SUBSYSTEM and condition in BLOCKING:
                out.append(
                    f"{name} blocks on {dependency} ({condition}). The local model is optional — AiSOC triages "
                    f"deterministically without it — so no service outside the model subsystem may wait on it."
                )

    for dependency, condition in sorted(_depends_on(services[PULL]).items()):
        if condition in BLOCKING:
            out.append(
                f"{PULL} blocks on {dependency} ({condition}). A health condition that never passes aborts `up` "
                f"for every service compose has not started yet, which is the same failure one layer up. Wait "
                f"inside the container, where a timeout is a message."
            )

    if NOT_FATAL_MARKER not in text:
        out.append(
            f"the {NOT_FATAL_MARKER!r} marker is gone from docker-compose.yml. The pull program must exit 0 "
            f"whether or not the model arrives: `_wait` in the Makefile reads an `exited` container with a "
            f"non-zero code as broken, so a failing pull would still fail `make up` with every dependency removed. "
            f"tests/test_model_pull_is_not_fatal.py proves the behaviour; this only checks it is still claimed."
        )

    return out


def check() -> int:
    if not COMPOSE.is_file():
        raise GateError(f"{COMPOSE} is missing")
    problems = findings(COMPOSE.read_text(encoding="utf-8"))
    if problems:
        print("LOCAL MODEL CAN BLOCK THE BOOT:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    print("check_llm_optional_at_boot: OK — nothing waits on the local model, and a failed pull is not fatal")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="accepted for symmetry; this script only checks")
    parser.parse_args(argv)
    try:
        return check()
    except GateError as exc:
        print(f"check_llm_optional_at_boot: FAILED to run: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
