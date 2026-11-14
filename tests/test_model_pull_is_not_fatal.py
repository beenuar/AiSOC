"""A failed model download degrades AI triage and stops nothing else.

The failure this pins
---------------------
`make up` from a clean worktree exited 2 after 62 seconds with 10 of the 16
CORE services still in `Created` and never started, because `litellm` waited
on `ollama-pull` with `service_completed_successfully` and the pull failed.
`scripts/check_llm_optional_at_boot.py` holds the dependency graph; this
holds the other half, which a graph cannot express: the pull container must
**exit 0** whether or not the model arrives, and must say what is degraded.

The exit code is load-bearing in a second place that is easy to miss. `_wait`
in the Makefile collects any service that is `exited` with a non-zero code
into "These services are not running" and fails `make up`. So even with every
`depends_on` removed, a pull that exited 1 would still fail the documented
first run over a capability that is working as designed.

Why the program is extracted and run rather than read
-----------------------------------------------------
A substring assertion against the YAML would pass on a program that does not
run — the defect class this repository keeps finding. So the script is pulled
out of `docker-compose.yml` and executed by `/bin/sh` against a stub `ollama`,
which is exactly what the container does.

Compose turns `$$` into `$` before the container sees the command, so the
extraction un-escapes it the same way. Verified against the real binary
(Compose v5.1.3) with a one-service probe: `v="$$FOO"; echo "value=$$v"` with
`FOO: bar` printed `value=bar`.
"""

from __future__ import annotations

import os
import pathlib
import stat
import subprocess
import tempfile

import pytest
import yaml

REPO = pathlib.Path(__file__).resolve().parents[1]
COMPOSE = REPO / "docker-compose.yml"

PULL_SERVICE = "ollama-pull"
MODEL = "llama3.2:3b-instruct-q4_K_M"

#: `sleep` is stubbed out alongside `ollama`. The program sleeps between
#: retries and while waiting for the server, which is right in a container
#: that blocks nothing and wrong in a test that would take three minutes to
#: assert an exit code. Only the waiting is removed; every branch still runs.
_STUBBED = ("ollama", "sleep")


def _pull_program() -> str:
    """The shell program compose hands to `/bin/sh -c`, as the container gets it."""
    document = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    service = document["services"][PULL_SERVICE]

    assert service.get("entrypoint") == ["/bin/sh", "-c"], f"{PULL_SERVICE} no longer runs a shell program; this test extracts one"
    command = service.get("command")
    assert isinstance(command, list) and len(command) == 1, f"{PULL_SERVICE} command is not a single shell program"

    return command[0].replace("$$", "$")


def _run(program: str, *, list_rc: int, show_rc: int, pull_rc: int) -> subprocess.CompletedProcess[str]:
    """Run the program with an `ollama` that answers however the case needs."""
    with tempfile.TemporaryDirectory() as raw:
        binaries = pathlib.Path(raw)

        (binaries / "ollama").write_text(
            "#!/bin/sh\n"
            'echo "ollama $*" >> "$OLLAMA_CALLS"\n'
            'case "$1" in\n'
            f"  list) exit {list_rc} ;;\n"
            f"  show) exit {show_rc} ;;\n"
            f'  pull) echo "pull: simulated"; exit {pull_rc} ;;\n'
            "  *) exit 127 ;;\n"
            "esac\n",
            encoding="utf-8",
        )
        # Not `exit 0` on its own: the program calls `sleep 2` and `sleep 5`,
        # and a stub that rejected arguments would mask a typo in them.
        (binaries / "sleep").write_text('#!/bin/sh\n[ -n "$1" ] || exit 2\nexit 0\n', encoding="utf-8")
        for name in _STUBBED:
            path = binaries / name
            path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

        calls = binaries / "calls.log"
        calls.write_text("", encoding="utf-8")

        result = subprocess.run(
            ["/bin/sh", "-c", program],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
            env={
                **os.environ,
                "PATH": f"{binaries}:{os.environ.get('PATH', '')}",
                "AISOC_LLM_LOCAL_MODEL": MODEL,
                "OLLAMA_CALLS": str(calls),
            },
        )
        result.stderr += f"\n--- calls ---\n{calls.read_text(encoding='utf-8')}"
        return result


@pytest.fixture(scope="module")
def program() -> str:
    return _pull_program()


def test_a_download_that_cannot_succeed_still_exits_zero(program: str) -> None:
    """The reported failure: the registry is unreachable, the stack must come up."""
    result = _run(program, list_rc=0, show_rc=1, pull_rc=1)

    assert result.returncode == 0, (
        "the pull exited non-zero. Compose aborts the whole `up` on a failed "
        "`service_completed_successfully` dependency, and `_wait` fails `make up` on a non-zero exit, so this "
        f"code is what left 10 of 16 CORE services in `Created`.\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    assert "ollama pull" in result.stderr, "the program never attempted the pull"


def test_the_failure_says_what_is_degraded_and_what_still_works(program: str) -> None:
    """Degradation stated, not silent — and specific enough to act on."""
    out = _run(program, list_rc=0, show_rc=1, pull_rc=1).stdout

    assert MODEL in out, "the message does not name the model that failed"
    assert "AI triage" in out, "the message does not name the capability that is degraded"
    assert "deterministic" in out, "the message does not say what AiSOC does instead"
    # Naming a cause the operator can check, and a command they can run, is
    # the difference between a diagnosis and an apology.
    assert "docker compose run --rm ollama-pull" in out, "the message offers no way to retry"
    assert "make up-host-llm" in out, "the message offers no alternative model"
    assert "proxy" in out or "network" in out, "the message names no likely cause"

    for unaffected in ("ingest", "fusion", "console"):
        assert unaffected in out, f"the message does not reassure that {unaffected} is unaffected"


def test_it_retries_before_giving_up(program: str) -> None:
    """A single transient failure must not cost the model for the whole run."""
    calls = _run(program, list_rc=0, show_rc=1, pull_rc=1).stderr
    attempts = calls.count(f"ollama pull {MODEL}")
    assert attempts == 3, f"expected 3 pull attempts, saw {attempts}"


def test_a_cached_model_is_not_re_pulled(program: str) -> None:
    """A second `up` must cost one `ollama show`, not a download."""
    result = _run(program, list_rc=0, show_rc=0, pull_rc=0)

    assert result.returncode == 0
    assert "already present" in result.stdout
    assert f"ollama pull {MODEL}" not in result.stderr, "a cached model was pulled again"


def test_a_successful_pull_says_so(program: str) -> None:
    """The positive control. Without it, a program that only ever printed the
    failure banner would pass every assertion above."""
    result = _run(program, list_rc=0, show_rc=1, pull_rc=0)

    assert result.returncode == 0
    assert "is ready" in result.stdout
    assert "could not be downloaded" not in result.stdout, "a successful pull reported a failure"
    assert result.stderr.count(f"ollama pull {MODEL}") == 1, "a successful pull was retried"


def test_an_ollama_that_never_answers_is_not_fatal_either(program: str) -> None:
    """The second abort path: the server itself never comes up.

    `ollama-pull` used to wait on `condition: service_healthy`, so this case
    aborted `up` before the program ran at all. The wait is now inside the
    program, which means it has to end.
    """
    result = _run(program, list_rc=1, show_rc=1, pull_rc=1)

    assert result.returncode == 0, f"a dead Ollama still fails the boot.\nstdout:\n{result.stdout}"
    assert "could not be downloaded" in result.stdout
