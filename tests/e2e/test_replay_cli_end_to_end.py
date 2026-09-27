"""The CLI, three services and a mocked Splunk ES: the phase's acceptance bar.

Gap-closure Phase 1.4.

What this proves
----------------
Phase 1's "Done when" reads: *the CLI, run against a mocked Splunk ES holding
200 recorded closed notables, produces a report that reproduces byte for byte
on a second run with the deterministic model path.*

Three of its four links were already proven by unit suites:

* mocked Splunk to 200 closed findings, in
  ``services/actions/tests/test_alert_history.py``
* findings to decisions, reproducibly, in
  ``services/agents/tests/test_replay_runner.py``
* decisions to a byte-identical report, in
  ``packages/aisoc-benchmark/tests/test_replay_metrics.py``

The fourth is CLI to API to report, end to end, and it is what this file is.
Three proven links are not the same claim as one end-to-end run.

Why it spawns processes instead of importing
--------------------------------------------
No Python process can hold two of these services. ``services/actions`` owns
the SIEM credential path, ``services/agents`` owns triage and
``services/connectors`` owns ``normalize()``; all three package their code as
top-level ``app``, so a process importing two of them would import two modules
called ``app`` and get one of them. That is the same constraint that put the
orchestration in the API rather than in the CLI, and it means an end-to-end
run is four processes, a database and a mock vendor.

They are started from the source tree with uvicorn rather than from images, so
this proves the code in the working tree rather than whatever was last
published.

Exactly one field is excluded
-----------------------------
Mean and p95 latency measure the machine the replay ran on and will differ
between two runs on one host. ``--exclude-latency`` asks the API for the
report with those two figures replaced by a note; everything else is a
property of the input and the code. The claim is therefore stated precisely:
byte for byte apart from wall-clock latency. ``test_only_latency_differs``
below asserts that the exclusion is the *only* thing standing between the two
runs, by comparing the unexcluded reports too.

Running it
----------
Needs a Postgres with the migration chain applied::

    docker run -d --name aisoc-e2e-pg -e POSTGRES_USER=aisoc \\
        -e POSTGRES_PASSWORD=aisoc -e POSTGRES_DB=aisoc -p 55433:5432 postgres:16
    export AISOC_E2E_DATABASE_MIGRATION_URL=postgresql+asyncpg://aisoc:aisoc@127.0.0.1:55433/aisoc
    export AISOC_APP_DB_PASSWORD=aisoc_app
    export AISOC_E2E_DATABASE_URL=postgresql+asyncpg://aisoc_app:aisoc_app@127.0.0.1:55433/aisoc
    python -m pytest tests/e2e/test_replay_cli_end_to_end.py

Skips when no database is configured, so a local ``pytest tests/`` stays
green. It **cannot** skip where it is supposed to run: ``integration.yml``
sets ``AISOC_REPLAY_E2E_REQUIRED=1`` and an unreachable database is then a
failure. A gate that quietly declines to run looks identical to one that
passed, and this repository has shipped that exact shape more than once.
"""

from __future__ import annotations

import http.server
import json
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

#: What the four services connect as. This is deliberately **not** the owner:
#: `061_runtime_app_role.sql` moves the deployment onto a DML-only `aisoc_app`
#: that the row-level-security policies apply to, and a superuser ignores every
#: policy in the schema even under `FORCE ROW LEVEL SECURITY`. Running the
#: end-to-end proof as the owner would measure a role nothing ships.
DSN = os.environ.get("AISOC_E2E_DATABASE_URL", "").strip()

#: The owner. Used for the migration chain and for creating the administrator,
#: both of which need privileges the runtime role deliberately lacks. Falls
#: back to `DSN` so a single-role setup still runs.
MIGRATION_DSN = os.environ.get("AISOC_E2E_DATABASE_MIGRATION_URL", "").strip() or DSN

REQUIRED = os.environ.get("AISOC_REPLAY_E2E_REQUIRED", "").strip() not in ("", "0", "false")

pytestmark = pytest.mark.skipif(
    not DSN and not REQUIRED,
    reason="needs a live Postgres with the migration chain applied (integration.yml)",
)

#: Long enough that a report reproducing is evidence rather than coincidence,
#: and the number the phase's acceptance bar names.
NOTABLE_COUNT = 200

#: Fixed so the window, the split and therefore the report do not depend on
#: the day the test runs. An unpinned window is a different window on a second
#: run, which is a different report for a reason that has nothing to do with
#: determinism.
WINDOW_START = datetime(2026, 3, 1, tzinfo=UTC)
WINDOW_END = datetime(2026, 6, 1, tzinfo=UTC)

SERVICE_TOKEN = "replay-e2e-service-token"
SECRET_KEY = "replay-e2e-secret-key-at-least-32-characters"

#: A real administrator, created by the deployment's own bootstrap script and
#: signed in through the real login route. The dev-mode auth bypass would have
#: been one line shorter and would have proved less: it skips the permission
#: checks these routes declare (`connectors:write` to start a run,
#: `reports:read` to read one), so a run under it could not tell a correctly
#: gated surface from an ungated one.
ADMIN_EMAIL = "replay-e2e@example.com"
ADMIN_PASSWORD = "replay-e2e-Password-1234"


# ---------------------------------------------------------------------------
# The recorded Splunk ES history
# ---------------------------------------------------------------------------


def _notables() -> list[dict[str, str]]:
    """200 closed notables, in the shape ``list_closed_notables`` selects.

    **Synthetic.** Hand-built to the field list the reader's SPL asks for.
    None of it came from a customer.

    The dispositions are laid out so the *test* window (the later 30% of the
    time split) holds more than the 30 malicious cases the report requires
    before it will print a headline accuracy. That is deliberate: a run whose
    headline is withheld would still reproduce byte for byte, and would prove
    less, because the withheld branch prints far fewer numbers.
    """
    rows: list[dict[str, str]] = []
    for index in range(NOTABLE_COUNT):
        closed_at = WINDOW_START + timedelta(hours=index * 6)
        # Two in three are true positives, which puts ~40 malicious cases in
        # the 60-finding test window.
        disposition = "disposition:1" if index % 3 != 2 else "disposition:3"
        rows.append(
            {
                "event_id": f"ES-{index:04d}",
                "rule_id": f"rule-{index % 7}",
                "rule_name": "Suspicious PowerShell execution",
                "search_name": "Suspicious PowerShell execution",
                "urgency": "high" if index % 2 == 0 else "medium",
                "disposition": disposition,
                "review_time": str(int(closed_at.timestamp())),
                "reviewer": f"analyst-{index % 4}",
                "comment": "Reviewed and closed.",
                "src": f"198.51.100.{index % 250}",
                "host": f"WS-{index % 50:03d}",
                "_time": str(int(closed_at.timestamp())),
            }
        )
    return rows


class _SplunkHandler(http.server.BaseHTTPRequestHandler):
    """The two REST endpoints ``SplunkClient.run_search`` actually calls."""

    rows: list[dict[str, str]] = []

    def log_message(self, *args: object) -> None:  # noqa: D102 - silence the default access log
        return

    def _json(self, payload: dict[str, object]) -> None:
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's naming
        if self.path.startswith("/services/search/jobs"):
            self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
            self._json({"sid": "e2e-search-1"})
            return
        self.send_error(404)

    def do_GET(self) -> None:  # noqa: N802
        if "/results" in self.path:
            self._json({"results": self.rows})
            return
        self.send_error(404)


# ---------------------------------------------------------------------------
# Process plumbing
# ---------------------------------------------------------------------------


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_for(url: str, *, timeout: float = 90.0, name: str = "") -> None:
    """Poll until a service answers, or fail naming which one did not.

    Any HTTP status counts as up, including a 404. The four services do not
    agree on a health path, and waiting for one specific path would make this
    a test of route naming rather than of whether the process is serving. An
    ASGI app that returns 404 has started, parsed its configuration and bound
    its port, which is the whole question here.

    A timeout is reported as "this service never came up", never as a skip. A
    harness that skips when a dependency is missing reports success for a run
    that measured nothing.
    """
    deadline = time.monotonic() + timeout
    last = ""
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as response:  # noqa: S310 - fixed localhost URL
                if response.status < 500:
                    return
        except urllib.error.HTTPError:
            # It answered. That is the signal.
            return
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            last = str(exc)
        time.sleep(0.3)
    raise AssertionError(f"{name or url} did not become reachable within {timeout:.0f}s (last error: {last})")


class _Service:
    """One uvicorn process, started from the source tree."""

    def __init__(self, name: str, directory: Path, port: int, env: dict[str, str]) -> None:
        self.name = name
        self.port = port
        self.log = open(  # noqa: SIM115 - held for the process lifetime, closed in stop()
            REPO_ROOT / f".e2e-{name}.log", "w", encoding="utf-8"
        )
        self.process = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
            [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(port)],
            cwd=str(directory),
            env={**os.environ, "PYTHONPATH": ".", **env},
            stdout=self.log,
            stderr=subprocess.STDOUT,
        )

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def wait(self, path: str = "/health") -> None:
        if self.process.poll() is not None:
            raise AssertionError(f"{self.name} exited immediately; see .e2e-{self.name}.log")
        _wait_for(f"{self.url}{path}", name=self.name)

    def stop(self) -> None:
        self.process.terminate()
        try:
            self.process.wait(timeout=15)
        except subprocess.TimeoutExpired:  # pragma: no cover - only on a wedged process
            self.process.kill()
        self.log.close()


@pytest.fixture(scope="module")
def splunk() -> Iterator[str]:
    _SplunkHandler.rows = _notables()
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _SplunkHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture(scope="module")
def stack(splunk: str) -> Iterator[dict[str, str]]:
    """actions, connectors, agents and the API, from the working tree."""
    if not DSN:
        raise AssertionError(
            "AISOC_REPLAY_E2E_REQUIRED is set but AISOC_E2E_DATABASE_URL is not. "
            "The end-to-end proof cannot run without a database, and reporting success "
            "for a run that measured nothing is the failure this guard exists to prevent."
        )

    # DDL and user creation run as the owner; everything the services do runs
    # as the runtime role. Collapsing the two is what let 92 RLS policies sit
    # inert for months elsewhere in this repository.
    owner_env = {
        "PYTHONPATH": ".",
        "DATABASE_URL": MIGRATION_DSN,
        "DATABASE_MIGRATION_URL": MIGRATION_DSN,
        "SECRET_KEY": SECRET_KEY,
    }
    migrate = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-m", "app.scripts.run_migrations"],
        cwd=str(REPO_ROOT / "services" / "api"),
        env={**os.environ, **owner_env},
        capture_output=True,
        text=True,
        check=False,
    )
    assert migrate.returncode == 0, f"migrations failed:\n{migrate.stdout}\n{migrate.stderr}"

    admin = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-m", "app.scripts.bootstrap_admin", "--password-stdin", "--reset-password"],
        cwd=str(REPO_ROOT / "services" / "api"),
        env={**os.environ, **owner_env, "AISOC_ADMIN_EMAIL": ADMIN_EMAIL},
        input=ADMIN_PASSWORD,
        capture_output=True,
        text=True,
        check=False,
    )
    assert admin.returncode == 0, f"bootstrap_admin failed:\n{admin.stdout}\n{admin.stderr}"

    ports = {name: _free_port() for name in ("actions", "connectors", "agents", "api")}
    shared = {
        "AISOC_DEV_MODE": "1",
        "AISOC_SERVICE_TOKEN": SERVICE_TOKEN,
        "SECRET_KEY": SECRET_KEY,
        # The deterministic model path. No key, no network, and the same
        # verdict for the same evidence every time.
        "AISOC_DETERMINISTIC": "1",
        "AISOC_CORS_ORIGINS": "http://127.0.0.1",
    }

    services = [
        _Service(
            "actions",
            REPO_ROOT / "services" / "actions",
            ports["actions"],
            {**shared, "AISOC_ACTIONS_SERVICE_TOKEN": SERVICE_TOKEN},
        ),
        _Service(
            "connectors",
            REPO_ROOT / "services" / "connectors",
            ports["connectors"],
            {**shared, "AISOC_CONNECTORS_DISABLE_SCHEDULER": "1"},
        ),
        _Service(
            "agents",
            REPO_ROOT / "services" / "agents",
            ports["agents"],
            {**shared, "CONNECTORS_SERVICE_URL": f"http://127.0.0.1:{ports['connectors']}"},
        ),
        _Service(
            "api",
            REPO_ROOT / "services" / "api",
            ports["api"],
            {
                **shared,
                "DATABASE_URL": DSN,
                "DATABASE_MIGRATION_URL": MIGRATION_DSN,
                "AISOC_ACTIONS_BASE_URL": f"http://127.0.0.1:{ports['actions']}",
                "AISOC_ACTIONS_SERVICE_TOKEN": SERVICE_TOKEN,
                "AGENTS_SERVICE_URL": f"http://127.0.0.1:{ports['agents']}",
                "CONNECTORS_SERVICE_URL": f"http://127.0.0.1:{ports['connectors']}",
            },
        ),
    ]
    try:
        for service in services:
            service.wait()
        api_url = services[-1].url
        yield {
            "api": api_url,
            "splunk": splunk,
            "token": _sign_in(api_url),
        }
    finally:
        for service in reversed(services):
            service.stop()


def _sign_in(api_url: str) -> str:
    """A real access token from the real login route."""
    request = urllib.request.Request(  # noqa: S310 - fixed localhost URL
        f"{api_url}/api/v1/auth/login",
        method="POST",
        data=json.dumps({"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
        body = json.loads(response.read())
    token = body.get("access_token")
    assert token, f"login returned no access token: {body}"
    return str(token)


def _api(stack: dict[str, str], method: str, path: str, payload: dict | None = None) -> dict:
    request = urllib.request.Request(  # noqa: S310 - fixed localhost URL
        f"{stack['api']}{path}",
        method=method,
        data=json.dumps(payload).encode() if payload is not None else None,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {stack['token']}"},
    )
    with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310
        return json.loads(response.read() or b"{}")


@pytest.fixture(scope="module")
def connector_id(stack: dict[str, str]) -> str:
    """A saved Splunk connector pointing at the mock, through the real API.

    Created through ``POST /connectors`` rather than inserted, so the
    credentials are encrypted by the same vault the job decrypts them with. A
    row written straight into the table would prove the replay works against
    plaintext nobody stores.
    """
    created = _api(
        stack,
        "POST",
        "/api/v1/connectors",
        {
            "name": "Splunk ES (end-to-end mock)",
            "connector_type": "splunk",
            "category": "siem",
            "auth_config": {"base_url": stack["splunk"], "token": "e2e-token"},
            "connector_config": {"ssl_verify": False},
        },
    )
    return str(created["id"])


def _run_cli(stack: dict[str, str], connector: str, output: Path) -> str:
    """One full `aisoc replay`, returning the report it wrote."""
    result = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [
            sys.executable,
            "-m",
            "aisoc_cli.main",
            "replay",
            "--api-url",
            stack["api"],
            "--api-key",
            stack["token"],
            "--connector-id",
            connector,
            "--since",
            WINDOW_START.isoformat(),
            "--until",
            WINDOW_END.isoformat(),
            "--exclude-latency",
            "--poll-interval",
            "1",
            "--timeout",
            "900",
            "--output",
            str(output),
        ],
        cwd=str(REPO_ROOT),
        env={**os.environ, "PYTHONPATH": str(REPO_ROOT / "packages" / "aisoc-cli" / "src")},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, f"aisoc replay failed:\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    return output.read_text()


@pytest.fixture(scope="module")
def two_runs(stack: dict[str, str], connector_id: str, tmp_path_factory: pytest.TempPathFactory) -> list[str]:
    """The same evaluation, twice, through the CLI.

    Module-scoped because each run replays 60 findings through the full chain
    and the whole point is to compare two of them, not to do it once per
    assertion.
    """
    directory = tmp_path_factory.mktemp("replay-e2e")
    return [
        _run_cli(stack, connector_id, directory / "first.md"),
        _run_cli(stack, connector_id, directory / "second.md"),
    ]


# ---------------------------------------------------------------------------
# The acceptance bar
# ---------------------------------------------------------------------------


def test_the_report_reproduces_byte_for_byte(two_runs: list[str]) -> None:
    """Phase 1's "Done when", end to end.

    Two invocations of the CLI, against a mocked Splunk ES holding 200
    recorded closed notables, through the API, the actions service, the
    connectors service and the agents service, on the deterministic model
    path.
    """
    first, second = two_runs

    assert first == second
    assert first.encode() == second.encode()


def test_the_report_describes_the_history_it_was_given(two_runs: list[str]) -> None:
    """A report that reproduces but measures nothing would pass the test above.

    So the artefact is checked for the numbers it is supposed to carry: the
    200 findings read, a graded test window, and a headline over a corpus deep
    enough for one.
    """
    report = two_runs[0]

    assert report.startswith("# Replay evaluation")
    assert "Decisions replayed: 60" in report
    assert '"findings_read": 200' in report
    # 70/30 by time over 200 findings.
    assert '"test_findings": 60' in report
    assert '"train_findings": 140' in report


def test_the_headline_is_printed_rather_than_withheld(two_runs: list[str]) -> None:
    """The deeper branch of the renderer, so the comparison covers more of it.

    A withheld headline reproduces just as reliably and prints far fewer
    numbers, so a run that was accidentally thin would weaken the proof
    without failing it.
    """
    report = two_runs[0]

    assert "## Headline accuracy" in report
    assert "Withheld." not in report
    assert "answered decisions" in report


def test_only_latency_differs_between_the_two_runs(stack: dict[str, str], connector_id: str, two_runs: list[str]) -> None:
    """The exclusion is the only thing standing between the runs, and it is one line.

    Fetching both reports again *without* the exclusion and diffing them shows
    exactly which lines are not reproducible. If that set is ever larger than
    the single latency line, the claim has quietly stopped being true and this
    fails rather than the byte comparison passing on a stripped artefact that
    hid it.
    """
    runs = _api(stack, "GET", "/api/v1/evaluations/replay?limit=2")
    assert len(runs) == 2, "expected exactly the two runs this module started"

    full = []
    for run in runs:
        request = urllib.request.Request(  # noqa: S310 - fixed localhost URL
            f"{stack['api']}/api/v1/evaluations/replay/{run['id']}/export?format=markdown",
            headers={"Authorization": f"Bearer {stack['token']}"},
        )
        with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310
            full.append(response.read().decode())

    differing = [(a, b) for a, b in zip(full[0].split("\n"), full[1].split("\n"), strict=True) if a != b]
    assert len(differing) <= 1, f"more than latency differs between two runs: {differing}"
    if differing:
        assert differing[0][0].startswith("- Mean latency:")


def test_the_run_wrote_nothing_through_triage(stack: dict[str, str]) -> None:
    """Shadow mode, asserted on the live chain rather than on the runner alone.

    The method block records what production *would* have written, per sink.
    Those counters being present and non-zero is the evidence that the
    writeback branch was reached and intercepted, rather than never reached.
    """
    runs = _api(stack, "GET", "/api/v1/evaluations/replay?limit=1")
    detail = _api(stack, "GET", f"/api/v1/evaluations/replay/{runs[0]['id']}")

    attempted = detail["method"]["shadow_writes_attempted"]
    assert attempted, "no write was even attempted, so shadow mode proved nothing"
    assert set(attempted) >= {"persist_auto_triage", "write_back_disposition"}


def test_the_decisions_behind_the_report_were_stored(stack: dict[str, str]) -> None:
    """A disputed number has to be re-derivable, which needs the rows."""
    runs = _api(stack, "GET", "/api/v1/evaluations/replay?limit=1")
    decisions = _api(stack, "GET", f"/api/v1/evaluations/replay/{runs[0]['id']}/decisions")

    assert len(decisions) == 60
    assert all(d["vendor"] == "splunk" for d in decisions)
    assert {d["expected_disposition"] for d in decisions} <= {"true_positive", "false_positive", "unlabeled"}


def test_the_json_export_reproduces_too(stack: dict[str, str]) -> None:
    """The other machine-readable half of the same artefact."""
    runs = _api(stack, "GET", "/api/v1/evaluations/replay?limit=2")

    exports = []
    for run in runs:
        request = urllib.request.Request(  # noqa: S310 - fixed localhost URL
            f"{stack['api']}/api/v1/evaluations/replay/{run['id']}/export?format=json&exclude_latency=true",
            headers={"Authorization": f"Bearer {stack['token']}"},
        )
        with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310
            body = json.loads(response.read())
        # The id is the one field that legitimately differs between two runs.
        body.pop("evaluation_id")
        exports.append(json.dumps(body, sort_keys=True))

    assert exports[0] == exports[1]
