"""CLI surface tests for ``aisoc replay``.

Gap-closure Phase 1.4 gate.

The contract these pin:

* ``aisoc replay`` starts a run, polls it to a terminal state, and writes the
  artefact the API stored. It renders nothing of its own.
* Progress goes to stderr and the report goes to stdout, so
  ``aisoc replay ... > report.md`` produces the report and nothing else.
* A failed evaluation exits non-zero with the server's own reason. A replay
  that could not read a window has measured nothing, and saying so is the
  useful answer.
* The tenant is never a flag. It comes from the credential.
* ``--exclude-latency`` reaches the API, which is where the exclusion is
  implemented, next to the renderer that emits the line.

``httpx.MockTransport`` stands in for the API. Nothing here makes a network
call.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from click.testing import CliRunner, Result

from aisoc_cli.main import cli

EVALUATION_ID = "3f2a1b4c-5d6e-4f70-8192-a3b4c5d6e7f8"

REPORT = """# Replay evaluation

## What was graded

- Decisions replayed: 60
- Carried an analyst label: 60

## Recall on malicious

- Malicious cases in the test window: 31
- Recall: 83.9% (95% CI 71.0% to 93.5%)
"""


def _summary(status: str, **overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "id": EVALUATION_ID,
        "status": status,
        "error": None,
        "connector_id": "c0ffee00-0000-0000-0000-000000000001",
        "vendor": "splunk",
        "window_start": "2026-03-01T00:00:00+00:00",
        "window_end": "2026-06-01T00:00:00+00:00",
        "train_fraction": 0.7,
        "bootstrap_seed": 20260926,
        "bootstrap_resamples": 1000,
        "findings_read": 200,
        "findings_labelled": 188,
        "decisions_recorded": 60,
        "graded": 58,
        "malicious_support": 31,
        "headline_accuracy": 0.8448,
        "headline_withheld_reason": None,
        "malicious_recall": 0.8387,
        "created_at": "2026-06-01T09:00:00+00:00",
        "started_at": "2026-06-01T09:00:01+00:00",
        "completed_at": "2026-06-01T09:04:12+00:00",
        "is_terminal": status in {"completed", "failed"},
    }
    body.update(overrides)
    return body


class _Api:
    """A scripted API. Records every request so the contract can be asserted."""

    def __init__(
        self, *, statuses: list[str] | None = None, summary_overrides: dict[str, Any] | None = None
    ) -> None:
        self.requests: list[httpx.Request] = []
        self._statuses = list(statuses or ["completed"])
        self._overrides = summary_overrides or {}

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path
        if request.method == "POST" and path.endswith("/evaluations/replay"):
            return httpx.Response(202, json=_summary("queued"))
        if path.endswith("/export"):
            return httpx.Response(
                200, text=REPORT, headers={"content-type": "text/markdown; charset=utf-8"}
            )
        status = self._statuses.pop(0) if len(self._statuses) > 1 else self._statuses[0]
        return httpx.Response(200, json=_summary(status, **self._overrides))


def _install(
    monkeypatch: pytest.MonkeyPatch,
    handler: Any,
    *,
    patch_sleep: bool = True,
) -> None:
    """Point the CLI's httpx client at a mock transport, and stop it sleeping.

    Patched by dotted path rather than by reaching through ``cli_main`` for
    its ``httpx`` and ``time`` attributes. Same effect, and it does not assert
    that the module re-exports its own imports, which it does not.
    """
    real_client = httpx.Client
    monkeypatch.setattr(
        "aisoc_cli.main.httpx.Client",
        lambda *a, **kw: real_client(*a, **{**kw, "transport": httpx.MockTransport(handler)}),
    )
    if patch_sleep:
        monkeypatch.setattr("aisoc_cli.main.time.sleep", lambda _seconds: None)


@pytest.fixture
def runner() -> CliRunner:
    # stderr kept separate so the "report on stdout, progress on stderr"
    # property can be asserted rather than assumed.
    return CliRunner()


@pytest.fixture
def api(monkeypatch: pytest.MonkeyPatch) -> _Api:
    scripted = _Api()
    _install(monkeypatch, scripted)
    return scripted


def _invoke(runner: CliRunner, *args: str) -> Result:
    return runner.invoke(cli, ["replay", *args], catch_exceptions=False)


def test_replay_is_registered_and_discoverable(runner: CliRunner) -> None:
    result = runner.invoke(cli, ["--help"])

    assert result.exit_code == 0
    assert "replay" in result.output


def test_a_run_is_started_polled_and_its_report_written(
    runner: CliRunner, api: _Api, tmp_path: Path
) -> None:
    output = tmp_path / "report.md"

    result = _invoke(
        runner,
        "--connector-id",
        "c0ffee00-0000-0000-0000-000000000001",
        "--since",
        "2026-03-01T00:00:00Z",
        "--until",
        "2026-06-01T00:00:00Z",
        "--output",
        str(output),
    )

    assert result.exit_code == 0
    # The bytes written are the bytes the API returned. Nothing is rendered,
    # reformatted or annotated on the way through.
    assert output.read_text() == REPORT

    posted = [r for r in api.requests if r.method == "POST"]
    assert len(posted) == 1
    body = json.loads(posted[0].content)
    assert body["connector_id"] == "c0ffee00-0000-0000-0000-000000000001"
    assert body["since"] == "2026-03-01T00:00:00Z"
    assert body["until"] == "2026-06-01T00:00:00Z"


def test_an_omitted_window_is_not_filled_in_locally(
    runner: CliRunner, api: _Api, tmp_path: Path
) -> None:
    """The CLI must not put its own clock into a report the API owns.

    Sending a locally-computed "now" would make the window depend on the
    machine the CLI ran on rather than on the deployment.
    """
    _invoke(
        runner,
        "--connector-id",
        "c0ffee00-0000-0000-0000-000000000001",
        "--output",
        str(tmp_path / "r.md"),
    )

    body = json.loads([r for r in api.requests if r.method == "POST"][0].content)
    assert "since" not in body
    assert "until" not in body


def test_the_report_goes_to_stdout_and_progress_to_stderr(runner: CliRunner, api: _Api) -> None:
    """`aisoc replay ... > report.md` has to produce the report and nothing else."""
    result = _invoke(runner, "--connector-id", "c0ffee00-0000-0000-0000-000000000001")

    assert result.exit_code == 0
    assert result.stdout == REPORT
    assert "queued" in result.stderr
    assert "replay evaluation" in result.stderr


def test_exclude_latency_reaches_the_api(runner: CliRunner, api: _Api, tmp_path: Path) -> None:
    """The exclusion is implemented beside the renderer, not in the CLI."""
    _invoke(
        runner,
        "--connector-id",
        "c0ffee00-0000-0000-0000-000000000001",
        "--exclude-latency",
        "--output",
        str(tmp_path / "r.md"),
    )

    export = [r for r in api.requests if r.url.path.endswith("/export")][0]
    assert export.url.params["exclude_latency"] == "true"
    assert export.url.params["format"] == "markdown"


def test_the_seed_and_resamples_are_passed_through_when_given(
    runner: CliRunner, api: _Api, tmp_path: Path
) -> None:
    _invoke(
        runner,
        "--connector-id",
        "c0ffee00-0000-0000-0000-000000000001",
        "--seed",
        "7",
        "--resamples",
        "200",
        "--output",
        str(tmp_path / "r.md"),
    )

    body = json.loads([r for r in api.requests if r.method == "POST"][0].content)
    assert body["bootstrap_seed"] == 7
    assert body["bootstrap_resamples"] == 200


def test_a_failed_evaluation_exits_non_zero_with_the_servers_reason(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    scripted = _Api(
        statuses=["failed"],
        summary_overrides={"error": "the actions service is unreachable at http://actions:8085"},
    )
    _install(monkeypatch, scripted)

    result = runner.invoke(
        cli, ["replay", "--connector-id", "c0ffee00-0000-0000-0000-000000000001"]
    )

    assert result.exit_code != 0
    assert "unreachable" in result.stderr
    # Nothing is written when there is nothing measured.
    assert result.stdout == ""


def test_polling_continues_until_a_terminal_status(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    scripted = _Api(statuses=["queued", "running", "running", "completed"])
    _install(monkeypatch, scripted)

    result = runner.invoke(
        cli, ["replay", "--connector-id", "c0ffee00-0000-0000-0000-000000000001"]
    )

    assert result.exit_code == 0
    polls = [
        r for r in scripted.requests if r.method == "GET" and not r.url.path.endswith("/export")
    ]
    assert len(polls) == 4


def test_no_wait_prints_the_id_and_stops(runner: CliRunner, api: _Api) -> None:
    result = _invoke(runner, "--connector-id", "c0ffee00-0000-0000-0000-000000000001", "--no-wait")

    assert result.exit_code == 0
    assert EVALUATION_ID in result.stderr
    assert not [r for r in api.requests if r.url.path.endswith("/export")]


def test_collect_fetches_an_existing_run_without_starting_one(runner: CliRunner, api: _Api) -> None:
    result = _invoke(runner, "--collect", EVALUATION_ID)

    assert result.exit_code == 0
    assert not [r for r in api.requests if r.method == "POST"]
    assert result.stdout == REPORT


def test_neither_connector_nor_collect_is_refused_with_both_options(runner: CliRunner) -> None:
    result = runner.invoke(cli, ["replay"])

    assert result.exit_code != 0
    assert "--connector-id" in result.stderr
    assert "--collect" in result.stderr


def test_there_is_no_tenant_flag(runner: CliRunner) -> None:
    """A tenant flag would be a value the operator chose that nothing checked."""
    result = runner.invoke(cli, ["replay", "--help"])

    assert result.exit_code == 0
    assert "--tenant" not in result.output
    # Click re-wraps help text, so the sentence is matched with whitespace
    # collapsed rather than against whatever the terminal width produced.
    collapsed = " ".join(result.output.split())
    assert "There is no tenant flag" in collapsed


def test_pdf_to_stdout_is_refused_rather_than_written_as_mojibake(
    runner: CliRunner, api: _Api
) -> None:
    result = runner.invoke(cli, ["replay", "--collect", EVALUATION_ID, "--format", "pdf"])

    assert result.exit_code != 0
    assert "--output" in result.stderr


def test_an_unreachable_api_says_so_and_names_the_url(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    _install(monkeypatch, refuse, patch_sleep=False)

    result = runner.invoke(
        cli,
        [
            "replay",
            "--connector-id",
            "c0ffee00-0000-0000-0000-000000000001",
            "--api-url",
            "http://127.0.0.1:8000",
        ],
    )

    assert result.exit_code != 0
    assert "http://127.0.0.1:8000" in result.stderr
