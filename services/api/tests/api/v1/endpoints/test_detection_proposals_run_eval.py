"""Unit tests for the WS-B4 run-eval bridge.

The `POST /detection-proposals/run-eval` endpoint is mostly orchestration:
it spawns ``scripts/run_evals.py`` via ``run_in_executor`` and surfaces the
JSON report back to the rule editor. The interesting logic is the helper
``_run_eval_subprocess`` — it owns the subprocess argv, working directory,
and ``PYTHONPATH`` env wiring. Getting that wrong silently breaks the
"eval-harness regression on save" gate, so we pin the contract here.

These tests stub ``subprocess.run`` so they remain millisecond-fast and CI-safe
(the real harness takes 5–15s).
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from app.api.v1.endpoints import detection_proposals as dp_endpoint


class _FakeCompleted:
    """Minimal stand-in for ``subprocess.CompletedProcess``."""

    def __init__(self, returncode: int = 0, stdout: str = "{}", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_eval_script_path_resolves_to_real_file():
    """Sanity check: the path math finds the real run_evals.py."""
    assert dp_endpoint._EVAL_SCRIPT.exists(), (
        f"Eval runner not found at {dp_endpoint._EVAL_SCRIPT}; the path math in "
        "detection_proposals.py is wrong or the deployment is missing scripts/."
    )
    assert dp_endpoint._EVAL_SCRIPT.name == "run_evals.py"


def test_run_eval_subprocess_builds_correct_argv(tmp_path: Path):
    """The subprocess argv must include --json, --out, and --max-regression-pp.

    Without --json the runner emits a banner instead of pure JSON, and without
    --max-regression-pp the gate gets the wrong baseline tolerance.
    """
    out_path = tmp_path / "eval_report.json"
    captured: dict[str, list[str]] = {}

    def fake_run(cmd: list[str], **kwargs):  # noqa: ANN001
        captured["cmd"] = cmd
        captured["cwd"] = kwargs.get("cwd")
        captured["env"] = kwargs.get("env", {})
        return _FakeCompleted(returncode=0, stdout="{}")

    with patch.object(subprocess, "run", side_effect=fake_run):
        rc, stdout, stderr = dp_endpoint._run_eval_subprocess(
            baseline_path=None,
            out_path=out_path,
            max_regression_pp=1.5,
            timeout_seconds=60,
        )

    assert rc == 0
    cmd = captured["cmd"]
    assert cmd[0] == sys.executable
    assert cmd[1].endswith("run_evals.py")
    assert "--json" in cmd
    assert "--out" in cmd and str(out_path) in cmd
    assert "--max-regression-pp" in cmd and "1.5" in cmd
    # cwd is the repo root so relative imports inside the runner work.
    assert captured["cwd"] == str(dp_endpoint._REPO_ROOT)
    # PYTHONPATH points at services/agents so the runner can import the eval modules.
    assert "services/agents" in captured["env"].get("PYTHONPATH", "")


def test_run_eval_subprocess_includes_baseline_when_provided(tmp_path: Path):
    """If a baseline path is supplied, the runner must receive --baseline."""
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(json.dumps({"score": 0.91}))
    out_path = tmp_path / "eval_report.json"
    captured: dict[str, list[str]] = {}

    def fake_run(cmd: list[str], **kwargs):  # noqa: ANN001
        captured["cmd"] = cmd
        return _FakeCompleted(returncode=0, stdout="{}")

    with patch.object(subprocess, "run", side_effect=fake_run):
        dp_endpoint._run_eval_subprocess(
            baseline_path=baseline_path,
            out_path=out_path,
            max_regression_pp=1.0,
            timeout_seconds=60,
        )

    cmd = captured["cmd"]
    assert "--baseline" in cmd
    baseline_idx = cmd.index("--baseline")
    assert cmd[baseline_idx + 1] == str(baseline_path)


def test_run_eval_subprocess_omits_baseline_when_none(tmp_path: Path):
    """Without a baseline, --baseline must NOT appear (runner skips compare)."""
    out_path = tmp_path / "eval_report.json"
    captured: dict[str, list[str]] = {}

    def fake_run(cmd: list[str], **kwargs):  # noqa: ANN001
        captured["cmd"] = cmd
        return _FakeCompleted(returncode=0, stdout="{}")

    with patch.object(subprocess, "run", side_effect=fake_run):
        dp_endpoint._run_eval_subprocess(
            baseline_path=None,
            out_path=out_path,
            max_regression_pp=1.0,
            timeout_seconds=60,
        )

    assert "--baseline" not in captured["cmd"]


def test_run_eval_subprocess_propagates_timeout(tmp_path: Path):
    """Timeout from the runner bubbles up so the API can return 504."""
    out_path = tmp_path / "eval_report.json"

    def fake_run(cmd: list[str], **kwargs):  # noqa: ANN001
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=kwargs.get("timeout", 0))

    with patch.object(subprocess, "run", side_effect=fake_run):
        with pytest.raises(subprocess.TimeoutExpired):
            dp_endpoint._run_eval_subprocess(
                baseline_path=None,
                out_path=out_path,
                max_regression_pp=1.0,
                timeout_seconds=5,
            )


def test_run_eval_subprocess_passes_through_nonzero_exit(tmp_path: Path):
    """Exit codes 1 and 2 are valid runner outcomes (suite below floor / regressed),
    so the helper must NOT call check=True. They are pass-through to the caller."""
    out_path = tmp_path / "eval_report.json"
    captured: dict[str, object] = {}

    def fake_run(cmd: list[str], **kwargs):  # noqa: ANN001
        captured["check"] = kwargs.get("check")
        return _FakeCompleted(returncode=2, stdout='{"all_passed": true}', stderr="")

    with patch.object(subprocess, "run", side_effect=fake_run):
        rc, stdout, stderr = dp_endpoint._run_eval_subprocess(
            baseline_path=None,
            out_path=out_path,
            max_regression_pp=1.0,
            timeout_seconds=60,
        )

    assert rc == 2
    assert captured["check"] is False
