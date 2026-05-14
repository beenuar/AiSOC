"""CLI surface tests for ``scripts/run_evals.py``.

These tests pin down the contract the AiSOC quickstart video relies on:

* ``--suite all`` runs every registered suite.
* ``--suite <name>`` runs only the requested suite.
* ``--suite bogus`` is rejected by argparse with a non-zero exit code.
* The human-readable banner emits ``PASS`` / ``FAIL`` for the demo.
* When the eval substrate cannot be imported, exit code 3 is used and a
  friendly ``pip install -e services/agents`` hint is printed to stderr.

The third case is exercised by running the script in a subprocess with a
``PYTHONPATH`` that hides ``services/agents``.
"""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SCRIPT = _REPO_ROOT / "scripts" / "run_evals.py"


def _run(*args: str, env: dict | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(_SCRIPT), *args],
        capture_output=True,
        text=True,
        cwd=_REPO_ROOT,
        env=env,
        check=False,
    )


@pytest.mark.timeout(120)
def test_suite_all_runs_every_suite(tmp_path: Path) -> None:
    out = tmp_path / "report.json"
    result = _run("--suite", "all", "--json", "--out", str(out))
    assert result.returncode in (0, 1), result.stderr
    payload = json.loads(out.read_text())
    assert payload["suite_filter"] == "all"
    # Every registered suite should appear in the report.
    expected = {
        "mitre_accuracy",
        "alert_reduction",
        "investigation_completeness",
        "response_quality",
        "hunt_corpus",
        "adversary_eval",
        "confidence_calibration",
        "memory_recall",
        "override_accuracy",
        "playbook_completion_rate",
        "detection_fp_rate",
    }
    assert expected.issubset(payload["suites"].keys())


@pytest.mark.timeout(60)
def test_suite_single_runs_only_that_suite(tmp_path: Path) -> None:
    out = tmp_path / "report.json"
    result = _run("--suite", "mitre_accuracy", "--out", str(out))
    assert result.returncode in (0, 1), result.stderr
    payload = json.loads(out.read_text())
    assert payload["suite_filter"] == "mitre_accuracy"
    assert list(payload["suites"].keys()) == ["mitre_accuracy"]
    # Banner should call out PASS or FAIL for the demo recording.
    assert ("PASS" in result.stdout) or ("FAIL" in result.stdout)


def test_unknown_suite_is_rejected() -> None:
    result = _run("--suite", "definitely-not-a-suite")
    assert result.returncode != 0
    # argparse writes the "invalid choice" message to stderr.
    assert "invalid choice" in result.stderr.lower()


def test_import_error_emits_install_hint(tmp_path: Path) -> None:
    """Simulate a fresh clone where ``services/agents`` deps are missing.

    We invoke the script with a sitecustomize that aborts imports of any
    ``tests.*`` module before the eval substrate gets a chance to load.
    """
    sitecustomize = tmp_path / "sitecustomize.py"
    sitecustomize.write_text(
        textwrap.dedent(
            """
            import sys
            class _BlockTestsImporter:
                def find_spec(self, fullname, path, target=None):
                    if fullname == "tests" or fullname.startswith("tests."):
                        raise ImportError(
                            "simulated missing services/agents dependency: "
                            + fullname
                        )
                    return None
            sys.meta_path.insert(0, _BlockTestsImporter())
            """
        )
    )
    env = {
        "PATH": "/usr/bin:/bin",
        "PYTHONPATH": str(tmp_path),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    result = _run("--suite", "mitre_accuracy", env=env)
    assert result.returncode == 3, (result.stdout, result.stderr)
    assert "pip install -e services/agents" in result.stderr
    assert "ERROR" in result.stderr
