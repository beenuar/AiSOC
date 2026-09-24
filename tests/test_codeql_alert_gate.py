"""Tests for the CodeQL zero-alert gate.

`apps/docs/docs/operations/security.md` has claimed since v8.0 wave-1 that the
CodeQL alert count on `main` is zero and that this is enforced as a CI gate.
There was no such gate. `codeql.yml` uploads SARIF and
`github/codeql-action/analyze` does not fail a build on findings; `main` has no
branch protection, so "Code scanning results" was not a required check either;
and `security.yml`'s only hard job was the claim-to-gate matrix. Alerts #893
and #896 sat open on `main` for hours under a documented invariant of zero, and
nothing anywhere could have noticed.

So these tests assert two different things, and the second matters as much as
the first:

1. The gate catches every shape of failure it claims to catch — in particular a
   `note`-severity alert, because both alerts that motivated it were `note` and
   a severity filter would have reproduced the original silence exactly.
2. The gate is *reachable*. A gate wired into no workflow, or wired only into
   `pull_request`, is the defect this repository keeps rediscovering: it
   inspects what contributors propose and never what actually lands. The last
   two tests read the workflow file and fail if that wiring disappears.
"""

from __future__ import annotations

import ast
import importlib.util
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
_SCRIPT = _REPO / "scripts" / "check_codeql_alerts.py"
_GATE_WORKFLOW = _REPO / ".github" / "workflows" / "codeql-alert-gate.yml"
_VALIDATE_PLAYBOOKS = _REPO / "scripts" / "validate_playbooks.py"


def _load_gate():
    spec = importlib.util.spec_from_file_location("check_codeql_alerts", _SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gate = _load_gate()


def _clean(now: datetime) -> dict:
    return gate._clean_fixture(_REPO, now)


def _run(data: dict, now: datetime, *, alerts_checked: bool = True) -> set[str]:
    return {
        code
        for code, _ in gate.evaluate(
            open_alerts=data["open_alerts"],
            analyses=data["analyses"],
            workflow=data["workflow"],
            now=now,
            max_age_days=gate.DEFAULT_MAX_ANALYSIS_AGE_DAYS,
            alerts_checked=alerts_checked,
        )
    }


# --------------------------------------------------------------------------
# The gate bites
# --------------------------------------------------------------------------
def test_clean_ref_passes() -> None:
    now = datetime.now(timezone.utc)
    assert _run(_clean(now), now) == set()


def test_note_severity_alert_is_caught() -> None:
    """The headline case: #893 and #896 were both `note`.

    A gate that counted only `error`/`warning`, or only alerts carrying a
    `security_severity_level` (both of these were `None`), would have printed
    OK for the entire window in which the invariant was false.
    """
    now = datetime.now(timezone.utc)
    data = _clean(now)
    data["open_alerts"] = [gate._alert(896, "py/print-during-import", "note", "scripts/validate_playbooks.py")]
    assert "open-alert" in _run(data, now)


@pytest.mark.parametrize("severity", ["note", "warning", "error"])
def test_every_severity_is_gated(severity: str) -> None:
    now = datetime.now(timezone.utc)
    data = _clean(now)
    data["open_alerts"] = [gate._alert(1, "py/some-rule", severity, "scripts/x.py")]
    assert "open-alert" in _run(data, now)


def test_unanalyzed_ref_is_not_a_clean_ref() -> None:
    """Zero alerts because nothing ran is the vacuous pass, not a pass."""
    now = datetime.now(timezone.utc)
    data = _clean(now)
    data["analyses"] = []
    assert "no-analysis" in _run(data, now)


def test_stale_analysis_is_caught() -> None:
    """`main` can be stale-green: a frozen scan leaves a frozen alert list."""
    now = datetime.now(timezone.utc)
    data = _clean(now)
    for analysis in data["analyses"]:
        analysis["created_at"] = (now - timedelta(days=gate.DEFAULT_MAX_ANALYSIS_AGE_DAYS + 1)).isoformat().replace("+00:00", "Z")
    assert "stale-analysis" in _run(data, now)


def test_language_dropped_from_analysis_is_caught() -> None:
    now = datetime.now(timezone.utc)
    data = _clean(now)
    data["analyses"] = data["analyses"][:-1]
    assert "language-not-analyzed" in _run(data, now)


def test_mixed_codeql_action_pins_are_caught() -> None:
    """CodeQL refuses to run when init/autobuild/analyze disagree.

    Dependabot splitting those three across separate PRs produces exactly this
    state, and it removes the analysis rather than the findings.
    """
    now = datetime.now(timezone.utc)
    data = _clean(now)
    data["workflow"] = dict(data["workflow"])
    data["workflow"]["action_versions"] = dict(data["workflow"]["action_versions"])
    data["workflow"]["action_versions"]["analyze"] = "v3.28.0"
    assert "action-version-mismatch" in _run(data, now)


def test_pr_only_scan_is_caught() -> None:
    now = datetime.now(timezone.utc)
    data = _clean(now)
    data["workflow"] = dict(data["workflow"])
    data["workflow"]["push_branches"] = []
    assert "no-push-to-main-trigger" in _run(data, now)


def test_offline_mode_claims_no_alert_verdict() -> None:
    """`--offline` must abstain, not quietly report a clean alert count."""
    now = datetime.now(timezone.utc)
    data = _clean(now)
    data["open_alerts"] = [gate._alert(1, "py/some-rule", "error", "scripts/x.py")]
    assert "open-alert" not in _run(data, now, alerts_checked=False)


def test_analysis_of_a_different_commit_is_not_this_commit() -> None:
    """The push-race: the gate and the scan are triggered by the same push.

    Unpinned, the gate reads the alert list left by the *previous* commit and
    calls the incoming one clean before anything has looked at it.
    """
    now = datetime.now(timezone.utc)
    data = _clean(now)
    for analysis in data["analyses"]:
        analysis["commit_sha"] = "a" * 40
    codes = {
        code
        for code, _ in gate.evaluate(
            open_alerts=[],
            analyses=data["analyses"],
            workflow=data["workflow"],
            now=now,
            max_age_days=gate.DEFAULT_MAX_ANALYSIS_AGE_DAYS,
            alerts_checked=True,
            commit="b" * 40,
        )
    }
    assert "no-analysis" in codes


def test_wait_times_out_into_a_failure_not_a_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    """A bounded wait that gives up must hand back an unanalyzed verdict."""
    now = datetime.now(timezone.utc)
    languages = _clean(now)["workflow"]["languages"]
    monkeypatch.setattr(
        gate,
        "fetch",
        lambda repo, ref: {"open_alerts": [], "dismissed_alerts": [], "analyses": []},
    )
    slept: list[float] = []
    data = gate.fetch_when_analyzed(
        "example/repo",
        "refs/heads/main",
        commit="c" * 40,
        languages=languages,
        wait_seconds=2,
        poll_seconds=1,
        sleep=slept.append,
    )
    assert data["analyses"] == []
    assert slept, "the gate returned without ever waiting"


def test_bundled_self_test_passes() -> None:
    """The same proof CI runs, run here too."""
    assert gate.self_test(_REPO) == 0


# --------------------------------------------------------------------------
# The gate fails closed
# --------------------------------------------------------------------------
def test_missing_workflow_raises_rather_than_passing() -> None:
    with pytest.raises(gate.GateError):
        gate.parse_workflow(_REPO / ".github" / "workflows" / "does-not-exist.yml")


def test_unreadable_inputs_exit_two_not_zero(tmp_path: Path) -> None:
    """Exit 2 is "could not read", and must never be confused with "clean"."""
    result = subprocess.run(
        [sys.executable, str(_SCRIPT), "--repo-root", str(tmp_path), "--offline"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2, result.stdout + result.stderr


def test_missing_token_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)
    with pytest.raises(gate.GateError):
        gate.fetch("beenuar/AiSOC", "refs/heads/main")


def test_gate_refuses_non_github_urls() -> None:
    with pytest.raises(gate.GateError):
        gate._get("https://example.invalid/alerts", "token")


# --------------------------------------------------------------------------
# The gate is reachable
# --------------------------------------------------------------------------
def test_gate_is_wired_into_a_workflow() -> None:
    """A gate no workflow invokes proves nothing, however good its self-test."""
    text = _GATE_WORKFLOW.read_text(encoding="utf-8")
    assert "scripts/check_codeql_alerts.py" in text
    assert "--self-test" in text, "the self-test must run in CI, not only locally"
    assert "tests/test_codeql_alert_gate.py" in text


def test_gate_runs_on_push_to_main_not_only_on_pull_requests() -> None:
    """A PR-only gate inspects what is proposed and never what landed."""
    text = _GATE_WORKFLOW.read_text(encoding="utf-8")
    on_block = gate._block(text, "on:")
    assert on_block is not None
    push_block = gate._block(on_block, "push:")
    assert push_block is not None and "main" in push_block
    assert gate._block(on_block, "pull_request:") is not None


def test_gate_pins_the_pushed_commit_rather_than_the_ref() -> None:
    """Otherwise the push run reads the analysis of the commit before it."""
    text = _GATE_WORKFLOW.read_text(encoding="utf-8")
    assert "--commit" in text and "--wait-seconds" in text


def test_codeql_workflow_pins_one_action_version() -> None:
    """CodeQL refuses to run when init/autobuild/analyze disagree.

    Asserted against the real workflow, not a fixture: a dependabot bump that
    lands for one of the three steps would otherwise silently remove the
    analysis this gate depends on.
    """
    workflow = gate.parse_workflow(_REPO / ".github" / "workflows" / "codeql.yml")
    pins = set(workflow["action_versions"].values())
    assert len(pins) == 1, f"mixed codeql-action pins: {workflow['action_versions']}"


# --------------------------------------------------------------------------
# The alert this wave fixed stays fixed
# --------------------------------------------------------------------------
def test_importing_validate_playbooks_is_silent_and_does_not_exit() -> None:
    """Regression for alert #896 (`py/print-during-import`).

    The module printed to stderr and called `sys.exit(2)` while being
    imported. Beyond the CodeQL note that is a live defect:
    `scripts/check_playbook_schema_parity.py` imports this module to read
    SUPPORTED_TRIGGERS, and `SystemExit` derives from `BaseException`, so its
    `except Exception` could not catch it.
    """
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; sys.path.insert(0, 'scripts'); import validate_playbooks; " "print(sorted(validate_playbooks.SUPPORTED_TRIGGERS))",
        ],
        cwd=_REPO,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    assert result.stdout.strip() == "['alert', 'case', 'manual', 'schedule']"


def test_broken_model_import_is_catchable_by_the_parity_gate() -> None:
    """It must raise ImportError, which `except Exception` catches."""
    program = (
        "import sys\n"
        "class Blocker:\n"
        "    def find_module(self, name, path=None):\n"
        "        return None\n"
        "    def find_spec(self, name, path=None, target=None):\n"
        "        if name.startswith('app.playbook'):\n"
        "            raise ImportError('blocked for the test')\n"
        "        return None\n"
        "sys.meta_path.insert(0, Blocker())\n"
        "sys.path.insert(0, 'scripts')\n"
        "try:\n"
        "    import validate_playbooks\n"
        "except Exception as exc:\n"
        "    print('CAUGHT', type(exc).__name__)\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", program],
        cwd=_REPO,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "CAUGHT ImportError" in result.stdout, result.stdout + result.stderr


def test_validate_playbooks_has_no_module_scope_print() -> None:
    """The property CodeQL's `py/print-during-import` checks, asserted locally."""
    tree = ast.parse(_VALIDATE_PLAYBOOKS.read_text(encoding="utf-8"))
    offenders: list[int] = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(node, ast.If) and ast.unparse(node.test) == "__name__ == '__main__'":
            continue  # the entrypoint guard does not run on import
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call) and getattr(sub.func, "id", None) == "print":
                offenders.append(sub.lineno)
    assert offenders == [], f"print() at module scope on line(s) {offenders}"
