"""Tests for the two grading-integrity gates.

`scripts/check_workflow_concurrency.py` (prevention, reads the workflow files)
and `scripts/check_main_run_cancellations.py` (detection, reads the Actions
API).

The property worth asserting is not "is the tree clean today" but "would the
gate still notice if it stopped being clean". A check that only ever sees good
input cannot tell a working detector from a dead one, and prints OK either way
— the dominant failure shape in this repository.

So the pre-fix shape is reconstructed on disk rather than described. Every
violation these gates were written against was removed by the same change that
added them, so a test that only ran against the live tree would be asserting
that zero equals zero. `test_pre_fix_shape_is_rejected` writes the exact block
`ci.yml` carried before the fix into a copy of the real workflow directory and
requires a non-zero exit.

`test_non_cancelling_shared_group_is_still_rejected` is the one that matters
most, because it encodes the thing that was got wrong once already:
`cancel-in-progress: false` is not a fix. GitHub cancels a run that is still
*pending* in a busy group when a newer one queues, so a non-cancelling shared
group still loses every intermediate run of a burst.
"""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
_CONCURRENCY = _REPO / "scripts" / "check_workflow_concurrency.py"
_CANCELLATIONS = _REPO / "scripts" / "check_main_run_cancellations.py"

# The block ci.yml carried on origin/main at 82f962c4, before the fix.
_PRE_FIX_BLOCK = """concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true
"""


def _load(path: Path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


conc = _load(_CONCURRENCY)
cancels = _load(_CANCELLATIONS)


def _run(script: Path, *args: str, cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(script), *args],
        capture_output=True,
        text=True,
        cwd=str(cwd or _REPO),
        check=False,
    )


def _tree_with_workflows(tmp_path: Path) -> Path:
    """A git repository holding a copy of the real workflow directory."""
    root = tmp_path / "tree"
    (root / ".github").mkdir(parents=True)
    shutil.copytree(_REPO / ".github/workflows", root / ".github/workflows")
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    return root


# ── prevention: the static shape gate ────────────────────────────────────────


def test_self_test_passes():
    result = _run(_CONCURRENCY, "--self-test")
    assert result.returncode == 0, result.stdout + result.stderr


def test_live_tree_is_clean():
    result = _run(_CONCURRENCY)
    assert result.returncode == 0, result.stdout + result.stderr


def test_pre_fix_shape_is_rejected(tmp_path: Path):
    """The exact block ci.yml carried before the fix must fail the gate."""
    root = _tree_with_workflows(tmp_path)
    ci = root / ".github/workflows/ci.yml"
    text = ci.read_text(encoding="utf-8")
    start = text.index("concurrency:")
    end = text.index("\njobs:", start)
    ci.write_text(text[:start] + _PRE_FIX_BLOCK + text[end + 1 :], encoding="utf-8")

    result = _run(_CONCURRENCY, "--repo-root", str(root))
    assert result.returncode == 1, result.stdout + result.stderr
    assert "ci.yml" in result.stdout
    assert "cancel-in-progress" in result.stdout


def test_non_cancelling_shared_group_is_still_rejected():
    """`cancel-in-progress: false` alone does not save a pending run."""
    doc = {
        "on": {"push": {"branches": ["main"]}},
        "concurrency": {"group": "x-${{ github.ref }}", "cancel-in-progress": False},
    }
    reasons = conc.diagnose(doc)
    assert reasons, "a shared group was accepted merely because it does not cancel in progress"
    assert any("shared across commits" in r for r in reasons)


def test_canonical_form_is_accepted():
    doc = {
        "on": {"push": {"branches": ["main"]}, "pull_request": {"branches": ["main"]}},
        "concurrency": {
            "group": "x-${{ github.event_name }}-${{ github.event.pull_request.number || github.sha }}",
            "cancel-in-progress": "${{ github.event_name == 'pull_request' }}",
        },
    }
    assert conc.diagnose(doc) == []


def test_tag_only_push_is_not_a_branch_trigger():
    """Every tag is its own ref, so those runs never contend."""
    doc = {
        "on": {"push": {"tags": ["cli-v*"]}},
        "concurrency": {"group": "x-${{ github.ref }}", "cancel-in-progress": True},
    }
    assert conc.diagnose(doc) == []


def test_unreadable_cancel_expression_fails_closed():
    doc = {
        "on": {"push": {"branches": ["main"]}},
        "concurrency": {
            "group": "x-${{ github.sha }}",
            "cancel-in-progress": "${{ vars.SOMETHING }}",
        },
    }
    assert conc.diagnose(doc), "an expression the gate cannot evaluate was assumed safe"


def test_exceptions_are_bidirectional():
    assert conc.compare({"new.yml": ["x"]}, {}), "an unexcused workflow passed"
    assert conc.compare({}, {"gone.yml": "stale"}), "a stale exception passed"
    assert conc.compare({"a.yml": ["x"]}, {"a.yml": "documented"}) == []


def test_every_recorded_exception_still_has_the_shape():
    """A reason that has outlived its workflow is an exemption waiting to launder."""
    findings, _total, _with_group = conc.scan(_REPO)
    for name in conc.EXCEPTIONS:
        assert name in findings, f"{name} is excepted but no longer drops a push run"


def test_empty_tree_is_not_a_pass(tmp_path: Path):
    root = tmp_path / "empty"
    (root / "scripts").mkdir(parents=True)
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    result = _run(_CONCURRENCY, "--repo-root", str(root))
    assert result.returncode != 0, result.stdout


def test_too_few_workflows_is_not_a_pass(tmp_path: Path):
    """A broken glob and a clean tree must not print the same word."""
    root = tmp_path / "thin"
    wf = root / ".github/workflows"
    wf.mkdir(parents=True)
    (wf / "only.yml").write_text("on: {push: {branches: [main]}}\njobs: {}\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    result = _run(_CONCURRENCY, "--repo-root", str(root))
    assert result.returncode == 2, result.stdout


# ── detection: the cancelled-run gate ────────────────────────────────────────


def _run_record(path: str, conclusion: str, created: str) -> dict:
    return {
        "path": f".github/workflows/{path}",
        "conclusion": conclusion,
        "created_at": created,
        "head_sha": "0123456789ab",
        "html_url": "https://example.invalid/run",
    }


def test_cancellation_self_test_passes():
    result = _run(_CANCELLATIONS, "--self-test")
    assert result.returncode == 0, result.stdout + result.stderr


def test_cancelled_run_is_reported():
    since = datetime(2026, 1, 1, tzinfo=UTC)
    unexcused, _excused, in_window = cancels.classify(
        [
            _run_record("ci.yml", "success", "2026-01-02T00:00:00Z"),
            _run_record("ci.yml", "cancelled", "2026-01-02T01:00:00Z"),
        ],
        since,
        {},
    )
    assert len(unexcused) == 1
    assert in_window == 2


def test_runs_before_the_window_are_history_not_findings():
    since = datetime(2026, 1, 1, tzinfo=UTC)
    unexcused, _excused, in_window = cancels.classify([_run_record("ci.yml", "cancelled", "2025-12-31T23:59:00Z")], since, {})
    assert unexcused == []
    assert in_window == 0


def test_recorded_exception_is_counted_not_failed():
    since = datetime(2026, 1, 1, tzinfo=UTC)
    name = next(iter(conc.EXCEPTIONS))
    unexcused, excused, _ = cancels.classify([_run_record(name, "cancelled", "2026-01-02T00:00:00Z")], since, conc.EXCEPTIONS)
    assert unexcused == []
    assert excused == {name: 1}


def test_empty_fetch_is_not_a_pass():
    assert cancels.verdict_for(fetched=0, in_window=0, unexcused=[], excused={}) != 0


def test_young_window_is_not_a_failure():
    assert cancels.verdict_for(fetched=200, in_window=0, unexcused=[], excused={}) == 0


def test_missing_token_refuses_rather_than_skips(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("GH_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    assert cancels.main([]) == 2


def test_empty_tree_refuses_even_with_a_token_and_an_ambient_repository(tmp_path: Path):
    """The verdict is about a repository, so the tree has to prove it is that one.

    The first draft read `GITHUB_REPOSITORY` and would happily have reported
    this repository's run history from a directory holding nothing — which the
    gate-contract probe caught.
    """
    root = tmp_path / "empty"
    (root / "scripts").mkdir(parents=True)
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    with pytest.raises(cancels.GateError):
        cancels.resolve_repository(root)


def test_a_real_checkout_resolves_to_this_repository():
    """The paired direction: refusing everything would satisfy the test above."""
    assert cancels.resolve_repository(_REPO).lower().endswith("/aisoc")


def test_the_two_gates_share_one_exception_list():
    """Two lists drift the first time either learns something the other has not."""
    assert cancels.EXCEPTIONS is conc.EXCEPTIONS
