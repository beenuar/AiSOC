"""Tests for the tool-attribution gate, `scripts/check_attribution.py`.

The gate and the client-side hook (`.githooks/commit-msg`) are two
implementations of one rule, so the properties worth asserting are not just
"does it catch a bad line" but "do the two agree, in both directions".

A gate checked only against clean input cannot tell you it still works: a regex
that stops matching turns it into a no-op that reports OK forever. A gate
checked only against bad input can pass by flagging everything, which would
strip a real contributor's `Co-authored-by:` trailer — the exact credit the
project does want to keep. Both directions are asserted here, against the same
fixture corpus the CI self-test uses.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
_SCRIPT = _REPO / "scripts" / "check_attribution.py"
_FIXTURES = _REPO / "scripts" / "attribution_fixtures.json"
_HOOK = _REPO / ".githooks" / "commit-msg"


def _load_gate():
    spec = importlib.util.spec_from_file_location("check_attribution", _SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gate = _load_gate()
_CORPUS = json.loads(_FIXTURES.read_text(encoding="utf-8"))


@pytest.mark.parametrize("sample", _CORPUS["bad"])
def test_gate_detects_known_bad(sample: str) -> None:
    """Not vacuous: every known attribution form is caught."""
    assert gate.is_attribution(sample), f"gate missed attribution: {sample!r}"


@pytest.mark.parametrize("sample", _CORPUS["good"])
def test_gate_ignores_known_good(sample: str) -> None:
    """Not over-broad: human trailers and neutral prose are left alone.

    This is the half that protects contributors. `Co-authored-by: Prince Sinha`
    and `dependabot[bot]` are credit the project wants; a model name quoted in
    prose, or a lockfile "regenerated with pnpm", is description, not
    attribution.
    """
    assert not gate.is_attribution(sample), f"gate flagged legitimate text: {sample!r}"


def _hook_output(line: str) -> str:
    """Run the real hook over a message containing `line`."""
    import tempfile

    with tempfile.NamedTemporaryFile("w", suffix=".msg", delete=False, encoding="utf-8") as fh:
        fh.write(f"chore: fixture subject\n\nbody line that must survive\n\n{line}\n")
        path = Path(fh.name)
    try:
        subprocess.run(["sh", str(_HOOK), str(path)], capture_output=True, text=True, cwd=_REPO)
        return path.read_text(encoding="utf-8")
    finally:
        path.unlink(missing_ok=True)


@pytest.mark.parametrize("sample", _CORPUS["bad"])
def test_hook_strips_known_bad(sample: str) -> None:
    out = _hook_output(sample)
    assert sample not in out, f"hook did not strip: {sample!r}"
    assert "body line that must survive" in out, "hook destroyed real content"


@pytest.mark.parametrize("sample", _CORPUS["good"])
def test_hook_preserves_known_good(sample: str) -> None:
    out = _hook_output(sample)
    assert sample in out, f"hook stripped legitimate text: {sample!r}"


def test_hook_and_gate_agree() -> None:
    """The two implementations must not drift apart.

    They read the same pattern file; this asserts they also *behave* the same,
    which is the property that actually matters and the one a shared data file
    alone does not guarantee.
    """
    disagreements = []
    for sample in _CORPUS["bad"] + _CORPUS["good"]:
        flagged = gate.is_attribution(sample)
        stripped = sample not in _hook_output(sample)
        if flagged != stripped:
            disagreements.append(f"{sample!r}: gate flagged={flagged}, hook stripped={stripped}")
    assert not disagreements, "hook and gate disagree:\n  " + "\n  ".join(disagreements)


def test_patterns_file_is_not_empty() -> None:
    """A pattern file that fails to load would make the gate silently permissive."""
    assert gate.PATTERNS, "no patterns loaded — the gate would pass everything"


def test_self_test_subcommand_passes() -> None:
    """The same invocation CI runs."""
    r = subprocess.run(
        [sys.executable, str(_SCRIPT), "--self-test"],
        capture_output=True,
        text=True,
        cwd=_REPO,
    )
    assert r.returncode == 0, f"self-test failed:\n{r.stdout}\n{r.stderr}"


def test_gate_fails_on_a_bad_text_file(tmp_path: Path) -> None:
    """End-to-end through the CLI, not just the predicate: a body with a footer
    must exit non-zero. This is the path CI uses for the PR body."""
    bad = tmp_path / "body.md"
    bad.write_text(
        "Real technical content.\n\nMade with [Cursor](https://cursor.com)\n",
        encoding="utf-8",
    )
    r = subprocess.run(
        [sys.executable, str(_SCRIPT), "--text-file", str(bad)],
        capture_output=True,
        text=True,
        cwd=_REPO,
    )
    assert r.returncode == 1, f"gate passed a body with a footer:\n{r.stdout}"
    assert "Made with" in r.stdout


def test_gate_passes_a_clean_text_file(tmp_path: Path) -> None:
    clean = tmp_path / "body.md"
    clean.write_text(
        "Real technical content.\n\nCo-authored-by: Prince Sinha <p@example.com>\n",
        encoding="utf-8",
    )
    r = subprocess.run(
        [sys.executable, str(_SCRIPT), "--text-file", str(clean)],
        capture_output=True,
        text=True,
        cwd=_REPO,
    )
    assert r.returncode == 0, f"gate flagged a clean body:\n{r.stdout}"
