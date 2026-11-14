"""The merge-marker gate detects what it claims, and only that.

Proven against the shape that reached `main`, and against the two near
misses that would make the gate a nuisance if it fired on them: a setext
heading underline and a deeply nested blockquote.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
GATE = REPO_ROOT / "scripts" / "check_merge_markers.py"

START = "<" * 7
MIDDLE = "=" * 7
END = ">" * 7


def _load():
    spec = importlib.util.spec_from_file_location("check_merge_markers", GATE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _tree(tmp_path: Path, files: dict[str, str]) -> Path:
    root = tmp_path / "tree"
    root.mkdir()
    subprocess.run(["git", "-C", str(root), "init", "-q"], check=True)
    for rel, body in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
    return root


def test_the_shape_that_reached_main_is_detected(tmp_path) -> None:
    module = _load()
    body = (
        f"Prose.\n\n{START} HEAD\nthe honest index: 180 rows\n{MIDDLE}\nthe honest index: 180 rows\n{END} 54de0d37 (a commit)\n`GATED`.\n"
    )
    findings, read, _subject = module.scan(_tree(tmp_path, {"docs/page.md": body}))
    assert read == 1
    assert len(findings) == 3
    assert "conflict start marker" in findings[0]
    assert "conflict separator" in findings[1]
    assert "conflict end marker" in findings[2]


def test_a_setext_heading_underline_is_not_a_finding(tmp_path) -> None:
    """A bare seven-equals line is legal Markdown, and common."""
    module = _load()
    findings, read, _subject = module.scan(_tree(tmp_path, {"docs/page.md": f"A heading\n{MIDDLE}\n\nProse.\n"}))
    assert read == 1
    assert findings == []


def test_a_deeply_nested_blockquote_is_not_a_finding(tmp_path) -> None:
    module = _load()
    findings, read, _subject = module.scan(_tree(tmp_path, {"docs/page.md": f"{END}quoted seven deep\n"}))
    assert read == 1
    assert findings == []


def test_a_clean_tree_passes(tmp_path) -> None:
    module = _load()
    findings, read, _subject = module.scan(_tree(tmp_path, {"a.md": "Prose.\n", "b.py": "VALUE = 1\n"}))
    assert read == 2
    assert findings == []


def test_an_empty_tree_reads_nothing(tmp_path) -> None:
    """A gate that reads nothing finds nothing, so `main()` has to refuse it."""
    root = tmp_path / "empty"
    root.mkdir()
    subprocess.run(["git", "-C", str(root), "init", "-q"], check=True)
    module = _load()
    findings, read, _subject = module.scan(root)
    assert read == 0
    assert findings == []


def test_a_tree_of_only_scripts_is_refused_rather_than_called_clean(tmp_path) -> None:
    """The shape `gate_toolkit`'s scratch tree produces.

    The scratch tree copies `scripts/` in so the gate is runnable, which
    means the gate *does* read real files there. Reporting them clean would
    be a verdict about this gate's own toolkit under the whole repository's
    name, so a tracked set holding nothing outside `scripts/` is refused.
    """
    module = _load()
    # The shape `gate_toolkit`'s SKELETON scratch tree produces: the gate's
    # own toolkit, plus one empty placeholder per content directory.
    root = _tree(tmp_path, {"scripts/gate.py": "VALUE = 1\n", "apps/.gitkeep": "", "docs/.gitkeep": ""})
    # `repo_root()` resolves through git from this file's own location, so a
    # subprocess started elsewhere still lands in the real checkout. The root
    # is rebound instead, which is what `gate_toolkit`'s own self-test does.
    module.REPO_ROOT = root
    assert module.main([]) != 0


def test_the_gate_answers_the_self_test_flag() -> None:
    result = subprocess.run([sys.executable, str(GATE), "--self-test"], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr


def test_the_live_repository_is_clean() -> None:
    """The regression this gate exists for, asserted against the real tree."""
    result = subprocess.run([sys.executable, str(GATE)], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
