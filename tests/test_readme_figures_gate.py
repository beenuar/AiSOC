"""The README figures gate must actually catch drift.

The README quoted 947 executable detection rules while the generated truth
table said 833, and 62 GATED claims while the matrix held 72. Both survived
review because nothing compared the front page to the artifact it was
summarising. These tests pin that comparison down: a gate that only ever
passes is indistinguishable from no gate.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
GATES = REPO_ROOT / "scripts" / "readme_gates.py"


def _load_gates(tmp_root: Path):
    """Import readme_gates.py with REPO_ROOT pointed at a scratch tree."""
    spec = importlib.util.spec_from_file_location("_readme_gates_under_test", GATES)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    module.REPO_ROOT = tmp_root
    module.README = tmp_root / "README.md"
    module.TRUTH_TABLE = tmp_root / "docs" / "detections" / "truth-table.md"
    module.CLAIM_MATRIX = tmp_root / "docs" / "audit" / "CLAIM_TO_GATE_MATRIX.md"
    return module


TRUTH_TABLE = """# truth table

| metric | count |
|--------|------:|
| rules on disk (total) | 6991 |
| **executable (loaded by the engine)** | **833** |
"""

MATRIX = """# matrix

| claim | source | gate | status | gap |
|---|---|---|---|---|
| one | README | ci.yml | GATED | - |
| two | README | ci.yml | GATED | - |
| three | README | ci.yml | PARTIAL | worker |
"""


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    (tmp_path / "docs" / "detections").mkdir(parents=True)
    (tmp_path / "docs" / "audit").mkdir(parents=True)
    (tmp_path / "docs" / "detections" / "truth-table.md").write_text(TRUTH_TABLE)
    (tmp_path / "docs" / "audit" / "CLAIM_TO_GATE_MATRIX.md").write_text(MATRIX)
    return tmp_path


def test_matching_figures_pass(tree: Path) -> None:
    (tree / "README.md").write_text("833 executable rules today, and 2 GATED / 1 PARTIAL / 0 NO GATE.\n")
    assert _load_gates(tree).gate_readme_figures() == []


def test_inflated_detection_count_fails(tree: Path) -> None:
    """The exact drift that shipped: README 947 vs truth table 833."""
    (tree / "README.md").write_text("947 executable rules. 2 GATED / 1 PARTIAL.\n")
    failures = _load_gates(tree).gate_readme_figures()
    assert len(failures) == 1
    assert "947" in failures[0].detail and "833" in failures[0].detail


def test_corpus_phrasing_is_also_checked(tree: Path) -> None:
    """'detection corpus (N rules)' is the README's other spelling of the count."""
    (tree / "README.md").write_text("the detection corpus (947 rules) fires. 2 GATED / 1 PARTIAL.\n")
    failures = _load_gates(tree).gate_readme_figures()
    assert len(failures) == 1
    assert "947" in failures[0].detail


def test_stale_claim_tally_fails(tree: Path) -> None:
    (tree / "README.md").write_text("833 executable. 62 GATED / 11 PARTIAL / 0 NO GATE.\n")
    failures = _load_gates(tree).gate_readme_figures()
    assert len(failures) == 1
    assert "62" in failures[0].detail and "2 GATED" in failures[0].detail


def test_partial_rows_are_not_counted_as_gated(tree: Path) -> None:
    """A PARTIAL row contains the substring 'GATED' only via 'NO GATE'/'PARTIAL' prose.

    Counting naively would report 3 GATED here and silently inflate the tally,
    which is the same class of error the gate exists to prevent.
    """
    gated, partial = _load_gates(tree)._matrix_counts()
    assert (gated, partial) == (2, 1)


def test_missing_sources_do_not_crash_the_gate(tmp_path: Path) -> None:
    """A partial checkout should skip these checks, not raise."""
    (tmp_path / "README.md").write_text("833 executable. 2 GATED / 1 PARTIAL.\n")
    assert _load_gates(tmp_path).gate_readme_figures() == []


def test_live_repo_is_consistent() -> None:
    """The gate must pass against the real tree, not only fixtures."""
    module = _load_gates(REPO_ROOT)
    assert module.gate_readme_figures() == []
