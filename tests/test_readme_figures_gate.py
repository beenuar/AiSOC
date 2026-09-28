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


def _import_gates():
    """Import readme_gates.py exactly as it ships, pointed at the real tree."""
    spec = importlib.util.spec_from_file_location("_readme_gates_under_test", GATES)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _load_gates(tmp_root: Path):
    """Import readme_gates.py with REPO_ROOT pointed at a scratch tree."""
    module = _import_gates()

    module.REPO_ROOT = tmp_root
    module.README = tmp_root / "README.md"
    module.TRUTH_TABLE = tmp_root / "docs" / "detections" / "truth-table.md"
    module.CLAIM_MATRIX = tmp_root / "docs" / "audit" / "CLAIM_TO_GATE_MATRIX.md"
    module.VERSION_FILE = tmp_root / "VERSION"
    # Every module-level path, not just REPO_ROOT: leaving FIGURE_DOCS
    # pointing at the real tree made the gate read the live compliance page
    # against a scratch matrix, and every test failed for a reason that had
    # nothing to do with what it was testing.
    module.FIGURE_DOCS = (tmp_root / "apps" / "docs" / "docs" / "compliance" / "evidence-pack.md",)
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
    (tmp_path / "VERSION").write_text("12.0.0\n")
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
    """The gate must pass against the real tree, not only fixtures.

    Loaded unmodified, which is the whole point of this test and was not true
    of it before. ``_load_gates`` narrows ``FIGURE_DOCS`` to the one scratch
    path its fixtures write, and passing the real root through it left that
    narrowing in place: the "real tree" check read the compliance page and
    neither ``ROADMAP.md`` nor ``RELEASES.md``. Both went stale, this test
    stayed green, and ``scripts/readme_gates.py`` failed in CI over the same
    repository this had just called consistent.

    A test that reconfigures the gate before pointing it at production is not
    testing production.
    """
    module = _import_gates()

    assert module.REPO_ROOT == REPO_ROOT
    # Pin the surface, so shrinking it is a visible edit rather than a silent
    # one. Three documents publish the tally today.
    assert len(module.FIGURE_DOCS) == 3
    assert module.gate_readme_figures() == []


def test_other_docs_quoting_the_tally_are_checked(tree: Path) -> None:
    """A compliance page quoting a stale number is worse than one quoting none."""
    (tree / "README.md").write_text("833 executable. 2 GATED / 1 PARTIAL.\n")
    pack = tree / "apps" / "docs" / "docs" / "compliance" / "evidence-pack.md"
    pack.parent.mkdir(parents=True, exist_ok=True)
    pack.write_text("The honest index: 62 rows\n`GATED`, 11 `PARTIAL` with gaps named.\n")

    failures = _load_gates(tree).gate_readme_figures()
    assert len(failures) == 1
    assert "evidence-pack.md" in failures[0].detail
    assert "62" in failures[0].detail


def test_a_matching_compliance_page_passes(tree: Path) -> None:
    (tree / "README.md").write_text("833 executable. 2 GATED / 1 PARTIAL.\n")
    pack = tree / "apps" / "docs" / "docs" / "compliance" / "evidence-pack.md"
    pack.parent.mkdir(parents=True, exist_ok=True)
    pack.write_text("The honest index: 2 rows\n`GATED`, 1 `PARTIAL` with gaps named.\n")
    assert _load_gates(tree).gate_readme_figures() == []


def test_an_absent_compliance_page_is_not_a_failure(tree: Path) -> None:
    """A partial checkout must skip the check, not fail it."""
    (tree / "README.md").write_text("833 executable. 2 GATED / 1 PARTIAL.\n")
    assert _load_gates(tree).gate_readme_figures() == []


# The matrix's own Summary block. This gate compared every prose restatement
# elsewhere against the rows and never the document doing the claiming, so the
# summary read "GATED: 108" against 109 counted rows and CI stayed green — the
# one-directional shape the matrix file's own counting note warns about.
STALE_SUMMARY = MATRIX + "\n## Summary\n\n- GATED: 7\n- PARTIAL: 1\n- NO GATE: 0\n"
CURRENT_SUMMARY = MATRIX + "\n## Summary\n\n- GATED: 2\n- PARTIAL: 1\n- NO GATE: 0\n"


def test_matrix_summary_disagreeing_with_its_own_rows_fails(tree: Path) -> None:
    (tree / "README.md").write_text("833 executable. 2 GATED / 1 PARTIAL.\n")
    (tree / "docs" / "audit" / "CLAIM_TO_GATE_MATRIX.md").write_text(STALE_SUMMARY)

    failures = _load_gates(tree).gate_readme_figures()
    assert len(failures) == 1, failures
    assert "CLAIM_TO_GATE_MATRIX.md" in failures[0].detail
    assert "GATED: 7" in failures[0].detail
    assert "2 GATED rows" in failures[0].detail


def test_matrix_summary_matching_its_own_rows_passes(tree: Path) -> None:
    (tree / "README.md").write_text("833 executable. 2 GATED / 1 PARTIAL.\n")
    (tree / "docs" / "audit" / "CLAIM_TO_GATE_MATRIX.md").write_text(CURRENT_SUMMARY)
    assert _load_gates(tree).gate_readme_figures() == []


def test_a_stale_partial_count_in_the_summary_also_fails(tree: Path) -> None:
    """Both figures, not just the one that happened to drift first."""
    (tree / "README.md").write_text("833 executable. 2 GATED / 1 PARTIAL.\n")
    (tree / "docs" / "audit" / "CLAIM_TO_GATE_MATRIX.md").write_text(MATRIX + "\n## Summary\n\n- GATED: 2\n- PARTIAL: 4\n")

    failures = _load_gates(tree).gate_readme_figures()
    assert len(failures) == 1, failures
    assert "PARTIAL: 4" in failures[0].detail


# ── The version a document presents as current ───────────────────────────────
#
# RELEASES.md announced v11.2.0 as the current release for the whole of
# v12.0.0 — stale TL;DR, stale `VERSION` is line, and no v12.0.0 section at
# all — while every check in the repository passed, because the figure gate
# read detection counts and the claim-gate tally and had never read a version
# string. The most basic fact the file carries was the one nothing checked.


def _releases(tree: Path, body: str) -> None:
    """A scratch tree whose README is clean, so only RELEASES.md is on trial."""
    (tree / "README.md").write_text("833 executable. 2 GATED / 1 PARTIAL.\n")
    (tree / "RELEASES.md").write_text(body)


def _version_failures(tree: Path):
    module = _load_gates(tree)
    module.FIGURE_DOCS = (tree / "RELEASES.md",)
    return module.gate_current_version()


def test_a_doc_naming_the_current_version_passes(tree: Path) -> None:
    _releases(tree, "AiSOC is on `v12.0.0`, released 2026-09-28.\n\n`VERSION` is `12.0.0`.\n")
    assert _version_failures(tree) == []


def test_a_stale_current_version_fails(tree: Path) -> None:
    """The exact text that shipped: the TL;DR and the section opener both stale."""
    _releases(tree, "AiSOC is on `v11.2.0`, released 2026-09-26.\n\n`VERSION` is `11.2.0`.\n")
    failures = _version_failures(tree)
    assert len(failures) == 2, failures
    assert all("11.2.0" in f.detail and "12.0.0" in f.detail for f in failures)


def test_a_past_tense_mention_does_not_fail(tree: Path) -> None:
    """RELEASES.md names ten superseded versions and must keep being able to.

    Every one of them opens in the past tense, which is the shape the gate
    declines to read. A gate that flagged these would force the release
    history to be rewritten on every bump, so it would be turned off.
    """
    _releases(
        tree,
        "AiSOC is on `v12.0.0`, released 2026-09-28.\n\n"
        "## v11.2.0 (2026-09-26)\n\n"
        "`VERSION` was `11.2.0`. The **v11.2.0** release (2026-09-26) widened the corpus.\n\n"
        "## v11.1.0 (2026-09-25)\n\n"
        "`VERSION` was `11.1.0`. As of v11.1.0 the console re-resolves its upstreams.\n",
    )
    assert _version_failures(tree) == []


def test_a_stale_claim_sharing_a_line_with_a_dated_figure_still_fails(tree: Path) -> None:
    """The reason `_is_historical` is not applied to these patterns.

    RELEASES.md's TL;DR is one long line that legitimately dates a *different*
    figure in the same sentence. Exempting the line — which is what the figure
    gate does — would have skipped the stale version claim eighty words to its
    left, so the gate would have passed on the tree it was written for.
    """
    _releases(
        tree,
        "> **TL;DR:** AiSOC is on `v11.2.0`, released 2026-09-26 — the corpus "
        "release. Every claim is gated (claim-to-gate matrix at the v11.2.0 "
        "cut: 147 rows — 139 GATED / 8 PARTIAL / 0 NO GATE).\n",
    )
    failures = _version_failures(tree)
    assert len(failures) == 1, failures
    assert "11.2.0" in failures[0].detail


def test_a_stale_readme_version_badge_fails(tree: Path) -> None:
    """A reader takes the badge as the version on sight, without reading prose."""
    (tree / "README.md").write_text(
        "[![Version](https://img.shields.io/badge/version-11.2.0-f59e0b)](CHANGELOG.md)\n833 executable. 2 GATED / 1 PARTIAL.\n"
    )
    module = _load_gates(tree)
    module.FIGURE_DOCS = ()
    failures = module.gate_current_version()
    assert len(failures) == 1, failures
    assert "README" in failures[0].detail and "11.2.0" in failures[0].detail


def test_a_missing_version_file_skips_the_check(tmp_path: Path) -> None:
    """A partial checkout or a release tarball must skip, not fail."""
    (tmp_path / "README.md").write_text("AiSOC is on `v3.0.0`.\n")
    module = _load_gates(tmp_path)
    module.FIGURE_DOCS = ()
    assert module.gate_current_version() == []


def test_the_live_tree_presents_its_own_version(tmp_path: Path) -> None:
    """Production, with nothing reconfigured — the half that actually gates."""
    module = _import_gates()

    assert module.REPO_ROOT == REPO_ROOT
    assert module._declared_version() == (REPO_ROOT / "VERSION").read_text().strip()
    assert module.gate_current_version() == []
