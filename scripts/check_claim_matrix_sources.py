#!/usr/bin/env python3
"""Every path the claim matrix cites in its Source column has to exist.

Why this exists
---------------
`docs/audit/CLAIM_TO_GATE_MATRIX.md` is the repository's audit backbone: 380
rows mapping a product claim to the CI gate that proves it. Nothing read the
**Source** column. `check_claim_gate_matrix.py` tallies statuses and checks
the summary block; `check_comment_paths.py` reads code *comments*, and a
markdown table cell is not a comment.

So nine rows cited documentation that does not exist anywhere in the tree —
`apps/docs/docs/console/{copilot,settings,index,playbooks,detection-tuning}.md`,
`concepts/outcome-memory.md`, `mssp/overview.md`, and `concepts/autonomy.md`
on a row that read GATED for a control with no caller at all. Several were
near misses for real files: `concepts/playbooks.md` and `console/rule-tuning.md`
exist, which is the shape that survives review — a reader seeing
`console/playbooks.md` has no reason to doubt it.

The audit backbone pointing at pages a reader cannot open is worse than a
missing row, because a row that cites a document reads as evidence.

Two design notes that are the whole job
---------------------------------------
**Locate the column by its header name, never by position.** A hardcoded
column index is how `project_stats.py` came to publish "0 rows — 0 gated"
against a real 278: a `Profile` column was inserted ahead of the status
column and every row then read `core`. The figure was invisible because
nothing compared it to anything.

**Resolve against the bases a writer actually uses.** Rows cite docs three
ways — from the repository root, relative to the docs root
(`concepts/playbooks.md`), and relative to this file's own directory
(`../decisions/0007-....md`). All three are legitimate and a gate that only
understood one would demand a rewrite of correct rows, which is how a gate
gets switched off.

Usage:
    python3 scripts/check_claim_matrix_sources.py
    python3 scripts/check_claim_matrix_sources.py --self-test
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import SELF_TEST_FLAG, repo_root, self_test_main  # noqa: E402

MATRIX = Path("docs/audit/CLAIM_TO_GATE_MATRIX.md")

#: The column whose cells are resolved. Found by header text.
SOURCE_HEADER = "Source"

#: Prefixes a cited path may be relative to, in the order a writer is likely
#: to have meant them. `""` is the repository root.
BASES: tuple[str, ...] = ("", "apps/docs/docs/", "apps/docs/", "docs/", "apps/web/src/app/", "apps/web/src/")

#: A token that looks like a path to a file rather than prose. Requires a
#: directory separator as well as an extension: a bare `README.md` in a
#: sentence is ambiguous, and `services/api/app/main.py` is not.
PATH_TOKEN_RE = re.compile(r"[A-Za-z0-9_.][A-Za-z0-9_./-]*\.(?:md|mdx|py|ts|tsx|sql|yml|yaml|json|go|sh|toml)\b")

#: Extensions whose files are generated into a build directory and are not
#: tracked. Cited by path in prose, resolved by nothing on a clean checkout.
IGNORE_EXACT: frozenset[str] = frozenset()


def _header_index(line: str, header: str) -> int | None:
    cells = [c.strip() for c in line.strip().strip("|").split("|")]
    for i, cell in enumerate(cells):
        if cell == header or cell.startswith(header + " "):
            return i
    return None


def _resolve(root: Path, token: str) -> bool:
    cleaned = token.strip("`").strip()
    if not cleaned or cleaned in IGNORE_EXACT:
        return True
    if "/" not in cleaned:
        # A bare filename in prose. Too ambiguous to adjudicate, and the rows
        # that were wrong all carried a directory.
        return True
    if cleaned.startswith("../"):
        # Relative to the matrix's own directory, which is how the ADR
        # citations are written.
        return (root / MATRIX.parent / cleaned).resolve().exists()
    return any((root / (base + cleaned)).exists() for base in BASES)


def dead_sources(root: Path) -> list[str]:
    """Every Source-column path token that resolves to nothing."""
    text = (root / MATRIX).read_text(encoding="utf-8")
    lines = text.splitlines()
    header_idx = None
    source_col = None
    for i, line in enumerate(lines):
        if not line.startswith("|"):
            continue
        col = _header_index(line, SOURCE_HEADER)
        if col is not None:
            header_idx, source_col = i, col
            break
    if header_idx is None or source_col is None:
        raise LookupError(f"{MATRIX} has no '{SOURCE_HEADER}' column header — the gate cannot locate what it reads")

    problems: list[str] = []
    row = 0
    for offset, line in enumerate(lines[header_idx + 2 :], start=header_idx + 3):
        if not line.startswith("|"):
            continue
        cells = line.strip().strip("|").split("|")
        if len(cells) <= source_col:
            continue
        row += 1
        for token in PATH_TOKEN_RE.findall(cells[source_col]):
            if not _resolve(root, token):
                problems.append(f"{MATRIX}:{offset}: row {row} cites `{token}`, which does not exist")
    if row == 0:
        raise LookupError(f"{MATRIX} has a '{SOURCE_HEADER}' header and no rows beneath it")
    return problems


def main() -> int:
    root = repo_root()
    try:
        problems = dead_sources(root)
    except (LookupError, OSError) as exc:
        print(f"check_claim_matrix_sources: {exc}", file=sys.stderr)
        return 1

    if problems:
        print(
            f"check_claim_matrix_sources: {len(problems)} Source citation(s) in the claim matrix point at "
            "a file that does not exist. A row that cites a document reads as evidence:",
            file=sys.stderr,
        )
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        print(
            "\nCorrect the path or name the real source. Near misses are the dangerous kind — "
            "`console/playbooks.md` does not exist and `concepts/playbooks.md` does.",
            file=sys.stderr,
        )
        return 1

    print("check_claim_matrix_sources: OK — every path cited in the claim matrix's Source column resolves")
    return 0


def _self_test() -> int:
    import tempfile

    extra: list[tuple[str, bool]] = []
    with tempfile.TemporaryDirectory(prefix="aisoc-matrix-src-") as tmp:
        root = Path(tmp)
        (root / MATRIX.parent).mkdir(parents=True)
        docs = root / "apps" / "docs" / "docs" / "concepts"
        docs.mkdir(parents=True)
        (docs / "playbooks.md").write_text("real\n", encoding="utf-8")
        (root / "docs" / "decisions").mkdir(parents=True)
        (root / "docs" / "decisions" / "0007-x.md").write_text("real\n", encoding="utf-8")

        def write(rows: str) -> None:
            (root / MATRIX).write_text(
                "# Claim-to-Gate Matrix\n\n"
                "| Claim | Source | Gate (workflow :: job) | Profile | Status | Closes in |\n"
                "|---|---|---|---|---|---|\n" + rows,
                encoding="utf-8",
            )

        write("| a | `concepts/playbooks.md` | g | core | GATED | - |\n")
        extra.append(("a docs-root-relative path that exists is not reported", not dead_sources(root)))

        write("| a | `console/playbooks.md` | g | core | GATED | - |\n")
        extra.append(("the near miss is reported", any("console/playbooks.md" in p for p in dead_sources(root))))

        write("| a | `../decisions/0007-x.md` | g | core | GATED | - |\n")
        extra.append(("a path relative to the matrix's own directory resolves", not dead_sources(root)))

        # The column is located by header name. Inserting a column ahead of
        # Source must not make the gate read the wrong cell — the exact
        # failure that made project_stats.py publish 0 rows against 278.
        (root / MATRIX).write_text(
            "| Claim | Profile | Source | Gate | Status | Closes in |\n"
            "|---|---|---|---|---|---|\n"
            "| a | core | `console/playbooks.md` | g | GATED | - |\n",
            encoding="utf-8",
        )
        extra.append(
            ("a column inserted ahead of Source does not move what is read", any("console/playbooks.md" in p for p in dead_sources(root)))
        )

        # An empty table must refuse rather than report clean.
        (root / MATRIX).write_text(
            "| Claim | Source | Gate | Profile | Status | Closes in |\n|---|---|---|---|---|---|\n", encoding="utf-8"
        )
        try:
            dead_sources(root)
            refused = False
        except LookupError:
            refused = True
        extra.append(("a table with no rows is refused, not reported clean", refused))

        (root / MATRIX).write_text("# No table here\n", encoding="utf-8")
        try:
            dead_sources(root)
            refused = False
        except LookupError:
            refused = True
        extra.append(("a matrix with no Source header is refused", refused))

    real = dead_sources(repo_root())
    extra.append((f"the real matrix resolves every Source path ({len(real)} dead)", not real))
    return self_test_main(Path(__file__).name, extra=extra)


if __name__ == "__main__":
    if SELF_TEST_FLAG in sys.argv[1:]:
        sys.exit(_self_test())
    sys.exit(main())
