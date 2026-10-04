#!/usr/bin/env python3
"""Refuse a second case table, and refuse a second status vocabulary.

Gap-closure wave 1.

The product shipped with two case tables that never synchronised. The
console wrote `aisoc_cases`; `resolution_time`, `metrics`, `insights`,
`executive_digest`, `mssp_portfolio` and the GraphQL layer all read
`cases`. **Every case an analyst created was invisible to every case
metric** — MTTR could sit at null while a tenant closed cases all week.

Nothing failed. Both tables existed, both sets of queries were valid,
and the only symptom was a number that stayed empty for a reason no
error message gave. That is what this gate exists to make loud.

Two questions, because the split had two halves
-------------------------------------------------
**One table.** No module may read or write `cases` as a bare table name.
Migration 083 renamed it `cases_pre_consolidation`, which is allowed:
keeping the pre-consolidation rows readable is deliberate, since a
migration that lost a row nobody noticed is worse than two tables.

**One vocabulary.** The readers filtered `status == "open"` and
`status == "in_progress"`, neither of which the console's state machine
can produce, so those counters were structurally zero. Status literals
now come from `app.services.case_status`, and a bare literal outside
that module is refused.

The second check is the one that matters more. Consolidating the tables
without consolidating the vocabulary would leave the counters just as
wrong, on one table instead of two.
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
import textwrap
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_main, verdict_args  # noqa: E402

# No module-level `self_test_if_requested` here, unlike most gates in this
# tree. It would answer `--self-test` before `_impossible_in` is defined, so
# the one thing worth proving -- that the detector catches the shapes that got
# past its first version -- could never run. The checks are handed to
# `self_test_main` through its `extra` parameter instead, which is what that
# parameter exists for.

# Ask git which tree this is, rather than counting directories above this
# file. Two levels up is whatever happens to be there — a worktree, a
# tarball, a container build context — and a gate that certifies the
# wrong tree is worse than one that fails.
ROOT = repo_root()

#: The table that no longer exists under this name.
RETIRED_TABLE = "cases"
SURVIVING_TABLE = "aisoc_cases"

#: `cases_pre_consolidation` is the deliberate archive, and `aisoc_cases`
#: obviously contains the substring. Neither must match.
#:
#: Case-sensitive on the keyword, which is what separates SQL from prose.
#: The first draft was case-insensitive and flagged the comment "Create
#: and update cases" in a permissions seed, plus two English sentences
#: reading "from cases the tenant actually closed". A gate with false
#: positives is a gate people learn to skip.
_BARE_TABLE_RE = re.compile(r"\b(?:FROM|JOIN|INTO|UPDATE)\s+cases\b(?!_pre_consolidation)")

#: A table name reached through interpolation rather than written out.
#:
#: `for table in ("alerts", "cases", "connectors")` building
#: `f"DELETE FROM {table}"` is invisible to the pattern above, and that
#: is where the last surviving reference hid — found by CI against real
#: Postgres, twice, after the literal search came back clean.
#:
#: Narrow on purpose. The first version matched any `"cases"` string
#: before a comma or bracket and produced 22 findings, every one a
#: false positive: a route prefix, a saved-view type, a permission
#: resource, a UI label. A file only qualifies if it *also* interpolates
#: a name straight into a SQL verb, which is the thing that makes a
#: string in a list become a table.
_TABLE_LIST_RE = re.compile(r"""["']cases["']\s*(?=[,)\]])""")
_SQL_INTERPOLATION_RE = re.compile(
    r"""(?:FROM|JOIN|INTO|UPDATE|TABLE)\s+\{""",
    re.IGNORECASE,
)

#: Comments are stripped before matching, so prose describing the change
#: does not trip the check on the change.
_PY_COMMENT_RE = re.compile(r"#.*$")
_SQL_COMMENT_RE = re.compile(r"--.*$")


def _without_comments(line: str, suffix: str) -> str:
    return (_SQL_COMMENT_RE if suffix == ".sql" else _PY_COMMENT_RE).sub("", line)


#: Status strings no AiSOC state machine produces. `open` is in neither the
#: case vocabulary (`aisoc_cases`' CHECK) nor the alert one
#: (`models/alert.py`: new/triaging/in_progress/resolved), so finding it
#: anywhere is proof of the pre-consolidation vocabulary.
IMPOSSIBLE_STATUSES = ("open",)

#: Impossible for a **case** and perfectly valid for an **alert**.
#:
#: This distinction is not pedantry: widening the detector without it
#: immediately produced three false positives on
#: `Alert.status.in_(["new", "triaging", "in_progress"])`, which is correct
#: code. A gate that flags correct code gets suppressed, and then it catches
#: nothing at all -- so these are only reported where the line is visibly
#: about cases.
CASE_ONLY_IMPOSSIBLE = ("in_progress",)

#: What makes a line visibly about cases. Deliberately narrow: a missed leak
#: is a wrong count, while a false positive on working alert code is how a
#: gate gets turned off.
_CASE_CONTEXT_RE = re.compile(r"\bCase\b|\baisoc_cases\b|CASE_STATUS|_CASE_STATUSES|case_status")

#: The four shapes a retired status literal actually takes in this tree.
#:
#: The first version of this gate matched only `Case.status == "x"` and
#: `"status": "x"`, and **passed while missing all four live leaks**: an ORM
#: `status="open"` keyword in an INSERT, two `_OPEN_*_STATUSES = (...)` tuples,
#: and a `.in_(["open", "in_progress"])`. None of those is an exotic spelling
#: -- they are how the code is ordinarily written -- so a detector that only
#: recognised two forms was a gate whose green was meaningless.
#:
#: Each alternative captures the literal in group 1 except `_IN_LIST_RE` and
#: `_TUPLE_RE`, which capture a whole collection body and are rescanned.
_STATUS_LITERAL_RE = re.compile(
    r"""(?:Case\.status\s*==\s*|["']status["']\s*:\s*|\bstatus\s*=\s*)["'](\w+)["']""",
)

#: `.in_(["open", "in_progress"])` and `.in_(("open",))`, on one line or
#: wrapped. The body is captured and each literal inside it checked.
_IN_LIST_RE = re.compile(r"""status\s*\.in_\s*\(\s*[\[\(]([^\]\)]*)""", re.S)

#: A module-level tuple or list of status strings, which is how two of the
#: live leaks were written -- under a comment saying they were kept in one
#: place precisely so they could not drift.
_STATUS_COLLECTION_RE = re.compile(
    r"""^\s*_?[A-Z_]*STATUS(?:ES)?[A-Z_]*\s*[:=][^=]*?[\[\(]([^\]\)]*)""",
    re.M,
)

#: An ORM column default on a status column:
#: `status: Mapped[str] = mapped_column(String(30), default="open", ...)`.
#:
#: The fifth shape, and the quietest: it seeds every row that does not set a
#: status explicitly, so the value the application falls back to was one the
#: CHECK rejects. The keyword is `default`, not `status`, which is why the
#: keyword pattern above does not reach it.
_COLUMN_DEFAULT_RE = re.compile(r"""\bstatus\b\s*:[^=]*=.*?\bdefault\s*=\s*["'](\w+)["']""")

#: Any quoted word, used to rescan a captured collection body.
_QUOTED_RE = re.compile(r"""["'](\w+)["']""")

#: Where the vocabulary is allowed to be spelled out.
VOCABULARY_OWNER = "services/api/app/services/case_status.py"

#: Files that legitimately name the retired table: the migration that
#: retires it, and this gate. Each entry is checked to still match
#: something, so a stale exemption is a failure rather than dead weight.
ALLOWED: dict[str, str] = {
    "services/api/migrations/083_one_case_table.sql": ("the consolidation itself — it must name the table it is retiring"),
}


def _tracked_sources() -> list[Path]:
    out: list[Path] = []
    for pattern in ("services/**/*.py", "services/**/*.sql", "scripts/**/*.py"):
        for path in ROOT.glob(pattern):
            if "__pycache__" in path.parts:
                continue
            # Tests are **not** excluded. The first draft skipped them,
            # and four live references survived in
            # `test_resolution_time_parity.py` and
            # `test_mssp_portfolio_isolation.py` — found by CI against
            # real Postgres rather than by the gate written to find
            # exactly that. A test that seeds the retired table is a
            # test asserting the consolidation did not happen.
            out.append(path)
    return sorted(out)


def find_retired_table_reads(paths: list[Path]) -> list[str]:
    findings: list[str] = []
    for path in paths:
        rel = str(path.relative_to(ROOT))
        if rel in ALLOWED:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for number, raw in enumerate(text.splitlines(), 1):
            line = _without_comments(raw, path.suffix)
            if _TABLE_LIST_RE.search(line) and _SQL_INTERPOLATION_RE.search(text):
                findings.append(
                    f"[interpolated-table] {rel}:{number} puts {RETIRED_TABLE!r} in a list of table "
                    f"names. Interpolated into SQL it reads the retired table just as surely as "
                    f"writing it out; use {SURVIVING_TABLE!r}"
                )
            if _BARE_TABLE_RE.search(line):
                findings.append(
                    f"[retired-table] {rel}:{number} queries `{RETIRED_TABLE}`, which migration 083 "
                    f"renamed. Read `{SURVIVING_TABLE}` — this is how every case metric came to be "
                    "blind to the cases analysts actually create"
                )
    return findings


#: Names that mean "this expression is about a case". A model class, the
#: table, the canonical module.
_CASE_NAMES = frozenset({"Case", "aisoc_cases", "case_status"})


def _is_case_attr(node: ast.AST, attr: str) -> bool:
    """True for `Case.<attr>`, which is the unambiguous case reference."""
    return isinstance(node, ast.Attribute) and node.attr == attr and isinstance(node.value, ast.Name) and node.value.id == "Case"


def _constants(node: ast.AST) -> list[str]:
    """Every string constant directly inside a list/tuple/set node."""
    if not isinstance(node, ast.List | ast.Tuple | ast.Set):
        return []
    return [e.value for e in node.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)]


def _scan_python(tree: ast.AST, impossible_case: set[str], impossible_any: set[str]) -> list[tuple[int, str]]:
    """Find retired case-status literals, by structure rather than by spelling.

    An AST rather than a regex, because the two cannot be told apart textually.
    `status: Mapped[str] = mapped_column(String(20), default="open")` is a
    defect in `models/case.py` and perfectly correct in `models/posture.py`,
    where a CSPM finding really is open or resolved -- and a regex sees one
    line. Flagging the posture model would be the kind of false positive that
    gets a gate suppressed, after which it catches nothing at all.

    Five shapes, each a reconstruction of something that shipped:

    1. `Case(status="open")`                  -- the constructor keyword
    2. `Case.status == "open"`                -- the comparison
    3. `Case.status.in_([...])`               -- the membership test
    4. `_OPEN_CASE_STATUSES = (...)`          -- the module collection
    5. `status: Mapped[...] = mapped_column(default="open")` inside a Case
       model -- the column default, scoped to the class it sits in
    """
    found: list[tuple[int, str]] = []

    def report(node: ast.AST, value: str) -> None:
        found.append((getattr(node, "lineno", 0), value))

    class _Visitor(ast.NodeVisitor):
        def __init__(self) -> None:
            self.class_stack: list[str] = []

        def visit_ClassDef(self, node: ast.ClassDef) -> None:  # noqa: N802
            self.class_stack.append(node.name)
            self.generic_visit(node)
            self.class_stack.pop()

        @property
        def in_case_model(self) -> bool:
            return any("Case" in name for name in self.class_stack)

        def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
            # 1. Case(status="open")
            if isinstance(node.func, ast.Name) and node.func.id == "Case":
                for kw in node.keywords:
                    if kw.arg == "status" and isinstance(kw.value, ast.Constant):
                        if kw.value.value in impossible_case:
                            report(kw.value, str(kw.value.value))

            # 3. Case.status.in_([...])
            if isinstance(node.func, ast.Attribute) and node.func.attr == "in_" and _is_case_attr(node.func.value, "status"):
                for arg in node.args:
                    for value in _constants(arg):
                        if value in impossible_case:
                            report(arg, value)

            self.generic_visit(node)

        def visit_Compare(self, node: ast.Compare) -> None:  # noqa: N802
            # 2. Case.status == "open"
            if _is_case_attr(node.left, "status"):
                for comparator in node.comparators:
                    if isinstance(comparator, ast.Constant) and comparator.value in impossible_case:
                        report(comparator, str(comparator.value))
            self.generic_visit(node)

        def visit_AnnAssign(self, node: ast.AnnAssign) -> None:  # noqa: N802
            # 5. the ORM column default, only inside a Case model
            if self.in_case_model and isinstance(node.target, ast.Name) and node.target.id == "status" and isinstance(node.value, ast.Call):
                for kw in node.value.keywords:
                    if kw.arg == "default" and isinstance(kw.value, ast.Constant):
                        if kw.value.value in impossible_case:
                            report(kw.value, str(kw.value.value))
            self.generic_visit(node)

        def visit_Assign(self, node: ast.Assign) -> None:  # noqa: N802
            # 4. a named collection of case statuses
            for target in node.targets:
                if isinstance(target, ast.Name) and "CASE" in target.id.upper() and "STATUS" in target.id.upper():
                    for value in _constants(node.value):
                        if value in impossible_case:
                            report(node.value, value)
            self.generic_visit(node)

        def visit_Constant(self, node: ast.Constant) -> None:  # noqa: N802
            # `open` is in neither vocabulary, so it is worth reporting
            # wherever it appears as a status value in a dict literal. Handled
            # by the caller's regex pass, which keeps this visitor to the
            # structural cases it can decide confidently.
            self.generic_visit(node)

    _Visitor().visit(tree)
    return found


def _impossible_in(line: str) -> list[str]:
    """Every retired status literal on one line, across all four shapes.

    Returned in source order and de-duplicated, so a line naming the same
    retired value twice reports once.
    """
    # `in_progress` is a real alert status, so it only counts against a line
    # that is visibly about cases. `open` counts everywhere, being absent from
    # both vocabularies.
    #
    # The structural cases are decided by `_scan_python`, which can tell a
    # `Case` from a `PostureFinding`. This pass is the textual backstop for
    # the shapes an AST does not resolve cleanly -- a dict literal, a SQL
    # string -- so it stays conservative on purpose.
    impossible = set(IMPOSSIBLE_STATUSES)
    if _CASE_CONTEXT_RE.search(line):
        impossible |= set(CASE_ONLY_IMPOSSIBLE)

    found: list[str] = []

    for match in _STATUS_LITERAL_RE.finditer(line):
        if match.group(1) in impossible:
            found.append(match.group(1))

    for pattern in (_IN_LIST_RE, _STATUS_COLLECTION_RE):
        for match in pattern.finditer(line):
            for quoted in _QUOTED_RE.finditer(match.group(1)):
                if quoted.group(1) in impossible:
                    found.append(quoted.group(1))

    # Written out rather than the `f in seen or seen.add(f)` idiom, which uses
    # a `None` return as a value and reads as a trick either way.
    seen: set[str] = set()
    unique: list[str] = []
    for value in found:
        if value not in seen:
            seen.add(value)
            unique.append(value)
    return unique


def find_impossible_statuses(paths: list[Path]) -> list[str]:
    """Report every retired case-status literal in the API service.

    Two passes, because the two kinds of evidence are different. The AST pass
    decides the structural cases confidently -- it knows `Case(status="open")`
    from `PostureFinding(status="open")`, which no regex can. The line pass
    then catches `open` in a status position anywhere, since `open` belongs to
    neither the case vocabulary nor the alert one and so is wrong wherever a
    status is being named.
    """
    findings: list[str] = []
    impossible_case = set(IMPOSSIBLE_STATUSES) | set(CASE_ONLY_IMPOSSIBLE)

    for path in paths:
        rel = str(path.relative_to(ROOT))
        if rel in (VOCABULARY_OWNER, "scripts/check_one_case_table.py"):
            continue
        if not rel.endswith(".py") or not rel.startswith("services/api/app/"):
            # A connector describing its own vendor finding as "open" is not
            # speaking this vocabulary, and flagging it would teach a reader
            # the gate does not know what it is looking at.
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue

        seen: set[tuple[int, str]] = set()

        try:
            tree = ast.parse(text)
        except SyntaxError:
            tree = None
        if tree is not None:
            for number, value in _scan_python(tree, impossible_case, set(IMPOSSIBLE_STATUSES)):
                seen.add((number, value))

        for number, raw in enumerate(text.splitlines(), 1):
            line = _without_comments(raw, path.suffix)
            for value in _impossible_in(line):
                seen.add((number, value))

        for number, value in sorted(seen):
            findings.append(
                f"[impossible-status] {rel}:{number} names case status "
                f"{value!r}, which the console's state machine cannot produce and the "
                "aisoc_cases CHECK rejects. Read app.services.case_status instead"
            )
    return findings


def find_stale_exemptions(paths: list[Path]) -> list[str]:
    """An exemption that no longer covers anything is a lie about the tree."""
    findings: list[str] = []
    for rel, reason in ALLOWED.items():
        path = ROOT / rel
        if not path.exists():
            findings.append(f"[stale-exemption] {rel} is exempted ({reason}) and does not exist")
            continue
        content = "\n".join(_without_comments(line, path.suffix) for line in path.read_text(encoding="utf-8").splitlines())
        if not _BARE_TABLE_RE.search(content):
            findings.append(f"[stale-exemption] {rel} is exempted ({reason}) but no longer names the retired table — remove the entry")
    return findings


def _self_test() -> int:
    """Prove the detector catches each shape that got past the first version.

    This is the part that matters. The original regex matched exactly two
    spellings and **passed while four live leaks sat in the tree**, so a
    self-test that only confirmed those two would have been just as green and
    just as useless. Each case below is a verbatim reconstruction of a line
    that shipped.

    The negatives are equally load-bearing: `in_progress` is a valid *alert*
    status, and a gate that reddens correct code gets suppressed, after which
    it catches nothing at all.
    """
    positives = [
        # hunt_scheduler.py:224 -- an ORM keyword in an INSERT. The CHECK
        # rejected this row, so a scheduled hunt that fired could not create
        # its case at all.
        ('        status="open",', "open", "ORM keyword in a Case() constructor"),
        # graphql/query.py:417 -- a membership test whose count was
        # structurally zero.
        (
            '        Case.status.in_(["open", "in_progress"])',
            "open",
            ".in_([...]) membership",
        ),
        # mssp_portfolio.py:134 -- a module tuple, under a comment claiming it
        # was kept in one place so it could not drift.
        (
            '_OPEN_CASE_STATUSES = ("open", "investigating", "in_progress")',
            "open",
            "module-level status tuple",
        ),
        # The two the original regex did catch, kept so widening cannot
        # silently drop them.
        ('    if Case.status == "open":', "open", "Case.status == literal"),
        ('    payload = {"status": "open"}', "open", "dict literal"),
        # Case-only: flagged because the line is visibly about cases.
        (
            '        Case.status.in_(["in_progress"])',
            "in_progress",
            "case-only value in a case context",
        ),
    ]
    negatives = [
        # Correct alert code. Flagging this is how a gate gets turned off.
        (
            '        Alert.status.in_(["new", "triaging", "in_progress"]),',
            "a valid alert status outside any case context",
        ),
        ('_OPEN_ALERT_STATUSES = ("new", "triaging", "in_progress")', "the alert tuple"),
        ('    Case.status == "investigating"', "a valid case status"),
        ('        status="new",', "the corrected constructor"),
    ]

    def _detect(snippet: str) -> list[str]:
        """Run both passes, as `find_impossible_statuses` does.

        A self-test that exercised only the regex would prove nothing about
        the three shapes the AST now owns, and those are the three that got
        past the first version of this gate.
        """
        values = list(_impossible_in(_without_comments(snippet, ".py")))
        try:
            tree = ast.parse(textwrap.dedent(snippet))
        except SyntaxError:
            return values
        impossible = set(IMPOSSIBLE_STATUSES) | set(CASE_ONLY_IMPOSSIBLE)
        values += [v for _, v in _scan_python(tree, impossible, set(IMPOSSIBLE_STATUSES))]
        return values

    checks: list[tuple[str, bool]] = []
    for line, expected, label in positives:
        checks.append((f"catches {label}", expected in _detect(line)))
    for line, label in negatives:
        checks.append((f"does not flag {label}", not _detect(line)))

    # The false positive that made the AST necessary. A CSPM posture finding
    # really is open or resolved, and a regex cannot tell it from a case.
    posture = 'class PostureFinding(Base):\n    status: Mapped[str] = mapped_column(String(20), default="open")\n'
    checks.append(("does not flag a posture finding's own 'open' status", not _detect(posture)))

    # And its counterpart, which must still be caught.
    case_model = 'class Case(Base):\n    status: Mapped[str] = mapped_column(String(30), default="open", index=True)\n'
    checks.append(("catches the same default on a Case model", "open" in _detect(case_model)))

    # The constructor keyword, in the multi-line form it actually shipped in.
    constructor = 'case = Case(\n    title="x",\n    status="open",\n)\n'
    checks.append(("catches a Case() constructor spanning lines", "open" in _detect(constructor)))

    # A comment describing the retired vocabulary must not trip the gate on
    # the commit that removes it.
    checks.append(
        (
            "ignores a comment naming the retired value",
            not _impossible_in(_without_comments('    x = 1  # was status="open"', ".py")),
        )
    )

    script = Path(__file__)
    return self_test_main(script.name, verdict_args(script), extra=checks)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        return _self_test()

    paths = _tracked_sources()
    if not paths:
        print("check_one_case_table: no sources found — refusing to report a tree clean", file=sys.stderr)
        return 2

    findings = find_retired_table_reads(paths) + find_impossible_statuses(paths) + find_stale_exemptions(paths)
    if findings:
        print(f"FAIL — {len(findings)} finding(s):")
        for finding in findings:
            print(f"  {finding}")
        return 1

    print(f"check_one_case_table: OK — {len(paths)} files, one case table and one status vocabulary")
    return 0


if __name__ == "__main__":
    sys.exit(main())
