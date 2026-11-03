#!/usr/bin/env python3
"""Refuse a status that a worker writes and no reader classifies.

The defect this exists to stop
------------------------------
``app.services.alert_status`` declared ``UNRESOLVED_STATUSES = ("new",
"triaging", "in_progress")``. The auto-triage worker in ``services/agents``
writes ``triaged``, which appeared in neither that tuple nor
``RESOLVED_STATUSES`` — so every triaged alert fell out of **both** buckets.
``/metrics/dashboard`` returned ``{"total": 0, "critical": 0}`` for a tenant
with nine open alerts, and a live pass watched the critical tile decay
3 → 2 → 1 → 0 as the worker got through the queue.

Nothing failed. Both tuples were valid, every query ran, and the only symptom
was a count that read zero for a reason no error message gave.

Two arms, because the drift had two halves
------------------------------------------
**Writers.** Every status literal written into ``alerts.status`` anywhere in
``services/`` must appear in ``WRITTEN_STATUSES``. This is the arm that
catches ``triaged``: a worker inventing a state is free to do so, and is not
free to do it silently.

**Readers.** No module outside ``alert_status`` may declare its own tuple of
alert statuses. Four copies had accumulated — ``cases.py``, ``health.py``,
``alert_queue.py``, ``alert_bulk_close.py`` — and they disagreed, which is
how the canonical one could be wrong about ``triaged`` while the copy in
``cases.py`` was right. Which copy is correct is luck; having copies is the
defect.

Why the writer arm is a registry and not a discovery
----------------------------------------------------
The gate could in principle *derive* the vocabulary from the writers and
never need a declared tuple. It deliberately does not: a value that is
written and never read is precisely the failure here, so the list a reader
consults has to be the thing a writer is checked against. Deriving it would
make the gate agree with itself no matter what the dashboard rendered.
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_main, verdict_args  # noqa: E402

ROOT = repo_root()

#: Where the single definition lives. Exempt from the reader arm, because its
#: whole job is to declare these tuples.
CANONICAL = Path("services/api/app/services/alert_status.py")

#: Trees whose Python may write `alerts.status`.
WRITER_TREES = ("services",)

#: A SQL statement that touches the alerts table. Matched against string
#: constants rather than raw file text so a comment quoting an old query
#: cannot fail the build.
_TOUCHES_ALERTS = re.compile(r"\b(?:UPDATE\s+alerts|INSERT\s+INTO\s+alerts)\b", re.IGNORECASE)

#: `SET status = 'x'` and the `THEN 'x'` arms of a `status = CASE` block.
_SET_STATUS = re.compile(r"\bstatus\s*=\s*'([a-z_]+)'", re.IGNORECASE)
_STATUS_CASE = re.compile(r"\bstatus\s*=\s*CASE(.*?)\bEND\b", re.IGNORECASE | re.DOTALL)
_THEN_LITERAL = re.compile(r"\bTHEN\s+'([a-z_]+)'", re.IGNORECASE)

#: Predicates read *against* the column rather than written to it. A gate that
#: counted these would flag every reader as a writer.
_COMPARISON = re.compile(r"\bstatus\s+(?:NOT\s+)?IN\s*\(", re.IGNORECASE)

#: Column names that are emphatically not an alert's lifecycle state. Several
#: live in the same statements (`patch_status`, `health_status`) and matching
#: them would import an unrelated vocabulary into this one.
_FOREIGN_COLUMNS = ("patch_status", "health_status", "signature_status", "sync_status")

#: Statuses that belong to a *different* row in a statement that also names
#: the alerts table. `vuln_promotion_sql` updates `asset_vulnerabilities`
#: and `alerts` in one file; the arm below reads one statement at a time, so
#: this is scoped per-statement rather than per-file.
_MAX_STATEMENT_CHARS = 8000


def _canonical_vocabulary() -> tuple[set[str], set[str], set[str]]:
    """Read the three tuples out of the canonical module, by AST.

    Imported rather than parsed would be simpler and would drag SQLAlchemy
    into a gate that several CI jobs run on a bare interpreter.
    """
    source = (ROOT / CANONICAL).read_text(encoding="utf-8")
    tree = ast.parse(source)
    found: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.AnnAssign | ast.Assign):
            continue
        targets = [node.target] if isinstance(node, ast.AnnAssign) else node.targets
        names = [t.id for t in targets if isinstance(t, ast.Name)]
        if not names or node.value is None:
            continue
        literals = {c.value for c in ast.walk(node.value) if isinstance(c, ast.Constant) and isinstance(c.value, str)}
        for name in names:
            found.setdefault(name, set()).update(literals)

    resolved = found.get("RESOLVED_STATUSES", set())
    written = found.get("WRITTEN_STATUSES", set()) | resolved
    pre_investigation = found.get("PRE_INVESTIGATION_STATUSES", set())
    return written, resolved, pre_investigation


def _statements_touching_alerts(path: Path) -> list[str]:
    """Every SQL string constant in ``path`` that writes the alerts table."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError):
        return []
    out: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
            continue
        text = node.value
        if len(text) > _MAX_STATEMENT_CHARS or not _TOUCHES_ALERTS.search(text):
            continue
        out.append(text)
    return out


def _statuses_written_in(statement: str) -> set[str]:
    """The literals this statement puts in a `status` column."""
    cleaned = statement
    for foreign in _FOREIGN_COLUMNS:
        cleaned = cleaned.replace(foreign, "_foreign_")
    # Strip the comparison predicates first, so `status NOT IN ('resolved')`
    # in a WHERE clause is not read as a write of `resolved`.
    cleaned = _COMPARISON.sub(" _comparison_ (", cleaned)

    found: set[str] = set(_SET_STATUS.findall(cleaned))
    for case_body in _STATUS_CASE.findall(cleaned):
        found.update(_THEN_LITERAL.findall(case_body))
    return {s.lower() for s in found}


def _orm_statuses_written_in(path: Path) -> set[str]:
    """`Alert(status="x")` and `update(Alert)...values(status="x")`.

    The `values` arm is scoped to a chain that names ``Alert``: without it,
    every `.values(status=...)` in the tree counts, and the gate reported a
    lake-query runner and an osquery work queue as alert writers because
    they happen to have a column with the same name.
    """
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError):
        return set()
    out: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.id if isinstance(func, ast.Name) else (func.attr if isinstance(func, ast.Attribute) else "")
        if name not in ("Alert", "values"):
            continue
        if name == "values" and "Alert" not in ast.unparse(node.func):
            continue
        for keyword in node.keywords:
            if keyword.arg == "status" and isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                out.add(keyword.value.value.lower())
    return out


#: Declarations that are deliberately their own list, with the reason.
#: Deliberately tiny: an allowlist is how a gate stops being a gate, so each
#: entry names a file whose list is *not* a classification of open-versus-done.
READER_EXEMPT: dict[str, str] = {
    "services/api/app/scripts/seed_demo.py": ("picks a spread of states for demo rows; it classifies nothing and reads nothing back"),
}


def _reader_copies(written: set[str]) -> list[tuple[Path, int, str]]:
    """Module-level tuples/sets of alert statuses declared outside the canonical module.

    A literal counts only when *every* member is an alert status and at least
    two are present — one string is a comparison, not a vocabulary — and when
    it is not also a valid case-status list, since `case_status` legitimately
    owns an overlapping set of words.

    `Literal[...]` annotations are skipped: a request model declaring which
    statuses a caller may close *to* is a write vocabulary, not a reader's
    classification of what counts as done.
    """
    from_case_vocabulary = _case_vocabulary()
    offenders: list[tuple[Path, int, str]] = []
    for path in _python_files():
        rel = path.relative_to(ROOT)
        if rel == CANONICAL or rel.as_posix() in READER_EXEMPT:
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, SyntaxError):
            continue
        in_literal = {
            id(node.slice) for node in ast.walk(tree) if isinstance(node, ast.Subscript) and ast.unparse(node.value).endswith("Literal")
        }
        for node in ast.walk(tree):
            if not isinstance(node, ast.Tuple | ast.Set | ast.List) or id(node) in in_literal:
                continue
            members = [e.value for e in node.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)]
            if len(members) < 2 or len(members) != len(node.elts):
                continue
            lowered = {m.lower() for m in members}
            if not lowered <= written:
                continue
            if lowered <= from_case_vocabulary:
                continue  # `case_status` owns these words too; not our business.
            offenders.append((rel, node.lineno, ", ".join(sorted(lowered))))
    return offenders


def _case_vocabulary() -> set[str]:
    """Words `app.services.case_status` legitimately owns."""
    case_status = ROOT / "services/api/app/services/case_status.py"
    if not case_status.exists():
        return set()
    try:
        tree = ast.parse(case_status.read_text(encoding="utf-8"))
    except (OSError, SyntaxError):
        return set()
    return {c.value.lower() for c in ast.walk(tree) if isinstance(c, ast.Constant) and isinstance(c.value, str)}


def _python_files() -> list[Path]:
    out: list[Path] = []
    for tree_name in WRITER_TREES:
        base = ROOT / tree_name
        if not base.is_dir():
            continue
        out.extend(p for p in base.rglob("*.py") if "/tests/" not in p.as_posix() and "/node_modules/" not in p.as_posix())
    return sorted(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="(default) report a verdict")
    parser.parse_args(argv)

    if not (ROOT / CANONICAL).exists():
        print(f"FAIL: the canonical vocabulary is missing at {CANONICAL}")
        return 1

    written, resolved, pre_investigation = _canonical_vocabulary()
    if not written or not resolved:
        print(f"FAIL: read no vocabulary out of {CANONICAL} — the tuples moved or were renamed")
        return 1

    files = _python_files()
    if not files:
        print(f"FAIL: scanned no Python under {WRITER_TREES} — wrong tree, or a broken glob")
        return 1

    problems: list[str] = []
    statements_seen = 0

    for path in files:
        statuses: set[str] = set()
        for statement in _statements_touching_alerts(path):
            statements_seen += 1
            statuses |= _statuses_written_in(statement)
        statuses |= _orm_statuses_written_in(path)
        for status in sorted(statuses - written):
            problems.append(
                f"{path.relative_to(ROOT)}: writes alerts.status = {status!r}, which is in neither "
                f"RESOLVED_STATUSES nor WRITTEN_STATUSES — every count on the dashboard will skip it"
            )

    if not statements_seen:
        print("FAIL: found no statement writing the alerts table — the scanner is not reading what it thinks it is")
        return 1

    unclassified = sorted(s for s in written if s not in resolved and s not in written)
    if unclassified:
        problems.append(f"declared but unclassified: {unclassified}")
    stray = sorted(pre_investigation - written)
    if stray:
        problems.append(f"PRE_INVESTIGATION_STATUSES names {stray}, which no writer writes")

    for path, lineno, members in _reader_copies(written):
        problems.append(
            f"{path}:{lineno}: declares its own alert-status list ({members}) — "
            "import it from app.services.alert_status so the two cannot disagree"
        )

    if problems:
        print(f"check_alert_status_vocabulary: {len(problems)} problem(s)\n")
        for problem in problems:
            print(f"  {problem}")
        return 1

    print(
        f"OK — {len(written)} statuses classified ({len(resolved)} terminal), "
        f"{statements_seen} alert-writing statement(s) across {len(files)} file(s), no second vocabulary"
    )
    return 0


def _self_test() -> int:
    """Prove the gate catches the shape that shipped.

    The injected violation is the real one: an `UPDATE alerts` that writes a
    status the canonical module does not know about.
    """
    written, _, _ = _canonical_vocabulary()
    probe = "UPDATE alerts SET status = CASE WHEN $1 THEN 'quarantined' ELSE status END WHERE id = $2"
    detected = bool(_statuses_written_in(probe) - written)

    comparison = "UPDATE alerts SET status = 'resolved' WHERE status NOT IN ('invented_state')"
    no_false_positive = _statuses_written_in(comparison) == {"resolved"}

    foreign = "UPDATE asset_vulnerabilities SET patch_status = 'overdue' FROM alerts WHERE true"
    foreign_ignored = not _statuses_written_in(foreign)

    return self_test_main(
        Path(__file__).name,
        verdict_args(Path(__file__)),
        extra=[
            ("detects a worker writing a status nobody classified", detected),
            ("does not read a WHERE-clause comparison as a write", no_false_positive),
            ("ignores a foreign *_status column in the same statement", foreign_ignored),
        ],
    )


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        raise SystemExit(_self_test())
    raise SystemExit(main())
