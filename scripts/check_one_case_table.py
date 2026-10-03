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
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from gate_toolkit import self_test_if_requested  # noqa: E402

self_test_if_requested(__file__)

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


#: Status strings the console's machine can never produce. Finding one of
#: these is proof a reader is using the pre-consolidation vocabulary.
IMPOSSIBLE_STATUSES = ("open", "in_progress")

_STATUS_LITERAL_RE = re.compile(
    r"""(?:Case\.status\s*==\s*|["']status["']\s*:\s*)["'](\w+)["']""",
)

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


def find_impossible_statuses(paths: list[Path]) -> list[str]:
    findings: list[str] = []
    for path in paths:
        rel = str(path.relative_to(ROOT))
        if rel in (VOCABULARY_OWNER, "scripts/check_one_case_table.py"):
            continue
        if not rel.endswith(".py") or not rel.startswith("services/api/app/"):
            # A connector describing its own vendor finding as "open" is
            # not speaking this vocabulary, and flagging it would teach a
            # reader the gate does not know what it is looking at.
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for number, raw in enumerate(text.splitlines(), 1):
            line = _without_comments(raw, path.suffix)
            for match in _STATUS_LITERAL_RE.finditer(line):
                if match.group(1) in IMPOSSIBLE_STATUSES:
                    findings.append(
                        f"[impossible-status] {rel}:{number} filters case status "
                        f"{match.group(1)!r}, which the console's state machine cannot produce, so "
                        "this counter is structurally zero. Use app.services.case_status"
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()

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
