#!/usr/bin/env python3
"""A table a migration creates must be named somewhere outside its migration.

Why this exists
---------------
Module reachability answers "does anything import this file". It cannot
answer the question that actually matters for stored state: **which code path
writes this table, and does it run on the default profile.** A module that
reads a table nobody writes runs perfectly; a migration that creates a table
nothing reads applies perfectly; and every gate in this repository passes on
both.

Three instances found in one sweep of `main`, each with every gate green:

* `triage_questions` (migration 154) — read on the triage hot path of every
  alert, **no writer anywhere**. `for_tenant()` returned empty for every
  tenant forever, and the store's own docstring asserted a writer that did
  not exist, so a reader auditing the file concluded the write half shipped.
* `hunt_source_reports` (migration 155) — a pure orphan. The producing route
  computed exactly the table's columns and returned them in the HTTP response
  without persisting anything, so `approved_at` had no writer and the
  migration's stated property, *"Nothing is hunted until this is set"*, was
  enforced by nobody.
* `aisoc_tenant_response_schedules` / `_windows` (migration 142) — appeared
  in exactly one file repo-wide, their own migration. A tenant could not
  declare a change freeze even by hand.

What is checked, and what deliberately is not
---------------------------------------------
For every table a tracked migration creates, this asks whether the name
appears in any **non-migration, non-test** tracked file. That is a weak
question on purpose — a mention is not a writer — and it is the strongest one
a static pass can answer without a per-table model of what "written" means.
A table nothing mentions at all is unambiguous, and all three instances above
were that.

The read/write asymmetry is **not** checked here. A reader with no writer
needs to know which statement writes, which means parsing INSERT/UPDATE
targets across raw SQL, SQLAlchemy Core and an ORM — and the repository's own
experience is that a detector which only knows one syntax reports OK while
missing the case it was written for. Where that distinction matters it is
asserted by a live round-trip test instead, because rows are the evidence.

Usage:
    python3 scripts/check_orphan_tables.py
    python3 scripts/check_orphan_tables.py --self-test
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import SELF_TEST_FLAG, repo_root, self_test_main  # noqa: E402

#: Where migrations live. Each entry is (directory, glob).
MIGRATION_GLOBS: tuple[tuple[str, str], ...] = (
    ("services/api/migrations", "*.sql"),
    ("services/ueba/alembic/versions", "*.py"),
    ("services/honeytokens/app/db/versions", "*.py"),
    ("services/purple-team/app/db/versions", "*.py"),
    ("services/osquery-tls/app/db/versions", "*.py"),
)

CREATE_TABLE_RE = re.compile(
    r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[\"']?(?:public\.)?([A-Za-z_][A-Za-z0-9_]*)[\"']?",
    re.IGNORECASE,
)

#: Tables that are genuinely referenced only by their own migration, each with
#: a reason. May only shrink — an entry whose table has gained a reference, or
#: whose table no longer exists, fails the gate rather than lingering.
#:
#: This is a **debt balance and not a target**, in the same sense as
#: `check_route_authz.py`'s ceiling. Every entry is a table a migration
#: creates that no production code names: the write half, the read half or
#: both are absent, and which it is cannot be decided statically. Each is
#: recorded with what is verifiable rather than with a guess about intent, and
#: each shares one return condition — a writer, a reader, and a round-trip
#: test against real rows, because rows are the evidence.
#:
#: Found by this gate on its first run over `main`; they predate it and are
#: not in the scope of the change that added it. Listing them is what makes
#: the decision not to wire them visible, which is the same reasoning
#: `ALLOWED_UNREACHABLE` in `check_module_reachability.py` is kept under.
ALLOWED_ORPHANS: dict[str, str] = {
    # ── migration 086, case orchestration ─────────────────────────────────
    # Five tables for queueing, SLA policy, escalation, shift handoff and a
    # status-transition audit. The console's case surface uses `aisoc_cases`
    # and its own columns; none of these five is named by any production
    # module. The two case tables that DID disagree were reconciled by
    # migration 083, which is the precedent for how this is closed.
    "case_queues": "Case orchestration (086). No production module names it.",
    "case_sla_policies": "Case orchestration (086). No production module names it.",
    "case_escalation_policies": "Case orchestration (086). No production module names it.",
    "case_shift_handoffs": "Case orchestration (086). No production module names it.",
    "case_status_transitions": "Case orchestration (086). No production module names it.",
    # ── migration 088, data governance ────────────────────────────────────
    # Field-level access rules and subject-deletion (DSAR) requests. Tenant
    # deletion is implemented in `tenant_deletion.py` against the tables it
    # names; neither of these is one of them.
    "field_access_rules": "Data governance (088). No production module names it.",
    "subject_deletion_requests": "Data governance (088). No production module names it; tenant deletion uses tenant_deletion.py.",
    # ── migration 056, marketplace v3 ─────────────────────────────────────
    # The community publish flow keeps submissions, installs and entitlements
    # in three process-global dicts — lost on restart and wrong on a second
    # replica. These are the tables those dicts were meant to become, and the
    # migration that created them has no readers, which is recorded in the
    # project's own notes as a known gap rather than discovered here.
    "marketplace_submissions": "Marketplace v3 (056). The publish flow keeps submissions in a process-global dict instead.",
    "marketplace_entitlements": "Marketplace v3 (056). The publish flow keeps entitlements in a process-global dict instead.",
    # ── migration 014, insider threat ─────────────────────────────────────
    # UEBA peer groups. `EntityBaseline.peer_group_id` is the ORM side of
    # this and its own migration never created the column, so the peer-group
    # feature has never had both halves at once.
    "insider_peer_group_members": "Insider threat (014). UEBA peer grouping; no production module names it.",
}

SKIP_PREFIXES = ("plans/",)


def _tracked(root: Path) -> list[str]:
    out = subprocess.run(["git", "ls-files", "-z"], cwd=root, capture_output=True, text=True, check=True).stdout
    return [rel for rel in out.split("\0") if rel and not rel.startswith(SKIP_PREFIXES)]


def _is_migration(rel: str) -> bool:
    return any(rel.startswith(d + "/") for d, _glob in MIGRATION_GLOBS)


def _is_test(rel: str) -> bool:
    parts = Path(rel).parts
    name = Path(rel).name
    return "tests" in parts or "test" in parts or name.startswith("test_") or name.endswith("_test.py") or name == "conftest.py"


def created_tables(root: Path, tracked: list[str]) -> dict[str, str]:
    """Table name -> the migration that creates it (first one wins)."""
    tables: dict[str, str] = {}
    for rel in tracked:
        if not _is_migration(rel):
            continue
        try:
            source = (root / rel).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for name in CREATE_TABLE_RE.findall(source):
            tables.setdefault(name.lower(), rel)
    return tables


def orphans(root: Path, tracked: list[str], tables: dict[str, str]) -> list[str]:
    """Tables named in no tracked file other than a migration or a test."""
    remaining = dict(tables)
    this_file = Path(__file__).resolve()
    for rel in tracked:
        if not remaining:
            break
        if _is_migration(rel) or _is_test(rel):
            continue
        # This gate's own allowlist names every table it excuses. Counting
        # that as a reference makes every entry instantly stale and the
        # allowlist unusable — the gate vouching for the tables it was told
        # to excuse.
        if (root / rel).resolve() == this_file:
            continue
        try:
            source = (root / rel).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        lowered = source.lower()
        for name in list(remaining):
            if name in lowered:
                del remaining[name]
    return sorted(remaining)


def main() -> int:
    root = repo_root()
    tracked = _tracked(root)
    tables = created_tables(root, tracked)
    if not tables:
        # Discovery walks the migration directories. An empty result printed a
        # clean verdict over a tree with no migrations in it, which reads
        # identically to a tree where every table is referenced.
        print(
            "check_orphan_tables: found no CREATE TABLE in any migration directory — refusing to report a clean tree",
            file=sys.stderr,
        )
        return 1

    found = orphans(root, tracked, tables)
    unexplained = [name for name in found if name not in ALLOWED_ORPHANS]
    stale = [name for name in ALLOWED_ORPHANS if name not in found]

    if stale:
        print("check_orphan_tables: allowlist entries that no longer describe an orphan:", file=sys.stderr)
        for name in stale:
            print(f"  {name}", file=sys.stderr)
        print("Remove them; the allowlist may only shrink.", file=sys.stderr)
        return 1

    if unexplained:
        print(
            f"check_orphan_tables: {len(unexplained)} table(s) are named by their own migration and "
            "by nothing else. A migration that applies cleanly and a reader that runs perfectly are "
            "both consistent with a table no code path writes:",
            file=sys.stderr,
        )
        for name in unexplained:
            print(f"  {name}  (created by {tables[name]})", file=sys.stderr)
        print(
            "\nEither wire it — a writer, a reader and a round-trip test against real rows — or record "
            "it in ALLOWED_ORPHANS with the reason and the condition that removes the entry.",
            file=sys.stderr,
        )
        return 1

    print(
        f"check_orphan_tables: OK — {len(tables)} table(s) created by migrations, each named outside its own "
        f"migration; {len(ALLOWED_ORPHANS)} allowlisted with a reason."
    )
    return 0


def _self_test() -> int:
    import tempfile

    extra: list[tuple[str, bool]] = []
    with tempfile.TemporaryDirectory(prefix="aisoc-orphan-") as tmp:
        root = Path(tmp)
        migrations = root / "services" / "api" / "migrations"
        migrations.mkdir(parents=True)
        (migrations / "001_init.sql").write_text(
            "CREATE TABLE IF NOT EXISTS used_table (id UUID);\nCREATE TABLE orphan_table (id UUID);\n",
            encoding="utf-8",
        )
        app = root / "services" / "api" / "app"
        app.mkdir(parents=True)
        (app / "store.py").write_text('SQL = "SELECT 1 FROM used_table"\n', encoding="utf-8")
        tests = root / "services" / "api" / "tests"
        tests.mkdir(parents=True)
        # A test mentioning the orphan must not rescue it — that is the shape
        # the gate exists to find, and counting it would make the gate agree
        # with the defect.
        (tests / "test_orphan.py").write_text('SQL = "SELECT 1 FROM orphan_table"\n', encoding="utf-8")

        tracked = ["services/api/migrations/001_init.sql", "services/api/app/store.py", "services/api/tests/test_orphan.py"]
        tables = created_tables(root, tracked)
        found = orphans(root, tracked, tables)
        extra += [
            ("both tables are discovered from the migration", set(tables) == {"used_table", "orphan_table"}),
            ("a table a module names is not reported", "used_table" not in found),
            ("a table only its migration names is reported", "orphan_table" in found),
            ("a test naming it does not rescue it, which is the point", "orphan_table" in found),
        ]

    root = repo_root()
    tracked = _tracked(root)
    tables = created_tables(root, tracked)
    extra.append((f"it read a real corpus ({len(tables)} tables)", len(tables) > 50))
    return self_test_main(Path(__file__).name, extra=extra)


if __name__ == "__main__":
    if SELF_TEST_FLAG in sys.argv[1:]:
        sys.exit(_self_test())
    sys.exit(main())
