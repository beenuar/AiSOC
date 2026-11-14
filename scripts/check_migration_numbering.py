#!/usr/bin/env python3
"""Two migrations must not claim the same number.

Why this exists
---------------

`services/api/migrations/NNN_*.sql` is a sequentially numbered, first-come
namespace, and nothing checked it. Two branches both picked **121** on the same
morning — `121_fusion_alert_outbox.sql`, which merged, and
`121_closure_authorization_default_deny.sql`, which was open at the time. Git
reports no conflict, because the filenames differ: two files were added, and
adding two files is not a conflict. Both could have merged.

What goes wrong is not cosmetic, and it is worth stating precisely because
"ambiguous order" undersells it. `services/api/app/scripts/run_migrations.py`
does two things:

    files = sorted(p for p in MIGRATIONS_DIR.iterdir() if p.suffix == ".sql")
    pending = [p for p in files if p.name not in already]

— it orders by the **whole filename**, and it records what it has applied by
**filename** in `aisoc_schema_migrations(name TEXT PRIMARY KEY)`. So with two
121s:

* on a **fresh** deployment both are pending and they apply in filename order,
  `121_closure…` before `121_fusion…`;
* on a deployment that already took `121_fusion…`, only `121_closure…` is
  pending, so it applies **after** it.

The same two migrations, applied in a different order on a new install than on
an upgrade. That divergence is silent, it is permanent once both rows exist,
and it is invisible to every other gate in this tree.

What this checks
----------------

Every numbered chain in the repository, discovered structurally rather than
from a list kept here, because a list would have missed two of the seven:
`services/osquery-tls` sets `script_location = app/db`, so its chain is at
`app/db/versions` and matches neither `*/migrations/*` nor `*/alembic/versions/*`,
and `infra/postgres/initdb` is numbered shell the Postgres entrypoint runs in
filename order. A directory qualifies when it holds two or more tracked files
whose names begin with digits and a separator — which is also what makes the
gate self-extending: a chain added tomorrow is checked tomorrow.

The unit is the **directory**, because that is what every runner in this tree
iterates: `MIGRATIONS_DIR.iterdir()` for the API, `script_location` for the
four alembic chains, the initdb mount for Postgres. No runner here recurses, so
`services/api/clickhouse/001_init.sql` and `clickhouse/tiering/002_tiering.sql`
are two namespaces rather than a collision — and that is checked rather than
assumed (`lake_migrations.py` declares its chain in Python and reads neither).

What it deliberately does not check
-----------------------------------

**Gaps are not failures.** `…/118`, `…/120` with no 119 is the normal residue
of a branch that was reverted, renumbered, or never merged, and every runner
here applies what it finds in order rather than counting. Failing on a gap
would mean a reverted branch reds `main` until somebody renumbers history, so
the count is reported and never graded. A duplicate is the opposite: there is
no workflow that legitimately produces one.

**Alembic `down_revision` chains are not walked.** For those four services the
filename prefix is a convention and the real ordering lives in the revision
identifiers inside the file. A duplicate prefix there is a naming collision and
a sign two branches raced, which is worth failing on; a broken `down_revision`
graph is a different defect and alembic itself raises on it.

Run:  python3 scripts/check_migration_numbering.py
      python3 scripts/check_migration_numbering.py --self-test
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from collections import defaultdict
from collections.abc import Mapping
from pathlib import Path

# `scripts/` is on sys.path when this file is run as a program, but not when a
# test loads it by path with importlib. gate_toolkit sits beside it either way.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_main

#: A migration filename opens with digits and an **underscore**: `121_x.sql`,
#: `0004_y.py`, `10_z.sh`. The number is captured without its padding so
#: `012_a.sql` and `12_b.sql` are recognised as the collision they are — they
#: are two different filenames, they sort apart, and they are the same
#: migration number.
#:
#: The separator is deliberately not `[_-]`. Written that way, the first run of
#: this gate reported `docs/perf/results/2026-09-27-*.json` as "migration
#: 2026 claimed by 7 files", because a dated filename opens with digits and a
#: dash. Every one of the seven real chains in this tree uses an underscore
#: and nothing else does, so the narrower pattern costs nothing and the
#: alternative was an allowlist of directories that are not migrations — a
#: list that would grow forever and silence the gate on whatever was added to
#: it by mistake.
_NUMBERED = re.compile(r"^(\d+)_")

#: What a migration runner executes. `docs/decisions/0001-*.md` is also a
#: first-come numbered namespace and is deliberately out of scope: two ADRs
#: sharing a number is a broken cross-reference, not two schemas that apply in
#: different orders on a fresh install than on an upgrade. It uses a dash
#: anyway, so it is excluded twice over; this is the half that would still
#: hold if somebody renamed them.
_RUNNABLE_SUFFIXES = frozenset({".sql", ".py", ".sh"})

#: A directory needs this many numbered files before it is treated as a chain.
#: One file cannot collide with anything, and counting a lone `001_init.sql` as
#: a chain would make the gate's subject depend on unrelated directories that
#: happen to hold one numbered file.
_MIN_CHAIN = 2


#: Duplicate numbers that are already on `main`, with the only reason that
#: justifies leaving one in place.
#:
#: These 28 files across 13 numbers predate this gate. Renumbering them is not
#: a cleanup, it is a schema incident: `aisoc_schema_migrations` is keyed on
#: the **filename**, so renaming `012_case_management.sql` makes it pending
#: again on every deployment that has already applied it, and the runner would
#: re-execute it. The files are defensively written (`IF NOT EXISTS`), so it
#: would *probably* be harmless — "probably harmless re-execution of 28
#: migrations across every installed deployment" is not a trade worth making to
#: tidy a number.
#:
#: They are therefore frozen exactly as they are, and the entry is checked in
#: both directions: an entry whose files no longer collide fails as a stale
#: exemption, and so does one that has gained a *third* file. The second half
#: is the one that matters — without it, `121_x.sql` could join a
#: grandfathered pair and be absorbed in silence, which is precisely the defect
#: this gate exists to catch.
GRANDFATHERED: dict[str, tuple[str, ...]] = {
    "services/api/migrations::12": ("012_case_management.sql", "012_mssp_console.sql"),
    "services/api/migrations::13": ("013_asset_inventory.sql", "013_compliance_evidence.sql"),
    "services/api/migrations::14": ("014_hunt_workbench.sql", "014_insider_threat.sql"),
    "services/api/migrations::15": ("015_phishing_triage.sql", "015_remediation_maturity.sql"),
    "services/api/migrations::16": ("016_knowledge_base.sql", "016_threat_intel.sql"),
    "services/api/migrations::40": ("040_critical_severity_alert_confidence.sql", "040_saved_hunts.sql"),
    "services/api/migrations::41": ("041_alert_correlation_narrative.sql", "041_attack_chains.sql"),
    "services/api/migrations::42": ("042_alerts_schema_drift_fix.sql", "042_waitlist.sql"),
    "services/api/migrations::43": (
        "043_audit_log_hash_chain.sql",
        "043_hunts_tenant_isolation.sql",
        "043_tenant_provision.sql",
    ),
    "services/api/migrations::44": ("044_alerts_idempotency_key.sql", "044_cases_tenant_isolation.sql"),
    "services/api/migrations::70": ("070_retro_hunts.sql", "070_tenant_skills.sql"),
    "services/api/migrations::95": ("095_action_approval_tier.sql", "095_playbook_references.sql"),
    "services/api/migrations::96": (
        "096_access_governance_permissions.sql",
        "096_console_mfa.sql",
        "096_playbook_wait_pauses.sql",
    ),
}


def tracked_files(root: Path) -> list[str]:
    """Paths git knows about, which includes staged additions.

    `git ls-files` reads the index, so a migration that has been `git add`ed is
    seen before it is committed. One that has not been added is invisible —
    which is why the self-test stages nothing and builds real repositories
    instead.
    """
    out = subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["git", "ls-files"],
        capture_output=True,
        text=True,
        check=False,
        cwd=root,
    )
    if out.returncode != 0:
        return []
    return [line for line in out.stdout.splitlines() if line.strip()]


def discover_chains(root: Path) -> dict[str, dict[int, list[str]]]:
    """`directory -> number -> [basename, ...]` for every numbered chain."""
    by_dir: dict[str, dict[int, list[str]]] = defaultdict(lambda: defaultdict(list))
    for rel in tracked_files(root):
        path = Path(rel)
        if path.suffix not in _RUNNABLE_SUFFIXES:
            continue
        match = _NUMBERED.match(path.name)
        if match is None:
            continue
        by_dir[path.parent.as_posix()][int(match.group(1))].append(path.name)
    return {d: dict(numbers) for d, numbers in by_dir.items() if sum(len(v) for v in numbers.values()) >= _MIN_CHAIN}


def collisions(chains: dict[str, dict[int, list[str]]]) -> list[tuple[str, int, list[str]]]:
    """Every (directory, number) claimed by more than one file."""
    found: list[tuple[str, int, list[str]]] = []
    for directory, numbers in sorted(chains.items()):
        for number, names in sorted(numbers.items()):
            if len(names) > 1:
                found.append((directory, number, sorted(names)))
    return found


def _key(directory: str, number: int) -> str:
    return f"{directory}::{number}"


def evaluate(
    root: Path,
    # `Mapping`, not `dict`: dict is invariant in its value type, so a
    # `dict[str, tuple[str, str]]` built by the self-test is not a
    # `dict[str, tuple[str, ...]]` and mypy is right to say so.
    grandfathered: Mapping[str, tuple[str, ...]] | None = None,
) -> tuple[list[str], list[str], dict[str, dict[int, list[str]]]]:
    """Returns (failures, notes, chains).

    `grandfathered` is a parameter rather than a straight read of the module
    constant so the self-test can point the same code at a synthetic table.
    Mutating the constant in place would have worked and would also have made
    every probe depend on the order the probes ran in.
    """
    frozen_table = GRANDFATHERED if grandfathered is None else grandfathered
    chains = discover_chains(root)
    failures: list[str] = []
    notes: list[str] = []

    if not chains:
        return (
            [
                "no numbered migration chain was found. Every runner in this tree reads one, "
                "so zero means the walk stopped matching rather than that the tree is clean."
            ],
            notes,
            chains,
        )

    live = collisions(chains)
    seen_keys = set()

    for directory, number, names in live:
        key = _key(directory, number)
        seen_keys.add(key)
        frozen = frozen_table.get(key)
        if frozen is None:
            failures.append(
                f"{directory}: migration {number:0{len(names[0].split('_')[0])}d} is claimed by "
                f"{len(names)} files\n"
                + "".join(f"      - {directory}/{n}\n" for n in names)
                + "      Both will be applied. On a fresh deployment they run in filename order;\n"
                "      on a deployment that already took one of them, the other runs afterwards.\n"
                "      Renumber the one that has not merged yet."
            )
        elif tuple(names) != frozen:
            failures.append(
                f"{directory}: migration {number} is grandfathered as {list(frozen)} but now holds "
                f"{names}. A file joined or left a known-historical collision; the gate will not "
                f"absorb a new duplicate into an old exemption."
            )

    for key in sorted(frozen_table):
        if key not in seen_keys:
            failures.append(
                f"stale exemption: {key} is grandfathered but no longer collides. "
                f"Remove the entry — an exemption that outlived its reason reads like a decision "
                f"somebody made."
            )

    for directory, numbers in sorted(chains.items()):
        present = sorted(numbers)
        missing = [n for n in range(present[0], present[-1] + 1) if n not in numbers]
        files = sum(len(v) for v in numbers.values())
        gap_note = f", {len(missing)} gap(s) (not graded)" if missing else ""
        notes.append(f"  {directory}: {files} file(s), {present[0]}–{present[-1]}{gap_note}")

    return failures, notes, chains


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--self-test", action="store_true", help="prove the gate detects a duplicate and forgives a gap")
    args = parser.parse_args(argv)

    if args.self_test:
        return _self_test()

    root = repo_root()
    failures, notes, chains = evaluate(root)

    print(f"check_migration_numbering: {len(chains)} numbered chain(s) under {root}")
    for line in notes:
        print(line)

    if failures:
        print(f"\nFAIL: {len(failures)} migration numbering problem(s).", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1

    total = sum(sum(len(v) for v in numbers.values()) for numbers in chains.values())
    print(
        f"\nOK: {total} migration file(s) across {len(chains)} chain(s); no two claim the same number, "
        f"and all {len(GRANDFATHERED)} grandfathered historical collisions still hold."
    )
    return 0


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

_RUNNER_NOTE = "-- probe\nSELECT 1;\n"


def _probe_repo(tmp: Path, files: dict[str, str]) -> Path:
    """A real git repository, because the gate reads the index rather than the disk."""
    root = tmp
    for rel, body in files.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")
    git = ["git", "-c", "user.name=gate", "-c", "user.email=gate@invalid", "-c", "commit.gpgsign=false"]
    for argv in (["init", "-q", "-b", "main"], ["add", "-A"], ["commit", "-qm", "probe"]):
        subprocess.run(git + argv, cwd=root, check=True, capture_output=True)  # noqa: S603
    return root


def _self_test() -> int:
    import tempfile

    d = "services/api/migrations"
    # Each case is (label, files, expect_failure). Written per *shape* the
    # filesystem can take rather than per instance observed on main: the
    # padding case and the third-file case are both collisions no instance on
    # main exhibits, and both are the ones a looser rule would miss.
    cases: list[tuple[str, dict[str, str], bool]] = [
        (
            "the real defect: PR #1525's 121 beside the merged 121",
            {
                f"{d}/120_alerts_tenant_dedup_unique.sql": _RUNNER_NOTE,
                f"{d}/121_fusion_alert_outbox.sql": _RUNNER_NOTE,
                f"{d}/121_closure_authorization_default_deny.sql": _RUNNER_NOTE,
            },
            True,
        ),
        (
            "clean: consecutive numbers",
            {f"{d}/001_a.sql": _RUNNER_NOTE, f"{d}/002_b.sql": _RUNNER_NOTE, f"{d}/003_c.sql": _RUNNER_NOTE},
            False,
        ),
        (
            "a gap is not a failure",
            {f"{d}/001_a.sql": _RUNNER_NOTE, f"{d}/002_b.sql": _RUNNER_NOTE, f"{d}/009_c.sql": _RUNNER_NOTE},
            False,
        ),
        (
            "padding differs, number does not: 012 and 12 collide",
            {f"{d}/011_a.sql": _RUNNER_NOTE, f"{d}/012_b.sql": _RUNNER_NOTE, f"{d}/12_c.sql": _RUNNER_NOTE},
            True,
        ),
        (
            "three files on one number",
            {
                f"{d}/001_a.sql": _RUNNER_NOTE,
                f"{d}/002_b.sql": _RUNNER_NOTE,
                f"{d}/002_c.sql": _RUNNER_NOTE,
                f"{d}/002_e.sql": _RUNNER_NOTE,
            },
            True,
        ),
        (
            "a 4-digit alembic chain is checked too",
            {
                "services/ueba/alembic/versions/0001_a.py": "x = 1\n",
                "services/ueba/alembic/versions/0002_b.py": "x = 1\n",
                "services/ueba/alembic/versions/0002_c.py": "x = 1\n",
            },
            True,
        ),
        (
            "a chain at a non-conventional script_location is still found",
            {
                "services/osquery-tls/app/db/versions/001_a.py": "x = 1\n",
                "services/osquery-tls/app/db/versions/003_b.py": "x = 1\n",
                "services/osquery-tls/app/db/versions/003_c.py": "x = 1\n",
            },
            True,
        ),
        (
            "numbered shell in initdb is a first-come namespace too",
            {"infra/postgres/initdb/10_a.sh": "#!/bin/sh\n", "infra/postgres/initdb/10_b.sh": "#!/bin/sh\n"},
            True,
        ),
        (
            "same number in two different directories is two namespaces",
            {
                f"{d}/001_a.sql": _RUNNER_NOTE,
                f"{d}/002_b.sql": _RUNNER_NOTE,
                "services/ueba/alembic/versions/0001_a.py": "x = 1\n",
                "services/ueba/alembic/versions/0002_b.py": "x = 1\n",
            },
            False,
        ),
        (
            "an untracked duplicate is invisible, and the gate must not claim otherwise",
            {f"{d}/001_a.sql": _RUNNER_NOTE, f"{d}/002_b.sql": _RUNNER_NOTE},
            False,
        ),
    ]

    results: list[tuple[str, bool]] = []
    with tempfile.TemporaryDirectory() as tmpdir:
        for i, (label, files, expect_failure) in enumerate(cases):
            root = _probe_repo(Path(tmpdir) / f"case{i}", files)
            if label.startswith("an untracked duplicate"):
                # Written to disk, never `git add`ed. The gate reads the index,
                # so this must stay clean -- and the point of the case is that
                # a gate run before `git add` cannot see what you are adding.
                (root / d / "002_shadow.sql").write_text(_RUNNER_NOTE, encoding="utf-8")
            # No historical collisions in these probe trees, so the real
            # grandfather table would report all 13 of its entries stale and
            # drown the case under test.
            failures, _notes, _chains = evaluate(root, grandfathered={})
            got = bool(failures)
            results.append((f"{label}: {'flagged' if got else 'clean'}", got == expect_failure))

    # The grandfather table, both directions, against a synthetic stand-in so
    # the probe does not depend on the live tree staying as it is.
    synthetic = {"services/api/migrations::12": ("012_case_management.sql", "012_mssp_console.sql")}
    with tempfile.TemporaryDirectory() as tmpdir:
        frozen_root = _probe_repo(
            Path(tmpdir) / "frozen",
            {
                f"{d}/012_case_management.sql": _RUNNER_NOTE,
                f"{d}/012_mssp_console.sql": _RUNNER_NOTE,
                f"{d}/013_other.sql": _RUNNER_NOTE,
            },
        )
        failures, _n, _c = evaluate(frozen_root, grandfathered=synthetic)
        results.append(("a grandfathered collision passes", not failures))

        third_root = _probe_repo(
            Path(tmpdir) / "third",
            {
                f"{d}/012_case_management.sql": _RUNNER_NOTE,
                f"{d}/012_mssp_console.sql": _RUNNER_NOTE,
                f"{d}/012_newcomer.sql": _RUNNER_NOTE,
            },
        )
        failures, _n, _c = evaluate(third_root, grandfathered=synthetic)
        results.append(("a third file joining a grandfathered pair is not absorbed", bool(failures)))

        stale_root = _probe_repo(
            Path(tmpdir) / "stale",
            {f"{d}/012_case_management.sql": _RUNNER_NOTE, f"{d}/013_other.sql": _RUNNER_NOTE},
        )
        failures, _n, _c = evaluate(stale_root, grandfathered=synthetic)
        results.append(("a grandfathered entry that no longer collides is reported stale", bool(failures)))

        # The live table against the live tree: every one of the 13 entries
        # must still name a real collision. This is the arm that keeps the
        # table from rotting, and it is checked here as well as in the gate so
        # `--self-test` alone answers "is this gate still honest".
        live_failures, _n, _c = evaluate(repo_root())
        results.append((f"all {len(GRANDFATHERED)} live grandfather entries still name a real collision", not live_failures))

    return self_test_main(Path(__file__).name, extra=results)


if __name__ == "__main__":
    raise SystemExit(main())
