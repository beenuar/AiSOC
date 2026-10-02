#!/usr/bin/env python3
"""Every Stable row in the README's maturity table must have earned it.

Why this gate exists
--------------------
The Project maturity table published a status for fifteen capabilities and
**nothing checked any of them**. There was no definition of Stable, Beta or
Alpha anywhere in the repository, no gate parsed the table, and the labels
appeared in no other file. Promoting a capability was a one-line edit.

That is the claim shape this project exists to refuse. Phase 1.1 of the
parity plan retracted twelve published claims nothing checked; the maturity
table was the last large claim surface with no gate behind it. Worse, an
audit found three of its rows were already wrong — two describing live
database coverage that exists nowhere in CI, and one naming the wrong compose
profile.

The definition is in `docs/audit/MATURITY_DEFINITION.md` and was read off the
four rows that already held Stable rather than invented, so no existing row
had to be demoted to fit a standard written after the fact.

What Stable requires
--------------------
1. **Unconditionally graded** — a PR check with no `paths:` filter and no
   `if:` guard that could skip it.
2. **Real production path** — the code a deployment runs, not a double.
3. **Proven able to fail** — a negative control.
4. **Real infrastructure** — containers, not in-memory SQLite with shims.

Why a registry rather than parsing the prose
---------------------------------------------
The `Tested` column is written for humans. A gate that tried to infer
evidence from it would either miss the row that matters or flag prose
forever — the reasoning `check_profile_service_counts.py` records about its
own list of exact sites. So each Stable row must name its evidence here, and
this gate verifies the named artefacts exist and hold the four properties.

It runs in **both directions**: an entry naming a row that is no longer
Stable, or pointing at a file that has been renamed or deleted, fails too. A
registry that only grows would accumulate stale entries implying coverage
nobody has.
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_main  # noqa: E402

REPO = repo_root()
README = REPO / "README.md"
WORKFLOWS = REPO / ".github" / "workflows"

#: The heading the table lives under, and the statuses it may publish.
TABLE_HEADING = "## Project maturity"
KNOWN_STATUSES = {"Stable", "Beta", "Alpha", "Ready, unpublished"}

#: A name that, when *defined* in a test, means the system under test was
#: replaced rather than exercised.
FAKE_DEFINITION = re.compile(r"^\s*class\s+(_?(Fake|Mock|Stub|Dummy)\w*)", re.M)

#: Libraries that intercept the boundary a test claims to cross. Listed
#: because requiring a *driver import* was the wrong discriminator and
#: produced a false negative on the strongest evidence in the repository:
#: `run_golden_pipeline.py` drives a running stack over `urllib`, which is
#: more real than any direct database connection, and imports no driver at
#: all.
#:
#: So real-path is now two sharper questions — does the test replace the
#: system under test, and does its job run real infrastructure — rather
#: than one blunt one about imports.
#:
#: `sqlite` is here deliberately: the SCIM suite runs on `sqlite+aiosqlite`
#: with `@compiles` shims for JSONB, UUID, INET and ARRAY, which is the
#: exact "double more capable than the real schema" shape that let a query
#: select two columns `detection_rules` does not have.
INTERCEPTORS = (
    "respx",
    "responses.activate",
    "unittest.mock.patch",
    "aioresponses",
    "sqlite+aiosqlite",
    "sqlite:///",
)


@dataclass(frozen=True)
class Evidence:
    """What a Stable row claims, and where to verify it."""

    #: Test files that exercise the real path. Repo-relative.
    tests: tuple[str, ...]
    #: Workflow filename that runs them, and the job id within it.
    workflow: str
    job: str
    #: Where the negative control lives, and the marker proving it is one.
    negative_control: str
    negative_marker: str
    #: Why this is the right evidence. Printed on failure, so an operator
    #: reading a red build gets the argument rather than just the rule.
    rationale: str
    #: Set when the proof is a static gate rather than a live container —
    #: the detection engine's replay proof, say. Those still need a
    #: negative control but have no driver to import.
    static_proof: bool = False


#: Evidence for every row the table marks Stable.
#:
#: Four entries existed in substance before this gate did — they are the
#: rows the definition was derived from. The rest are added as each
#: capability earns promotion, never before.
EVIDENCE: dict[str, Evidence] = {
    "UEBA": Evidence(
        tests=("tests/isolation/test_ueba_live.py",),
        workflow="ueba-live.yml",
        job="ueba-live",
        negative_control=".github/workflows/ueba-live.yml",
        negative_marker="The gate fails when the schema loses a column the model declares",
        rationale=(
            "The schema comes from the migrations the service ships rather than from "
            "`Base.metadata.create_all`, because the defect was a column present in the "
            "model and absent from the migration — building the schema from the model "
            "under test would paper over it. The negative control drops `peer_group_id`, "
            "the column migration 0001 forgot, and requires the suite to go red."
        ),
    ),
    "Alert-triggered playbooks, with a durable approval pause": Evidence(
        tests=("tests/isolation/test_playbook_pause_live.py",),
        workflow="playbook-pause-live.yml",
        job="playbook-pause-live",
        negative_control=".github/workflows/playbook-pause-live.yml",
        negative_marker="The gate fails when the partial unique index is gone",
        rationale=(
            "Every property the feature is named for belongs to the database: surviving a "
            "restart is a claim about rows on disk, and single resolution is enforced by a "
            "partial unique index the offline fake re-implements in Python. The negative "
            "control drops that index and requires the constraint test to fail."
        ),
    ),
    "Per-tenant detection tuning in the live engine": Evidence(
        tests=("tests/isolation/test_tenant_tuning_live.py",),
        workflow="tenant-tuning-live.yml",
        job="tenant-tuning-live",
        negative_control=".github/workflows/tenant-tuning-live.yml",
        negative_marker="The gate fails when the query names columns that do not exist",
        rationale=(
            "`_fetch` fails soft, so a permanently broken overlay is indistinguishable "
            "from a tenant with no tuning — both suppress nothing. The negative control "
            "re-injects the real defect, the two columns `detection_rules` does not have, "
            "and requires six of the ten tests to fail."
        ),
    ),
    "SCIM 2.0, white-label, usage metering": Evidence(
        tests=("tests/isolation/test_scim_live.py",),
        workflow="scim-live.yml",
        job="scim-live",
        negative_control=".github/workflows/scim-live.yml",
        negative_marker="The gate fails when SCIM stops scoping to the token's tenant",
        rationale=(
            "The offline suite runs on SQLite with `@compiles` shims for the four types "
            "Postgres and SQLite disagree about most, and mounts the router on a bare "
            "`FastAPI()` rather than the real application. This drives "
            "`create_application()` against real Postgres as the runtime role, and the two "
            "static contract gates move here from a path-filtered workflow."
        ),
    ),
    "Scheduled connectors": Evidence(
        tests=("tests/isolation/test_connector_scheduler_live.py",),
        workflow="connector-scheduler-live.yml",
        job="connector-scheduler-live",
        negative_control=".github/workflows/connector-scheduler-live.yml",
        negative_marker="The gate fails when poll jobs are registered paused",
        rationale=(
            "The defect that meant connecting a source never pulled data was "
            "`next_run_time=None`, which APScheduler registers as PAUSED — invisible to "
            "any mock, because a test asserting `add_job` was called passes whether or not "
            "the job will ever fire. This drives a real AsyncIOScheduler against real "
            "Postgres and real sockets, and the negative control re-injects that exact "
            "argument."
        ),
    ),
    "Entity graph (Neo4j)": Evidence(
        tests=("tests/isolation/test_graph_service_live.py",),
        workflow="graph-live.yml",
        job="graph-live",
        negative_control=".github/workflows/graph-live.yml",
        negative_marker="The gate fails when tenant scoping is removed",
        rationale=(
            "Every query comes from `graph_service.py` and runs through the driver a "
            "deployment uses, against a Neo4j started the way the shipped compose starts "
            "it, on every pull request with no path filter. The negative control removes "
            "the anchor's tenant predicate — the exact defect that function's docstring "
            "records — and requires the suite to go red."
        ),
    ),
    "Ingest → detect → correlate → alert": Evidence(
        tests=("tests/e2e/golden_pipeline/run_golden_pipeline.py",),
        workflow="golden-pipeline.yml",
        job="golden",
        negative_control=".github/workflows/golden-pipeline.yml",
        negative_marker="The gate fails when the pipeline is broken",
        rationale=(
            "Eleven independently reported stages driving one real event through ingest, "
            "Kafka, fusion, Postgres and the public API on the real `make up` stack. The "
            "negative control stops fusion and requires the check to go red; without it a "
            "green run would only prove the script ran."
        ),
    ),
    "Detection engine": Evidence(
        tests=("scripts/compile_sigma_ruleset.py",),
        workflow="validate-detections.yml",
        job="validate",
        negative_control="scripts/compile_sigma_ruleset.py",
        negative_marker="--prove-gate",
        rationale=(
            "`--prove-gate` reverts the Windows connector and requires all 1,687 Windows "
            "rules to fall silent, so the claim that a rule was watched to fire can itself "
            "fail. Executable means replayed and observed, never inferred from a directory "
            "or an `enabled:` flag."
        ),
        static_proof=True,
    ),
    "Alert correlation into incidents": Evidence(
        tests=("tests/e2e/golden_pipeline/run_golden_pipeline.py",),
        workflow="golden-pipeline.yml",
        job="golden",
        negative_control=".github/workflows/golden-pipeline.yml",
        negative_marker="The gate fails when the pipeline is broken",
        rationale=(
            "Correlation is exercised inside the golden pipeline rather than only by its "
            "own unit tests: the alert that reaches Postgres has been through the real "
            "correlator with a real correlation key."
        ),
    ),
    "REST API + web console": Evidence(
        tests=("tests/e2e/golden_pipeline/run_golden_pipeline.py",),
        workflow="golden-pipeline.yml",
        job="golden",
        negative_control=".github/workflows/golden-pipeline.yml",
        negative_marker="The gate fails when the pipeline is broken",
        rationale=(
            "The final stage reads the alert back out of the public API against a running "
            "stack, so the route, its auth and its serialisation are all on the path the "
            "check grades."
        ),
    ),
}


@dataclass
class Row:
    capability: str
    status: str
    tested: str
    production: str
    line: int


@dataclass
class Finding:
    code: str
    detail: str


@dataclass
class Scan:
    rows: list[Row] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)


def _match_key(capability: str) -> str | None:
    """The evidence key for a capability cell, matched on a stable prefix.

    Prefix rather than exact text because a row's wording carries live
    counts — "Detection engine (2603 executable rules) of 6991" changes
    whenever the corpus does, and a gate that breaks on a recount would be
    teaching people to edit the gate instead of the claim.
    """
    for key in EVIDENCE:
        if capability.startswith(key):
            return key
    return None


def parse_table(text: str) -> tuple[list[Row], list[Finding]]:
    """Rows of the maturity table, and anything malformed about it."""
    findings: list[Finding] = []
    lines = text.splitlines()
    try:
        start = next(i for i, ln in enumerate(lines) if ln.strip() == TABLE_HEADING)
    except StopIteration:
        return [], [
            Finding(
                "table-missing",
                f"README.md has no {TABLE_HEADING!r} section. This gate grades that table; "
                "finding nothing and scanning nothing print the same word, so it refuses "
                "rather than reporting the repository clean.",
            )
        ]

    rows: list[Row] = []
    for offset, raw in enumerate(lines[start:], start=start):
        if raw.startswith("## ") and offset != start:
            break
        if not raw.startswith("| ") or raw.startswith("|---") or raw.startswith("| Capability"):
            continue
        cells = [c.strip() for c in raw.strip().strip("|").split("|")]
        if len(cells) < 4:
            continue
        rows.append(Row(cells[0], cells[1], cells[2], cells[3], offset + 1))

    if not rows:
        findings.append(
            Finding(
                "table-empty",
                "The Project maturity section parsed to zero rows. A parser that matches nothing reports every capability clean.",
            )
        )
    for row in rows:
        if row.status not in KNOWN_STATUSES:
            findings.append(
                Finding(
                    "unknown-status",
                    f"line {row.line}: {row.capability!r} publishes status {row.status!r}, "
                    f"which is not one of {sorted(KNOWN_STATUSES)}. See "
                    "docs/audit/MATURITY_DEFINITION.md.",
                )
            )
    return rows, findings


def workflow_is_unconditional(workflow: str, job: str) -> tuple[bool, str]:
    """Whether this workflow grades every pull request.

    A `paths:` filter means a change outside the list never re-grades the
    capability, and a required check that never reports is weaker than no
    check: it looks green on every commit it did not read.
    """
    path = WORKFLOWS / workflow
    if not path.is_file():
        return False, f"{workflow} does not exist"
    text = path.read_text(encoding="utf-8", errors="replace")

    head = text.split("jobs:", 1)[0]
    if re.search(r"^\s{4,}paths(-ignore)?:", head, re.M):
        return False, f"{workflow} filters its triggers on `paths:`, so a change elsewhere never re-grades this"

    block = _job_block(text, job)
    if block is None:
        return False, f"{workflow} declares no job {job!r}"
    guard = re.search(r"^\s{4}if:\s*(.+)$", block, re.M)
    if guard and "changes.outputs" in guard.group(1):
        return False, f"{workflow} job {job!r} is guarded by `if: {guard.group(1).strip()}`, so it can be skipped"
    return True, ""


def _job_block(text: str, job: str) -> str | None:
    """The YAML block for one job, by indentation rather than by parsing.

    Deliberately not `yaml.safe_load`: a workflow carries `on:` keys and
    GitHub expressions that a strict loader mangles, and this only needs
    the text of one block.
    """
    match = re.search(rf"^  {re.escape(job)}:\s*$", text, re.M)
    if match is None:
        return None
    rest = text[match.end() :]
    following = re.search(r"^  \S", rest, re.M)
    return rest[: following.start()] if following else rest


#: Ways a job can stand up real infrastructure. `docker run` is here
#: because `isolation-live.yml` says in its own comment that it starts
#: single-container stores that way deliberately — and leaving it out made
#: this gate reject a job that starts a real Neo4j, which is the false
#: negative that teaches people to work around a gate instead of trusting
#: it.
_CONTAINER_MARKERS = ("make up", "docker compose", "docker run")


def declares_containers(workflow: str, job: str) -> bool:
    """Whether the job runs real infrastructure.

    A `services:` block, or the job standing the thing up itself. The
    golden pipeline runs `make up`, which is more real than any
    `services:` declaration.
    """
    path = WORKFLOWS / workflow
    if not path.is_file():
        return False
    block = _job_block(path.read_text(encoding="utf-8", errors="replace"), job)
    if block is None:
        return False
    if re.search(r"^\s+services:", block, re.M):
        return True
    return any(marker in block for marker in _CONTAINER_MARKERS)


def exercises_real_path(test: str) -> tuple[bool, str]:
    """Whether a test drives the real system rather than a stand-in.

    Asks whether the system under test was *replaced*, not whether a
    particular driver was imported. The job's own infrastructure is
    checked separately by `declares_containers`, which is the stronger
    evidence for "real" anyway.
    """
    path = REPO / test
    if not path.is_file():
        return False, f"{test} does not exist"
    source = path.read_text(encoding="utf-8", errors="replace")

    fakes = FAKE_DEFINITION.findall(source)
    if fakes:
        names = ", ".join(sorted({f[0] for f in fakes}))
        return False, (
            f"{test} defines {names}, so the system under test is replaced rather than "
            "exercised. A double that answers whatever it is asked cannot fail."
        )
    code = _without_prose(source)
    intercepted = [name for name in INTERCEPTORS if name in code]
    if intercepted:
        return False, (f"{test} uses {', '.join(intercepted)}, which intercepts the boundary it claims to cross.")
    return True, ""


def _without_prose(source: str) -> str:
    """The source with docstrings and comments removed.

    A live suite's docstring routinely *names* the thing it refuses to
    use — the SCIM one explains at length why the offline harness's
    SQLite shims cannot certify the capability. Grepping the whole file
    flagged that explanation as the offence it describes, which is the
    same mistake as searching for a socket option in a function whose
    docstring exists to say why it must not be set.

    Falls back to the raw source when the file does not parse: a syntax
    error should surface as a failing test, not as a silently relaxed
    rule here.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return source

    skip: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str) and node.end_lineno:
            skip.update(range(node.lineno, node.end_lineno + 1))

    return "\n".join("" if index in skip or raw.lstrip().startswith("#") else raw for index, raw in enumerate(source.splitlines(), start=1))


def has_negative_control(entry: Evidence) -> tuple[bool, str]:
    """Whether something proves the check can go red."""
    path = REPO / entry.negative_control
    if not path.is_file():
        return False, f"{entry.negative_control} does not exist"
    if entry.negative_marker not in path.read_text(encoding="utf-8", errors="replace"):
        return False, (
            f"{entry.negative_control} no longer contains {entry.negative_marker!r}. The "
            "negative control is what separates 'we tested it' from 'we know the test "
            "would notice'."
        )
    return True, ""


def scan() -> Scan:
    if not README.is_file():
        return Scan(findings=[Finding("no-readme", f"{README} does not exist")])

    rows, findings = parse_table(README.read_text(encoding="utf-8", errors="replace"))
    result = Scan(rows=rows, findings=list(findings))
    stable_keys: set[str] = set()

    for row in rows:
        if row.status != "Stable":
            continue
        key = _match_key(row.capability)
        if key is None:
            result.findings.append(
                Finding(
                    "stable-without-evidence",
                    f"line {row.line}: {row.capability!r} is marked Stable and names no "
                    "evidence in scripts/check_maturity_table.py. Stable is earned, not "
                    "edited: add the entry with its negative control, or leave the row "
                    "Beta. See docs/audit/MATURITY_DEFINITION.md.",
                )
            )
            continue
        stable_keys.add(key)
        entry = EVIDENCE[key]

        ok, why = workflow_is_unconditional(entry.workflow, entry.job)
        if not ok:
            result.findings.append(Finding("not-unconditional", f"{key}: {why}. Why this evidence: {entry.rationale}"))

        if not entry.static_proof:
            for test in entry.tests:
                ok, why = exercises_real_path(test)
                if not ok:
                    result.findings.append(Finding("not-real-path", f"{key}: {why}"))
            if not declares_containers(entry.workflow, entry.job):
                result.findings.append(
                    Finding(
                        "no-containers",
                        f"{key}: {entry.workflow} job {entry.job!r} declares no `services:` "
                        "containers and does not bring a stack up, so nothing it runs "
                        "touched real infrastructure.",
                    )
                )
        else:
            for test in entry.tests:
                if not (REPO / test).is_file():
                    result.findings.append(Finding("not-real-path", f"{key}: {test} does not exist"))

        ok, why = has_negative_control(entry)
        if not ok:
            result.findings.append(Finding("no-negative-control", f"{key}: {why}"))

    # The reverse direction. An entry for a row that is no longer Stable
    # implies coverage nobody is checking, which is how a registry that only
    # grows becomes a liability rather than a control.
    for key in EVIDENCE:
        if key not in stable_keys:
            result.findings.append(
                Finding(
                    "stale-evidence",
                    f"{key!r} has an evidence entry but no row marks it Stable. Remove the "
                    "entry so the registry shrinks when a capability is demoted.",
                )
            )
    return result


def _self_test() -> int:
    """Prove this gate still catches each kind of false Stable claim.

    Every case perturbs the real tree in memory rather than a fixture, so
    the gate is exercised against the table it actually grades.
    """
    import dataclasses

    cases: list[tuple[str, bool]] = []
    baseline = scan()
    cases.append(("the real tree passes, which every case below perturbs", not baseline.findings))

    original = dict(EVIDENCE)

    # 1. A row marked Stable with no evidence entry at all.
    #
    # The victim is chosen from the table rather than named, because this
    # case originally hardcoded a capability that was later promoted. The
    # replacement then matched nothing, the case found nothing unbacked,
    # and a self-test that silently stops testing is worse than one that
    # was never written. If every row is Stable there is nothing to
    # perturb, so the case reports honestly rather than passing.
    text = README.read_text(encoding="utf-8", errors="replace")
    victim = next((r for r in baseline.rows if r.status in ("Beta", "Alpha")), None)
    if victim is None:
        cases.append(("no Beta or Alpha row left to perturb for this case", False))
    else:
        faked = text.replace(
            f"| {victim.capability} | {victim.status} |",
            f"| {victim.capability} | Stable |",
            1,
        )
        rows, _ = parse_table(faked)
        unbacked = [r for r in rows if r.status == "Stable" and _match_key(r.capability) is None]
        cases.append((f"detects {victim.capability[:38]!r} marked Stable with no evidence", bool(unbacked)))

    # 2. An entry whose workflow is path-filtered.
    ok, _ = workflow_is_unconditional("isolation-live.yml", "live-stores")
    cases.append(("detects a path-filtered workflow as skippable", not ok))

    # 3. An entry whose test is a fake rather than the real path.
    ok, _ = exercises_real_path("services/agents/tests/test_playbook_pause_resume.py")
    cases.append(("detects a test that defines a fake standing in for the system", not ok))

    # 4. A negative control whose marker has gone.
    # `dataclasses.replace`, not `copy.replace`: the latter is 3.13+ and
    # CI pins 3.11.
    broken = dataclasses.replace(original["Detection engine"], negative_marker="--a-flag-that-does-not-exist")
    ok, _ = has_negative_control(broken)
    cases.append(("detects a negative control whose marker is gone", not ok))

    # 5. A missing test file.
    ok, _ = exercises_real_path("tests/e2e/golden_pipeline/this_file_does_not_exist.py")
    cases.append(("detects an evidence file that does not exist", not ok))

    # 6. The table itself going missing.
    _rows, findings = parse_table("# A readme with no maturity table\n")
    cases.append(("refuses a README with no maturity table", bool(findings)))

    return self_test_main(Path(__file__).name, [], cases)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="prove the gate still detects each case")
    parser.add_argument("--list", action="store_true", help="print every row and its status")
    args = parser.parse_args()

    if args.self_test:
        return _self_test()

    result = scan()

    if args.list:
        for row in result.rows:
            backed = "evidence" if _match_key(row.capability) else "—"
            print(f"  {row.status:<18} {backed:<9} {row.capability[:70]}")
        print()

    counts: dict[str, int] = {}
    for row in result.rows:
        counts[row.status] = counts.get(row.status, 0) + 1
    summary = ", ".join(f"{n} {s}" for s, n in sorted(counts.items()))

    if result.findings:
        print(f"MATURITY TABLE GATE FAILED — {len(result.findings)} finding(s):", file=sys.stderr)
        for finding in result.findings:
            print(f"  [{finding.code}] {finding.detail}", file=sys.stderr)
        print(
            "\nStable is earned, not edited. docs/audit/MATURITY_DEFINITION.md says what each label requires and how to promote a row.",
            file=sys.stderr,
        )
        return 1

    print(f"maturity-table: OK — {len(result.rows)} rows ({summary}); every Stable row's evidence holds.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
