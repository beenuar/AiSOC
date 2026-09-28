#!/usr/bin/env python3
"""No commit that lands on a protected branch may go ungraded.

Why this exists
---------------
A required status check is a promise that every commit reaching the branch was
graded. `ci.yml` broke that promise quietly for months: its concurrency group
was keyed on `github.ref`, which is the same string for every push to `main`,
with `cancel-in-progress: true`. During a merge burst each merge killed the
previous merge's run mid-`Python — Tests`.

Measured on this repository before the fix, over the last 1,000 push-triggered
runs on `main`: 259 ended `cancelled`. `ci.yml` alone was 36 cancelled out of
51. Over the last 30 commits on `main`, only 336 of the 660 required-check x
commit pairs actually graded — 51%.

None of that looked like a problem, and that is the point:

* A cancelled run reports `cancelled`, not `failure`. Nothing turns red.
* Worse, a job whose `needs:` dependency was cancelled never starts, so it
  never produces a check run at all. The eight `python-services-wave-2-test`
  matrix checks did not report on 15 of 30 commits for exactly that reason:
  their `needs: python-lint` was killed first. A check that is *absent* is
  even less visible than one that is cancelled.
* `main` reads green on whatever HEAD happens to be, because HEAD is the one
  commit nothing superseded.

What this gate asserts
----------------------
For every workflow that can be triggered by a push to a protected branch, the
concurrency configuration must not be able to discard that push's run. Two
independent ways it can, and both are checked:

`cancel-in-progress`
    The obvious one. Truthy for a push event means the next push kills this
    run mid-flight.

a concurrency group shared across commits
    The non-obvious one, and the reason `cancel-in-progress: false` is not a
    fix on its own. GitHub's documented behaviour is that when a run queues
    into a busy group, *any run already pending in that group is cancelled*.
    So a non-cancelling group still loses every intermediate run on a burst —
    it only guarantees the first and the last.

    This is not theoretical either. `publish-images.yml` was moved to
    `cancel-in-progress: false` after a release left twelve images current and
    the thirteenth two commits behind. On the day this gate was written that
    workflow still had 13 runs on `main` ending `cancelled`, each with **zero
    jobs** — cancelled while pending, before a single step existed.

The fix in both cases is the same: key the group so a push never shares one.
A pull request still supersedes its own earlier runs, because only a branch's
head commit needs grading:

    group: <prefix>-${{ github.event_name }}-${{ github.event.pull_request.number || github.sha }}
    cancel-in-progress: ${{ github.event_name == 'pull_request' }}

Bidirectional by construction
-----------------------------
The recurring failure in this repository is the one-directional check: it
compares A against B and never B against A, so drift in the direction things
actually change slips past while the check prints OK. An exception list keyed
only on "is this workflow allowed?" has that shape — the entry outlives the
reason and is there to launder the next regression.

So every exception records the reason, and both directions are errors:

    tree -> exceptions   a workflow that can drop a push run with no entry.
    exceptions -> tree   an entry whose workflow is gone, or which no longer
                         has the shape it excuses.

Non-vacuity
-----------
A gate that can pass while inspecting nothing is worse than no gate. Three
guards, all printed:

* the root comes from `git rev-parse` via `gate_toolkit.repo_root`, never from
  this file's location, and is verified against sentinel paths;
* the walk must reach a plausible number of workflows, and must still find
  push-triggered workflows that declare a concurrency group — a scan that
  matches none means the parse broke, not that the tree is clean;
* `--self-test` runs the detector over known-bad and known-good workflow
  documents and asserts it separates them, and asserts the comparison itself
  rejects an empty scan.

Usage:
    python3 scripts/check_workflow_concurrency.py --self-test
    python3 scripts/check_workflow_concurrency.py
    python3 scripts/check_workflow_concurrency.py --list
    python3 scripts/check_workflow_concurrency.py --repo-root /path/to/checkout
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root

WORKFLOWS_REL = Path(".github/workflows")

#: Branches whose commits are graded by required status checks. A push to any
#: of these must survive the next push.
PROTECTED_BRANCHES = frozenset({"main", "develop"})

#: If the walk finds fewer workflow files than this, the glob is broken rather
#: than the tree small.
MIN_WORKFLOWS = 20

#: Expressions that evaluate false for a `push` event. Anything else in
#: `cancel-in-progress` is treated as "can cancel a push", including a bare
#: `true` and any expression this gate cannot read — guessing in the
#: permissive direction is how a gate becomes decoration.
SAFE_CANCEL_EXPRESSIONS = frozenset(
    {
        "${{ github.event_name == 'pull_request' }}",
        '${{ github.event_name == "pull_request" }}',
        "${{ github.event_name == 'pull_request' || github.event_name == 'pull_request_target' }}",
    }
)

#: Context references that make a concurrency group unique to one commit, so
#: two pushes can never land in the same group and cancel each other.
PER_COMMIT_KEYS = ("github.sha", "github.run_id", "github.run_number", "github.event.head_commit.id")

#: workflow file -> why it is allowed to drop a push run. Shrink-only, and
#: verified in both directions: an entry whose workflow no longer has the shape
#: is a failure, not a harmless leftover.
EXCEPTIONS: dict[str, str] = {
    "deploy-docs.yml": (
        "GitHub Pages accepts one deployment at a time and the newest build is "
        "the only one anyone wants served. Publishing an older docs build over "
        "a newer one is the failure here, so a shared 'pages' group that drops "
        "superseded deploys is the correct behaviour, not a lost grade."
    ),
    "publish-images.yml": (
        "Deliberate, and the cost is recorded rather than hidden. A per-commit "
        "group would publish every commit's immutable sha- tag, but it would "
        "also let two multi-architecture runs (15 images x 2 architectures) "
        "race for the moving ':latest' and ':main' tags, and the older run "
        "could win. Serialising keeps the newest commit on the moving tags, at "
        "the cost of intermediate commits not getting a sha- tag. "
        "check_published_images.py, run daily by image-availability.yml, is "
        "what catches a moving tag that fell behind."
    ),
}


class GateError(RuntimeError):
    """Raised when the gate cannot trust its own inputs."""


def _as_mapping(value: object) -> dict:
    """`on:` is parsed by PyYAML as the boolean True, and may be a str or list."""
    if isinstance(value, dict):
        return value
    if isinstance(value, list):
        return dict.fromkeys(value)
    if isinstance(value, str):
        return {value: None}
    return {}


def triggers_on_protected_push(doc: dict) -> bool:
    """Can a push to a protected branch start this workflow?

    A `push:` block carrying only `tags:` is a release trigger — every tag is
    its own ref, so those runs never contend with each other.
    """
    on = _as_mapping(doc.get("on", doc.get(True)))
    if "push" not in on:
        return False
    push = _as_mapping(on.get("push"))
    branches = push.get("branches")
    if branches is None:
        # No branch filter: a tags-only trigger is not a branch trigger;
        # anything else fires on every branch, which includes the protected
        # ones.
        return "tags" not in push and "tags-ignore" not in push
    return any(b in PROTECTED_BRANCHES or b in ("**", "*") for b in branches)


def concurrency_of(doc: dict) -> tuple[str | None, object]:
    conc = doc.get("concurrency")
    if conc is None:
        return None, False
    if isinstance(conc, str):
        return conc, False
    return conc.get("group"), conc.get("cancel-in-progress", False)


def cancels_a_push(cancel: object) -> bool:
    """Would `cancel-in-progress` kill an in-flight run on a push event?"""
    if cancel is False or cancel is None:
        return False
    if cancel is True:
        return True
    text = " ".join(str(cancel).split())
    return text not in SAFE_CANCEL_EXPRESSIONS


def group_is_per_commit(group: str | None) -> bool:
    return bool(group) and any(key in group for key in PER_COMMIT_KEYS)


def diagnose(doc: dict) -> list[str]:
    """Ways this workflow can discard a push run. Empty means it cannot."""
    if not triggers_on_protected_push(doc):
        return []
    group, cancel = concurrency_of(doc)
    if group is None:
        # No group means no contention: every run stands on its own.
        return []
    problems = []
    if cancels_a_push(cancel):
        problems.append(f"cancel-in-progress is {cancel!r}, which is truthy for a push")
    if not group_is_per_commit(group):
        problems.append(f"group {group!r} is shared across commits, so a run still pending when the next push queues is cancelled")
    return problems


def scan(root: Path) -> tuple[dict[str, list[str]], int, int]:
    """(workflow -> problems, workflows read, push-triggered with a group)."""
    wf_dir = root / WORKFLOWS_REL
    files = sorted(list(wf_dir.glob("*.yml")) + list(wf_dir.glob("*.yaml")))
    findings: dict[str, list[str]] = {}
    with_group = 0
    for path in files:
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise GateError(f"{path.name} is not parseable YAML: {exc}") from exc
        if not isinstance(doc, dict):
            continue
        if triggers_on_protected_push(doc) and concurrency_of(doc)[0] is not None:
            with_group += 1
        problems = diagnose(doc)
        if problems:
            findings[path.name] = problems
    return findings, len(files), with_group


def compare(findings: dict[str, list[str]], exceptions: dict[str, str]) -> list[str]:
    """Both directions. Returns failure lines; empty means clean."""
    problems: list[str] = []
    for name, reasons in sorted(findings.items()):
        if name in exceptions:
            continue
        problems.append(f"DROPS A PUSH RUN   {name}")
        for reason in reasons:
            problems.append(f"                     - {reason}")
    for name in sorted(exceptions):
        if name not in findings:
            problems.append(
                f"STALE EXCEPTION    {name}: recorded as allowed to drop a push run, "
                "but it no longer can (or the workflow is gone) — drop the entry"
            )
    return problems


def self_test() -> int:
    """Prove the detector separates known-bad from known-good, both ways."""
    failures: list[str] = []

    shared_cancelling = {
        "on": {"push": {"branches": ["main"]}},
        "concurrency": {"group": "x-${{ github.ref }}", "cancel-in-progress": True},
    }
    shared_queueing = {
        "on": {"push": {"branches": ["main"]}},
        "concurrency": {"group": "x-${{ github.ref }}", "cancel-in-progress": False},
    }
    per_commit = {
        "on": {"push": {"branches": ["main"]}, "pull_request": None},
        "concurrency": {
            "group": "x-${{ github.event_name }}-${{ github.event.pull_request.number || github.sha }}",
            "cancel-in-progress": "${{ github.event_name == 'pull_request' }}",
        },
    }
    no_group = {"on": {"push": {"branches": ["main"]}}}
    pr_only = {
        "on": {"pull_request": None},
        "concurrency": {"group": "x-${{ github.ref }}", "cancel-in-progress": True},
    }
    tag_only = {
        "on": {"push": {"tags": ["v*"]}},
        "concurrency": {"group": "x-${{ github.ref }}", "cancel-in-progress": True},
    }
    unreadable_cancel = {
        "on": {"push": {"branches": ["main"]}},
        "concurrency": {
            "group": "x-${{ github.sha }}",
            "cancel-in-progress": "${{ inputs.something }}",
        },
    }

    cases = [
        ("cancelling shared group on main", shared_cancelling, True),
        # The one a `cancel-in-progress: false` fix leaves behind.
        ("non-cancelling but shared group on main", shared_queueing, True),
        ("per-commit group, PR-only cancellation", per_commit, False),
        ("no concurrency block at all", no_group, False),
        ("pull_request only", pr_only, False),
        ("tag push only", tag_only, False),
        # An expression the gate cannot evaluate must fail closed.
        ("unreadable cancel-in-progress expression", unreadable_cancel, True),
    ]
    for label, doc, should_flag in cases:
        flagged = bool(diagnose(doc))
        if flagged != should_flag:
            verb = "missed" if should_flag else "flagged"
            failures.append(f"detector {verb} {label}")

    # The shared-group case must be reported for the *sharing*, not only for
    # the cancel flag — otherwise flipping the flag would silence it.
    reasons = diagnose(shared_queueing)
    if not any("shared across commits" in r for r in reasons):
        failures.append("detector does not report a shared group when cancel-in-progress is false")

    # compare(), both directions.
    if not compare({"new.yml": ["x"]}, {}):
        failures.append("compare() passed an unexcused workflow that drops a push run")
    if not compare({}, {"gone.yml": "stale"}):
        failures.append("compare() passed an exception with no matching finding")
    if compare({"a.yml": ["x"]}, {"a.yml": "documented"}):
        failures.append("compare() failed a workflow with a recorded exception")

    if failures:
        print("self-test FAILED:")
        for line in failures:
            print(f"  - {line}")
        return 1

    print(
        f"self-test OK — detector separates {len(cases)} known cases, reports a shared "
        "group independently of cancel-in-progress, and compare() is bidirectional"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo-root", type=Path, default=None, help="the tree to inspect (default: git rev-parse)")
    parser.add_argument("--list", action="store_true", help="print every push-triggered workflow and its verdict")
    parser.add_argument("--self-test", action="store_true", help="prove the gate is not vacuous, then exit")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    root = (args.repo_root or repo_root()).resolve()
    wf_dir = root / WORKFLOWS_REL
    if not wf_dir.is_dir():
        print(f"FAIL: {wf_dir} does not exist — this is not a checkout of the repository")
        return 2

    try:
        findings, total, with_group = scan(root)
    except GateError as exc:
        print(f"FAIL: {exc}")
        return 2

    print(f"read {total} workflow file(s) under {wf_dir}")
    if total < MIN_WORKFLOWS:
        print(f"FAIL: only {total} workflow(s) found (expected >= {MIN_WORKFLOWS}); the walk is broken, not the tree small")
        return 2
    if with_group == 0:
        print("FAIL: no push-triggered workflow declares a concurrency group.")
        print("      Every one of them did when this gate was written, so the trigger")
        print("      parse broke rather than the tree becoming clean.")
        return 2
    print(f"{with_group} of them can be started by a push to {'/'.join(sorted(PROTECTED_BRANCHES))} and declare a concurrency group")

    if args.list:
        for path in sorted((root / WORKFLOWS_REL).glob("*.yml")):
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
            if not isinstance(doc, dict) or not triggers_on_protected_push(doc):
                continue
            group, cancel = concurrency_of(doc)
            verdict = "DROPS" if diagnose(doc) else "keeps"
            if path.name in EXCEPTIONS and diagnose(doc):
                verdict = "DROPS (excepted)"
            print(f"  {verdict:16s} {path.name:30s} cancel={cancel!r} group={group!r}")

    problems = compare(findings, EXCEPTIONS)
    if problems:
        print(f"\nFAIL: {len(problems)} problem(s).\n")
        for line in problems:
            print(f"  {line}")
        print(
            "\nA push to a protected branch must not be able to lose its run. Key the\n"
            "group per commit and cancel only pull-request runs:\n\n"
            "  concurrency:\n"
            "    group: <prefix>-${{ github.event_name }}-${{ github.event.pull_request.number || github.sha }}\n"
            "    cancel-in-progress: ${{ github.event_name == 'pull_request' }}\n\n"
            "If dropping the run is genuinely correct, add an entry to EXCEPTIONS\n"
            "saying why and what is lost."
        )
        return 1

    excused = len(EXCEPTIONS)
    print(f"OK — no workflow can discard a push to a protected branch ({excused} recorded exception(s), each with a reason)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
