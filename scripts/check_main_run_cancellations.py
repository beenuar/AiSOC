#!/usr/bin/env python3
"""A run on `main` that ends `cancelled` must be visible, not silently accepted.

Why this exists
---------------
`check_workflow_concurrency.py` is prevention: it reads the workflow files and
refuses a concurrency block that can discard a push. This is detection, and
the two answer different questions. A workflow can be shaped correctly and
still lose runs — a manual cancel, a runner-pool eviction, a `timeout-minutes`
kill, an org-level concurrency limit, or a concurrency block added by a future
change the static gate has not learned to read.

The reason detection is needed at all is that a cancellation is invisible by
construction:

* the run's conclusion is `cancelled`, not `failure`, so nothing goes red;
* a job whose `needs:` dependency was cancelled never starts, so it produces
  no check run at all — absent is quieter still;
* the commit page shows a green tick from whatever *did* report, beside a
  commit that was never graded.

Measured on this repository before the concurrency fix: of the last 1,000
push-triggered runs on `main`, 259 ended `cancelled`, and only 51% of the
required-check x commit pairs over the last 30 commits actually graded.

What it asserts
---------------
No push-triggered run on `main` created after `SINCE` ended `cancelled`,
except in workflows that record cancellation as a deliberate trade. Those are
not silently skipped: their counts are printed every run, so an exception that
starts costing more than it is worth is visible rather than forgotten.

Non-vacuity
-----------
"Found nothing" and "asked nothing" print the same word, so:

* the repository under inspection is resolved from the checkout's own `origin`
  remote, after sentinel files prove the checkout is this repository. Taking
  it from `GITHUB_REPOSITORY` alone would let the gate render a confident
  verdict about `beenuar/AiSOC` while standing in a directory holding nothing
  — the meta-gate probe that copies `scripts/` into an empty repository caught
  exactly that on the first draft of this file.
* the unwindowed fetch must return runs. Zero means the token, the repository
  or the API shape is wrong — that is a failure, not a clean repository.
* the window is reported separately from the fetch, and a window holding no
  runs yet says so loudly instead of rendering a verdict it did not earn.
* `--self-test` drives the classifier over a synthetic run list and asserts it
  separates cancelled from successful, honours the exception list, and refuses
  an empty fetch.

Usage:
    python3 scripts/check_main_run_cancellations.py --self-test
    GH_TOKEN=... python3 scripts/check_main_run_cancellations.py
    GH_TOKEN=... python3 scripts/check_main_run_cancellations.py --window-days 7
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from check_workflow_concurrency import EXCEPTIONS
from gate_toolkit import repo_root

BRANCH = "main"
API = "https://api.github.com"

#: Files that must exist for a directory to be this repository. Cheap
#: insurance against rendering a verdict about `beenuar/AiSOC` while standing
#: in a tree that is not it.
SENTINELS = (".github/workflows/ci.yml", "scripts/check_workflow_concurrency.py", "CHANGELOG.md")

#: Runs before this are the history the concurrency fix was measured against.
#: Grading them would make the gate permanently red for a condition that has
#: already been fixed, which teaches everyone to ignore it — the exact failure
#: this repository keeps relearning. Moving this date forward to silence a
#: finding is the one edit that makes the gate worthless.
SINCE = "2026-09-29T00:00:00Z"

#: Below this many runs in the unwindowed fetch, the query is broken rather
#: than the repository quiet.
MIN_RUNS_FETCHED = 20

#: How many runs to fetch. Comfortably more than a busy day.
FETCH_LIMIT = 300


class GateError(RuntimeError):
    """Raised when the gate cannot trust its own inputs."""


def resolve_repository(root: Path) -> str:
    """`owner/name`, from the checkout being inspected.

    Deliberately not `GITHUB_REPOSITORY` first: that is an ambient string, and
    a gate that trusts it will happily describe this repository's run history
    while pointed at a directory containing nothing.
    """
    missing = [s for s in SENTINELS if not (root / s).exists()]
    if missing:
        raise GateError(f"{root} does not look like the AiSOC repository (missing: {', '.join(missing)})")
    out = subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["git", "-C", str(root), "remote", "get-url", "origin"],
        capture_output=True,
        text=True,
        check=False,
    )
    url = out.stdout.strip()
    match = re.search(r"[:/]([^/:]+/[^/]+?)(?:\.git)?$", url) if url else None
    if match:
        return match.group(1)
    ambient = os.environ.get("GITHUB_REPOSITORY")
    if ambient:
        # Only reachable once the sentinels have already proved the tree, so
        # this is a detached checkout of the right repository, not a guess.
        return ambient
    raise GateError(f"{root} has no `origin` remote and GITHUB_REPOSITORY is unset")


def _get(url: str, token: str) -> dict:
    req = urllib.request.Request(  # noqa: S310 - fixed https host
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "aisoc-grading-integrity/1.0",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
        return json.loads(resp.read().decode("utf-8"))


def fetch_runs(repo: str, token: str, limit: int = FETCH_LIMIT) -> list[dict]:
    """Push-triggered runs on `main`, newest first."""
    runs: list[dict] = []
    page = 1
    while len(runs) < limit:
        url = f"{API}/repos/{repo}/actions/runs?branch={BRANCH}&event=push&per_page=100&page={page}"
        payload = _get(url, token)
        batch = payload.get("workflow_runs") or []
        if not batch:
            break
        runs.extend(batch)
        page += 1
    return runs[:limit]


def workflow_file(run: dict) -> str:
    return (run.get("path") or "").rsplit("/", 1)[-1]


def classify(runs: list[dict], since: datetime, exceptions: dict[str, str]) -> tuple[list[dict], dict[str, int], int]:
    """(unexcused cancellations, excused counts by workflow, runs in window)."""
    unexcused: list[dict] = []
    excused: dict[str, int] = {}
    in_window = 0
    for run in runs:
        created = run.get("created_at") or ""
        try:
            when = datetime.fromisoformat(created.replace("Z", "+00:00"))
        except ValueError:
            continue
        if when < since:
            continue
        in_window += 1
        if run.get("conclusion") != "cancelled":
            continue
        name = workflow_file(run)
        if name in exceptions:
            excused[name] = excused.get(name, 0) + 1
        else:
            unexcused.append(run)
    return unexcused, excused, in_window


def self_test() -> int:
    failures: list[str] = []
    since = datetime(2026, 1, 1, tzinfo=UTC)

    def run(path: str, concl: str, day: int = 2) -> dict:
        return {
            "path": f".github/workflows/{path}",
            "conclusion": concl,
            "created_at": f"2026-01-{day:02d}T00:00:00Z",
            "head_sha": "deadbeefcafe",
            "html_url": "https://example.invalid/run",
        }

    excepted = next(iter(EXCEPTIONS))

    unexcused, excused, in_window = classify(
        [
            run("ci.yml", "success"),
            run("ci.yml", "cancelled"),
            run(excepted, "cancelled"),
            # Before the window: history, deliberately not graded.
            run("ci.yml", "cancelled", day=1) | {"created_at": "2025-12-31T00:00:00Z"},
        ],
        since,
        EXCEPTIONS,
    )
    if len(unexcused) != 1:
        failures.append(f"classifier found {len(unexcused)} unexcused cancellations, expected 1")
    if excused.get(excepted) != 1:
        failures.append(f"classifier did not excuse the recorded exception {excepted}")
    if in_window != 3:
        failures.append(f"classifier counted {in_window} runs in window, expected 3")

    # A clean window must be reachable, or every assertion above is satisfied
    # by a function that always reports a problem.
    unexcused, _, in_window = classify([run("ci.yml", "success")], since, EXCEPTIONS)
    if unexcused or in_window != 1:
        failures.append("classifier reported a problem over a window with one successful run")

    # An empty fetch must not read as clean.
    if verdict_for(fetched=0, in_window=0, unexcused=[], excused={}) == 0:
        failures.append("an empty fetch was treated as a clean result")
    # A populated fetch with a young window is not a failure, but must not be
    # reported as a graded window either.
    if verdict_for(fetched=50, in_window=0, unexcused=[], excused={}) != 0:
        failures.append("a populated fetch with a young window was treated as a failure")
    if verdict_for(fetched=50, in_window=10, unexcused=[{"x": 1}], excused={}) == 0:
        failures.append("an unexcused cancellation in the window was treated as clean")

    if failures:
        print("self-test FAILED:")
        for line in failures:
            print(f"  - {line}")
        return 1
    print(
        "self-test OK — classifier separates cancelled from successful, honours the "
        f"{len(EXCEPTIONS)} recorded exception(s), ignores runs before the window, and "
        "an empty fetch is not a pass"
    )
    return 0


def verdict_for(*, fetched: int, in_window: int, unexcused: list, excused: dict) -> int:
    """The exit code, factored out so the self-test can drive it directly."""
    del excused  # counted and printed, never a failure on its own
    if fetched < MIN_RUNS_FETCHED:
        return 2
    if unexcused:
        return 1
    if in_window == 0:
        return 0
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--self-test", action="store_true", help="prove the gate is not vacuous, then exit")
    parser.add_argument("--repo-root", type=Path, default=None, help="the checkout to inspect (default: git rev-parse)")
    parser.add_argument(
        "--window-days",
        type=int,
        default=None,
        help="grade only the last N days instead of everything since SINCE",
    )
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    root = (args.repo_root or repo_root()).resolve()
    try:
        repo = resolve_repository(root)
    except GateError as exc:
        print(f"FAIL: {exc}")
        return 2

    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not token:
        # Refusing is the point. A gate that shrugs at a missing credential is
        # a gate that reports OK on every run once the credential expires.
        print("FAIL: no GH_TOKEN/GITHUB_TOKEN in the environment — this gate can only")
        print("      be answered by the Actions API, and skipping would report a clean")
        print("      result about runs it never read.")
        return 2

    since = datetime.fromisoformat(SINCE.replace("Z", "+00:00"))
    if args.window_days is not None:
        since = max(since, datetime.now(UTC) - timedelta(days=args.window_days))

    try:
        runs = fetch_runs(repo, token)
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError) as exc:
        print(f"FAIL: could not read the Actions API for {repo}: {exc}")
        return 2

    unexcused, excused, in_window = classify(runs, since, EXCEPTIONS)

    print(f"checkout         {root}")
    print(f"repository       {repo}")
    print(f"branch           {BRANCH} (push-triggered runs only)")
    print(f"fetched          {len(runs)} run(s)")
    print(f"graded window    created at or after {since.isoformat()} — {in_window} run(s)")

    if len(runs) < MIN_RUNS_FETCHED:
        print(f"\nFAIL: only {len(runs)} run(s) came back (expected >= {MIN_RUNS_FETCHED}).")
        print("      The query, the token scope or the repository is wrong; an empty")
        print("      answer is not a quiet repository.")
        return 2

    if excused:
        print("\nrecorded exceptions — cancelled, and deliberately so:")
        for name, count in sorted(excused.items()):
            print(f"  {name}: {count} cancelled run(s)")
            print(f"      {EXCEPTIONS[name].split('.')[0].strip()}.")

    if unexcused:
        print(f"\nFAIL: {len(unexcused)} run(s) on {BRANCH} ended `cancelled`.\n")
        for run in unexcused:
            print(f"  {run.get('created_at')}  {workflow_file(run):28s} {(run.get('head_sha') or '')[:8]}")
            print(f"      {run.get('html_url')}")
        print(
            "\nA cancelled run on a protected branch is a commit nothing graded, and it\n"
            "reports `cancelled` rather than `failure`, so nothing else will say so.\n"
            "Find out why it was cancelled. If a concurrency group did it,\n"
            "scripts/check_workflow_concurrency.py explains the shape and the fix. If\n"
            "the cancellation is correct, record it in that gate's EXCEPTIONS with the\n"
            "reason and what is lost."
        )
        return 1

    if in_window == 0:
        print(
            f"\nNOTICE: no push-triggered run on {BRANCH} has been created since "
            f"{since.isoformat()} yet.\n"
            f"        The API answered with {len(runs)} run(s), so the query works — the\n"
            "        window is simply young. Nothing has been graded clean here."
        )
        return 0

    print(f"\nOK — {in_window} run(s) on {BRANCH} in the window, none cancelled outside the recorded exceptions")
    return 0


if __name__ == "__main__":
    sys.exit(main())
