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
No push-triggered run on `main` within the window it can actually read ended
`cancelled`, except in workflows that record cancellation as a deliberate
trade. Those are not silently skipped: their counts are printed every run, so
an exception that starts costing more than it is worth is visible rather than
forgotten.

The window is roughly a day, and that is a hard limit rather than a setting
---------------------------------------------------------------------------
About sixty workflows run on every push here, and the Actions API refuses any
result past offset 1,000 for this query, so the deepest fetch available
reaches about 20 hours. The operational consequence belongs in the output
rather than in a comment: **a cancelled run has to be noticed and re-run
within about a day, or it ages out of this gate's view entirely** and the
report goes green because the evidence scrolled past.

That is also the defect this file carried. It printed `SINCE` — a date about
five weeks back — as its "graded window" while fetching 300 runs, which at
this push rate is under nine hours: a claim overstated by roughly 100x, in a
gate written to catch precisely the shape of a passing condition that is not
the property it claims. The findings were always right; the stated coverage
was not. The window is now derived from the oldest run actually returned,
`SINCE` is reported as a floor the fetch did or did not reach, and the
horizon is printed every run.

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
* a populated fetch none of whose runs carries a readable `created_at` is an
  unknown, not an empty window: with no window there is nothing to report a
  cancellation against, so it fails rather than reporting clean.
* the window is reported separately from the fetch, and a window holding no
  runs yet says so loudly instead of rendering a verdict it did not earn.
* `--self-test` drives the classifier over a synthetic run list and asserts it
  separates cancelled from successful, honours the exception list, refuses an
  empty fetch and an undateable one, and reports the window it graded in both
  directions — a floor it reached and a floor it could not.

Usage:
    python3 scripts/check_main_run_cancellations.py --self-test
    GH_TOKEN=... python3 scripts/check_main_run_cancellations.py
    GH_TOKEN=... python3 scripts/check_main_run_cancellations.py --window-days 7
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import urllib.error
from datetime import UTC, datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from check_required_check_substance import api_get
from check_workflow_concurrency import EXCEPTIONS
from gate_toolkit import repo_root

BRANCH = "main"
API = "https://api.github.com"

#: Files that must exist for a directory to be this repository. Cheap
#: insurance against rendering a verdict about `beenuar/AiSOC` while standing
#: in a tree that is not it.
SENTINELS = (".github/workflows/ci.yml", "scripts/check_workflow_concurrency.py", "CHANGELOG.md")

#: The oldest run this gate is willing to grade, as a declared floor rather
#: than a description of what it reads. Two separate things are true of it
#: and collapsing them is what made the old output misleading:
#:
#: 1. Runs before this are the history the concurrency fix was measured
#:    against. Grading them would make the gate permanently red for a
#:    condition that has already been fixed, which teaches everyone to ignore
#:    it — the exact failure this repository keeps relearning. **Moving this
#:    date forward to silence a finding is the one edit that makes the gate
#:    worthless.** That has not changed and is not what the next paragraph
#:    is about.
#:
#: 2. It is currently **not reachable**, and no setting here can make it so.
#:    About sixty workflows run on every push, and the Actions API refuses
#:    any result past offset 1,000 (see `FETCH_LIMIT`), so the deepest fetch
#:    available reaches roughly a day — measured at 20.6 hours on
#:    2026-11-05. The floor is therefore about 37 days behind the deepest
#:    thing the gate can see.
#:
#: It is kept rather than deleted because it is the only thing that states
#: which runs are deliberately out of scope, and because the relationship is
#: not permanent: if push volume fell, 1,000 runs would reach past it and the
#: floor would start binding again. What changed is that the gate now
#: *reports* whether it reached the floor instead of printing it as though it
#: had. A floor that silently did nothing was the defect; a floor that says
#: it could not be reached is a fact an operator can act on.
SINCE = "2026-09-29T00:00:00Z"

#: Below this many runs in the unwindowed fetch, the query is broken rather
#: than the repository quiet.
MIN_RUNS_FETCHED = 20

#: 1,000 is not a number anyone chose. It is GitHub's hard ceiling for this
#: endpoint, found by paging until the answer came back empty: at
#: `per_page=100` page 11 returns zero runs, and at `per_page=50` page 21
#: returns zero — the same boundary from two different page sizes, so the cap
#: is on the result *offset* and no paging strategy gets past it. The
#: response keeps reporting `total_count: 2500`, which is why this looks like
#: a setting and is not.
#:
#: Raised from 300 once the backlog in reach was measured at zero: over the
#: full 1,000 runs there were 3 cancelled runs, all `publish-images.yml`,
#: which is already in `EXCEPTIONS` with a written justification. Widening
#: therefore bought depth without importing a red board, which is the only
#: moment it is safe to do.
FETCH_LIMIT = 1000


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
    """One Actions API read, with the sibling gate's retry policy.

    This used to be a single-attempt copy of the same request. The two gates
    run in the same workflow against the same API, so whatever makes one of
    them unreadable makes the other unreadable at the same moment — and only
    one of them rode it out. Reusing the reader rather than restating it also
    means a rate limit is waited on here too, which is the condition a merge
    burst produces and the one that was costing manual re-runs.

    The prefix check stays at this layer as well as inside: urllib honours
    `file://`, so a URL that did not come from `API` is refused rather than
    fetched, and that refusal should not depend on an import.
    """
    if not url.startswith(API + "/"):
        raise GateError(f"refusing to call a non-GitHub URL: {url}")
    return api_get(url, token)


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


def run_created(run: dict) -> datetime | None:
    """The run's creation time, or None if it does not carry a readable one."""
    try:
        return datetime.fromisoformat((run.get("created_at") or "").replace("Z", "+00:00"))
    except ValueError:
        return None


def fetched_span(runs: list[dict]) -> tuple[datetime | None, datetime | None, int]:
    """(oldest, newest, how many runs carried a readable timestamp).

    This is the window the gate actually graded, and the whole reason it is
    computed: the fetch is bounded by a run count, not by a date, so the date
    it reaches is an *output* of the fetch and cannot be known in advance.
    Printing a configured date instead is how the old output claimed five
    weeks of coverage over an eight-hour read.

    The count is returned separately because a populated fetch none of whose
    runs can be dated is an unknown, not an empty window, and the two must
    not reach the same verdict.
    """
    stamps = [t for t in (run_created(r) for r in runs) if t is not None]
    if not stamps:
        return None, None, 0
    return min(stamps), max(stamps), len(stamps)


def humanise(delta: timedelta) -> str:
    """A duration an operator reads without doing arithmetic."""
    hours = delta.total_seconds() / 3600
    if hours < 48:
        return f"{hours:.1f} hours"
    return f"{hours / 24:.1f} days"


def classify(runs: list[dict], since: datetime, exceptions: dict[str, str]) -> tuple[list[dict], dict[str, int], int]:
    """(unexcused cancellations, excused counts by workflow, runs in window)."""
    unexcused: list[dict] = []
    excused: dict[str, int] = {}
    in_window = 0
    for run in runs:
        when = run_created(run)
        if when is None:
            # Counted as undateable by `fetched_span`, which is what refuses
            # the verdict. Skipping silently here would be the unknown-as-pass
            # this gate exists to refuse.
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


def window_lines(
    *,
    oldest: datetime | None,
    newest: datetime | None,
    dated: int,
    fetched: int,
    floor: datetime,
    floor_label: str,
    limit: int = FETCH_LIMIT,
    now: datetime | None = None,
) -> list[str]:
    """What the gate graded, what it was asked to grade, and the gap.

    Three facts, kept apart on purpose, because merging any two of them is
    what produced a line reading `created at or after <five weeks ago>` about
    a fetch eight hours deep:

    ``graded window``  derived from the oldest run that actually came back.
    ``declared floor`` the configured intent, and whether the fetch reached it.
    ``horizon``        how long a cancellation stays visible here, which is an
                       operational deadline rather than a footnote: past it
                       the run is not findable by this gate at all.

    Two durations are printed because they answer different questions and
    differ by however long the branch has been idle. The *span* is how much
    time `limit` runs covers, which is the rate that decides how fast a
    finding ages out; the *reach* is how far back the gate can currently see,
    which is what an operator asking "would last night's cancellation still
    show up here?" actually needs.
    """
    if oldest is None or newest is None:
        return [
            f"fetched          {fetched} run(s)",
            "graded window    UNKNOWN — not one run carried a readable `created_at`",
        ]

    now = now or datetime.now(UTC)
    at_ceiling = " — the API's hard ceiling for this query" if fetched >= limit else ""
    span = humanise(newest - oldest)
    lines = [
        f"fetched          {fetched} run(s){at_ceiling}",
        f"graded window    {oldest.isoformat()} → {newest.isoformat()}",
        f"                 {dated} run(s) spanning {span}, reaching {humanise(now - oldest)} back from",
        f"                 now — derived from the oldest run the API returned, not from {floor_label}",
    ]

    if oldest <= floor:
        lines.append(f"declared floor   {floor.isoformat()} — reached")
    else:
        short_by = humanise(oldest - floor)
        lines += [
            f"declared floor   {floor.isoformat()} ({humanise(newest - floor)} back) — NOT REACHED",
            f"                 short by {short_by}. About sixty workflows run on every push",
            f"                 here, so {limit} runs is about a day. Raising the limit cannot",
            f"                 close this: {limit} is the most the endpoint will return for",
            "                 this query at any page size.",
        ]

    lines += [
        f"horizon          {limit} newer runs push a cancellation out of view, which at this",
        f"                 rate is about {span}. One not noticed and re-run inside that is",
        "                 not findable here afterwards — the gate will read clean because",
        "                 the evidence scrolled past, not because anything was fixed.",
    ]
    return lines


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
    if verdict_for(fetched=0, dated=0, in_window=0, unexcused=[], excused={}) == 0:
        failures.append("an empty fetch was treated as a clean result")
    # A populated fetch with a young window is not a failure, but must not be
    # reported as a graded window either.
    if verdict_for(fetched=50, dated=50, in_window=0, unexcused=[], excused={}) != 0:
        failures.append("a populated fetch with a young window was treated as a failure")
    if verdict_for(fetched=50, dated=50, in_window=10, unexcused=[{"x": 1}], excused={}) == 0:
        failures.append("an unexcused cancellation in the window was treated as clean")
    # A populated fetch the gate could not date is an unknown, not a quiet
    # repository: with no window there is nothing to report a cancellation
    # against, so reporting clean would be inventing the evidence.
    if verdict_for(fetched=50, dated=0, in_window=0, unexcused=[], excused={}) == 0:
        failures.append("a fetch with no readable timestamp was treated as a clean result")

    # ── the reported window describes the fetch, not the configuration ──
    #
    # Both directions, because the defect this replaced was one-directional
    # by construction: the gate printed a constant, so it was right whenever
    # the constant happened to be right and silent about the rest.
    now = datetime.now(UTC)
    shallow_oldest, shallow_newest = now - timedelta(hours=9), now
    shallow = window_lines(
        oldest=shallow_oldest,
        newest=shallow_newest,
        dated=300,
        fetched=300,
        floor=since,
        floor_label="SINCE",
    )
    shallow_text = "\n".join(shallow)
    if shallow_oldest.isoformat() not in shallow_text:
        failures.append("the reported window does not name the oldest run fetched")
    if "9.0 hours" not in shallow_text:
        failures.append("the reported window does not state how deep the fetch reached")
    if "NOT REACHED" not in shallow_text:
        failures.append("a floor the fetch could not reach was not reported as unreachable")
    if "horizon" not in shallow_text:
        failures.append("the operational horizon is not stated")

    # The paired direction. Always printing NOT REACHED would satisfy every
    # assertion above, and would be a different lie about the same window.
    # Reaching a floor means fetching back *past* it, so the oldest run has
    # to be older than the floor — not the other way round, which is the
    # mistake this fixture made on the first pass.
    deep_text = "\n".join(
        window_lines(
            oldest=now - timedelta(hours=24),
            newest=now,
            dated=300,
            fetched=300,
            floor=now - timedelta(hours=20),
            floor_label="SINCE",
        )
    )
    if "NOT REACHED" in deep_text or "reached" not in deep_text:
        failures.append("a floor the fetch did reach was still reported as unreachable")

    # An undateable fetch must not render a window it does not have.
    blind_text = "\n".join(window_lines(oldest=None, newest=None, dated=0, fetched=50, floor=since, floor_label="SINCE"))
    if "UNKNOWN" not in blind_text:
        failures.append("a fetch with no readable timestamp still rendered a window")

    if failures:
        print("self-test FAILED:")
        for line in failures:
            print(f"  - {line}")
        return 1
    print(
        "self-test OK — classifier separates cancelled from successful, honours the "
        f"{len(EXCEPTIONS)} recorded exception(s), ignores runs before the window, "
        "neither an empty fetch nor an undateable one is a pass, and the reported "
        "window is derived from the oldest run fetched in both directions "
        "(reachable floor and unreachable floor)"
    )
    return 0


def verdict_for(*, fetched: int, dated: int, in_window: int, unexcused: list, excused: dict) -> int:
    """The exit code, factored out so the self-test can drive it directly.

    `dated` is separate from `fetched` because a populated answer the gate
    understood none of is an unknown, and this gate's whole value is refusing
    to report clean on absent evidence. Before it existed, runs with an
    unparseable `created_at` were dropped inside `classify`, leaving
    `in_window == 0`, which was read as a young window and exited 0.
    """
    del excused  # counted and printed, never a failure on its own
    if fetched < MIN_RUNS_FETCHED:
        return 2
    if dated == 0:
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
    floor_label = "SINCE"
    if args.window_days is not None:
        narrowed = datetime.now(UTC) - timedelta(days=args.window_days)
        if narrowed > since:
            since, floor_label = narrowed, f"--window-days {args.window_days}"

    try:
        runs = fetch_runs(repo, token)
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError) as exc:
        print(f"FAIL: could not read the Actions API for {repo}: {exc}")
        return 2

    unexcused, excused, in_window = classify(runs, since, EXCEPTIONS)
    oldest, newest, dated = fetched_span(runs)

    print(f"checkout         {root}")
    print(f"repository       {repo}")
    print(f"branch           {BRANCH} (push-triggered runs only)")
    for line in window_lines(
        oldest=oldest,
        newest=newest,
        dated=dated,
        fetched=len(runs),
        floor=since,
        floor_label=floor_label,
    ):
        print(line)

    verdict = verdict_for(fetched=len(runs), dated=dated, in_window=in_window, unexcused=unexcused, excused=excused)

    if len(runs) < MIN_RUNS_FETCHED:
        print(f"\nFAIL: only {len(runs)} run(s) came back (expected >= {MIN_RUNS_FETCHED}).")
        print("      The query, the token scope or the repository is wrong; an empty")
        print("      answer is not a quiet repository.")
        return verdict

    # Written against the timestamps rather than `dated`, though
    # `fetched_span` makes the two equivalent: this is the condition "the
    # window could not be established", and saying it directly is both what
    # the message claims and what proves to the type checker that the
    # subtraction below has two operands.
    if oldest is None or newest is None:
        print(f"\nFAIL: {len(runs)} run(s) came back and not one carried a readable")
        print("      `created_at`, so the graded window cannot be established at all.")
        print("      That is an unknown, not a clean repository: with no window there")
        print("      is nothing to report a cancellation against.")
        return verdict

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
            "reason and what is lost.\n"
            "\n"
            "Re-run it rather than excusing it, and do so now: the window above is the\n"
            "whole of what this gate can see, so once the run ages out of it this\n"
            "report goes green with nothing fixed."
        )
        return verdict

    if in_window == 0:
        print(
            f"\nNOTICE: no push-triggered run on {BRANCH} has been created since "
            f"{since.isoformat()} yet.\n"
            f"        The API answered with {len(runs)} run(s), so the query works — the\n"
            "        window is simply young. Nothing has been graded clean here."
        )
        return verdict

    print(
        f"\nOK — {in_window} run(s) on {BRANCH} over the {humanise(newest - oldest)} the API would "
        "return,\n     none cancelled outside the recorded exceptions"
    )
    return verdict


if __name__ == "__main__":
    sys.exit(main())
