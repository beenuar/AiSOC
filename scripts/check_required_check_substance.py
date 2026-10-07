#!/usr/bin/env python3
"""A required check that reports success must have executed its assertions.

Why this exists
---------------
`check_workflow_concurrency.py` refuses a workflow shape that can discard a
push. `check_main_run_cancellations.py` reports a run on `main` that ended
`cancelled`. Both are about a grading that never happened *and said so*. This
is the third shape, and it is the quiet one: the run happens, the check is
green, and the work inside it was skipped.

Measured on this repository before the fix (`--window-runs 100`, successful
push runs on `main`, 2026-09-25 to 2026-09-29 — the numbers this gate prints):

    Backup → destroy → restore (Postgres via S3)   26 of 100 substantive
    docker compose up — full stack                 73 of 100 substantive
    the other 20 required checks                  100 of 100 substantive

On the runs it skipped, the disaster-recovery gate executed one step —
"Nothing under the disaster-recovery path changed" — and reported the same
green tick as the ones that seeded, backed up, destroyed and restored a
database. `docs/audit/CLAIM_TO_GATE_MATRIX.md` cites that check as the GATED
evidence for backup encryption, so the tick was standing in for a rehearsal
that had mostly not been held.

What it asserts
---------------
For every context in `.github/required-checks.json`, over successful
push-triggered runs on the protected branch created at or after
`enforced_from`:

* the job that produces the check was not itself skipped; and
* no step that *could* have run, ran not; and
* no step reported `failure` while the job stayed green (`continue-on-error`).

"Could have run" is decided by `scripts/gh_expr.py`, which evaluates each
step's `if:` under a simulated push to the protected branch:

    TRUE     unconditional — must have run
    UNKNOWN  gated on something only the run knows (a change filter, a job
             output) — on a protected-branch push it must be observed to have
             run, because this is precisely the class a path filter switches
             off
    FALSE    cannot run on such a push (`failure()`, `cancelled()`,
             `github.event_name == 'pull_request'`) — correctly skipped, and
             not reported

That is the "genuinely not applicable" versus "skipped where it should have
run" distinction, and it is *derived from the workflow* rather than asserted
by a list of step names. A list would go stale on the first rename, silently,
which is the same class of defect as the one being fixed.

Non-vacuity
-----------
Every way this gate could report OK without doing its work is closed, because
that is the failure mode it exists to catch:

* the repository is resolved from the checkout's own `origin` remote after
  sentinel files prove the checkout is this repository — a gate that trusts
  `GITHUB_REPOSITORY` will describe `beenuar/AiSOC` while standing in an
  empty directory;
* a missing token is a failure, not a skip;
* every context in the manifest must resolve to a real job in a real workflow
  file. A renamed job fails here rather than being silently dropped;
* the manifest must match branch protection whenever the token can read it
  (`administration: read`, which `GITHUB_TOKEN` cannot be granted). When it
  cannot, the gate says so in its output rather than implying it verified;
* the unwindowed fetch must return runs for each workflow;
* a context with zero runs in the enforced window is tolerated only while the
  window is younger than `YOUNG_WINDOW_DAYS`; after that, silence is a
  failure, because a required check that stopped running is the loudest
  version of this same defect;
* `--self-test` drives the classifier over a synthetic pre-fix job and asserts
  it fails, then over the post-fix shape and asserts it passes.

Usage:
    python3 scripts/check_required_check_substance.py --self-test
    python3 scripts/check_required_check_substance.py --static
    GH_TOKEN=... python3 scripts/check_required_check_substance.py
    GH_TOKEN=... python3 scripts/check_required_check_substance.py \
        --enforced-from 2026-01-01T00:00:00Z --window-runs 80
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from itertools import product
from pathlib import Path
from typing import Any

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root
from gh_expr import UNKNOWN, Unknown, evaluate, string_literals, unresolved_references

API = "https://api.github.com"

MANIFEST = Path(".github/required-checks.json")

#: Files that must exist for a directory to be this repository.
SENTINELS = (".github/workflows/ci.yml", "scripts/gate_toolkit.py", "CHANGELOG.md")

#: How many successful push runs per workflow to read. A busy day on this
#: repository is 25-40 pushes, so this is roughly two days.
DEFAULT_WINDOW_RUNS = 80

#: One page. See `fetch_successful_push_runs` — this endpoint is not stable
#: across pages, so a deeper window would be an arbitrary subset reported
#: under a confident denominator.
MAX_RELIABLE_WINDOW = 100

#: A read that comes back stale usually clears in seconds. One that keeps
#: coming back stale does not, and is refused rather than graded.
FETCH_ATTEMPTS = 3
FETCH_RETRY_SECONDS = 6

#: Commits on the branch used as the freshness oracle, and how many of the
#: newest runs (of any conclusion — a failed run for a recent commit proves
#: the read is fresh) may be searched for one of them. On a push event the
#: run executing this gate is itself in the list, which is the proof working
#: as intended, not a loophole: a stale snapshot would not contain it.
FRESHNESS_COMMITS = 30
FRESH_HEAD_RUNS = 5

#: Below this many runs in the unwindowed fetch for a workflow, the query is
#: broken rather than the workflow quiet.
MIN_RUNS_FETCHED = 3

#: A freshly moved `enforced_from` legitimately has no runs behind it yet.
#: After this many days it does not, and silence becomes a failure.
YOUNG_WINDOW_DAYS = 7

#: Step conclusions the API reports.
RAN = {"success"}
DID_NOT_RUN = {"skipped"}


class GateError(RuntimeError):
    """Raised when the gate cannot trust its own inputs."""


# ── The three answers a step's `if:` can give on a protected-branch push ────

MUST_RUN = "must-run"  # if: absent, or statically true
CONDITIONAL = "conditional"  # depends on a runtime output — must be observed
NOT_APPLICABLE = "not-applicable"  # statically false on such a push


@dataclass
class StepSpec:
    name: str
    verdict: str
    condition: str | None
    #: True when the step's whole body is `echo`/`printf` into
    #: `$GITHUB_STEP_SUMMARY`. Such a step asserts nothing and cannot fail, so
    #: it is not evidence that the check did its work — it is usually the
    #: announcement that the check did *not*.
    notice: bool = False


@dataclass
class JobSpec:
    context: str
    workflow_path: Path
    workflow_file: str
    job_id: str
    steps: list[StepSpec]
    triggers_on_push_to_branch: bool
    #: True when the push trigger carries a `paths:` filter, so a commit can
    #: legitimately produce no run and the freshness oracle does not apply.
    push_is_path_filtered: bool = False
    #: Every path through the job, split into complete runs and reduced ones.
    paths: PathAnalysis = field(default_factory=lambda: PathAnalysis([], {}, undecidable=False))
    #: `continue-on-error` steps no later blocking step reads the outcome of.
    #: Each is a way this check can report success over a failure, and one the
    #: Actions REST API cannot show — see `unguarded_soft_failures`.
    unguarded_soft_failures: list[str] = field(default_factory=list)

    @property
    def achievable(self) -> list[frozenset[str]]:
        return self.paths.maximal

    @property
    def undecidable(self) -> bool:
        return self.paths.undecidable

    @property
    def graded_steps(self) -> list[StepSpec]:
        return [s for s in self.steps if s.verdict in {MUST_RUN, CONDITIONAL}]

    @property
    def assertive_steps(self) -> list[StepSpec]:
        return [s for s in self.graded_steps if not s.notice]

    @property
    def must_run_steps(self) -> list[StepSpec]:
        return [s for s in self.steps if s.verdict == MUST_RUN]


@dataclass
class RunVerdict:
    run_id: int
    created_at: str
    head_sha: str
    html_url: str
    substantive: bool
    job_conclusion: str
    missing: list[str] = field(default_factory=list)
    soft_failed: list[str] = field(default_factory=list)
    enforced: bool = True


# ── Repository / manifest ──────────────────────────────────────────────────


def resolve_repository(root: Path) -> str:
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
        return ambient
    raise GateError(f"{root} has no `origin` remote and GITHUB_REPOSITORY is unset")


def load_manifest(root: Path) -> dict:
    path = root / MANIFEST
    if not path.exists():
        raise GateError(f"{MANIFEST} is missing — the gate has no list of required checks to grade")
    doc = json.loads(path.read_text(encoding="utf-8"))
    for key in ("branch", "enforced_from", "contexts"):
        if key not in doc:
            raise GateError(f"{MANIFEST} has no `{key}`")
    if not doc["contexts"]:
        raise GateError(f"{MANIFEST} lists no contexts — an empty list would pass every assertion below")
    return doc


# ── Workflow parsing ───────────────────────────────────────────────────────


def _matrix_names(job: dict) -> list[dict[str, str]]:
    """Every `matrix.*` substitution a job's rendered name can take."""
    matrix = ((job.get("strategy") or {}).get("matrix")) or {}
    axes = {k: v for k, v in matrix.items() if isinstance(v, list) and k not in {"include", "exclude"}}
    combos: list[dict[str, str]] = [{}]
    for key, values in axes.items():
        combos = [{**combo, key: str(value)} for combo in combos for value in values]
    for extra in matrix.get("include") or []:
        if isinstance(extra, dict):
            combos.append({k: str(v) for k, v in extra.items()})
    return combos


_MATRIX_REF = re.compile(r"\$\{\{\s*matrix\.([A-Za-z_][A-Za-z0-9_-]*)\s*\}\}")


def _render_names(job_id: str, job: dict) -> list[str]:
    raw = job.get("name") or job_id
    if "${{" not in str(raw):
        return [str(raw)]
    names = []
    for combo in _matrix_names(job):

        def substitute(match: re.Match[str], axes: dict[str, str] = combo) -> str:
            return axes.get(match.group(1), match.group(0))

        names.append(_MATRIX_REF.sub(substitute, str(raw)))
    return names or [str(raw)]


def _triggers_on_push_to(workflow: dict, branch: str) -> tuple[bool, bool]:
    """(runs on a push to `branch`, that trigger carries a `paths:` filter)."""
    on = workflow.get("on") or workflow.get(True) or {}
    if isinstance(on, str):
        return on == "push", False
    if isinstance(on, list):
        return "push" in on, False
    push = on.get("push")
    if push is None:
        return False, False
    if not isinstance(push, dict):
        return True, False
    filtered = bool(push.get("paths") or push.get("paths-ignore"))
    branches = push.get("branches")
    if branches is None:
        return True, filtered
    matched = any(b == branch or (b.endswith("**") and branch.startswith(b[:-2])) for b in branches)
    return matched, filtered


_SUMMARY_REDIRECT = r'>>?\s*"?\$\{?GITHUB_STEP_SUMMARY\}?"?'

#: A line of shell that only announces something, matched against the *masked*
#: form produced by `_mask_literals` below. Anything else in a `run:` body — a
#: command, a pipe, a substitution — means the step can fail, and a step that
#: can fail is evidence the check did work.
_ANNOUNCE_LINE = re.compile(
    rf"""^(?:
          \{{
        | \}}         (?:\s* {_SUMMARY_REDIRECT} )?
        | (?:echo|printf|:) (?:\s* (?:""|''|-[neE]+) )*  (?:\s* {_SUMMARY_REDIRECT} )?
        )\s*$""",
    re.VERBOSE,
)

#: Inside a double-quoted span these keep their meaning and can run something;
#: everything else is text. An unescaped backtick or `$(` is a command
#: substitution, and a step containing one is not an announcement.
_LIVE_IN_DQUOTES = re.compile(r"\$\(|`|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?")


def _mask_literals(line: str) -> str:
    """Replace quoted *text* with empty quotes, keeping anything still live.

    The skip notices in this tree echo prose containing backticks, arrows and
    shell metacharacters — all inert inside quotes. Scanning the raw line for
    metacharacters therefore rejects a step that only prints, which is how
    the first draft of this gate measured every one of those runs as having
    done its work. Masking the prose and keeping variable references and
    command substitutions leaves exactly the part that can execute.
    """
    out: list[str] = []
    index = 0
    length = len(line)
    while index < length:
        char = line[index]
        if char == "'":
            end = line.find("'", index + 1)
            if end == -1:
                return line  # unbalanced: refuse to simplify it
            out.append("''")
            index = end + 1
        elif char == '"':
            index += 1
            inner: list[str] = []
            while index < length and line[index] != '"':
                if line[index] == "\\" and index + 1 < length:
                    index += 2  # escaped: literal text, drop it
                    continue
                live = _LIVE_IN_DQUOTES.match(line, index)
                if live:
                    inner.append(live.group())
                    index = live.end()
                    continue
                index += 1
            if index >= length:
                return line  # unbalanced
            index += 1
            out.append('"' + "".join(inner) + '"')
        else:
            out.append(char)
            index += 1
    return "".join(out)


def is_notice(step: dict) -> bool:
    """True when the step's whole body is an announcement into the job summary.

    Derived from the step body, never from its name. Both skip notices in
    this repository are a brace group of `echo`s redirected into
    `$GITHUB_STEP_SUMMARY`; neither can fail, so neither is evidence that the
    required check graded anything. Recognising them structurally is what
    lets the run-history half tell an either/or branch (two ways of booting a
    stack, both real work) from a skip path (an announcement instead of work)
    without a list of step names that goes stale on the first rename.
    """
    if step.get("uses") or not isinstance(step.get("run"), str):
        return False
    body = str(step["run"])
    if "GITHUB_STEP_SUMMARY" not in body:
        return False
    for raw in body.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if not _ANNOUNCE_LINE.match(_mask_literals(line)):
            return False
    return True


def unguarded_soft_failures(job: dict) -> list[str]:
    """`continue-on-error` steps whose failure nothing turns back into one.

    This is the one part of the gate's claim the run history cannot answer.
    The Actions REST API reports each step's *conclusion*, and
    `continue-on-error` is defined as the thing that rewrites a failed step's
    conclusion to `success` — the pre-rewrite `outcome` is available to
    workflow expressions and is not in the payload. Measured: across 4,660
    jobs read from 80 push runs on `main`, the API reported `failure` on zero
    steps inside a green job, in a tree that does run three
    `continue-on-error` steps. So a gate that only watched run history would
    be silent about this case while appearing to cover it.

    It is decidable from the workflow, though. A `continue-on-error` step is
    safe exactly when some later step that is *not* itself
    `continue-on-error` reads its `outcome` and fails the job. A step with no
    `id` can never be read, so it can never be guarded.
    """
    steps = [s for s in (job.get("steps") or []) if isinstance(s, dict)]
    soft = {
        str(s.get("id") or ""): str(s.get("name") or s.get("uses") or f"step #{index}")
        for index, s in enumerate(steps)
        if s.get("continue-on-error") is True
    }
    if not soft:
        return []
    guarded: set[str] = set()
    for step in steps:
        if step.get("continue-on-error") is True:
            continue
        condition = str(step.get("if") or "")
        for step_id in soft:
            if step_id and re.search(rf"steps\.{re.escape(step_id)}\.(outcome|conclusion)\b", condition):
                guarded.add(step_id)
    return sorted(name for step_id, name in soft.items() if step_id not in guarded)


def resolve_job_outputs(workflow: dict) -> dict[str, str]:
    """`needs.<job>.outputs.<name>` bindings this gate can settle statically.

    A job output is declared as an expression, so when that expression holds
    on a push to a protected branch — `${{ github.event_name == 'push' || ...
    }}` — every step gated on it runs, provably, without reading the shell
    that computes the other half.

    This is what lets the exemption be written once, where the filter's value
    is decided, instead of repeated on every consumer. Outputs whose
    expression depends on a step's output stay unresolved, which leaves the
    consumer conditional and therefore something the run history must
    confirm.
    """
    bindings: dict[str, str] = {}
    for job_id, job in (workflow.get("jobs") or {}).items():
        if not isinstance(job, dict):
            continue
        for name, expression in (job.get("outputs") or {}).items():
            value = evaluate(expression)
            if value is True:
                bindings[f"needs.{job_id}.outputs.{name}"] = "true"
            elif value is False:
                bindings[f"needs.{job_id}.outputs.{name}"] = "false"
    return bindings


def classify_job_steps(job: dict, context: dict[str, Any] | None = None) -> list[StepSpec]:
    specs: list[StepSpec] = []
    job_if = job.get("if")
    job_gate = evaluate(job_if, context)
    for index, step in enumerate(job.get("steps") or []):
        if not isinstance(step, dict):
            continue
        name = step.get("name") or step.get("uses") or f"step #{index}"
        condition = step.get("if")
        verdict_value = evaluate(condition, context)
        # A job-level `if` that cannot hold on such a push makes every step
        # inside it not-applicable, whatever the step says.
        if job_gate is False:
            verdict_value = False
        elif isinstance(job_gate, Unknown) and verdict_value is True:
            verdict_value = UNKNOWN

        if verdict_value is True:
            verdict = MUST_RUN
        elif verdict_value is False:
            verdict = NOT_APPLICABLE
        else:
            verdict = CONDITIONAL
        specs.append(
            StepSpec(
                name=str(name),
                verdict=verdict,
                condition=None if condition is None else str(condition),
                notice=is_notice(step),
            )
        )
    return specs


#: A value standing for "anything the author did not write a branch for".
_OTHER = "\x00other"

#: Above this many reference/value combinations the job is not enumerated.
#: Reached by no job in this repository; if one ever is, the gate refuses
#: rather than reporting a verdict it did not compute.
MAX_ASSIGNMENTS = 4096


@dataclass
class PathAnalysis:
    #: The complete runs: sets of assertive steps, none a reduced form of another.
    maximal: list[frozenset[str]]
    #: The reduced runs, mapped to the filter values that reach them. These are
    #: the paths on which the check reports a verdict having done strictly less
    #: work than the same job does on another path.
    reduced: dict[frozenset[str], dict[str, str]]
    undecidable: bool


def achievable_work_sets(job: dict, specs: list[StepSpec], context: dict[str, Any] | None = None) -> PathAnalysis:
    """Every set of assertive steps this job can execute on a protected-branch push.

    A job's conditions read a handful of run-time references. Binding each to
    every value the author compared it against (plus "something else")
    enumerates the paths through the job that were actually written, and
    evaluating the conditions under each binding says which steps that path
    runs.

    This is what separates the two cases that look identical in a green tick:

    * `Boot stack (pull-by-default)` and `Boot stack (force rebuild)` are two
      achievable sets, neither a subset of the other. Either is a complete
      run.
    * the skip path executes *no* assertive step at all, so its set is the
      empty set — a strict subset of every other achievable set, and that
      relation is what both halves of this gate report.
    """
    raw_steps = [s for s in (job.get("steps") or []) if isinstance(s, dict)]
    conditions = [s.get("if") for s in raw_steps]
    refs: set[str] = set()
    values: set[str] = set()
    for condition in conditions:
        refs |= unresolved_references(condition, context)
        values |= string_literals(condition)
    if not refs:
        return PathAnalysis([], {}, undecidable=False)
    candidates = sorted(values | {_OTHER})
    if len(candidates) ** len(refs) > MAX_ASSIGNMENTS:
        return PathAnalysis([], {}, undecidable=True)

    ordered_refs = sorted(refs)
    paths: dict[frozenset[str], dict[str, str]] = {}
    for combo in product(candidates, repeat=len(ordered_refs)):
        assignment = {ref: ("" if value == _OTHER else value) for ref, value in zip(ordered_refs, combo, strict=True)}
        binding = {**(context or {}), **assignment}
        running: set[str] = set()
        for spec, condition in zip(specs, conditions, strict=True):
            if spec.verdict == NOT_APPLICABLE or spec.notice:
                continue
            if evaluate(condition, binding) is True:
                running.add(spec.name)
        paths.setdefault(frozenset(running), assignment)

    sets = set(paths)
    # A path that is a strict subset of another is not a complete run: the
    # same job, reachable through the same conditions, does strictly less.
    # Those are what the static half refuses and what the run-history half
    # reports having happened.
    reduced = {s: paths[s] for s in sets if any(s < other for other in sets)}
    maximal = [s for s in sets if s not in reduced]
    if maximal == [frozenset()]:
        # Every path through this job runs no assertive step at all. Either
        # the job really does nothing, or this analysis misread it. Both are
        # worth refusing; neither is worth reporting OK about.
        return PathAnalysis([], {}, undecidable=True)
    return PathAnalysis(sorted(maximal, key=lambda s: (-len(s), sorted(s))), reduced, undecidable=False)


def index_workflows(root: Path, contexts: list[str], branch: str) -> tuple[dict[str, JobSpec], list[str]]:
    """Map each required-check context to the job that produces it."""
    found: dict[str, JobSpec] = {}
    wanted = set(contexts)
    for path in sorted((root / ".github" / "workflows").glob("*.y*ml")):
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:  # pragma: no cover - a broken workflow is CI's problem
            raise GateError(f"{path} is not valid YAML: {exc}") from exc
        if not isinstance(doc, dict):
            continue
        on_push, path_filtered = _triggers_on_push_to(doc, branch)
        context = resolve_job_outputs(doc)
        for job_id, job in (doc.get("jobs") or {}).items():
            if not isinstance(job, dict):
                continue
            for name in _render_names(job_id, job):
                if name not in wanted or name in found:
                    continue
                steps = classify_job_steps(job, context)
                found[name] = JobSpec(
                    context=name,
                    workflow_path=path.relative_to(root),
                    workflow_file=path.name,
                    job_id=job_id,
                    steps=steps,
                    triggers_on_push_to_branch=on_push,
                    push_is_path_filtered=path_filtered,
                    paths=achievable_work_sets(job, steps, context),
                    unguarded_soft_failures=unguarded_soft_failures(job),
                )
    unresolved = [c for c in contexts if c not in found]
    return found, unresolved


# ── Actions API ────────────────────────────────────────────────────────────


def _get(url: str, token: str) -> dict:
    if not url.startswith(API + "/"):
        raise GateError(f"refusing to call a non-GitHub URL: {url}")
    req = urllib.request.Request(  # noqa: S310 - refused above unless it is the GitHub API
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "aisoc-grading-integrity/1.0",
        },
    )
    with urllib.request.urlopen(req, timeout=45) as resp:  # noqa: S310
        return json.loads(resp.read().decode("utf-8"))


def fetch_protection_contexts(repo: str, token: str, branch: str) -> list[str] | None:
    """Branch protection's own list, or None when the token cannot read it.

    `GITHUB_TOKEN` cannot be granted `administration: read`, so in CI this is
    always None and the manifest is the only source. Returning None rather
    than raising keeps that honest: the caller prints that it could not
    verify instead of implying it did.
    """
    try:
        payload = _get(f"{API}/repos/{repo}/branches/{urllib.parse.quote(branch)}/protection", token)
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError):
        return None
    checks = (payload.get("required_status_checks") or {}).get("contexts")
    return list(checks) if checks is not None else None


def _runs_url(repo: str, workflow_file: str, branch: str, per_page: int, page: int) -> str:
    # No `status=` filter, deliberately. The freshness check in
    # `fetch_successful_push_runs` needs every push run: filtering to
    # successes here made a workflow that genuinely failed on 30+ consecutive
    # commits indistinguishable from a stale API snapshot, and for this
    # gate's own workflow that was self-locking — each run failing the
    # staleness check was itself the reason no recent successful run existed.
    return (
        f"{API}/repos/{repo}/actions/workflows/{urllib.parse.quote(workflow_file)}/runs"
        f"?branch={urllib.parse.quote(branch)}&event=push"
        f"&per_page={per_page}&page={page}"
    )


def fetch_recent_commits(repo: str, token: str, branch: str, count: int) -> set[str]:
    """The newest commit SHAs on the branch, as an oracle for "is this read fresh".

    A different endpoint on purpose. The runs endpoint can serve a stale but
    *internally consistent* snapshot — measured here, it returned 100 runs
    ending on 11 August while `main` had run that morning, and a second read
    of the same endpoint agreed with it, so no amount of cross-checking the
    runs list against itself could tell. The commit list is a separate
    surface with separate caching, and it answers the question the runs list
    cannot be trusted on.
    """
    payload = _get(f"{API}/repos/{repo}/commits?sha={urllib.parse.quote(branch)}&per_page={count}", token)
    return {str(commit["sha"]) for commit in payload if isinstance(commit, dict)}


def fetch_successful_push_runs(
    repo: str, token: str, workflow_file: str, branch: str, limit: int, recent_shas: set[str] | None
) -> list[dict]:
    """The newest `limit` successful push runs — ordered here, not trusted from the API.

    One page, deliberately. This endpoint does not reliably return runs
    newest-first *across* pages and it repeats rows: measured on this
    repository, asking for 250 returned 250 rows holding **157 unique run
    ids**, with the first row of page 1 five weeks older than the newest run
    that existed. Taking a prefix of the concatenated pages graded an
    arbitrary window and silently omitted the most recent runs — which, for a
    gate whose whole subject is a check quietly not covering something, would
    have been the same defect wearing this gate's own badge.

    A deeper window is therefore not available from here, and saying so is
    better than publishing a denominator that does not describe what was
    read. Within one page the order is not assumed either: rows are sorted by
    `created_at`, and freshness is checked against `recent_shas` — the branch's
    own commit list, from a different endpoint — because the failure that
    actually happened was a stale snapshot that any second read of *this*
    endpoint agreed with.

    Freshness is asserted against push runs of *any* conclusion, and only the
    successful ones are graded. A failed or in-progress run for a recent
    commit proves the endpoint is serving current data just as well as a
    successful one does; requiring a recent *success* conflated two
    conditions that need opposite responses — a stale snapshot (refuse to
    grade) and a workflow that genuinely failed on the last 30+ commits
    (grade the successes the page does hold, and let the shrunken window
    speak for itself). The second condition is real: a merge burst outran
    `ci.yml` on 2026-10-05, this gate then failed every push for it, and
    because the gate's own workflow thereby stopped producing successful push
    runs, the staleness check locked against *itself* — no future run could
    ever have passed.
    """
    if limit > MAX_RELIABLE_WINDOW:
        raise GateError(
            f"a window of {limit} runs cannot be read reliably: this endpoint is only stable "
            f"for its first page, so {MAX_RELIABLE_WINDOW} is the deepest honest window. "
            "Grading more would mean grading an arbitrary subset while printing a confident "
            "denominator."
        )
    last_seen = "nothing"
    for attempt in range(FETCH_ATTEMPTS):
        batch = _get(_runs_url(repo, workflow_file, branch, MAX_RELIABLE_WINDOW, 1), token).get("workflow_runs") or []
        seen = {int(run["id"]): run for run in batch}
        ordered = sorted(seen.values(), key=lambda r: str(r.get("created_at") or ""), reverse=True)
        successes = [run for run in ordered if str(run.get("conclusion")) == "success"][:limit]
        if recent_shas is None or not ordered:
            # Freshness cannot be asserted for a workflow that does not run on
            # every push; the caller says so in its output rather than
            # implying a check it did not make.
            return successes
        if any(str(run.get("head_sha")) in recent_shas for run in ordered[:FRESH_HEAD_RUNS]):
            return successes
        last_seen = str(ordered[0].get("created_at"))
        if attempt < FETCH_ATTEMPTS - 1:
            time.sleep(FETCH_RETRY_SECONDS)

    raise GateError(
        f"{workflow_file}: the newest push run of any conclusion this endpoint returned is {last_seen}, "
        f"and it is for none of the last {len(recent_shas or ())} commits on {branch} — which this "
        "workflow runs on every one of. After "
        f"{FETCH_ATTEMPTS} attempts that is a stale read, not a quiet workflow, and grading it "
        "would report a confident proportion over a window that stops weeks short of now."
    )


def fetch_run_jobs(repo: str, token: str, run_id: int) -> list[dict]:
    jobs: list[dict] = []
    page = 1
    while page <= 5:
        payload = _get(f"{API}/repos/{repo}/actions/runs/{run_id}/jobs?per_page=100&page={page}", token)
        batch = payload.get("jobs") or []
        if not batch:
            break
        jobs.extend(batch)
        if len(batch) < 100:
            break
        page += 1
    return jobs


# ── Grading ────────────────────────────────────────────────────────────────


def grade_run(spec: JobSpec, job: dict | None) -> tuple[bool, str, list[str], list[str]]:
    """(substantive, job_conclusion, assertions that did not run, steps that soft-failed).

    A run is substantive when it executed a *complete* path through the job.
    Complete means the set of assertive steps it ran is one of the maximal
    achievable sets — not a strict subset of one. That is the distinction the
    gate is for: two different complete paths (pull the images, or build them)
    both pass, while the path that announces it is doing nothing does not.
    """
    if job is None:
        return False, "absent", [s.name for s in spec.assertive_steps], []
    conclusion = str(job.get("conclusion") or "unknown")
    if conclusion == "skipped":
        # GitHub counts a skipped check as satisfying branch protection, so
        # this is the same defect with the conditional moved up a level.
        return False, conclusion, [s.name for s in spec.assertive_steps], []

    by_name: dict[str, str] = {}
    for step in job.get("steps") or []:
        by_name.setdefault(str(step.get("name") or ""), str(step.get("conclusion") or "unknown"))
    if not by_name:
        return False, conclusion, [s.name for s in spec.assertive_steps], []

    # Only steps this run actually had. A workflow edited since then leaves
    # names in the spec that the run never knew, and those say nothing about
    # it.
    known = [s for s in spec.steps if s.name in by_name]
    ran = {s.name for s in known if by_name[s.name] in RAN}
    soft_failed = [s.name for s in known if by_name[s.name] == "failure"]

    # An unconditional step that did not run is always wrong: no assignment of
    # any filter could have switched it off.
    missing = [s.name for s in known if s.verdict == MUST_RUN and by_name[s.name] in DID_NOT_RUN]

    observed = frozenset(s.name for s in known if not s.notice and s.name in ran)
    achievable = [frozenset(a & by_name.keys()) for a in spec.achievable]
    dominating = [a for a in achievable if observed < a]
    if dominating:
        fuller = max(dominating, key=len)
        missing.extend(sorted(fuller - observed))

    return (not missing and not soft_failed), conclusion, sorted(set(missing)), soft_failed


def audit_context(
    spec: JobSpec,
    runs: list[dict],
    jobs_by_run: dict[int, list[dict]],
    enforced_from: datetime,
) -> list[RunVerdict]:
    verdicts: list[RunVerdict] = []
    for run in runs:
        run_id = int(run["id"])
        job = next((j for j in jobs_by_run.get(run_id, []) if str(j.get("name")) == spec.context), None)
        substantive, conclusion, missing, soft = grade_run(spec, job)
        created = str(run.get("created_at") or "")
        try:
            when = datetime.fromisoformat(created.replace("Z", "+00:00"))
        except ValueError:
            when = datetime.fromtimestamp(0, UTC)
        verdicts.append(
            RunVerdict(
                run_id=run_id,
                created_at=created,
                head_sha=str(run.get("head_sha") or "")[:8],
                html_url=str(run.get("html_url") or ""),
                substantive=substantive,
                job_conclusion=conclusion,
                missing=missing,
                soft_failed=soft,
                enforced=when >= enforced_from,
            )
        )
    return verdicts


# ── Static half ────────────────────────────────────────────────────────────


def static_findings(specs: dict[str, JobSpec]) -> list[tuple[str, PathAnalysis]]:
    """Required checks that can still reach a reduced run on a protected-branch push.

    This is prevention, and it needs no API. It asserts the same relation the
    run-history half detects, one step earlier: *no path through the job may
    do strictly less than another path through the same job.*

    The distinction that matters, and the reason this is not simply "no
    conditional steps":

    * two ways of booting the same stack — pull the published images, or
      build them from source — are both complete. Neither set of steps is a
      subset of the other, so neither is reduced, and both pass.
    * announcing that nothing was checked is not. That path runs no assertive
      step at all, so its set is empty and strictly inside every other, and
      it fails here.

    The fix that clears it is to spell the push exemption into the expression
    — on the job output that carries the filter, or on each step that reads
    it — because that is a property this evaluator can *prove*, rather than a
    promise made inside a shell script it cannot read.
    """
    out: list[tuple[str, PathAnalysis]] = []
    for name, spec in sorted(specs.items()):
        if not spec.triggers_on_push_to_branch:
            continue
        if spec.paths.reduced:
            out.append((name, spec.paths))
    return out


# ── Self-test ──────────────────────────────────────────────────────────────

_SKIP_NOTICE = '{\n  echo "## not exercised"\n  echo ""\n} >> "$GITHUB_STEP_SUMMARY"\n'

_PRE_FIX_JOB = {
    "name": "Backup → destroy → restore (Postgres via S3)",
    "steps": [
        {"uses": "actions/checkout@v7"},
        {
            "name": "Nothing under the disaster-recovery path changed",
            "if": "needs.changes.outputs.backup != 'true'",
            "run": _SKIP_NOTICE,
        },
        {"name": "Seed data", "if": "needs.changes.outputs.backup == 'true'", "run": "psql -c 'insert'"},
        {"name": "Backup", "if": "needs.changes.outputs.backup == 'true'", "run": "./scripts/backup.sh"},
        {
            "name": "Restore and assert integrity",
            "if": "needs.changes.outputs.backup == 'true'",
            "run": "./scripts/restore.sh",
        },
        {"name": "Forensics", "if": "failure()", "run": "docker logs s3"},
    ],
}

_POST_FIX_JOB = {
    "name": "Backup → destroy → restore (Postgres via S3)",
    "steps": [
        {"uses": "actions/checkout@v7"},
        {
            "name": "Nothing under the disaster-recovery path changed",
            "if": "needs.changes.outputs.backup != 'true' && github.event_name != 'push'",
            "run": _SKIP_NOTICE,
        },
        {
            "name": "Seed data",
            "if": "needs.changes.outputs.backup == 'true' || github.event_name == 'push'",
            "run": "psql -c 'insert'",
        },
        {
            "name": "Backup",
            "if": "needs.changes.outputs.backup == 'true' || github.event_name == 'push'",
            "run": "./scripts/backup.sh",
        },
        {
            "name": "Restore and assert integrity",
            "if": "needs.changes.outputs.backup == 'true' || github.event_name == 'push'",
            "run": "./scripts/restore.sh",
        },
        {"name": "Forensics", "if": "failure()", "run": "docker logs s3"},
    ],
}

#: Two complete paths, neither a subset of the other. This is the shape the
#: first draft of this gate got wrong: it required every conditional step to
#: run, so a run that legitimately built from source instead of pulling was
#: reported as having skipped its work.
_EITHER_OR_JOB = {
    "name": "docker compose up — full stack",
    "steps": [
        {"name": "Checkout", "uses": "actions/checkout@v7"},
        {"name": "Nothing to smoke", "if": "steps.relevant.outputs.run != 'true'", "run": _SKIP_NOTICE},
        {"name": "Validate compose file", "if": "steps.relevant.outputs.run == 'true'", "run": "docker compose config"},
        {
            "name": "Pre-pull published images",
            "if": "steps.relevant.outputs.run == 'true' && steps.rebuild.outputs.rebuild != 'true'",
            "run": "docker compose pull",
        },
        {
            "name": "Boot stack (pull-by-default)",
            "if": "steps.relevant.outputs.run == 'true' && steps.rebuild.outputs.rebuild != 'true'",
            "run": "docker compose up -d",
        },
        {
            "name": "Boot stack (force rebuild)",
            "if": "steps.relevant.outputs.run == 'true' && steps.rebuild.outputs.rebuild == 'true'",
            "run": "docker compose up -d --build",
        },
        {"name": "Wait for stack to converge", "if": "steps.relevant.outputs.run == 'true'", "run": "curl ..."},
    ],
}


def _spec_from(job: dict, context: str) -> JobSpec:
    steps = classify_job_steps(job)
    return JobSpec(
        context=context,
        workflow_path=Path("synthetic.yml"),
        workflow_file="synthetic.yml",
        job_id="synthetic",
        steps=steps,
        triggers_on_push_to_branch=True,
        paths=achievable_work_sets(job, steps),
    )


def _api_job(context: str, conclusions: dict[str, str], conclusion: str = "success") -> dict:
    return {
        "name": context,
        "conclusion": conclusion,
        "steps": [{"name": n, "conclusion": c} for n, c in conclusions.items()],
    }


def self_test() -> int:  # noqa: PLR0912, PLR0915 - a flat list of assertions reads better than helpers
    failures: list[str] = []
    context = "Backup → destroy → restore (Postgres via S3)"

    # ── the expression evaluator draws the three-way distinction ──────────
    pre = _spec_from(_PRE_FIX_JOB, context)
    verdicts = {s.name: s.verdict for s in pre.steps}
    if verdicts.get("Forensics") != NOT_APPLICABLE:
        failures.append("`if: failure()` was not classified as not-applicable on a successful push")
    if verdicts.get("Seed data") != CONDITIONAL:
        failures.append("a change-filtered step was not classified as conditional")
    if verdicts.get("actions/checkout@v7") != MUST_RUN:
        failures.append("an unconditional step was not classified as must-run")

    # A step gated on an earlier step having failed is a failure handler, not
    # a change filter. In a run that succeeded it correctly did not run — and
    # the `continue-on-error` case it could hide behind is caught separately,
    # by the soft-failure assertion further down.
    handlers = _spec_from(
        {
            "steps": [
                {"name": "Enforce staged policy", "if": "steps.audit.outcome == 'failure'"},
                {"name": "Report a needed job that failed", "if": "needs.build.result == 'failure'"},
                {"name": "Still change-gated", "if": "steps.audit.outputs.found == 'true'"},
            ]
        },
        "synthetic",
    )
    handler_verdicts = {s.name: s.verdict for s in handlers.steps}
    if handler_verdicts.get("Enforce staged policy") != NOT_APPLICABLE:
        failures.append("a step gated on an earlier step's failure was treated as a change filter")
    if handler_verdicts.get("Report a needed job that failed") != NOT_APPLICABLE:
        failures.append("a step gated on a needed job's failure was treated as a change filter")
    if handler_verdicts.get("Still change-gated") != CONDITIONAL:
        failures.append("a step gated on a step *output* stopped being treated as a change filter")

    # ── the pre-fix history is a failure ──────────────────────────────────
    pre_fix_api = _api_job(
        context,
        {
            "actions/checkout@v7": "success",
            "Nothing under the disaster-recovery path changed": "success",
            "Seed data": "skipped",
            "Backup": "skipped",
            "Restore and assert integrity": "skipped",
            "Forensics": "skipped",
        },
    )
    substantive, _, missing, _ = grade_run(pre, pre_fix_api)
    if substantive:
        failures.append("a run that skipped every assertion was graded substantive")
    if "Seed data" not in missing:
        failures.append("the skipped assertion was not named in the finding")
    if "Forensics" in missing:
        failures.append("a correctly-skipped `if: failure()` step was reported as a finding")

    # ── the post-fix shape passes, and only because it really ran ─────────
    post = _spec_from(_POST_FIX_JOB, context)
    post_verdicts = {s.name: s.verdict for s in post.steps}
    if post_verdicts.get("Seed data") != MUST_RUN:
        failures.append("the push exemption did not make the assertion unconditional on a push")
    if post_verdicts.get("Nothing under the disaster-recovery path changed") != NOT_APPLICABLE:
        failures.append("the post-fix skip notice is still reachable on a push")
    post_fix_api = _api_job(
        context,
        {
            "actions/checkout@v7": "success",
            "Nothing under the disaster-recovery path changed": "skipped",
            "Seed data": "success",
            "Backup": "success",
            "Restore and assert integrity": "success",
            "Forensics": "skipped",
        },
    )
    substantive, _, missing, _ = grade_run(post, post_fix_api)
    if not substantive:
        failures.append(f"a run that executed every assertion was not graded substantive: {missing}")

    # A clean verdict must be *reachable* or every assertion above is
    # satisfied by a function that always reports a problem.
    substantive, _, _, _ = grade_run(post, _api_job(context, {"Seed data": "skipped"}))
    if substantive:
        failures.append("a post-fix run that skipped an assertion was graded substantive")

    # ── two complete paths, neither a reduced version of the other ────────
    either_or = _spec_from(_EITHER_OR_JOB, "docker compose up — full stack")
    pulled = _api_job(
        "docker compose up — full stack",
        {
            "Checkout": "success",
            "Nothing to smoke": "skipped",
            "Validate compose file": "success",
            "Pre-pull published images": "success",
            "Boot stack (pull-by-default)": "success",
            "Boot stack (force rebuild)": "skipped",
            "Wait for stack to converge": "success",
        },
    )
    built = _api_job(
        "docker compose up — full stack",
        {
            "Checkout": "success",
            "Nothing to smoke": "skipped",
            "Validate compose file": "success",
            "Pre-pull published images": "skipped",
            "Boot stack (pull-by-default)": "skipped",
            "Boot stack (force rebuild)": "success",
            "Wait for stack to converge": "success",
        },
    )
    skipped_entirely = _api_job(
        "docker compose up — full stack",
        {
            "Checkout": "success",
            "Nothing to smoke": "success",
            "Validate compose file": "skipped",
            "Pre-pull published images": "skipped",
            "Boot stack (pull-by-default)": "skipped",
            "Boot stack (force rebuild)": "skipped",
            "Wait for stack to converge": "skipped",
        },
    )
    for label, api_job in (("pulled", pulled), ("built from source", built)):
        substantive, _, missing, _ = grade_run(either_or, api_job)
        if not substantive:
            failures.append(f"a complete run that {label} was reported as having skipped work: {missing}")
    substantive, _, missing, _ = grade_run(either_or, skipped_entirely)
    if substantive:
        failures.append("a run that announced it was doing nothing was graded substantive")
    if "Boot stack (pull-by-default)" not in missing:
        failures.append(f"the skip path's finding did not name the work it stood in for: {missing}")

    # ── a notice is recognised by what it does, not what it is called ─────
    prose = (
        "{\n"
        '  echo "## Compose smoke — not exercised"\n'
        '  echo ""\n'
        '  echo "This pull request changes nothing under \\`services/\\`, \\`apps/web/\\`,"\n'
        '  echo "the lockfiles, or this workflow, so the stack was not booted."\n'
        '} >> "$GITHUB_STEP_SUMMARY"\n'
    )
    if not is_notice({"name": "renamed since", "run": prose}):
        failures.append("a skip notice whose prose contains shell metacharacters was read as work")
    if is_notice({"name": "Show runner capacity", "run": 'uname -a >> "$GITHUB_STEP_SUMMARY"\n'}):
        failures.append("a step running a command into the job summary was read as a notice")
    if is_notice({"name": "smuggled", "run": 'echo "$(scripts/thing.py)" >> "$GITHUB_STEP_SUMMARY"\n'}):
        failures.append("a command substitution inside an echo was read as a notice")
    if is_notice({"name": "an action", "uses": "actions/checkout@v7"}):
        failures.append("a step that runs an action was read as a notice")
    if is_notice({"name": "writes elsewhere", "run": 'echo "x" >> "$GITHUB_ENV"\n'}):
        failures.append("a step writing somewhere other than the job summary was read as a notice")

    # ── continue-on-error is not a pass ───────────────────────────────────
    #
    # Two halves, because the API only shows one of them. If it ever does
    # report a failed step inside a green job, the run-history path says so:
    _, _, _, soft = grade_run(post, _api_job(context, {"Seed data": "failure"}, conclusion="success"))
    if "Seed data" not in soft:
        failures.append("a step that failed under continue-on-error inside a green job was not reported")
    # …and because it does not, the shape is refused statically instead.
    audit_job = {
        "steps": [
            {"id": "audit-pnpm", "name": "Audit pnpm dependencies", "continue-on-error": True, "run": "pnpm audit"},
            {"name": "Enforce staged policy", "if": "steps.audit-pnpm.outcome == 'failure'", "run": "exit 1"},
        ]
    }
    if unguarded_soft_failures(audit_job):
        failures.append("a continue-on-error step with a blocking handler was reported as unguarded")
    del audit_job["steps"][1]
    if unguarded_soft_failures(audit_job) != ["Audit pnpm dependencies"]:
        failures.append("a continue-on-error step with no handler was not reported")
    if unguarded_soft_failures({"steps": [{"name": "unreferenceable", "continue-on-error": True, "run": "x"}]}) != ["unreferenceable"]:
        failures.append("a continue-on-error step with no id was treated as guarded")
    if unguarded_soft_failures(
        {
            "steps": [
                {"id": "a", "name": "soft", "continue-on-error": True, "run": "x"},
                {"name": "also soft", "if": "steps.a.outcome == 'failure'", "continue-on-error": True, "run": "y"},
            ]
        }
    ) != ["also soft", "soft"]:
        failures.append("a handler that is itself continue-on-error was treated as blocking")

    # ── a skipped job is not a pass ───────────────────────────────────────
    substantive, concl, _, _ = grade_run(post, _api_job(context, {}, conclusion="skipped"))
    if substantive or concl != "skipped":
        failures.append("a required check whose job was skipped entirely was treated as graded")

    # ── an absent job is not a pass ───────────────────────────────────────
    substantive, _, _, _ = grade_run(post, None)
    if substantive:
        failures.append("a run in which the required check's job never appeared was treated as graded")

    # ── the exemption can be written once, on the job output ──────────────
    workflow = {
        "jobs": {
            "changes": {
                "outputs": {
                    "backup": "${{ github.event_name == 'push' || steps.areas.outputs.backup }}",
                    "spine": "${{ steps.areas.outputs.spine }}",
                }
            }
        }
    }
    bindings = resolve_job_outputs(workflow)
    if bindings.get("needs.changes.outputs.backup") != "true":
        failures.append("a job output carrying the push exemption was not resolved on a push")
    if "needs.changes.outputs.spine" in bindings:
        failures.append("a job output computed entirely in shell was resolved anyway")
    hoisted = classify_job_steps(
        {"steps": [{"name": "Seed data", "if": "needs.changes.outputs.backup == 'true'", "run": "psql"}]},
        bindings,
    )
    if hoisted[0].verdict != MUST_RUN:
        failures.append("a step gated on a push-exempt job output was not made unconditional")

    # ── the static half flags pre-fix and clears post-fix ─────────────────
    if not static_findings({context: pre}):
        failures.append("the static half did not flag the pre-fix job")
    if static_findings({context: post}):
        failures.append("the static half flagged the post-fix job")

    # An either/or — pull the images or build them — is two complete runs,
    # not a reduced one. The static half must pass it once the skip path is
    # closed, or the only way to satisfy this gate would be to delete every
    # alternative a workflow legitimately has.
    either_or_fixed = _spec_from(
        {
            "steps": [
                {
                    "name": "Nothing to smoke",
                    "if": "steps.relevant.outputs.run != 'true' && github.event_name != 'push'",
                    "run": _SKIP_NOTICE,
                },
                {
                    "name": "Boot stack (pull-by-default)",
                    "if": "(steps.relevant.outputs.run == 'true' || github.event_name == 'push')"
                    " && steps.rebuild.outputs.rebuild != 'true'",
                    "run": "docker compose up -d",
                },
                {
                    "name": "Boot stack (force rebuild)",
                    "if": "(steps.relevant.outputs.run == 'true' || github.event_name == 'push')"
                    " && steps.rebuild.outputs.rebuild == 'true'",
                    "run": "docker compose up -d --build",
                },
            ]
        },
        "either-or",
    )
    if static_findings({"either-or": either_or_fixed}):
        failures.append("the static half rejected two complete alternatives as a reduced run")
    if len(either_or_fixed.achievable) != 2:
        failures.append(f"an either/or was not read as two complete runs: {either_or_fixed.achievable}")

    # ── the verdict function refuses an empty read ────────────────────────
    if verdict_for(contexts_graded=0, findings=[], starved=[], unresolved=[]) == 0:
        failures.append("grading zero contexts was treated as a clean result")
    if verdict_for(contexts_graded=3, findings=[], starved=[], unresolved=["x"]) == 0:
        failures.append("a required check with no job in the tree was treated as clean")
    if verdict_for(contexts_graded=3, findings=[], starved=["x"], unresolved=[]) == 0:
        failures.append("a context starved of runs past the young window was treated as clean")
    if verdict_for(contexts_graded=3, findings=[], starved=[], unresolved=[]) != 0:
        failures.append("a genuinely clean audit could not report clean")

    # ── matrix names render, or eight required checks silently vanish ─────
    rendered = _render_names(
        "python-services-wave-2-test",
        {
            "name": "Python — Service unit tests wave 2 (${{ matrix.service }})",
            "strategy": {"matrix": {"service": ["actions", "ueba"]}},
        },
    )
    if rendered != ["Python — Service unit tests wave 2 (actions)", "Python — Service unit tests wave 2 (ueba)"]:
        failures.append(f"matrix job names did not render: {rendered}")

    if failures:
        print("self-test FAILED:")
        for line in failures:
            print(f"  - {line}")
        return 1
    print(
        "self-test OK — the classifier separates unconditional, change-gated and\n"
        "not-applicable steps; a run that skipped its assertions fails; a run that\n"
        "executed them passes; continue-on-error, a skipped job, an absent job, an\n"
        "empty read and an unresolved context are each refused."
    )
    return 0


def verdict_for(*, contexts_graded: int, findings: list, starved: list, unresolved: list) -> int:
    """The exit code, factored out so the self-test can drive it directly."""
    if unresolved:
        return 2
    if contexts_graded == 0:
        return 2
    if starved:
        return 1
    if findings:
        return 1
    return 0


# ── A cache, so a measurement can be re-read rather than re-fetched ────────
#
# Reading 22 required checks over 80 runs each is ~1,800 API calls and takes
# about eight minutes. That is fine once and intolerable while iterating on
# the classifier, and re-running the *same* measurement is exactly how the
# pre-fix figures in this file's docstring were produced and can be checked.
#
# It is refused under CI: a gate that can be satisfied by a file on disk is a
# gate that can be satisfied by a stale file on disk.


def _cache_path(cache_dir: Path, repo: str, workflow_file: str, branch: str, limit: int) -> Path:
    safe = f"{repo}_{workflow_file}_{branch}_{limit}".replace("/", "_")
    return cache_dir / f"{safe}.json"


def load_or_fetch(
    cache_dir: Path | None,
    repo: str,
    token: str,
    workflow_file: str,
    branch: str,
    limit: int,
    recent_shas: set[str] | None,
) -> tuple[list[dict], dict[int, list[dict]]]:
    path = _cache_path(cache_dir, repo, workflow_file, branch, limit) if cache_dir else None
    if path and path.exists():
        doc = json.loads(path.read_text(encoding="utf-8"))
        return doc["runs"], {int(k): v for k, v in doc["jobs"].items()}
    runs = fetch_successful_push_runs(repo, token, workflow_file, branch, limit, recent_shas)
    jobs = {int(run["id"]): fetch_run_jobs(repo, token, int(run["id"])) for run in runs}
    if path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"runs": runs, "jobs": jobs}), encoding="utf-8")
    return runs, jobs


# ── main ───────────────────────────────────────────────────────────────────


def _print_soft_failures(specs: dict[str, JobSpec]) -> int:
    offenders = {name: spec.unguarded_soft_failures for name, spec in sorted(specs.items()) if spec.unguarded_soft_failures}
    if not offenders:
        return 0
    print(f"\nFAIL: {len(offenders)} required check(s) can report success over a failed step.\n")
    for name, steps in offenders.items():
        print(f"  {name}")
        for step in steps:
            print(f"      - {step}   continue-on-error, and nothing reads its outcome")
    print(
        "\nThe Actions API cannot see this: `continue-on-error` is defined as rewriting\n"
        "the step's conclusion to `success`, so the run history shows a clean job. Give\n"
        "the step an `id` and add a later blocking step that reads it:\n"
        "    if: steps.<id>.outcome == 'failure'\n"
        "or take `continue-on-error` off, if the step's failure should fail the check."
    )
    return 1


def _print_static(specs: dict[str, JobSpec]) -> int:
    findings = static_findings(specs)
    print(f"\nstatic half — {len(specs)} required check(s) read from the workflow tree")
    for name, spec in sorted(specs.items()):
        counts = {v: sum(1 for s in spec.steps if s.verdict == v) for v in (MUST_RUN, CONDITIONAL, NOT_APPLICABLE)}
        push = "push" if spec.triggers_on_push_to_branch else "no-push"
        print(
            f"  {name:62s} {spec.workflow_file:28s} {push:7s} "
            f"{counts[MUST_RUN]:3d} unconditional  {counts[CONDITIONAL]:3d} change-gated  "
            f"{counts[NOT_APPLICABLE]:3d} n/a-on-push"
        )
    if findings:
        print(f"\nFAIL: {len(findings)} required check(s) can still skip an assertion on a push to a protected branch.\n")
        for name, analysis in findings:
            fullest = max(analysis.maximal, key=len, default=frozenset())
            print(f"  {name}")
            for reduced, assignment in analysis.reduced.items():
                conditions = ", ".join(f"{ref} = {value or '<anything else>'!r}" for ref, value in assignment.items())
                print(f"      with {conditions}")
                print(f"      it runs {len(reduced)} assertive step(s) instead of {len(fullest)}; not run:")
                for step in sorted(fullest - reduced)[:8]:
                    print(f"        - {step}")
                if len(fullest - reduced) > 8:
                    print(f"        … and {len(fullest - reduced) - 8} more")
        print(
            "\nOn a pull request a path filter is correct: only the changed area needs\n"
            "grading. On a push to a protected branch it is not, because every commit\n"
            "that lands has to be graded by the check that is required of it.\n"
            "Spell the exemption into the condition so it can be proved here:\n"
            "    if: needs.<filter>.outputs.<area> == 'true' || github.event_name == 'push'\n"
            "and give the skip notice the matching exclusion:\n"
            "    if: needs.<filter>.outputs.<area> != 'true' && github.event_name != 'push'"
        )
    soft = _print_soft_failures(specs)
    if findings or soft:
        return 1
    print("\nOK — no required check can skip an assertion, or pass over a failed step,")
    print("     on a push to the protected branch")
    return 0


def main(argv: list[str] | None = None) -> int:  # noqa: PLR0911, PLR0912, PLR0915
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--self-test", action="store_true", help="prove the gate is not vacuous, then exit")
    parser.add_argument("--static", action="store_true", help="read the workflow tree only; no API calls")
    parser.add_argument("--repo-root", type=Path, default=None)
    parser.add_argument("--window-runs", type=int, default=DEFAULT_WINDOW_RUNS)
    parser.add_argument(
        "--enforced-from",
        default=None,
        help="override the manifest floor (ISO-8601). Used to re-run this gate against pre-fix history.",
    )
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=None,
        help="re-read a previous fetch instead of calling the API. Refused under CI.",
    )
    args = parser.parse_args(argv)

    if args.cache_dir and os.environ.get("CI"):
        print("FAIL: --cache-dir is for reproducing a measurement by hand. Under CI it would")
        print("      let a stale file on disk stand in for the run history this gate exists")
        print("      to read.")
        return 2

    if args.self_test:
        return self_test()

    root = (args.repo_root or repo_root()).resolve()
    try:
        manifest = load_manifest(root)
        repo = resolve_repository(root)
    except (GateError, json.JSONDecodeError) as exc:
        print(f"FAIL: {exc}")
        return 2

    branch = str(manifest["branch"])
    contexts = [str(c) for c in manifest["contexts"]]
    try:
        specs, unresolved = index_workflows(root, contexts, branch)
    except GateError as exc:
        print(f"FAIL: {exc}")
        return 2

    print(f"checkout         {root}")
    print(f"repository       {repo}")
    print(f"branch           {branch}")
    print(f"required checks  {len(contexts)} from {MANIFEST}")

    if unresolved:
        print(f"\nFAIL: {len(unresolved)} required check(s) have no job in this tree:\n")
        for name in unresolved:
            print(f"  {name}")
        print(
            "\nA required check whose job has been renamed can never report, which\n"
            "blocks every pull request; and a name in the manifest that matches\n"
            "nothing means this gate silently grades fewer checks than it claims.\n"
            "Fix the name in .github/required-checks.json and in branch protection."
        )
        return 2

    undecidable = sorted(name for name, spec in specs.items() if spec.undecidable)
    if undecidable:
        print(f"\nFAIL: {len(undecidable)} required check(s) read more run-time references than")
        print(f"      this gate enumerates (cap {MAX_ASSIGNMENTS} combinations), so it cannot say")
        print("      which paths through the job are complete runs. Reporting OK here would be")
        print("      the same defect one level up.")
        for name in undecidable:
            print(f"  {name}")
        return 2

    if args.static:
        return _print_static(specs)

    # Checked in both modes: it is the half of the claim the API cannot
    # answer, so leaving it to the run-history path would mean not checking
    # it at all.
    soft_failure_code = _print_soft_failures(specs)

    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not token:
        print("FAIL: no GH_TOKEN/GITHUB_TOKEN in the environment — this gate can only be")
        print("      answered by the Actions API, and skipping would report a clean result")
        print("      about runs it never read.")
        return 2

    floor_raw = args.enforced_from or str(manifest["enforced_from"])
    enforced_from = datetime.fromisoformat(floor_raw.replace("Z", "+00:00"))
    window_is_young = (datetime.now(UTC) - enforced_from) < timedelta(days=YOUNG_WINDOW_DAYS)
    print(f"enforced from    {enforced_from.isoformat()}" + ("  (young window)" if window_is_young else ""))

    live = fetch_protection_contexts(repo, token, branch)
    if live is None:
        print("protection       NOT VERIFIED — this token cannot read branch protection")
        print("                 (`administration: read`, which GITHUB_TOKEN cannot be granted).")
        print(f"                 The {len(contexts)} context(s) graded below come from {MANIFEST} alone.")
    elif sorted(live) != sorted(contexts):
        print("\nFAIL: the manifest and branch protection disagree about what is required.\n")
        for name in sorted(set(live) - set(contexts)):
            print(f"  required on {branch}, absent from the manifest:  {name}")
        for name in sorted(set(contexts) - set(live)):
            print(f"  in the manifest, not required on {branch}:       {name}")
        return 2
    else:
        print(f"protection       verified — {len(live)} context(s) match branch protection exactly")

    try:
        recent_shas = fetch_recent_commits(repo, token, branch, FRESHNESS_COMMITS)
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError) as exc:
        print(f"\nFAIL: could not read the commit list for {branch}, which is this gate's only")
        print(f"      independent check that the run history it reads is current: {exc}")
        return 2
    if len(recent_shas) < FRESHNESS_COMMITS:
        print(f"\nFAIL: the commit list for {branch} returned {len(recent_shas)} of {FRESHNESS_COMMITS}")
        print("      requested. Without it the run history cannot be shown to be current.")
        return 2

    # One fetch per workflow, shared by every context it hosts.
    by_workflow: dict[str, list[JobSpec]] = {}
    for spec in specs.values():
        by_workflow.setdefault(spec.workflow_file, []).append(spec)

    results: dict[str, list[RunVerdict]] = {}
    unverified_freshness: list[str] = []
    # Oldest and newest run graded, per workflow. Printed because a
    # proportion without the window it was measured over is not a number
    # anyone can check — and because printing it is what made this gate's own
    # broken pagination obvious.
    windows: dict[str, tuple[str, str]] = {}
    starved: list[str] = []
    findings: list[tuple[str, RunVerdict]] = []
    no_push_trigger: list[str] = []

    for workflow_file, hosted in sorted(by_workflow.items()):
        if not hosted[0].triggers_on_push_to_branch:
            no_push_trigger.extend(s.context for s in hosted)
            continue
        # The freshness oracle is only valid for a workflow that runs on every
        # push to the branch. One filtered by path legitimately has no run for
        # a recent commit, so it is graded without the check and named below.
        oracle = recent_shas if not hosted[0].push_is_path_filtered else None
        if oracle is None:
            unverified_freshness.append(workflow_file)
        try:
            runs, jobs_by_run = load_or_fetch(args.cache_dir, repo, token, workflow_file, branch, args.window_runs, oracle)
        except GateError as exc:
            print(f"\nFAIL: {exc}")
            return 2
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError, OSError) as exc:
            print(f"\nFAIL: could not read runs for {workflow_file}: {exc}")
            return 2
        windows[workflow_file] = (
            str(runs[-1].get("created_at") or "?") if runs else "?",
            str(runs[0].get("created_at") or "?") if runs else "?",
        )
        if len(runs) < MIN_RUNS_FETCHED:
            print(f"\nFAIL: only {len(runs)} successful push run(s) came back for {workflow_file} (expected >= {MIN_RUNS_FETCHED}).")
            print("      An empty answer is a broken query or a check that stopped running,")
            print("      not a clean repository.")
            return 2
        for spec in hosted:
            results[spec.context] = audit_context(spec, runs, jobs_by_run, enforced_from)

    print("\nwindow graded, per workflow (oldest .. newest successful push run):")
    for workflow_file, (oldest, newest) in sorted(windows.items()):
        fresh = "freshness NOT verified" if workflow_file in unverified_freshness else ""
        print(f"  {workflow_file:28s} {oldest} .. {newest}  {fresh}")
    if unverified_freshness:
        print(
            f"\n  {len(unverified_freshness)} workflow(s) above carry a `paths:` filter on their push\n"
            "  trigger, so a recent commit can legitimately have produced no run and the\n"
            "  commit-list freshness oracle does not apply to them. Their window was graded\n"
            "  without it."
        )

    print(f"\n{'required check':62s} {'substantive / graded':22s} {'enforced window':s}")
    print("-" * 118)
    for name in contexts:
        verdicts = results.get(name)
        if verdicts is None:
            print(f"{name:62s} {'— no push trigger —':22s} not graded here")
            continue
        total = len(verdicts)
        good = sum(1 for v in verdicts if v.substantive)
        enforced = [v for v in verdicts if v.enforced]
        enforced_bad = [v for v in enforced if not v.substantive]
        pct = (100.0 * good / total) if total else 0.0
        window = f"{len(enforced) - len(enforced_bad)}/{len(enforced)}" if enforced else "0 runs yet"
        print(f"{name:62s} {good:3d} / {total:3d}  ({pct:5.1f}%)   {window}")
        for verdict in enforced_bad:
            findings.append((name, verdict))
        if not enforced and not window_is_young:
            starved.append(name)

    if no_push_trigger:
        print(
            f"\nnot graded by this gate ({len(no_push_trigger)}): the workflow does not run on a push to "
            f"{branch}, so there is no landed-commit history to read. These are graded on the pull "
            "request only; scripts/check_workflow_concurrency.py covers the absent-run case."
        )
        for name in no_push_trigger:
            print(f"  {name}")

    graded = len(results)
    if findings:
        print(f"\nFAIL: {len(findings)} run(s) in the enforced window reported success without executing their work.\n")
        for name, verdict in findings[:40]:
            detail = verdict.job_conclusion if verdict.job_conclusion != "success" else ""
            print(f"  {name}  {verdict.created_at}  {verdict.head_sha}  {detail}")
            for step in verdict.missing[:6]:
                print(f"      did not run: {step}")
            for step in verdict.soft_failed[:6]:
                print(f"      failed under continue-on-error: {step}")
            print(f"      {verdict.html_url}")
        if len(findings) > 40:
            print(f"  … and {len(findings) - 40} more")

    if starved:
        print(f"\nFAIL: {len(starved)} required check(s) have no run at all in the enforced window,")
        print(f"      which is older than {YOUNG_WINDOW_DAYS} days. A check that stopped running")
        print("      is the loudest version of the defect this gate exists to catch.")
        for name in starved:
            print(f"  {name}")

    code = verdict_for(contexts_graded=graded, findings=findings, starved=starved, unresolved=unresolved)
    code = max(code, soft_failure_code)
    if code != 0:
        return code

    enforced_runs = sum(1 for verdicts in results.values() for v in verdicts if v.enforced)
    if enforced_runs == 0:
        # "Found nothing" and "asked nothing" print the same word unless one
        # of them refuses to.
        print(
            f"\nNOTICE: no run on {branch} has been created since {enforced_from.isoformat()} yet.\n"
            f"        The API answered with history for all {graded} required check(s), so the\n"
            "        query works — the window is simply young, and the proportions above are\n"
            f"        the pre-floor history. Nothing has been graded clean here. After\n"
            f"        {YOUNG_WINDOW_DAYS} days an empty window becomes a failure."
        )
        return 0

    print(f"\nOK — {graded} required check(s) graded over {enforced_runs} run(s) in the enforced")
    print("     window; every one of them executed its assertions")
    return code


if __name__ == "__main__":
    sys.exit(main())
