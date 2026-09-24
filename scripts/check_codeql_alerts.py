#!/usr/bin/env python3
"""
Gate: zero open CodeQL alerts on the ref — from a scan that actually ran.

`apps/docs/docs/operations/security.md` states that the CodeQL alert count on
`main` is zero and that we treat it as a CI gate. Until this script existed
that sentence described no mechanism: `codeql.yml` uploads SARIF and
`github/codeql-action/analyze` does not fail a build on findings, `main` has no
branch protection so "Code scanning results" was not a required check, and
`security.yml`'s only hard job was the claim-to-gate matrix. Two `note`-severity
alerts sat open on `main` under a documented invariant of zero.

What this checks, and why each part exists:

1. `open-alert` — any open CodeQL alert on the ref, **at every severity
   including `note`**. The two alerts that motivated this gate were both
   `note`; a gate that filtered them out would have reproduced the original
   failure while printing OK.
2. `no-analysis` / `language-not-analyzed` — the ref must actually have been
   analyzed, per language declared in the workflow matrix. Zero alerts because
   nothing ran is the vacuous pass this repository keeps rediscovering, so an
   empty read is a failure, never a clean bill of health.
3. `stale-analysis` — the newest analysis must be recent. `main` can be
   stale-green: a workflow that stopped running still leaves its last passing
   result in place, and the alert list simply freezes.
4. `action-version-mismatch` — CodeQL refuses to run at all when one workflow
   pins different versions across `init` / `autobuild` / `analyze`, which is
   exactly what a dependabot bump splitting those three across separate PRs
   produces. That failure mode removes the analysis, and without (2) and (3) it
   would read as "no alerts".
5. `no-push-to-main-trigger` / `no-pull-request-trigger` — a PR-only scan
   inspects what contributors propose and never what lands.

Dismissed alerts are out of scope by design: dismissal is GitHub's audited
escape hatch (it records actor, reason and timestamp, and requires write
access), and this repository uses it for ~22 accepted-risk
`py/request-without-cert-validation` findings on on-prem appliance clients.
They are counted and printed rather than hidden, so a silent mass-dismissal is
visible in this gate's own output.

Scorecard also uploads SARIF to the same code-scanning page. Its findings are a
different policy with a different owner, so they are reported here and not
gated.

Usage:
    python3 scripts/check_codeql_alerts.py                    # gate `main`
    python3 scripts/check_codeql_alerts.py --ref refs/pull/1/merge
    python3 scripts/check_codeql_alerts.py --json
    python3 scripts/check_codeql_alerts.py --self-test        # prove it bites
    python3 scripts/check_codeql_alerts.py --offline          # static checks only

Exit codes: 0 clean · 1 the invariant is broken · 2 the gate could not read its
inputs (never reported as clean).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

API_ROOT = "https://api.github.com"
DEFAULT_REPO = "beenuar/AiSOC"
DEFAULT_REF = "refs/heads/main"
WORKFLOW_REL = Path(".github/workflows/codeql.yml")

# The tool whose alerts this gate owns. Scorecard uploads to the same page
# under its own name and is reported, not gated.
GATED_TOOL = "CodeQL"

# The weekly cron plus a push on every merge means a healthy `main` is analyzed
# far more often than this. Ten days clears the widest legitimate gap (a quiet
# week where only the Monday schedule fires) while still catching a workflow
# that has stopped running.
DEFAULT_MAX_ANALYSIS_AGE_DAYS = 10

_ACTION_RE = re.compile(r"github/codeql-action/(init|autobuild|analyze)@(\S+)")
_LANGUAGE_LIST_RE = re.compile(r"language:\s*\[([^\]]+)\]")
_BRANCH_LIST_RE = re.compile(r"branches:\s*\[([^\]]+)\]")


class GateError(RuntimeError):
    """An input could not be read. Never downgraded to a passing result."""


# --------------------------------------------------------------------------
# Workflow parsing (offline)
# --------------------------------------------------------------------------
def _block(text: str, header: str) -> str | None:
    """The indented block following the line whose content is `header`."""
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if line.strip() != header:
            continue
        base = len(line) - len(line.lstrip())
        out: list[str] = []
        for nxt in lines[i + 1 :]:
            if not nxt.strip():
                out.append(nxt)
                continue
            if len(nxt) - len(nxt.lstrip()) <= base:
                break
            out.append(nxt)
        return "\n".join(out)
    return None


def parse_workflow(path: Path) -> dict[str, Any]:
    """Read the declared languages, action pins and triggers out of codeql.yml.

    Parsed with targeted regexes rather than PyYAML: this gate runs on a bare
    `actions/setup-python` interpreter with nothing pip-installed, and a gate
    that cannot run is worse than one with a narrower parser. Every field is
    required — a parse that finds nothing raises instead of returning an empty
    result that would read as "no problems found".
    """
    if not path.exists():
        raise GateError(f"expected input does not exist: {path}")
    text = path.read_text(encoding="utf-8")

    versions: dict[str, str] = {}
    for step, pin in _ACTION_RE.findall(text):
        versions[step] = pin
    for step in ("init", "autobuild", "analyze"):
        if step not in versions:
            raise GateError(f"{path}: no `github/codeql-action/{step}` step found")

    lang_match = _LANGUAGE_LIST_RE.search(text)
    if not lang_match:
        raise GateError(f"{path}: could not parse the `language:` matrix")
    languages = [item.strip().strip("'\"") for item in lang_match.group(1).split(",")]
    languages = [item for item in languages if item]
    if not languages:
        raise GateError(f"{path}: parsed an empty `language:` matrix")

    on_block = _block(text, "on:")
    if on_block is None:
        raise GateError(f"{path}: could not find the `on:` trigger block")
    push_block = _block(on_block, "push:")
    push_branches: list[str] = []
    if push_block is not None:
        branch_match = _BRANCH_LIST_RE.search(push_block)
        if branch_match:
            push_branches = [item.strip().strip("'\"") for item in branch_match.group(1).split(",")]

    return {
        "path": str(path),
        "action_versions": versions,
        "languages": languages,
        "push_branches": push_branches,
        "has_pull_request_trigger": _block(on_block, "pull_request:") is not None
        or re.search(r"^\s*pull_request:\s*$", on_block, re.MULTILINE) is not None,
    }


# --------------------------------------------------------------------------
# GitHub API (fails closed)
# --------------------------------------------------------------------------
def _token() -> str:
    for name in ("GITHUB_TOKEN", "GH_TOKEN"):
        value = os.environ.get(name)
        if value:
            return value
    raise GateError(
        "no GITHUB_TOKEN/GH_TOKEN in the environment; the gate needs "
        "`security-events: read` to query code scanning. Re-run with --offline "
        "to check only what can be checked without it."
    )


def _get(url: str, token: str) -> tuple[Any, str | None]:
    request = urllib.request.Request(  # noqa: S310 - fixed https API_ROOT below
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "aisoc-codeql-alert-gate",
        },
    )
    if not url.startswith(API_ROOT + "/"):
        raise GateError(f"refusing to call a non-GitHub URL: {url}")
    try:
        with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
            payload = json.loads(response.read().decode("utf-8"))
            link = response.headers.get("Link")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:300]
        raise GateError(f"GET {url} -> HTTP {exc.code}: {detail}") from exc
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        raise GateError(f"GET {url} -> {type(exc).__name__}: {exc}") from exc

    next_url = None
    if link:
        for part in link.split(","):
            if 'rel="next"' in part:
                next_url = part.split(";")[0].strip().strip("<>")
    return payload, next_url


def _paginate(url: str, token: str, limit_pages: int = 20) -> list[dict]:
    items: list[dict] = []
    pages = 0
    while url and pages < limit_pages:
        payload, url = _get(url, token)
        if not isinstance(payload, list):
            raise GateError(f"expected a JSON array from {url!r}, got {type(payload).__name__}")
        items.extend(payload)
        pages += 1
    return items


def fetch(repo: str, ref: str) -> dict[str, Any]:
    """Open alerts, dismissed alerts and analyses for `ref`. Raises on failure."""
    token = _token()
    quoted = urllib.parse.quote(ref, safe="/")
    base = f"{API_ROOT}/repos/{repo}/code-scanning"
    open_alerts = _paginate(f"{base}/alerts?state=open&ref={quoted}&per_page=100", token)
    dismissed = _paginate(f"{base}/alerts?state=dismissed&ref={quoted}&per_page=100", token)
    analyses = _paginate(f"{base}/analyses?ref={quoted}&per_page=100", token, limit_pages=2)
    return {"open_alerts": open_alerts, "dismissed_alerts": dismissed, "analyses": analyses}


def fetch_when_analyzed(
    repo: str,
    ref: str,
    *,
    commit: str | None,
    languages: list[str],
    wait_seconds: int,
    poll_seconds: int = 30,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    """`fetch`, but wait for the analyses of `commit` to land first.

    The gate and the analysis it reads are triggered by the same push, so
    without this the gate would routinely evaluate the previous commit and
    call the new one clean. Timing out is a failure, not a pass: the caller
    still evaluates, and the missing analyses surface as `no-analysis` or
    `language-not-analyzed`.
    """
    deadline = time.monotonic() + max(wait_seconds, 0)
    while True:
        data = fetch(repo, ref)
        if not commit or wait_seconds <= 0:
            return data
        covered = _analysis_languages(data["analyses"], commit)
        if all(language in covered for language in languages):
            return data
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return data
        missing = [item for item in languages if item not in covered]
        pending = ", ".join(missing)
        print(
            f"waiting for {GATED_TOOL} analysis of {commit[:8]} ({pending}); {int(remaining)}s left",
            flush=True,
        )
        sleep(min(poll_seconds, max(remaining, 1)))


# --------------------------------------------------------------------------
# Evaluation (pure — the self-test drives this directly)
# --------------------------------------------------------------------------
def _analysis_languages(analyses: list[dict], commit: str | None = None) -> dict[str, datetime]:
    """Newest analysis timestamp per language, read from the SARIF category.

    `commit` pins the result to one revision. Without it a run triggered by a
    push would happily read the *previous* commit's analysis — the alert list
    for a ref does not change until the new analysis lands — and report the
    incoming commit clean before anything had looked at it.
    """
    newest: dict[str, datetime] = {}
    for analysis in analyses:
        if analysis.get("tool", {}).get("name") != GATED_TOOL:
            continue
        if commit and analysis.get("commit_sha") != commit:
            continue
        category = analysis.get("category") or ""
        language = category.split("/language:")[-1] if "/language:" in category else ""
        if not language:
            continue
        created = analysis.get("created_at")
        if not created:
            continue
        stamp = datetime.fromisoformat(created.replace("Z", "+00:00"))
        if language not in newest or stamp > newest[language]:
            newest[language] = stamp
    return newest


def evaluate(
    *,
    open_alerts: list[dict],
    analyses: list[dict],
    workflow: dict[str, Any],
    now: datetime,
    max_age_days: int,
    alerts_checked: bool,
    commit: str | None = None,
) -> list[tuple[str, str]]:
    """Return (code, detail) for every way the invariant is currently false."""
    failures: list[tuple[str, str]] = []

    pins = workflow["action_versions"]
    if len(set(pins.values())) > 1:
        rendered = ", ".join(f"{step}@{pin}" for step, pin in sorted(pins.items()))
        failures.append(
            (
                "action-version-mismatch",
                f"codeql-action steps pin different versions ({rendered}); CodeQL refuses "
                "to run at all in this state, which would empty the alert list rather than "
                "clear it",
            )
        )

    if "main" not in workflow["push_branches"]:
        failures.append(
            (
                "no-push-to-main-trigger",
                f"{workflow['path']} does not run on push to main "
                f"(push branches: {workflow['push_branches'] or 'none'}); a PR-only scan "
                "never inspects what actually landed",
            )
        )
    if not workflow["has_pull_request_trigger"]:
        failures.append(
            (
                "no-pull-request-trigger",
                f"{workflow['path']} does not run on pull requests, so a contributor only "
                "learns about a new alert after it is already on main",
            )
        )

    if alerts_checked:
        by_language = _analysis_languages(analyses, commit)
        scope = f" for commit {commit[:8]}" if commit else ""
        if not by_language:
            failures.append(
                (
                    "no-analysis",
                    f"no {GATED_TOOL} analysis found for this ref{scope} — zero alerts here "
                    "means nothing was scanned, not that nothing was found",
                )
            )
        else:
            for language in workflow["languages"]:
                if language not in by_language:
                    failures.append(
                        (
                            "language-not-analyzed",
                            f"the workflow declares `{language}` but no {GATED_TOOL} analysis "
                            f"for it exists on this ref{scope} (analyzed: {sorted(by_language)})",
                        )
                    )
            cutoff = now - timedelta(days=max_age_days)
            for language, stamp in sorted(by_language.items()):
                if stamp < cutoff:
                    age = (now - stamp).days
                    failures.append(
                        (
                            "stale-analysis",
                            f"the newest `{language}` analysis is {age} days old "
                            f"({stamp.date()}), past the {max_age_days}-day limit; the alert "
                            "list is frozen, not clean",
                        )
                    )

        for alert in open_alerts:
            if alert.get("tool", {}).get("name") != GATED_TOOL:
                continue
            rule = alert.get("rule", {})
            location = alert.get("most_recent_instance", {}).get("location", {})
            failures.append(
                (
                    "open-alert",
                    f"#{alert.get('number')} {rule.get('id')} [{rule.get('severity')}] "
                    f"{location.get('path')}:{location.get('start_line')}",
                )
            )

    return failures


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def _summarise(items: list[dict], key) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        name = key(item)
        counts[name] = counts.get(name, 0) + 1
    return counts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY") or DEFAULT_REPO)
    parser.add_argument("--ref", default=DEFAULT_REF)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--max-analysis-age-days", type=int, default=DEFAULT_MAX_ANALYSIS_AGE_DAYS)
    parser.add_argument(
        "--commit",
        default=None,
        help="require the analyses to be of this revision, not merely of this ref",
    )
    parser.add_argument(
        "--wait-seconds",
        type=int,
        default=0,
        help="wait this long for --commit to be analyzed; timing out still fails",
    )
    parser.add_argument("--json", action="store_true")
    parser.add_argument(
        "--offline",
        action="store_true",
        help="check only the workflow wiring; states in its output that the alert "
        "query was not performed (for fork PRs, whose token cannot read code scanning)",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="inject an alert and each vacuous-pass shape, and require the gate to catch each",
    )
    args = parser.parse_args(argv)

    root = args.repo_root.resolve()
    if args.self_test:
        return self_test(root)

    try:
        workflow = parse_workflow(root / WORKFLOW_REL)
        if args.offline:
            data: dict[str, Any] = {"open_alerts": [], "dismissed_alerts": [], "analyses": []}
        else:
            data = fetch_when_analyzed(
                args.repo,
                args.ref,
                commit=args.commit,
                languages=workflow["languages"],
                wait_seconds=args.wait_seconds,
            )
    except GateError as exc:
        print(f"check_codeql_alerts: FAILED to read its inputs: {exc}", file=sys.stderr)
        return 2

    now = datetime.now(timezone.utc)
    failures = evaluate(
        open_alerts=data["open_alerts"],
        analyses=data["analyses"],
        workflow=workflow,
        now=now,
        max_age_days=args.max_analysis_age_days,
        alerts_checked=not args.offline,
        commit=args.commit,
    )

    by_language = _analysis_languages(data["analyses"], args.commit)
    gated_open = [a for a in data["open_alerts"] if a.get("tool", {}).get("name") == GATED_TOOL]
    other_open = [a for a in data["open_alerts"] if a.get("tool", {}).get("name") != GATED_TOOL]
    gated_dismissed = [a for a in data["dismissed_alerts"] if a.get("tool", {}).get("name") == GATED_TOOL]

    if args.json:
        print(
            json.dumps(
                {
                    "repo": args.repo,
                    "ref": args.ref,
                    "commit": args.commit,
                    "offline": args.offline,
                    "workflow": workflow,
                    "analyses_by_language": {k: v.isoformat() for k, v in by_language.items()},
                    "open_codeql_alerts": [
                        {
                            "number": a.get("number"),
                            "rule": a.get("rule", {}).get("id"),
                            "severity": a.get("rule", {}).get("severity"),
                            "path": a.get("most_recent_instance", {}).get("location", {}).get("path"),
                        }
                        for a in gated_open
                    ],
                    "dismissed_codeql_alerts": len(gated_dismissed),
                    "open_other_tool_alerts": len(other_open),
                    "failures": [{"code": c, "detail": d} for c, d in failures],
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 1 if failures else 0

    # Name what was scanned before the verdict. A gate that prints only OK is
    # indistinguishable from one that checked nothing.
    print(f"repo             {args.repo}")
    print(f"ref              {args.ref}{'  @ ' + args.commit[:8] if args.commit else ''}")
    print(f"workflow         {workflow['path']}  (languages: {', '.join(workflow['languages'])})")
    pins = set(workflow["action_versions"].values())
    print(f"codeql-action    {'consistent @' + pins.pop() if len(pins) == 1 else 'MIXED PINS'}")
    print(
        f"triggers         push:{workflow['push_branches'] or 'none'}  "
        f"pull_request:{'yes' if workflow['has_pull_request_trigger'] else 'no'}"
    )
    if args.offline:
        print()
        print("NOT VERIFIED     open-alert count, analysis freshness and language coverage")
        print("                 (--offline: no code-scanning read available on this event)")
    else:
        if by_language:
            for language, stamp in sorted(by_language.items()):
                age = (now - stamp).days
                print(f"  analysed       {language:24s} {stamp.isoformat()}  ({age}d ago)")
        else:
            print("  analysed       nothing")
        print()
        print(f"open {GATED_TOOL} alerts   {len(gated_open)} (every severity, `note` included)")
        print(f"dismissed        {len(gated_dismissed)} — audited accepted risk, not gated here")
        if other_open:
            other = _summarise(other_open, lambda a: a.get("tool", {}).get("name") or "?")
            print(f"other tools      {other} open — reported, owned elsewhere")
    print()

    if failures:
        print(f"FAIL — {len(failures)} finding(s):")
        for code, detail in failures:
            print(f"  [{code}] {detail}")
        return 1
    if args.offline:
        print("OK (offline) — workflow wiring is sound; the alert count was NOT checked.")
        return 0
    scanned = f"commit {args.commit[:8]}" if args.commit else f"the last {args.max_analysis_age_days} days"
    print(f"OK — zero open {GATED_TOOL} alerts on {args.ref}, from a scan that ran on")
    print(f"     every declared language ({', '.join(workflow['languages'])}) for {scanned}.")
    return 0


# --------------------------------------------------------------------------
# Self-test
# --------------------------------------------------------------------------
def _clean_fixture(root: Path, now: datetime) -> dict[str, Any]:
    """A ref that genuinely satisfies the invariant, built from the real workflow."""
    workflow = parse_workflow(root / WORKFLOW_REL)
    analyses = [
        {
            "tool": {"name": GATED_TOOL},
            "category": f"/language:{language}",
            "created_at": (now - timedelta(hours=2)).isoformat().replace("+00:00", "Z"),
        }
        for language in workflow["languages"]
    ]
    return {"open_alerts": [], "analyses": analyses, "workflow": workflow}


def _alert(number: int, rule: str, severity: str, path: str) -> dict[str, Any]:
    return {
        "number": number,
        "tool": {"name": GATED_TOOL},
        "rule": {"id": rule, "severity": severity},
        "most_recent_instance": {"location": {"path": path, "start_line": 1}},
    }


def self_test(root: Path) -> int:
    """Inject each shape of failure and require the gate to catch it.

    The first two cases are the ones that matter most: they are the alerts that
    were open on `main` while the documentation claimed zero. A severity filter
    anywhere in this gate makes case 1 fail here rather than on the security
    page months later.
    """
    now = datetime.now(timezone.utc)
    try:
        base = _clean_fixture(root, now)
    except GateError as exc:
        print(f"self-test: cannot read the tree: {exc}", file=sys.stderr)
        return 2

    def run(data: dict[str, Any], *, alerts_checked: bool = True, commit: str | None = None) -> set[str]:
        return {
            code
            for code, _ in evaluate(
                open_alerts=data["open_alerts"],
                analyses=data["analyses"],
                workflow=data["workflow"],
                now=now,
                max_age_days=DEFAULT_MAX_ANALYSIS_AGE_DAYS,
                alerts_checked=alerts_checked,
                commit=commit,
            )
        }

    baseline = run(base)
    if baseline:
        print("self-test: the clean fixture already fails; fix that first", file=sys.stderr)
        for code in sorted(baseline):
            print(f"  [{code}]", file=sys.stderr)
        return 1

    def mutate(**overrides: Any) -> dict[str, Any]:
        data = {
            "open_alerts": list(base["open_alerts"]),
            "analyses": [dict(a) for a in base["analyses"]],
            "workflow": dict(base["workflow"]),
        }
        data["workflow"]["action_versions"] = dict(base["workflow"]["action_versions"])
        data["workflow"]["languages"] = list(base["workflow"]["languages"])
        data["workflow"]["push_branches"] = list(base["workflow"]["push_branches"])
        data.update(overrides)
        return data

    stale = mutate()
    for analysis in stale["analyses"]:
        analysis["created_at"] = (now - timedelta(days=DEFAULT_MAX_ANALYSIS_AGE_DAYS + 5)).isoformat().replace("+00:00", "Z")

    mixed = mutate()
    mixed["workflow"]["action_versions"]["analyze"] = "v3.28.0"

    no_push = mutate()
    no_push["workflow"]["push_branches"] = []

    no_pr = mutate()
    no_pr["workflow"]["has_pull_request_trigger"] = False

    dropped_language = mutate()
    dropped_language["analyses"] = dropped_language["analyses"][:-1]

    cases: list[tuple[str, str, dict[str, Any]]] = [
        (
            "a `note`-severity alert — #893/#896's severity, which a filtered gate would pass",
            "open-alert",
            mutate(
                open_alerts=[
                    _alert(893, "py/unused-global-variable", "note", "scripts/x.py"),
                ]
            ),
        ),
        (
            "an `error`-severity alert",
            "open-alert",
            mutate(open_alerts=[_alert(1, "py/sql-injection", "error", "services/api/app/db.py")]),
        ),
        (
            "the ref was never analyzed — zero alerts because nothing ran",
            "no-analysis",
            mutate(analyses=[]),
        ),
        (
            "one declared language silently stopped being analyzed",
            "language-not-analyzed",
            dropped_language,
        ),
        (
            "stale-green: the analysis is frozen, so the alert list cannot move",
            "stale-analysis",
            stale,
        ),
        (
            "codeql-action pins split across init/autobuild/analyze, so CodeQL never runs",
            "action-version-mismatch",
            mixed,
        ),
        (
            "the scan stopped running on push to main and only inspects proposals",
            "no-push-to-main-trigger",
            no_push,
        ),
        (
            "the scan stopped running on pull requests",
            "no-pull-request-trigger",
            no_pr,
        ),
    ]

    print(f"self-test against {root / WORKFLOW_REL}")
    print("clean fixture: 0 failures (the baseline every case below perturbs)\n")
    ok = True
    for description, expected, data in cases:
        codes = run(data)
        caught = expected in codes
        ok &= caught
        print(f"  {'PASS' if caught else 'FAIL'}  {description}")
        print(f"        expected [{expected}]  got {sorted(codes) or 'nothing'}")

    # A push run must not read the previous commit's analysis and call the
    # incoming one clean. With --commit pinned, an analysis of anything else
    # is no analysis at all.
    pinned = run(base, commit="0" * 40)
    pinned_ok = "no-analysis" in pinned
    ok &= pinned_ok
    print(f"  {'PASS' if pinned_ok else 'FAIL'}  an analysis of a different commit is not this commit's")
    print(f"        expected [no-analysis]  got {sorted(pinned) or 'nothing'}")

    # --offline must not be a silent skip that still claims the alert count.
    offline_codes = run(
        mutate(open_alerts=[_alert(2, "py/print-during-import", "note", "scripts/y.py")]),
        alerts_checked=False,
    )
    offline_quiet = "open-alert" not in offline_codes
    ok &= offline_quiet
    print(f"  {'PASS' if offline_quiet else 'FAIL'}  --offline reports no alert verdict at all")
    print(f"        expected no [open-alert]  got {sorted(offline_codes) or 'nothing'}")

    print()
    if not ok:
        print("self-test FAILED: the gate did not catch a defect it claims to catch")
        return 1
    print(f"self-test OK: {len(cases) + 2} injected defects, each caught by its own code")
    return 0


if __name__ == "__main__":
    sys.exit(main())
