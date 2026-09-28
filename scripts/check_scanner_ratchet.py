#!/usr/bin/env python3
"""The observe-mode scanners get a ratchet, and `.security/allowlist.yml` gets a reader.

Why this exists
---------------

``.github/workflows/security.yml`` describes its three observe-mode scanners
as "report-and-ratchet" and names ``.security/allowlist.yml`` as where the
triaged baseline lives. Both halves of that sentence were untrue.

There was no ratchet. Semgrep, checkov and tfsec each ran under
``continue-on-error: true`` — checkov additionally with a trailing ``|| true``
— printed a number, and nothing compared that number to anything. A pull
request that added twenty findings and one that removed twenty produced the
same green tick, so the counts written into the workflow header ("Semgrep 92,
35 at ERROR; checkov 91 failed; tfsec 32, 7 CRITICAL, 5 HIGH") were a
measurement taken once and then left to rot.

And ``.security/allowlist.yml`` had **no reader anywhere in the tree**. A
repository-wide search for its path returned two documents talking *about* it
and not one line of code that opens it. Its header declares a schema, requires
a reason and an expiry on every entry, and says expired entries "fail CI" —
enforced by nothing. An allow-list nobody reads is worse than no allow-list:
it looks like a control, so the next person assumes the triage happened.

``scripts/check_gate_coverage.py`` would have caught this had the orphan been
a *script*. It inventories ``scripts/`` against the workflows. A control file
in YAML with no caller is the same defect one file type over, and nothing was
looking for it.

What it checks
--------------

``regression``
    A scanner reports more findings than its recorded ceiling. This is the
    property the word "ratchet" promises and the only one that protects the
    tree from accumulating new findings.

``stale-ceiling``
    A scanner reports *fewer* findings than its ceiling. Shrink-only: the
    ceiling must come down in the same change that removes the finding, or
    the number drifts back up for free and the ratchet is decorative. The
    failure prints the measured count, so one CI run tells you the value to
    write.

``vacuous``
    Zero findings against a non-zero ceiling. A scanner that reports nothing
    where it previously reported dozens did not run. This repository has the
    scar: the Trivy pin 404'd, ``tar`` failed, a binary that was not there was
    invoked, and ``continue-on-error`` reported green. "Clean" and "did not
    run" must never look the same.

``version-drift``
    The scanner version that produced this report is not the version the
    ceiling was measured with. Counts move when rules move, so a ceiling
    compared against a different scanner is not a comparison. Failing here
    turns a silent re-baseline into an explicit, actionable one.

    A version the gate could not establish **at all** fails the same arm.
    This arm used to read ``if version and measured_with and ...``, so a
    scanner reporting no version skipped the comparison and passed. tfsec was
    exactly that case: its JSON carries no version field, ``_tfsec_counts``
    returned ``None``, and the ``measured_with: "1.28.13"`` sitting in the
    allow-list was never compared against anything — a bump that left the
    finding count unchanged went through unnoticed. A scanner whose version
    cannot be established is not a scanner whose version matches.

    Where the report carries no version the caller establishes one out of
    band and passes ``--tool-version``. The workflow reads it from the
    binary's own ``--version``, which is what actually ran — a pinned
    download URL says what was *asked* for, and a cached or substituted
    binary would still satisfy it. When both a report version and a
    ``--tool-version`` are present they must agree, checked in both
    directions, because two sources that never meet drift.

``allowlist``
    Every entry carries a non-empty reason and an expiry no more than 90 days
    out, names a tool that is actually run, and has not expired. The file's
    own header has required this since it was written; this is the first
    thing to enforce it.

``coverage``  (both directions)
    Every scanner ``security.yml`` invokes has a ceiling, **and** every
    ceiling names a scanner ``security.yml`` invokes. One direction alone is
    the failure shape this repository keeps rediscovering: a gate that
    compares A against B and never B against A passes while drift
    accumulates in the direction things actually change. Here the drift that
    matters is a scanner being removed from the workflow while its ceiling
    stays behind, which would leave a ratchet guarding nothing.

What it reads
-------------

``.security/allowlist.yml`` for the ceilings and the entries, parsed by a
strict reader over the documented subset rather than by PyYAML — the gate has
to run in ``Python — Lint & Type-check``, which installs ruff and mypy and
nothing else. The reader refuses anything it does not recognise rather than
skipping it, and ``scripts/tests/test_check_scanner_ratchet.py`` asserts it
agrees with ``yaml.safe_load`` on the real file so the two cannot diverge.

``.github/workflows/security.yml`` for which scanners are actually invoked.

The scanner's own JSON report, when ``--tool``/``--report`` are given.

Usage
-----

::

    python3 scripts/check_scanner_ratchet.py                     # allow-list + coverage
    python3 scripts/check_scanner_ratchet.py --list              # print the ceilings
    python3 scripts/check_scanner_ratchet.py --tool semgrep --report semgrep.json
    python3 scripts/check_scanner_ratchet.py --self-test

Exit codes: 0 clean, 1 findings, 2 the check itself could not run.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

# `scripts/` is on sys.path when this file is run as a program, but not when a
# test loads it by path with importlib. gate_toolkit sits beside it either way.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_if_requested

self_test_if_requested(__file__)

ALLOWLIST_REL = Path(".security") / "allowlist.yml"
WORKFLOW_REL = Path(".github") / "workflows" / "security.yml"

#: How far out an allow-list expiry may sit. The file's own header states 90
#: days; this is that sentence, enforced.
MAX_EXPIRY_DAYS = 90

#: The scanners this gate knows how to count. A tool invoked by the workflow
#: that is missing here fails `coverage` rather than being skipped, because a
#: scanner nobody counts is the state this gate exists to end.
KNOWN_TOOLS = ("semgrep", "checkov", "tfsec")


class AllowlistError(ValueError):
    """The allow-list could not be read as the schema its header declares."""


# ── the strict reader ────────────────────────────────────────────────────────
#
# The documented subset is: top-level keys; two levels of nesting under
# `ceilings:`; scalars that are integers or quoted strings; and `entries:` as
# either `[]` or a list of flat `- key: value` mappings. Anything else raises.


def _scalar(raw: str, where: str) -> Any:
    text = raw.strip()
    if text.startswith(('"', "'")) and text.endswith(text[0]) and len(text) >= 2:
        return text[1:-1]
    if re.fullmatch(r"-?\d+", text):
        return int(text)
    if text in {"true", "false"}:
        return text == "true"
    if text == "[]":
        return []
    raise AllowlistError(f"{where}: cannot read {raw!r} — quote strings, and use plain integers for counts")


def parse_allowlist(text: str) -> dict[str, Any]:
    """Read the documented subset of the allow-list. Refuse the rest."""
    root: dict[str, Any] = {}
    stack: list[tuple[int, Any]] = [(-1, root)]
    for lineno, raw in enumerate(text.splitlines(), start=1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        line = raw.strip()
        where = f"{ALLOWLIST_REL}:{lineno}"

        if "\t" in raw:
            raise AllowlistError(f"{where}: tab indentation is not readable as YAML")

        while stack and indent <= stack[-1][0]:
            stack.pop()
        if not stack:
            raise AllowlistError(f"{where}: indentation does not nest under anything")
        parent = stack[-1][1]

        if line.startswith("- "):
            if not isinstance(parent, list):
                raise AllowlistError(f"{where}: list item under a mapping")
            item: dict[str, Any] = {}
            parent.append(item)
            key, _, value = line[2:].partition(":")
            if not _:
                raise AllowlistError(f"{where}: list items must be `- key: value` mappings")
            item[key.strip()] = _scalar(value, where)
            # A list item's own keys sit at the column the `-` opened, plus
            # two: `- tool: x` then `  id: y`. Both belong to the same item.
            stack.append((indent + 1, item))
            continue

        key, sep, value = line.partition(":")
        if not sep:
            raise AllowlistError(f"{where}: expected `key: value`, got {line!r}")
        key = key.strip()
        if not value.strip():
            child: dict[str, Any] | list[Any] = [] if key == "entries" else {}
            if isinstance(parent, dict):
                parent[key] = child
            else:
                raise AllowlistError(f"{where}: mapping key inside a list item without a value")
            stack.append((indent, child))
            continue
        if isinstance(parent, dict):
            parent[key] = _scalar(value, where)
        else:
            raise AllowlistError(f"{where}: `{key}` is not inside a mapping")
    return root


# ── counting each scanner's report ───────────────────────────────────────────


def _semgrep_counts(doc: Any) -> tuple[dict[str, int], str | None]:
    results = doc.get("results") or []
    severities = [str((r.get("extra") or {}).get("severity", "")).upper() for r in results]
    return (
        {"total": len(results), "error": sum(1 for s in severities if s == "ERROR")},
        doc.get("version"),
    )


def _checkov_counts(doc: Any) -> tuple[dict[str, int], str | None]:
    # checkov emits a list when several frameworks ran and a bare object when
    # one did. Both shapes reach this gate, so both are read.
    blocks = doc if isinstance(doc, list) else [doc]
    failed = 0
    version: str | None = None
    for block in blocks:
        if not isinstance(block, dict):
            continue
        version = block.get("check_version") or block.get("summary", {}).get("checkov_version") or version
        summary = block.get("summary") or {}
        if "failed" in summary:
            failed += int(summary["failed"] or 0)
        else:
            failed += len((block.get("results") or {}).get("failed_checks") or [])
    return {"failed": failed}, version


def _tfsec_counts(doc: Any) -> tuple[dict[str, int], str | None]:
    results = doc.get("results") or []
    severities = [str(r.get("severity", "")).upper() for r in results]
    return (
        {
            "total": len(results),
            "critical": sum(1 for s in severities if s == "CRITICAL"),
            "high": sum(1 for s in severities if s == "HIGH"),
        },
        None,
    )


_COUNTERS = {"semgrep": _semgrep_counts, "checkov": _checkov_counts, "tfsec": _tfsec_counts}


def count_findings(tool: str, doc: Any) -> tuple[dict[str, int], str | None]:
    """Findings by bucket, plus the scanner version the report declares."""
    counter = _COUNTERS.get(tool)
    if counter is None:
        raise ValueError(f"no counter for {tool!r}; known: {', '.join(sorted(_COUNTERS))}")
    return counter(doc)


# ── what the workflow actually runs ──────────────────────────────────────────


def tools_invoked(workflow_text: str) -> set[str]:
    """Which scanners ``security.yml`` runs, read from its `run:`/`uses:` lines."""
    found: set[str] = set()
    for line in workflow_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        for tool in KNOWN_TOOLS:
            # An invocation, not a mention: the tool name at the head of a
            # shell word, or in an action reference.
            if re.search(rf"(^|[\s|&;/]){re.escape(tool)}([\s@-]|$)", stripped):
                found.add(tool)
    return found


def _versions_pinned(workflow_text: str) -> dict[str, str]:
    """The exact version each scanner is installed at, where one is pinned.

    Two install shapes, because the workflow uses both. A pip-installed
    scanner pins with ``pip install name==X.Y.Z``; a curled binary pins with a
    shell ``VERSION=X.Y.Z`` inside its own ``- name: Install <tool>`` step.

    Reading only the pip shape is why tfsec was invisible here, and that
    mattered more than it looks: ``test_every_ceiling_pins_the_version_the_
    workflow_installs`` iterates over what this function returns, so a
    scanner it cannot see is silently exempt from the very cross-check that
    exists to keep the pin and the ceiling honest.
    """
    pins: dict[str, str] = {}
    for match in re.finditer(r"pip install[^\n]*?([a-z0-9_-]+)==([0-9][^\s'\"]*)", workflow_text):
        pins[match.group(1)] = match.group(2)

    # Binary installs: bind a `VERSION=` assignment to the install step that
    # encloses it, so the pin is attributed to the right tool rather than to
    # whichever assignment happened to come last in the file.
    step_heads = list(re.finditer(r"^\s*-\s*name:\s*Install\s+([A-Za-z0-9_-]+)\s*$", workflow_text, re.MULTILINE))
    for index, head in enumerate(step_heads):
        tool = head.group(1).strip().lower()
        if tool not in KNOWN_TOOLS:
            continue
        end = step_heads[index + 1].start() if index + 1 < len(step_heads) else len(workflow_text)
        assignment = re.search(r"^\s*VERSION=v?([0-9][^\s'\"]*)", workflow_text[head.end() : end], re.MULTILINE)
        if assignment:
            pins[tool] = assignment.group(1)
    return pins


def normalise_version(raw: str | None) -> str | None:
    """The version number out of whatever the scanner printed, or None.

    ``tfsec --version`` prints a bare version; other binaries wrap theirs in a
    banner. Extracting the first dotted numeric run handles both and refuses
    to guess when there is nothing numeric to find, rather than returning a
    banner string that could never equal a ``measured_with``.
    """
    if raw is None:
        return None
    match = re.search(r"[0-9]+(?:\.[0-9]+)+", raw)
    return match.group(0) if match else None


# ── the checks ───────────────────────────────────────────────────────────────


def check_allowlist_entries(entries: list[Any], today: date) -> list[str]:
    problems: list[str] = []
    for index, entry in enumerate(entries):
        where = f"{ALLOWLIST_REL} entries[{index}]"
        if not isinstance(entry, dict):
            problems.append(f"{where}: not a mapping")
            continue
        tool = entry.get("tool")
        if tool not in KNOWN_TOOLS:
            problems.append(f"{where}: tool {tool!r} is not one of {', '.join(KNOWN_TOOLS)}")
        if not str(entry.get("id") or "").strip():
            problems.append(f"{where}: no rule id")
        if not str(entry.get("reason") or "").strip():
            problems.append(f"{where}: no reason — a suppression nobody justified is a suppression nobody can review")
        expires = str(entry.get("expires") or "")
        try:
            when = datetime.strptime(expires, "%Y-%m-%d").date()
        except ValueError:
            problems.append(f"{where}: expires {expires!r} is not YYYY-MM-DD")
            continue
        if when < today:
            problems.append(f"{where}: expired on {when} — re-triage it or fix the finding, do not extend the date")
        elif (when - today).days > MAX_EXPIRY_DAYS:
            problems.append(f"{where}: expires {when}, more than {MAX_EXPIRY_DAYS} days out")
    return problems


def check_coverage(ceilings: dict[str, Any], invoked: set[str]) -> list[str]:
    problems: list[str] = []
    for tool in sorted(invoked - set(ceilings)):
        problems.append(
            f"{WORKFLOW_REL} runs {tool} and {ALLOWLIST_REL} declares no ceiling for it — an uncounted scanner is an observe-mode scanner"
        )
    for tool in sorted(set(ceilings) - invoked):
        problems.append(f"{ALLOWLIST_REL} declares a ceiling for {tool} but {WORKFLOW_REL} does not run it — the ratchet guards nothing")
    return problems


def check_report(tool: str, ceiling: dict[str, Any], counts: dict[str, int], version: str | None) -> list[str]:
    problems: list[str] = []
    buckets = {k: v for k, v in ceiling.items() if isinstance(v, int)}
    if not buckets:
        return [f"{ALLOWLIST_REL}: ceilings.{tool} declares no integer bucket to compare against"]

    measured_with = str(ceiling.get("measured_with") or "")
    if measured_with and not version:
        problems.append(
            f"{tool}: the ceiling was measured with {measured_with} and this run could not establish "
            "which version produced the report, so the counts below are being compared across an "
            "unknown version gap. Pass --tool-version with what the binary reports for itself."
        )
    elif version and measured_with and version != measured_with:
        problems.append(
            f"{tool}: this run used {version}, the ceiling was measured with {measured_with}. "
            "Counts move when rules move — re-measure and update both, do not compare across versions."
        )

    for bucket, limit in sorted(buckets.items()):
        actual = counts.get(bucket)
        if actual is None:
            problems.append(f"{tool}: ceiling names bucket {bucket!r}, the report has no such count")
            continue
        if actual > limit:
            problems.append(f"{tool}: {actual} {bucket} findings against a ceiling of {limit} — this change adds {actual - limit}")
        elif actual == 0 and limit > 0:
            problems.append(
                f"{tool}: 0 {bucket} findings against a ceiling of {limit}. A scanner that previously "
                "reported findings and now reports none did not run — check the install step."
            )
        elif actual < limit:
            problems.append(
                f"{tool}: {actual} {bucket} findings against a ceiling of {limit}. "
                f"Lower it to {actual} in this change, or the number drifts back up for free."
            )
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Ratchet the observe-mode security scanners.")
    parser.add_argument("--tool", choices=KNOWN_TOOLS, help="compare one scanner's report against its ceiling")
    parser.add_argument("--report", type=Path, help="the scanner's JSON output")
    parser.add_argument(
        "--tool-version",
        default=None,
        help=(
            "what the scanner binary reports for itself, for scanners whose JSON "
            "carries no version field. Any banner is accepted; the dotted version "
            "is extracted from it."
        ),
    )
    parser.add_argument("--list", action="store_true", help="print the declared ceilings and exit")
    parser.add_argument("--repo-root", type=Path, default=None)
    args = parser.parse_args(argv)

    root = args.repo_root.resolve() if args.repo_root else repo_root()
    allowlist_path = root / ALLOWLIST_REL
    workflow_path = root / WORKFLOW_REL

    if not allowlist_path.is_file():
        print(f"ERROR: {ALLOWLIST_REL} not found under {root}", file=sys.stderr)
        return 2
    if not workflow_path.is_file():
        print(f"ERROR: {WORKFLOW_REL} not found under {root}", file=sys.stderr)
        return 2

    try:
        doc = parse_allowlist(allowlist_path.read_text(encoding="utf-8"))
    except AllowlistError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    ceilings = doc.get("ceilings")
    if not isinstance(ceilings, dict) or not ceilings:
        print(f"ERROR: {ALLOWLIST_REL} declares no ceilings — nothing to ratchet", file=sys.stderr)
        return 2
    entries = doc.get("entries")
    if entries is None or not isinstance(entries, list):
        print(f"ERROR: {ALLOWLIST_REL} has no `entries:` list", file=sys.stderr)
        return 2

    workflow_text = workflow_path.read_text(encoding="utf-8")
    invoked = tools_invoked(workflow_text)
    if not invoked:
        print(f"ERROR: parsed no scanner invocations out of {WORKFLOW_REL}", file=sys.stderr)
        return 2

    if args.list:
        pins = _versions_pinned(workflow_text)
        for tool in sorted(ceilings):
            buckets = ", ".join(f"{k}={v}" for k, v in sorted(ceilings[tool].items()) if isinstance(v, int))
            print(f"  {tool:<8} {buckets}  measured_with={ceilings[tool].get('measured_with', '—')}  workflow pin={pins.get(tool, '—')}")
        return 0

    problems = check_allowlist_entries(entries, datetime.now(UTC).date())
    problems += check_coverage(ceilings, invoked)

    scanned = f"{len(ceilings)} ceiling(s), {len(entries)} allow-list entr(ies), {len(invoked)} scanner(s) invoked"

    if args.tool:
        if args.report is None:
            print("ERROR: --tool needs --report", file=sys.stderr)
            return 2
        if not args.report.is_file():
            print(f"ERROR: {args.report} not found — the scanner wrote no report, so there is nothing to ratchet", file=sys.stderr)
            return 2
        try:
            report = json.loads(args.report.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            print(f"ERROR: {args.report} is not JSON ({exc}) — the scanner did not finish", file=sys.stderr)
            return 2
        ceiling = ceilings.get(args.tool)
        if not isinstance(ceiling, dict):
            print(f"ERROR: no ceiling declared for {args.tool}", file=sys.stderr)
            return 2
        counts, reported_version = count_findings(args.tool, report)
        declared_version = normalise_version(args.tool_version)
        if args.tool_version and declared_version is None:
            print(f"ERROR: --tool-version {args.tool_version!r} contains no version number", file=sys.stderr)
            return 2
        # Both directions. A scanner that declares a version in its report and
        # is also told one on the command line must have them agree; taking
        # either silently would let the two drift apart unnoticed, which is the
        # one-directional shape this gate's own coverage arm exists to refuse.
        if reported_version and declared_version and reported_version != declared_version:
            problems.append(
                f"{args.tool}: the report says it was produced by {reported_version} but the binary "
                f"reports itself as {declared_version} — one of the two is not the scanner that ran"
            )
        version = reported_version or declared_version
        problems += check_report(args.tool, ceiling, counts, version)
        measured = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
        scanned = f"{args.tool} {version or 'version unreported'}: {measured}"

    if problems:
        print(f"scanner-ratchet: {len(problems)} finding(s) — {scanned}", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1

    print(f"scanner-ratchet: OK — {scanned}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
