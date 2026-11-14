#!/usr/bin/env python3
"""A named deferral must have its scope in the tracker, and the tracker must
not hold scope for a deferral nothing names.

Why this exists
---------------
Six sub-phases of the hardening program were deferred with a letter suffix —
3.5+, 5b, 7b+, 9b, 10b, 11b — and ``ROADMAP.md`` said each was "tracked in
``docs/audit/PROGRESS.md``". That file is in ``.gitignore``. It was never
committed, so six named commitments had their scope recorded only by a
filename pointing at nothing. ``docs/audit/DEFERRED_SUBPHASES.md`` was
written to replace it, and is committed.

Writing that replacement was itself an audit, and the audit read
``ROADMAP.md`` and stopped there. Two more lettered deferrals were named
elsewhere in the tree and appeared in no list of them:

``6b``
    ``docs/decisions/0005-storage-consolidation.md`` — "Follow-up (Phase 6b,
    tracked in ``docs/audit/PROGRESS.md``). Wire the model into the
    managed-mode sizing guide and the LLM-cost dashboard". The same dangling
    pointer, in a document nobody re-read when the pointer was corrected.

``8b``
    ``services/agents/app/llm/prompt_registry.py`` — "Migration of the
    existing inline prompts is tracked as 8b". One module reads the registry;
    seventeen still declare their prompts inline.

Neither was recoverable by looking harder at the roadmap, because neither was
in it. The failure is structural: the set of deferrals lived in a reader's
head, so a deferral written down anywhere else was invisible by construction.
That is what this derives instead.

What it checks, in both directions
----------------------------------

``untracked-deferral``
    A lettered sub-phase named in deferral language anywhere in the tracked
    tree, with no section in the tracker and no record that it landed. This
    is the direction that produced 6b and 8b.

``unreferenced-section``
    The same question asked backwards. A tracker section for a sub-phase
    nothing else mentions is a commitment that has been renamed, absorbed or
    quietly dropped, and a tracker carrying scope for work nobody refers to
    decays into the thing it replaced. A gate that only looks one way passes
    while drift accumulates in the other.

``dangling-tracker-pointer``
    A tracked file still sending a reader to ``docs/audit/PROGRESS.md`` for
    the scope of something. Prose describing it as the gitignored file it was
    is fine and must stay fine — the tracker's own preamble and ``ROADMAP.md``
    both explain the history — so a mention within three lines of a phrase
    placing it in the past is not a finding.

``stale-landed-record`` / ``stale-exclusion``
    The recorded lists below, read back. All are shrink-only and checked in
    both directions: an entry naming a sub-phase nothing mentions is stale,
    an entry for one the tracker has since given a section to is a
    contradiction, and an excluded path matching no tracked file is excusing
    a surface that is no longer there. Every exclusion is printed on every
    run, clean or not. Without both, an exemption list becomes the place a
    real orphan goes to hide.

What it reads
-------------
Every tracked text file, from ``git ls-files`` — the defect was a deferral
written in a source docstring and in an ADR, so restricting the corpus to the
roadmap would rebuild the blind spot this exists to remove. Four historical
surfaces are excluded by prefix and each says why, as are this gate and its
tests, which quote every shape they detect.

Two strictnesses, deliberately, because the two directions fail differently.
Deciding something *is* an untracked deferral fails a build on a heuristic,
so it takes explicit deferral language: ``tracked as 5b``, ``Follow-up (Phase
6b``, or a bare ``Phase 6b``. Deciding a tracker section *is* referenced only
credits a section that already exists, so it takes any occurrence of the
identifier on a line that also talks about phases, deferrals or tracking —
which is what finds ``7b+``, whose only live mention reads "7b+ (…) scoped
in". Both print what they matched, so a credit nobody would accept is visible
by reading rather than by trusting the exit code.

Identifiers match a lowercase letter only. The hardening program writes its
deferrals lowercase throughout (``5b``, ``7b+``); ``Phase 1A``, ``Phase 2C``
and ``Phase 4B`` belong to a different, completed plan, and folding the two
vocabularies together would make this gate demand tracker sections for
another plan's finished work.

Usage
-----

::

    python3 scripts/check_deferral_tracker.py              # gate
    python3 scripts/check_deferral_tracker.py --list       # every mention found
    python3 scripts/check_deferral_tracker.py --json
    python3 scripts/check_deferral_tracker.py --self-test

Exit codes: 0 clean, 1 findings, 2 the scan itself could not run.

Note that the corpus comes from ``git ls-files``, which does not list
untracked files. Run this with your changes staged.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

# `scripts/` is on sys.path when this file is run as a program, but not when a
# test loads it by path with importlib. gate_toolkit sits beside it either way.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_main  # noqa: E402

#: The committed tracker. Every open lettered deferral's scope lives here.
TRACKER = "docs/audit/DEFERRED_SUBPHASES.md"

#: The tracker that was never committed. A reader sent here finds nothing.
DEAD_TRACKER = "docs/audit/PROGRESS.md"

# --------------------------------------------------------------------------
# Recorded exceptions. Shrink-only, and checked in both directions: an entry
# that stops describing the tree fails the build rather than sitting here.
# --------------------------------------------------------------------------

#: Lettered sub-phases that shipped, so a mention of one is a reference to
#: finished work rather than an open commitment with nowhere to record it.
#: Each says where that can be confirmed, because a bare list of identifiers
#: is a second place for drift to hide.
LANDED_SUBPHASES: dict[str, str] = {
    "4a": "shipped — ROADMAP.md Phase 4 records '4a/4b/4c landed'; 4a is the de-circularised DAC candidate-rule gate",
    "4b": "shipped — ROADMAP.md Phase 4; the executable-vs-imported detection truth table",
    "4c": "shipped — ROADMAP.md Phase 4; what remains of Phase 4 is a funded provider key, an account action rather than a sub-phase",
    "9a": "shipped — ROADMAP.md Phase 9, the autonomy-safety policy layer; its wiring is 9b, which the tracker holds",
}

#: Surfaces excluded from the scan, with the reason. All four record what was
#: true when they were written; editing one so it names today's paths would
#: make it claim a history it does not have.
HISTORICAL: dict[str, str] = {
    "CHANGELOG.md": "append-only release history — an entry describes the tree at that release",
    "RELEASES.md": "published release notes, same reason",
    "docs/community-feedback/": "dated snapshots of feedback, kept as received",
    "plans/": "plan documents are kept as written; the tree records what was built from them",
}

#: This gate and its tests quote the two orphans and the dangling pointer they
#: exist to catch. Scanning them would make it flag itself, which is the same
#: exclusion ``check_attribution.py`` keeps for the same reason.
#:
#: Unlike ``HISTORICAL`` these are *not* checked for staleness. The gate is
#: routinely run as a copy of ``scripts/`` in a tree that has no tests — the
#: empty-tree probe and the pre-fix proof both do exactly that — and an
#: absent test file there is the normal case, not drift. It also fails in the
#: safe direction: rename the test file and this stops excusing it, so the
#: gate starts flagging its own fixtures loudly rather than going quiet.
SELF_REFERENTIAL: dict[str, str] = {
    "scripts/check_deferral_tracker.py": "the gate itself — its docstring quotes every shape it detects",
    "scripts/tests/test_check_deferral_tracker.py": "its tests, which inject those shapes deliberately",
}

# --------------------------------------------------------------------------
# Patterns
# --------------------------------------------------------------------------

#: ``5b``, ``10b``, ``7b+``, ``3.5+``. Lowercase letter only — see the module
#: docstring. The lookarounds keep the token off the tail of a hex digest
#: (``c8b9d670``), a model tag (``llama3.1:8b``) and a version (``v8.1.0``).
#: The trailing ``\.\w`` rather than a bare ``.`` is not a detail: half these
#: mentions end a sentence, and excluding every following full stop silently
#: lost "tracked as 8b." and "Phase 12c." — a gate blind to the most ordinary
#: way of writing the thing it looks for.
_ID = r"(?:\d{1,2}(?:\.\d{1,2})?[a-z]\+?|\d{1,2}\.\d{1,2}\+)"
_TOKEN = rf"(?<![\w.+:/-]){_ID}(?![\w+-]|\.\w)"

#: "tracked as 5b", "tracked as non-blocking 3.5+", "deferred to 12c".
_DEFERRED_AS = re.compile(rf"(?i:tracked\s+as|deferred\s+(?:as|to|until))\s+(?i:non-blocking\s+)?({_TOKEN})")

#: "Follow-up (Phase 6b, tracked in …)" — the shape the ADR used.
_FOLLOW_UP = re.compile(rf"(?i:follow-?up)\s*\(\s*(?i:phase)\s+({_TOKEN})")

#: A bare "Phase 6b". Weaker on its own, which is what LANDED_SUBPHASES is for.
_PHASE = re.compile(rf"\b(?i:phase)\s+({_TOKEN})")

_MARKERS = (_DEFERRED_AS, _FOLLOW_UP, _PHASE)

#: Any identifier, for the generous direction.
_ANY_ID = re.compile(f"({_TOKEN})")

#: What makes a line one that could be talking about a deferral at all.
_DEFERRAL_CONTEXT = re.compile(r"phase|defer|track|scoped|follow-?up", re.I)

#: ``## 5b — backfill and replay-from-offset``
_SECTION = re.compile(rf"^#{{1,3}}\s+({_TOKEN})\s*[—:-]")

#: Prose placing the dead tracker in the past rather than pointing at it.
_QUALIFIED = re.compile(
    r"gitignore|never committed|was never|previously|used to|no longer|historical|replaced by|replaces|is gone|does not exist",
    re.I,
)

#: How far from a mention of the dead tracker the qualifying phrase may sit.
#: The tracker's own preamble puts it in the next paragraph.
_QUALIFY_WINDOW = 3


def _tracked_files(root: Path) -> list[str]:
    """Every tracked path, per git.

    git rather than ``Path.rglob`` so build output and ``node_modules`` cannot
    contribute a mention, and so the corpus is the set under review.
    """
    out = subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["git", "ls-files", "-z"],
        capture_output=True,
        text=True,
        check=False,
        cwd=root,
    )
    if out.returncode != 0:
        return []
    return [name for name in out.stdout.split("\0") if name]


def sections(text: str) -> dict[str, int]:
    """``{identifier: line number}`` for every section the tracker declares."""
    found: dict[str, int] = {}
    for number, line in enumerate(text.splitlines(), 1):
        match = _SECTION.match(line)
        if match is not None:
            found.setdefault(match.group(1), number)
    return found


def named_as_deferral(line: str) -> set[str]:
    """Identifiers this line names in deferral language."""
    return {match.group(1) for marker in _MARKERS for match in marker.finditer(line)}


def mentioned(line: str) -> set[str]:
    """Identifiers on a line that is talking about phases or deferrals."""
    if _DEFERRAL_CONTEXT.search(line) is None:
        return set()
    return {match.group(1) for match in _ANY_ID.finditer(line)}


def dead_tracker_pointers(lines: list[str]) -> list[int]:
    """Line numbers sending a reader to the dead tracker with no qualifier."""
    unqualified: list[int] = []
    for index, line in enumerate(lines):
        if DEAD_TRACKER not in line:
            continue
        window = lines[max(0, index - _QUALIFY_WINDOW) : index + _QUALIFY_WINDOW + 1]
        if _QUALIFIED.search("\n".join(window)) is None:
            unqualified.append(index + 1)
    return unqualified


def scan(root: Path, *, historical: dict[str, str] | None = None) -> dict:
    """Read the tracker and the tree. No verdict here."""
    excluded = {**HISTORICAL, **SELF_REFERENTIAL} if historical is None else historical
    tracker_path = root / TRACKER
    if not tracker_path.is_file():
        return {"error": f"{TRACKER} is missing; there is no tracker to check the tree against"}

    declared = sections(tracker_path.read_text(encoding="utf-8"))

    deferrals: dict[str, list[str]] = {}
    references: dict[str, list[str]] = {}
    pointers: list[str] = []
    read = 0
    matched_exclusions: set[str] = set()

    for relative in _tracked_files(root):
        hit = next((prefix for prefix in excluded if relative == prefix or relative.startswith(prefix)), None)
        if hit is not None:
            matched_exclusions.add(hit)
            continue
        try:
            text = (root / relative).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        read += 1
        lines = text.splitlines()

        pointers.extend(f"{relative}:{number}" for number in dead_tracker_pointers(lines))

        for number, line in enumerate(lines, 1):
            where = f"{relative}:{number}"
            for identifier in named_as_deferral(line):
                deferrals.setdefault(identifier, []).append(where)
            if relative == TRACKER:
                # The tracker cannot be its own evidence that a section is
                # still referenced; that is how an entry outlives its work.
                continue
            for identifier in mentioned(line):
                references.setdefault(identifier, []).append(where)

    return {
        "root": root,
        "declared": declared,
        "deferrals": deferrals,
        "references": references,
        "pointers": pointers,
        "files_read": read,
        "excluded": excluded,
        "must_match": {prefix for prefix in excluded if prefix not in SELF_REFERENTIAL},
        "matched_exclusions": matched_exclusions,
    }


def evaluate(scanned: dict, *, landed: dict[str, str] | None = None) -> tuple[list[str], list[str]]:
    """``(findings, credits)`` — what is wrong, and what the verdict rests on."""
    shipped = LANDED_SUBPHASES if landed is None else landed
    declared: dict[str, int] = scanned["declared"]
    deferrals: dict[str, list[str]] = scanned["deferrals"]
    references: dict[str, list[str]] = scanned["references"]
    findings: list[str] = []
    credits: list[str] = []

    # untracked-deferral — the direction that produced 6b and 8b.
    for identifier, where in sorted(deferrals.items()):
        if identifier in declared:
            continue
        if identifier in shipped:
            credits.append(f"{identifier}: recorded as landed — {shipped[identifier]}")
            continue
        findings.append(
            f"untracked-deferral: {identifier} is named as a deferral at {', '.join(where[:3])} and "
            f"{TRACKER} has no section for it. Either add one in the voice of the others, or record it "
            f"in LANDED_SUBPHASES with where that can be confirmed"
        )

    # unreferenced-section — the same question, backwards.
    for identifier, line in sorted(declared.items()):
        where = references.get(identifier) or []
        if not where:
            findings.append(
                f"unreferenced-section: {TRACKER}:{line} holds scope for {identifier} and nothing outside "
                f"the tracker mentions it. Either the work was renamed or absorbed and the section should "
                f"say so, or the reference it was written against has been deleted"
            )
            continue
        credits.append(f"{identifier}: section at {TRACKER}:{line}, referenced at {where[0]}")

    for where in scanned["pointers"]:
        findings.append(
            f"dangling-tracker-pointer: {where} sends a reader to {DEAD_TRACKER}, which is gitignored and "
            f"was never committed. Point at {TRACKER}, or say in the same breath that the file is gone"
        )

    # The exemption list, read back. An entry nothing names is describing a
    # tree that has moved; an entry the tracker now has a section for says two
    # contradictory things about one sub-phase.
    for identifier in sorted(shipped):
        if identifier in declared:
            findings.append(
                f"stale-landed-record: LANDED_SUBPHASES records {identifier} as shipped and {TRACKER} now "
                f"has a section for it. One of the two is wrong"
            )
        elif identifier not in deferrals and identifier not in references:
            findings.append(
                f"stale-landed-record: LANDED_SUBPHASES records {identifier} and nothing in the tree names "
                f"it. Remove the entry — an exemption nobody needs is where a real one goes to hide"
            )

    # The exclusion list, read back, for the same reason — and printed either
    # way, because an exclusion nobody reads is indistinguishable from a gate
    # that never looked.
    for prefix, reason in sorted(scanned["excluded"].items()):
        if prefix in scanned["matched_exclusions"]:
            credits.append(f"excluded: {prefix} — {reason}")
        elif prefix in scanned["must_match"]:
            findings.append(f"stale-exclusion: '{prefix}' is excluded ({reason}) and no tracked file matches it")

    return findings, credits


def main(argv: list[str] | None = None, *, landed: dict[str, str] | None = None, historical: dict[str, str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check every lettered deferral against the committed tracker.")
    parser.add_argument("--self-test", action="store_true", help="prove the gate fails closed and still detects each violation")
    parser.add_argument("--list", action="store_true", help="print every mention found, then the verdict")
    parser.add_argument("--json", dest="as_json", action="store_true", help="machine-readable scan output")
    parser.add_argument("--repo-root", type=Path, default=None, help="the tree to inspect")
    args = parser.parse_args(argv)

    if args.self_test:
        with tempfile.TemporaryDirectory(prefix="aisoc-deferral-tracker-") as scratch:
            extra = _injected_cases(Path(scratch))
        return self_test_main(Path(__file__).name, [], extra=extra)

    root = (args.repo_root or repo_root()).resolve()
    scanned = scan(root, historical=historical)
    if "error" in scanned:
        print(f"REFUSED: {scanned['error']}")
        return 2

    declared: dict[str, int] = scanned["declared"]

    print(f"root: {root}")
    print(f"tracker: {TRACKER} — {len(declared)} section(s): {', '.join(sorted(declared)) or 'none'}")
    print(f"corpus: {scanned['files_read']} tracked text file(s) read, {len(scanned['excluded'])} path(s) excluded and named below")

    # Non-vacuity. A tracker with no sections and a corpus of no files both
    # produce zero findings, and neither says anything about the tree.
    if not declared:
        print(f"REFUSED: {TRACKER} declares no sections; a clean verdict here would describe a tracker the gate never parsed")
        return 2
    if not scanned["files_read"]:
        print("REFUSED: no tracked text files were read; there is nothing to check the tracker against")
        return 2

    findings, credits = evaluate(scanned, landed=landed)

    if args.as_json:
        print(
            json.dumps(
                {"declared": declared, "deferrals": scanned["deferrals"], "pointers": scanned["pointers"], "findings": findings},
                indent=2,
                sort_keys=True,
            )
        )

    if args.list:
        for identifier, where in sorted(scanned["deferrals"].items()):
            for location in where:
                print(f"  named as a deferral  {identifier:6} {location}")

    for credit in credits:
        print(f"  {credit}")

    if findings:
        print(f"\nFAIL: the deferral record and the tree disagree ({len(findings)} finding(s))")
        for finding in findings:
            print(f"  - {finding}")
        return 1

    print(
        f"\nOK: {len(declared)} tracked deferral(s), each named somewhere and each named deferral tracked; "
        f"{len(LANDED_SUBPHASES)} recorded as landed; no tracked file points at {DEAD_TRACKER}"
    )
    return 0


# ─── Self-test ───────────────────────────────────────────────────────────────
#
# The empty-tree refusal comes from the toolkit. These are the cases only this
# gate can express: a violation of each rule it enforces, plus the near misses
# that would make it a nuisance, injected into scratch trees — because a gate
# that has never failed is not known to work.
#
# The scratch trees carry their own exemption lists. The module-level ones
# describe this repository, and every entry would read as stale against a
# four-file tree, which would drown the case each probe is actually making.

_TRACKER_BODY = "# The lettered deferrals\n\n## 5b — backfill and replay-from-offset\n\n**Status: open.**\n"
_ROADMAP = "- [x] Phase 5 — Data spine (backfill/replay-from-offset tracked as 5b)\n"
_HISTORICAL = {"CHANGELOG.md": "append-only release history"}


def _tree(root: Path, files: dict[str, str]) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "-C", str(root), "init", "-q"], check=True)  # noqa: S603
    for relative, body in files.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)  # noqa: S603
    return root


def _files(**extra: str) -> dict[str, str]:
    """A minimal clean tree: one tracked section, one reference, one excluded
    surface so the exclusion list is not itself reported stale."""
    return {TRACKER: _TRACKER_BODY, "ROADMAP.md": _ROADMAP, "CHANGELOG.md": "## [Unreleased]\n", **extra}


def _verdict(root: Path, landed: dict[str, str] | None = None) -> int:
    """``main`` over ``root`` with its output swallowed.

    The probes below care only about the exit status, and fifteen verdicts
    printed in full would bury the self-test's own result.
    """
    with contextlib.redirect_stdout(io.StringIO()):
        return main(["--repo-root", str(root)], landed=landed or {}, historical=_HISTORICAL)


def _injected_cases(scratch: Path) -> list[tuple[str, bool]]:
    adr = f"- **Follow-up (Phase 6b, tracked in `{DEAD_TRACKER}`).** Wire the model in.\n"
    docstring = '"""Migration of the existing inline prompts is tracked as 8b."""\n'
    qualified = f"`{DEAD_TRACKER}` is in `.gitignore` and was never committed.\n"
    across_paragraph = f"See `{DEAD_TRACKER}`.\n\nThat file was never committed.\n"

    return [
        (
            "a tree whose every named deferral has a section passes",
            _verdict(_tree(scratch / "clean", _files())) == 0,
        ),
        (
            "untracked-deferral: the ADR shape, 'Follow-up (Phase 6b, …)' with no section, fails",
            _verdict(_tree(scratch / "orphan-adr", _files(**{"docs/decisions/0005.md": adr}))) == 1,
        ),
        (
            "untracked-deferral: the docstring shape, 'tracked as 8b' in source, fails",
            _verdict(_tree(scratch / "orphan-src", _files(**{"services/a/p.py": docstring}))) == 1,
        ),
        (
            "untracked-deferral: a bare 'Phase 12c' in a doc fails",
            _verdict(_tree(scratch / "orphan-bare", _files(**{"docs/x.md": "Deferred to Phase 12c.\n"}))) == 1,
        ),
        (
            "a sub-phase recorded as landed is not an untracked deferral",
            _verdict(_tree(scratch / "landed", _files(**{"docs/x.md": "Phase 4c closed the row.\n"})), landed={"4c": "shipped"}) == 0,
        ),
        (
            "stale-landed-record: an exemption nothing in the tree names fails",
            _verdict(_tree(scratch / "stale-landed", _files()), landed={"4c": "shipped"}) == 1,
        ),
        (
            "stale-landed-record: an exemption the tracker has a section for fails",
            _verdict(_tree(scratch / "contradiction", _files()), landed={"5b": "shipped"}) == 1,
        ),
        (
            "unreferenced-section: a section nothing outside the tracker mentions fails",
            _verdict(_tree(scratch / "unreferenced", {**_files(), "ROADMAP.md": "- [x] Phase 5 — Data spine\n"})) == 1,
        ),
        (
            "dangling-tracker-pointer: an unqualified pointer at the dead tracker fails",
            _verdict(_tree(scratch / "pointer", _files(**{"docs/y.md": f"Scope lives in `{DEAD_TRACKER}`.\n"}))) == 1,
        ),
        (
            "prose calling the dead tracker gitignored and never committed passes",
            _verdict(_tree(scratch / "qualified", _files(**{"docs/y.md": qualified}))) == 0,
        ),
        (
            "a qualifier in the next paragraph passes, as the tracker's own preamble has it",
            _verdict(_tree(scratch / "qualified-para", _files(**{"docs/y.md": across_paragraph}))) == 0,
        ),
        (
            "a historical surface naming a deferral and the dead tracker is not a finding",
            _verdict(_tree(scratch / "historical", _files(**{"CHANGELOG.md": f"tracked as 9b in `{DEAD_TRACKER}`\n"}))) == 0,
        ),
        (
            "stale-exclusion: an excluded path matching no tracked file fails",
            _verdict(_tree(scratch / "stale-exclusion", {TRACKER: _TRACKER_BODY, "ROADMAP.md": _ROADMAP})) == 1,
        ),
        (
            "the other plan's uppercase 'Phase 4B' is not a lettered deferral",
            _verdict(_tree(scratch / "uppercase", _files(**{"docs/z.md": "Phase 4B — mobile responder PWA.\n"}))) == 0,
        ),
        (
            "a model tag and a hex digest do not read as identifiers",
            _verdict(_tree(scratch / "nearmiss", _files(**{"docs/z.md": "Phase notes: llama3.1:8b tracked at c8b9d670.\n"}))) == 0,
        ),
        (
            "a tracker declaring no sections is refused rather than called clean",
            _verdict(_tree(scratch / "vacuous", {**_files(), TRACKER: "# The lettered deferrals\n"})) == 2,
        ),
    ]


if __name__ == "__main__":
    raise SystemExit(main())
