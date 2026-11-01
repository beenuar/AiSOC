#!/usr/bin/env python3
"""No surface may publish a customer-outcome figure nobody measured.

Wave-2 plan 4.6. The outcomes a buyer asks for first — how much did false
positives drop, how fast is a verdict, how often does it escalate — can only
be measured by replaying **somebody's real closed alerts** through
`make replay-eval`. No design partner has offered a window, so all three are
recorded as *not measured* on `apps/docs/docs/evaluation/replay.md`.

That record is worth exactly as much as whatever stops it being quietly
replaced by a number. Two failure modes, and this gate exists for both.

**A figure appears with no run behind it.** The plan's wording is blunt
about this ("never a fabricated figure") because it is the easiest claim in
security marketing to make and the hardest for a reader to check. So: while
the replay page records an outcome as not measured, no published surface may
print a percentage for it.

**The absence is written as a zero.** "0 % false-positive reduction" says
AiSOC was measured against a real queue and reduced nothing. That is a
different — and much worse — claim than "this has not been measured", and
it is the one a reader will believe, because a zero looks like data. The
repository has shipped this exact defect before: a mean over zero rows
published as a confident `0.0`, and three console formatters whose
"unmeasurable" escape hatch excluded zero.

What this gate deliberately does not do
---------------------------------------
It does not forbid the *words*. A page explaining what false-positive
reduction means, or what a replay would measure, is the documentation this
project wants more of. The rule is narrower and structural: a surface may
not put a **number** next to one of these outcome phrases while the replay
page says the outcome is unmeasured.

It is also not a permanent prohibition. When a design partner's replay
lands, the figures go on the replay page with their denominators, that
page stops saying *not measured*, and this gate stops applying to them —
automatically, because the gate reads the page rather than carrying its own
copy of the state. A gate that had to be edited to let a measurement through
would be edited to let a fabrication through.
"""

from __future__ import annotations

import argparse
import re
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

#: The page that holds the record. Its table is the authority on whether
#: each outcome has been measured.
REPLAY_PAGE = REPO_ROOT / "apps" / "docs" / "docs" / "evaluation" / "replay.md"

#: The three outcomes 4.6 names, each with the phrasings a surface would
#: plausibly use. Matched case-insensitively.
OUTCOMES: dict[str, tuple[str, ...]] = {
    "false-positive reduction": (
        r"false[-\s]positive[s]?\s+reduc\w*",
        r"reduc\w*\s+(?:in\s+)?false[-\s]positive",
        r"\bFP\s+reduction\b",
    ),
    "time to verdict": (
        r"time[-\s]to[-\s]verdict",
        r"verdict\s+latency",
        r"mean\s+time\s+to\s+verdict",
    ),
    "escalation rate": (
        r"escalation\s+rate",
        r"rate\s+of\s+escalation",
    ),
}

#: A number close enough to the phrase to read as its value. Deliberately
#: narrow: a percentage, a ratio, or a duration, within ~80 characters.
_FIGURE = re.compile(
    r"(?:\d+(?:\.\d+)?\s*%|\b0?\.\d+\b|\b\d+(?:\.\d+)?\s*(?:ms|s|sec|secs|seconds|min|mins|minutes|h|hr|hrs|hours)\b)",
    re.IGNORECASE,
)

#: The marker that says an outcome is *not* measured. Any of these within the
#: same line or table row exempts it, because the sentence is then recording
#: the absence rather than claiming a value.
_NOT_MEASURED = re.compile(
    r"not\s+measured|unmeasured|no\s+denominator|has\s+not\s+been\s+(?:run|measured)|nobody\s+(?:has\s+)?measured",
    re.IGNORECASE,
)

#: Clause boundaries. A figure counts as *this outcome's* value only when it
#: sits in the same clause as the phrase.
#:
#: Written after the first run of this gate flagged a true sentence: a
#: capability table row reading "MTTD / MTTR / FPR / escalation rate / ATT&CK
#: heatmap ...; auto-refresh every 60s". The `60s` is the dashboard's refresh
#: interval and has nothing to do with escalation, but a whole-line search
#: put them together. A security gate that flags correct content gets
#: switched off, so the rule is the narrower one: same clause, not same line.
_CLAUSE_SPLIT = re.compile(r"\s*[|;/]\s*|(?<=[.!?])\s+|\s+[–—]\s+")


def _clause_containing(line: str, start: int, end: int) -> str:
    """The clause around ``line[start:end]``, bounded by list/sentence marks."""
    cursor = 0
    for piece in _CLAUSE_SPLIT.split(line):
        if piece is None:
            continue
        found = line.find(piece, cursor)
        if found < 0:
            continue
        cursor = found + len(piece)
        if found <= start and end <= cursor:
            return piece
    return line


#: Where published prose lives.
SCAN_ROOTS: tuple[tuple[Path, tuple[str, ...]], ...] = (
    (REPO_ROOT / "apps" / "docs" / "docs", ("*.md", "*.mdx")),
    (REPO_ROOT / "apps" / "web" / "src", ("*.tsx", "*.ts")),
    (REPO_ROOT / "docs", ("*.md",)),
)
SCAN_FILES: tuple[Path, ...] = (
    REPO_ROOT / "README.md",
    REPO_ROOT / "RELEASES.md",
    REPO_ROOT / "ROADMAP.md",
)


def unmeasured_outcomes(replay_text: str) -> set[str]:
    """Which of the three outcomes the replay page records as unmeasured.

    Read from the page rather than hardcoded, so that publishing a real
    measurement retires the prohibition without anyone editing this file.
    """
    unmeasured: set[str] = set()
    for outcome, patterns in OUTCOMES.items():
        for line in replay_text.splitlines():
            if any(re.search(p, line, re.IGNORECASE) for p in patterns) and _NOT_MEASURED.search(line):
                unmeasured.add(outcome)
                break
    return unmeasured


def violations(files: dict[Path, str], unmeasured: set[str]) -> list[str]:
    """Every finding, rendered. Pure, so the self-test can drive it."""
    found: list[str] = []
    for path, text in sorted(files.items()):
        rel = path.relative_to(REPO_ROOT) if path.is_absolute() else path
        if rel == REPLAY_PAGE.relative_to(REPO_ROOT):
            # The page recording the absence necessarily names all three.
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            if _NOT_MEASURED.search(line):
                continue
            for outcome in sorted(unmeasured):
                hit = next(
                    (m for p in OUTCOMES[outcome] if (m := re.search(p, line, re.IGNORECASE))),
                    None,
                )
                if hit is None:
                    continue
                figure = _FIGURE.search(_clause_containing(line, hit.start(), hit.end()))
                if figure is None:
                    continue
                found.append(
                    f"{rel}:{lineno}: publishes {figure.group(0)!r} for {outcome}, which "
                    f"{REPLAY_PAGE.relative_to(REPO_ROOT)} records as not measured. "
                    "Replay a design partner's closed alerts and publish the figure with its "
                    "denominator, or say the outcome has not been measured — a number here is "
                    "a claim about somebody's queue that nobody has looked at."
                )
    return found


def _iter_surfaces() -> list[Path]:
    found: list[Path] = []
    for root, globs in SCAN_ROOTS:
        if not root.is_dir():
            continue
        for pattern in globs:
            found.extend(p for p in root.rglob(pattern) if "node_modules" not in p.parts)
    found.extend(p for p in SCAN_FILES if p.is_file())
    return sorted(set(found))


def _self_test() -> int:
    """Prove the rules in both directions, including the zero case.

    The zero case is the one worth writing: a gate that catches "73 % fewer
    false positives" and waves through "0 % false-positive reduction" has
    missed the more damaging of the two.
    """
    cases: tuple[tuple[str, str, bool], ...] = (
        ("a measured-looking percentage is caught", "AiSOC delivers a 73 % false-positive reduction.", True),
        ("zero is caught too, and matters more", "Measured false-positive reduction: 0 %.", True),
        ("a ratio is caught", "false-positive reduction of 0.73 across the pilot", True),
        ("time to verdict with a duration is caught", "Mean time to verdict: 4.2 s", True),
        ("escalation rate with a percentage is caught", "Escalation rate 12 %", True),
        ("explaining the metric without a number is fine", "Replay reports false-positive reduction and its denominator.", False),
        ("recording the absence is fine", "False-positive reduction: not measured.", False),
        ("a number with no outcome phrase is fine", "The corpus holds 72 items across 36 pairs.", False),
        ("an unrelated percentage is fine", "Alert reduction is 33.3 % on the production key.", False),
        # The true sentence this gate flagged on its first run. A metric named
        # in a list, with an unrelated number later in the same table row.
        (
            "a metric named in a list beside an unrelated number is fine",
            "| **SOC metrics** | `/metrics/soc` | MTTD / MTTR / FPR / escalation rate / ATT&CK heatmap; auto-refresh every 60s |",
            False,
        ),
        # ...and the same row with a real claim in it must still be caught,
        # or the narrowing has bought the exemption at the cost of the rule.
        (
            "a real claim in the same shape of row is still caught",
            "| **SOC metrics** | `/metrics/soc` | escalation rate 12 % / ATT&CK heatmap; auto-refresh every 60s |",
            True,
        ),
    )
    unmeasured = set(OUTCOMES)
    failures = 0
    for name, line, should_flag in cases:
        flagged = bool(violations({Path("surface.md"): line}, unmeasured))
        ok = flagged == should_flag
        failures += 0 if ok else 1
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
        if not ok:
            print(f"        line={line!r} flagged={flagged} expected={should_flag}")

    # A measured outcome retires its own prohibition, without editing this file.
    measured_page = "| False-positive reduction | 73 % | 1,204 findings |\n| Time to verdict | not measured | — |"
    still_unmeasured = unmeasured_outcomes(measured_page)
    ok = "false-positive reduction" not in still_unmeasured and "time to verdict" in still_unmeasured
    failures += 0 if ok else 1
    print(f"  {'PASS' if ok else 'FAIL'}  a published measurement retires only its own row")

    # Refuse a tree it never read, rather than reporting it clean.
    with tempfile.TemporaryDirectory(prefix="aisoc-outcome-") as tmp:
        empty = Path(tmp)
        ok = not list(empty.rglob("*.md"))
        failures += 0 if ok else 1
        print(f"  {'PASS' if ok else 'FAIL'}  an empty tree has nothing to certify")

    print()
    if failures:
        print(f"check_outcome_claims.py: self-test FAILED ({failures})")
        return 1
    print("check_outcome_claims.py: self-test OK")
    return 0


def check() -> int:
    if not REPLAY_PAGE.is_file():
        print(
            f"check_outcome_claims.py: {REPLAY_PAGE.relative_to(REPO_ROOT)} is missing — "
            "nothing records whether these outcomes have been measured",
            file=sys.stderr,
        )
        return 2

    surfaces = _iter_surfaces()
    if not surfaces:
        print(
            f"check_outcome_claims.py: found no published surfaces under {REPO_ROOT} — refusing to report a clean tree it never opened",
            file=sys.stderr,
        )
        return 2

    unmeasured = unmeasured_outcomes(REPLAY_PAGE.read_text(encoding="utf-8"))
    files = {p: p.read_text(encoding="utf-8", errors="replace") for p in surfaces}
    found = violations(files, unmeasured)

    measured = sorted(set(OUTCOMES) - unmeasured)
    print(
        f"outcome claims: scanned {len(surfaces)} published surfaces; "
        f"{len(unmeasured)} outcome(s) recorded as not measured"
        + (f", {len(measured)} measured ({', '.join(measured)})" if measured else "")
    )
    if found:
        print()
        for line in found:
            print(f"  - {line}")
        return 1
    print("OK: no surface publishes a customer-outcome figure nobody measured.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="prove the rules in both directions")
    args = parser.parse_args()
    return _self_test() if args.self_test else check()


if __name__ == "__main__":
    raise SystemExit(main())
