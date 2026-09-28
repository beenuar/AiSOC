#!/usr/bin/env python3
"""A backend failure must never render as a safety verdict.

The shape
---------
`LookupForm` held a `result` and a `notFound` flag, and its `catch` had
nowhere to put *"this did not work"* except the flag that means *"we checked,
and it is clean"*::

    try {
      const r = await threatIntelApi.lookup(query.trim());
      setResult(r);
    } catch {
      setNotFound(true);   // -> renders a green CLEAN badge
    }

So a transport error, a 5xx, or a route that did not exist all rendered as an
all-clear on the indicator the analyst had just typed in. It was not a latent
branch: the lookup called `/api/v1/enrichment/lookup`, which the API does not
serve, so **every** lookup took the `catch` and the panel had only ever been
capable of saying "clean".

This is the worst direction for a security product to fail in, and it is a
*shape* rather than a bug in one file — which is why it is gated rather than
only fixed.

What is flagged
---------------
A `catch` (or a rejection handler, or a `?? FALLBACK` on a failed read) whose
body assigns a **verdict word** — clean, safe, benign, not malicious, no
threats found. Those words are claims about the subject. A failure knows
nothing about the subject.

What is not flagged
-------------------
Setting an error state, rendering "not checked", rethrowing, logging, or
assigning an empty list. An empty *list* is a different claim from a clean
*verdict*: "we hold no rows" is about the store, and the honesty gates for
mock data already cover a catch that invents rows.

Stdlib only, and a regex over the source rather than a parse: the corpus is
TypeScript and a TS parser is not available to a Python gate here. The cost
is that this sees text; the mitigation is the self-test corpus below, which
holds a known-bad and a known-good example of every pattern and asserts the
matcher separates them.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

# `scripts/` is on sys.path when this file is run as a program, but not when a
# test loads it by path with importlib. gate_toolkit sits beside it either way.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_if_requested

self_test_if_requested(__file__)

#: Words that assert the subject is safe. Matched against what a failure
#: handler *assigns*, never against prose.
VERDICT_RE = re.compile(
    r"""
    (?: setNotFound\s*\(\s*true
      | setClean\s*\(\s*true
      | \bstatus\s*:\s*['"](?:clean|safe|benign|ok)['"]
      | \bverdict\s*:\s*['"](?:clean|safe|benign|not_malicious|no_threat)['"]
      | \bmalicious\s*:\s*false
      | \bisMalicious\s*:\s*false
      | \bthreat\s*:\s*['"](?:none|clean)['"]
    )
    """,
    re.VERBOSE,
)

#: A `catch` block, including the bare form the defect used.
#:
#: The inner alternation allows one level of nesting, which is not
#: decoration: `catch { setResult({ status: 'clean' }) }` is the shape and a
#: flat `[^{}]*` body misses it. Two levels is beyond a regex and beyond this
#: gate — the corpus in `scripts/tests/` is what says which shapes are
#: covered.
CATCH_RE = re.compile(r"catch\s*(?:\([^)]*\))?\s*\{((?:[^{}]|\{[^{}]*\})*)\}", re.DOTALL)

#: `await x().catch(() => VERDICT)` and `.then(…, () => VERDICT)`.
REJECTION_RE = re.compile(r"\.catch\s*\(\s*\(?[^)]*\)?\s*=>\s*([^;\n]*)", re.DOTALL)

#: `data ?? { status: 'clean' }` — a fallback used when a read produced
#: nothing, which includes when it failed.
FALLBACK_RE = re.compile(r"\?\?\s*(\{[^{}]*\})")

SEARCH_ROOTS = ("apps/web/src", "packages/ui/src")
SUFFIXES = (".ts", ".tsx")

#: Files whose *subject* is the defect: the honesty test that asserts a
#: failure is not rendered as clean has to name the thing it forbids.
ALLOWED = ("ThreatIntelLookupHonesty.test.tsx",)


def _findings(text: str, rel: str) -> list[str]:
    hits: list[str] = []
    for pattern, label in ((CATCH_RE, "catch"), (REJECTION_RE, "rejection handler"), (FALLBACK_RE, "?? fallback")):
        for match in pattern.finditer(text):
            body = match.group(1)
            verdict = VERDICT_RE.search(body)
            if not verdict:
                continue
            line = text[: match.start()].count("\n") + 1
            hits.append(f"{rel}:{line}  a {label} assigns {verdict.group(0).strip()!r} — a failure is not a verdict about the subject")
    return hits


def scan(root: Path | None = None) -> tuple[list[str], int]:
    root = root or repo_root()
    findings: list[str] = []
    scanned = 0
    for base in SEARCH_ROOTS:
        directory = root / base
        if not directory.is_dir():
            continue
        for path in sorted(directory.rglob("*")):
            if path.suffix not in SUFFIXES or not path.is_file():
                continue
            if path.name in ALLOWED:
                continue
            scanned += 1
            findings += _findings(path.read_text(encoding="utf-8"), str(path.relative_to(root)))
    return findings, scanned


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="render the verdict (default)")
    parser.parse_args(argv)

    findings, scanned = scan()
    if not scanned:
        print(
            "check_failure_is_not_a_verdict: scanned zero files. A clean result over an empty scan is worse than no gate.",
            file=sys.stderr,
        )
        return 2
    if findings:
        print(f"FAIL — {len(findings)} place(s) render a failure as a safety verdict:", file=sys.stderr)
        for finding in findings:
            print(f"  - {finding}", file=sys.stderr)
        print(
            "\nReport the failure and name what was not checked. `status: 'failed'` with a reason "
            "is the shape `threatIntelApi.lookup` uses.",
            file=sys.stderr,
        )
        return 1
    print(f"OK: {scanned} console source files, none turn a failure into a clean verdict.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
