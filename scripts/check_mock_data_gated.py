#!/usr/bin/env python3
"""CI gate: fabricated domain data must be gated behind demo mode.

Roughly three dozen console components carried a `MOCK_*` / `DEMO_*` array of
plausible-looking security data — alerts on named hosts, connectors with
last-sync times, SLA percentages, MITRE coverage cells — and served it whenever
the API call failed or had not yet resolved. None of it consulted demo mode.

Two reasons that is worse than an empty state. A fabricated alert is
indistinguishable from a real one, so an operator has no way to know the backend
was unreachable. And SWR v2 disables `revalidateOnMount` whenever `fallbackData`
is supplied, so a component passing a mock unconditionally may never fetch at
all: the sample data is not a placeholder, it is what the view shows.

This gate checks the two mechanical shapes that caused it:

* `fallbackData:` receiving a bare `MOCK_*` / `DEMO_*` reference rather than one
  wrapped in `demoFallback(...)`.
* A `catch` block assigning a `MOCK_*` / `DEMO_*` value with no `canUseDemoData`
  check anywhere in the file.

It is deliberately shallow. It cannot prove a view is honest — only that these
two regressions have not reappeared. The reviewable property is that adding a
new ungated mock fallback fails here rather than shipping.

Usage:
    python scripts/check_mock_data_gated.py [--root apps/web/src]
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

MOCK_NAME = r"(?:MOCK|DEMO|SAMPLE|FALLBACK)_[A-Z0-9_]+"

#: A `fallbackData:` whose value mentions sample data. Whether it is gated is
#: decided separately by looking for `demoFallback(`, rather than with a
#: lookahead: `fallbackData:\s*(?!demoFallback\()` looks correct and is not,
#: because `\s*` backtracks to zero width and the lookahead then passes at the
#: space, letting `.*` find the name inside the wrapper it was meant to accept.
FALLBACK_WITH_MOCK = re.compile(rf"fallbackData:.*{MOCK_NAME}")

#: An assignment of a mock inside a file, e.g. `setRules(MOCK_RULES)`.
MOCK_ASSIGN = re.compile(rf"\bset[A-Z]\w*\(\s*{MOCK_NAME}")

#: Files exempt by nature: the gate helper itself, tests, and stories.
EXEMPT_SUFFIXES = (".test.ts", ".test.tsx", ".stories.tsx", "demoFallback.ts")

#: Editor placeholder text is not data presented as tenant state.
EXEMPT_NAMES = {
    "SAMPLE_BODIES",
    "SAMPLE_EVENT",
    "SAMPLE_SIGMA",
    "SAMPLE_KQL",
    "SAMPLE_EQL",
    "SAMPLE_SPL",
    "SAMPLE_ESQL",
    "SAMPLE_YAML",
    "SAMPLE_QUERY",
    "SAMPLE_RULE",
    "DEMO_EMAIL",
    "DEMO_PASSWORD",
}


def _is_exempt_name(line: str) -> bool:
    return any(name in line for name in EXEMPT_NAMES)


def scan(root: pathlib.Path) -> list[str]:
    problems: list[str] = []

    for path in sorted(root.rglob("*.ts*")):
        if path.name.endswith(EXEMPT_SUFFIXES):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        rel = path.relative_to(root.parent.parent.parent)
        lines = text.split("\n")
        file_has_guard = "canUseDemoData" in text

        for number, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith(("*", "//", "/*")) or _is_exempt_name(line):
                continue

            if FALLBACK_WITH_MOCK.search(line) and "demoFallback(" not in line:
                problems.append(
                    f"{rel}:{number}: fallbackData receives sample data directly. "
                    f"Wrap it in demoFallback(...) so it is withheld outside the hosted demo."
                )

            if MOCK_ASSIGN.search(line) and not file_has_guard:
                problems.append(
                    f"{rel}:{number}: sample data assigned to state with no canUseDemoData() "
                    f"check in this file. Show an error or empty state instead."
                )

    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default="apps/web/src", help="directory to scan")
    args = parser.parse_args()

    root = pathlib.Path(args.root)
    if not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 2

    problems = scan(root)
    if problems:
        print(f"{len(problems)} ungated sample-data site(s):\n", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        print(
            "\nSee apps/web/src/lib/demoFallback.ts. Fabricated security data must " "never render as a tenant's real state.",
            file=sys.stderr,
        )
        return 1

    print("All sample-data fallbacks are gated behind demo mode.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
