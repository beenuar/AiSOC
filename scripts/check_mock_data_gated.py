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

This gate checks the mechanical shapes that caused it:

* `fallbackData:` receiving a bare `MOCK_*` / `DEMO_*` reference rather than one
  wrapped in `demoFallback(...)`.
* A `catch` block assigning a `MOCK_*` / `DEMO_*` value with no `canUseDemoData`
  check anywhere in the file.
* A module-scope array of fabricated *records* — named entities carrying
  measurements — rendered by a component with no demo gate.

That third check exists because the first two only recognise mock data that
announces itself. Both require the `MOCK_` / `DEMO_` naming convention *and* an
assignment through a state setter or SWR, which models one situation: a view
that fetches, and substitutes a sample when the fetch fails.

`MSSPDashboardView.tsx` was the worse case and was invisible to all of it. It
declared `const TENANTS = [...]` — six companies with invented alert counts,
MTTD/MTTR figures, risk scores, analyst headcounts and ARR — passed it straight
to `useState`, and **made no API call at all**. No mock-ish name, no setter, no
`fallbackData`, so nothing matched; and because there was no fetch, there was no
real path for a fallback to fall back *from*. Every operator on every deployment
saw the same six rows, permanently. `TeamAnalyticsView.tsx` had the same shape
with six named analysts and their accuracy scores.

So the third check is name-agnostic. It looks for what makes fabricated domain
data harmful rather than for what an author happened to call it: records that
name an entity a customer would recognise (a company, a person, a host, an IP,
an address) *and* attach numbers to it. UI configuration — filter lists, sort
options, language menus, marketing copy — carries neither, which is what keeps
the check quiet: 93 module-scope object arrays in the console at the time of
writing, 7 matched, and the 4 already behind `demoFallback()` were the mocks.

It remains deliberately shallow. It cannot prove a view is honest — only that
these regressions have not reappeared. The reviewable property is that adding a
new ungated mock fails here rather than shipping.

Usage:
    python scripts/check_mock_data_gated.py [--root apps/web/src]
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

# `scripts/` is on sys.path when this file is run as a program, but not when a
# test loads it by path with importlib. gate_toolkit sits beside it either way.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from gate_toolkit import self_test_if_requested

self_test_if_requested(__file__)

MOCK_NAME = r"(?:MOCK|DEMO|SAMPLE|FALLBACK)_[A-Z0-9_]+"

#: A `fallbackData:` whose value mentions sample data. Whether it is gated is
#: decided separately by looking for `demoFallback(`, rather than with a
#: lookahead: `fallbackData:\s*(?!demoFallback\()` looks correct and is not,
#: because `\s*` backtracks to zero width and the lookahead then passes at the
#: space, letting `.*` find the name inside the wrapper it was meant to accept.
FALLBACK_WITH_MOCK = re.compile(rf"fallbackData:.*{MOCK_NAME}")

#: An assignment of a mock inside a file, e.g. `setRules(MOCK_RULES)`.
MOCK_ASSIGN = re.compile(rf"\bset[A-Z]\w*\(\s*{MOCK_NAME}")

#: A *factory* that builds sample data, e.g. `setTimeline(makeDemoTimeline())`.
#: The two patterns above match a constant by name, which is one of the two
#: ways to render fabricated state — `InvestigationTimeline.tsx` used the other
#: and passed this gate while rendering a fully invented investigation
#: (a named analyst, a routable source IP, "Session suspended; email
#: dispatched") whenever no run was selected.
MOCK_FACTORY_ASSIGN = re.compile(r"\bset[A-Z]\w*\(\s*(?:make|build|get|create)(?:Mock|Demo|Sample|Fake|Fallback)\w*\(")

#: Sample data reached through a nullish/OR fallback at the point of *render*,
#: e.g. `const rows = data?.items ?? MOCK_ROWS;`.
#:
#: This is the shape the three patterns above cannot see, because the file can
#: be correctly gated at the SWR boundary and still bypass it one line later.
#: `ThreatIntelView.tsx` did exactly that: line 239 passed
#: `fallbackData: demoFallback({ indicators: MOCK_INDICATORS })` — which the
#: gate accepted, correctly — and line 242 then read
#: `data?.indicators ?? MOCK_INDICATORS`. With demo mode off and the API
#: returning 404, `data` is undefined and the mock renders anyway: five
#: invented IOCs (a "Tor exit node with ransomware C2", a LockBit payload
#: hash) under the counters "5 Total IOCs · 4 Malicious · 3 Added Today", on a
#: deployment where no indicator had ever been ingested. Observed live; this
#: gate reported "All sample-data fallbacks are gated behind demo mode."
MOCK_RENDER_FALLBACK = re.compile(rf"(?:\?\?|\|\|)\s*{MOCK_NAME}\b")

#: Sites where the fallback is UI configuration rather than a tenant's data.
#: Keyed by `(path suffix, constant)` with the reason it is not a finding.
#: Kept deliberately small: this gate's value depends on it staying quiet on
#: the filter lists and option sets that make up most module-scope arrays in
#: this console, and a gate that flags those gets switched off.
RENDER_FALLBACK_EXEMPT: dict[tuple[str, str], str] = {
    (
        "identity/permissions/EffectivePermissionsView.tsx",
        "DEMO_PROVIDERS",
    ): "the provider capability list (aws/azure/gcp/gws/okta + coverage tier), not tenant data",
    (
        "identity/permissions/EffectivePermissionsView.tsx",
        "DEMO_RESULT",
    ): "supplies the default value of the principal input, not a rendered result",
}

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


# ── Fabricated records declared inline ──────────────────────────────────────

#: Any module-scope `const NAME = [` / `const NAME: T[] = [`. Anchored at column
#: zero so a filter list built inside a component body is out of scope; what
#: this check is after is a dataset baked into the module.
MODULE_ARRAY = re.compile(r"^(?:export\s+)?const\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::[^=]*)?=\s*\[")

#: `key: 42` / `key: 3.5`. The *measurements*.
NUMERIC_KEY = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*:\s*-?\d+(?:[._]\d+)*\b")

#: `key: 'some string'`. The candidate *identities*.
STRING_VALUE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\s*:\s*'([^']{2,60})'")

#: Keys whose numbers describe how something is *drawn*, not what it measures.
#: Without this a cytoscape stylesheet (`width: 40, height: 40`) and the
#: decorative SVG node coordinates on the landing page both match.
LAYOUT_KEYS = frozenset(
    """x y cx cy r rx ry dx dy width height size top left right bottom opacity duration delay scale rotate
    zindex z index order weight strokewidth fontsize radius angle offset speed step cols rows span gap
    padding margin col row min max position""".split()
)

#: "Acme Financial", "Sarah Chen", "GlobalRetail Corp" — a name a customer would
#: read as one of their own entities. Single capitalised words are excluded:
#: "Starter", "Critical" and "Execution" are labels, not identities.
PROPER_NOUN = re.compile(r"^[A-Z][A-Za-z.&]*(?:[ -][A-Z][A-Za-z.&]*)+$")

#: WIN-DC01, srv-01.corp.local, 10.0.0.4, jsmith@acme.corp.
ESTATE_IDENTIFIER = re.compile(r"^(?:[A-Z]{2,}-[A-Z0-9-]{2,}|[a-z][\w-]*-\d+\.[a-z][\w.-]+|\d{1,3}(?:\.\d{1,3}){3}|[\w.+-]+@[\w-]+\.\w+)$")

#: Any of these in the file means the author considered demo mode.
DEMO_GATE = re.compile(r"demoFallback|canUseDemoData|isDemoMode")

#: Reviewed exceptions: fabricated-looking records that are not, and never
#: render as, a tenant's state. Keyed on (path suffix, const name) so an
#: exemption cannot silently widen to a different constant in the same file.
#:
#: Checked in *both* directions — `--check-allowlist` fails when an entry no
#: longer matches anything, so a stale exemption is removed rather than
#: accumulating as cover for whatever is written next under that name.
#: Empty on purpose. The one entry this held excused `MitreStrip.tsx`, whose
#: twelve ATT&CK tactic tiles carried unsourced coverage counts behind a caveat
#: in the body copy. The component was imported nowhere and rendered on no
#: route, so the caveat was the only thing standing between those numbers and a
#: reader — and it would have stopped standing there the moment someone mounted
#: the section. Deleting the component was the fix; improving its disclaimer
#: would have left the numbers in the tree for the next person to inherit.
ALLOWED_ILLUSTRATIVE: dict[tuple[str, str], str] = {}


def _render_fallback_exempt(rel_path: str, matched: str) -> bool:
    """True when this `?? MOCK_*` site is documented UI configuration."""
    return any(rel_path.endswith(suffix) and const in matched for (suffix, const) in RENDER_FALLBACK_EXEMPT)


def _array_body(lines: list[str], start: int) -> str:
    """Lines from `start` to the bracket that closes the array."""
    depth = 0
    body: list[str] = []
    for index in range(start, min(start + 500, len(lines))):
        body.append(lines[index])
        depth += lines[index].count("[") - lines[index].count("]")
        if index > start and depth <= 0:
            break
    return "\n".join(body)


def _looks_fabricated(blob: str) -> bool:
    """A set of records that names entities and attaches numbers to them."""
    if blob.count("{") < 3:
        return False
    measurements = {key for key in NUMERIC_KEY.findall(blob) if key.lower() not in LAYOUT_KEYS}
    if len(measurements) < 2:
        return False
    return any(PROPER_NOUN.match(value) or ESTATE_IDENTIFIER.match(value) for value in STRING_VALUE.findall(blob))


def find_inline_records(root: pathlib.Path) -> list[tuple[str, int, str, bool]]:
    """Every module-scope fabricated-record array: (path, line, name, gated)."""
    found: list[tuple[str, int, str, bool]] = []
    for path in sorted(root.rglob("*.tsx")):
        if path.name.endswith(EXEMPT_SUFFIXES):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        gated = bool(DEMO_GATE.search(text))
        lines = text.split("\n")
        for number, line in enumerate(lines):
            match = MODULE_ARRAY.match(line)
            if not match or _is_exempt_name(line):
                continue
            if _looks_fabricated(_array_body(lines, number)):
                found.append((str(path.relative_to(root.parent.parent.parent)), number + 1, match.group(1), gated))
    return found


def _allowlist_key(rel_path: str, name: str) -> tuple[str, str] | None:
    for (suffix, const), _reason in ALLOWED_ILLUSTRATIVE.items():
        if rel_path.endswith(suffix) and const == name:
            return (suffix, const)
    return None


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

            render_fallback = MOCK_RENDER_FALLBACK.search(line)
            if render_fallback and not file_has_guard and not _render_fallback_exempt(str(rel), render_fallback.group(0)):
                problems.append(
                    f"{rel}:{number}: sample data is reached through a `??`/`||` fallback with "
                    f"no canUseDemoData() check in this file. Gating the SWR fallbackData does "
                    f"not cover this — when the request fails the mock renders anyway. Fall back "
                    f"to an empty value and let the view show its error state."
                )

            if MOCK_FACTORY_ASSIGN.search(line) and not file_has_guard:
                problems.append(
                    f"{rel}:{number}: a sample-data factory is assigned to state with no "
                    f"canUseDemoData() check in this file. Show an error or empty state instead."
                )

    # A distinct name from the `rel: Path` above. `_allowlist_key` matches on
    # a string suffix, and handing it a Path would make every allow-list entry
    # miss — noisily, but for a reason nobody would look for here.
    for record_path, number, name, gated in find_inline_records(root):
        if gated or _allowlist_key(record_path, name) is not None:
            continue
        problems.append(
            f"{record_path}:{number}: `{name}` is a module-scope array of named entities with "
            f"measurements attached, in a component with no demo gate. If it is a tenant's "
            f"state, read it from the API; if it is a sample, gate it with canUseDemoData()."
        )

    return problems


def stale_allowlist_entries(root: pathlib.Path) -> list[str]:
    """Allow-list entries that no longer match anything in the tree.

    The direction the first version of this gate would have missed. An
    exemption that outlives the code it excused is cover for whatever is
    written next under that name.
    """
    live = {_allowlist_key(rel, name) for rel, _n, name, _g in find_inline_records(root)}
    return [f"{suffix} :: {const}" for (suffix, const) in ALLOWED_ILLUSTRATIVE if (suffix, const) not in live]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default="apps/web/src", help="directory to scan")
    parser.add_argument(
        "--list-records",
        action="store_true",
        help="list every module-scope fabricated-record array and whether it is gated",
    )
    args = parser.parse_args()

    root = pathlib.Path(args.root)
    if not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 2

    if args.list_records:
        for rel, number, name, gated in find_inline_records(root):
            state = "gated" if gated else ("allow-listed" if _allowlist_key(rel, name) else "UNGATED")
            print(f"[{state}] {rel}:{number} const {name}")
        return 0

    problems = scan(root)

    stale = stale_allowlist_entries(root)
    if stale:
        print(f"{len(stale)} stale allow-list entry(ies) in ALLOWED_ILLUSTRATIVE:\n", file=sys.stderr)
        for entry in stale:
            print(f"  {entry} — no longer matches anything; remove it", file=sys.stderr)
        return 1

    if problems:
        print(f"{len(problems)} ungated sample-data site(s):\n", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        print(
            "\nSee apps/web/src/lib/demoFallback.ts. Fabricated security data must never render as a tenant's real state.",
            file=sys.stderr,
        )
        return 1

    print("All sample-data fallbacks are gated behind demo mode.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
