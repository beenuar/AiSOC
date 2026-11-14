#!/usr/bin/env python3
"""CI gate: one demo gate, and nothing fabricated reachable without it.

`scripts/check_mock_data_gated.py` recognises the *shapes* that carried
fabricated security data into the console: a bare mock handed to SWR's
``fallbackData``, a mock assigned through a state setter, a mock reached
through ``??``/``||``. Every one of those is a specific syntax, and each was
added after a specific escape. This gate asks the two questions that do not
depend on guessing which syntax comes next.

**Is the fabricated value reachable at all?**
    ``SLADashboard.tsx`` passed ``fallbackData: demoFallback(MOCK_SLA_METRICS)``
    — correct, and the shape gate accepted it — then wrote
    ``const metrics = isValidMetrics ? rawMetrics : MOCK_SLA_METRICS`` one line
    later. A ternary is not a ``??``, so nothing matched. Outside the hosted
    demo ``demoFallback`` returns ``undefined``, which makes ``isValidMetrics``
    falsy on **first paint as well as on error**, so 847 alerts, 23 breaches
    and a 42.5-minute MTTR rendered in both states on every deployment.

    So this gate enumerates no syntax. It takes every *read* of a fabricated
    symbol and asks whether a gate is in scope at that point. ``cond ? x :
    MOCK`` fails, and so does whatever is written in its place next.

**Does the component decide for itself that it is in demo mode?**
    ``HuntView.tsx`` held ``const [demoMode, setDemoMode] = useState(false)``
    and flipped it to ``true`` inside a fetch ``catch``. Demo mode is a
    property of the *deployment*, so a component that derives it from a failed
    request fabricates precisely when the backend is unhealthy — which is when
    a reader is least equipped to notice, and when an operator most needs to
    know the estate is not being observed. Disclosure copy does not fix it:
    the same words would appear if the data were real.

    ``NEXT_PUBLIC_DEMO_MODE``, read through ``lib/demoMode.ts``, is the only
    thing allowed to answer that question.

What counts as a fabricated symbol
----------------------------------
Three kinds, because the first alone is trivially side-stepped:

* a constant named by the convention — ``MOCK_*`` / ``DEMO_*`` / ``SAMPLE_*``
  / ``FALLBACK_*``;
* a *factory* that builds one — ``buildDemoCase()``, ``makeMockRows()``. The
  constant check cannot see these: ``CaseWorkspace`` called
  ``buildDemoCase(caseId)`` and the id came from the route param, so the
  invention presented as the case the analyst had opened;
* anything whose own initializer reads one of the above. ``EASMView``
  declared ``const SUMMARY = { totalAssets: MOCK_ASSETS.length, … }``, which
  carries the fabrication under a name the convention does not cover.

What counts as a gate being in scope
------------------------------------
Gating is not always on the line that reads. All four of these are real and
correct in this tree, so a per-line check would reject working code and be
switched off within a week:

* the read's own statement, expanded by bracket balance, so a value handed to
  a multi-line ``demoFallback({ … })`` is seen as gated;
* an enclosing block whose condition mentions the gate —
  ``if (canUseDemoData()) { setRules(MOCK_RULES); }``;
* an early-return guard in the same block — ``if (!canUseDemoData()) return
  [];`` followed later by the read, which is how ``LiveFeedPanel`` does it;
* a local whose initializer mentions the gate, then used at the read —
  ``const useFallback = !!error && canUseDemoData()``.

What it does *not* accept is a bare mention of the gate somewhere else in the
file, which is the hole in the older checks: ``SLADashboard`` had
``demoFallback`` on line 446 and the ungated ternary on line 457.

Deliberately narrow in one direction: it says nothing about whether a view is
*honest*, only that these two ways of losing the gate cannot reappear.

Usage:
    python scripts/check_demo_state_gated.py [--root apps/web/src]
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

#: The naming convention a fabricated constant follows in this tree.
MOCK_NAME = re.compile(r"\b((?:MOCK|DEMO|SAMPLE|FALLBACK)_[A-Z0-9_]+)\b")

#: A factory that builds fabricated data. The constant convention cannot see
#: these, and they are how the worst instance in this tree was written:
#: `buildDemoCase(caseId)` took its id from the route param, so the invented
#: incident presented as the case the analyst had actually opened.
FACTORY_NAME = re.compile(
    r"\b(?:(?:build|make|get|create|generate)(?:Mock|Demo|Sample|Fake|Fallback)[A-Za-z0-9_]*"
    r"|(?:demo|mock|sample|fake|fallback)[A-Z][A-Za-z0-9_]*)\b"
)

#: The single gate. `demoFallback()` withholds a value outside the hosted
#: demo; `canUseDemoData()` / `isDemoMode()` answer the same question for
#: imperative paths.
GATE = re.compile(r"\b(?:demoFallback|canUseDemoData|isDemoMode)\b")

#: `const NAME = …` / `function name(` — the start of a definition.
CONST_DECL = re.compile(r"^(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]*)?=")
FUNC_DECL = re.compile(r"^(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*[(<]")

#: `const [demoMode, setDemoMode] = useState(…)`. Matched on the *declared*
#: name so `sampleNotice` — a disclosure string, not a mode — stays in scope
#: for authors who want one.
LOCAL_DEMO_STATE = re.compile(
    r"const\s*\[\s*(demo|demoMode|isDemo|isDemoMode|useDemo|usingDemoData|usingMockData|mockMode|sampleMode|isSample|fallbackMode)\s*,\s*\w+\s*\]\s*=\s*useState",
)

#: Files exempt by nature: the gate helpers themselves, tests, and stories.
#: A test *must* be able to name a fabricated constant — that is how it proves
#: the constant does not render.
EXEMPT_SUFFIXES = (
    ".test.ts",
    ".test.tsx",
    ".spec.ts",
    ".spec.tsx",
    ".stories.tsx",
    "demoFallback.ts",
    "demoMode.ts",
)

#: Constants whose name matches the convention but whose value is editor
#: placeholder text or an input default, not data presented as tenant state.
#: Mirrors the list in `check_mock_data_gated.py`; kept separate rather than
#: imported because that file belongs to a different gate and the two must
#: stay free to diverge.
EXEMPT_NAMES = frozenset(
    """SAMPLE_BODIES SAMPLE_EVENT SAMPLE_SIGMA SAMPLE_KQL SAMPLE_EQL SAMPLE_SPL SAMPLE_ESQL
    SAMPLE_YAML SAMPLE_QUERY SAMPLE_RULE DEMO_EMAIL DEMO_PASSWORD DEMO_PROVIDERS DEMO_RESULT""".split()
)

#: Sample data reachable without a gate, each with the reason it is not fixed.
#:
#: A ratchet, not an amnesty. Entries are checked in *both* directions: one
#: that stops matching fails the run, so an exemption cannot outlive the code
#: it excused and become cover for whatever is written next under that name.
#: The list may only shrink.
#:
#: Empty on purpose. The gate was written alongside the change that closed the
#: last seven sites, and an allow-list seeded at birth is a gate that has
#: never been true. Anything added here has to carry a reason a reviewer can
#: check, and a reason that is "this one is hard" belongs in an issue instead.
KNOWN_UNGATED: dict[tuple[str, str], str] = {}


def _is_comment(line: str) -> bool:
    return line.lstrip().startswith(("*", "//", "/*", "*/"))


def _strip_comment(line: str) -> str:
    """Drop a trailing `//` comment so prose cannot supply or hide a token."""
    cut = line.find("//")
    return line if cut < 0 else line[:cut]


def _definition_ranges(lines: list[str]) -> list[tuple[int, int, str]]:
    """Line spans of every top-level ``const``/``function`` definition.

    Returned as ``(start, end, name)`` with inclusive bounds. Used for two
    things: a read inside a fabricated definition is part of that definition
    rather than a render of it, and a definition that reads a fabricated
    symbol becomes fabricated itself.
    """
    spans: list[tuple[int, int, str]] = []
    index = 0
    while index < len(lines):
        line = _strip_comment(lines[index])
        match = CONST_DECL.match(line) or FUNC_DECL.match(line)
        if not match:
            index += 1
            continue

        depth = 0
        end = index
        for cursor in range(index, len(lines)):
            body = _strip_comment(lines[cursor])
            depth += sum(body.count(c) for c in "([{") - sum(body.count(c) for c in ")]}")
            end = cursor
            if cursor > index or depth <= 0:
                if depth <= 0:
                    break
        spans.append((index, end, match.group(1)))
        index = end + 1
    return spans


def fabricated_symbols(lines: list[str]) -> tuple[set[str], list[tuple[int, int]]]:
    """Names that carry fabricated data in this file, and where they are defined.

    Resolved to a fixed point so a constant assembled out of another one — the
    shape that put ``EASMView``'s headline counts beyond the naming convention
    — is itself treated as fabricated.
    """
    spans = _definition_ranges(lines)

    # A *data* declaration: `const NAME … = [` or `= {`. The distinction is
    # what separates a fabricated record set from a scalar helper —
    # `const MOCK_BASE = new Date('2026-05-06').getTime()` is a deterministic
    # timestamp anchor that keeps the mocks from drifting across SSR, not a
    # named entity with measurements attached, and flagging it teaches authors
    # that the gate cries wolf.
    literal = {name for start, _e, name in spans if re.search(r"=\s*[\[{]\s*$", _strip_comment(lines[start]))}

    #: Declarations that hold a value rather than behaviour. A component or a
    #: helper that *renders* a correctly-gated mock is not itself fabricated,
    #: and promoting it would flag its own definition line as a read of itself.
    holds_data = {
        name
        for start, _e, name in spans
        if CONST_DECL.match(_strip_comment(lines[start])) and "=>" not in _strip_comment(lines[start]).split("=", 1)[-1]
    }

    names = {
        name
        for _s, _e, name in spans
        if name not in EXEMPT_NAMES and (FACTORY_NAME.fullmatch(name) or (MOCK_NAME.fullmatch(name) and name in literal))
    }

    changed = True
    while changed:
        changed = False
        for start, end, name in spans:
            if name in names or name in EXEMPT_NAMES or name not in holds_data:
                continue
            body = "\n".join(_strip_comment(line) for line in lines[start : end + 1])
            if any(re.search(rf"\b{re.escape(known)}\b", body) for known in names):
                names.add(name)
                changed = True

    ranges = [(s, e) for s, e, name in spans if name in names]
    return names, ranges


def _statement_around(lines: list[str], index: int) -> str:
    """The bracket-balanced statement containing line ``index``.

    A read can sit several lines below the call that gates it::

        fallbackData: demoFallback({
          alerts: MOCK_ALERTS,
        }),

    so judging the matched line alone rejects correct code. Expanding by
    bracket balance rather than by a fixed window of neighbours is what keeps
    the opposite error out: an unrelated ``canUseDemoData()`` three lines above
    must not launder an ungated read below it.
    """
    start = index
    depth = 0
    while start > 0:
        body = _strip_comment(lines[start])
        depth += sum(body.count(c) for c in ")]}") - sum(body.count(c) for c in "([{")
        if depth <= 0 and (not lines[start - 1].strip() or _strip_comment(lines[start - 1]).rstrip().endswith((";", "{", "}"))):
            break
        start -= 1

    end = index
    depth = 0
    while end < len(lines) - 1:
        body = _strip_comment(lines[end])
        depth += sum(body.count(c) for c in "([{") - sum(body.count(c) for c in ")]}")
        if depth <= 0 and body.rstrip().endswith((";", ",", "{", "}")):
            break
        end += 1

    return "\n".join(lines[start : end + 1])


def _guarded_definitions(lines: list[str]) -> list[tuple[int, int]]:
    """Spans of definitions that return early unless the build is the demo.

    ``EASMView`` and ``ShiftsView`` open with ``if (!canUseDemoData()) return
    <NotYetWired …>``. Nothing in such a function reaches the DOM on a
    non-demo build — including a ``useState(MOCK_ITEMS)`` initializer above
    the guard, which produces no output at all. The guard has to be
    unconditional to count, so it is only recognised at the top level of the
    function body rather than nested inside another branch.
    """
    guard = re.compile(r"if\s*\(\s*!\s*(?:canUseDemoData|isDemoMode)\s*\(")
    guarded: list[tuple[int, int]] = []

    for start, end, _name in _definition_ranges(lines):
        depth = 0
        for cursor in range(start, end + 1):
            body = _strip_comment(lines[cursor])
            if depth == 1 and guard.search(body):
                block = "\n".join(_strip_comment(line) for line in lines[cursor : min(cursor + 12, end + 1)])
                if "return" in block:
                    guarded.append((start, end))
                    break
            depth += body.count("{") - body.count("}")
    return guarded


def _gate_in_scope(lines: list[str], index: int, gated_locals: set[str]) -> bool:
    """Whether a demo gate governs line ``index``.

    Walks outward from the read: its own statement, then each enclosing block,
    looking for the gate itself or a local derived from it. Also accepts an
    early-return guard (``if (!canUseDemoData()) return …``) seen earlier at
    the read's own depth, which is how a ``useMemo`` body is gated.
    """
    tokens = re.compile(rf"\b(?:demoFallback|canUseDemoData|isDemoMode{''.join('|' + re.escape(n) for n in gated_locals)})\b")

    if tokens.search(_statement_around(lines, index)):
        return True

    # Walk backwards tracking depth relative to the read. A line that leaves
    # the read's depth negative opened a block the read sits inside; a span
    # that dips above zero and returns is a *sibling* block the read follows.
    guard = re.compile(r"if\s*\(\s*!\s*(?:canUseDemoData|isDemoMode)\s*\(")
    depth = 0
    sibling: list[str] = []
    for cursor in range(index - 1, -1, -1):
        if _is_comment(lines[cursor]):
            continue
        body = _strip_comment(lines[cursor])
        opens = sum(body.count(c) for c in "([{")
        closes = sum(body.count(c) for c in ")]}")

        if depth == 0 and guard.search(body) and "return" in body:
            return True

        depth += closes - opens
        if depth > 0:
            sibling.append(body)
            continue
        if depth < 0:
            # `cursor` opened an enclosing block; its condition is in scope.
            if tokens.search(body):
                return True
            depth = 0
            sibling.clear()
            continue
        # Back at the read's own depth: `cursor` opened a sibling block. An
        # `if (!canUseDemoData()) { return … }` above the read returns before
        # anything below it renders, which is how `EASMView` and `ShiftsView`
        # withhold their sample inventories.
        if sibling and guard.search(body) and any("return" in line for line in sibling):
            return True
        sibling.clear()
    return False


def _gated_locals(lines: list[str]) -> set[str]:
    """Locals whose initializer consults the gate, e.g. ``useFallback``."""
    found: set[str] = set()
    for line in lines:
        body = _strip_comment(line)
        match = CONST_DECL.match(body.strip())
        if match and GATE.search(body):
            found.add(match.group(1))
    return found


def _ratchet_key(rel: str, name: str) -> tuple[str, str] | None:
    for (suffix, const), _reason in KNOWN_UNGATED.items():
        if rel.endswith(suffix) and const == name:
            return (suffix, const)
    return None


def findings(root: pathlib.Path) -> tuple[list[str], set[tuple[str, str]]]:
    """Every ungated read and every self-declared demo mode, plus what matched."""
    problems: list[str] = []
    matched: set[tuple[str, str]] = set()

    for path in sorted(root.rglob("*.ts*")):
        if path.name.endswith(EXEMPT_SUFFIXES):
            continue
        lines = path.read_text(encoding="utf-8", errors="replace").split("\n")
        rel = str(path.relative_to(root.parent.parent.parent))

        names, definitions = fabricated_symbols(lines)
        gated_locals = _gated_locals(lines)
        guarded = _guarded_definitions(lines)

        for number, line in enumerate(lines):
            if _is_comment(line):
                continue
            body = _strip_comment(line)

            state = LOCAL_DEMO_STATE.search(body)
            if state:
                key = _ratchet_key(rel, state.group(1))
                if key:
                    matched.add(key)
                else:
                    problems.append(
                        f"{rel}:{number + 1}: `{state.group(1)}` is component state. Demo mode is a "
                        f"property of the deployment — read it through isDemoMode()/canUseDemoData() in "
                        f"lib/demoMode.ts. State derived from a fetch failure fabricates exactly when "
                        f"the backend is unhealthy."
                    )

            if any(start <= number <= end for start, end in definitions + guarded):
                continue
            read = sorted({n for n in names if re.search(rf"\b{re.escape(n)}\b", body)})
            if not read or _gate_in_scope(lines, number, gated_locals):
                continue

            ungated = []
            for name in read:
                key = _ratchet_key(rel, name)
                if key:
                    matched.add(key)
                else:
                    ungated.append(name)
            if ungated:
                problems.append(
                    f"{rel}:{number + 1}: `{', '.join(ungated)}` is read with no demo gate in scope. "
                    f"Wrap it in demoFallback(...) or guard it with canUseDemoData(); outside the "
                    f"hosted demo this renders fabricated data as the tenant's own."
                )

    return problems, matched


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default="apps/web/src", help="directory to scan")
    parser.add_argument("--check", action="store_true", help="accepted for symmetry with the other gates")
    args = parser.parse_args()
    del args.check

    root = pathlib.Path(args.root)
    if not root.is_dir():
        print(
            f"error: {root} is not a directory — refusing to report a result for a tree I did not open",
            file=sys.stderr,
        )
        return 2

    scanned = sum(1 for path in root.rglob("*.ts*") if not path.name.endswith(EXEMPT_SUFFIXES))
    if scanned == 0:
        print(
            f"error: no TypeScript sources under {root} — refusing to report a result for an empty corpus",
            file=sys.stderr,
        )
        return 2

    problems, matched = findings(root)

    stale = [f"{suffix} :: {const}" for (suffix, const) in KNOWN_UNGATED if (suffix, const) not in matched]
    if stale:
        print(f"{len(stale)} stale entry(ies) in KNOWN_UNGATED:\n", file=sys.stderr)
        for entry in stale:
            print(f"  {entry} — no longer matches anything; remove it", file=sys.stderr)
        return 1

    if problems:
        print(f"{len(problems)} ungated demo-data site(s) across {scanned} file(s):\n", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        print(
            "\nSee apps/web/src/lib/demoFallback.ts. Fabricated security data must never render "
            "as a tenant's real state, and no component may decide for itself that it is a demo.",
            file=sys.stderr,
        )
        return 1

    print(
        f"OK: {scanned} file(s) scanned; every fabricated symbol is reachable only behind the demo gate "
        f"({len(KNOWN_UNGATED)} known exception(s) ratcheted)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
