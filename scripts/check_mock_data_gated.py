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

The gate has two halves.

*Named sample data* — anything called `MOCK_*` / `DEMO_*` / `SAMPLE_*` /
`FALLBACK_*`, or built by a `makeDemo…()` / `buildDemo…()` factory — is reported
wherever it can reach a render without passing a demo check. That covers SWR
`fallbackData`, state setters, `useState` initial values, `return` from a hook
or helper, and conditional fallbacks written with `??`, `||` or a ternary.

*Fabricated records* are found without reference to any naming convention, by
what makes them harmful: a module-scope dataset that names entities a customer
would read as their own. `MSSPDashboardView.tsx` was the worst case and was
invisible to every name-based pattern — it declared `const TENANTS = [...]`,
six companies with invented alert counts, MTTD/MTTR figures and ARR, passed it
straight to `useState`, and **made no API call at all**. No mock-ish name, no
setter, no `fallbackData`, and because there was no fetch there was no real
path for a fallback to fall back *from*. Every operator on every deployment saw
the same six rows, permanently.

What counts as a fabricated record
----------------------------------
The first version of this check required an identity **and** at least two
numeric keys, on the reasoning that harm comes from naming an entity and
attaching numbers to it. That was true of the MSSP table that motivated it and
false in general, and it made the check quiet on four live datasets at once:

    TECHNIQUES          15 records, zero numeric keys
    DEMO_RESULTS         6 records, zero numeric keys
    MOCK_ASSETS         10 records, zero numeric keys
    MOCK_HANDOFF_ITEMS   8 records, zero numeric keys

`CoverageAdvisorView.tsx` is the clearest of the four: fifteen invented ATT&CK
coverage verdicts with no number anywhere in the literal, from which the
component *derives* and renders "Coverage 50%". The headline figure never
exists as a literal the gate could see. Requiring numbers asked for the wrong
thing — it asked for the symptom rather than the claim.

So the numeric requirement is gone, and what replaces it is two arms:

* an **estate identifier** — a hostname, an address, a ticket reference, a
  mailbox — is sufficient on its own. Measured over this console, that arm
  produces no configuration false positives at all: no filter list, option set
  or route table contains `WORKSTATION-042`, `203.0.113.42` or `ALR-4201`.

* a **proper noun** is far weaker on its own — "Detection Rules", "Microsoft
  Sentinel" and "Initial Access" are the product's own vocabulary, not a
  customer's estate — so it counts only alongside an *assertion of state*: a
  status/severity/verdict key, a timestamp, or two or more measurements. That
  is what separates fifteen coverage verdicts from the fourteen-entry MITRE
  tactic list two directories away, which carries `{ id, name, shortName }` and
  asserts nothing.

Gating is read per constant, not per file. The previous version asked whether
`demoFallback` appeared anywhere in the text, so one correctly-gated SWR call
credited every other dataset in the module — and `HuntView.tsx` has exactly
that pair, one constant behind a demo conditional and another forty lines away
that is not.

What it will not do
-------------------
It will not certify a corpus it did not read. A renamed directory, a changed
suffix or a wrong `--root` all produce zero findings over zero files, so the
file count is part of the verdict rather than a statistic printed beside it.

And when it cannot say the tree is clean, it says so instead of saying
nothing. `KNOWN_UNGATED` records sites the detector reports and the tree has
not fixed, with a reason each, so a stricter rule can land without either
weakening it or waiting on somebody else's change; while any entry stands, the
closing line is a count of what is outstanding rather than the unqualified
sentence. It is empty today, and it emptied itself: the seven sites this
revision first detected were fixed, the recorded counts stopped matching, and
the entries had to go before the build would pass.

It remains deliberately shallow. It cannot prove a view is honest — only that
these regressions have not reappeared. The reviewable property is that adding a
new ungated mock fails here rather than shipping.

Usage:
    python scripts/check_mock_data_gated.py [--root apps/web/src]
    python scripts/check_mock_data_gated.py --list-records
    python scripts/check_mock_data_gated.py --list-known
    python scripts/check_mock_data_gated.py --self-test
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys
from dataclasses import dataclass

# `scripts/` is on sys.path when this file is run as a program, but not when a
# test loads it by path with importlib. gate_toolkit sits beside it either way.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from gate_toolkit import SELF_TEST_FLAG, repo_root, self_test_main  # noqa: E402

MOCK_NAME = r"(?:MOCK|DEMO|SAMPLE|FALLBACK)_[A-Z0-9_]+"

#: `makeDemoTimeline(`, `buildDemoCase(` — sample data produced rather than
#: named. `InvestigationTimeline.tsx` used this form and passed the gate while
#: rendering a fully invented investigation (a named analyst, a routable source
#: IP, "Session suspended; email dispatched") whenever no run was selected.
SAMPLE_FACTORY = r"\b(?:make|build|get|create)(?:Mock|Demo|Sample|Fake|Fallback)\w*\("

#: Either spelling of sample data, for the rules that accept both.
SAMPLE_REF = rf"(?:{MOCK_NAME}\b|{SAMPLE_FACTORY})"

_MOCK_NAME_RE = re.compile(MOCK_NAME)


# ── Demo gating ─────────────────────────────────────────────────────────────

#: Any of these on a line means *that line* consulted demo mode.
DEMO_GATE = re.compile(r"demoFallback\s*\(|canUseDemoData|isDemoMode")

#: `if (!canUseDemoData())` — the component withholds itself entirely when demo
#: mode is off. `EASMView.tsx` and `ShiftsView.tsx` both open this way and then
#: reference their mocks freely below, which is correct and must stay quiet.
WITHHOLDING_GUARD = re.compile(r"if\s*\(\s*!\s*(?:canUseDemoData|isDemoMode)\s*\(\s*\)\s*\)")

#: A positive demo check, which gates the block it introduces:
#: `if (canUseDemoData()) { setRows(MOCK_ROWS); }` — the idiom `demoFallback.ts`
#: documents. Gating has to follow the block, not just the line, or the gate
#: would flag the exact shape its own helper tells people to write.
POSITIVE_GATE = re.compile(r"(?:canUseDemoData|isDemoMode)\s*\(\s*\)")

#: `const useFallback = !!error && canUseDemoData();` — the demo predicate
#: bound to a name and used a few lines later. Both `DetectionsView.tsx` and
#: `SettingsView.tsx` gate correctly this way, and a gate that reads only the
#: literal call would report them and be wrong. One hop, deliberately: the
#: alias has to be assigned *from* the predicate, so `HuntView.tsx`'s
#: `const [demoMode, setDemoMode] = useState(false)` — a flag the component
#: raises itself when the backend fails — is not mistaken for a demo check.
DEMO_ALIAS = re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]*)?=\s*[^;]*?(?:canUseDemoData|isDemoMode)\s*\(")


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip())


def demo_guarded_lines(lines: list[str]) -> list[bool]:
    """Per line: is sample data reached here already behind a demo check?

    Indentation rather than brace depth. Braces appear inside template
    literals, JSX and embedded query strings all over this console, so a
    counter drifts; every file here is Prettier-formatted, so indentation does
    not. The cost is that a one-line `if` body written without braces on the
    *next* line is read as a block, which over-credits by at most one line.
    """
    if _withholds_itself(lines):
        return [True] * len(lines)

    aliases = {name for line in lines for name in DEMO_ALIAS.findall(line)}
    alias_ref = re.compile(r"\b(?:" + "|".join(re.escape(a) for a in sorted(aliases)) + r")\b") if aliases else None

    guarded = [False] * len(lines)
    blocks: list[int] = []  # indentation of each open positive-gate block

    for number, line in enumerate(lines):
        stripped = line.strip()
        if not stripped:
            guarded[number] = bool(blocks)
            continue

        indent = _indent(line)
        while blocks and indent <= blocks[-1]:
            blocks.pop()

        guarded[number] = bool(blocks) or bool(DEMO_GATE.search(line)) or bool(alias_ref and alias_ref.search(line))

        if POSITIVE_GATE.search(line) and not WITHHOLDING_GUARD.search(line) and stripped.endswith(("{", "(", "&&")):
            blocks.append(indent)

    return guarded


def _withholds_itself(lines: list[str]) -> bool:
    """Whether the module refuses to render at all when demo mode is off.

    `if (!canUseDemoData()) { return <Empty /> }` covers the whole component,
    not just the lines below it — `EASMView.tsx` derives a summary object at
    module scope from the mock it guards, and `ShiftsView.tsx` seeds `useState`
    six lines *above* its guard. Both are correct: nothing renders.

    This is the one file-level credit the gate still extends, and it is
    narrower than what it replaces. The previous version credited a file for
    containing the string `demoFallback` anywhere in it, so a correctly-gated
    SWR call excused every unrelated constant in the module. This requires the
    component to actually leave.
    """
    for number, line in enumerate(lines):
        if not WITHHOLDING_GUARD.search(line):
            continue
        indent = _indent(line)
        body_end = number + 1
        while body_end < len(lines) and (not lines[body_end].strip() or _indent(lines[body_end]) > indent):
            body_end += 1
        if any("return" in lines[index] for index in range(number, body_end)):
            return True
    return False


# ── Named sample data reaching a render ─────────────────────────────────────


@dataclass(frozen=True)
class Rule:
    """One mechanical shape, with the sentence a reader gets when it fires."""

    name: str
    pattern: re.Pattern[str]
    detail: str


#: `fallbackData:` receiving sample data directly. Whether it is gated is
#: decided by looking for `demoFallback(` rather than with a lookahead:
#: `fallbackData:\s*(?!demoFallback\()` looks correct and is not, because `\s*`
#: backtracks to zero width and the lookahead then passes at the space, letting
#: `.*` find the name inside the wrapper it was meant to accept.
FALLBACK_WITH_MOCK = re.compile(rf"fallbackData:.*{MOCK_NAME}")

#: Sample data assigned to component state: `setRules(MOCK_RULES)`,
#: `setTimeline(makeDemoTimeline())`.
MOCK_ASSIGN = re.compile(rf"\bset[A-Z]\w*\(\s*{SAMPLE_REF}")

#: Retained under its historical name because the published gate contract and
#: the existing tests both refer to it; the factory arm now also reaches the
#: other rules through `SAMPLE_REF`.
MOCK_FACTORY_ASSIGN = re.compile(rf"\bset[A-Z]\w*\(\s*{SAMPLE_FACTORY}")

#: An *inline object literal* handed to a setter inside a `catch`. The gate's
#: docstring always promised it caught "a `catch` block assigning a sample
#: value", and it never did: `MOCK_ASSIGN` needs a bare named identifier, so
#: `CaseWorkspace.tsx` escaped while inventing an entire investigation in its
#: error path — a named host, a routable pivot IP, a C2 domain, "confidence
#: 0.88" — and reported it as `status: 'completed'`.
CATCH_SETTER = re.compile(r"\bset[A-Z]\w*\(\s*\{")

#: Sample data reached through a conditional at the point of *render*, whether
#: written with `??`, `||` or a ternary. `ThreatIntelView.tsx` passed
#: `fallbackData: demoFallback({ indicators: MOCK_INDICATORS })` — which the
#: gate accepted, correctly — and read `data?.indicators ?? MOCK_INDICATORS`
#: three lines later. `SLADashboard.tsx` wrote the same bypass as
#: `isValidMetrics ? rawMetrics : MOCK_SLA_METRICS`, which is identical in
#: meaning and matched nothing, because the first spelling of this rule was
#: `(?:\?\?|\|\|)\s*MOCK_NAME`. `\s*` also meant a single `(` defeated it, so
#: `data ?? (demoMode ? DEMO_SAVED : [])` read clean.
RENDER_FALLBACK = re.compile(rf"(?:\?\?|\|\|)[\s(!]*(?:[A-Za-z_$][\w$.]*\s*\?\s*)?{SAMPLE_REF}")

#: `cond ? MOCK_A : real` and `cond ? real : MOCK_B`. Bounded so it cannot run
#: across a whole minified line looking for something to blame.
TERNARY_FALLBACK = re.compile(rf"\?[\s(!]*{SAMPLE_REF}|\?[^?;]{{0,160}}?:\s*[(!\s]*{SAMPLE_REF}")

#: Sample data as the initial value of component state. `useState(TECHNIQUES)`
#: renders on first paint with no fetch behind it at all, which is the MSSP
#: shape again in one line.
STATE_SEED = re.compile(rf"\buseState(?:<[^>]*>)?\(\s*{SAMPLE_REF}")

#: `return buildDemoCase(caseId)` inside a `useMemo`. The factory rule was
#: widened once for `setTimeline(makeDemoTimeline())` and the `return` form was
#: never covered, so `CaseWorkspace.tsx` substituted a whole fabricated case
#: for any case id the API failed on.
RETURN_SAMPLE = re.compile(rf"\breturn\s+{SAMPLE_REF}")

RULES: tuple[Rule, ...] = (
    Rule(
        "fallbackData",
        FALLBACK_WITH_MOCK,
        "fallbackData receives sample data directly. Wrap it in demoFallback(...) so it is withheld outside the hosted demo.",
    ),
    Rule(
        "state-assignment",
        MOCK_ASSIGN,
        "sample data is assigned to state with no demo check. Show an error or empty state instead.",
    ),
    Rule(
        "state-seed",
        STATE_SEED,
        "sample data seeds component state, so it renders on first paint with no fetch behind it. Start from an empty value.",
    ),
    Rule(
        "returned-sample",
        RETURN_SAMPLE,
        "sample data is returned to the caller with no demo check, so the view receives it as though it were real.",
    ),
    Rule(
        "render-fallback",
        RENDER_FALLBACK,
        "sample data is reached through a `??`/`||` fallback with no demo check. Gating the SWR fallbackData does not cover "
        "this — when the request fails the mock renders anyway. Fall back to an empty value and let the view show its error state.",
    ),
    Rule(
        "ternary-fallback",
        TERNARY_FALLBACK,
        "sample data is reached through a ternary with no demo check. `cond ? real : MOCK_X` is the same bypass as `?? MOCK_X`. "
        "Fall back to an empty value and let the view show its error state.",
    ),
)

#: Sites where the fallback is UI configuration rather than a tenant's data.
#: Keyed by `(path suffix, constant)` with the reason it is not a finding.
#: Kept deliberately small: this gate's value depends on it staying quiet on
#: the filter lists and option sets that make up most module-scope arrays in
#: this console, and a gate that flags those gets switched off.
#:
#: Checked in both directions by `stale_render_exempt_entries()`, for the same
#: reason `ALLOWED_ILLUSTRATIVE` is: an exemption that outlives the code it
#: excused is cover for whatever is written next under that name. This half of
#: the gate had no staleness check for its first three revisions.
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
#:
#: Matched against the *constant being reported*, not against the whole line.
#: A substring test over the line skipped any line that so much as mentioned
#: one of these — including a line that also carried a real violation, and
#: including `SAMPLE_QUERY` matching inside `SAMPLE_QUERY_RESULTS`.
EXEMPT_NAMES = frozenset(
    {
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
)


def _exempt_match(matched: str) -> bool:
    """True when every sample name in this fragment is editor placeholder text."""
    names = set(_MOCK_NAME_RE.findall(matched))
    return bool(names) and names <= EXEMPT_NAMES


# ── Fabricated records declared inline ──────────────────────────────────────

#: Any module-scope `const NAME = [` / `const NAME = {` / `const NAME: T[] = [`.
#: Anchored at column zero so a filter list built inside a component body is out
#: of scope; what this check is after is a dataset baked into the module.
#:
#: The object form matters as much as the array form and was missing: a
#: fabricated alert, an audit page, an attack graph and a chat context are all
#: written `= {` in this console, and all of them were invisible.
MODULE_LITERAL = re.compile(r"^(?:export\s+)?const\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::[^=]*)?=\s*([\[{])")

#: The start of the next module-scope declaration, used to bound a literal's
#: body. Bracket counting alone is not enough — a literal holding a template
#: literal of SPL or a JSX snippet never balances — and an unbounded read then
#: drags hundreds of unrelated lines into the evidence for one constant.
NEXT_DECLARATION = re.compile(r"^(?:export\b|const\b|let\b|function\b|async\b|interface\b|type\b|class\b|/\*\*)")

#: `key: 42` / `key: 3.5`. The *measurements*.
NUMERIC_KEY = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*:\s*-?\d+(?:[._]\d+)*\b")

#: `key: 'some string'`. The candidate *identities*. Both quote styles: this
#: console is single-quoted by Prettier, but a dataset pasted in from a vendor
#: response arrives double-quoted and was invisible.
STRING_VALUE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\s*:\s*['\"]([^'\"]{2,60})['\"]")

#: Keys whose numbers describe how something is *drawn*, not what it measures.
#: Without this a cytoscape stylesheet (`width: 40, height: 40`) and the
#: decorative SVG node coordinates on the landing page both match.
LAYOUT_KEYS = frozenset(
    """x y cx cy r rx ry dx dy width height size top left right bottom opacity duration delay scale rotate
    zindex z index order weight strokewidth fontsize radius angle offset speed step cols rows span gap
    padding margin col row min max position""".split()
)

#: Keys that assert *how something currently stands* rather than how it is
#: labelled or laid out. This is what lets the proper-noun arm stay quiet: a
#: navigation list, a tactic vocabulary and a connector marquee all carry
#: recognisable names and none of them claims a state for what it names.
ASSERTION_KEYS = frozenset(
    """status state severity priority risk riskscore score health verdict disposition confidence coverage
    covered impact likelihood criticality posture exposure compliance sla breached progress trend
    lastseen lastsync lastfired lastrun firstseen createdat updatedat closedat detectedat timestamp ts time date""".split()
)

ASSERTION_KEY = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*:\s*[^,\n}]", re.MULTILINE)

#: An ISO-8601 instant as a *value*. Configuration never carries one.
TIMESTAMP_VALUE = re.compile(r"['\"]\d{4}-\d{2}-\d{2}T\d{2}:\d{2}")

#: "Acme Financial", "Sarah Chen", "GlobalRetail Corp" — a name a customer would
#: read as one of their own entities. Single capitalised words are excluded:
#: "Starter", "Critical" and "Execution" are labels, not identities.
PROPER_NOUN = re.compile(r"^[A-Z][A-Za-z.&]*(?:[ -][A-Z][A-Za-z.&]*)+$")

#: WIN-DC01, srv-01.corp.local, 10.0.0.4, jsmith@acme.corp.
ESTATE_IDENTIFIER = re.compile(r"^(?:[A-Z]{2,}-[A-Z0-9-]{2,}|[a-z][\w-]*-\d+\.[a-z][\w.-]+|\d{1,3}(?:\.\d{1,3}){3}|[\w.+-]+@[\w-]+\.\w+)$")

#: The mailbox half of the above, which is the one arm that is not self-evident.
#: A hostname or an address in module-scope data is estate data with nothing
#: more to say about it; a mailbox might instead be the project's own published
#: contact details, and the marketing pages carry exactly that — a security
#: disclosure address and a sales address, each sitting beside the link you are
#: meant to click. So a mailbox counts as an estate identifier unless the
#: literal is a list of links, which is what `MAILBOX_IS_A_LINK` decides.
MAILBOX = re.compile(r"^[\w.+-]+@[\w-]+\.\w+$")
MAILBOX_IS_A_LINK = re.compile(r"\b(?:href|url|link|to)\s*:|mailto:")

#: Reviewed exceptions: fabricated-looking records that are not, and never
#: render as, a tenant's state. Keyed on (path suffix, const name) so an
#: exemption cannot silently widen to a different constant in the same file.
#:
#: Checked in *both* directions — `stale_allowlist_entries()` fails when an
#: entry no longer matches anything, so a stale exemption is removed rather
#: than accumulating as cover for whatever is written next under that name.
#: Empty on purpose. The one entry this held excused `MitreStrip.tsx`, whose
#: twelve ATT&CK tactic tiles carried unsourced coverage counts behind a caveat
#: in the body copy. The component was imported nowhere and rendered on no
#: route, so the caveat was the only thing standing between those numbers and a
#: reader — and it would have stopped standing there the moment someone mounted
#: the section. Deleting the component was the fix; improving its disclaimer
#: would have left the numbers in the tree for the next person to inherit.
ALLOWED_ILLUSTRATIVE: dict[tuple[str, str], str] = {}

#: Live violations this gate detects and the tree has not fixed yet.
#:
#: Not an exemption and not a relaxation. Every site here is *reported by the
#: detector*; this records that it is known, unfixed, and owned elsewhere, so
#: the stricter gate can be merged without either weakening it or waiting on a
#: change to `apps/web` that belongs to another author. The distinction that
#: matters: removing a rule would make the tree look clean, and this makes the
#: tree look exactly as dirty as it is.
#:
#: Keyed `(path suffix, rule) -> (how many, why)`. The count is what makes an
#: entry falsifiable in both directions, the same way `EMPTY_TREE_EXCEPTIONS`
#: records a disposition rather than a bare name: fix one of them and the
#: count no longer matches, so the entry has to go; add a second violation of
#: the same rule to the same file and the count no longer matches either, so
#: it cannot hide behind the first.
#:
#: Shrink-only. `--list-known` prints what is left.
#: **Empty, and it emptied itself.** This held the seven sites the relaxed
#: detector found: a fabricated case returned from a `useMemo`, an invented
#: investigation written into a `catch` and reported as `status: 'completed'`,
#: a hunt substituting three detections on named workstations, an SLA ternary
#: bypassing the `demoFallback` three lines above it, a hard-coded chat
#: context, and fifteen ATT&CK coverage verdicts behind a printed percentage.
#: Every one of them was *reported* for as long as this ledger existed — it
#: recorded that they were known, it never hid them. They were fixed in a
#: parallel change, the recorded counts stopped matching, and the entries had
#: to be deleted before the build would pass again. That is the direction the
#: count exists for, and it is the reason to keep the mechanism rather than
#: leave the next person to invent a weaker one.
KNOWN_UNGATED: dict[tuple[str, str], tuple[int, str]] = {}


def _known_ungated_key(finding: Finding) -> tuple[str, str] | None:
    for suffix, rule in KNOWN_UNGATED:
        if finding.rule == rule and finding.path.endswith(suffix):
            return (suffix, rule)
    return None


def stale_known_ungated_entries(findings: list[Finding]) -> list[str]:
    """Entries whose count no longer matches what the detector reports.

    Both directions from one comparison. A site that has been fixed makes the
    count too low and the entry has to be deleted; a new violation of the same
    rule in the same file makes it too high and cannot shelter behind the
    recorded one.
    """
    seen: dict[tuple[str, str], int] = {}
    for finding in findings:
        key = _known_ungated_key(finding)
        if key is not None:
            seen[key] = seen.get(key, 0) + 1
    stale = []
    for key, (expected, _reason) in KNOWN_UNGATED.items():
        actual = seen.get(key, 0)
        if actual != expected:
            verb = "has been fixed — delete this entry" if actual < expected else "has grown; a new violation cannot hide here"
            stale.append(f"{key[0]} :: {key[1]} — recorded {expected}, detector reports {actual}: {verb}")
    return stale


def _render_fallback_exempt(rel_path: str, matched: str) -> bool:
    """True when this conditional-fallback site is documented UI configuration."""
    return any(rel_path.endswith(suffix) and const in matched for (suffix, const) in RENDER_FALLBACK_EXEMPT)


def _literal_body(lines: list[str], start: int, opener: str) -> str:
    """Lines from `start` to the bracket that closes the literal.

    `opener` is passed rather than re-derived: the caller has just matched it,
    and matching a second time invites the reader to wonder what happens when
    the second match fails.
    """
    closer = "]" if opener == "[" else "}"
    depth = 0
    body: list[str] = []
    for index in range(start, min(start + 500, len(lines))):
        if index > start and NEXT_DECLARATION.match(lines[index]):
            break
        body.append(lines[index])
        depth += lines[index].count(opener) - lines[index].count(closer)
        if index > start and depth <= 0:
            break
    return "\n".join(body)


def _asserts_state(blob: str) -> bool:
    """Whether the records claim how something currently stands."""
    measurements = {key for key in NUMERIC_KEY.findall(blob) if key.lower() not in LAYOUT_KEYS}
    if len(measurements) >= 2:
        return True
    if TIMESTAMP_VALUE.search(blob):
        return True
    return any(key.lower() in ASSERTION_KEYS for key in ASSERTION_KEY.findall(blob))


def _looks_fabricated(blob: str) -> bool:
    """A set of records naming entities a customer would read as their own.

    Two arms, deliberately unequal. An estate identifier stands alone — no
    filter list, option set or route table in this console holds a hostname or
    an address. A proper noun does not, because most of this console's
    configuration is made of proper nouns; it counts only where the records
    also assert a state for what they name.
    """
    values = STRING_VALUE.findall(blob)
    estate = [value for value in values if ESTATE_IDENTIFIER.match(value)]
    if any(not MAILBOX.match(value) for value in estate):
        return True
    if estate and not MAILBOX_IS_A_LINK.search(blob):
        return True
    if not any(PROPER_NOUN.match(value) for value in values):
        return False
    return _asserts_state(blob)


def _is_comment(line: str) -> bool:
    return line.strip().startswith(("*", "//", "/*"))


def _uses_of(name: str, lines: list[str], declared: range) -> list[int]:
    """Line numbers where `name` is referenced in *code* outside its declaration.

    Comments are excluded, and that is not a detail. Three components carry a
    comment explaining why the mock is *not* reached at render — "Not `??
    MOCK_INDICATORS`; `fallbackData` above already withholds it" — and counting
    that sentence as a use site made the gate report the very files whose
    authors had written down the fix. A gate reading its own documentation as
    the defect it documents is the same mistake one level up.
    """
    reference = re.compile(rf"\b{re.escape(name)}\b")
    return [number for number, line in enumerate(lines) if number not in declared and not _is_comment(line) and reference.search(line)]


@dataclass(frozen=True)
class Record:
    """One module-scope literal that reads as fabricated tenant data."""

    path: str
    line: int
    name: str
    gated: bool
    #: The lines that reach it without passing a demo check. Used to drop the
    #: declaration finding when a line rule has already named the same bypass.
    ungated_uses: tuple[int, ...] = ()


def find_inline_records(root: pathlib.Path) -> list[Record]:
    """Every module-scope fabricated-record literal and whether it is gated.

    Gating is decided **per constant**, from the lines that reference it. The
    previous version asked `DEMO_GATE.search(text)` once per file, so a single
    `demoFallback` anywhere marked every module-scope array in that file as
    gated — and a correctly-gated constant sitting beside an ungated one read
    clean. `HuntView.tsx` is the live example: `DEMO_SAVED` is reached through
    a demo conditional and `DEMO_RESULTS`, forty lines away, is not.
    """
    found: list[Record] = []
    for path in _sources(root):
        text = path.read_text(encoding="utf-8", errors="replace")
        lines = text.split("\n")
        guarded = demo_guarded_lines(lines)
        for number, line in enumerate(lines):
            match = MODULE_LITERAL.match(line)
            if not match or match.group(1) in EXEMPT_NAMES:
                continue
            body = _literal_body(lines, number, match.group(2))
            if not _looks_fabricated(body):
                continue
            declared = range(number, number + body.count("\n") + 1)
            uses = _uses_of(match.group(1), lines, declared)
            # A dataset nothing references is *not* thereby safe, and treating
            # it as safe would re-open the hole the `.ts` glob fix closes: move
            # a fabricated array into `lib/`, import it from a component, and
            # the declaring module has no use site at all. The allow-list's own
            # history says the same thing — `MitreStrip.tsx` was imported
            # nowhere and rendered on no route, and the fix was deleting it,
            # not excusing it until someone mounted the section.
            gated = bool(uses) and all(guarded[use] for use in uses)
            found.append(
                Record(
                    str(path.relative_to(root.parent.parent.parent)),
                    number + 1,
                    match.group(1),
                    gated,
                    tuple(use + 1 for use in uses if not guarded[use]),
                )
            )
    return found


def _sources(root: pathlib.Path) -> list[pathlib.Path]:
    """Every TypeScript module in scope, both `.ts` and `.tsx`.

    The record scan globbed `*.tsx` only, so the same fabricated dataset was a
    finding in a component and invisible in the `lib/` module beside it —
    which is where a dataset ends up the first time two components need it.
    """
    return sorted(p for p in root.rglob("*.ts*") if p.suffix in (".ts", ".tsx") and not p.name.endswith(EXEMPT_SUFFIXES))


def _allowlist_key(rel_path: str, name: str) -> tuple[str, str] | None:
    for (suffix, const), _reason in ALLOWED_ILLUSTRATIVE.items():
        if rel_path.endswith(suffix) and const == name:
            return (suffix, const)
    return None


@dataclass(frozen=True)
class Finding:
    """One site, tagged with the rule that produced it.

    The tag is not decoration. Several of these rules overlap by construction
    — a parenthesised `?? (demoMode ? DEMO_SAVED : [])` is matched by both the
    nullish rule and the ternary rule — so a self-test that only asked "did
    anything fire" would pass with the fix for either one reverted. Naming the
    rule is what makes each case falsifiable on its own terms.
    """

    rule: str
    path: str
    line: int
    detail: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line}: {self.detail}"


@dataclass
class Report:
    """What the scan found, and what it opened to find it."""

    findings: list[Finding]
    files: int
    records: list[Record]

    @property
    def problems(self) -> list[str]:
        return [str(finding) for finding in self.findings]


def scan(root: pathlib.Path) -> list[str]:
    """Every finding, as a reader-facing line. The shape the tests drive."""
    return inspect(root).problems


def inspect(root: pathlib.Path) -> Report:
    findings: list[Finding] = []
    sources = _sources(root)
    records = find_inline_records(root)
    #: Every (file, line) a line rule has already spoken for. A named mock
    #: reported at the line that bypasses the gate does not also need its
    #: declaration reported forty lines up: that is one defect described twice,
    #: and the second description points away from the fix.
    spoken_for: set[tuple[str, int]] = set()

    for path in sources:
        text = path.read_text(encoding="utf-8", errors="replace")
        rel = str(path.relative_to(root.parent.parent.parent))
        lines = text.split("\n")
        guarded = demo_guarded_lines(lines)
        in_catch = _catch_regions(lines)

        for number, line in enumerate(lines):
            if _is_comment(line) or guarded[number]:
                continue

            fired: set[str] = set()
            for rule in RULES:
                # Every match on the line, not the first. `re.search` stops at
                # the first hit, so a line carrying an exempt placeholder
                # *before* a real bypass would be dismissed on the strength of
                # the placeholder.
                hits = [m.group(0) for m in rule.pattern.finditer(line)]
                if not any(_actionable(rule, rel, line, hit) for hit in hits):
                    continue
                fired.add(rule.name)
                findings.append(Finding(rule.name, rel, number + 1, rule.detail))
                spoken_for.add((rel, number + 1))

            # One fallback written `?? (cond ? MOCK : [])` satisfies both
            # conditional rules and is one bypass, not two.
            if {"ternary-fallback", "render-fallback"} <= fired:
                findings.pop()

            if in_catch[number] and not fired and CATCH_SETTER.search(line):
                body = _braced_body(lines, number)
                if _invents_records(body):
                    findings.append(
                        Finding(
                            "catch-inline-object",
                            rel,
                            number + 1,
                            "a `catch` block assigns an inline object of fabricated records to state. The error path is "
                            "exactly where an operator most needs to be told the backend failed.",
                        )
                    )
                    # The whole object, not just its opening line: the names it
                    # renders sit on the lines below the setter.
                    spoken_for.update((rel, n) for n in range(number + 1, number + body.count("\n") + 2))

    for record in records:
        if record.gated or _allowlist_key(record.path, record.name) is not None:
            continue
        if record.ungated_uses and all((record.path, use) in spoken_for for use in record.ungated_uses):
            continue
        findings.append(
            Finding(
                "inline-records",
                record.path,
                record.line,
                f"`{record.name}` is a module-scope dataset of named entities, reached by a component with no demo "
                f"gate. If it is a tenant's state, read it from the API; if it is a sample, gate it with "
                f"canUseDemoData().",
            )
        )

    return Report(findings=findings, files=len(sources), records=records)


def _actionable(rule: Rule, rel: str, line: str, hit: str) -> bool:
    """Whether one match of one rule is a finding rather than an accepted shape."""
    if _exempt_match(hit):
        return False
    if rule.name == "fallbackData" and "demoFallback(" in line:
        return False
    if rule.name in ("render-fallback", "ternary-fallback") and _render_fallback_exempt(rel, hit):
        return False
    return True


def _catch_regions(lines: list[str]) -> list[bool]:
    """Per line: is this inside a `catch` block?

    Same indentation reasoning as `demo_guarded_lines`. The rule this feeds is
    deliberately narrow — an inline object literal handed to a setter is only
    a finding in an error path, because everywhere else it is ordinary state.
    """
    inside = [False] * len(lines)
    opened: int | None = None
    for number, line in enumerate(lines):
        if not line.strip():
            inside[number] = opened is not None
            continue
        indent = _indent(line)
        if opened is not None and indent <= opened:
            opened = None
        if opened is None and re.search(r"\}?\s*catch\b", line):
            opened = indent
        inside[number] = opened is not None
    return inside


def _braced_body(lines: list[str], start: int) -> str:
    """From `start` to the brace that closes the object opened on it.

    The setter and its opening brace are usually all that fits on the line —
    `setInvestigationData({` — so a single-line test sees an empty object and
    finds nothing. Reading the body is the whole point: what is fabricated is
    on the lines below.
    """
    depth = 0
    body: list[str] = []
    for index in range(start, min(start + 200, len(lines))):
        body.append(lines[index])
        depth += lines[index].count("{") - lines[index].count("}")
        if index > start and depth <= 0:
            break
    return "\n".join(body)


def _invents_records(blob: str) -> bool:
    """Whether an inline object literal carries fabricated domain data.

    `setPage({ size: 20 })` is state. `setInvestigationData({ … 'WIN-FIN-DB01'
    … 'c2.evil-corp.io' … 'confidence: 0.88' })` is a verdict about an estate
    nobody has, reported as `status: 'completed'`. Naming sample data inside
    the object counts too: `setResults({ total: DEMO_RESULTS.length, hits:
    DEMO_RESULTS })` reaches a render through a brace the setter rule cannot
    see past.
    """
    return _looks_fabricated(blob) or bool(_MOCK_NAME_RE.search(blob))


def stale_allowlist_entries(root: pathlib.Path) -> list[str]:
    """Allow-list entries that no longer match anything in the tree.

    The direction the first version of this gate would have missed. An
    exemption that outlives the code it excused is cover for whatever is
    written next under that name.
    """
    live = {_allowlist_key(record.path, record.name) for record in find_inline_records(root)}
    return [f"{suffix} :: {const}" for (suffix, const) in ALLOWED_ILLUSTRATIVE if (suffix, const) not in live]


def stale_render_exempt_entries(root: pathlib.Path) -> list[str]:
    """`RENDER_FALLBACK_EXEMPT` entries that no longer match any live line.

    The same direction, for the other allow-list. `ALLOWED_ILLUSTRATIVE` was
    checked both ways from the start and this one was not, so an exemption here
    could outlive the code it excused and nothing would say so.
    """
    live: set[tuple[str, str]] = set()
    for path in _sources(root):
        rel = str(path.relative_to(root.parent.parent.parent))
        text = path.read_text(encoding="utf-8", errors="replace")
        for suffix, const in RENDER_FALLBACK_EXEMPT:
            if rel.endswith(suffix) and re.search(rf"\b{re.escape(const)}\b", text):
                live.add((suffix, const))
    return [f"{suffix} :: {const}" for (suffix, const) in RENDER_FALLBACK_EXEMPT if (suffix, const) not in live]


# ── Self-test ───────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Case:
    """One self-test case: source, and the rule that must account for it.

    `expect` names the rule, so a case cannot pass on the strength of a
    different rule happening to cover the same line. That matters here because
    the conditional rules overlap deliberately: reverting the parenthesis fix
    in `RENDER_FALLBACK` leaves `TERNARY_FALLBACK` matching the same fixture,
    and a boolean "did anything fire" would have gone on reporting PASS.

    `expect=None` means the case must produce nothing at all.
    """

    description: str
    source: str
    expect: str | None
    suffix: str = ".tsx"


#: Each case owns its source string and is written to its own directory tree,
#: built fresh from `Case(...)` every run. A self-test elsewhere in this tree
#: shallow-copied one baseline object across its cases, so the first case
#: poisoned it and every later case "caught" a code it had inherited rather
#: than provoked. Strings are immutable and each tree is new, so neither can
#: happen here.
def self_test_cases() -> tuple[Case, ...]:
    return (
        Case(
            "fifteen coverage verdicts with no number anywhere",
            "const TECHNIQUES = [\n"
            "  { id: 'T1071', name: 'Application Layer Protocol', status: 'partial', priority: 'medium' },\n"
            "  { id: 'T1078', name: 'Valid Accounts', status: 'partial', priority: 'high' },\n"
            "];\nexport function V() { return <b>{TECHNIQUES.length}</b>; }\n",
            "inline-records",
        ),
        Case(
            "a single record naming a host — the old three-record floor",
            "const ROWS = [{ host: 'WIN-DC01', user: 'svc_admin' }];\nexport function V() { return <b>{ROWS.length}</b>; }\n",
            "inline-records",
        ),
        Case(
            "an object literal rather than an array",
            "const CONTEXT = { caseId: 'CS-2187', alertCount: 7 };\nexport function V() { return <b>{CONTEXT.caseId}</b>; }\n",
            "inline-records",
        ),
        Case(
            "a fabricated dataset in a .ts module, not a .tsx component",
            "export const ROWS = [{ host: 'WIN-DC01', risk: 91, score: 12 }];\nexport const used = ROWS.length;\n",
            "inline-records",
            suffix=".ts",
        ),
        Case(
            "a ternary reaching a mock, which `??`-only matching missed",
            "const metrics = isValid ? rawMetrics : MOCK_SLA_METRICS;\n",
            "ternary-fallback",
        ),
        Case(
            "a parenthesised nullish fallback, which `\\s*` could not cross",
            "const saved = state.data ?? (flag ? DEMO_SAVED : []);\n",
            "render-fallback",
        ),
        Case(
            "a demo factory returned rather than assigned to a setter",
            "function pick() {\n  if (useFallback) return buildDemoCase(caseId);\n  return undefined;\n}\n",
            "returned-sample",
        ),
        Case(
            "a mock seeding useState rather than reaching a setter",
            "const [items] = useState(MOCK_HANDOFF_ITEMS);\n",
            "state-seed",
        ),
        Case(
            "an inline object of fabricated records assigned in a catch",
            "async function run() {\n  try {\n    await go();\n  } catch (e) {\n"
            "    setInvestigationData({\n      host: 'WIN-FIN-DB01',\n      domain: 'c2.evil-corp.io',\n"
            "      confidence: 0.88,\n    });\n  }\n}\n",
            "catch-inline-object",
        ),
        Case(
            "a line mentioning an exempt placeholder before a real bypass",
            "const q = saved ?? SAMPLE_KQL; const rows = data ?? MOCK_ALERTS;\n",
            "render-fallback",
        ),
        Case(
            "an ungated constant sitting beside a correctly gated one",
            "const MOCK_GOOD = [{ host: 'WIN-DC01', risk: 1, score: 2 }];\n"
            "const MOCK_BAD = [{ host: 'WIN-SQL02', risk: 3, score: 4 }];\n"
            "export function V() {\n"
            "  const { data } = useSWR(k, f, { fallbackData: demoFallback(MOCK_GOOD) });\n"
            "  return <b>{data?.length}{MOCK_BAD.length}</b>;\n}\n",
            "inline-records",
        ),
        # ── and the directions it must not fire in ──────────────────────────
        Case(
            "a navigation list: proper nouns, no state asserted",
            "const NAV_ITEMS = [\n  { label: 'Detection Rules', href: '/detection' },\n"
            "  { label: 'Threat Intel', href: '/threat-intel' },\n];\nexport function V() { return <b>{NAV_ITEMS.length}</b>; }\n",
            None,
        ),
        Case(
            "a vendor vocabulary map: proper nouns, no state",
            "const BACKEND_LABELS = { qradar: 'IBM QRadar', sentinel: 'Microsoft Sentinel' };\n"
            "export function V() { return <b>{BACKEND_LABELS.qradar}</b>; }\n",
            None,
        ),
        Case(
            "a contact list: a mailbox beside the link you are meant to click",
            "const FACTS = [{ label: 'Security disclosures', value: 'security@example.com', href: 'https://example.com' }];\n"
            "export function V() { return <b>{FACTS.length}</b>; }\n",
            None,
        ),
        Case(
            "the documented `if (canUseDemoData())` idiom",
            "function load() {\n  try {\n    go();\n  } catch {\n    if (canUseDemoData()) {\n      setRows(MOCK_ROWS);\n    }\n  }\n}\n",
            None,
        ),
        Case(
            "a demo predicate bound to a name and used a line later",
            "const useFallback = !!error && canUseDemoData();\nconst rules = data?.rules ?? (useFallback ? DEMO_RULES : []);\n",
            None,
        ),
        Case(
            "a component that withholds itself outside demo mode",
            "const MOCK_ASSETS = [{ ip: '203.0.113.42', status: 'critical' }];\n"
            "export function V() {\n  if (!canUseDemoData()) {\n    return <Empty />;\n  }\n  return <b>{MOCK_ASSETS.length}</b>;\n}\n",
            None,
        ),
        Case(
            "a comment explaining why a mock is *not* reached at render",
            "const MOCK_INDICATORS = [{ ip: '185.220.101.45', confidence: 95, score: 3 }];\n"
            "export function V() {\n  const { data } = useSWR(k, f, { fallbackData: demoFallback(MOCK_INDICATORS) });\n"
            "  // Not `?? MOCK_INDICATORS`: the fallbackData above already withholds it.\n"
            "  return <b>{data?.length ?? 0}</b>;\n}\n",
            None,
        ),
        Case(
            "an editor placeholder on its own",
            "const q = saved ?? SAMPLE_KQL;\n",
            None,
        ),
        Case(
            "a named mock reported at its bypass is not reported twice",
            "const MOCK_ROWS = [{ host: 'WIN-DC01', risk: 4, score: 9 }];\n"
            "export function V() {\n  return <b>{(data ?? MOCK_ROWS).length}</b>;\n}\n",
            "render-fallback",
        ),
    )


def _self_test_results(tmp: pathlib.Path) -> list[tuple[str, bool]]:
    """Run every case against a fresh `apps/web/src` built from scratch."""
    results: list[tuple[str, bool]] = []
    for index, case in enumerate(self_test_cases()):
        root = tmp / f"case{index}" / "apps" / "web" / "src" / "components" / "x"
        root.mkdir(parents=True)
        (root / f"V{case.suffix}").write_text(case.source, encoding="utf-8")
        rules = [finding.rule for finding in inspect(root.parent.parent).findings]
        if case.expect is None:
            results.append((f"stays quiet on {case.description}", not rules))
        else:
            results.append((f"catches, as [{case.expect}], {case.description}", rules == [case.expect]))
    return results


def _ratchet_results() -> list[tuple[str, bool]]:
    """The recorded-site ledger, in both directions.

    Every case constructs its own `Finding` and its own one-entry ledger. A
    self-test elsewhere in this tree shared one mutable baseline across cases,
    so the first case poisoned it and the rest "caught" what they inherited.
    """

    def finding() -> Finding:
        return Finding("returned-sample", "apps/web/src/components/cases/CaseWorkspace.tsx", 329, "detail")

    def ledger(count: int) -> dict[tuple[str, str], tuple[int, str]]:
        return {("components/cases/CaseWorkspace.tsx", "returned-sample"): (count, "recorded reason")}

    original = KNOWN_UNGATED.copy()
    results: list[tuple[str, bool]] = []
    try:
        for description, recorded, found, expect_stale in (
            ("a recorded site still present is not stale", 1, 1, False),
            ("a recorded site that has been fixed must be deleted", 1, 0, True),
            ("a second violation cannot hide behind a recorded one", 1, 2, True),
            ("a recorded site is suppressed from the failure list", 1, 1, False),
        ):
            KNOWN_UNGATED.clear()
            KNOWN_UNGATED.update(ledger(recorded))
            findings = [finding() for _ in range(found)]
            stale = bool(stale_known_ungated_entries(findings))
            results.append((f"RATCHET: {description}", stale == expect_stale))
        KNOWN_UNGATED.clear()
        KNOWN_UNGATED.update(ledger(1))
        suppressed = _known_ungated_key(finding()) is not None
        unrelated = _known_ungated_key(Finding("state-seed", "apps/web/src/components/other/X.tsx", 1, "d")) is None
        results.append(("RATCHET: an entry covers only the rule and file it names", suppressed and unrelated))
    finally:
        KNOWN_UNGATED.clear()
        KNOWN_UNGATED.update(original)
    return results


def self_test() -> int:
    """Prove the gate still detects each shape, and still refuses nothing."""
    import tempfile

    print("check_mock_data_gated self-test\n")
    with tempfile.TemporaryDirectory(prefix="aisoc-mock-gate-") as tmp:
        extra = _self_test_results(pathlib.Path(tmp))
    extra += _ratchet_results()

    empty_corpus = pathlib.Path(tempfile.mkdtemp(prefix="aisoc-mock-empty-"))
    (empty_corpus / "apps" / "web" / "src").mkdir(parents=True)
    extra.append(("refuses a corpus directory that exists and holds no TypeScript", _refuses_empty_corpus(empty_corpus)))

    return self_test_main(pathlib.Path(__file__).name, [], extra)


def _refuses_empty_corpus(tree: pathlib.Path) -> bool:
    """The corpus floor, exercised in-process.

    `scan()` over a directory with no sources finds nothing, which is why the
    count has to be the verdict rather than the findings list. Without this a
    renamed directory or a changed suffix reads exactly like a clean console.
    """
    return inspect(tree / "apps" / "web" / "src").files == 0


# ── CLI ─────────────────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", default="apps/web/src", help="directory to scan, relative to the repository root")
    parser.add_argument(
        "--list-records",
        action="store_true",
        help="list every module-scope fabricated-record literal and whether it is gated",
    )
    parser.add_argument("--list-known", action="store_true", help="list the recorded known-ungated sites and their reasons")
    parser.add_argument(SELF_TEST_FLAG, action="store_true", help="prove this gate detects the shapes it claims to")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    base = repo_root()
    root = pathlib.Path(args.root)
    if not root.is_absolute():
        root = base / root
    if not root.is_dir():
        print(f"error: {root} is not a directory — nothing was scanned, so nothing can be certified", file=sys.stderr)
        return 2

    report = inspect(root)

    # Found nothing and scanned nothing print the same word. A renamed console
    # directory, a changed suffix or a wrong `--root` all produce zero findings
    # over zero files, and without this the gate would call that clean.
    if report.files == 0:
        print(f"error: no .ts/.tsx sources under {root} — the corpus is empty, so a clean result would be invented", file=sys.stderr)
        return 2

    if args.list_records:
        for record in sorted(report.records, key=lambda r: (r.path, r.line)):
            state = "gated" if record.gated else ("allow-listed" if _allowlist_key(record.path, record.name) else "UNGATED")
            print(f"[{state:>12}] {record.path}:{record.line} const {record.name}")
        print(f"\n{len(report.records)} fabricated-record literal(s) across {report.files} file(s) under {root}")
        return 0

    if args.list_known:
        for (suffix, rule), (count, reason) in sorted(KNOWN_UNGATED.items()):
            print(f"{suffix}  [{rule}] x{count}\n    {reason}")
        print(f"\n{len(KNOWN_UNGATED)} recorded site(s), {sum(c for c, _ in KNOWN_UNGATED.values())} finding(s). Shrink-only.")
        return 0

    stale = [
        *(f"ALLOWED_ILLUSTRATIVE  {entry} — no longer matches anything; remove it" for entry in stale_allowlist_entries(root)),
        *(f"RENDER_FALLBACK_EXEMPT  {entry} — no longer matches anything; remove it" for entry in stale_render_exempt_entries(root)),
        *(f"KNOWN_UNGATED  {entry}" for entry in stale_known_ungated_entries(report.findings)),
    ]
    if stale:
        print(f"{len(stale)} stale allow-list entry(ies):\n", file=sys.stderr)
        for entry in stale:
            print(f"  {entry}", file=sys.stderr)
        return 1

    outstanding = [finding for finding in report.findings if _known_ungated_key(finding) is None]
    if outstanding:
        print(f"{len(outstanding)} ungated sample-data site(s):\n", file=sys.stderr)
        for finding in outstanding:
            print(f"  {finding}", file=sys.stderr)
        print(
            "\nSee apps/web/src/lib/demoFallback.ts. Fabricated security data must never render as a tenant's real state.",
            file=sys.stderr,
        )
        return 1

    gated = sum(1 for record in report.records if record.gated)
    recorded = len(report.findings)
    print(f"scanned {report.files} .ts/.tsx file(s) under {root}")
    print(f"  {len(report.records)} module-scope fabricated-record literal(s): {gated} gated, {len(report.records) - gated} reported")
    if recorded:
        # The unqualified sentence is a claim about the whole console, so it is
        # only printed when it is true of the whole console.
        print("No new ungated sample-data sites.")
        print(f"  {recorded} known-ungated site(s) still outstanding — `--list-known` for the list. This number may only go down.")
    else:
        print("All sample-data fallbacks are gated behind demo mode.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
