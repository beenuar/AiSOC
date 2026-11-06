#!/usr/bin/env python3
"""Every shipped locale is checked against the base catalogue, both ways.

Wave 2, Phase 9.3.

What this is for
----------------
A translation catalogue rots in two directions and only one of them is
visible:

* **A key the base has and a locale does not** is an untranslated string. It
  falls back to English, which is correct behaviour and also invisible — the
  page renders, nobody is told, and the gap is discovered by a customer.
* **A key a locale has and the base does not** is almost always a typo in the
  translated file, or a string deleted from the product months ago. It is
  never rendered, so no amount of using the console finds it.

The second direction is the one nobody checks, which is the recurring shape
in this repository: a gate that compares A against B and never B against A
prints OK while drift accumulates in the direction things actually change.

Why the counts are reported per surface
---------------------------------------
"`ar` is 6 keys short" is a number. "`ar` is missing `settings.branding`,
`settings.delegations`, …" grouped under `settings` tells a translator which
screen to sit down with. The catalogue's dotted grouping exists for this.

Deliberately not a failure by default
-------------------------------------
An untranslated key is **reported, not fatal**, because a partially
translated locale is the normal state of every real deployment and a gate
that reds the build on one would get the locale deleted rather than
finished. A *ratchet* is the right control: `--max-untranslated` caps the
backlog so it cannot grow silently. An unknown key — the invisible direction
— is always fatal, because it is a defect rather than a backlog.

The arm the first version was missing
-------------------------------------
Everything above compares the locales **with each other**. All of it stayed
green for the whole life of the catalogue while *not one component imported
it* — a working translator, right-to-left support and 48 maintained keys,
read by nobody, reported by this gate as OK. That is this repository's
most-repeated defect shape, and a gate whose passing condition is a proxy
for the property rather than the property itself cannot see it.

So the gate also asks **who renders each key**, and the unit is the key, not
the module. A count of importers is the same proxy one level up: one import
satisfies it while 47 keys go unrendered. A key is read when a non-test file
outside the catalogue's own directory passes it to `translate()`, `t()` or
`hasTranslation()` as a literal — or names its surface in a template prefix,
`` t(`severity.${level}`) ``, which credits the keys under `severity.`
because the alternative is a five-arm ternary written to satisfy a gate.

Three scopes are excluded on purpose, and each exclusion is the point rather
than a convenience:

* **the catalogue's own directory** — the module calling itself is what
  being unread looks like from the inside;
* **test files** — a key exercised only by a test is the defect, not the
  evidence against it. This repository has shipped a passing test over an
  unreachable function often enough to name the shape;
* **build output** — the one match outside the module on the pre-fix tree
  was a TypeScript build artifact, which renders nothing.

Fatal, not ratcheted — and the asymmetry is deliberate
------------------------------------------------------
An *untranslated* key is ratcheted because the person who can fix it is a
native speaker who may never arrive; redding the build on their absence gets
the locale deleted rather than finished. An *unread* key has no such third
party. Whoever added it can render it or delete it in the same commit, so
there is nothing to wait for and no reason to tolerate a balance.

The exemption is therefore a **named key with a reason**
(`KEYS_WITHOUT_A_READER`), not a number. A numeric ceiling of 3 says three
keys are unread without saying which, and lets one be wired while another
rots into the space it freed. The named list is checked in both directions,
like `check_hosted_hostname.py`'s: an entry for a key that *is* read, or for
a key the catalogue does not have, fails the build rather than sitting
there.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root  # noqa: E402

REPO_ROOT = repo_root()
WEB_SRC = REPO_ROOT / "apps" / "web" / "src"
I18N_DIR = WEB_SRC / "lib" / "i18n"
MESSAGES = I18N_DIR / "messages"
BASE = "en"

#: Backlog ceiling. Not a target — a debt balance, in the same sense as
#: `check_route_authz.py`'s. Lower it when a locale is finished; never raise
#: it to make a run pass.
MAX_UNTRANSLATED = 6

#: Base keys allowed to have no render site, each with the reason.
#:
#: One entry, and it is the shape this list exists for: a key the product
#: genuinely renders, down a path the scan cannot see rather than one it has
#: not been told about. An exemption with a reason beside it is a decision;
#: a numeric ceiling of "1 unread key" would be the same fact with the
#: reasoning deleted, and would let this one be fixed while a different key
#: rotted into the space it freed. Both directions are checked below, so an
#: entry that stops being needed fails the build rather than sitting here.
#:
#: Keys that named copy the console does not have were **deleted** instead
#: of listed — `cases.closedAt` and three `hunt.*` entries described a close
#: timestamp, a query-provenance label and an unsupported-filter notice that
#: no component has ever shown. An exemption is for a key that is rendered
#: and cannot be seen; a key that is not rendered at all is not exempt, it
#: is wrong.
KEYS_WITHOUT_A_READER: dict[str, str] = {
    "common.unknown": (
        "rendered by formatDate() for an unparseable timestamp. That call "
        "lives inside the catalogue's own module, which this scan excludes "
        "by design — a module calling itself is what being unread looks "
        "like from the inside — so the one real render site is invisible "
        "to it. Covered instead by i18n.test.ts, which asserts formatDate "
        "returns this string for an invalid date."
    ),
}

#: Where the key sits in each recognised call's argument list.
#:
#: `t` is the binding `useLocale()` hands a component, so the key is first;
#: the free functions take the locale first. The call-site pattern excludes a
#: preceding identifier character so `format(`, `split(` and `.at(` do not
#: match — `\b` cannot do this job, because `_` is a word character.
CALL_NAMES: dict[str, int] = {"translate": 1, "hasTranslation": 1, "t": 0}

_CALL_RE = re.compile(r"(?<![A-Za-z0-9_$])(translate|hasTranslation|t)\s*\(")

#: Names whose presence in an import clause means this file has a translator.
#:
#: Scanning every file for ``t(`` matches a regex literal such as
#: ``/T(\d+)/i`` in a module that has nothing to do with translation — found
#: on the pre-fix tree, where it inflated the computed-key count by one. A
#: bare ``t`` only means a translation where something put one in scope, so
#: the binding is the right precondition rather than the directory: a
#: component gets ``t`` from ``useLocale()`` and never imports the catalogue.
TRANSLATION_BINDINGS = frozenset({"translate", "hasTranslation", "useLocale", "t"})

_IMPORT_CLAUSE_RE = re.compile(
    r"(?:^|[\s;])import\s+([^'\"]*?)\s+from\s*['\"]",
    re.MULTILINE | re.DOTALL,
)

_IDENTIFIER_RE = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")

_IMPORT_RE = re.compile(
    r"""(?:^|[\s;])(?:import|export)\b[^'"\n]*?from\s*['"]([^'"]+)['"]"""
    r"""|(?:^|[\s;])import\s*['"]([^'"]+)['"]"""
    r"""|\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)""",
    re.MULTILINE,
)


class CatalogueError(RuntimeError):
    """A catalogue that could not be read."""


def _strip_comments(source: str) -> str:
    """Remove line and block comments without touching string contents."""
    out: list[str] = []
    i = 0
    quote: str | None = None
    while i < len(source):
        ch = source[i]
        if quote:
            out.append(ch)
            if ch == "\\":
                if i + 1 < len(source):
                    out.append(source[i + 1])
                    i += 2
                    continue
            elif ch == quote:
                quote = None
            i += 1
            continue
        if ch in "\"'`":
            quote = ch
            out.append(ch)
            i += 1
            continue
        if source.startswith("//", i):
            while i < len(source) and source[i] != "\n":
                i += 1
            continue
        if source.startswith("/*", i):
            end = source.find("*/", i + 2)
            i = len(source) if end == -1 else end + 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _keys_from_source(source: str) -> set[str]:
    """Dotted keys of the exported object literal, parsed structurally.

    A regex over the whole file would match keys inside the module docstring
    and inside type declarations. This walks braces instead, so what is
    counted is the nesting the runtime sees.

    Two things the first version got wrong, both found by running it:

    * it anchored on the first ``= {`` in the file, which in a locale that
      declares a ``DeepPartial`` helper is the **type alias**, so it parsed
      zero keys and reported a fully-translated locale as entirely missing;
    * it counted braces inside string *values*, so ``'{count} alerts'``
      opened a nesting level and invented a surface called ``countOne``.

    Both produce a confident wrong number rather than an error, which is the
    failure mode this gate exists to prevent elsewhere.
    """
    body = _strip_comments(source)

    # Anchor on the export, not on the first `= {`.
    export = re.search(r"export\s+const\s+[A-Za-z_][A-Za-z0-9_]*\s*(?::[^=]+)?=\s*\{", body)
    if export is None:
        raise CatalogueError("no exported object literal found")

    keys: set[str] = set()
    stack: list[str] = []
    pending: str | None = None
    i = export.end() - 1
    depth = 0

    token = re.compile(r"\s*(?:([A-Za-z_][A-Za-z0-9_]*)|'([^']*)'|\"([^\"]*)\")\s*:")

    while i < len(body):
        ch = body[i]

        # Skip string literals whole: a value may contain braces, and
        # `'{count} alerts'` must not open a nesting level.
        if ch in "\"'`":
            quote = ch
            i += 1
            while i < len(body):
                if body[i] == "\\":
                    i += 2
                    continue
                if body[i] == quote:
                    i += 1
                    break
                i += 1
            continue

        if ch == "{":
            depth += 1
            if pending is not None:
                stack.append(pending)
                pending = None
            i += 1
            continue
        if ch == "}":
            depth -= 1
            if stack:
                stack.pop()
            if depth == 0:
                break
            i += 1
            continue

        match = token.match(body, i)
        if match:
            name = match.group(1) or match.group(2) or match.group(3)
            rest = body[match.end() :].lstrip()
            if rest.startswith("{"):
                pending = name
                i = match.end()
                continue
            keys.add(".".join([*stack, name]))
            i = match.end()
            continue
        i += 1
    return keys


def load_catalogue(path: Path) -> set[str]:
    try:
        return _keys_from_source(path.read_text(encoding="utf-8"))
    except CatalogueError as exc:
        raise CatalogueError(f"{path.name}: {exc}") from exc


def _surface(key: str) -> str:
    return key.split(".", 1)[0]


def compare(base_keys: set[str], locale_keys: set[str]) -> tuple[list[str], list[str]]:
    """``(untranslated, unknown)`` — base-not-in-locale, locale-not-in-base."""
    return sorted(base_keys - locale_keys), sorted(locale_keys - base_keys)


# ─── Who renders each key ─────────────────────────────────────────────────


def _skip_string(source: str, start: int) -> int:
    """Index just past the string or template literal opening at ``start``.

    Template literals are walked rather than searched for a closing
    backtick, because ``${...}`` may itself contain a string containing a
    backtick. Getting this wrong swallows the rest of the file and reports
    a confident zero call sites, which is the failure mode the parser above
    already shipped twice.
    """
    quote = source[start]
    i = start + 1
    while i < len(source):
        ch = source[i]
        if ch == "\\":
            i += 2
            continue
        if quote == "`" and source.startswith("${", i):
            depth = 1
            i += 2
            while i < len(source) and depth:
                inner = source[i]
                if inner in "\"'`":
                    i = _skip_string(source, i)
                    continue
                if inner == "{":
                    depth += 1
                elif inner == "}":
                    depth -= 1
                i += 1
            continue
        if ch == quote:
            return i + 1
        i += 1
    return len(source)


def split_arguments(source: str, open_paren: int) -> list[str] | None:
    """Top-level argument texts of the call whose ``(`` sits at ``open_paren``.

    ``None`` when the call never closes, so a truncated read is not mistaken
    for a call with no arguments.
    """
    depth = 0
    args: list[str] = []
    start = open_paren + 1
    i = open_paren
    while i < len(source):
        ch = source[i]
        if ch in "\"'`":
            i = _skip_string(source, i)
            continue
        if ch in "([{":
            depth += 1
            i += 1
            continue
        if ch in ")]}":
            depth -= 1
            if depth == 0:
                args.append(source[start:i])
                return args
            i += 1
            continue
        if ch == "," and depth == 1:
            args.append(source[start:i])
            start = i + 1
            i += 1
            continue
        i += 1
    return None


def key_from_argument(argument: str) -> tuple[str, str] | None:
    """``('exact', key)``, ``('prefix', surface)`` or ``None``.

    A bare template prefix with no dot — ``t(`${whatever}`)`` — resolves to
    nothing rather than to every key in the catalogue. That is the one shape
    that could defeat this gate wholesale, so it credits nothing and the
    keys it was standing in for are reported unread.
    """
    text = argument.strip()
    if not text or text[0] not in "\"'`":
        return None
    # A concatenation such as `'a' + suffix` opens and closes a quote too;
    # only a literal that spans the whole argument is a key.
    if _skip_string(text, 0) != len(text):
        return None
    inner = text[1:-1]
    if text[0] in "\"'":
        return None if "\\" in inner else ("exact", inner)
    if "${" not in inner:
        return ("exact", inner)
    prefix = inner.split("${", 1)[0]
    return ("prefix", prefix) if "." in prefix else None


def call_sites(source: str) -> tuple[list[tuple[str, str]], int]:
    """``(resolved, unresolved)`` translation call sites in one file.

    ``unresolved`` counts calls whose key is a variable. They credit nothing
    — which needs no separate failure, because the keys they would have
    rendered are then reported unread by the arm below.
    """
    resolved: list[tuple[str, str]] = []
    unresolved = 0
    for match in _CALL_RE.finditer(source):
        index = CALL_NAMES[match.group(1)]
        args = split_arguments(source, match.end() - 1)
        if args is None or len(args) <= index:
            continue
        found = key_from_argument(args[index])
        if found is None:
            unresolved += 1
        else:
            resolved.append(found)
    return resolved, unresolved


def keys_rendered(sources: dict[str, str], base_keys: set[str]) -> tuple[set[str], list[tuple[str, str]], int]:
    """``(rendered, unknown_call_sites, unresolved)`` across many files."""
    rendered: set[str] = set()
    unknown: list[tuple[str, str]] = []
    unresolved = 0
    for path, source in sorted(sources.items()):
        # Comments first. A component explaining *why* it does not write
        # ``t(entry.key)`` would otherwise be counted as writing it, and an
        # advisory number that is wrong is worse than no number.
        resolved, dynamic = call_sites(_strip_comments(source))
        unresolved += dynamic
        for kind, value in resolved:
            if kind == "exact":
                if value in base_keys:
                    rendered.add(value)
                elif value.strip():
                    unknown.append((path, value))
                continue
            matched = {k for k in base_keys if k.startswith(value)}
            if matched:
                rendered |= matched
            else:
                unknown.append((path, f"{value}*"))
    return rendered, unknown, unresolved


def resolve_specifier(importer: Path, specifier: str) -> Path | None:
    """Where a TypeScript import specifier points, or ``None`` if external."""
    if specifier.startswith("@/"):
        return WEB_SRC / specifier[2:]
    if specifier.startswith("."):
        return (importer.parent / specifier).resolve()
    return None


def imports_catalogue(importer: Path, source: str) -> bool:
    """Whether this file imports anything from the i18n module."""
    for match in _IMPORT_RE.finditer(source):
        specifier = match.group(1) or match.group(2) or match.group(3)
        target = resolve_specifier(importer, specifier or "")
        if target is None:
            continue
        if target == I18N_DIR or I18N_DIR in target.parents:
            return True
    return False


def imports_a_translator(source: str) -> bool:
    """Whether anything in this file's imports can translate.

    A file that binds no translator cannot contain a translation call site,
    whatever its regex literals look like.
    """
    for match in _IMPORT_CLAUSE_RE.finditer(source):
        if set(_IDENTIFIER_RE.findall(match.group(1))) & TRANSLATION_BINDINGS:
            return True
    return False


def is_excluded(path: Path) -> bool:
    """Files whose use of a key is not the console rendering it.

    The catalogue's own directory, because a module calling itself is what
    being unread looks like from the inside; and tests, because a key
    exercised only by a test is the defect rather than the evidence against
    it.
    """
    if path == I18N_DIR or I18N_DIR in path.parents:
        return True
    if ".test." in path.name or ".spec." in path.name:
        return True
    test_dir = WEB_SRC / "test"
    return "__tests__" in path.parts or test_dir == path or test_dir in path.parents


def check_readers(base_keys: set[str]) -> int:
    """Fail when the catalogue, or any key in it, is rendered by nothing."""
    if not WEB_SRC.is_dir():
        print(
            f"check_i18n_keys.py: {WEB_SRC.name} is missing — cannot tell an unread catalogue from an unscanned tree",
            file=sys.stderr,
        )
        return 2

    sources: dict[str, str] = {}
    importers: list[str] = []
    scanned = 0
    for path in sorted(WEB_SRC.rglob("*.ts*")):
        if path.suffix not in {".ts", ".tsx"} or not path.is_file():
            continue
        if is_excluded(path):
            continue
        source = path.read_text(encoding="utf-8", errors="replace")
        relative = str(path.relative_to(REPO_ROOT))
        scanned += 1
        if imports_a_translator(source):
            sources[relative] = source
        if imports_catalogue(path, source):
            importers.append(relative)

    if not scanned:
        # "Found nothing" and "scanned nothing" print the same word unless
        # the gate counts what it opened.
        print(
            "check_i18n_keys.py: scanned zero console sources — refusing to report readers it never looked for",
            file=sys.stderr,
        )
        return 2

    rendered, unknown, unresolved = keys_rendered(sources, base_keys)
    unread = sorted(base_keys - rendered)
    print(
        f"\ni18n readers: {len(rendered)} of {len(base_keys)} base keys are rendered, "
        f"from {len(importers)} importer(s) and {len(sources)} translating file(s) "
        f"across {scanned} console source(s)"
    )
    if unresolved:
        print(f"  {unresolved} call site(s) pass a computed key, which credits nothing")

    failed = False

    if not importers:
        failed = True
        print("\nFAIL: nothing outside the catalogue's own directory imports it.")
        print("      Every check above compares the locales with each other, so all")
        print("      of them stay green while the whole capability is unreachable.")

    stale = sorted(k for k in KEYS_WITHOUT_A_READER if k in rendered)
    phantom = sorted(k for k in KEYS_WITHOUT_A_READER if k not in base_keys)
    excused = set(KEYS_WITHOUT_A_READER) - set(stale) - set(phantom)
    outstanding = [k for k in unread if k not in excused]

    if outstanding:
        failed = True
        by_surface: dict[str, list[str]] = {}
        for key in outstanding:
            by_surface.setdefault(_surface(key), []).append(key)
        print(f"\nFAIL: {len(outstanding)} base key(s) are rendered by no component:")
        for surface, keys in sorted(by_surface.items()):
            print(f"    {surface}: {', '.join(keys)}")
        print("      Render them, delete them, or record them in KEYS_WITHOUT_A_READER")
        print("      with the reason. A maintained string nobody can see is not a")
        print("      translation; it is a file.")

    if unknown:
        failed = True
        print(f"\nFAIL: {len(unknown)} call site(s) name a key the base catalogue lacks:")
        for site, key in sorted(unknown)[:20]:
            print(f"    {site}: {key}")
        print("      These render the key itself on screen. The mirror of an unknown")
        print("      key in a locale file, and just as invisible to the locales.")

    if stale:
        failed = True
        print(f"\nFAIL: KEYS_WITHOUT_A_READER excuses {len(stale)} key(s) that are read:")
        for key in stale:
            print(f"    {key}")
        print("      Remove the entry. An exemption nobody needs is one nobody rereads.")

    if phantom:
        failed = True
        print(f"\nFAIL: KEYS_WITHOUT_A_READER names {len(phantom)} key(s) the base lacks:")
        for key in phantom:
            print(f"    {key}")

    if failed:
        return 1
    excused_note = f", {len(excused)} excused" if excused else ""
    print(f"OK: every base key is rendered by a component{excused_note}.")
    return 0


def _self_test() -> int:
    cases: tuple[tuple[str, set[str], set[str], list[str], list[str]], ...] = (
        ("identical catalogues", {"a.b"}, {"a.b"}, [], []),
        ("an untranslated key is reported", {"a.b", "a.c"}, {"a.b"}, ["a.c"], []),
        ("a key the base lacks is reported", {"a.b"}, {"a.b", "a.z"}, [], ["a.z"]),
        ("both directions at once", {"a.b", "a.c"}, {"a.b", "a.z"}, ["a.c"], ["a.z"]),
    )
    failures = 0
    for name, base, locale, want_untranslated, want_unknown in cases:
        untranslated, unknown = compare(base, locale)
        ok = untranslated == want_untranslated and unknown == want_unknown
        failures += 0 if ok else 1
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")

    # The parser must read nesting rather than matching every `word:` in the
    # file — a docstring or a type declaration would otherwise contribute.
    sample = """
    /** A docstring with a decoy: fake: 'value' */
    export const en = {
      common: { save: 'Save', nested: { deep: 'x' } },
      // comment: 'ignored'
      nav: { alerts: 'Alerts' },
    } as const;
    export type Messages = typeof en;
    """
    parsed = _keys_from_source(sample)
    expected = {"common.save", "common.nested.deep", "nav.alerts"}
    ok = parsed == expected
    failures += 0 if ok else 1
    print(f"  {'PASS' if ok else 'FAIL'}  the parser reads nesting, not every 'word:' in the file")
    if not ok:
        print(f"        parsed={sorted(parsed)}")

    # The two bugs the first parser shipped with, each of which produced a
    # confident wrong number rather than an error.
    braces = """
    export const en = {
      alerts: { count: '{count} alerts', countOne: '1 alert' },
    } as const;
    """
    parsed = _keys_from_source(braces)
    ok = parsed == {"alerts.count", "alerts.countOne"}
    failures += 0 if ok else 1
    print(f"  {'PASS' if ok else 'FAIL'}  a brace inside a value does not open a nesting level")
    if not ok:
        print(f"        parsed={sorted(parsed)}")

    aliased = """
    type DeepPartial<T> = { [K in keyof T]?: T[K] };
    export const ar: DeepPartial<Messages> = {
      nav: { alerts: 'x' },
    };
    """
    parsed = _keys_from_source(aliased)
    ok = parsed == {"nav.alerts"}
    failures += 0 if ok else 1
    print(f"  {'PASS' if ok else 'FAIL'}  a type alias before the export is not mistaken for the catalogue")
    if not ok:
        print(f"        parsed={sorted(parsed)}")

    # ── The reader arm, both directions ──────────────────────────────────
    #
    # Written against the shapes the console actually uses, plus the two
    # that would quietly defeat the gate: a key named only by a test, and a
    # template with no literal prefix.
    base = {
        "alerts.title",
        "alerts.empty",
        "alerts.count",
        "severity.high",
        "severity.low",
        "nav.cases",
    }

    reader_cases: tuple[tuple[str, dict[str, str], set[str], list[str]], ...] = (
        (
            "a literal call site renders the key",
            {"AlertsView.tsx": "<h1>{t('alerts.title')}</h1>"},
            {"alerts.title"},
            [],
        ),
        (
            "the two-argument free function renders it too",
            {"a.tsx": "translate(locale, 'alerts.empty')"},
            {"alerts.empty"},
            [],
        ),
        (
            "hasTranslation counts, since it reads the catalogue",
            {"a.tsx": "hasTranslation(locale, 'nav.cases')"},
            {"nav.cases"},
            [],
        ),
        (
            "a template prefix credits its surface, not the whole catalogue",
            {"a.tsx": "t(`severity.${level}`)"},
            {"severity.high", "severity.low"},
            [],
        ),
        (
            "a template with no literal prefix credits nothing",
            {"a.tsx": "t(`${anything}`)"},
            set(),
            [],
        ),
        (
            "a computed key credits nothing",
            {"a.tsx": "t(key)"},
            set(),
            [],
        ),
        (
            "a call site naming a key the base lacks is reported",
            {"a.tsx": "t('alerts.titel')"},
            set(),
            ["alerts.titel"],
        ),
        (
            "a prefix matching no surface is reported",
            {"a.tsx": "t(`nope.${x}`)"},
            set(),
            ["nope.*"],
        ),
        (
            "a nested call does not confuse the argument split",
            {"a.tsx": "t('alerts.count', { n: fmt(a, b) })"},
            {"alerts.count"},
            [],
        ),
        (
            "an identifier ending in t is not a call site",
            {"a.tsx": "format('alerts.title'); split('alerts.empty')"},
            set(),
            [],
        ),
        (
            "a backtick inside an interpolation does not swallow the file",
            {"a.tsx": "x = `${f(`inner`)}`; t('alerts.title')"},
            {"alerts.title"},
            [],
        ),
        (
            "a concatenation is not a literal key",
            {"a.tsx": "t('alerts.' + name)"},
            set(),
            [],
        ),
        (
            "a call site written inside a comment is not a call site",
            {"a.tsx": "// t('alerts.title') would not work here\nt('alerts.empty')"},
            {"alerts.empty"},
            [],
        ),
    )
    for name, sources, want_rendered, want_unknown in reader_cases:
        rendered, unknown_sites, _ = keys_rendered(sources, base)
        found_unknown = [k for _, k in unknown_sites]
        ok = rendered == want_rendered and found_unknown == want_unknown
        failures += 0 if ok else 1
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
        if not ok:
            print(f"        rendered={sorted(rendered)} unknown={found_unknown}")

    # The exclusions are the arm, not a convenience: each of these is a
    # shape that has credited an unreachable capability in this repository.
    exclusion_cases: tuple[tuple[str, Path, bool], ...] = (
        ("a component counts", WEB_SRC / "components" / "alerts" / "AlertsView.tsx", False),
        ("the catalogue's own module does not", I18N_DIR / "index.ts", True),
        ("the catalogue's own test does not", I18N_DIR / "i18n.test.ts", True),
        ("a component's test does not", WEB_SRC / "components" / "X.test.tsx", True),
        ("a spec file does not", WEB_SRC / "components" / "X.spec.ts", True),
        ("test infrastructure does not", WEB_SRC / "test" / "setup.ts", True),
        ("a __tests__ directory does not", WEB_SRC / "a" / "__tests__" / "b.tsx", True),
    )
    for name, path, want in exclusion_cases:
        ok = is_excluded(path) == want
        failures += 0 if ok else 1
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")

    import_cases: tuple[tuple[str, Path, str, bool], ...] = (
        (
            "an alias import of the catalogue is an import",
            WEB_SRC / "components" / "a.tsx",
            "import { translate } from '@/lib/i18n';",
            True,
        ),
        (
            "a relative import of the catalogue is an import",
            WEB_SRC / "lib" / "a.ts",
            "import { LOCALES } from './i18n/locales';",
            True,
        ),
        (
            "an unrelated alias import is not",
            WEB_SRC / "components" / "a.tsx",
            "import { api } from '@/lib/api';",
            False,
        ),
        (
            "a package whose name contains i18n is not this catalogue",
            WEB_SRC / "components" / "a.tsx",
            "import x from 'next-i18next';",
            False,
        ),
    )
    for name, path, source, want in import_cases:
        ok = imports_catalogue(path, source) == want
        failures += 0 if ok else 1
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")

    # The precondition that stops a regex literal counting as a call site.
    # The last case is the one measured on the pre-fix tree.
    binding_cases: tuple[tuple[str, str, bool], ...] = (
        ("a component importing useLocale can translate", "import { useLocale } from '@/components/i18n/LocaleProvider';", True),
        ("a module importing translate can translate", "import { translate } from '@/lib/i18n';", True),
        ("a module importing only direction cannot", "import { direction } from '@/lib/i18n';", False),
        ("a module importing nothing relevant cannot", "import { clsx } from 'clsx';", False),
        ("a regex literal in a non-translating module is not a call site", "const m = /T(\\d+)/i.exec(s);", False),
    )
    for name, source, want in binding_cases:
        ok = imports_a_translator(source) == want
        failures += 0 if ok else 1
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")

    print()
    if failures:
        print(f"check_i18n_keys.py: self-test FAILED ({failures})")
        return 1
    print("check_i18n_keys.py: self-test OK")
    return 0


def check(max_untranslated: int) -> int:
    if not MESSAGES.is_dir():
        print(f"check_i18n_keys.py: {MESSAGES.relative_to(REPO_ROOT)} is missing", file=sys.stderr)
        return 2

    base_path = MESSAGES / f"{BASE}.ts"
    if not base_path.is_file():
        print(f"check_i18n_keys.py: base catalogue {BASE}.ts is missing", file=sys.stderr)
        return 2

    base_keys = load_catalogue(base_path)
    if not base_keys:
        print(
            "check_i18n_keys.py: parsed zero keys from the base catalogue — refusing to report agreement it never measured", file=sys.stderr
        )
        return 2

    print(f"i18n: base catalogue {BASE}.ts has {len(base_keys)} keys")

    failed = False
    total_untranslated = 0
    for path in sorted(MESSAGES.glob("*.ts")):
        if path.stem == BASE:
            continue
        locale_keys = load_catalogue(path)
        untranslated, unknown = compare(base_keys, locale_keys)
        total_untranslated += len(untranslated)

        by_surface: dict[str, int] = {}
        for key in untranslated:
            by_surface[_surface(key)] = by_surface.get(_surface(key), 0) + 1
        summary = ", ".join(f"{s} {n}" for s, n in sorted(by_surface.items())) or "none"
        print(f"  {path.stem}: {len(locale_keys)} translated, {len(untranslated)} untranslated ({summary})")

        if unknown:
            failed = True
            print(f"    FAIL: keys the base catalogue does not have: {unknown}")
            print("      These render nowhere, so no amount of using the console finds them.")
            print("      Usually a typo in the translated file, or a string deleted from the product.")

    if total_untranslated > max_untranslated:
        failed = True
        print(
            f"\nFAIL: {total_untranslated} untranslated keys against a ceiling of {max_untranslated}. "
            "The ceiling is a debt balance, not a target — translate the keys, do not raise it."
        )

    if not failed:
        print(f"\nOK: no unknown keys, and {total_untranslated} untranslated within the ceiling ({max_untranslated}).")

    readers = check_readers(base_keys)
    if readers == 2:
        return 2
    return 1 if failed or readers else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--max-untranslated", type=int, default=MAX_UNTRANSLATED)
    args = parser.parse_args()
    return _self_test() if args.self_test else check(args.max_untranslated)


if __name__ == "__main__":
    raise SystemExit(main())
