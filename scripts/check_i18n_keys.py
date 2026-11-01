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
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
MESSAGES = REPO_ROOT / "apps" / "web" / "src" / "lib" / "i18n" / "messages"
BASE = "en"

#: Backlog ceiling. Not a target — a debt balance, in the same sense as
#: `check_route_authz.py`'s. Lower it when a locale is finished; never raise
#: it to make a run pass.
MAX_UNTRANSLATED = 6


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

    if failed:
        return 1
    print(f"\nOK: no unknown keys, and {total_untranslated} untranslated within the ceiling ({max_untranslated}).")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--max-untranslated", type=int, default=MAX_UNTRANSLATED)
    args = parser.parse_args()
    return _self_test() if args.self_test else check(args.max_untranslated)


if __name__ == "__main__":
    raise SystemExit(main())
