#!/usr/bin/env python3
"""One file says what version this build is, and every surface derives from it.

Why this exists
---------------
The root ``VERSION`` file is the single source of truth. A surface that
restates it instead of reading it is only correct until the next release — at
which point nothing notices, because agreeing with a constant is not something
anyone checks.

**This gate is green on arrival, and that is the point.** It was written
against a live defect; #1732 fixed the defect before this landed. What
remains is prevention, so read the paragraph below as history rather than as
a finding — a stale problem statement read as a live one is a mistake this
repository has made before.

The defect, measured when this gate was written (``VERSION`` = 22.2.0):

    services/api/app/core/config.py   APP_VERSION = "0.1.0"
    services/api/app/core/config.py   VERSION     = "0.1.0"

``settings.VERSION`` is what the API reports — it is the ``version=`` passed to
the FastAPI application, so it is also the version in the published OpenAPI
document, and it is served as a JSON field by the root route. A deployment
running 22.2.0 therefore told every client it was **0.1.0**, and had done since
the literal was written. No gate compared the two, because no gate existed that
knew they were the same number.

``APP_VERSION`` now reads ``Field(default_factory=resolve_version)`` against
``app/core/version.py``. Re-measured on this tree: all five registered
surfaces derive, none restates. Reverting that one line to the literal is the
gate's negative control and it exits 1 naming both numbers.

The console reaches the same number by two independent routes: the repo-root
``VERSION`` file inlined at build time as ``NEXT_PUBLIC_APP_VERSION``, and
``apps/web/package.json`` imported directly by the sidebar. Those agree today
only because ``check_release_policy.py`` separately holds ``VERSION`` and
``package.json`` in step. Two origins kept in sync by a third thing is not one
source of truth; it is a coincidence with a maintainer.

What it asserts
---------------
Two rules over a registry of surfaces that report the application's version.

``agreement``
    A surface that resolves to a concrete version must resolve to the tree's
    ``VERSION``. This is the arm that caught the ``0.1.0`` defect above, and
    it names the real number on both sides, so the failure says what is wrong
    rather than only that something is.

``single-origin``
    A surface may not *restate* the version. Deriving it is fine however it is
    delivered — read the file, inline it at build time, serve it from a runtime
    endpoint. Carrying a version-shaped string literal is not, because that
    literal is a second declaration of the same fact and it cannot be kept
    right by anything except someone remembering.

    A fallback counts. ``'0.0.0'`` is a plausible-looking version and renders
    as one, so a read that failed becomes a build that confidently claims to be
    0.0.0. The honest fallback is a sentinel that cannot be mistaken for a
    version, which is what ``runtime-config/route.ts`` already does with
    ``'unknown'`` — that is the shape to copy, and it is why this gate takes
    ``unknown`` and refuses ``0.0.0``.

    Importing the number from ``apps/web/package.json`` is the same defect
    wearing a different costume: a second origin rather than a second copy.

Non-vacuity
-----------
Every way this gate could report OK without doing its work is closed, because
that is the failure mode the repository keeps re-finding:

* the root is resolved with ``gate_toolkit.repo_root()``, from git, so a copy
  of this script run from elsewhere describes a real checkout or says it could
  not find one — never a confident OK about a tree nobody asked about;
* an absent, empty or non-semver ``VERSION`` is a refusal, not a pass. There is
  nothing to agree with, so "everything agrees" would be a lie;
* **every registered surface must exist and be readable.** A renamed or deleted
  file fails here rather than quietly reducing coverage to the files that
  happen to remain — the shape that let a one-directional gate print OK while
  the thing it watched had moved;
* a run that scanned zero surfaces, or found zero version-reporting symbols on
  a surface that is registered as carrying one, is a refusal;
* ``--self-test`` drives the classifier in **both** directions over synthetic
  content — a clean surface must pass and each violating shape must be caught —
  and then runs the gate against a tree with no content and requires it to
  refuse.

Usage
-----
    python3 scripts/check_single_version_source.py              # gate
    python3 scripts/check_single_version_source.py --list       # per-surface detail
    python3 scripts/check_single_version_source.py --self-test  # prove it detects drift

Exit codes: 0 clean, 1 findings, 2 the scan itself could not run.
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import SELF_TEST_FLAG, repo_root, self_test_main

#: A version-shaped string literal. Deliberately not anchored to semver's full
#: grammar: `0.1.0`, `1.2`, `22.2.0-rc1` are all numbers a reader takes for a
#: version, and all of them are a second declaration of it.
VERSION_SHAPED = re.compile(r"^\d+\.\d+(\.\d+)?([-+][0-9A-Za-z.-]+)?$")

#: What `VERSION` itself has to look like for this gate to have a question to
#: ask. An empty or malformed file means there is no source of truth to compare
#: against, which is a refusal rather than a pass.
SEMVER = re.compile(r"^\d+\.\d+\.\d+([-+][0-9A-Za-z.-]+)?$")

#: Fallbacks that cannot be mistaken for a version. A surface is allowed to say
#: it does not know; it is not allowed to guess a plausible number.
HONEST_SENTINELS = frozenset({"unknown", "unset", "", "dev", "development", "n/a", "not-set"})


@dataclass(frozen=True)
class Surface:
    """A file that reports the application's version, and how it is read."""

    path: str
    #: Python attribute names, or JS/TS identifiers, that carry the version.
    symbols: tuple[str, ...]
    #: What this surface is, in the failure message.
    reports: str


#: The surfaces that tell someone what version this build is.
#:
#: Registered explicitly rather than discovered, because the question "does
#: this file report a version" has no syntactic answer — and a gate that
#: guessed would both miss surfaces and flag the changelog. Each entry must
#: exist: see `collect`, which refuses a missing one rather than skipping it.
SURFACES: tuple[Surface, ...] = (
    Surface(
        path="services/api/app/core/config.py",
        symbols=("APP_VERSION", "VERSION"),
        reports="the version the API serves to every client (FastAPI `version=`, the OpenAPI document, the root route)",
    ),
    Surface(
        path="apps/web/next.config.js",
        symbols=("APP_VERSION",),
        reports="the version baked into the console bundle as NEXT_PUBLIC_APP_VERSION",
    ),
    # Both console surfaces are listed under the spelling they use today *and*
    # the one they are moving to. The symbol is how this gate finds the value,
    # so a rename it does not know about makes the surface unwatched — and the
    # gate refuses rather than reporting it clean, which is how this list came
    # to carry both: it fired on exactly that, against a change that renames
    # `APP_VERSION` and `NEXT_PUBLIC_APP_VERSION` to a `consoleVersion` read
    # from one runtime hook. The refusal was right and the registry was stale.
    Surface(
        path="apps/web/src/components/layout/Sidebar.tsx",
        symbols=("APP_VERSION", "consoleVersion", "useConsoleVersion"),
        reports="the version rendered in the console sidebar",
    ),
    Surface(
        path="apps/web/src/components/settings/SettingsView.tsx",
        symbols=("NEXT_PUBLIC_APP_VERSION", "consoleVersion", "useConsoleVersion"),
        reports="the version rendered in Settings → About",
    ),
    Surface(
        path="apps/web/src/app/api/runtime-config/route.ts",
        symbols=("consoleVersion",),
        reports="the version the console reports at runtime from /api/runtime-config",
    ),
)

#: Reading the version out of the web package manifest is a second *origin*,
#: not a second copy. It agrees with `VERSION` today only because
#: `check_release_policy.py` holds the two in step; nothing makes the console
#: read the one the rest of the tree treats as authoritative.
PACKAGE_JSON_ORIGIN = re.compile(r"\bpackageJson\s*\.\s*version\b|\brequire\(\s*['\"][^'\"]*package\.json['\"]\s*\)\s*\.\s*version\b")


@dataclass
class Finding:
    path: str
    line: int
    rule: str
    detail: str


@dataclass
class SurfaceReport:
    surface: Surface
    #: ``(line, literal, is_fallback)``. The third element is what separates
    #: "this restates the version" from "this is what a failed read renders
    #: as", which `grade` turns into two different sentences.
    literals: list[tuple[int, str, bool]] = field(default_factory=list)
    package_json_lines: list[int] = field(default_factory=list)
    symbols_seen: int = 0


def read_version(root: Path) -> str:
    """The tree's version, or a refusal. Never a default."""
    path = root / "VERSION"

    def refuse(reason: str) -> None:
        print(f"FAIL  {reason}")
        print()
        print("Refusing to report a tree clean when it carries nothing to be clean about.")
        raise SystemExit(2)

    try:
        raw = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        refuse(f"{path} is unreadable ({exc.__class__.__name__}); there is no source of truth to compare against")
    if not raw:
        refuse(f"{path} is empty; there is no source of truth to compare against")
    if not SEMVER.match(raw):
        refuse(f"{path} holds {raw!r}, which is not a version; refusing to grade against it")
    return raw


def python_literals(source: str, symbols: tuple[str, ...]) -> tuple[list[tuple[int, str, bool]], int]:
    """Version-shaped literals assigned to ``symbols``, and how many were found.

    Only the *assigned value* is inspected, so a version mentioned in a comment
    or a docstring is not a finding — a gate that flagged prose would be
    switched off within a week, and this file's own docstring quotes the
    literal it exists to catch.
    """
    tree = ast.parse(source)
    found: list[tuple[int, str, bool]] = []
    seen = 0
    targets: list[str]
    value: ast.expr | None
    for node in ast.walk(tree):
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            targets, value = [node.target.id], node.value
        elif isinstance(node, ast.Assign):
            targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
            value = node.value
        else:
            # Anything that is not one of those two statements is skipped here
            # rather than filtered below, which is also what makes `node.lineno`
            # provable: `ast.walk` yields `ast.AST`, and only the two narrowed
            # types above are guaranteed to carry a line number.
            continue
        if not targets or value is None:
            continue
        for name in targets:
            if name not in symbols:
                continue
            seen += 1
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                if VERSION_SHAPED.match(value.value.strip()):
                    # A pydantic field default is the value the setting takes
                    # whenever the environment does not override it, which on
                    # a default deployment is always. It is the primary.
                    found.append((node.lineno, value.value.strip(), False))
    return found, seen


#: A version-shaped string in JS/TS. Matched against quoted literals only, so
#: a dependency range in prose or a comment is not swept in.
_JS_STRING = re.compile(r"""(['"`])(\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.-]+)?)\1""")


def js_literals(source: str, symbols: tuple[str, ...]) -> tuple[list[tuple[int, str, bool]], int]:
    """Version-shaped string literals on lines that mention a version symbol.

    Line-scoped rather than parsed: this tree has no JS parser available to a
    bare interpreter, and the alternative — flagging every version-shaped
    string in a `.tsx` file — would hit dependency pins and test fixtures and
    be correctly ignored. Scoping to a line that also names the version symbol
    keeps every finding one a reader agrees with on sight.
    """
    found: list[tuple[int, str, bool]] = []
    seen = 0
    for number, line in enumerate(source.splitlines(), start=1):
        code = line.split("//", 1)[0]
        if not any(sym in code for sym in symbols):
            continue
        seen += 1
        # Two shapes mean "the derived read is still the primary, this is what
        # it falls back to": a `||`/`??` immediately before the literal, and a
        # *mutable* declaration initialised to it, which is the `let x = '0.0.0'`
        # that a following try/catch overwrites. A `const` initialised to a
        # literal cannot be overwritten, so that one really is the value.
        # Both are findings either way; they are different sentences, and
        # printing the wrong one would make the gate's own message untrue.
        mutable_init = bool(re.match(r"\s*(let|var)\s+\w+\s*=", code))
        for match in _JS_STRING.finditer(code):
            literal = match.group(2).strip()
            if literal.lower() in HONEST_SENTINELS:
                continue
            coalesced = bool(re.search(r"(\|\||\?\?)\s*$", code[: match.start()]))
            found.append((number, literal, coalesced or mutable_init))
    return found, seen


def inspect(surface: Surface, source: str) -> SurfaceReport:
    report = SurfaceReport(surface=surface)
    if surface.path.endswith(".py"):
        report.literals, report.symbols_seen = python_literals(source, surface.symbols)
    else:
        report.literals, report.symbols_seen = js_literals(source, surface.symbols)
        for number, line in enumerate(source.splitlines(), start=1):
            if PACKAGE_JSON_ORIGIN.search(line.split("//", 1)[0]):
                report.package_json_lines.append(number)
    return report


def collect(root: Path) -> tuple[list[SurfaceReport], list[str]]:
    """Read every registered surface. A missing one is an error, never a skip."""
    reports: list[SurfaceReport] = []
    errors: list[str] = []
    for surface in SURFACES:
        path = root / surface.path
        try:
            source = path.read_text(encoding="utf-8")
        except OSError as exc:
            errors.append(
                f"{surface.path}: registered as reporting {surface.reports}, but it could not "
                f"be read ({exc.__class__.__name__}). Update SURFACES in the same change that "
                f"moves the file."
            )
            continue
        try:
            reports.append(inspect(surface, source))
        except SyntaxError as exc:
            errors.append(f"{surface.path}: could not be parsed ({exc}); refusing to report it clean")
    return reports, errors


def grade(reports: list[SurfaceReport], version: str) -> list[Finding]:
    findings: list[Finding] = []
    for report in reports:
        for line, literal, is_fallback in report.literals:
            if is_fallback:
                rule = "single-origin"
                detail = (
                    f"falls back to the literal {literal!r} when the derived read fails. That is a plausible-looking "
                    f"version, so a failed read renders as a confident claim to be {literal} rather than as a failed "
                    f"read. Use a sentinel that cannot be mistaken for a version — 'unknown', as "
                    f"runtime-config/route.ts already does."
                )
            elif literal == version:
                rule = "single-origin"
                detail = (
                    f"restates the version as the literal {literal!r}. It agrees with VERSION today and will stop "
                    f"agreeing at the next release, silently — derive it from the root VERSION file instead."
                )
            else:
                rule = "agreement"
                detail = (
                    f"reports {literal!r} while the tree is {version!r}. This surface is {report.surface.reports}, "
                    f"so that is the version it is telling people they are running."
                )
            findings.append(Finding(report.surface.path, line, rule, detail))
        for line in report.package_json_lines:
            findings.append(
                Finding(
                    report.surface.path,
                    line,
                    "single-origin",
                    "takes the version from apps/web/package.json, a second origin. It matches VERSION only "
                    "because check_release_policy.py holds those two in step; read the value the rest of the "
                    "tree derives from instead.",
                )
            )
    return findings


# ── self-test ───────────────────────────────────────────────────────────────

_CLEAN_PY = "class Settings:\n    APP_VERSION: str = _version_from_tree()\n    VERSION: str = APP_VERSION\n"
_DIRTY_PY = 'class Settings:\n    APP_VERSION: str = "0.1.0"\n    VERSION: str = "0.1.0"\n'
_PROSE_PY = '"""APP_VERSION was once "0.1.0"."""\nAPP_VERSION: str = derive()\n'
_CLEAN_TSX = "const APP_VERSION = runtimeConfig.consoleVersion ?? 'unknown';\n"
_DIRTY_TSX = "const APP_VERSION = packageJson.version;\n"
_FALLBACK_TSX = "value={`v${process.env.NEXT_PUBLIC_APP_VERSION || '0.0.0'}`}\n"
_MUTABLE_INIT_JS = "let APP_VERSION = '0.0.0';\n"
_CONST_LITERAL_JS = "const APP_VERSION = '0.1.0';\n"


def _self_test_cases() -> list[tuple[str, bool]]:
    """Both directions: a clean surface passes, each violating shape is caught."""
    py = Surface(path="x.py", symbols=("APP_VERSION", "VERSION"), reports="t")
    tsx = Surface(path="x.tsx", symbols=("APP_VERSION", "NEXT_PUBLIC_APP_VERSION"), reports="t")

    clean_py = grade([inspect(py, _CLEAN_PY)], "22.2.0")
    dirty_py = grade([inspect(py, _DIRTY_PY)], "22.2.0")
    prose_py = grade([inspect(py, _PROSE_PY)], "22.2.0")
    agreeing = grade([inspect(py, 'APP_VERSION: str = "22.2.0"\n')], "22.2.0")
    clean_tsx = grade([inspect(tsx, _CLEAN_TSX)], "22.2.0")
    dirty_tsx = grade([inspect(tsx, _DIRTY_TSX)], "22.2.0")
    fallback = grade([inspect(tsx, _FALLBACK_TSX)], "22.2.0")
    mutable = grade([inspect(tsx, _MUTABLE_INIT_JS)], "22.2.0")
    const_lit = grade([inspect(tsx, _CONST_LITERAL_JS)], "22.2.0")

    return [
        ("a Python surface deriving its version is accepted", not clean_py),
        ("a Python surface restating a stale version is caught", len(dirty_py) == 2 and all(f.rule == "agreement" for f in dirty_py)),
        ("a version quoted in a docstring is not a finding", not prose_py),
        (
            "a literal that agrees with VERSION today is still caught as a second declaration",
            len(agreeing) == 1 and agreeing[0].rule == "single-origin",
        ),
        ("a console surface reading a runtime value with an honest sentinel is accepted", not clean_tsx),
        ("a console surface taking the version from package.json is caught", len(dirty_tsx) == 1 and dirty_tsx[0].rule == "single-origin"),
        (
            "a version-shaped fallback like '0.0.0' is caught, and named as a fallback",
            len(fallback) == 1 and fallback[0].rule == "single-origin" and "falls back" in fallback[0].detail,
        ),
        (
            "a mutable initialiser a later read overwrites is caught, and named as a fallback",
            len(mutable) == 1 and "falls back" in mutable[0].detail,
        ),
        ("a const literal is caught, and named as the value the surface reports", len(const_lit) == 1 and const_lit[0].rule == "agreement"),
    ]


def main(argv: list[str] | None = None) -> int:
    # Answered before the gate touches the tree, and with this gate's own
    # both-directions cases attached — `self_test_if_requested` carries only
    # the empty-tree probe, which on its own would prove the gate fails
    # closed without proving it detects anything.
    if SELF_TEST_FLAG in (argv if argv is not None else sys.argv[1:]):
        return self_test_main(Path(__file__).name, [], _self_test_cases())

    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--list", action="store_true", help="print every surface and what it was found to do")
    parser.add_argument(SELF_TEST_FLAG, action="store_true", help="prove this gate still detects what it claims to")
    args = parser.parse_args(argv)

    root = repo_root()
    version = read_version(root)

    reports, errors = collect(root)
    print(f"checkout   {root}")
    print(f"VERSION    {version}")
    print(f"surfaces   {len(reports)} of {len(SURFACES)} read")
    print()

    if errors:
        for message in errors:
            print(f"FAIL  {message}")
        print()
        print("Refusing to render a verdict over a surface set this gate could not read in full.")
        return 2

    if not reports:
        print("FAIL: no surfaces were read, so a clean result would mean nothing.")
        return 2

    blind = [r for r in reports if r.symbols_seen == 0]
    if blind:
        for report in blind:
            symbols = ", ".join(report.surface.symbols)
            print(f"FAIL  {report.surface.path}: registered as reporting {report.surface.reports},")
            print(f"      but none of its version symbols ({symbols}) was found in the file.")
        print()
        print("A surface whose version symbol has been renamed is unwatched, not clean.")
        return 2

    if args.list:
        for report in reports:
            state = "derives from VERSION"
            if report.literals or report.package_json_lines:
                state = "RESTATES the version"
            print(f"  {report.surface.path:<56} {report.symbols_seen:>2} symbol(s)  {state}")
        print()

    findings = grade(reports, version)
    if findings:
        for finding in findings:
            print(f"FAIL  {finding.path}:{finding.line}  [{finding.rule}]")
            print(f"      {finding.detail}")
        print()
        print(f"{len(findings)} finding(s). The root VERSION file is the only place that may declare this")
        print("build's version; every surface above has to derive from it.")
        return 1

    print(f"OK — all {len(reports)} version-reporting surface(s) derive from VERSION ({version}); none restates it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
