#!/usr/bin/env python3
"""Every repository path named in a code comment must exist.

Why this exists as a separate gate
----------------------------------
``docker-compose.yml`` carried a reference to
``docs/architecture/decisions/0001-llm-gateway-in-core.md`` — a path with no
directory behind it. Two workstreams tripped over it within an hour, and it
had survived every check in the tree, because **a comment is the one place
no gate reads**. ``check_repo_self_links.py`` opens markdown and matches
``github.com/...`` URLs; lychee resolves links; nothing had ever looked at
the prose inside source files, which is where most cross-file references in
this repository actually live.

That prose is load-bearing. "Keep this in sync with X", "the operator table
lives at Y", "CI check Z compares the two sets" — each is an instruction to
the next contributor, and each is worthless the moment the path is wrong. On
its first run this gate found nine dead references in comments and thirteen
more in Python docstrings, including a migration renumbered 055 → 063, a
connector doc that moved under ``apps/docs/docs/``, and three separate
pointers at CI checks that had never been written.

What it reads, and what it deliberately does not
------------------------------------------------
The corpus was measured before the gate was written, because a naive version
would have been mostly noise. Of **3,092** path-shaped strings in non-
markdown comments, most are not repository paths at all: MIME types, MCP
method names (``tools/call``), Splunk REST routes (``services/search/jobs``),
container images, URL routes, Go import paths. Flagging those would produce a
gate people learn to ignore, which is worse than none.

Three structural filters cut the corpus to the references that are actually
claims about this tree:

1. **A known file extension.** ``tools/call`` and ``services/ocsf`` are not
   files. This is also what excludes ``cost_telemetry._PRICING`` and
   ``graph_ws.Broadcaster``, which are attribute references wearing a slash.
2. **A first segment that names something at the top of this repository.**
   ``application/json`` and ``github.com/x/y`` do not survive it; the
   ``docs/…`` reference that started this does.
3. **Not a URL, not templated, not a glob, not gitignored.** A build artefact
   under ``dist/`` legitimately does not exist in a clean checkout.

A path is then resolved against the repository root *and* against each
ancestor of the file that mentions it, because a comment in
``services/agents/tests/`` saying ``tests/conftest.py`` means the one beside
it, not one at the root.

Measured blind spot, accepted on purpose
----------------------------------------
Extension-less directory references — ``infra/terraform/aws``,
``services/ocsf`` — are **not** checked. 286 of them resolve and 52 do not,
and hand-classifying the 52 put genuine rot at roughly one in five: the rest
are URL routes, API paths and tool names that happen to start with a
directory name. A gate at 20% precision is a gate that gets ignored, so this
one says what it skipped (see the summary it prints) rather than guessing.

Exceptions
----------
``ACCEPTED`` records the references that are deliberately unresolvable:
placeholders in usage text, and prose *about* a path that was removed or
moved. Each carries a reason and is checked in both directions — an entry
naming a reference that now resolves, or one that is no longer in the
corpus, fails the build rather than sitting there.

Usage
-----
    python3 scripts/check_comment_paths.py
    python3 scripts/check_comment_paths.py --list       # every reference read
    python3 scripts/check_comment_paths.py --self-test  # prove it still detects

Exit codes: 0 clean, 1 findings, 2 the scan itself could not run.
"""

from __future__ import annotations

import argparse
import ast
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

# `scripts/` is on sys.path when this file is run as a program, but not when a
# test loads it by path with importlib. gate_toolkit sits beside it either way.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import SELF_TEST_FLAG, repo_root, self_test_main  # noqa: E402

# --------------------------------------------------------------------------
# Corpus definition
# --------------------------------------------------------------------------
#: (line-comment token, block-comment delimiters) per extension. A language
#: absent from here is not read, and the summary says how many files that was.
COMMENT_SYNTAX: dict[str, tuple[str | None, tuple[str, str] | None]] = {
    ".py": ("#", None),
    ".sh": ("#", None),
    ".bash": ("#", None),
    ".yaml": ("#", None),
    ".yml": ("#", None),
    ".toml": ("#", None),
    ".tf": ("#", None),
    ".ini": ("#", None),
    ".cfg": ("#", None),
    ".go": ("//", ("/*", "*/")),
    ".ts": ("//", ("/*", "*/")),
    ".tsx": ("//", ("/*", "*/")),
    ".js": ("//", ("/*", "*/")),
    ".mjs": ("//", ("/*", "*/")),
    ".cjs": ("//", ("/*", "*/")),
    ".sql": ("--", ("/*", "*/")),
}

#: Files with no extension that are still comment-bearing.
COMMENT_FILENAMES = {"Dockerfile": ("#", None), "Makefile": ("#", None)}

#: An archived prototype subtree kept for history; its paths describe a repo
#: that no longer exists. CodeQL excludes it for the same reason.
EXCLUDED_PREFIXES = ("plans/cyble-aisoc/",)

#: Suffixes that make a token a plausible file reference. Anything else is
#: either not a file or a directory, and directories are the measured blind
#: spot documented above.
FILE_SUFFIXES = frozenset(
    {
        ".py",
        ".go",
        ".ts",
        ".tsx",
        ".js",
        ".mjs",
        ".cjs",
        ".md",
        ".mdx",
        ".yaml",
        ".yml",
        ".json",
        ".sql",
        ".sh",
        ".tf",
        ".toml",
        ".ini",
        ".cfg",
        ".txt",
        ".lock",
        ".tmpl",
        ".tpl",
        ".mod",
        ".sum",
        ".css",
        ".html",
        ".svg",
        ".png",
    }
)

#: A path-shaped run of characters. The first segment is deliberately
#: narrower than the rest: a leading `(` or `[` is punctuation around the
#: reference, while `apps/web/src/app/(app)/…` is a real Next.js route group.
TOKEN_RE = re.compile(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.()\[\]-]+)+")

#: Trailing punctuation a sentence leaves attached to a path.
TRAILING = "`'\"),;:.]}>"

#: A scheme, or a dotted host followed by a slash, immediately before the
#: token — in which case the token is part of a URL and not our path.
URL_PREFIX_RE = re.compile(r"(?:[A-Za-z][A-Za-z0-9+.-]*://\S*|[A-Za-z0-9-]+\.[A-Za-z]{2,}/\S*)$")


# --------------------------------------------------------------------------
# Recorded exceptions. Shrink-only, checked in both directions.
# --------------------------------------------------------------------------
#: Keyed ``(file, token) -> reason``. An entry whose reference now resolves,
#: or which no longer appears in the corpus at all, is a finding: a stale
#: exception is how a list stops describing the tree it excuses.
ACCEPTED: dict[tuple[str, str], str] = {
    (".github/workflows/screencast.yml", "apps/web/pnpm-lock.yaml"): (
        "Prose asserting the file's absence — the sentence is 'apps/web/pnpm-lock.yaml does not "
        "exist', which is the fact the step depends on."
    ),
    ("apps/web/eslint.config.mjs", "apps/web/.eslintrc.json"): (
        "Names the file this config replaced. The reference is historical and rewriting it to a "
        "path that exists would lose the only record of the migration."
    ),
    ("infra/fly/managed/provision.sh", "infra/fly/managed/tenants/acme.yaml"): (
        "A placeholder tenant file in the usage line. Real tenant descriptors are supplied by the "
        "operator and are not committed."
    ),
    ("infra/fly/managed/render.sh", "infra/fly/managed/tenants/acme.yaml"): (
        "Same usage line in the sibling script, same placeholder."
    ),
    ("scripts/audit_runbook_links.py", "docs/runbooks/foo.md"): (
        "An illustrative path in a docstring explaining which link shapes the gate accepts."
    ),
    ("scripts/check_competitor_names.py", "docs/connectors/x.md"): (
        "An illustrative path in a docstring explaining glob semantics: 'docs/connectors/** matches "
        "docs/connectors/x.md'."
    ),
    ("scripts/check_gate_contract.py", "scripts/foo.py"): (
        "An illustrative path in a docstring showing what shlex returns for a quoted path inside an "
        "echo. Naming a real script would make the example read as a claim about that script."
    ),
    ("scripts/check_repo_self_links.py", "services/api/app/api/deps.py"): (
        "Prose recording the dead link that motivated that gate — the path moved under v1/, and the "
        "sentence is about it having moved."
    ),
    ("tools/detection_import/splunk_importer.py", "detections/cloud/foo.yml"): (
        "An illustrative path in a docstring showing how a category is derived from a rule path."
    ),
    ("scripts/aisoc-demo.ts", "apps/web/public/screenshots/01-alerts-queue.png"): (
        "An output destination, not an existing file: `--screenshots` writes the four PNGs there "
        "from a live stack. The directory ships SVG placeholders until someone runs it, which "
        "apps/web/public/screenshots/README.md states."
    ),
}


# --------------------------------------------------------------------------
# Reading the corpus
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class Reference:
    """One path-shaped token found in one comment."""

    file: str
    line: int
    token: str
    context: str


class ScanError(RuntimeError):
    """The scan could not be set up. Never downgraded to a clean result."""


def tracked_files(root: Path) -> list[str]:
    out = subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["git", "ls-files"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    if out.returncode != 0:
        raise ScanError(f"cannot list tracked files under {root}: {out.stderr.strip()}")
    return [f for f in out.stdout.splitlines() if f and not f.startswith(EXCLUDED_PREFIXES)]


def ignored_paths(root: Path, candidates: list[str]) -> set[str]:
    """Which candidates git would ignore. One subprocess, not one per path.

    A reference to ``services/mcp/dist/index.js`` is correct and unresolvable
    at the same time: the file is a build artefact that exists at runtime and
    never in a checkout. Asking git keeps that judgement structural instead of
    becoming a second list of directory names to maintain.
    """
    if not candidates:
        return set()
    out = subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["git", "check-ignore", "--stdin"],
        cwd=root,
        input="\n".join(candidates),
        capture_output=True,
        text=True,
        check=False,
    )
    return {line.strip() for line in out.stdout.splitlines() if line.strip()}


def comment_text(path: Path, ext: str) -> list[tuple[int, str]]:
    """Every comment in the file, as (line number, comment body).

    Crude on purpose: a ``#`` inside a string literal is read as a comment.
    That costs nothing, because the token still has to survive three
    structural filters and then fail to resolve before it is reported.
    """
    line_token, block = COMMENT_SYNTAX.get(ext, COMMENT_FILENAMES.get(path.name, (None, None)))
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return []
    out: list[tuple[int, str]] = []
    in_block = False
    for lineno, line in enumerate(text.splitlines(), start=1):
        rest = line
        if block:
            if in_block:
                end = rest.find(block[1])
                if end >= 0:
                    out.append((lineno, rest[:end]))
                    in_block = False
                    rest = rest[end + len(block[1]) :]
                else:
                    out.append((lineno, rest))
                    continue
            start = rest.find(block[0])
            if start >= 0:
                end = rest.find(block[1], start + len(block[0]))
                if end >= 0:
                    out.append((lineno, rest[start + len(block[0]) : end]))
                    rest = rest[:start] + " " + rest[end + len(block[1]) :]
                else:
                    out.append((lineno, rest[start + len(block[0]) :]))
                    in_block = True
                    continue
        if line_token:
            found = re.search(r"(?:^|\s)" + re.escape(line_token), rest)
            if found:
                out.append((lineno, rest[found.end() :]))
    return out


def docstring_text(path: Path) -> list[tuple[int, str]]:
    """Every Python docstring, as (line number, line).

    Docstrings are the same invisible prose as comments and carry more of it:
    they held thirteen of the twenty-two dead references this gate found on
    its first run, including every 'keep these copies in sync' pointer.
    """
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (SyntaxError, UnicodeDecodeError, OSError, ValueError):
        return []
    out: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Module | ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            continue
        doc = ast.get_docstring(node, clean=False)
        if not doc:
            continue
        first = getattr(node.body[0], "lineno", 1) if node.body else 1
        # The literal's lineno is its last line for a multi-line string in
        # some versions; anchoring at the node keeps the number close enough
        # to find the text, which is all a reader needs.
        start = first - doc.count("\n")
        for offset, line in enumerate(doc.splitlines()):
            out.append((max(1, start + offset), line))
    return out


def extract(root: Path, files: list[str]) -> tuple[list[Reference], dict[str, int]]:
    """Every path-shaped token in every comment and docstring we can read."""
    refs: list[Reference] = []
    counts = {"files_read": 0, "files_skipped_unknown_syntax": 0, "tokens_seen": 0}
    for rel in files:
        path = root / rel
        ext = path.suffix
        readable = ext in COMMENT_SYNTAX or path.name in COMMENT_FILENAMES
        if not readable:
            counts["files_skipped_unknown_syntax"] += 1
            continue
        counts["files_read"] += 1
        lines = comment_text(path, ext)
        if ext == ".py":
            lines += docstring_text(path)
        for lineno, body in lines:
            for match in TOKEN_RE.finditer(body):
                counts["tokens_seen"] += 1
                token = match.group(0).rstrip(TRAILING)
                if not token or URL_PREFIX_RE.search(body[: match.start()]):
                    continue
                refs.append(Reference(file=rel, line=lineno, token=token, context=body.strip()[:120]))
    return refs, counts


# --------------------------------------------------------------------------
# Deciding which references are claims about this tree
# --------------------------------------------------------------------------
def is_repo_path(token: str, toplevel: frozenset[str]) -> bool:
    """Whether this token is asserting that a file exists in this repository.

    Three structural questions, in the order that discards the most: is it a
    URL or a template, does it name a file, and does it start at the top of
    this tree. See the module docstring for the measurement behind each.
    """
    if "://" in token or "$" in token or "{" in token or "*" in token:
        return False
    if Path(token).suffix not in FILE_SUFFIXES:
        return False
    return token.split("/", 1)[0] in toplevel


def resolve(ref: Reference, known: frozenset[str]) -> str | None:
    """The path this reference names, or None.

    Tried against the repository root first and then against each ancestor of
    the referring file, because ``tests/conftest.py`` in a comment inside
    ``services/agents/tests/`` means the one beside it.
    """
    if ref.token in known:
        return ref.token
    base = Path(ref.file).parent
    for parent in [base, *base.parents]:
        if str(parent) == ".":
            continue
        candidate = f"{parent}/{ref.token}"
        if candidate in known:
            return candidate
    return None


def known_paths(files: list[str]) -> frozenset[str]:
    """Every tracked file and every directory containing one."""
    known: set[str] = set(files)
    for rel in files:
        for parent in Path(rel).parents:
            if str(parent) != ".":
                known.add(str(parent))
    return frozenset(known)


@dataclass
class Result:
    refs_examined: int = 0
    resolved: int = 0
    excused: int = 0
    ignored: int = 0
    missing: list[Reference] = None  # type: ignore[assignment]
    stale_exceptions: list[tuple[tuple[str, str], str]] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.missing is None:
            self.missing = []
        if self.stale_exceptions is None:
            self.stale_exceptions = []


def judge(
    refs: list[Reference],
    known: frozenset[str],
    toplevel: frozenset[str],
    ignored: frozenset[str],
    accepted: dict[tuple[str, str], str],
) -> Result:
    """Pure verdict over an already-read corpus, so the self-test can drive it."""
    result = Result()
    seen_keys: set[tuple[str, str]] = set()
    resolved_keys: set[tuple[str, str]] = set()
    for ref in refs:
        if not is_repo_path(ref.token, toplevel):
            continue
        result.refs_examined += 1
        key = (ref.file, ref.token)
        seen_keys.add(key)
        if resolve(ref, known) is not None:
            result.resolved += 1
            resolved_keys.add(key)
            continue
        if ref.token in ignored:
            result.ignored += 1
            continue
        if key in accepted:
            result.excused += 1
            continue
        result.missing.append(ref)

    # The other direction. An exception that no longer excuses anything is a
    # claim about the tree that has stopped being true, and leaving it makes
    # the list a liability instead of a control.
    for key, reason in sorted(accepted.items()):
        if key not in seen_keys:
            result.stale_exceptions.append((key, "no longer appears in any comment — remove the entry"))
        elif key in resolved_keys:
            result.stale_exceptions.append((key, "now resolves to a real path — remove the entry"))
        elif not reason.strip():
            result.stale_exceptions.append((key, "carries no reason"))
    return result


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo-root", type=Path, default=None, help="the tree to inspect (default: git rev-parse)")
    parser.add_argument("--list", action="store_true", help="print every reference that was resolved")
    parser.add_argument(SELF_TEST_FLAG, action="store_true", help="prove this gate detects the drift it claims to")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    root = (args.repo_root or repo_root()).resolve()
    try:
        files = tracked_files(root)
    except ScanError as exc:
        print(f"check_comment_paths: FAILED to run the scan: {exc}", file=sys.stderr)
        return 2

    known = known_paths(files)
    toplevel = frozenset(f.split("/", 1)[0] for f in files)
    refs, counts = extract(root, files)
    candidates = sorted({r.token for r in refs if is_repo_path(r.token, toplevel)})
    ignored = frozenset(ignored_paths(root, candidates))
    result = judge(refs, known, toplevel, ignored, ACCEPTED)

    print(f"repo root        {root}")
    print(
        f"corpus           {counts['files_read']} comment-bearing file(s) read, "
        f"{counts['files_skipped_unknown_syntax']} with no comment syntax this gate knows"
    )
    print(f"                 {counts['tokens_seen']} path-shaped token(s) seen, {result.refs_examined} of them repository-path claims")
    print(
        f"verdict          {result.resolved} resolve, {result.ignored} name a gitignored build artefact, "
        f"{result.excused} excused, {len(result.missing)} do not"
    )
    print("not checked      extension-less directory references (286 resolve / 52 do not, and hand-")
    print("                 classifying the 52 put genuine rot near one in five — see the module docstring)")
    print()

    # Say what was opened before saying it was clean. An empty corpus and a
    # clean corpus produce the same "OK" from the same branch otherwise, which
    # is the failure this repository has shipped five times.
    if not counts["files_read"] or not result.refs_examined:
        print(
            f"check_comment_paths: FAIL — read {counts['files_read']} file(s) and found "
            f"{result.refs_examined} repository-path claim(s) under {root}. A clean result over "
            "nothing is not a clean result; check COMMENT_SYNTAX and TOKEN_RE.",
            file=sys.stderr,
        )
        return 1

    if args.list:
        for ref in sorted(refs, key=lambda r: (r.file, r.line)):
            if is_repo_path(ref.token, toplevel) and resolve(ref, known):
                print(f"  ok  {ref.file}:{ref.line}  {ref.token}")
        print()

    if not result.missing and not result.stale_exceptions:
        print(f"check_comment_paths: OK — every repository path named in a comment exists ({result.resolved} checked)")
        return 0

    if result.missing:
        print(f"{len(result.missing)} comment(s) name a path that does not exist:")
        for ref in result.missing:
            print(f"  {ref.file}:{ref.line}  ->  {ref.token}")
            print(f"      {ref.context}")
        print("\nA comment is an instruction to the next contributor. Fix the path, or record it")
        print("in ACCEPTED with the reason it cannot resolve.")

    if result.stale_exceptions:
        print(f"\n{len(result.stale_exceptions)} recorded exception(s) no longer describe the tree:")
        for (file, token), why in result.stale_exceptions:
            print(f"  {file} -> {token}: {why}")
    return 1


# --------------------------------------------------------------------------
# Self-test
# --------------------------------------------------------------------------
def self_test() -> int:
    """Inject each defect this gate exists to catch, and each it must not.

    Every case builds its corpus from a fresh constructor. A shared reference
    list mutated between cases would let one case poison the baseline and
    every later case would 'catch' an inherited finding rather than its own.
    """
    # Mirrors the real tree closely enough to be meaningful: `tests` is a
    # top-level directory in this repository, which is what lets a
    # package-relative `tests/conftest.py` be examined at all.
    toplevel = frozenset({"docs", "services", "apps", "scripts", "tests"})
    known = frozenset(
        {
            "docs",
            "docs/architecture",
            "docs/architecture/overview.md",
            "services",
            "services/agents",
            "services/agents/tests",
            "services/agents/tests/conftest.py",
            "scripts",
            "scripts/check_comment_paths.py",
            "tests",
        }
    )

    def ref(file: str, token: str, line: int = 1) -> Reference:
        return Reference(file=file, line=line, token=token, context=f"see {token}")

    def run(refs: list[Reference], *, ignored: frozenset[str] = frozenset(), accepted: dict | None = None) -> Result:
        return judge(refs, known, toplevel, ignored, dict(accepted or {}))

    checks: list[tuple[str, bool]] = []

    baseline = run([ref("services/agents/main.py", "docs/architecture/overview.md")])
    checks.append(("the unperturbed baseline reports nothing", not baseline.missing and baseline.resolved == 1))

    # --- what it must flag -------------------------------------------------
    dead = run([ref("docker-compose.yml", "docs/architecture/decisions/0001-llm-gateway-in-core.md")])
    checks.append(
        (
            "the compose comment that started this — a path with no directory behind it",
            [r.token for r in dead.missing] == ["docs/architecture/decisions/0001-llm-gateway-in-core.md"],
        )
    )

    renumbered = run([ref("services/agents/x.py", "services/api/migrations/055_cost_provenance.sql")])
    checks.append(("a migration referenced by a number it no longer has", len(renumbered.missing) == 1))

    # --- what it must NOT flag: enumerate what it credits -------------------
    # This direction is the one that finds the blind spot. A gate that flagged
    # everything would pass every case above.
    credited = [
        ("a MIME type", ref("services/api/x.py", "application/json")),
        ("an MCP method name", ref("services/mcp/src/server.ts", "tools/call")),
        ("a Splunk REST route", ref("services/connectors/x.py", "services/search/jobs")),
        ("a Go import path", ref("services/ingest/main.go", "github.com/segmentio/kafka-go")),
        ("a container image", ref("infra/x.yaml", "ghcr.io/beenuar/aisoc-devcontainer")),
        ("a glob", ref("scripts/x.py", "services/**/*.py")),
        ("a templated path", ref("scripts/x.py", "services/${SERVICE}/app.py")),
        ("an attribute reference wearing a slash", ref("x.py", "services/api/app/core/config.is_dev_env")),
        ("an extension-less directory reference (the accepted blind spot)", ref("x.py", "infra/terraform/aws")),
        ("a URL route", ref("apps/web/x.tsx", "playbooks/new")),
        # Conservative by construction: a package-relative reference whose
        # first segment names nothing at the top of the tree is skipped
        # rather than guessed at. A miss, not a false positive, and recorded
        # here so the trade is visible rather than discovered.
        ("a relative path anchored at no top-level name", ref("services/agents/x.py", "internal/helper.py")),
    ]
    for label, reference in credited:
        outcome = run([reference])
        checks.append((f"does not flag {label}", not outcome.missing and outcome.refs_examined == 0))

    # A path relative to the referring package resolves, and is not a finding.
    relative = run([ref("services/agents/tests/test_x.py", "tests/conftest.py")])
    checks.append(("a package-relative path resolves against the referring file", not relative.missing and relative.resolved == 1))

    # A gitignored build artefact is correct and unresolvable at once.
    artefact = run([ref("services/mcp/src/config.ts", "services/mcp/dist/config.js")], ignored=frozenset({"services/mcp/dist/config.js"}))
    checks.append(("a gitignored build artefact is not a finding", not artefact.missing and artefact.ignored == 1))

    # --- the exceptions ratchet, both directions ---------------------------
    excused = run([ref("a.sh", "docs/nope.md")], accepted={("a.sh", "docs/nope.md"): "recorded reason"})
    checks.append(("a recorded exception suppresses its own finding", not excused.missing and excused.excused == 1))

    now_real = run(
        [ref("services/agents/main.py", "docs/architecture/overview.md")],
        accepted={("services/agents/main.py", "docs/architecture/overview.md"): "recorded reason"},
    )
    checks.append(("an exception whose path now resolves is reported stale", len(now_real.stale_exceptions) == 1))

    vanished = run([], accepted={("gone.py", "docs/gone.md"): "recorded reason"})
    checks.append(("an exception for a comment that no longer exists is reported stale", len(vanished.stale_exceptions) == 1))

    unexplained = run([ref("a.sh", "docs/nope.md")], accepted={("a.sh", "docs/nope.md"): "   "})
    checks.append(("an exception with no reason is reported", len(unexplained.stale_exceptions) == 1))

    # An exception is keyed on (file, token): the same bad path in another
    # file is still a finding, so one excused placeholder cannot licence it
    # everywhere.
    elsewhere = run(
        [ref("a.sh", "docs/nope.md"), ref("b.sh", "docs/nope.md")],
        accepted={("a.sh", "docs/nope.md"): "recorded reason"},
    )
    checks.append(("an exception covers only the file it names", [r.file for r in elsewhere.missing] == ["b.sh"]))

    # --- the readers, not just the rules -----------------------------------
    parsed = comment_text(Path(__file__), ".py")
    checks.append(("the comment reader finds comments in this very file", len(parsed) > 20))
    docs = docstring_text(Path(__file__))
    checks.append(("the docstring reader finds this module's own docstring", any("docker-compose.yml" in line for _, line in docs)))
    checks.append(
        (
            "a URL is recognised by its prefix, not by the token",
            bool(URL_PREFIX_RE.search("see https://github.com/beenuar/AiSOC/blob/main/")) and not URL_PREFIX_RE.search("see "),
        )
    )

    return self_test_main(Path(__file__).name, [], checks)


if __name__ == "__main__":
    sys.exit(main())
