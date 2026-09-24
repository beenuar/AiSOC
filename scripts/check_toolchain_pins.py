#!/usr/bin/env python3
"""Assert the Go and Node halves of this build are as deterministic as the Python half.

``scripts/check_dependency_pins.py`` made every *package* install path agree.
It stopped at the Python services, and named what it left behind: the six Go
modules have ``go.sum`` and the pnpm workspace has ``pnpm-lock.yaml``, so the
raw material for reproducibility was there, but nothing compared the paths that
use it and nothing audited the *toolchain* those paths run on.

Both gaps are the same defect one level up. A workflow that compiles with a
different Go or Node version than the Dockerfile ships is testing different
software, in exactly the way CI installing ``cryptography>=41,<46`` while the
service required ``>=46,<51`` meant the version CI tested could never be the
version the image shipped. A lockfile that CI enforces and the production image
opts out of is the pip fallback wearing a different hat: the image boots on a
dependency set nobody tested and the traceback points somewhere innocent.

Measured on this repository before this gate existed:

* ``apps/web/Dockerfile`` ran ``pnpm install --no-frozen-lockfile`` while all
  thirteen workflows that install the same workspace run ``--frozen-lockfile``.
  The production web image was the one install path in the repository free to
  resolve its own answer.
* ``services/realtime`` committed a ``package-lock.json`` and then never copied
  it into its image, which runs ``npm install`` twice. The lockfile was inert.
* ``apps/web/Dockerfile`` installed ``pnpm@8`` — any 8.x — while
  ``package.json`` pins ``pnpm@8.15.1`` and ``install.sh`` installs exactly
  ``8.15.1``. Two resolvers, two answers, the ``poetry 1.7.1 vs 1.8.2`` finding
  again.
* Node: two images and the devcontainer shipped 20 while thirteen workflows
  tested on 22.
* ``services/enrichment/Dockerfile`` copied ``go.sum*`` — the glob makes the
  checksum file optional, so deleting it downgrades the build to an unverified
  resolve without failing.
* ``ci.yml`` pointed ``cache-dependency-path`` at two ``go.sum`` files that do
  not exist. ``setup-go`` reports that as a *warning*, so the cache had been
  silently disabled while the job stayed green.

Directions. The dominant failure shape in this repository is a one-directional
gate that compares A against B and never B against A, so drift in the direction
things actually change slips through while the gate prints OK. Every comparison
below runs both ways, and ``--self-test`` injects drift in each direction
separately and asserts this file reports it:

  agreement        every path declaring a runtime must name the same version
  ship -> test     a version an image ships that no CI path exercises
  test -> ship     a version CI exercises that no image ships
  floor <= toolchain
                   a `go`/`requires-python` floor above the toolchain installed
  unlocked install an install path free to resolve outside the lockfile
  dead lockfile    a committed lockfile that no install path consumes
  module -> sum    a Go module with requirements and no checksum file
  sum -> module    a checksum file with no module, or a cache path naming a
                   file that does not exist
  module -> CI     a Go module no workflow builds
  CI -> module     a workflow building a module directory that is not there
  override scope   an `esbuild` override that escapes its parent package
  coverage         a file declaring a runtime or an install path that this
                   gate never opened
  parser coverage  a file this gate *did* open whose declaration the parser
                   could not read — the blind spot `check_dependency_pins`
                   found in itself on its first run

Usage:
    python scripts/check_toolchain_pins.py [--repo-root PATH] [--verbose]
    python scripts/check_toolchain_pins.py --self-test
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

# ── The runtimes whose version must agree ────────────────────────────────────
#
# A runtime earns a row when two versions of it are two different behaviours
# for code in this tree, not merely two different numbers.
RUNTIMES: dict[str, str] = {
    "go": (
        "the compiler. `go vet` and the escape analysis that decides whether "
        "the ingest hot path allocates both change between minors, and the "
        "`go` directive in go.mod selects language semantics"
    ),
    "node": (
        "the runtime `services/realtime` and the Next.js server actually "
        "execute on. 20 and 22 differ in the fetch/undici stack, the test "
        "runner and OpenSSL, and Node 20 left security support in April 2026"
    ),
    "pnpm": (
        "the resolver that turns pnpm-lock.yaml into node_modules. Two "
        "resolvers are two answers to 'what does this commit install' — the "
        "same defect as two poetry versions, which this repository already hit"
    ),
    "python": ("the interpreter the thirteen Python services run on. Their manifests " "declare ^3.11 and every image ships 3.11"),
}

# ── Declared exemptions ──────────────────────────────────────────────────────
#
# An exemption without a reason is a hole. Each of these is a measured
# decision recorded where the gate can show it, so a future reader can
# challenge it rather than inherit it.

# The pnpm action version every workflow uses unless exempted below. Declared
# rather than inferred from a majority vote: with a vote, flipping enough
# workflows moves the "correct" answer and the gate ratifies the drift it
# exists to catch.
PNPM_ACTION_VERSION = "v6.0.9"

# Workflows deliberately not on the repo-wide pnpm action version.
PNPM_ACTION_EXEMPT: dict[str, str] = {
    ".github/workflows/e2e.yml": (
        "runs inside mcr.microsoft.com/playwright, which ships a global "
        "pnpm 11.x. action-setup@v6 self-switches down to the packageManager "
        "pin and leaves @tailwindcss/oxide's native binding unlinked in the "
        "restored store; v4 installs 8.15.1 directly with no switch"
    ),
    ".github/workflows/visual-regression.yml": (
        "same Playwright container and the same pnpm self-switch; pinning " "`version:` under v6 does not avoid it"
    ),
}

# Install paths allowed to resolve outside the lockfile, with the reason.
UNLOCKED_INSTALL_EXEMPT: dict[str, str] = {
    ".github/workflows/mobile.yml": (
        "apps/mobile is deliberately outside the root pnpm workspace and "
        "keeps its own lockfile, so a root lockfile refresh must not red it"
    ),
}

# Workflows that run a Python interpreter the service images do not ship.
#
# This is a real gap, recorded rather than closed, and it is weaker than the
# Go and Node checks on purpose — saying so is the point. Every service
# manifest declares `python = "^3.11"`, which *permits* 3.12, so none of these
# workflows violates anything written down; but every image ships 3.11, so
# what CI exercises is not what production runs. That is the same shape as a
# workflow compiling on a different Go version, one notch milder because the
# ranges overlap instead of being disjoint.
#
# Closing it means moving twenty-four workflows to 3.11 or thirteen images to
# 3.12 and re-locking all thirteen manifests; neither belongs in the change
# that discovered it. What is enforced meanwhile is that the set cannot grow
# silently and cannot rot: a workflow added to the split without being listed
# fails, and a listed workflow that no longer differs fails too.
PYTHON_INTERPRETER_SPLIT: set[str] = {
    ".github/workflows/adoption-snapshot.yml",
    ".github/workflows/ai-sdk.yml",
    ".github/workflows/attribution.yml",
    ".github/workflows/check-openapi.yml",
    ".github/workflows/ci.yml",
    ".github/workflows/codeql-alert-gate.yml",
    ".github/workflows/competitor-names.yml",
    ".github/workflows/cross-tenant-rbac.yml",
    ".github/workflows/golden-pipeline.yml",
    ".github/workflows/governance.yml",
    ".github/workflows/graph-schema-check.yml",
    ".github/workflows/hosted-hostname.yml",
    ".github/workflows/integration.yml",
    ".github/workflows/isolation-live.yml",
    ".github/workflows/isolation.yml",
    ".github/workflows/openapi-breaking.yml",
    ".github/workflows/papers.yml",
    ".github/workflows/perf.yml",
    ".github/workflows/python-detections.yml",
    ".github/workflows/release.yml",
    ".github/workflows/reproducible-builds.yml",
    ".github/workflows/security-audit.yml",
    ".github/workflows/security.yml",
    ".github/workflows/wet-eval.yml",
}

# Every resolved esbuild version pnpm-lock.yaml is expected to contain.
#
# The overrides in package.json are scoped per parent (`vite>esbuild`) rather
# than workspace-wide, because forcing esbuild across the workspace broke
# Turbopack's font import map — Next bundles its own copy and must keep it.
# That scoping means a `vite` bump can pull a different esbuild through the
# override without any esbuild line changing in the diff, so the resolved set
# is pinned here and a change has to be made deliberately.
EXPECTED_ESBUILD: dict[str, str] = {
    "0.25.12": "bundled by Next.js — must not be overridden, see above",
    "0.28.1": "the version the scoped tsup/vite/bundle-require overrides ask for",
}

# Prose, vendored history and generated artefacts.
SKIP_PREFIXES = (
    "plans/",
    "apps/docs/",
    "docs/",
    "scripts/check_toolchain_pins.py",
    "tests/test_toolchain_pin_gate.py",
    "CHANGELOG.md",
    "RELEASES.md",
)

# Directories that are downloaded or generated rather than written. Matched as
# a *path segment*, not a prefix: `node_modules/` as a prefix misses
# `services/realtime/node_modules/...`, and with dependencies installed this
# gate scanned 223 vendored manifests and reported Node floors of `0.10` and
# `6.* || 8.* || >= 10.*` from other people's packages. A gate whose answer
# depends on whether someone has run `pnpm install` is not structural.
SKIP_SEGMENTS = frozenset({"node_modules", ".git", ".venv", "venv", "dist", ".next", "vendor", "__pycache__"})


def skipped(rel: str) -> bool:
    return rel.startswith(SKIP_PREFIXES) or bool(SKIP_SEGMENTS & set(rel.split("/")))


def walk(root: Path, name: str | None = None) -> list[Path]:
    """Every non-skipped file under `root`, optionally filtered by filename.

    `Path.rglob` has no way to prune a subtree, so it descends into every
    `node_modules` before discarding the results — ten seconds on a checkout
    with dependencies installed. Pruning at the directory level keeps the
    gate fast enough that nobody is tempted to stop running it locally.
    """
    found: list[Path] = []
    for parent, directories, files in os.walk(root):
        directories[:] = [d for d in directories if d not in SKIP_SEGMENTS]
        for filename in files:
            if name is not None and filename != name:
                continue
            path = Path(parent) / filename
            if not skipped(path.relative_to(root).as_posix()):
                found.append(path)
    return sorted(found)


def normalise_version(raw: str) -> str:
    """Reduce a runtime version to the precision that is actually pinned.

    `node:22-alpine`, `'22'` and `22.11.0` are one toolchain written three
    ways. Go and Node are compared at major.minor because that is the
    precision every declaration in this tree carries; a patch release is not
    a decision anyone made here.
    """
    digits = re.match(r"(\d+)(?:\.(\d+))?", raw.strip().strip("\"'"))
    if not digits:
        return raw.strip()
    return f"{digits.group(1)}.{digits.group(2)}" if digits.group(2) else digits.group(1)


def version_tuple(raw: str) -> tuple[int, ...]:
    digits = re.match(r"(\d+(?:\.\d+)*)", raw.strip().strip("\"'"))
    return tuple(int(p) for p in digits.group(1).split(".")) if digits else (0,)


def _pad(left: tuple[int, ...], right: tuple[int, ...]) -> tuple[tuple[int, ...], tuple[int, ...]]:
    width = max(len(left), len(right))
    return left + (0,) * (width - len(left)), right + (0,) * (width - len(right))


def at_most(floor: str, toolchain: str) -> bool:
    """Whether a declared floor is satisfied by an installed toolchain."""
    a, b = _pad(version_tuple(floor), version_tuple(toolchain))
    return a <= b


@dataclass
class Pin:
    """One runtime version, and the exact place it was written."""

    runtime: str
    version: str
    path: str
    # ship  — a version an image or published artefact actually runs on
    # test  — a version CI compiles or tests with
    # dev   — the contributor toolchain (devcontainer, installer)
    # floor — a minimum a manifest declares, not a toolchain that gets installed
    role: str
    raw: str


@dataclass
class Install:
    """One command that materialises node_modules."""

    tool: str  # pnpm | npm
    path: str
    locked: bool
    # The directory whose lockfile this command consumes. pnpm resolves to the
    # workspace root; npm resolves to the directory the command runs in.
    owner: str
    raw: str


@dataclass
class Scan:
    pins: list[Pin] = field(default_factory=list)
    installs: list[Install] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    go_modules: dict[str, dict] = field(default_factory=dict)
    go_cache_paths: list[tuple[str, str]] = field(default_factory=list)
    pnpm_actions: list[tuple[str, str]] = field(default_factory=list)
    go_ci_builds: set[str] = field(default_factory=set)

    def by_runtime(self, runtime: str) -> list[Pin]:
        return [p for p in self.pins if p.runtime == runtime]


# ── Parsing ──────────────────────────────────────────────────────────────────
#
# Every pattern below is paired with a note about what it would *miss*, because
# the parser's blind spot is the failure mode this family of gate actually has.
# `check_parser_coverage` is the backstop: it re-reads each scanned file with a
# looser pattern and fails if the parser produced nothing for a declaration the
# file plainly contains.

# `node-version: '22'`, `go-version: "1.26"`, `python-version: 3.12`.
_SETUP_VERSION = re.compile(
    r"^\s*(?P<runtime>node|go|python)-version:\s*(?P<version>[\"']?[\d.]+[\"']?)\s*(?:#.*)?$",
    re.MULTILINE,
)
# `node-version-file: .nvmrc` — an indirection the version regex above cannot
# see. Nothing in this tree uses it today; if that changes the gate must read
# the file rather than silently extract nothing from the workflow.
_SETUP_VERSION_FILE = re.compile(r"^\s*(?P<runtime>node|go|python)-version-file:\s*(?P<target>\S+)", re.MULTILINE)
# `uses: actions/setup-node@sha` with no version input at all: the step then
# takes whatever the runner image happens to ship, which is the unbounded-pin
# shape.
_SETUP_ACTION = re.compile(r"uses:\s*actions/setup-(?P<runtime>node|go|python)@")
# `image: mcr.microsoft.com/playwright:v1.49.0-jammy` under a job `container:`.
# A job container supplies its own toolchain, so it is a declaration even
# though no `*-version:` key appears.
_JOB_CONTAINER = re.compile(r"^\s*image:\s*(?P<image>[\w./-]+:[\w.-]+)\s*$", re.MULTILINE)
_PNPM_ACTION = re.compile(r"uses:\s*pnpm/action-setup@\w+\s*#\s*(?P<version>v[\d.]+)")

# `FROM node:20-alpine AS base`, `FROM golang:1.26-alpine`, `FROM python:3.11-slim`.
_DOCKER_FROM = re.compile(
    r"^\s*FROM\s+(?:[\w.\-/]+/)?(?P<image>golang|node|python)" r":(?P<version>[\d.]+)(?P<suffix>[\w.-]*)",
    re.MULTILINE | re.IGNORECASE,
)
# The devcontainer base encodes its Node version in the tag, not after a colon
# and a number: `javascript-node:1-20-bookworm`.
_DEVCONTAINER_NODE = re.compile(r"devcontainers/javascript-node:\d+-(?P<version>\d+)-")
# `FROM node:${NODE_VERSION}` — an ARG indirection. Nothing uses it today;
# extracting nothing from such a line while counting the file scanned is
# precisely the blind spot, so it is matched and resolved explicitly.
_DOCKER_FROM_ARG = re.compile(r"^\s*FROM\s+(?P<image>golang|node|python):\$\{?(?P<arg>\w+)\}?", re.MULTILINE | re.IGNORECASE)
_DOCKER_ARG = re.compile(r"^\s*ARG\s+(?P<name>\w+)=(?P<value>[\w.-]+)", re.MULTILINE)

_PNPM_GLOBAL = re.compile(r"npm\s+install\s+-g\s+pnpm@(?P<version>[\d.]+)")
_COREPACK_PNPM = re.compile(r"corepack\s+prepare\s+pnpm@(?P<version>[\d.]+)")
# `install.sh` decides what a self-hoster ends up running, in three spellings:
# the floor it enforces, the NodeSource channel it adds, and the Homebrew
# formula it installs. It installed Node 20 while every workflow tested on 22
# and both images shipped 22, so the one-line installer handed people a
# different runtime from the one the project is built against.
_INSTALLER_NODE = re.compile(r"version_at_least\s+node\s+(?P<a>\d+)|setup_(?P<b>\d+)\.x|node@(?P<c>\d+)\b|nodejs(?P<d>\d\d)\b")

_PNPM_INSTALL = re.compile(r"(?P<cmd>pnpm\s+(?:--filter\s+\S+\s+)?(?:install|i)\b[^\n&|;]*)")
# `(?<![\\w-])` matters: without it this matches the trailing `npm install`
# inside `pnpm install`, and every pnpm command is reported twice — once
# correctly and once as an unlocked npm install that does not exist.
_NPM_INSTALL = re.compile(r"(?<![\w-])(?P<cmd>npm\s+(?:ci|install)\b[^\n&|;]*)")
# A Dockerfile that installs Node dependencies must copy the lockfile into
# the build context, or the install resolves afresh however it is spelled.
_DOCKER_COPY = re.compile(r"^\s*COPY\s+(?P<files>[^\n]+)", re.MULTILINE)

_GO_DIRECTIVE = re.compile(r"^go\s+(?P<version>[\d.]+)\s*$", re.MULTILINE)
_GO_REQUIRE = re.compile(r"^\s*require\b", re.MULTILINE)
_GO_CACHE_PATH = re.compile(r"^\s*cache-dependency-path:\s*(?P<path>\S+)\s*$", re.MULTILINE)
_GO_COPY_SUM = re.compile(r"^\s*COPY\s+(?P<files>[^\n]*go\.sum\S*)", re.MULTILINE)
# `cd services/ingest`, and `cd services/${{ matrix.service }}`. The matrix
# form is the parser's blind spot in this family: a line-by-line reader
# extracts nothing from it, so five of the six Go modules looked ungated when
# in fact one was. `_matrix_values` below resolves it.
_GO_CD = re.compile(r"cd\s+(?P<dir>(?:services|packages)/[\w.${}\s-]+?)\s*$", re.MULTILINE)
# A job can select its module with `defaults: run: working-directory:` instead
# of a `cd`, and `build-extensions.yml` does. A parser that knew only about
# `cd` reported `services/osquery-extensions` as compiled by nothing while the
# workflow that compiles it sat two directories away.
_GO_WORKDIR = re.compile(r"^\s*working-directory:\s*(?P<dir>\S+)\s*$", re.MULTILINE)
_GO_VERB = re.compile(r"\bgo\s+(?:build|test|vet|mod)\b")
_MATRIX_LIST = re.compile(r"^\s*(?P<key>\w+):\s*\[(?P<items>[^\]]+)\]\s*$", re.MULTILINE)
_EXPANSION = re.compile(r"\$\{\{\s*matrix\.(?P<key>\w+)\s*\}\}")


def _matrix_values(text: str) -> dict[str, list[str]]:
    """Inline `key: [a, b, c]` matrix legs, so `${{ matrix.key }}` can be resolved."""
    values: dict[str, list[str]] = {}
    for match in _MATRIX_LIST.finditer(text):
        items = [i.strip().strip("\"'") for i in match.group("items").split(",")]
        values.setdefault(match.group("key"), []).extend(i for i in items if i)
    return values


def _expand(template: str, matrix: dict[str, list[str]]) -> list[str]:
    """Every concrete path a `${{ matrix.* }}` template can become."""
    found = _EXPANSION.search(template)
    if not found:
        return [template.strip()] if "${{" not in template else []
    key = found.group("key")
    if key not in matrix:
        return []
    out: list[str] = []
    for value in matrix[key]:
        out += _expand(template[: found.start()] + value + template[found.end() :], matrix)
    return out


def _strip_quoted(text: str) -> str:
    """Blank out quoted spans in *shell* sources, which are data not commands.

    `install.sh` says `die "pnpm install failed."` and
    `info "Installing JS workspace deps (pnpm install)..."`. Read literally
    those are three more install paths, all of them messages about a fourth.

    Applied only to shell and Dockerfile sources. In JSON the command *is* the
    quoted value — `devcontainer.json` declares
    `"onCreateCommand": "pnpm install --frozen-lockfile=false"` — so stripping
    quotes there would delete the very install path being looked for, which is
    the blind spot this function exists to avoid creating.
    """
    # Shell strings wrap, so the double-quoted form has to cross newlines —
    # `install.sh` has a two-line `die "…"`. Bounded to 600 characters so a
    # single unbalanced quote blanks one message rather than the rest of the
    # file, which would turn this from a false-positive fix into a blind spot.
    return re.sub(r"\"[^\"]{0,600}\"|'[^'\n]*'", " ", text, flags=re.DOTALL)


def _uncommented(text: str) -> str:
    """Drop comment-only lines.

    Comments in this repository discuss versions and install commands at
    length — `apps/web/Dockerfile` explains its pnpm choice over eight lines —
    so reading them as declarations produces confident nonsense. This is the
    same precaution `_pip_install_tokens` needed in the dependency gate, which
    once reported packages named `that`, `was` and `a`.
    """
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


def _fold_yaml_run_blocks(text: str) -> str:
    """Join `run: >-` folded scalars into the single command they become.

    A folded block runs as one shell line, so a line-by-line reader sees the
    `run:` header, finds no command after it, and extracts nothing — while
    still counting the file as scanned. `integration.yml` hid a whole
    dependency set from the dependency gate this way.
    """
    lines = text.splitlines()
    out: list[str] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        header = re.match(r"^(\s*)(-?\s*run:)\s*>-?\s*$", line)
        if not header:
            out.append(line)
            index += 1
            continue
        indent = len(header.group(1))
        body: list[str] = []
        index += 1
        while index < len(lines):
            candidate = lines[index]
            if candidate.strip() and (len(candidate) - len(candidate.lstrip())) <= indent:
                break
            body.append(candidate.strip())
            index += 1
        out.append(f"{header.group(1)}{header.group(2)} " + " ".join(b for b in body if b))
    return "\n".join(out)


def _install_commands(text: str, rel: str, owner: str, shell_source: bool = False) -> list[Install]:
    """Every command in a file that materialises node_modules."""
    body = _fold_yaml_run_blocks(_uncommented(text))
    body = re.sub(r"\\\s*\n", " ", body)  # fold shell line continuations
    if shell_source:
        body = _strip_quoted(body)
    found: list[Install] = []

    for match in _PNPM_INSTALL.finditer(body):
        command = match.group("cmd").strip()
        # `--frozen-lockfile` is the locked form. There are two opt-outs and
        # both were in the tree: `--no-frozen-lockfile` in the production web
        # image, and `--frozen-lockfile=false` in the devcontainer — which a
        # substring test reads as *enabling* the flag it disables.
        locked = bool(re.search(r"--frozen-lockfile(?!\s*=\s*false)", command)) and ("--no-frozen-lockfile" not in command)
        found.append(Install("pnpm", rel, locked, owner, command))

    for match in _NPM_INSTALL.finditer(body):
        command = match.group("cmd").strip()
        if re.search(r"\s-g\b|--global\b", command):
            continue  # installing a global tool, not this project's tree
        locked = bool(re.match(r"npm\s+ci\b", command))
        found.append(Install("npm", rel, locked, owner, command))

    return found


def parse_workflow(path: Path, rel: str, scan_result: Scan, root: Path) -> None:
    text = _uncommented(path.read_text(encoding="utf-8"))

    for match in _SETUP_VERSION.finditer(text):
        scan_result.pins.append(Pin(match.group("runtime"), normalise_version(match.group("version")), rel, "test", match.group(0).strip()))
    for match in _SETUP_VERSION_FILE.finditer(text):
        # Recorded as an unreadable declaration rather than skipped, so it
        # surfaces as a gate failure instead of a silent gap.
        scan_result.pins.append(Pin(match.group("runtime"), f"@file:{match.group('target')}", rel, "test", match.group(0).strip()))
    for match in _JOB_CONTAINER.finditer(text):
        scan_result.pins.append(Pin("container", match.group("image"), rel, "test", match.group(0).strip()))
    for match in _PNPM_ACTION.finditer(text):
        scan_result.pnpm_actions.append((rel, match.group("version")))
    for match in _GO_CACHE_PATH.finditer(text):
        target = match.group("path").strip("\"'")
        if "${{" not in target:
            scan_result.go_cache_paths.append((rel, target))
    # A `cd` only counts as compiling a module when a `go` verb follows it.
    # Matching every `cd services/<x>` reported five Python services as Go
    # modules the workflow built; matching only literal paths reported five
    # real Go modules as built by nothing, because `ci.yml` drives them
    # through `cd services/${{ matrix.service }}`. Both halves are needed.
    matrix = _matrix_values(text)
    for match in _GO_CD.finditer(text):
        if not _GO_VERB.search(text[match.end() : match.end() + 300]):
            continue
        for directory in _expand(match.group("dir"), matrix):
            scan_result.go_ci_builds.add(directory)
    # `working-directory:` is job- or step-scoped and this reader is not, so a
    # workflow with a Go job and a Python job would otherwise attribute the
    # Python job's directory to Go. Accepting only directories that actually
    # hold a go.mod keeps it precise without parsing the job graph.
    if _GO_VERB.search(text):
        for match in _GO_WORKDIR.finditer(text):
            for directory in _expand(match.group("dir").strip("\"'"), matrix):
                if (root / directory / "go.mod").exists():
                    scan_result.go_ci_builds.add(directory)

    # A setup step with no version input takes whatever the runner ships.
    for match in _SETUP_ACTION.finditer(text):
        runtime = match.group("runtime")
        window = text[match.end() : match.end() + 400]
        key = f"{runtime}-version"
        if key not in window.split("- ")[0]:
            scan_result.pins.append(Pin(runtime, "", rel, "test", match.group(0).strip()))

    scan_result.installs += _install_commands(path.read_text(encoding="utf-8"), rel, "")


def parse_dockerfile(path: Path, rel: str, scan_result: Scan, role: str) -> None:
    raw = path.read_text(encoding="utf-8")
    text = _uncommented(raw)
    args = {m.group("name"): m.group("value") for m in _DOCKER_ARG.finditer(text)}

    for match in _DOCKER_FROM.finditer(text):
        runtime = {"golang": "go", "node": "node", "python": "python"}[match.group("image").lower()]
        scan_result.pins.append(Pin(runtime, normalise_version(match.group("version")), rel, role, match.group(0).strip()))
    for match in _DOCKER_FROM_ARG.finditer(text):
        runtime = {"golang": "go", "node": "node", "python": "python"}[match.group("image").lower()]
        resolved = args.get(match.group("arg"), "")
        scan_result.pins.append(Pin(runtime, normalise_version(resolved) if resolved else "", rel, role, match.group(0).strip()))
    for match in _DEVCONTAINER_NODE.finditer(text):
        scan_result.pins.append(Pin("node", normalise_version(match.group("version")), rel, role, match.group(0).strip()))
    for match in _PNPM_GLOBAL.finditer(text):
        scan_result.pins.append(Pin("pnpm", match.group("version"), rel, role, match.group(0).strip()))

    scan_result.installs += _install_commands(raw, rel, str(Path(rel).parent), shell_source=True)

    # A Go builder stage must copy the checksum file unconditionally. `go.sum*`
    # is a glob: if the file is ever absent the COPY still succeeds and
    # `go mod download` resolves without verification.
    for match in _GO_COPY_SUM.finditer(text):
        if "go.sum*" in match.group("files"):
            scan_result.go_modules.setdefault(str(Path(rel).parent), {})["optional_sum"] = rel


def parse_shell(path: Path, rel: str, scan_result: Scan) -> None:
    raw = path.read_text(encoding="utf-8")
    text = _uncommented(raw)
    for match in _PNPM_GLOBAL.finditer(text):
        scan_result.pins.append(Pin("pnpm", match.group("version"), rel, "dev", match.group(0).strip()))
    for match in _COREPACK_PNPM.finditer(text):
        scan_result.pins.append(Pin("pnpm", match.group("version"), rel, "dev", match.group(0).strip()))
    for match in _INSTALLER_NODE.finditer(text):
        version = next(g for g in match.groups() if g)
        scan_result.pins.append(Pin("node", normalise_version(version), rel, "dev", match.group(0).strip()))
    scan_result.installs += _install_commands(raw, rel, "", shell_source=True)


def parse_go_mod(path: Path, rel: str, scan_result: Scan) -> None:
    text = path.read_text(encoding="utf-8")
    directory = str(Path(rel).parent)
    entry = scan_result.go_modules.setdefault(directory, {})
    entry["mod"] = rel
    entry["requires"] = bool(_GO_REQUIRE.search(text))
    entry["sum"] = (path.parent / "go.sum").exists()
    match = _GO_DIRECTIVE.search(text)
    if match:
        scan_result.pins.append(Pin("go", normalise_version(match.group("version")), rel, "floor", match.group(0).strip()))


def parse_package_json(path: Path, rel: str, scan_result: Scan) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    manager = data.get("packageManager", "")
    if manager.startswith("pnpm@"):
        # Not a floor: `pnpm/action-setup` with no `version:` input installs
        # exactly this, so it is the toolchain every CI job runs.
        scan_result.pins.append(Pin("pnpm", manager.split("@", 1)[1], rel, "test", f"packageManager: {manager}"))
    engine = (data.get("engines") or {}).get("node")
    if engine:
        # A published package's `engines` states what a *consumer* needs, which
        # is deliberately broader than the toolchain this repository builds
        # with. It is recorded as a floor, never as a toolchain.
        scan_result.pins.append(Pin("node", re.sub(r"^[^\d]*", "", engine), rel, "floor", f"engines.node: {engine}"))


def scan(root: Path) -> Scan:
    result = Scan()

    workflows = root / ".github" / "workflows"
    for workflow in sorted(workflows.glob("*.yml")) if workflows.is_dir() else []:
        rel = workflow.relative_to(root).as_posix()
        result.files.append(rel)
        parse_workflow(workflow, rel, result, root)

    for dockerfile in walk(root, "Dockerfile"):
        rel = dockerfile.relative_to(root).as_posix()
        if skipped(rel):
            continue
        result.files.append(rel)
        # The devcontainer is the toolchain a contributor's first build runs
        # on; a version there that CI does not use is a local green that reds
        # on push.
        parse_dockerfile(dockerfile, rel, result, "dev" if rel.startswith(".devcontainer/") else "ship")

    for gomod in walk(root, "go.mod"):
        rel = gomod.relative_to(root).as_posix()
        if skipped(rel):
            continue
        result.files.append(rel)
        parse_go_mod(gomod, rel, result)

    for gosum in walk(root, "go.sum"):
        rel = gosum.relative_to(root).as_posix()
        if skipped(rel):
            continue
        result.files.append(rel)
        result.go_modules.setdefault(str(Path(rel).parent), {})["sum_file"] = rel

    for manifest in walk(root, "package.json"):
        rel = manifest.relative_to(root).as_posix()
        if skipped(rel):
            continue
        result.files.append(rel)
        parse_package_json(manifest, rel, result)

    for pyproject in sorted(root.glob("services/*/pyproject.toml")):
        rel = pyproject.relative_to(root).as_posix()
        result.files.append(rel)
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        declared = data.get("tool", {}).get("poetry", {}).get("dependencies", {}).get("python") or data.get("project", {}).get(
            "requires-python"
        )
        if isinstance(declared, str):
            result.pins.append(Pin("python", re.sub(r"^[^\d]*", "", declared), rel, "floor", f"python {declared}"))

    installer = root / "install.sh"
    if installer.exists():
        rel = installer.relative_to(root).as_posix()
        result.files.append(rel)
        parse_shell(installer, rel, result)

    # The devcontainer's lifecycle hooks are install paths: `onCreateCommand`
    # runs `pnpm install` on every Codespace boot. `check_scan_coverage` is
    # what surfaced this file — it was declaring an install command from
    # outside the scanned set.
    devcontainer = root / ".devcontainer" / "devcontainer.json"
    if devcontainer.exists():
        rel = devcontainer.relative_to(root).as_posix()
        result.files.append(rel)
        result.installs += _install_commands(devcontainer.read_text(encoding="utf-8"), rel, "")

    return result


# ── The checks ───────────────────────────────────────────────────────────────


def _toolchains(data: Scan, runtime: str) -> list[Pin]:
    """Declarations that actually install a toolchain, as opposed to floors."""
    return [p for p in data.by_runtime(runtime) if p.role in {"ship", "test", "dev"}]


def check_runtime_agreement(data: Scan) -> list[str]:
    """Every path installing a runtime must install the same version.

    Python is excluded from strict equality and handled by
    `check_python_split` instead: its manifests declare a floor rather than a
    pin, so CI on 3.12 and an image on 3.11 both satisfy what is written. That
    is a weaker property than Go and Node have, and saying so is the point.
    """
    problems: list[str] = []
    for runtime, reason in sorted(RUNTIMES.items()):
        if runtime == "python":
            continue
        declarations = _toolchains(data, runtime)
        if not declarations:
            continue

        unbounded = [p for p in declarations if not p.version]
        unreadable = [p for p in declarations if p.version.startswith("@file:")]
        versions: dict[str, list[Pin]] = {}
        for pin in declarations:
            if pin.version and not pin.version.startswith("@file:"):
                versions.setdefault(pin.version, []).append(pin)

        if unbounded:
            where = ", ".join(sorted({p.path for p in unbounded}))
            problems.append(
                f"`{runtime}` is set up with no version in {where} — the step takes whatever "
                f"the runner image ships, which changes without any diff. Why it matters: {reason}"
            )
        if unreadable:
            where = ", ".join(sorted({f"{p.path} ({p.version})" for p in unreadable}))
            problems.append(
                f"`{runtime}` is declared through a version file in {where}; this gate does not "
                f"read that indirection, so the version would go uncompared"
            )
        if len(versions) > 1:
            detail = "; ".join(f"[{version}] {', '.join(sorted({p.path for p in pins}))}" for version, pins in sorted(versions.items()))
            problems.append(f"`{runtime}` is pinned {len(versions)} different ways: {detail}. Why it matters: {reason}")
    return problems


def check_ship_test_parity(data: Scan) -> list[str]:
    """Both directions between what images ship and what CI exercises.

    Forward (ship -> test) catches an image on a runtime nothing tests: the
    Node 20 images under thirteen Node 22 workflows. Reverse (test -> ship)
    catches CI moving ahead of the images, which is the direction versions
    actually travel — CI bumps are cheap and Dockerfiles get forgotten.
    """
    problems: list[str] = []
    for runtime in sorted(RUNTIMES):
        if runtime == "python":
            continue  # ratcheted by check_python_split, which explains why
        shipped = {p.version for p in data.by_runtime(runtime) if p.role == "ship" and p.version}
        tested = {p.version for p in data.by_runtime(runtime) if p.role == "test" and p.version}
        if not shipped or not tested:
            continue
        for version in sorted(shipped - tested):
            where = sorted({p.path for p in data.by_runtime(runtime) if p.role == "ship" and p.version == version})
            problems.append(
                f"`{runtime}` {version} is shipped by {', '.join(where)} but no workflow " f"builds or tests on it (ship -> test)"
            )
        for version in sorted(tested - shipped):
            where = sorted({p.path for p in data.by_runtime(runtime) if p.role == "test" and p.version == version})
            problems.append(
                f"`{runtime}` {version} is used by {', '.join(where)} but no image ships it — "
                f"CI is testing a runtime nothing runs in production (test -> ship)"
            )
    return problems


def check_floors(data: Scan) -> list[str]:
    """A declared minimum must be satisfied by every toolchain installed."""
    problems: list[str] = []
    for runtime in sorted(RUNTIMES):
        toolchains = [p for p in _toolchains(data, runtime) if p.version and not p.version.startswith("@file:")]
        for floor in [p for p in data.by_runtime(runtime) if p.role == "floor" and p.version]:
            for pin in toolchains:
                if not at_most(floor.version, pin.version):
                    problems.append(
                        f"{floor.path} declares `{runtime}` >= {floor.version}, but {pin.path} "
                        f"installs {pin.version} (floor <= toolchain)"
                    )
    return problems


def check_python_split(data: Scan) -> list[str]:
    """Every service image must ship one interpreter, and CI must satisfy it.

    Deliberately weaker than the Go and Node checks, and the difference is
    stated rather than hidden. The manifests declare `^3.11`, which permits
    3.12, so a workflow on 3.12 is not violating anything written down — but
    it is still not the interpreter the image runs. What is enforced here is
    the part that is unambiguous: the images agree with each other, and no
    workflow drops below the floor the manifests declare. The residual split
    is printed by `report` so the number is visible rather than implied.
    """
    problems: list[str] = []
    pins = data.by_runtime("python")
    shipped = {p.version for p in pins if p.role == "ship"}
    if len(shipped) > 1:
        detail = "; ".join(
            f"[{version}] " + ", ".join(sorted({p.path for p in pins if p.role == "ship" and p.version == version}))
            for version in sorted(shipped)
        )
        problems.append(f"service images ship {len(shipped)} different Python interpreters: {detail}")
        return problems

    if not shipped:
        return problems  # no Python images in this tree; nothing to compare against

    differing = {p.path for p in pins if p.role == "test" and p.version and p.version not in shipped}
    scanned_workflows = {f for f in data.files if f.startswith(".github/workflows/")}
    for path in sorted(differing - PYTHON_INTERPRETER_SPLIT):
        problems.append(
            f"{path} tests on a Python interpreter no image ships ({', '.join(sorted(shipped))}) "
            f"and is not in PYTHON_INTERPRETER_SPLIT — the split may not grow silently"
        )
    for path in sorted((PYTHON_INTERPRETER_SPLIT & scanned_workflows) - differing):
        problems.append(
            f"PYTHON_INTERPRETER_SPLIT names {path}, which now matches the shipped "
            f"interpreter — remove it so the recorded gap stays the real one"
        )
    return problems


def check_locked_installs(data: Scan) -> list[str]:
    """Both directions between install commands and the lockfiles in the tree.

    Forward: an install free to resolve its own answer. Reverse: a lockfile
    committed and consumed by nothing — which is how `services/realtime`
    carried a `package-lock.json` for an image that ran `npm install`.
    """
    problems: list[str] = []
    for install in data.installs:
        if install.locked or install.path in UNLOCKED_INSTALL_EXEMPT:
            continue
        problems.append(
            f"{install.path} runs `{install.raw}` — free to resolve outside the lockfile, so "
            f"this path can install a version set no other path tested (unlocked install)"
        )
    return problems


def check_dead_lockfiles(root: Path, data: Scan) -> list[str]:
    """The reverse direction: a committed lockfile nothing can consume.

    `check_locked_installs` asks whether every install honours a lockfile.
    This asks the opposite — whether every lockfile is reachable by an
    install at all. A lockfile with no manifest beside it, or whose package
    manager is never invoked anywhere in the tree, records a version set that
    nothing installs while looking like evidence that something does.
    """
    problems: list[str] = []
    tools_used = {install.tool for install in data.installs}
    for pattern, tool in (("package-lock.json", "npm"), ("pnpm-lock.yaml", "pnpm")):
        for lockfile in walk(root, pattern):
            rel = lockfile.relative_to(root).as_posix()
            if not (lockfile.parent / "package.json").exists():
                problems.append(f"{rel} has no package.json beside it (dead lockfile)")
            elif tool not in tools_used:
                problems.append(
                    f"{rel} is committed but no path in this repository runs `{tool}` — "
                    f"the lockfile records a version set nothing installs (dead lockfile)"
                )
    return problems


def check_image_copies_lockfile(root: Path, data: Scan) -> list[str]:
    """An image installing Node dependencies must copy the lockfile it installs from.

    The sharp edge of the reverse direction. `services/realtime` committed a
    `package-lock.json`, and its Dockerfile copied `package.json` and ran
    `npm install` — so the lockfile was never in the build context and every
    image build re-resolved. Spelling the command `npm ci` would not have
    helped; it would have failed for want of a file nobody copied. The two
    halves have to be checked together.
    """
    problems: list[str] = []
    wanted = {"pnpm": ("pnpm-lock.yaml",), "npm": ("package-lock.json",)}
    for install in data.installs:
        if not install.path.endswith("Dockerfile"):
            continue
        path = root / install.path
        if not path.is_file():
            continue
        copied = " ".join(m.group("files") for m in _DOCKER_COPY.finditer(_uncommented(path.read_text("utf-8"))))
        if not any(name in copied for name in wanted[install.tool]):
            problems.append(
                f"{install.path} runs `{install.raw}` but never COPYs "
                f"{' or '.join(wanted[install.tool])} into the build context, so the image "
                f"resolves dependencies afresh however the command is spelled (image -> lockfile)"
            )
    return problems


def check_go_modules(root: Path, data: Scan) -> list[str]:
    """Go module integrity, in every direction the pieces can disagree."""
    problems: list[str] = []

    for directory, entry in sorted(data.go_modules.items()):
        if entry.get("mod") and entry.get("requires") and not entry.get("sum"):
            problems.append(
                f"{entry['mod']} declares requirements but {directory}/go.sum does not exist — "
                f"`go mod download` resolves them unverified (module -> sum)"
            )
        if entry.get("sum_file") and not entry.get("mod"):
            problems.append(f"{entry['sum_file']} has no go.mod beside it (sum -> module)")
        if entry.get("optional_sum") and entry.get("requires"):
            problems.append(
                f"{entry['optional_sum']} copies `go.sum*` — the glob makes the checksum file "
                f"optional, so deleting it downgrades the build to an unverified resolve "
                f"without failing (module -> sum)"
            )

    # A cache path naming a file that is not there. `setup-go` reports this as
    # a warning and carries on, so the job stays green with the cache silently
    # off — a green tick for a step that did not happen.
    for workflow, target in sorted(data.go_cache_paths):
        if "*" in target:
            continue
        if not (root / target).exists():
            problems.append(
                f"{workflow} sets cache-dependency-path `{target}`, which does not exist — "
                f"setup-go warns and continues, so the cache is off and the job still passes "
                f"(sum -> module)"
            )

    # A compiled binary committed beside the source it was built from.
    # `services/demo-producer/demo-producer` was a 6.9 MB macOS arm64
    # executable in a module whose Dockerfile builds a GOOS=linux one:
    # nothing consumed it, nothing rebuilt it, and running the documented
    # `go build ./...` overwrote it and dirtied the working tree. A build
    # output tracked as source is the opposite of a reproducible build.
    for directory, entry in sorted(data.go_modules.items()):
        if not entry.get("mod"):
            continue
        for candidate in sorted((root / directory).glob("*")):
            if not candidate.is_file() or candidate.suffix:
                continue
            try:
                magic = candidate.read_bytes()[:4]
            except OSError:
                continue
            if magic[:4] in (b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe"):
                problems.append(
                    f"{directory}/{candidate.name} is a compiled binary committed inside a Go "
                    f"module — `go build` overwrites it, so the tracked bytes are one machine's "
                    f"output and nothing rebuilds or verifies them (build output as source)"
                )

    modules = {directory for directory, entry in data.go_modules.items() if entry.get("mod")}
    for directory in sorted(modules - data.go_ci_builds):
        problems.append(f"{directory}/go.mod is built by no workflow — nothing compiles it (module -> CI)")
    for directory in sorted(data.go_ci_builds - modules):
        problems.append(f"a workflow builds `{directory}`, which holds no go.mod (CI -> module)")

    return problems


def check_esbuild_overrides(root: Path) -> list[str]:
    """esbuild must stay overridden per parent, and the resolved set must be pinned.

    Forcing esbuild across the workspace broke Turbopack's font import map,
    because Next bundles its own copy and the override replaced it. The
    overrides are therefore scoped (`vite>esbuild`) — but that scoping means a
    `vite` bump can pull a different esbuild with no esbuild line in the diff,
    so the resolved versions are compared too.
    """
    problems: list[str] = []
    manifest = root / "package.json"
    if not manifest.exists():
        return []
    overrides = (json.loads(manifest.read_text(encoding="utf-8")).get("pnpm") or {}).get("overrides") or {}
    for key in sorted(overrides):
        if key == "esbuild" or key.startswith("esbuild@"):
            problems.append(
                f"package.json overrides `{key}` workspace-wide. Next bundles its own esbuild "
                f"and a workspace-wide override replaces it, which breaks Turbopack's font "
                f"import map — scope it to its parent as `<parent>>esbuild` (override scope)"
            )

    lockfile = root / "pnpm-lock.yaml"
    if not lockfile.exists():
        return problems
    resolved = set(re.findall(r"\besbuild@(\d+\.\d+\.\d+)", lockfile.read_text(encoding="utf-8")))
    if not resolved:
        return problems
    for version in sorted(resolved - set(EXPECTED_ESBUILD)):
        problems.append(
            f"pnpm-lock.yaml resolves esbuild {version}, which is not in the expected set "
            f"({', '.join(sorted(EXPECTED_ESBUILD))}). A vite or tsup bump pulls esbuild "
            f"through the scoped override; confirm Turbopack still builds, then record it "
            f"in EXPECTED_ESBUILD (override scope)"
        )
    for version in sorted(set(EXPECTED_ESBUILD) - resolved):
        problems.append(
            f"EXPECTED_ESBUILD names esbuild {version} ({EXPECTED_ESBUILD[version]}) but the "
            f"lockfile resolves no such version — the expectation is stale (override scope)"
        )
    return problems


def check_pnpm_actions(data: Scan) -> list[str]:
    """One pnpm action version, or a recorded reason for the difference."""
    problems: list[str] = []
    if not data.pnpm_actions:
        return []
    seen = {path for path, _ in data.pnpm_actions}
    for path, version in sorted(data.pnpm_actions):
        if version == PNPM_ACTION_VERSION or path in PNPM_ACTION_EXEMPT:
            continue
        problems.append(
            f"{path} uses pnpm/action-setup {version} while the repository declares "
            f"{PNPM_ACTION_VERSION}. Two action majors resolve pnpm differently; add a "
            f"measured reason to PNPM_ACTION_EXEMPT or move it"
        )
    if PNPM_ACTION_VERSION not in {v for _, v in data.pnpm_actions}:
        problems.append(f"PNPM_ACTION_VERSION is {PNPM_ACTION_VERSION} but no workflow uses it — " f"the declared version is stale")
    # An exemption for a workflow that no longer sets up pnpm is a comment
    # asserting a constraint nothing is under. Only checked against files the
    # scan actually saw, so an exemption for a workflow outside this tree
    # (a fixture, a fork) does not fail the run.
    for path in sorted(PNPM_ACTION_EXEMPT):
        if path in data.files and path not in seen:
            problems.append(
                f"PNPM_ACTION_EXEMPT names {path}, which no longer sets up pnpm — " f"remove the exemption rather than leaving it to rot"
            )
    return problems


# Loose enough to see a declaration the strict parsers miss, strict enough not
# to fire on prose. Used only to compare against what the parser extracted.
_RUNTIME_MENTION = re.compile(
    r"""(?:^|\s)(?:node|go|python)-version(?:-file)?:\s*\S|""" r"""^\s*FROM\s+(?:golang|node|python):|""" r"""npm\s+install\s+-g\s+pnpm@""",
    re.MULTILINE | re.IGNORECASE,
)


def check_parser_coverage(root: Path, data: Scan) -> list[str]:
    """A file this gate opened but did not actually read.

    The other direction of `check_scan_coverage`. That one asks whether every
    file holding a declaration is in the scanned set; this asks whether the
    parser extracted anything from the files it did scan. Both are needed,
    because a file can be globbed, counted, named in the summary — and still
    have its declaration skipped by a parser that does not understand the
    syntax it is written in. That is the bug `check_dependency_pins` found in
    itself: it reported `ruff` agreeing across seven files, none of which had
    been read for it.
    """
    problems: list[str] = []
    extracted_from = {p.path for p in data.pins} | {i.path for i in data.installs}
    for rel in sorted(set(data.files)):
        path = root / rel
        if not path.is_file() or rel.endswith(("go.sum", "poetry.lock", "pnpm-lock.yaml")):
            continue
        try:
            text = _uncommented(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError):
            continue
        if _RUNTIME_MENTION.search(text) and rel not in extracted_from:
            problems.append(
                f"{rel} declares a runtime version but the parser extracted nothing from it — "
                f"the file is counted as scanned while contributing no declaration "
                f"(parser coverage)"
            )
    return problems


_STRAY = re.compile(
    r"""^\s*FROM\s+(?:golang|node|python):|"""
    r"""(?:node|go|python)-version:\s*["']?\d|"""
    r"""pnpm\s+install\b|npm\s+ci\b|npm\s+install\s+-g\s+pnpm@""",
    re.MULTILINE | re.IGNORECASE,
)


def check_scan_coverage(root: Path, data: Scan) -> list[str]:
    """A file declaring a runtime or an install path that this gate never opened."""
    scanned = set(data.files)
    stray: set[str] = set()
    for path in walk(root):
        rel = path.relative_to(root).as_posix()
        if rel in scanned or skipped(rel):
            continue
        if path.suffix not in {".yml", ".yaml", ".json", ".sh", ""}:
            continue
        if path.suffix == "" and not path.name.startswith("Dockerfile"):
            continue
        try:
            text = _uncommented(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError):
            continue
        if _STRAY.search(text):
            stray.add(rel)
    return [
        f"{rel} declares a runtime version or an install command but is not a path this gate "
        f"scans — add it to `scan()` or to SKIP_PREFIXES with a reason (coverage)"
        for rel in sorted(stray)
    ]


def report(data: Scan) -> None:
    for runtime in sorted(RUNTIMES):
        pins = data.by_runtime(runtime)
        if not pins:
            continue
        toolchains = sorted({p.version for p in pins if p.role in {"ship", "test", "dev"} and p.version})
        floors = sorted({p.version for p in pins if p.role == "floor" and p.version})
        print(
            f"  {runtime}: {len(pins)} declarations across {len({p.path for p in pins})} files"
            f" — toolchain {', '.join(toolchains) or 'none'}" + (f", floors {', '.join(floors)}" if floors else "")
        )
        if runtime == "python":
            shipped = sorted({p.version for p in pins if p.role == "ship"})
            differing = sorted({p.path for p in pins if p.role == "test" and p.version and p.version not in shipped})
            if differing:
                # Not a failure: the manifests declare a floor, and every one
                # of these satisfies it. Printed because a gap nobody can see
                # is a gap nobody fixes.
                print(
                    f"      note: {len(differing)} workflow(s) test on an interpreter the images "
                    f"do not ship ({', '.join(shipped)}): {', '.join(Path(p).name for p in differing)}"
                )

    locked = sum(1 for i in data.installs if i.locked)
    print(f"  node installs: {len(data.installs)} ({locked} locked, {len(data.installs) - locked} unlocked)")
    modules = sorted(d for d, e in data.go_modules.items() if e.get("mod"))
    print(f"  go modules: {len(modules)} — {', '.join(modules)}")


def run(root: Path, verbose: bool = False) -> tuple[int, list[str]]:
    if not (root / ".github" / "workflows").is_dir() or not (root / "services").is_dir():
        return 1, [f"{root} does not look like the AiSOC repository (no .github/workflows and services/). " f"Pass --repo-root explicitly."]

    data = scan(root)
    if not data.pins and not data.installs:
        return 1, [f"scanned {len(data.files)} file(s) under {root} and found no runtime declaration at all"]

    problems = (
        check_runtime_agreement(data)
        + check_ship_test_parity(data)
        + check_floors(data)
        + check_python_split(data)
        + check_locked_installs(data)
        + check_dead_lockfiles(root, data)
        + check_image_copies_lockfile(root, data)
        + check_go_modules(root, data)
        + check_esbuild_overrides(root)
        + check_pnpm_actions(data)
        + check_parser_coverage(root, data)
        + check_scan_coverage(root, data)
    )

    print(f"check_toolchain_pins: root {root}")
    print(
        f"  scanned {len(set(data.files))} paths "
        f"({sum(1 for f in set(data.files) if f.startswith('.github/'))} workflows, "
        f"{sum(1 for f in set(data.files) if f.endswith('Dockerfile'))} Dockerfiles, "
        f"{sum(1 for f in set(data.files) if f.endswith('go.mod'))} go.mod, "
        f"{sum(1 for f in set(data.files) if f.endswith('package.json'))} package.json)"
    )
    report(data)
    if verbose:
        for rel in sorted(set(data.files)):
            print(f"    scanned {rel}")

    if problems:
        print("check_toolchain_pins: FAIL")
        for problem in problems:
            print(f"  - {problem}")
        return 1, problems
    print("check_toolchain_pins: OK")
    return 0, []


# ── Self-test ────────────────────────────────────────────────────────────────


def _fixture(root: Path) -> None:
    """A miniature repository that passes, for the injections to break."""
    (root / ".github" / "workflows").mkdir(parents=True)
    (root / "services" / "web-svc").mkdir(parents=True)
    (root / "services" / "go-svc").mkdir(parents=True)

    (root / "package.json").write_text(
        json.dumps(
            {
                "name": "fixture",
                "private": True,
                "packageManager": "pnpm@8.15.1",
                "engines": {"node": ">=22.0.0"},
                "pnpm": {"overrides": {"vite>esbuild": "^0.28.1"}},
            }
        ),
        encoding="utf-8",
    )
    (root / "pnpm-lock.yaml").write_text("lockfileVersion: '6.0'\n  /esbuild@0.28.1:\n  /esbuild@0.25.12:\n", encoding="utf-8")

    (root / "services" / "web-svc" / "Dockerfile").write_text(
        "FROM node:22-alpine AS base\nRUN npm install -g pnpm@8.15.1\n"
        "COPY package.json pnpm-lock.yaml ./\nRUN pnpm install --frozen-lockfile\n",
        encoding="utf-8",
    )
    (root / "services" / "go-svc" / "Dockerfile").write_text(
        "FROM golang:1.26-alpine AS builder\nCOPY go.mod go.sum ./\nRUN go mod download\n", encoding="utf-8"
    )
    (root / "services" / "go-svc" / "go.mod").write_text(
        "module example.com/go-svc\n\ngo 1.26\n\nrequire github.com/x/y v1.0.0\n", encoding="utf-8"
    )
    (root / "services" / "go-svc" / "go.sum").write_text("github.com/x/y v1.0.0 h1:abc=\n", encoding="utf-8")

    (root / "install.sh").write_text(
        "#!/usr/bin/env bash\n"
        'if version_at_least node 22 "node --version"; then ok; fi\n'
        "curl -fsSL https://deb.nodesource.com/setup_22.x | bash -\n"
        "corepack prepare pnpm@8.15.1 --activate\n"
        "( cd $REPO_ROOT && pnpm install --frozen-lockfile )\n",
        encoding="utf-8",
    )
    (root / ".github" / "workflows" / "ci.yml").write_text(
        "name: CI\njobs:\n"
        "  node:\n    steps:\n"
        "      - uses: pnpm/action-setup@aaa # v6.0.9\n"
        "      - uses: actions/setup-node@bbb # v6\n"
        "        with:\n          node-version: '22'\n"
        "      - run: pnpm install --frozen-lockfile\n"
        "  go:\n    steps:\n"
        "      - uses: actions/setup-go@ccc # v7\n"
        "        with:\n          go-version: '1.26'\n"
        "          cache-dependency-path: services/go-svc/go.sum\n"
        "      - run: |\n          cd services/go-svc\n          go build ./...\n",
        encoding="utf-8",
    )


def self_test() -> int:
    import shutil
    import tempfile

    def build(mutate=None) -> tuple[int, list[str]]:
        temp = Path(tempfile.mkdtemp(prefix="toolchain_selftest_"))
        try:
            _fixture(temp)
            if mutate:
                mutate(temp)
            return run(temp)
        finally:
            shutil.rmtree(temp, ignore_errors=True)

    def drift_node_image_behind_ci(root: Path) -> None:
        """The measured bug: images on 20, every workflow on 22."""
        path = root / "services" / "web-svc" / "Dockerfile"
        path.write_text(path.read_text().replace("node:22-alpine", "node:20-alpine"), encoding="utf-8")

    def drift_ci_ahead_of_images(root: Path) -> None:
        """The reverse direction: CI bumps, the Dockerfile is forgotten."""
        path = root / ".github" / "workflows" / "ci.yml"
        path.write_text(path.read_text().replace("node-version: '22'", "node-version: '24'"), encoding="utf-8")

    def drift_go_toolchain(root: Path) -> None:
        path = root / "services" / "go-svc" / "Dockerfile"
        path.write_text(path.read_text().replace("golang:1.26", "golang:1.25"), encoding="utf-8")

    def drift_floor_above_toolchain(root: Path) -> None:
        path = root / "services" / "go-svc" / "go.mod"
        path.write_text(path.read_text().replace("go 1.26", "go 1.28"), encoding="utf-8")

    def drift_pnpm_resolver(root: Path) -> None:
        """`pnpm@8` instead of `pnpm@8.15.1` — the poetry 1.7.1/1.8.2 shape."""
        path = root / "services" / "web-svc" / "Dockerfile"
        path.write_text(path.read_text().replace("pnpm@8.15.1", "pnpm@8.9.0"), encoding="utf-8")

    def drift_unlocked_install(root: Path) -> None:
        path = root / "services" / "web-svc" / "Dockerfile"
        path.write_text(path.read_text().replace("--frozen-lockfile", "--no-frozen-lockfile"), encoding="utf-8")

    def drift_dead_lockfile(root: Path) -> None:
        """A lockfile committed where nothing can consume it."""
        (root / "services" / "go-svc" / "package-lock.json").write_text('{"lockfileVersion": 3}', encoding="utf-8")

    def drift_image_without_lockfile(root: Path) -> None:
        """The measured `services/realtime` shape: install, but never copy the lock."""
        (root / "services" / "web-svc" / "package.json").write_text('{"name": "web-svc"}', encoding="utf-8")
        (root / "services" / "web-svc" / "package-lock.json").write_text('{"lockfileVersion": 3}', encoding="utf-8")
        path = root / "services" / "web-svc" / "Dockerfile"
        path.write_text(path.read_text() + "RUN npm ci --omit=dev\n", encoding="utf-8")

    def drift_missing_go_sum(root: Path) -> None:
        (root / "services" / "go-svc" / "go.sum").unlink()

    def drift_optional_go_sum(root: Path) -> None:
        path = root / "services" / "go-svc" / "Dockerfile"
        path.write_text(path.read_text().replace("go.mod go.sum", "go.mod go.sum*"), encoding="utf-8")

    def drift_stale_cache_path(root: Path) -> None:
        path = root / ".github" / "workflows" / "ci.yml"
        path.write_text(path.read_text().replace("services/go-svc/go.sum", "services/absent/go.sum"), encoding="utf-8")

    def drift_ungated_go_module(root: Path) -> None:
        (root / "packages" / "orphan-go").mkdir(parents=True)
        (root / "packages" / "orphan-go" / "go.mod").write_text("module example.com/orphan\n\ngo 1.26\n", encoding="utf-8")

    def drift_installer_node(root: Path) -> None:
        """The one-line installer handing a self-hoster a different runtime."""
        path = root / "install.sh"
        path.write_text(path.read_text().replace("setup_22.x", "setup_20.x"), encoding="utf-8")

    def drift_committed_binary(root: Path) -> None:
        """A compiled binary committed beside the source it was built from."""
        (root / "services" / "go-svc" / "go-svc").write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 64)

    def drift_ci_builds_absent_module(root: Path) -> None:
        """The reverse of `module -> CI`: a build step for a module that moved."""
        path = root / ".github" / "workflows" / "ci.yml"
        path.write_text(path.read_text().replace("cd services/go-svc", "cd services/renamed-svc"), encoding="utf-8")

    def drift_workspace_wide_esbuild(root: Path) -> None:
        path = root / "package.json"
        data = json.loads(path.read_text())
        data["pnpm"]["overrides"]["esbuild"] = "^0.28.1"
        path.write_text(json.dumps(data), encoding="utf-8")

    def drift_esbuild_resolution(root: Path) -> None:
        """A vite bump pulling a different esbuild, with no esbuild line in the diff."""
        path = root / "pnpm-lock.yaml"
        path.write_text(path.read_text().replace("esbuild@0.28.1", "esbuild@0.30.0"), encoding="utf-8")

    def drift_unversioned_setup(root: Path) -> None:
        path = root / ".github" / "workflows" / "ci.yml"
        path.write_text(path.read_text().replace("        with:\n          node-version: '22'\n", ""), encoding="utf-8")

    def drift_unscanned_install_path(root: Path) -> None:
        (root / "extra").mkdir()
        (root / "extra" / "bootstrap.sh").write_text("#!/bin/sh\npnpm install\n", encoding="utf-8")

    def drift_into_a_syntax_the_parser_skips(root: Path) -> None:
        """A Node version behind an ARG indirection.

        This is the shape of the bug `check_dependency_pins` found in itself:
        a declaration that is present, in a scanned file, and invisible to the
        parser. If `_DOCKER_FROM_ARG` is ever removed, this case fails.
        """
        path = root / "services" / "web-svc" / "Dockerfile"
        path.write_text(
            "ARG NODE_VERSION=20\nFROM node:${NODE_VERSION}-alpine AS base\n"
            "RUN npm install -g pnpm@8.15.1\nRUN pnpm install --frozen-lockfile\n",
            encoding="utf-8",
        )

    def drift_inside_a_folded_run_block(root: Path) -> None:
        """An unlocked install reaching the shell through a folded scalar."""
        path = root / ".github" / "workflows" / "ci.yml"
        path.write_text(
            path.read_text()
            + "      - name: Install via a folded scalar\n"
            + "        run: >-\n"
            + "          pnpm install\n"
            + "          --prefer-offline\n",
            encoding="utf-8",
        )

    cases = [
        ("clean fixture passes", None, None),
        ("ship -> test (image behind CI)", drift_node_image_behind_ci, "ship -> test"),
        ("test -> ship (CI ahead of images)", drift_ci_ahead_of_images, "test -> ship"),
        ("go toolchain disagreement", drift_go_toolchain, "`go` is pinned 2 different ways"),
        ("floor above toolchain", drift_floor_above_toolchain, "floor <= toolchain"),
        ("pnpm resolver disagreement", drift_pnpm_resolver, "`pnpm` is pinned 2 different ways"),
        ("installer installs another Node", drift_installer_node, "`node` is pinned 2 different ways"),
        ("unlocked install", drift_unlocked_install, "unlocked install"),
        ("dead lockfile", drift_dead_lockfile, "dead lockfile"),
        ("image installs without copying the lock", drift_image_without_lockfile, "image -> lockfile"),
        ("module -> sum (no go.sum)", drift_missing_go_sum, "module -> sum"),
        ("module -> sum (optional go.sum glob)", drift_optional_go_sum, "module -> sum"),
        ("sum -> module (cache path absent)", drift_stale_cache_path, "sum -> module"),
        ("build output committed as source", drift_committed_binary, "build output as source"),
        ("module -> CI (module nothing builds)", drift_ungated_go_module, "module -> CI"),
        ("CI -> module (build step for a module that moved)", drift_ci_builds_absent_module, "CI -> module"),
        ("workspace-wide esbuild override", drift_workspace_wide_esbuild, "override scope"),
        ("esbuild resolution moved", drift_esbuild_resolution, "override scope"),
        ("setup step with no version", drift_unversioned_setup, "no version"),
        ("unscanned install path", drift_unscanned_install_path, "coverage"),
        ("declaration in a syntax the parser skips", drift_into_a_syntax_the_parser_skips, "ship -> test"),
        ("drift inside a folded run block", drift_inside_a_folded_run_block, "unlocked install"),
    ]

    failures: list[str] = []
    for name, mutate, expect in cases:
        code, problems = build(mutate)
        blob = " ".join(problems)
        if expect is None:
            failure = f"{name}: expected a clean pass, got {problems}" if code != 0 else None
        elif code == 0:
            failure = f"{name}: injected drift went UNDETECTED"
        elif expect not in blob:
            failure = f"{name}: detected something else — {problems}"
        else:
            failure = None
        if failure:
            failures.append(failure)
        print(f"  self-test [{'FAIL' if failure else 'ok'}] {name}")

    # A gate handed a directory that is not the repo must refuse, not print OK.
    empty = Path(tempfile.mkdtemp(prefix="toolchain_selftest_empty_"))
    try:
        code, _ = run(empty)
    finally:
        shutil.rmtree(empty, ignore_errors=True)
    if code == 0:
        failures.append("non-repo root: printed OK about a tree with no install paths")
    print(f"  self-test [{'ok' if code != 0 else 'FAIL'}] refuses a non-repo root")

    if failures:
        print("\ncheck_toolchain_pins --self-test: FAIL")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print(f"\ncheck_toolchain_pins --self-test: OK — {len(cases) + 1} cases, every direction detected")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo-root", type=Path, default=None, help="tree to check")
    parser.add_argument("--verbose", action="store_true", help="list every file scanned")
    parser.add_argument("--self-test", action="store_true", help="prove the gate detects drift in each direction")
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    root = (args.repo_root or Path(__file__).resolve().parent.parent).resolve()
    return run(root, verbose=args.verbose)[0]


if __name__ == "__main__":
    sys.exit(main())
