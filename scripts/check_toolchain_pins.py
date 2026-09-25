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
  module -> format a Go module no formatting check covers
  format -> module a formatting step scoped to a directory holding no module,
                   or a `gofmt -l` whose result reaches no exit status — a
                   step that can only ever pass
  image -> CI      a service published as a container image that no workflow
                   builds, lints or tests
  CI -> image      a publish entry naming a context or Dockerfile that is not
                   in the tree
  target -> ship   a ruff or mypy target naming an interpreter no image ships
  ship -> target   an interpreter shipped that no tooling config targets
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
import subprocess
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
    "python": ("the interpreter the thirteen Python services run on. Their manifests declare ^3.11 and every image ships 3.11"),
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
        "same Playwright container and the same pnpm self-switch; pinning `version:` under v6 does not avoid it"
    ),
}

# Install paths allowed to resolve outside the lockfile, with the reason.
UNLOCKED_INSTALL_EXEMPT: dict[str, str] = {
    ".github/workflows/mobile.yml": (
        "apps/mobile is deliberately outside the root pnpm workspace and keeps its own lockfile, so a root lockfile refresh must not red it"
    ),
}

# Python is checked exactly as strictly as Go and Node. It was not, and the
# note that used to sit here recorded why: twenty-four workflows ran 3.12
# while all thirteen images shipped 3.11, and because every manifest declares
# `^3.11` — which *permits* 3.12 — nothing written down was being violated.
# That is precisely why it survived. CI was not exercising the interpreter
# production runs, which is the disjoint-`cryptography`-ranges defect one
# level up and one notch milder.
#
# It is closed in the direction of 3.11, and the reason is that 3.11 was
# already the answer everywhere except CI. The images ship it, the
# devcontainer installs it, `ruff.toml` targets `py311`, every `[tool.mypy]`
# sets `python_version = "3.11"`, and all twenty-two manifests floor at 3.11
# or below. Moving CI down aligned one set of files; moving the images up
# would have meant changing all of those *and* raising the published floor
# for seven installable packages — a breaking change for downstream
# consumers, made to fix a CI hygiene problem. Testing at the declared floor
# is also the stronger guarantee: a project that publishes `>=3.11` and tests
# only 3.12 has never run the configuration it tells people to use.
#
# There is deliberately no exemption list. An interpreter split that can be
# recorded is an interpreter split that can grow.

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

# `apps/mobile` and `services/realtime` resolve esbuild too, and neither is
# checked against EXPECTED_ESBUILD above. That is deliberate and is not the
# one-directional hole it resembles: the pinned *resolved set* exists because
# Next bundles its own esbuild and a replacement breaks Turbopack's font
# import map, and Next lives only in the root workspace. What does apply
# everywhere is the *scoping* rule — no install root may override esbuild
# workspace-wide — and `check_esbuild_overrides` now enforces that against
# every root rather than against the repository root alone.

# Install roots allowed to resolve a package another root pins, with the
# reason and the exact versions the exemption was verified against.
#
# Version-bearing on purpose. `("body-parser", "services/realtime")` alone
# would be a permanent hole: realtime could drift to any other 1.x and this
# gate would keep crediting it. Recording the versions makes each entry a
# ratchet — a bump re-fires the check and someone has to re-verify — and
# `check_override_propagation` fails in the reverse direction too, so an entry
# naming a root that no longer resolves the package, or a version the lockfile
# no longer contains, fails the build rather than sitting here.
#
# What an entry may say, and what it may not. These record *a package on two
# supported major lines*, verified clean on both. They do not record "we
# accept a vulnerable version": an override floor exists because something
# below it is exploitable, and a root resolving an affected release has to be
# fixed, not exempted. The evidence for each is a version query against the
# OSV API — the resolved version, not the range a manifest declares — because
# ten justifications in this repository's history were found to be untrue when
# checked that way.
CROSS_ROOT_OVERRIDE_EXEMPT: dict[tuple[str, str], tuple[tuple[str, ...], str]] = {
    ("body-parser", "services/realtime"): (
        ("1.20.8",),
        "the root override `>=2.3.0 <3` is a major-line floor for the "
        "workspace's Express 5 tree; realtime is on Express 4, whose 1.x line "
        "is separately patched. OSV version query for body-parser 1.20.8 on "
        "2026-09-24 returns no advisories",
    ),
    ("ws", "apps/mobile"): (
        ("6.2.6", "7.5.13"),
        "React Native's development server pins its own websocket majors: 6.2.6 "
        "through @react-native/dev-middleware and react-native itself, 7.5.13 "
        "through metro and react-devtools-core. Both are the terminal patched "
        "releases of those lines and OSV version queries for ws 6.2.6 and "
        "7.5.13 on 2026-09-24 return no advisories. Forcing 8.x here would "
        "override the transport the Metro dev server speaks, which is a bundler "
        "change made to satisfy a range written for the web workspace — and "
        "none of these three reach the shipped app bundle",
    ),
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


def git_root() -> Path:
    """The repository being checked, asked of git rather than inferred.

    This used to be `Path(__file__).parent.parent`, which is the tree the
    *script* lives in — not necessarily the tree anyone wants checked. A copy
    of this file vendored, symlinked or invoked from a sibling checkout would
    have printed a confident OK about a tree it never opened. `git rev-parse`
    answers the question actually being asked.
    """
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=True,
            cwd=Path(__file__).resolve().parent,
        )
        return Path(completed.stdout.strip())
    except (OSError, subprocess.CalledProcessError):
        # Not a git checkout (a release tarball, a container build context).
        # Falling back is fine; silently falling back is not, because the
        # caller would never learn which tree was read.
        fallback = Path(__file__).resolve().parent.parent
        print(f"check_toolchain_pins: not a git checkout — falling back to {fallback}", file=sys.stderr)
        return fallback


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
class NodeRoot:
    """One directory that resolves its own node_modules.

    An *install root*, not a workspace member: a directory holding both a
    manifest and a lockfile, so `pnpm install` or `npm install` run there
    produces a version set of its own. There are four in this tree and they
    were treated as one for as long as only the repository root was read.
    """

    directory: str  # "" for the repository root
    manifest: str
    lockfile: str
    tool: str  # pnpm | npm
    # Override key exactly as written -> spec. Keys may be a bare name, a
    # scoped name, a name with a version selector (`js-yaml@3`) or a
    # parent-scoped path (`vite>esbuild`).
    overrides: dict[str, str] = field(default_factory=dict)
    # The key the overrides were read from, so `check_override_parser_coverage`
    # can tell "no overrides" apart from "overrides this parser cannot see".
    overrides_key: str = ""
    # package -> every version the lockfile resolved for it. A list, not one
    # version: pnpm keeps several majors of the same package side by side and
    # collapsing them would hide exactly the one that is vulnerable.
    resolved: dict[str, list[str]] = field(default_factory=dict)


@dataclass
class Scan:
    pins: list[Pin] = field(default_factory=list)
    installs: list[Install] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    node_roots: list[NodeRoot] = field(default_factory=list)
    go_modules: dict[str, dict] = field(default_factory=dict)
    go_cache_paths: list[tuple[str, str]] = field(default_factory=list)
    pnpm_actions: list[tuple[str, str]] = field(default_factory=list)
    go_ci_builds: set[str] = field(default_factory=set)
    # (workflow, scope, command, enclosing run block). `scope` is "" for a
    # repo-wide run and a directory when the step is confined to one. The
    # block is kept so "can this step actually fail?" is answered from the
    # step itself: searching the rest of the file for an `exit 1` would find
    # one in an unrelated job and call the step safe.
    gofmt_steps: list[tuple[str, str, str, str]] = field(default_factory=list)
    # Directory -> (workflow, the line that proves it). Kept as evidence
    # rather than a bare set so `report` can print *why* each published
    # service counts as covered: the first version of this recorded a
    # directory because a quoted path appeared in a shell array, and a set
    # of strings gives a reader no way to notice that.
    ci_dirs: dict[str, tuple[str, str]] = field(default_factory=dict)
    # service name -> (context, dockerfile), from the publish matrix.
    published: dict[str, tuple[str, str]] = field(default_factory=dict)
    # Manifests declaring [tool.mypy] without a `python_version`.
    untargeted_mypy: list[str] = field(default_factory=list)

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
# `\S+` was not enough: `working-directory: services/${{ matrix.service }}`
# contains spaces, so it captured `services/${{` and resolved to nothing —
# the eight services in `python-services-test` looked exercised by no step
# at all. It never bit the Go check because `build-extensions.yml` names a
# literal path, which is how a blind spot survives: the one caller that
# would expose it does not use the syntax.
# `(?:-\s+)?` because `working-directory:` can be the *first* key of a step,
# in which case the line begins `- working-directory:` and an anchor of
# `^\s*` alone does not reach it. Found by this file's own self-test.
_GO_WORKDIR = re.compile(
    r"^\s*(?:-\s+)?working-directory:\s*(?P<dir>\S+(?:\s*\$\{\{[^}]*\}\}\S*)?|\S+)\s*$",
    re.MULTILINE,
)
_GO_VERB = re.compile(r"\bgo\s+(?:build|test|vet|mod)\b")
_EXPANSION = re.compile(r"\$\{\{\s*matrix\.(?P<key>\w+)\s*\}\}")

_MATRIX_HEADER = re.compile(r"^(?P<indent>\s*)matrix:\s*(?:#.*)?$")
_MATRIX_INLINE = re.compile(r"^(?P<indent>\s*)(?P<key>\w+):\s*\[(?P<items>.+)\]\s*(?:#.*)?$")
_MATRIX_DECLARE = re.compile(r"^(?P<indent>\s*)(?P<key>\w+):\s*(?:#.*)?$")
_MATRIX_ITEM = re.compile(r"^(?P<indent>\s*)-\s*(?P<value>.+?)\s*$")


def _matrix_values(text: str) -> dict[str, list[str]]:
    """Every matrix leg, so `${{ matrix.key }}` can be resolved to real paths.

    Both spellings, because this tree uses both and the first version of this
    function read only one. `ci.yml` writes the Go matrices inline —
    `service: [enrichment, ingest, demo-producer]` — and the Python one as a
    block list of eight services. A reader that knows only the inline form
    reports those eight as tested by nothing, and the reason it was never
    noticed is that the inline form happens to be the one both *Go* matrices
    use, so every existing check passed over the gap.

    Scoped to the block under a `matrix:` key rather than matched anywhere in
    the file: a bare `key:` followed by `- item` lines also describes `steps:`
    and `ports:`, and attributing those to the matrix invents legs.
    """
    values: dict[str, list[str]] = {}
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        header = _MATRIX_HEADER.match(lines[index])
        if not header:
            index += 1
            continue
        base = len(header.group("indent"))
        index += 1
        key: str | None = None
        key_indent = -1
        while index < len(lines):
            line = lines[index]
            if line.strip() and (len(line) - len(line.lstrip())) <= base:
                break  # dedented out of the matrix block
            inline = _MATRIX_INLINE.match(line)
            declare = _MATRIX_DECLARE.match(line)
            item = _MATRIX_ITEM.match(line)
            if inline:
                found = [v.strip().strip("\"'") for v in inline.group("items").split(",")]
                values.setdefault(inline.group("key"), []).extend(v for v in found if v)
                key = None
            elif declare:
                key, key_indent = declare.group("key"), len(declare.group("indent"))
            elif item and key and len(item.group("indent")) > key_indent:
                value = item.group("value").strip().strip("\"'")
                # An `include:` leg is a mapping (`- service: api`), not a
                # scalar. Those are parsed by `_publish_targets`, which needs
                # the other keys of the same leg; taking the first one here
                # would record `service: api` as if it were a leg value.
                if ":" not in value:
                    values.setdefault(key, []).append(value)
            index += 1
    return values


# `- service: realtime` / `context: services/realtime` legs of a publish
# matrix. A service published as an image and built by no CI job is how
# `services/realtime` shipped untested; finding that requires reading the
# publish list rather than guessing from directory names.
_PUBLISH_LEG = re.compile(
    r"^\s*-\s*service:\s*(?P<service>\S+)\s*$\n(?P<body>(?:^\s+\w[\w-]*:.*$\n?)+)",
    re.MULTILINE,
)
_PUBLISH_FIELD = re.compile(r"^\s*(?P<key>context|dockerfile):\s*(?P<value>\S+)\s*$", re.MULTILINE)

# The devcontainer installs Python from apt, not `FROM python:X.Y`, so the
# Dockerfile parser above extracts nothing from it. A contributor's first
# build runs on that interpreter; a version there that CI does not use is a
# local green that reds on push.
_APT_PYTHON = re.compile(r"\bpython(?P<version>3\.\d+)(?:\s|-venv|\b)")

# `target-version = "py311"` (ruff) and `python_version = "3.11"` (mypy).
# These decide which syntax ruff accepts and which standard library mypy
# checks against. A tooling target that is not the shipped interpreter means
# both tools are reasoning about a Python nobody runs.
_RUFF_TARGET = re.compile(r"""^\s*target-version\s*=\s*["']py(?P<major>\d)(?P<minor>\d+)["']""", re.MULTILINE)
_MYPY_TARGET = re.compile(r"""^\s*python_version\s*=\s*["'](?P<version>\d+\.\d+)["']""", re.MULTILINE)

# A `gofmt` invocation in a workflow, and the shapes that make its result
# reach an exit status. `gofmt -l` prints offenders and exits 0, so without
# one of these the step is a log message with a green tick on it.
_GOFMT = re.compile(r"\bgofmt\b[^\n]*")
_GOFMT_FAILS = re.compile(r"exit\s+1|\|\|\s*(?:exit|false)\b|-n\s+[\"']?\$|\bif\s+\[\s*-n\b|--exit-code\b")

# A first-party directory named in a command — `cd services/api`,
# `pytest services/api/tests`, `--filter apps/web`. Evidence that CI
# exercises that tree, however the step spells it.
#
# The `${{ matrix.x }}` alternative is spelled out rather than folded into a
# character class, because the expansion contains spaces: a class of
# `[\w.${}/-]+` stops at the first one, yielding `services/${{`, which
# resolves to nothing and reports every matrix-driven service as untested.
# That is the `cd services/${{ matrix.service }}` blind spot #817 found,
# re-entering through a different regex.
_SEGMENT = r"(?:\$\{\{[^}]*\}\}|[\w.-]+)"
_PROJECT_DIR = re.compile(rf"(?<![\w./-])(?P<dir>(?:services|apps|packages)/{_SEGMENT}(?:/{_SEGMENT})*)")

# A path counts as exercised only when something *runs* on it. Without this,
# any line that happens to contain a path is evidence, and a list of paths
# is not a test of them.
_COMMAND_VERB = re.compile(
    r"(?<![\w-])(?:cd|pytest|python3?|pip|poetry|uv|npm|pnpm|yarn|node|npx|go|gofmt|ruff|mypy|"
    r"tsc|eslint|vitest|docker|make|bash|sh|cargo|terraform|helm)(?![\w-])"
)


def _record_ci_dir(scan_result: Scan, directory: str, workflow: str, evidence: str) -> None:
    """First sighting wins, so the printed evidence is stable across runs."""
    scan_result.ci_dirs.setdefault(directory, (workflow, evidence))


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


_JOBS_HEADER = re.compile(r"^jobs:\s*(?:#.*)?$")
_JOB_ID = re.compile(r"^(?P<indent>\s+)(?P<name>[\w-]+):\s*(?:#.*)?$")


def _jobs(text: str) -> list[tuple[str, str]]:
    """Split a workflow into its jobs.

    A matrix, a `working-directory:` and a `run:` block all belong to one
    job, and reading them file-wide attributes one job's context to another.
    Measured, on this repository: `ci.yml` declares `service:` twice — the Go
    build matrix inline as `[enrichment, ingest, demo-producer]`, and the
    Python one as a block list of eight — so a file-wide reader resolved
    `cd services/${{ matrix.service }}` in the *Go* job to all eleven and
    reported eight Python services as Go modules that had gone missing. The
    same read took the first `working-directory:` in the file, `apps/web`,
    and applied it to a job five hundred lines away.
    """
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines) if _JOBS_HEADER.match(line)), None)
    if start is None:
        return []
    jobs: list[tuple[str, str]] = []
    current: str | None = None
    body: list[str] = []
    indent: int | None = None
    for line in lines[start + 1 :]:
        if line.strip() and not line[0].isspace():
            break  # dedented back out of `jobs:`
        found = _JOB_ID.match(line)
        if found and (indent is None or len(found.group("indent")) == indent):
            indent = len(found.group("indent"))
            if current is not None:
                jobs.append((current, "\n".join(body)))
            current, body = found.group("name"), []
            continue
        body.append(line)
    if current is not None:
        jobs.append((current, "\n".join(body)))
    return jobs


_RUN_HEADER = re.compile(r"^(?P<indent>\s*)(?:-\s+)?run:\s*(?P<inline>.*)$")
_BLOCK_SCALAR = frozenset({"|", ">", "|-", ">-", "|+", ">+", ""})


def _run_blocks(text: str) -> list[str]:
    """Every `run:` block body, and nothing else.

    Scanning a whole workflow for a command finds it in three places that are
    not commands: a `name:` describing the step, an `echo` explaining the
    failure, and a comment. The first version of the gofmt check matched all
    three — `- name: gofmt -l (whole tree)` and
    `echo "gofmt: OK — ..."` each counted as an invocation, so one step
    looked like seven. Reading only run bodies removes the first and the
    third; `_strip_quoted` at the call site removes the second.
    """
    lines = text.splitlines()
    blocks: list[str] = []
    index = 0
    while index < len(lines):
        header = _RUN_HEADER.match(lines[index])
        if not header:
            index += 1
            continue
        indent = len(header.group("indent"))
        inline = header.group("inline").strip()
        index += 1
        if inline and inline not in _BLOCK_SCALAR:
            blocks.append(inline)
            continue
        body: list[str] = []
        while index < len(lines):
            line = lines[index]
            if line.strip() and (len(line) - len(line.lstrip())) <= indent:
                break
            body.append(line)
            index += 1
        blocks.append("\n".join(body))
    return blocks


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
    # Everything below is job-scoped, because a matrix, a `working-directory:`
    # and a `run:` block each belong to one job. See `_jobs`.
    for _job, job_text in _jobs(text) or [("", text)]:
        matrix = _matrix_values(job_text)

        # A `cd` only counts as compiling a module when a `go` verb follows
        # it. Matching every `cd services/<x>` reported five Python services
        # as Go modules the workflow built; matching only literal paths
        # reported five real Go modules as built by nothing, because `ci.yml`
        # drives them through `cd services/${{ matrix.service }}`. Both
        # halves are needed.
        for match in _GO_CD.finditer(job_text):
            if not _GO_VERB.search(job_text[match.end() : match.end() + 300]):
                continue
            for directory in _expand(match.group("dir"), matrix):
                scan_result.go_ci_builds.add(directory)
        # Accepting only directories that actually hold a go.mod keeps this
        # precise even when a job mixes languages.
        if _GO_VERB.search(job_text):
            for match in _GO_WORKDIR.finditer(job_text):
                for directory in _expand(match.group("dir").strip("\"'"), matrix):
                    if (root / directory / "go.mod").exists():
                        scan_result.go_ci_builds.add(directory)

        # Every directory this job runs something in. Used by
        # `check_published_service_ci`; deliberately wider than
        # `go_ci_builds`, which is narrowed to directories holding a go.mod.
        job_scope = ""
        folded = _fold_yaml_run_blocks(job_text)
        for match in _GO_WORKDIR.finditer(folded):
            scoped = _expand(match.group("dir").strip("\"'"), matrix)
            for directory in scoped:
                _record_ci_dir(scan_result, directory, rel, match.group(0).strip())
            if len(scoped) == 1:
                job_scope = scoped[0]
        for block in _run_blocks(folded):
            # Quoted spans are data, not commands. `compose-smoke.yml` holds
            # a shell array of build-context paths — `'services/realtime/'`
            # among them — used to decide whether an image is stale. Read
            # literally that array says CI exercises eleven services; it
            # tests none of them. Same shape as `die "pnpm install failed."`
            # counting as an install path.
            commands = _strip_quoted(block)
            for line in commands.splitlines():
                # A path is evidence only when a command acts on it. A bare
                # path in a list is a mention.
                if not _COMMAND_VERB.search(line):
                    continue
                for match in _PROJECT_DIR.finditer(line):
                    for directory in _expand(match.group("dir"), matrix):
                        # `services/api/tests` is evidence that
                        # `services/api` is exercised, so every prefix counts.
                        parts = directory.split("/")
                        for depth in range(2, len(parts) + 1):
                            _record_ci_dir(scan_result, "/".join(parts[:depth]), rel, line.strip()[:100])

            # gofmt, read from the command and not from the prose around it.
            # `_strip_quoted` because `echo "gofmt: OK"` is a message about a
            # check, not a check — the same shape as `die "pnpm install
            # failed."` counting as an install path.
            for match in _GOFMT.finditer(commands):
                confined = re.findall(r"cd\s+(?P<dir>(?:services|packages|apps)/[\w.${}/-]+)", commands[: match.start()])
                scope = confined[-1] if confined else job_scope
                scan_result.gofmt_steps.append((rel, scope, match.group(0).strip(), block))

    # A setup step with no version input takes whatever the runner ships.
    for match in _SETUP_ACTION.finditer(text):
        runtime = match.group("runtime")
        window = text[match.end() : match.end() + 400]
        key = f"{runtime}-version"
        if key not in window.split("- ")[0]:
            scan_result.pins.append(Pin(runtime, "", rel, "test", match.group(0).strip()))

    scan_result.installs += _install_commands(path.read_text(encoding="utf-8"), rel, "")

    # The publish matrix: which services are built into container images.
    for leg in _PUBLISH_LEG.finditer(text):
        fields = {m.group("key"): m.group("value").strip("\"'") for m in _PUBLISH_FIELD.finditer(leg.group("body"))}
        if "context" in fields:
            scan_result.published[leg.group("service")] = (fields["context"], fields.get("dockerfile", "Dockerfile"))


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
    # The devcontainer gets its interpreter from apt, so `FROM python:X.Y`
    # matches nothing and the file contributed no Python declaration at all
    # — scanned, counted, and silent.
    if role == "dev":
        for match in _APT_PYTHON.finditer(text):
            scan_result.pins.append(Pin("python", match.group("version"), rel, role, match.group(0).strip()))

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


def _parse_python_targets(text: str, rel: str, scan_result: Scan) -> None:
    """ruff's `target-version` and mypy's `python_version`, as role `target`.

    Not a toolchain — neither line installs anything — and not a floor
    either, because both are exact: ruff refuses syntax newer than its
    target, and mypy checks against that version's standard library. They
    are the interpreter the *static* tools believe in, and they are worth
    comparing because they are written once and then never revisited.
    """
    for match in _RUFF_TARGET.finditer(text):
        version = f"{match.group('major')}.{match.group('minor')}"
        scan_result.pins.append(Pin("python", version, rel, "target", match.group(0).strip()))
    for match in _MYPY_TARGET.finditer(text):
        scan_result.pins.append(Pin("python", match.group("version"), rel, "target", match.group(0).strip()))


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


# A pnpm lockfile package header: `  /image-size@2.0.4:` or
# `  /@babel/core@7.29.7(peer@1.2.3):`. The peer suffix is dropped — it
# identifies a variant of the same release, not a different version.
_PNPM_PKG = re.compile(r"^ {2}/(?P<name>@[^/@\s]+/[^@\s]+|[^@/\s][^@\s]*)@(?P<version>\d[^(:\s]*)", re.MULTILINE)

#: An override key, split into the package it governs and the selector on it.
#:
#: Four shapes appear in this tree and they do not mean the same thing:
#:   `image-size`          every resolution of the package
#:   `js-yaml@3`           only resolutions in that version line
#:   `@babel/plugin-…`     a scoped package, where the `@` is part of the name
#:   `vite>esbuild`        only where `vite` is the parent — a *scoped*
#:                         override, which is the whole point of the esbuild
#:                         arrangement and must not be read as a global one
_OVERRIDE_KEY = re.compile(r"^(?:(?P<parent>[^>]+)>)?(?P<name>@[^/@]+/[^@]+|[^@>]+)(?:@(?P<selector>.+))?$")


def parse_override_key(key: str) -> tuple[str | None, str, str | None]:
    """`(parent, package, selector)` for one override key."""
    match = _OVERRIDE_KEY.match(key.strip())
    if not match:
        return None, key.strip(), None
    return match.group("parent"), match.group("name"), match.group("selector")


def parse_pnpm_lock(text: str) -> dict[str, list[str]]:
    resolved: dict[str, list[str]] = {}
    for match in _PNPM_PKG.finditer(text):
        resolved.setdefault(match.group("name"), []).append(match.group("version"))
    return resolved


def parse_npm_lock(text: str) -> dict[str, list[str]]:
    resolved: dict[str, list[str]] = {}
    for key, meta in (json.loads(text).get("packages") or {}).items():
        if "node_modules/" not in key or not isinstance(meta, dict):
            continue
        version = meta.get("version")
        if isinstance(version, str) and version:
            # Nested paths carry the package last: `node_modules/a/node_modules/b`.
            resolved.setdefault(key.rsplit("node_modules/", 1)[1], []).append(version)
    return resolved


def _flatten_npm_overrides(block: dict, prefix: str = "") -> dict[str, str]:
    """npm's nested `overrides` object, flattened to the same shape as pnpm's.

    npm permits `{"a": {"b": "1.0.0"}}`, which pnpm writes `a>b`. Reading only
    the flat form would credit a nested override as absent, so the two
    spellings are normalised to one before anything compares them.
    """
    flat: dict[str, str] = {}
    for key, value in block.items():
        name = f"{prefix}{key}"
        if isinstance(value, str):
            flat[name] = value
        elif isinstance(value, dict):
            if isinstance(value.get("."), str):
                flat[name] = value["."]
            flat.update(_flatten_npm_overrides({k: v for k, v in value.items() if k != "."}, f"{name}>"))
    return flat


def parse_node_root(manifest: Path, lockfile: Path, rel_dir: str) -> NodeRoot:
    data = json.loads(manifest.read_text(encoding="utf-8"))
    pnpm_overrides = (data.get("pnpm") or {}).get("overrides") or {}
    npm_overrides = data.get("overrides") or {}
    if pnpm_overrides:
        overrides, key = dict(pnpm_overrides), "pnpm.overrides"
    elif npm_overrides:
        overrides, key = _flatten_npm_overrides(npm_overrides), "overrides"
    else:
        overrides, key = {}, ""

    text = lockfile.read_text(encoding="utf-8")
    if lockfile.name == "pnpm-lock.yaml":
        tool, resolved = "pnpm", parse_pnpm_lock(text)
    else:
        tool, resolved = "npm", parse_npm_lock(text)

    return NodeRoot(
        directory=rel_dir,
        manifest=manifest.name if not rel_dir else f"{rel_dir}/{manifest.name}",
        lockfile=lockfile.name if not rel_dir else f"{rel_dir}/{lockfile.name}",
        tool=tool,
        overrides=overrides,
        overrides_key=key,
        resolved=resolved,
    )


def scan_node_roots(root: Path) -> list[NodeRoot]:
    """Every directory in the tree that resolves its own node_modules.

    Discovered structurally rather than listed. A list would have had one
    entry — the repository root — for the same reason every other check here
    did: `apps/mobile` was created as an independent install root precisely so
    its install would stop rewriting the root lockfile, and nothing that reads
    dependency resolution was told it now existed.
    """
    found: list[NodeRoot] = []
    for name in ("pnpm-lock.yaml", "package-lock.json"):
        for lockfile in walk(root, name):
            manifest = lockfile.parent / "package.json"
            if not manifest.is_file():
                continue  # reported by `check_dead_lockfiles`
            rel_dir = lockfile.parent.relative_to(root).as_posix()
            found.append(parse_node_root(manifest, lockfile, "" if rel_dir == "." else rel_dir))
    return sorted(found, key=lambda r: r.directory)


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

    result.node_roots = scan_node_roots(root)
    for node_root in result.node_roots:
        result.files.append(node_root.lockfile)

    # `packages/*` as well as `services/*`: the packages are the *published*
    # artefacts, so their floor is a promise to a downstream consumer rather
    # than an internal note. Reading only `services/` meant the floor that
    # actually ships to users was the one nothing compared.
    for pyproject in sorted(root.glob("services/*/pyproject.toml")) + sorted(root.glob("packages/*/pyproject.toml")):
        rel = pyproject.relative_to(root).as_posix()
        result.files.append(rel)
        raw = pyproject.read_text(encoding="utf-8")
        data = tomllib.loads(raw)
        declared = data.get("tool", {}).get("poetry", {}).get("dependencies", {}).get("python") or data.get("project", {}).get(
            "requires-python"
        )
        if isinstance(declared, str):
            result.pins.append(Pin("python", re.sub(r"^[^\d]*", "", declared), rel, "floor", f"python {declared}"))
        _parse_python_targets(raw, rel, result)
        # A tree that asks to be type-checked and does not say against which
        # Python gets the interpreter mypy happens to run on.
        mypy_config = data.get("tool", {}).get("mypy")
        if isinstance(mypy_config, dict) and "python_version" not in mypy_config:
            result.untargeted_mypy.append(rel)

    # `ruff.toml` at the root configures every tree that has no local table.
    ruff_config = root / "ruff.toml"
    if ruff_config.exists():
        rel = ruff_config.relative_to(root).as_posix()
        result.files.append(rel)
        _parse_python_targets(ruff_config.read_text(encoding="utf-8"), rel, result)

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

    Python is held to this now. It used to be excused here because its
    manifests declare a floor rather than a pin, so CI on 3.12 and an image
    on 3.11 both satisfied what was written — which is exactly how the split
    survived twenty-four workflows. A floor is what a *consumer* may use; it
    is not a licence for the project's own paths to disagree about what they
    run.
    """
    problems: list[str] = []
    for runtime, reason in sorted(RUNTIMES.items()):
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
        shipped = {p.version for p in data.by_runtime(runtime) if p.role == "ship" and p.version}
        tested = {p.version for p in data.by_runtime(runtime) if p.role == "test" and p.version}
        if not shipped or not tested:
            continue
        for version in sorted(shipped - tested):
            where = sorted({p.path for p in data.by_runtime(runtime) if p.role == "ship" and p.version == version})
            problems.append(f"`{runtime}` {version} is shipped by {', '.join(where)} but no workflow builds or tests on it (ship -> test)")
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
                        f"{floor.path} declares `{runtime}` >= {floor.version}, but {pin.path} installs {pin.version} (floor <= toolchain)"
                    )
    return problems


def check_python_tooling_target(data: Scan) -> list[str]:
    """Both directions between the shipped interpreter and the static tools' target.

    `ruff.toml` says `target-version = "py311"` and every `[tool.mypy]` says
    `python_version = "3.11"`. Neither installs anything, so no other check
    in this file looks at them — and both decide what the tools *believe*.
    ruff rejects syntax newer than its target and accepts syntax the runtime
    may not have; mypy resolves the standard library for the version it is
    told. Pointed at the wrong interpreter they are two more checks reasoning
    about software nobody runs, which is the defect this gate exists for,
    arrived at from a third direction.

    Forward (target -> ship) catches a target left behind after the images
    move. Reverse (ship -> target) catches the images moving while the
    targets stay, which is the direction that actually happens: a Dockerfile
    bump is one line and nobody greps for `target-version`.
    """
    problems: list[str] = []
    pins = data.by_runtime("python")
    shipped = {p.version for p in pins if p.role == "ship" and p.version}
    targets = [p for p in pins if p.role == "target" and p.version]
    if not shipped or not targets:
        return problems

    for pin in targets:
        if pin.version not in shipped:
            problems.append(
                f"{pin.path} targets Python {pin.version} (`{pin.raw}`) but the images ship "
                f"{', '.join(sorted(shipped))} — ruff and mypy are reasoning about an "
                f"interpreter nothing runs (target -> ship)"
            )
    declared = {p.version for p in targets}
    for version in sorted(shipped - declared):
        problems.append(
            f"images ship Python {version}, which no ruff `target-version` or mypy "
            f"`python_version` names ({', '.join(sorted(declared))}) — the static tools were "
            f"left behind by a Dockerfile bump (ship -> target)"
        )
    # A declared-but-untargeted tree is the same defect with nothing to
    # compare: five of the six trees declaring [tool.mypy] pin 3.11 and one
    # did not, so its share of the recorded baseline followed whatever
    # interpreter CI ran and a workflow change could red the ratchet without
    # touching the code.
    for path in sorted(data.untargeted_mypy):
        problems.append(
            f"{path} declares [tool.mypy] with no `python_version`, so it is checked against "
            f"whichever interpreter the job happens to run — pin it to the shipped "
            f"{', '.join(sorted(shipped))} (target -> ship)"
        )
    return problems


def check_go_formatting(data: Scan) -> list[str]:
    """Both directions between the Go modules and the formatting check in CI.

    CI ran `go vet` and `go build` and never `gofmt`; `go vet` does not look
    at formatting, so 28 unformatted files across four modules were invisible
    to a pipeline that otherwise compiled every one of them.

    Forward (module -> format) catches a module no formatting step reaches.
    Reverse (format -> module) catches the two ways the step itself can be
    hollow: scoped to a directory that holds no module, or written as a bare
    `gofmt -l`, which prints the offenders and exits 0 — a step that reports
    the problem in its log and passes anyway. That second shape is the whole
    family of defect this repository keeps finding, so it is checked rather
    than assumed.
    """
    problems: list[str] = []
    modules = {directory for directory, entry in data.go_modules.items() if entry.get("mod")}
    if not modules:
        return problems

    if not data.gofmt_steps:
        return [
            f"no workflow runs `gofmt` anywhere, but this tree has {len(modules)} Go module(s) "
            f"({', '.join(sorted(modules))}). `go vet` does not check formatting (module -> format)"
        ]

    repo_wide = [s for s in data.gofmt_steps if not s[1]]
    scoped = {s[1] for s in data.gofmt_steps if s[1]}

    for workflow, scope, command, block in data.gofmt_steps:
        # `gofmt -l` succeeds whether or not it printed anything. Turning that
        # into a failure takes an explicit test of the output; without one the
        # step is decoration.
        if "-l" in command.split() and not _GOFMT_FAILS.search(block):
            problems.append(
                f"{workflow} runs `{command}` but nothing in that step turns the result into a "
                f"non-zero exit — `gofmt -l` prints the offenders and succeeds, so the step can "
                f"only ever pass (format -> module)"
            )
        if scope and scope not in modules:
            problems.append(
                f"{workflow} runs gofmt confined to `{scope}`, which holds no go.mod — the step "
                f"formats nothing this repository builds (format -> module)"
            )

    if not repo_wide:
        for directory in sorted(modules - scoped):
            problems.append(
                f"{directory}/go.mod is covered by no formatting check — every gofmt step in CI "
                f"is scoped to another directory (module -> format)"
            )
    return problems


def check_published_service_ci(root: Path, data: Scan) -> list[str]:
    """Both directions between what is published as an image and what CI builds.

    `services/realtime` was published to GHCR on every release with no build,
    test, lint or type-check job anywhere in the pipeline. It is one of the
    two ends of the Kafka spine and it holds the TypeScript CORS guard, so
    "nobody noticed" meant "a break reached whoever deployed it first".

    Forward (image -> CI) is that finding. Reverse (CI -> image) catches the
    publish matrix naming a context or Dockerfile that is not in the tree,
    which fails the release rather than the pull request and so is found at
    the worst possible moment.
    """
    problems: list[str] = []
    if not data.published:
        return problems

    for service, (context, dockerfile) in sorted(data.published.items()):
        target = context if context != "." else str(Path(dockerfile).parent)
        if not (root / target).is_dir():
            problems.append(
                f"the publish matrix builds `{service}` from `{target}`, which is not a "
                f"directory in this tree — the release fails, not the pull request (CI -> image)"
            )
            continue
        if not (root / dockerfile).is_file() and not (root / target / dockerfile).is_file():
            problems.append(f"the publish matrix builds `{service}` with dockerfile `{dockerfile}`, which does not exist (CI -> image)")
        if target not in data.ci_dirs:
            problems.append(
                f"`{service}` is published as a container image from `{target}`, and no workflow "
                f"builds, lints or tests it — a break in it is found by whoever deploys it "
                f"(image -> CI)"
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


_RELEASE = re.compile(r"^(\d+(?:\.\d+)*)")
_CLAUSE = re.compile(r"^(?P<op>>=|<=|>|<|=|\^|~)?(?P<version>\d[\w.*-]*)$")


def satisfies_npm_range(version: str, spec: str) -> bool | None:
    """Whether a concrete version is inside an npm range.

    Returns ``None`` — not ``False`` — for a range this function cannot
    reason about. A boolean for an unparsed spec is the shape that makes a
    gate credit something it never evaluated: `False` reds the build for no
    reason and `True` passes silently, and the second is how the caller ends
    up printing OK about a comparison that did not happen. The caller reports
    ``None`` as a finding against this gate rather than against the tree.

    Only the operators actually written in this repository's overrides are
    supported (`>=`, `<=`, `>`, `<`, `=`, `^`, `~`, bare, and space- or
    comma-joined conjunctions of them). `||` unions and hyphen ranges are
    deliberately absent rather than approximated.
    """
    release = _RELEASE.match(version)
    if not release:
        return None
    actual = tuple(int(p) for p in release.group(1).split("."))

    normalised = spec.strip().replace(",", " ")
    if not normalised or "||" in normalised or " - " in normalised or normalised in {"*", "x", "latest"}:
        return None

    for clause in normalised.split():
        match = _CLAUSE.match(clause)
        if not match or "*" in match.group("version") or "-" in match.group("version"):
            return None
        bound_release = _RELEASE.match(match.group("version"))
        if not bound_release:
            return None
        bound = tuple(int(p) for p in bound_release.group(1).split("."))
        operator = match.group("op") or "="
        left, right = _pad(actual, bound)

        if operator in {"^", "~"}:
            # `^1.2.3` is `>=1.2.3 <2.0.0`; `^0.2.3` is `>=0.2.3 <0.3.0`
            # (npm treats a leading zero major as unstable). `~1.2.3` is
            # `>=1.2.3 <1.3.0`.
            if left < right:
                return False
            if operator == "~" or (operator == "^" and bound and bound[0] == 0):
                ceiling = bound[:2] if len(bound) >= 2 else bound
                if actual[: len(ceiling)] != ceiling:
                    return False
            elif actual[:1] != bound[:1]:
                return False
            continue

        ok = {">=": left >= right, ">": left > right, "<=": left <= right, "<": left < right, "=": left == right}[operator]
        if not ok:
            return False
    return True


def _governed(versions: list[str], selector: str | None) -> list[str]:
    """The resolutions an override key actually governs.

    A bare key governs every resolution; `js-yaml@3` governs only the 3.x
    line. Without this, the root's `brace-expansion@1` pin would be compared
    against the 5.0.12 the workspace also resolves and fail for a version the
    key was never written about.
    """
    if not selector:
        return versions
    return [v for v in versions if satisfies_npm_range(v, selector) is True]


def check_override_propagation(root: Path, data: Scan) -> list[str]:
    """A dependency resolution decision made in one install root and not another.

    This is the Node half of the defect ``check_dependency_pins`` was built
    for on the Python side, where CI installed a ``cryptography`` range
    disjoint from the one a service required. Here the two sides are two
    *install roots*: the repository workspace pinned ``image-size`` to
    ``>=2.0.4 <3`` after establishing that ``<= 2.0.2`` is vulnerable, and
    ``apps/mobile`` — an independent root with its own lockfile, created that
    way so its install would stop rewriting the root lock — kept resolving
    1.2.1 through Metro. The fix could not reach it and nothing compared them,
    so two high-severity advisories stayed open against a package the
    repository had already decided the answer for.

    Both directions:

    declaration -> resolution
        a root resolving a package another root pins, at a version outside
        that pin, with no pin of its own. The direction the tree drifted.
    resolution -> declaration
        a root whose own lockfile resolves a version its own override
        forbids — a lockfile that was not regenerated after the manifest
        moved, which is the same disagreement inside one root.
    exemption -> tree / tree -> exemption
        an exemption naming a root that no longer resolves the package, or
        one whose recorded version no longer matches what the lockfile says.

    Not checked, and said plainly rather than left to be discovered: an
    override declared in one root and resolved by no root at all is *not*
    reported. Several here are deliberately defensive — nothing in this tree
    resolves js-yaml 3.x, and the `js-yaml@3` pin exists so that if something
    later does, it lands patched. Calling that dead would push people to
    delete the pin that is doing the work.
    """
    problems: list[str] = []
    by_dir = {r.directory: r for r in data.node_roots}

    # ── declaration -> resolution, across roots ──────────────────────────
    for declaring in data.node_roots:
        for key, spec in sorted(declaring.overrides.items()):
            parent, package, selector = parse_override_key(key)
            if parent:
                continue  # `vite>esbuild` constrains one parent, not the package
            for other in data.node_roots:
                if other.directory == declaring.directory:
                    continue
                governed = _governed(other.resolved.get(package, []), selector)
                if not governed:
                    continue
                exempt = CROSS_ROOT_OVERRIDE_EXEMPT.get((package, other.directory))
                offending = []
                for version in sorted(set(governed)):
                    verdict = satisfies_npm_range(version, spec)
                    if verdict is None:
                        problems.append(
                            f"{declaring.manifest} pins `{key}` to `{spec}`, which this gate cannot "
                            f"evaluate against the {version} that {other.lockfile} resolved — a range "
                            f"the comparison skips is a comparison that did not happen; teach "
                            f"`satisfies_npm_range` the operator or rewrite the pin (override propagation)"
                        )
                    elif verdict is False:
                        offending.append(version)
                if not offending:
                    continue
                if exempt and set(offending) <= set(exempt[0]):
                    continue
                if exempt:
                    offending = sorted(set(offending) - set(exempt[0]))
                own = other.overrides.get(key) or other.overrides.get(package)
                held = f" — it declares `{own}` of its own" if own else " and declares no override of its own"
                problems.append(
                    f"{declaring.manifest} pins `{key}` to `{spec}` but {other.lockfile} resolves "
                    f"{package}@{', '.join(offending)}{held}. `{other.directory or '.'}` is a separate "
                    f"install root, so a resolution applied in one lockfile does not reach the other; "
                    f"add the override there too, or record a measured reason in "
                    f"CROSS_ROOT_OVERRIDE_EXEMPT (override propagation)"
                )

    # ── resolution -> declaration, inside one root ───────────────────────
    for node_root in data.node_roots:
        for key, spec in sorted(node_root.overrides.items()):
            parent, package, selector = parse_override_key(key)
            if parent:
                continue
            for version in sorted(set(_governed(node_root.resolved.get(package, []), selector))):
                if satisfies_npm_range(version, spec) is False:
                    problems.append(
                        f"{node_root.manifest} overrides `{key}` to `{spec}` but {node_root.lockfile} "
                        f"resolves {package}@{version}, which does not satisfy it — the lockfile was "
                        f"not regenerated after the manifest moved, so `{node_root.tool} install "
                        f"--frozen-lockfile` installs a version the manifest forbids "
                        f"(override propagation)"
                    )

    # ── exemption <-> tree ───────────────────────────────────────────────
    for (package, directory), (versions, _) in sorted(CROSS_ROOT_OVERRIDE_EXEMPT.items()):
        # Named apart from the `node_root` the loops above bind: this one is
        # a lookup that can miss, and reusing the name would narrow an
        # optional into a type the earlier loops guaranteed.
        exempt_root = by_dir.get(directory)
        if exempt_root is None:
            # Only reported when the directory is *there* and has stopped
            # resolving its own node_modules. An exemption for a directory
            # that does not exist in this tree at all is a fixture or a fork,
            # not drift — the same distinction `check_pnpm_actions` draws by
            # testing its exemptions against the files the scan actually saw.
            if (root / directory).is_dir():
                problems.append(
                    f"CROSS_ROOT_OVERRIDE_EXEMPT names `{directory}`, which is no longer an install "
                    f"root — it has no lockfile of its own, so the exemption asserts a constraint "
                    f"nothing is under (override propagation)"
                )
            continue
        got = set(exempt_root.resolved.get(package, []))
        if not got:
            problems.append(
                f"CROSS_ROOT_OVERRIDE_EXEMPT exempts `{package}` in `{directory}`, which no longer "
                f"resolves it — the exemption asserts a constraint nothing is under (override propagation)"
            )
        elif stale := sorted(set(versions) - got):
            problems.append(
                f"CROSS_ROOT_OVERRIDE_EXEMPT was verified against `{package}@{', '.join(stale)}` in "
                f"`{directory}`, which now resolves {', '.join(sorted(got))}. The exemption records "
                f"exact versions on purpose so a bump re-opens the question — re-verify the resolved "
                f"version against OSV and update it (override propagation)"
            )
    return problems


def check_node_root_corpus(data: Scan) -> list[str]:
    """Refuse to render a verdict over install roots that were never read.

    Every check above answers "do these roots agree", and a root whose
    lockfile yielded nothing agrees with everyone. That is the shape this
    repository keeps finding: *found nothing* and *scanned nothing* print the
    same word. So a discovered root that parsed to zero resolutions, or a
    tree with no install root at all, is a failure of the gate rather than a
    pass for the tree — which is also what keeps this check from reporting OK
    on an empty corpus.
    """
    if not data.node_roots:
        return [
            "no Node install root was discovered (a directory holding both package.json and a "
            "lockfile). Either the tree has none, or the discovery walk is looking in the wrong "
            "place — both mean the cross-root comparison below ran over nothing (node root corpus)"
        ]
    return [
        f"{node_root.lockfile} parsed to zero resolved packages, so every comparison against it "
        f"passes by default. A {node_root.tool} lockfile this gate cannot read is not a clean "
        f"root, it is an unread one (node root corpus)"
        for node_root in data.node_roots
        if not node_root.resolved
    ]


def check_override_parser_coverage(root: Path, data: Scan) -> list[str]:
    """A manifest whose override block this parser could not see.

    The other direction of discovery. `check_node_root_corpus` asks whether
    the lockfiles were read; this asks whether the *manifests* were, because
    a root counted and compared while contributing no override is
    indistinguishable from one that genuinely pins nothing.
    """
    problems: list[str] = []
    declares = re.compile(r'"(?:pnpm|overrides)"\s*:')
    for node_root in data.node_roots:
        path = root / node_root.manifest
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        if declares.search(text) and not node_root.overrides:
            problems.append(
                f"{node_root.manifest} declares an override block but the parser extracted nothing "
                f"from it — the root is counted as compared while contributing no pin "
                f"(override parser coverage)"
            )
    return problems


def check_esbuild_overrides(root: Path, data: Scan) -> list[str]:
    """esbuild must stay overridden per parent, and the resolved set must be pinned.

    Forcing esbuild across the workspace broke Turbopack's font import map,
    because Next bundles its own copy and the override replaced it. The
    overrides are therefore scoped (`vite>esbuild`) — but that scoping means a
    `vite` bump can pull a different esbuild with no esbuild line in the diff,
    so the resolved versions are compared too.

    The scoping half is checked against *every* install root. It used to read
    the repository root's manifest alone, which left the one place a
    workspace-wide esbuild override could be added without anything noticing:
    `apps/mobile` installs separately and is the root whose bundler is not
    Turbopack, so the mistake would look locally harmless there and reach the
    web build through nothing but a future reviewer's memory.
    """
    problems: list[str] = []
    for node_root in data.node_roots:
        for key in sorted(node_root.overrides):
            if key == "esbuild" or key.startswith("esbuild@"):
                problems.append(
                    f"{node_root.manifest} overrides `{key}` workspace-wide. Next bundles its own "
                    f"esbuild and a workspace-wide override replaces it, which breaks Turbopack's "
                    f"font import map — scope it to its parent as `<parent>>esbuild` (override scope)"
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
        problems.append(f"PNPM_ACTION_VERSION is {PNPM_ACTION_VERSION} but no workflow uses it — the declared version is stale")
    # An exemption for a workflow that no longer sets up pnpm is a comment
    # asserting a constraint nothing is under. Only checked against files the
    # scan actually saw, so an exemption for a workflow outside this tree
    # (a fixture, a fork) does not fail the run.
    for path in sorted(PNPM_ACTION_EXEMPT):
        if path in data.files and path not in seen:
            problems.append(
                f"PNPM_ACTION_EXEMPT names {path}, which no longer sets up pnpm — remove the exemption rather than leaving it to rot"
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
        targets = sorted({p.version for p in pins if p.role == "target" and p.version})
        print(
            f"  {runtime}: {len(pins)} declarations across {len({p.path for p in pins})} files"
            f" — toolchain {', '.join(toolchains) or 'none'}"
            + (f", floors {', '.join(floors)}" if floors else "")
            + (f", static-tool target {', '.join(targets)}" if targets else "")
        )

    locked = sum(1 for i in data.installs if i.locked)
    print(f"  node installs: {len(data.installs)} ({locked} locked, {len(data.installs) - locked} unlocked)")
    # Named, not counted. "4 install roots compared" is true whether the
    # fourth was read or silently parsed to nothing, and a root that resolved
    # zero packages agrees with every other root about everything.
    print(f"  node install roots: {len(data.node_roots)} — each with what was actually read from it")
    for node_root in data.node_roots:
        print(
            f"      {(node_root.directory or '.'):<30} {node_root.tool:<5} "
            f"{len(node_root.resolved):>5} packages resolved, "
            f"{len(node_root.overrides)} override(s) from {node_root.overrides_key or 'none declared'}"
        )
    modules = sorted(d for d, e in data.go_modules.items() if e.get("mod"))
    print(f"  go modules: {len(modules)} — {', '.join(modules)}")
    scopes = ", ".join(f"{w.split('/')[-1]}{f' [{s}]' if s else ' [repo-wide]'}" for w, s, _, _ in data.gofmt_steps) or "none"
    print(f"  gofmt steps: {len(data.gofmt_steps)} — {scopes}")
    # Printed with the line that proves it, not as a tally. A count says
    # "13 covered" whether the evidence is `working-directory: services/api`
    # or a quoted path in an unrelated shell array, and this check recorded
    # the second kind until someone read the list.
    print(f"  published images: {len(data.published)} — each with the CI step that exercises it")
    for service, (context, dockerfile) in sorted(data.published.items()):
        target = context if context != "." else str(Path(dockerfile).parent)
        evidence = data.ci_dirs.get(target)
        detail = f"{evidence[0].split('/')[-1]}: {evidence[1]}" if evidence else "NOTHING"
        print(f"      {service:<12} {target:<20} {detail}")


def run(root: Path, verbose: bool = False) -> tuple[int, list[str]]:
    if not (root / ".github" / "workflows").is_dir() or not (root / "services").is_dir():
        return 1, [f"{root} does not look like the AiSOC repository (no .github/workflows and services/). Pass --repo-root explicitly."]

    data = scan(root)
    if not data.pins and not data.installs:
        return 1, [f"scanned {len(data.files)} file(s) under {root} and found no runtime declaration at all"]

    problems = (
        check_runtime_agreement(data)
        + check_ship_test_parity(data)
        + check_floors(data)
        + check_python_tooling_target(data)
        + check_locked_installs(data)
        + check_dead_lockfiles(root, data)
        + check_image_copies_lockfile(root, data)
        + check_go_modules(root, data)
        + check_go_formatting(data)
        + check_published_service_ci(root, data)
        + check_esbuild_overrides(root, data)
        + check_pnpm_actions(data)
        + check_node_root_corpus(data)
        + check_override_propagation(root, data)
        + check_override_parser_coverage(root, data)
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
    (root / "services" / "py-svc").mkdir(parents=True)

    (root / "package.json").write_text(
        json.dumps(
            {
                "name": "fixture",
                "private": True,
                "packageManager": "pnpm@8.15.1",
                "engines": {"node": ">=22.0.0"},
                "pnpm": {"overrides": {"vite>esbuild": "^0.28.1", "image-size": ">=2.0.4 <3"}},
            }
        ),
        encoding="utf-8",
    )
    (root / "pnpm-lock.yaml").write_text(
        "lockfileVersion: '6.0'\n  /esbuild@0.28.1:\n  /esbuild@0.25.12:\n  /image-size@2.0.4:\n", encoding="utf-8"
    )

    # A second install root, shaped like `apps/mobile`: its own manifest and
    # its own lockfile, outside the workspace the root one describes. The
    # cross-root checks have nothing to compare without it, and a fixture with
    # one root is how a gate for two roots passes its own self-test while
    # exercising neither direction.
    satellite = root / "apps" / "satellite"
    satellite.mkdir(parents=True)
    (satellite / "package.json").write_text(
        json.dumps({"name": "satellite", "private": True, "pnpm": {"overrides": {"image-size": ">=2.0.4 <3"}}}),
        encoding="utf-8",
    )
    (satellite / "pnpm-lock.yaml").write_text("lockfileVersion: '6.0'\n  /image-size@2.0.4:\n", encoding="utf-8")
    (root / "pnpm-workspace.yaml").write_text('packages:\n  - "apps/*"\n  - "!apps/satellite"\n', encoding="utf-8")

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

    (root / "services" / "py-svc" / "Dockerfile").write_text("FROM python:3.11-slim\nCOPY . /app\n", encoding="utf-8")
    (root / "services" / "py-svc" / "pyproject.toml").write_text(
        '[tool.poetry.dependencies]\npython = "^3.11"\n\n[tool.mypy]\npython_version = "3.11"\n', encoding="utf-8"
    )
    (root / "ruff.toml").write_text('target-version = "py311"\n', encoding="utf-8")

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
        "      - run: |\n          cd services/web-svc\n          npm test\n"
        "  go:\n    steps:\n"
        "      - uses: actions/setup-go@ccc # v7\n"
        "        with:\n          go-version: '1.26'\n"
        "          cache-dependency-path: services/go-svc/go.sum\n"
        "      - run: |\n          cd services/go-svc\n          go build ./...\n"
        # A second `service:` matrix in the same file, written as a block
        # list: the shape a file-wide matrix reader resolves into the job
        # above. Keeping it in the clean fixture means removing job scoping
        # breaks `clean fixture passes`, not merely one injected case.
        "  py:\n    strategy:\n      matrix:\n        service:\n          - py-svc\n    steps:\n"
        "      - uses: actions/setup-python@ddd # v7\n"
        "        with:\n          python-version: '3.11'\n"
        "      - run: |\n          cd services/${{ matrix.service }}\n          pytest\n"
        "  gofmt:\n    steps:\n"
        "      - name: gofmt -l every file\n"
        "        run: |\n"
        "          out=$(gofmt -l .)\n"
        '          if [ -n "$out" ]; then echo "$out"; exit 1; fi\n',
        encoding="utf-8",
    )
    (root / ".github" / "workflows" / "publish-images.yml").write_text(
        "name: Publish\njobs:\n  publish:\n    strategy:\n      matrix:\n        include:\n"
        "          - service: go-svc\n            context: services/go-svc\n            dockerfile: Dockerfile\n"
        "          - service: py-svc\n            context: services/py-svc\n            dockerfile: Dockerfile\n"
        "          - service: web-svc\n            context: services/web-svc\n            dockerfile: Dockerfile\n"
        "    steps:\n      - run: docker build .\n",
        encoding="utf-8",
    )


def self_test() -> int:
    import shutil
    import tempfile

    def build(mutate=None) -> tuple[int, list[str]]:
        temp = Path(tempfile.mkdtemp(prefix="toolchain_selftest_"))
        # Two injections below add an entry to the module-level exemption
        # list, which is how an exemption is drifted. Restoring it per case
        # keeps one case from deciding the verdict of the next — a self-test
        # whose cases leak into each other proves the wrong thing.
        saved = dict(CROSS_ROOT_OVERRIDE_EXEMPT)
        try:
            _fixture(temp)
            if mutate:
                mutate(temp)
            return run(temp)
        finally:
            CROSS_ROOT_OVERRIDE_EXEMPT.clear()
            CROSS_ROOT_OVERRIDE_EXEMPT.update(saved)
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

    def drift_python_ci_ahead_of_images(root: Path) -> None:
        """The measured bug this change closes: CI on 3.12, images on 3.11.

        Python used to be excused from strict equality here because the
        manifests declare a floor that permits both. Twenty-four workflows
        drifted under that exemption.
        """
        path = root / ".github" / "workflows" / "ci.yml"
        path.write_text(path.read_text().replace("python-version: '3.11'", "python-version: '3.12'"), encoding="utf-8")

    def drift_python_image_ahead_of_ci(root: Path) -> None:
        """The other direction: the image moves and CI is forgotten."""
        path = root / "services" / "py-svc" / "Dockerfile"
        path.write_text(path.read_text().replace("python:3.11", "python:3.13"), encoding="utf-8")

    def drift_ruff_target(root: Path) -> None:
        """A static-tool target left behind — ruff linting for another Python."""
        (root / "ruff.toml").write_text('target-version = "py312"\n', encoding="utf-8")

    def drift_mypy_target(root: Path) -> None:
        path = root / "services" / "py-svc" / "pyproject.toml"
        path.write_text(path.read_text().replace('python_version = "3.11"', 'python_version = "3.10"'), encoding="utf-8")

    def drift_mypy_without_a_target(root: Path) -> None:
        """A tree asking to be type-checked without saying against which Python."""
        path = root / "services" / "py-svc" / "pyproject.toml"
        path.write_text(path.read_text().replace('python_version = "3.11"', "strict = true"), encoding="utf-8")

    def drift_no_gofmt_at_all(root: Path) -> None:
        """The measured bug: `go vet` and `go build`, and no formatting check."""
        path = root / ".github" / "workflows" / "ci.yml"
        text = path.read_text()
        path.write_text(text[: text.index("  gofmt:\n")], encoding="utf-8")

    def drift_gofmt_scoped_off_the_modules(root: Path) -> None:
        """A formatting step that runs, passes, and covers no module."""
        path = root / ".github" / "workflows" / "ci.yml"
        path.write_text(path.read_text().replace("out=$(gofmt -l .)", "cd services/web-svc\n          out=$(gofmt -l .)"), encoding="utf-8")

    def drift_gofmt_that_cannot_fail(root: Path) -> None:
        """`gofmt -l` prints the offenders and exits 0 — a step with no verdict."""
        path = root / ".github" / "workflows" / "ci.yml"
        text = path.read_text()
        path.write_text(
            text[: text.index("  gofmt:\n")] + "  gofmt:\n    steps:\n      - run: gofmt -l .\n",
            encoding="utf-8",
        )

    def drift_published_service_without_ci(root: Path) -> None:
        """The measured `services/realtime` shape: an image nothing builds."""
        (root / "services" / "orphan-svc").mkdir()
        (root / "services" / "orphan-svc" / "Dockerfile").write_text("FROM python:3.11-slim\n", encoding="utf-8")
        path = root / ".github" / "workflows" / "publish-images.yml"
        path.write_text(
            path.read_text().replace(
                "    steps:\n",
                "          - service: orphan-svc\n            context: services/orphan-svc\n"
                "            dockerfile: Dockerfile\n    steps:\n",
            ),
            encoding="utf-8",
        )

    def drift_coverage_claimed_by_a_quoted_path(root: Path) -> None:
        """A published service whose only mention is a path inside a shell array.

        Measured: `compose-smoke.yml` holds a list of build-context paths to
        decide whether a GHCR image is stale, `'services/realtime/'` among
        them. The first version of this check read that list as evidence
        that CI exercised eleven services, so the very defect it was written
        to find reported OK. If `_strip_quoted` or `_COMMAND_VERB` is ever
        dropped, this case fails.
        """
        (root / "services" / "orphan-svc").mkdir()
        (root / "services" / "orphan-svc" / "Dockerfile").write_text("FROM python:3.11-slim\n", encoding="utf-8")
        publish = root / ".github" / "workflows" / "publish-images.yml"
        publish.write_text(
            publish.read_text().replace(
                "    steps:\n",
                "          - service: orphan-svc\n            context: services/orphan-svc\n"
                "            dockerfile: Dockerfile\n    steps:\n",
            ),
            encoding="utf-8",
        )
        ci = root / ".github" / "workflows" / "ci.yml"
        ci.write_text(
            ci.read_text() + "  stale:\n    steps:\n      - run: |\n"
            "          contexts=(\n            'services/orphan-svc/'\n          )\n"
            '          echo "${contexts[@]}"\n',
            encoding="utf-8",
        )

    def drift_matrix_working_directory(root: Path) -> None:
        """A service exercised only through `working-directory: .../${{ matrix.x }}`.

        `\\S+` stops at the space inside the expansion, so the directory
        resolved to `services/${{` and eight real services looked untested.
        Putting the surviving service behind that syntax means a regression
        in the pattern shows up as a false *failure* here.
        """
        ci = root / ".github" / "workflows" / "ci.yml"
        ci.write_text(
            ci.read_text().replace(
                "      - run: |\n          cd services/${{ matrix.service }}\n          pytest\n",
                "      - working-directory: services/${{ matrix.service }}\n        run: pytest\n",
            ),
            encoding="utf-8",
        )

    def drift_publish_context_that_moved(root: Path) -> None:
        """The reverse: a publish entry for a directory that is not there."""
        path = root / ".github" / "workflows" / "publish-images.yml"
        path.write_text(path.read_text().replace("context: services/py-svc", "context: services/renamed-svc"), encoding="utf-8")

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

    # ── The cross-root install-root directions ───────────────────────────
    #
    # Written by enumerating what the check *credits* rather than what it
    # flags. It credits a root as agreeing when the root declares the same
    # override, when the version it resolved satisfies the other root's pin,
    # or when the package is absent from it — and each of those three is also
    # what a root looks like when the parser could not read its lockfile, its
    # manifest, or the range being compared. Those are the last four cases
    # here, and they are the ones that would have let this check pass while
    # comparing nothing.

    def drift_override_reaching_one_root(root: Path) -> None:
        """The measured bug: the workspace pins image-size, apps/mobile does not."""
        path = root / "apps" / "satellite" / "package.json"
        path.write_text(json.dumps({"name": "satellite", "private": True}), encoding="utf-8")
        (root / "apps" / "satellite" / "pnpm-lock.yaml").write_text("lockfileVersion: '6.0'\n  /image-size@1.2.1:\n", encoding="utf-8")

    def drift_lockfile_behind_its_own_manifest(root: Path) -> None:
        """The same disagreement inside one root: the manifest moved, the lock did not."""
        (root / "apps" / "satellite" / "pnpm-lock.yaml").write_text("lockfileVersion: '6.0'\n  /image-size@1.2.1:\n", encoding="utf-8")

    def drift_workspace_wide_esbuild_in_a_satellite_root(root: Path) -> None:
        """The esbuild trap in the one root the old check could not see."""
        path = root / "apps" / "satellite" / "package.json"
        data = json.loads(path.read_text())
        data["pnpm"]["overrides"]["esbuild"] = "^0.28.1"
        path.write_text(json.dumps(data), encoding="utf-8")

    def drift_exemption_for_a_root_that_stopped_being_one(root: Path) -> None:
        """A directory still in the tree that no longer resolves its own node_modules.

        Deliberately not a directory that is simply absent: an exemption for
        a path this tree never had is a fixture or a fork, and failing on
        that would make the gate unusable anywhere but here.
        """
        (root / "apps" / "folded-in").mkdir(parents=True)
        (root / "apps" / "folded-in" / "package.json").write_text(json.dumps({"name": "folded-in"}), encoding="utf-8")
        CROSS_ROOT_OVERRIDE_EXEMPT[("image-size", "apps/folded-in")] = (("1.2.1",), "a root folded back into the workspace")

    def drift_exemption_whose_version_moved(root: Path) -> None:
        CROSS_ROOT_OVERRIDE_EXEMPT[("image-size", "apps/satellite")] = (("1.2.1",), "verified against a version since bumped")

    def drift_unreadable_lockfile(root: Path) -> None:
        """A lockfile in a format the parser does not understand.

        It yields no resolutions, so every cross-root comparison against it
        passes — the exact shape of a gate reporting OK about a root it never
        read. `check_node_root_corpus` must call this a failure of the gate.
        """
        (root / "apps" / "satellite" / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\nsnapshots: {}\n", encoding="utf-8")

    def drift_override_block_the_parser_cannot_read(root: Path) -> None:
        """A manifest that declares overrides under a key this parser misses."""
        path = root / "apps" / "satellite" / "package.json"
        path.write_text(
            json.dumps({"name": "satellite", "private": True, "pnpm": {"override": {"image-size": ">=2.0.4 <3"}}}),
            encoding="utf-8",
        )

    def drift_range_the_comparison_cannot_evaluate(root: Path) -> None:
        """A spec `satisfies_npm_range` has no answer for.

        A boolean here would be invented. Passing is the dangerous half: the
        gate would print OK having compared nothing.
        """
        path = root / "package.json"
        data = json.loads(path.read_text())
        data["pnpm"]["overrides"]["image-size"] = "1.x || >=2.0.4"
        path.write_text(json.dumps(data), encoding="utf-8")
        (root / "apps" / "satellite" / "pnpm-lock.yaml").write_text("lockfileVersion: '6.0'\n  /image-size@1.2.1:\n", encoding="utf-8")

    def drift_no_install_root_at_all(root: Path) -> None:
        (root / "pnpm-lock.yaml").unlink()
        (root / "apps" / "satellite" / "pnpm-lock.yaml").unlink()

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
        ("python: CI ahead of the images", drift_python_ci_ahead_of_images, "`python` is pinned 2 different ways"),
        ("python: image ahead of CI", drift_python_image_ahead_of_ci, "`python` is pinned 2 different ways"),
        ("ruff targets another interpreter", drift_ruff_target, "target -> ship"),
        ("mypy targets another interpreter", drift_mypy_target, "target -> ship"),
        ("mypy declared with no target at all", drift_mypy_without_a_target, "no `python_version`"),
        ("no gofmt anywhere", drift_no_gofmt_at_all, "module -> format"),
        ("gofmt scoped off the modules", drift_gofmt_scoped_off_the_modules, "format -> module"),
        ("gofmt -l that cannot fail", drift_gofmt_that_cannot_fail, "can only ever pass"),
        ("published image with no CI job", drift_published_service_without_ci, "image -> CI"),
        ("coverage claimed by a quoted path in a list", drift_coverage_claimed_by_a_quoted_path, "image -> CI"),
        ("coverage through a matrix working-directory", drift_matrix_working_directory, None),
        ("publish entry for a directory that moved", drift_publish_context_that_moved, "CI -> image"),
        ("override reaching one install root and not the other", drift_override_reaching_one_root, "override propagation"),
        ("lockfile behind its own manifest", drift_lockfile_behind_its_own_manifest, "override propagation"),
        ("workspace-wide esbuild in a satellite root", drift_workspace_wide_esbuild_in_a_satellite_root, "override scope"),
        ("exemption for a root that stopped being one", drift_exemption_for_a_root_that_stopped_being_one, "no longer an install root"),
        ("exemption whose verified version moved", drift_exemption_whose_version_moved, "re-opens the question"),
        ("lockfile the parser cannot read", drift_unreadable_lockfile, "node root corpus"),
        ("override block the parser cannot read", drift_override_block_the_parser_cannot_read, "override parser coverage"),
        ("range the comparison cannot evaluate", drift_range_the_comparison_cannot_evaluate, "cannot evaluate"),
        ("no install root at all", drift_no_install_root_at_all, "no Node install root"),
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

    return run((args.repo_root or git_root()).resolve(), verbose=args.verbose)[0]


if __name__ == "__main__":
    sys.exit(main())
