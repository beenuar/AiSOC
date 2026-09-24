#!/usr/bin/env python3
"""Assert every install path for a package agrees with every other install path.

The failure this exists to prevent is "the same commit does not build the same
way twice". A service is installed from more than one place — its
``pyproject.toml``, its ``Dockerfile``, a ``poetry.lock``, and whichever CI
workflows pip-install its dependencies to run a test — and nothing compared
them. When they disagree, the thing CI tested and the thing the image ships are
different software, and the difference surfaces as a failure pointing at an
innocent file.

Two measured instances, both of which this gate now catches:

* ``sqlglot`` enforces tenant isolation on the ClickHouse lake. It was declared
  ``<31`` in ``services/api/pyproject.toml`` and ``<27`` in the Dockerfile and
  five workflows. sqlglot 27 renamed the SELECT's FROM key, so on the versions
  only pyproject allowed the rewriter returned queries with no tenant
  predicate — and reported success. CI installed the narrow range, so it could
  never see it.
* ``fastapi`` was declared ``>=0.111,<0.142`` in ``services/api/pyproject.toml``
  and ``>=0.111,<0.112`` in the Dockerfile's pip fallback, with no bound at all
  in six workflows. Every release from 0.111.0 to 0.116.2 refuses to import
  ``api/v1/endpoints/community.py``; on 2026-09-24 the fallback fired and the
  image shipped 0.111.1.

So the property enforced here is *agreement*, not any particular bound. Moving
a range is fine; moving it in one place is not.

Directions. The dominant failure shape in this repository is a one-directional
gate that compares A against B and never B against A, so drift in the direction
things actually change slips through while the gate prints OK. Every comparison
below therefore runs both ways, and ``--self-test`` injects drift in each
direction separately and asserts this file reports it:

  manifest -> image   a package the manifest declares must not be installed
                      at a different version by the image
  image -> manifest   a package the image installs must be declared by the
                      manifest (the direction the old fallback lists drifted)
  agreement           for a critical package, every range written anywhere
                      must normalise to the same range
  lock -> agreement   the version a lock actually resolved must satisfy that
                      range, so the file that decides what ships is compared
                      too rather than trusted
  unbounded           a path naming a critical package with no version bound
                      permits every version, including the broken ones
  coverage            a file that declares a critical package and is not in
                      the scanned set fails, so adding an install path without
                      telling this gate is itself an error

Usage:
    python scripts/check_dependency_pins.py [--repo-root PATH] [--verbose]
    python scripts/check_dependency_pins.py --self-test
"""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

# ── Which packages must agree repo-wide ──────────────────────────────────────
#
# Not every dependency belongs here. Two services may legitimately ship
# different httpx minors: they are separate images and nothing crosses between
# them. A package earns a row only when a version difference is a correctness
# or a security difference, and the reason is recorded so a future reader can
# challenge it rather than inherit it.
CRITICAL: dict[str, str] = {
    "fastapi": (
        "below 0.117 a `-> None` handler under PEP 563 trips FastAPI's "
        "'204 must not have a response body' assert, so the service cannot be "
        "imported at all — measured across every release from 0.111.0"
    ),
    "sqlglot": (
        "parses untrusted operator SQL for the lake tenant-isolation rewriter; "
        "27 renamed the FROM argument key and silently dropped the tenant "
        "predicate, the table allowlist and the table-function ban"
    ),
    "cryptography": (
        "two contracts, not one library preference: the Fernet / MultiFernet "
        "token format shared by the service that writes vault tokens (api) and "
        "the ones that read them (connectors, agents, osquery-tls) under a "
        "single credential key, and the Ed25519 plugin signatures that "
        "packages/aisoc-cli produces and services/api verifies"
    ),
    "pyjwt": (
        "the only JWT implementation in the tree — it verifies first-party "
        "access and refresh tokens, realtime tickets and OIDC/SAML assertions"
    ),
    "ruff": (
        "`ruff format --check services/` is a hard gate and the formatter's "
        "output changes between minors, so two ruff versions are two different "
        "answers to whether this tree is formatted. A contributor whose "
        "manifest permits a newer ruff than CI installs reformats the tree and "
        "reds their own PR with no dependency change in the diff"
    ),
    "poetry": (
        "the resolver that turns a manifest into an installed version set. "
        "Two resolvers are two answers to 'what does this commit install', "
        "and the security audit exports with one while the images install "
        "with another"
    ),
}

# Installed to *perform* a build rather than to run the service, so they are
# exempt from the "the manifest must declare it" direction. They are still
# compared against each other: `poetry` is in CRITICAL above precisely because
# the Dockerfiles disagreed (1.7.1 vs 1.8.2) while two workflows installed it
# unbounded.
BUILD_TOOLING = {"poetry", "poetry-plugin-export", "pip", "setuptools", "wheel", "uv", "build", "hatchling"}

# Prose, vendored history and generated artefacts. `docs/` and `apps/docs/`
# describe pins in sentences; `plans/` is an archived prototype subtree.
SKIP_PREFIXES = (
    "plans/",
    "apps/docs/",
    "docs/",
    "node_modules/",
    ".git/",
    "scripts/check_dependency_pins.py",
    "scripts/check_sqlglot_pin.py",
    "tests/test_dependency_pin_gate.py",
    # The suppression list is a record of advisories and the versions that
    # resolved them. It names packages in prose; it installs nothing.
    "scripts/security_audit_ignores.txt",
)

# Two workflows install several versions of one package on purpose, so they
# cannot declare a single pin. An exemption that stopped there would be a hole,
# so each is checked differently instead of being ignored:
#
#   lake-isolation.yml  runs the lake rewriter against two sqlglot majors,
#                       including one outside the shipped range, so a future
#                       bump cannot silently turn isolation off.
#                       `scripts/check_sqlglot_pin.py` asserts its `shipped`
#                       leg equals the agreed pin.
#   reproducible-builds.yml
#                       imports the API on both ends of the fastapi range, so
#                       the bound is tested rather than assumed.
#                       `check_matrix_brackets` below asserts its legs sit on
#                       the boundaries the manifests actually declare.
MATRIX_EXEMPT = (
    ".github/workflows/lake-isolation.yml",
    ".github/workflows/reproducible-builds.yml",
)


def canonical(name: str) -> str:
    """PEP 503 name normalisation: `PyJWT`, `py-jwt` and `py_jwt` are one name."""
    return re.sub(r"[-_.]+", "-", name).strip().lower()


def normalise(spec: str) -> str:
    """Reduce a specifier to a comparable form.

    `>=46.0.0,<51.0.0` and `>=46,<51` are one constraint written two ways, and
    failing a build over trailing zeros teaches people to silence the gate
    rather than read it. Clause order is not meaningful either.
    """
    parts: list[str] = []
    for clause in spec.replace(" ", "").split(","):
        if not clause:
            continue
        match = re.fullmatch(r"(?P<op>[<>=!~^]+)(?P<ver>[0-9][0-9.*]*)", clause)
        if not match:
            parts.append(clause)
            continue
        version = match.group("ver").rstrip(".")
        while version.endswith(".0"):
            version = version[: -len(".0")]
        parts.append(f"{match.group('op')}{version}")
    return ",".join(sorted(parts))


def version_tuple(version: str) -> tuple[int, ...]:
    """Numeric release segment of a version, for range membership only.

    Pre-release and local segments are dropped deliberately: this answers
    "is the locked version inside the declared range", not "which of these two
    releases is newer", and no pin in this tree is written against a
    pre-release.
    """
    digits = re.match(r"(\d+(?:\.\d+)*)", version)
    return tuple(int(p) for p in digits.group(1).split(".")) if digits else (0,)


def _pad(left: tuple[int, ...], right: tuple[int, ...]) -> tuple[tuple[int, ...], tuple[int, ...]]:
    width = max(len(left), len(right))
    return left + (0,) * (width - len(left)), right + (0,) * (width - len(right))


def same_version(left: str, right: str) -> bool:
    """`0.117` and `0.117.0` are the same release written two ways."""
    a, b = _pad(version_tuple(left), version_tuple(right))
    return a == b


def satisfies(version: str, spec: str) -> bool:
    """Whether a concrete version falls inside a comma-joined specifier."""
    actual = version_tuple(version)
    for clause in spec.replace(" ", "").split(","):
        if not clause:
            continue
        match = re.fullmatch(r"(?P<op>[<>=!]+)(?P<ver>[0-9][0-9.]*)", clause)
        if not match:
            return False  # an operator this gate cannot reason about is not a pass
        bound = version_tuple(match.group("ver"))
        left, right = _pad(actual, bound)
        operator = match.group("op")
        ok = {
            ">=": left >= right,
            ">": left > right,
            "<=": left <= right,
            "<": left < right,
            "==": left == right,
            "!=": left != right,
        }.get(operator)
        if ok is None or not ok:
            return False
    return True


@dataclass
class Declaration:
    """One package requirement, and the exact place it was written."""

    package: str
    spec: str  # "" means the path named the package with no version bound
    path: str
    kind: str  # manifest | image | ci | lock
    service: str | None
    raw: str


@dataclass
class Scan:
    declarations: list[Declaration] = field(default_factory=list)
    files: list[str] = field(default_factory=list)

    def by_package(self, package: str) -> list[Declaration]:
        return [d for d in self.declarations if d.package == package]


# ── Parsing each kind of install path ────────────────────────────────────────

_REQUIREMENT = re.compile(
    r"""^["']?(?P<name>[A-Za-z][A-Za-z0-9._-]*)(?P<extras>\[[^\]]*\])?(?P<spec>[<>=!~][^"'\s]*)?["']?$"""
)

# Shell words that appear inside a `pip install` line and are not packages.
_NOT_PACKAGES = {
    "pip", "python", "python3", "-m", "set", "eux", "-e", "echo", "if", "then",
    "else", "fi", "true", "&&", "||", ";", ".", "install", "poetry",
}


def _fold_yaml_run_blocks(text: str) -> str:
    """Join `run: >-` folded scalars into the single command they become.

    GitHub Actions runs a folded block as one shell line, so

        run: >-
          pip install --quiet
          "fastapi>=0.117,<0.142" "pydantic[email]"

    is one `pip install` invocation. A line-by-line reader sees only the first
    line, finds `pip install` with no packages after it, and extracts nothing —
    while still counting the file as scanned. `integration.yml` installs the
    whole API dependency set this way, and it was invisible to the first
    version of this gate for exactly that reason. `check_parser_coverage`
    below is the backstop that makes a repeat of this a failure rather than a
    quiet gap.

    `run: |` (literal) blocks are left alone: there each line is its own
    command, which the per-line reader already handles correctly.
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


def _pip_install_tokens(text: str) -> list[tuple[str, str]]:
    """Every package token on a `pip install` command, with its source line.

    Comment lines are dropped *before* shell continuations are folded. Folding
    first would splice a paragraph of prose onto the command below it, and the
    comments in this repository discuss `pip install` at length — the first
    version of this function reported that a Dockerfile installed packages
    named `that`, `was` and `a`.

    Collection also stops at the first `&&`, `||` or `;`, because everything
    after one is a different command. `RUN pip install poetry && poetry config
    virtualenvs.create false` does not install a package called `false`.
    """
    stripped = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    stripped = _fold_yaml_run_blocks(stripped)
    joined = re.sub(r"\\\s*\n", " ", stripped)  # fold shell line continuations
    out: list[tuple[str, str]] = []
    for line in joined.splitlines():
        if "pip install" not in line:
            continue
        tail = re.sub(r"#.*", "", line.split("pip install", 1)[1])
        tail = re.split(r"&&|\|\||;", tail, maxsplit=1)[0]
        for token in tail.split():
            token = token.strip()
            if not token or token.startswith("-") or token in _NOT_PACKAGES:
                continue
            out.append((token, line.strip()))
    return out


def _folded_dep_blocks(text: str) -> list[tuple[str, str]]:
    """Package tokens from `SOMETHING_DEPS: >-` folded YAML env blocks.

    These are pip arguments that reach pip through `${{ env.API_DEPS }}`, so
    they are install paths even though no `pip install` appears on their lines.
    """
    out: list[tuple[str, str]] = []
    lines = text.splitlines()
    for index, line in enumerate(lines):
        header = re.match(r"^(\s*)([A-Z0-9_]*DEPS):\s*>-\s*$", line)
        if not header:
            continue
        indent = len(header.group(1))
        for body in lines[index + 1 :]:
            if body.strip() and (len(body) - len(body.lstrip())) <= indent:
                break
            for token in body.split():
                token = token.strip()
                if not token or token.startswith("-") or token in _NOT_PACKAGES:
                    continue
                out.append((token, body.strip()))
    return out


def _requirement(token: str) -> tuple[str, str] | None:
    match = _REQUIREMENT.match(token)
    if not match:
        return None
    return canonical(match.group("name")), (match.group("spec") or "").strip(",")


def parse_manifest(path: Path, rel: str, service: str | None) -> list[Declaration]:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    found: list[Declaration] = []

    # Runtime *and* dev/optional groups. `ruff` lives only in dev groups, and
    # `ruff format --check` is a hard gate, so a parser that read runtime
    # dependencies alone would have reported agreement about a package it
    # never looked at. `check_parser_coverage` is what caught that here.
    poetry = data.get("tool", {}).get("poetry", {})
    groups: list[dict] = [poetry.get("dependencies", {})]
    groups += [g.get("dependencies", {}) for g in poetry.get("group", {}).values()]
    for deps in groups:
        for name, spec in deps.items():
            if name == "python":
                continue
            if isinstance(spec, dict):
                spec = spec.get("version", "")
            if not isinstance(spec, str):
                continue
            found.append(Declaration(canonical(name), spec.strip(), rel, "manifest", service, f"{name} = {spec!r}"))

    project = data.get("project", {})
    requirements = list(project.get("dependencies", []) or [])
    for extra in (project.get("optional-dependencies", {}) or {}).values():
        requirements += list(extra)
    for requirement in requirements:
        parsed = _requirement(requirement.strip())
        if parsed:
            found.append(Declaration(parsed[0], parsed[1], rel, "manifest", service, requirement))
    return found


def parse_lock(path: Path, rel: str, service: str | None) -> list[Declaration]:
    """Resolved versions out of a poetry.lock, as `==` declarations."""
    found: list[Declaration] = []
    for name, version in re.findall(
        r'^name = "([^"]+)"\nversion = "([^"]+)"', path.read_text(encoding="utf-8"), re.MULTILINE
    ):
        found.append(Declaration(canonical(name), f"=={version}", rel, "lock", service, f"{name} {version}"))
    return found


def parse_shell(path: Path, rel: str, kind: str, service: str | None) -> list[Declaration]:
    text = path.read_text(encoding="utf-8")
    tokens = _pip_install_tokens(text)
    if kind == "ci":
        tokens += _folded_dep_blocks(text)
    found: list[Declaration] = []
    for token, raw in tokens:
        parsed = _requirement(token)
        if parsed:
            found.append(Declaration(parsed[0], parsed[1], rel, kind, service, raw))
    return found


def scan(root: Path) -> Scan:
    result = Scan()

    # `packages/*` are install paths too: CI pip-installs three of them in
    # editable mode and `release.yml` publishes them. `aisoc-cli` signs plugin
    # submissions with Ed25519 keys the API verifies, so its cryptography pin
    # is one half of a contract whose other half lives in services/api.
    manifests = sorted(root.glob("services/*/pyproject.toml")) + sorted(root.glob("packages/*/pyproject.toml"))
    for manifest in manifests:
        rel = manifest.relative_to(root).as_posix()
        service = manifest.parent.name
        result.files.append(rel)
        result.declarations += parse_manifest(manifest, rel, service)

        lock = manifest.parent / "poetry.lock"
        if lock.exists():
            lock_rel = lock.relative_to(root).as_posix()
            result.files.append(lock_rel)
            result.declarations += parse_lock(lock, lock_rel, service)

        dockerfile = manifest.parent / "Dockerfile"
        if dockerfile.exists():
            docker_rel = dockerfile.relative_to(root).as_posix()
            result.files.append(docker_rel)
            result.declarations += parse_shell(dockerfile, docker_rel, "image", service)

    workflows = root / ".github" / "workflows"
    for workflow in sorted(workflows.glob("*.yml")) if workflows.is_dir() else []:
        rel = workflow.relative_to(root).as_posix()
        if rel in MATRIX_EXEMPT:
            continue
        result.files.append(rel)
        result.declarations += parse_shell(workflow, rel, "ci", None)

    # The devcontainer is an install path like any other: it is the toolchain a
    # contributor's first `ruff format` runs from, and an unpinned ruff there
    # fails a gate they cannot reproduce locally.
    devcontainer = root / ".devcontainer" / "Dockerfile"
    if devcontainer.exists():
        rel = devcontainer.relative_to(root).as_posix()
        result.files.append(rel)
        result.declarations += parse_shell(devcontainer, rel, "image", None)

    return result


# ── The checks ───────────────────────────────────────────────────────────────


def check_service_internal(data: Scan) -> list[str]:
    """manifest <-> image, run in both directions.

    Forward: a package both files name must carry the same range.
    Reverse: a package the image installs must be declared by the manifest. The
    reverse direction is the one that rotted — the Dockerfiles kept their own
    dependency list under a comment asking for lockstep, and all twelve had
    drifted from the manifest they mirrored.
    """
    problems: list[str] = []
    services = {d.service for d in data.declarations if d.service}
    for service in sorted(services):
        manifest = {d.package: d for d in data.declarations if d.service == service and d.kind == "manifest"}
        image = [d for d in data.declarations if d.service == service and d.kind == "image"]
        for declaration in image:
            if declaration.package in BUILD_TOOLING:
                continue
            declared = manifest.get(declaration.package)
            if declared is None:
                problems.append(
                    f"{declaration.path} installs `{declaration.package}` but "
                    f"services/{service}/pyproject.toml does not declare it "
                    f"(image -> manifest)"
                )
            elif normalise(declared.spec) != normalise(declaration.spec):
                problems.append(
                    f"{service}: `{declaration.package}` is {declared.spec or 'unbounded'} in "
                    f"pyproject.toml and {declaration.spec or 'unbounded'} in Dockerfile "
                    f"(manifest -> image)"
                )
    return problems


def check_agreement(data: Scan) -> list[str]:
    """Every range written for a critical package must be the same range."""
    problems: list[str] = []
    for package, reason in sorted(CRITICAL.items()):
        declarations = [d for d in data.by_package(package) if d.kind != "lock"]
        if not declarations:
            continue

        unbounded = [d for d in declarations if not d.spec]
        ranges: dict[str, list[Declaration]] = {}
        for declaration in declarations:
            if declaration.spec:
                ranges.setdefault(normalise(declaration.spec), []).append(declaration)

        if unbounded:
            where = ", ".join(sorted({d.path for d in unbounded}))
            problems.append(
                f"`{package}` is installed with no version bound in {where} — "
                f"that permits every release ever published. Why it matters: {reason}"
            )
        if len(ranges) > 1:
            detail = "; ".join(
                f"[{spec}] {', '.join(sorted({d.path for d in found}))}" for spec, found in sorted(ranges.items())
            )
            problems.append(
                f"`{package}` is pinned {len(ranges)} different ways: {detail}. Why it matters: {reason}"
            )
    return problems


def check_locks_satisfy(data: Scan) -> list[str]:
    """The version a lock resolved must be inside the agreed range.

    A lock is the only file that says what actually ships. Comparing the ranges
    to each other and never to the lock would leave the gate agreeing loudly
    about a number nothing installs.
    """
    problems: list[str] = []
    for package in sorted(CRITICAL):
        ranges = {normalise(d.spec) for d in data.by_package(package) if d.kind != "lock" and d.spec}
        if len(ranges) != 1:
            continue  # already reported by check_agreement
        agreed = next(iter(ranges))
        for declaration in data.by_package(package):
            if declaration.kind != "lock":
                continue
            resolved = declaration.spec.lstrip("=")
            if not satisfies(resolved, agreed):
                problems.append(
                    f"{declaration.path} resolved `{package}` {resolved}, which is outside "
                    f"the declared range {agreed} (lock -> agreement)"
                )
    return problems


_CRITICAL_MENTION = re.compile(
    rf"""(?:^|["'\s])({"|".join(re.escape(p) for p in CRITICAL)})\s*(?:=\s*["']|\[[^\]]*\])?\s*["']?[<>=!~]""",
    re.IGNORECASE | re.MULTILINE,
)


def _uncommented(text: str) -> str:
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


def check_parser_coverage(root: Path, data: Scan) -> list[str]:
    """A file this gate opened but did not actually read.

    The other direction of `check_coverage`. That one asks "is every file
    holding a declaration in the scanned set"; this one asks "did the parser
    extract every declaration in the files it did scan". Both are needed,
    because a file can be globbed, counted, reported in the summary — and
    still have its install block skipped by a parser that does not understand
    the syntax it is written in. `integration.yml` sat in exactly that state:
    scanned, counted, and silently contributing nothing.

    The comparison is per package per file, so it catches "this file declares
    X and the parser produced no X from it" — the shape both real bugs took.
    It would not catch a file declaring X twice where only one is read. Said
    plainly rather than left for someone to discover: counting occurrences
    would mean matching the regex's idea of a declaration against the
    parser's, and a disagreement between those two would fail the build for a
    reason that is not drift.
    """
    problems: list[str] = []
    for rel in sorted(set(data.files)):
        path = root / rel
        if not path.is_file() or rel.endswith("poetry.lock"):
            continue
        try:
            text = _uncommented(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError):
            continue
        mentioned = {canonical(m.group(1)) for m in _CRITICAL_MENTION.finditer(text)}
        extracted = {d.package for d in data.declarations if d.path == rel}
        for package in sorted(mentioned - extracted):
            problems.append(
                f"{rel} declares `{package}` but the parser extracted nothing for it from this file — "
                f"the file is counted as scanned while contributing no declaration"
            )
    return problems


_FLOOR_LEG = re.compile(r"""-\s*fastapi:\s*["']([^"']+)["']\s*\n\s*label:\s*floor""")


def check_matrix_brackets(root: Path, data: Scan) -> list[str]:
    """The fastapi range-matrix must test the boundary the manifests declare.

    Exempting a matrix workflow from "one range everywhere" is only safe if
    something still ties it to that range. Otherwise raising the floor in
    thirteen manifests would leave the matrix quietly proving that a version
    nobody ships still works.
    """
    path = root / ".github" / "workflows" / "reproducible-builds.yml"
    if not path.exists():
        return []  # the workflow is optional; `check_agreement` still applies
    ranges = {normalise(d.spec) for d in data.by_package("fastapi") if d.kind != "lock" and d.spec}
    if len(ranges) != 1:
        return []  # already reported
    lower = next((c[2:] for c in sorted(next(iter(ranges)).split(",")) if c.startswith(">=")), None)
    leg = _FLOOR_LEG.search(path.read_text(encoding="utf-8"))
    if leg is None:
        return ["reproducible-builds.yml has no fastapi matrix leg labelled `floor`"]
    if lower is None or not same_version(leg.group(1), lower):
        return [
            f"reproducible-builds.yml tests the floor at fastapi {leg.group(1)}, "
            f"but the manifests declare a lower bound of {lower}"
        ]
    return []


def check_coverage(root: Path, data: Scan) -> list[str]:
    """A file declaring a critical package that the scan never opened.

    Without this, adding a Dockerfile or workflow outside the globs above would
    add an install path the gate cannot see, and the gate would keep printing
    OK about a set that no longer describes the repository.
    """
    scanned = set(data.files)
    stray: set[str] = set()
    names = "|".join(re.escape(p) for p in CRITICAL)
    pattern = re.compile(rf"""(?:^|["'\s])({names})\s*(?:=\s*["']|[<>=!~])""", re.IGNORECASE | re.MULTILINE)

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        if rel in scanned or rel.startswith(SKIP_PREFIXES) or rel in MATRIX_EXEMPT:
            continue
        if path.suffix not in {".yml", ".yaml", ".toml", ".txt", ".lock", ""}:
            continue
        if path.suffix == "" and path.name != "Dockerfile":
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if pattern.search(text):
            stray.add(rel)
    return [
        f"{rel} declares a critical package but is not an install path this gate scans — "
        f"add it to `scan()` or to SKIP_PREFIXES with a reason"
        for rel in sorted(stray)
    ]


def run(root: Path, verbose: bool = False) -> tuple[int, list[str]]:
    if not (root / ".github" / "workflows").is_dir() or not (root / "services").is_dir():
        return 1, [
            f"{root} does not look like the AiSOC repository (no .github/workflows and services/). "
            f"Pass --repo-root explicitly."
        ]

    data = scan(root)
    if not data.declarations:
        return 1, [f"scanned {len(data.files)} file(s) under {root} and found no dependency declaration at all"]

    problems = (
        check_service_internal(data)
        + check_agreement(data)
        + check_locks_satisfy(data)
        + check_matrix_brackets(root, data)
        + check_parser_coverage(root, data)
        + check_coverage(root, data)
    )

    kinds = {kind: sum(1 for d in data.declarations if d.kind == kind) for kind in ("manifest", "lock", "image", "ci")}
    print(f"check_dependency_pins: root {root}")
    print(
        f"  scanned {len(data.files)} install paths "
        f"({sum(1 for f in data.files if f.endswith('pyproject.toml'))} manifests, "
        f"{sum(1 for f in data.files if f.endswith('poetry.lock'))} locks, "
        f"{sum(1 for f in data.files if f.endswith('Dockerfile'))} Dockerfiles, "
        f"{sum(1 for f in data.files if f.startswith('.github/'))} workflows)"
    )
    print(f"  {len(data.declarations)} declarations ({', '.join(f'{k}={v}' for k, v in kinds.items())})")
    for package in sorted(CRITICAL):
        found = data.by_package(package)
        if not found:
            continue
        ranges = sorted({normalise(d.spec) for d in found if d.kind != "lock" and d.spec})
        locked = sorted({d.spec.lstrip("=") for d in found if d.kind == "lock"})
        print(
            f"  {package}: {len(found)} declarations across {len({d.path for d in found})} files"
            f" — range {', '.join(ranges) or 'none'}"
            + (f", locked {', '.join(locked)}" if locked else "")
        )
    if verbose:
        for rel in data.files:
            print(f"    scanned {rel}")

    if problems:
        print("check_dependency_pins: FAIL")
        for problem in problems:
            print(f"  - {problem}")
        return 1, problems
    print("check_dependency_pins: OK")
    return 0, []


# ── Self-test ────────────────────────────────────────────────────────────────


def _fixture(root: Path) -> None:
    """A miniature repository that passes, for the injections to break."""
    (root / ".github" / "workflows").mkdir(parents=True)
    service = root / "services" / "demo"
    service.mkdir(parents=True)
    (service / "pyproject.toml").write_text(
        '[tool.poetry]\nname = "demo"\nversion = "0.1.0"\n\n'
        '[tool.poetry.dependencies]\npython = "^3.11"\n'
        'fastapi = ">=0.117,<0.142"\ncryptography = ">=46,<51"\n',
        encoding="utf-8",
    )
    (service / "poetry.lock").write_text(
        '[[package]]\nname = "fastapi"\nversion = "0.141.1"\n\n'
        '[[package]]\nname = "cryptography"\nversion = "50.0.1"\n',
        encoding="utf-8",
    )
    (service / "Dockerfile").write_text(
        "FROM python:3.11-slim\nRUN pip install poetry==2.4.1\n"
        "RUN poetry install --only main --no-root\n",
        encoding="utf-8",
    )
    (root / ".github" / "workflows" / "ci.yml").write_text(
        'name: CI\njobs:\n  t:\n    steps:\n'
        '      - run: pip install "fastapi>=0.117,<0.142" "cryptography>=46,<51"\n',
        encoding="utf-8",
    )


def self_test() -> int:
    import shutil
    import tempfile

    def build(mutate=None) -> tuple[int, list[str]]:
        temp = Path(tempfile.mkdtemp(prefix="pin_selftest_"))
        try:
            _fixture(temp)
            if mutate:
                mutate(temp)
            return run(temp)
        finally:
            shutil.rmtree(temp, ignore_errors=True)

    def drift_manifest_to_image(root: Path) -> None:
        path = root / "services" / "demo" / "Dockerfile"
        path.write_text(path.read_text() + 'RUN pip install "fastapi>=0.111,<0.112"\n', encoding="utf-8")

    def drift_image_to_manifest(root: Path) -> None:
        path = root / "services" / "demo" / "Dockerfile"
        path.write_text(path.read_text() + 'RUN pip install "requests>=2,<3"\n', encoding="utf-8")

    def drift_ci_range(root: Path) -> None:
        path = root / ".github" / "workflows" / "ci.yml"
        path.write_text(path.read_text().replace('"cryptography>=46,<51"', '"cryptography>=41,<46"'), encoding="utf-8")

    def drift_unbounded(root: Path) -> None:
        path = root / ".github" / "workflows" / "ci.yml"
        path.write_text(path.read_text().replace('"fastapi>=0.117,<0.142"', "fastapi"), encoding="utf-8")

    def drift_lock(root: Path) -> None:
        path = root / "services" / "demo" / "poetry.lock"
        path.write_text(path.read_text().replace('version = "0.141.1"', 'version = "0.111.1"'), encoding="utf-8")

    def drift_unscanned_path(root: Path) -> None:
        (root / "extra").mkdir()
        (root / "extra" / "Dockerfile").write_text(
            'FROM python:3.11-slim\nRUN pip install "fastapi>=0.111,<0.112"\n', encoding="utf-8"
        )

    def drift_inside_a_folded_run_block(root: Path) -> None:
        """The syntax `integration.yml` uses, which the first parser could not read."""
        path = root / ".github" / "workflows" / "ci.yml"
        path.write_text(
            path.read_text()
            + "      - name: Install via a folded scalar\n"
            + "        run: >-\n"
            + "          pip install --quiet\n"
            + '          "cryptography>=41,<46" structlog\n',
            encoding="utf-8",
        )

    def drift_into_a_syntax_the_parser_skips(root: Path) -> None:
        """A declaration in a TOML table `parse_manifest` does not read.

        This is the shape of the bug `check_parser_coverage` found in this
        gate itself: dev-group dependencies were declared, scanned and
        invisible, so `ruff` was reported as agreeing across files none of
        which had actually been read for it.
        """
        path = root / "services" / "demo" / "pyproject.toml"
        path.write_text(path.read_text() + '\n[tool.uv]\ndev-dependencies = ["sqlglot>=27,<31"]\n', encoding="utf-8")

    def drift_matrix_off_the_boundary(root: Path) -> None:
        (root / ".github" / "workflows" / "reproducible-builds.yml").write_text(
            "name: Reproducible builds\njobs:\n  fastapi-range:\n    strategy:\n      matrix:\n"
            "        include:\n          - fastapi: '0.111.0'\n            label: floor\n",
            encoding="utf-8",
        )

    cases = [
        ("clean fixture passes", None, None),
        ("manifest -> image", drift_manifest_to_image, "manifest -> image"),
        ("image -> manifest", drift_image_to_manifest, "image -> manifest"),
        ("range disagreement", drift_ci_range, "pinned 2 different ways"),
        ("unbounded install", drift_unbounded, "no version bound"),
        ("lock -> agreement", drift_lock, "lock -> agreement"),
        ("unscanned install path", drift_unscanned_path, "not an install path this gate scans"),
        ("drift inside a folded run block", drift_inside_a_folded_run_block, "pinned 2 different ways"),
        ("declaration in a syntax the parser skips", drift_into_a_syntax_the_parser_skips, "parser extracted nothing"),
        ("matrix leg off the declared boundary", drift_matrix_off_the_boundary, "tests the floor at fastapi"),
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
    empty = Path(tempfile.mkdtemp(prefix="pin_selftest_empty_"))
    try:
        code, _ = run(empty)
    finally:
        shutil.rmtree(empty, ignore_errors=True)
    if code == 0:
        failures.append("non-repo root: printed OK about a tree with no install paths")
    print(f"  self-test [{'ok' if code != 0 else 'FAIL'}] refuses a non-repo root")

    if failures:
        print("\ncheck_dependency_pins --self-test: FAIL")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print(f"\ncheck_dependency_pins --self-test: OK — {len(cases) + 1} cases, every direction detected")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=None,
        help="tree to check; defaults to this script's parent repository",
    )
    parser.add_argument("--verbose", action="store_true", help="list every file scanned")
    parser.add_argument("--self-test", action="store_true", help="prove the gate detects drift in each direction")
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    root = (args.repo_root or Path(__file__).resolve().parent.parent).resolve()
    return run(root, verbose=args.verbose)[0]


if __name__ == "__main__":
    sys.exit(main())
