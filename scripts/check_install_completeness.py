#!/usr/bin/env python3
"""An install is complete when it contains every runtime package its lock declares.

Why this exists
---------------
``reproducible-builds.yml`` proves that two builds of one commit install the
same versions. Two *empty* installs also diff clean, so each leg carried a
floor: more than fifty packages for ``api``, more than twenty for every other
image, more than ten for a lock-only install.

A fixed floor is a proxy for "this install is real", and it is wrong at both
ends. It was wrong in the strict direction first: ``services/escalations``
imports one third-party module and declares one, and its complete Linux
runtime install is **three** packages — ``psycopg``, ``psycopg-binary`` and
``typing-extensions``. The floor of twenty failed it for being correct, and
the only available remedies were both bad. Lowering the number to three
re-opens the hole for ``api``, whose 116-package install would then satisfy a
floor of three while missing a hundred packages. Exempting the service
removes the check from the one service where an empty install is hardest to
notice.

The floor is also wrong in the permissive direction, which is the half that
matters more: a service whose install silently loses half its dependencies
still clears a floor written for its full size, and that is the failure the
floor was added to catch. ``pip-audit`` reporting no vulnerabilities against
a requirements file a failed ``poetry export`` left empty is the same family.

So the expectation is derived from the thing that defines truth. Every
service image is built the same way::

    poetry export --only main --format requirements.txt --output /requirements.txt
    pip install --no-cache-dir --require-hashes -r /requirements.txt

which makes the property exact rather than approximate: **the install
contains every ``main``-group package in the lock whose environment marker
holds in the environment the install actually ran in.** Three packages is a
pass for ``escalations`` and a catastrophic failure for ``api``, and neither
verdict needs a number written down anywhere.

Separating runtime from dev, which is where this goes wrong
-----------------------------------------------------------
Getting the split wrong in the permissive direction would make the gate
vacuous: an expectation that collapses toward empty is satisfied by an
install that is also empty. Three things in these locks make the split
non-obvious, and each has to be read exactly.

``groups`` is not the whole answer
    ``services/escalations`` declares its test dependencies as a PEP 621
    ``[project.optional-dependencies]`` extra rather than a Poetry group, so
    **all twelve** of its locked packages say ``groups = ["main"]`` —
    ``pytest``, ``coverage`` and ``pluggy`` included. Reading ``groups``
    alone would expect eight test packages in a runtime image that
    deliberately has none, and the gate would fail every correct build.
    Extras are carried in the marker instead: ``markers = 'extra == "dev"'``,
    which is false when no extra is requested, and ``poetry export --only
    main`` requests none.

``markers`` is sometimes a table keyed by group
    Under lock-version 2.1 a package in two groups gets one marker per
    group: ``typing-extensions`` carries ``{dev = 'python_version <
    "3.15"'}``, which constrains it in ``dev`` and **not at all** in
    ``main``. Flattening that table to a single expression is wrong in both
    directions — it would drop a package the runtime image installs, and for
    ``colorama`` in four services it would apply the ``dev`` marker in place
    of the different ``main`` one.

markers decide membership, not just version
    ``tzdata`` in ``escalations`` is ``sys_platform == "win32"``: a genuine
    non-optional runtime dependency that is **never installed on Linux**.
    Counting it would expect a fourth package that correctly is not there.

What it refuses to guess
------------------------
Marker truth depends on the environment, so the environment comes from the
thing under test — ``scripts/marker_environment.py`` piped into the image's
own interpreter — and never from the runner, which is a different platform
running a different Python.

The tree-wide audit has no image to ask, and rather than assume a plausible
environment it evaluates each marker across every environment the tree
permits: both published architectures, and the whole patch range of the base
image's Python minor. A marker that answers the same way everywhere is
settled; one that does not is reported ``undetermined`` and counted as
neither installed nor missing. This is not hypothetical. ``async-timeout`` in
``services/actions`` is ``python_full_version < "3.11.3"``, so whether it is
a runtime package at all depends on the patch level of ``python:3.11-slim``
on the day the image was built. Picking ``3.11.0`` would expect a package
that is not installed; picking ``3.11.14`` would be right today and a
silently wrong assumption later. An unknown counted as either is this
repository's most-repeated gate defect, so it is counted as neither and said
out loud.

Usage
-----
    python3 scripts/check_install_completeness.py --check
    python3 scripts/check_install_completeness.py --check --service escalations
    python3 scripts/check_install_completeness.py \\
        --service escalations --freeze first.txt --environment env.json
    python3 scripts/check_install_completeness.py --self-test

Exit codes: 0 clean, 1 findings, 2 the check itself could not render a verdict.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from itertools import product
from pathlib import Path

# `scripts/` is on sys.path when this file runs as a program, but not when a
# test loads it by path with importlib. Its siblings sit beside it either way.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_main  # noqa: E402
from marker_environment import marker_environment  # noqa: E402

SCRIPT = "check_install_completeness.py"
SERVICES_REL = "services"

#: Marker variables the tree pins exactly. Every service image is
#: `FROM python:3.11-slim`, which fixes the platform and the interpreter; the
#: audit re-reads that from each Dockerfile rather than trusting this list, so
#: a service moved to a different base fails loudly instead of being graded
#: under an assumption that stopped being true.
_SETTLED = {
    "os_name": "posix",
    "sys_platform": "linux",
    "platform_system": "Linux",
    "platform_python_implementation": "CPython",
    "implementation_name": "cpython",
}

#: Marker variables the tree does *not* pin, with the values that bracket
#: what a real install could see. The images publish `linux/amd64` and
#: `linux/arm64` manifests, so `platform_machine` is genuinely two values;
#: the patch level of a `-slim` tag moves under the same tag, so the full
#: version is a range rather than a point.
_UNSETTLED_SHAPES = {
    "platform_machine": ("x86_64", "aarch64"),
    "platform_release": ("", "99.99.99"),
    "platform_version": ("", "zzzz"),
}

_CANONICALISE = re.compile(r"[-_.]+")
_BASE_IMAGE = re.compile(r"^\s*FROM\s+python:(\d+)\.(\d+)(?:\.(\d+))?[-\s]", re.MULTILINE)
#: `name==version`, the only shape `pip freeze` emits for a `--require-hashes`
#: install. Editable and URL installs are matched too so that a service that
#: ever grows one is read rather than silently dropped from the comparison.
_FROZEN = re.compile(r"^\s*(?:-e\s+)?(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:==|@|\s)", re.MULTILINE)

UNDETERMINED = None


class GateError(Exception):
    """The check cannot render a verdict. Never rounded to a pass."""


def canonical(name: str) -> str:
    """PEP 503 normalisation, so `psycopg_binary` and `psycopg-binary` agree."""
    return _CANONICALISE.sub("-", name).strip().lower()


# --------------------------------------------------------------------------
# Marker evaluation
# --------------------------------------------------------------------------
def _marker_type():
    """`packaging.markers.Marker`, imported late and refused loudly if absent.

    Late because the tree-wide audit refuses an empty tree before it needs to
    evaluate anything, and a gate that dies on an import in a tree with no
    content proves nothing about the tree. `packaging` rather than a hand-
    rolled evaluator because marker comparison is *version* comparison, not
    string comparison: `python_full_version < "3.11.3"` is false on 3.11.10
    and lexicographically true, and that exact marker is on a main-group
    package here.
    """
    try:
        from packaging.markers import Marker
    except ModuleNotFoundError as exc:  # pragma: no cover - environment-dependent
        raise GateError(f"this check needs `packaging` to evaluate PEP 508 markers (pip install 'packaging>=23'): {exc}") from exc
    return Marker


def resolve_marker(expression: str | None, environments: Sequence[Mapping[str, str]]) -> bool | None:
    """True / False when every candidate environment agrees, else UNDETERMINED.

    A marker is a claim about an environment. With one candidate — the real
    one, read out of the image — the answer is simply that claim's truth. With
    several, agreement is the only honest verdict; disagreement means the tree
    does not determine whether the package is installed, and saying so beats
    picking the convenient half.
    """
    if expression is None:
        return True
    if not environments:
        raise GateError("no candidate environment to evaluate markers against")
    marker_cls = _marker_type()
    try:
        marker = marker_cls(expression)
    except Exception as exc:  # packaging raises InvalidMarker, which varies by version
        raise GateError(f"cannot parse environment marker {expression!r}: {exc}") from exc

    verdicts = set()
    for environment in environments:
        # `extra` is bound to the empty string because `poetry export --only
        # main` requests no extras: `extra == "dev"` is how an extras-only
        # package is spelled in these locks, and it must come out false.
        try:
            verdicts.add(bool(marker.evaluate({**environment, "extra": ""})))
        except Exception as exc:
            raise GateError(f"cannot evaluate environment marker {expression!r}: {exc}") from exc
        if len(verdicts) > 1:
            return UNDETERMINED
    return verdicts.pop()


def candidate_environments(python_minor: str) -> list[dict[str, str]]:
    """Every environment a published image of this tree could present.

    `python_minor` is read from the service's own Dockerfile. The patch level
    is a range rather than a value because `python:3.11-slim` is a moving tag.
    """
    major, minor = python_minor.split(".", 1)
    full_versions = (f"{major}.{minor}.0", f"{major}.{minor}.999")
    axes = {
        **_UNSETTLED_SHAPES,
        "python_full_version": full_versions,
        "implementation_version": full_versions,
    }
    names = sorted(axes)
    out = []
    for combination in product(*(axes[name] for name in names)):
        out.append({**_SETTLED, "python_version": python_minor, **dict(zip(names, combination, strict=True))})
    return out


# --------------------------------------------------------------------------
# The lock
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class LockedPackage:
    name: str
    version: str
    groups: tuple[str, ...]
    main_marker: str | None


def read_lock(path: Path) -> list[LockedPackage]:
    """Every package in a `poetry.lock`, with the marker that applies to `main`."""
    try:
        document = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise GateError(f"{path}: cannot read lock: {exc}") from exc

    packages = document.get("package")
    if not packages:
        raise GateError(f"{path}: declares no packages at all — refusing to grade an install against it")

    out = []
    for entry in packages:
        name = entry.get("name")
        if not name:
            raise GateError(f"{path}: a package entry has no name")
        # A lock written before groups were recorded has none; `main` is the
        # only group such a lock can mean.
        groups = tuple(entry.get("groups") or ("main",))
        markers = entry.get("markers")
        if isinstance(markers, Mapping):
            # Keyed by group under lock-version 2.1. A group absent from the
            # table is unconstrained in that group, which is not the same as
            # "inherits the other group's marker".
            main_marker = markers.get("main")
        elif isinstance(markers, str):
            main_marker = markers
        elif markers is None:
            main_marker = None
        else:
            raise GateError(f"{path}: {name}: unexpected markers of type {type(markers).__name__}")
        out.append(
            LockedPackage(
                name=canonical(name),
                version=str(entry.get("version", "")),
                groups=groups,
                main_marker=main_marker,
            )
        )
    return out


@dataclass
class RuntimeSet:
    """What a lock says a runtime install of this service must contain."""

    expected: set[str] = field(default_factory=set)
    undetermined: dict[str, str] = field(default_factory=dict)
    excluded_by_marker: dict[str, str] = field(default_factory=dict)
    excluded_by_group: set[str] = field(default_factory=set)

    @property
    def considered(self) -> int:
        return len(self.expected) + len(self.undetermined) + len(self.excluded_by_marker) + len(self.excluded_by_group)


def runtime_set(packages: Iterable[LockedPackage], environments: Sequence[Mapping[str, str]]) -> RuntimeSet:
    """The `main`-group packages whose markers hold, and why the rest are out."""
    out = RuntimeSet()
    for package in packages:
        if "main" not in package.groups:
            out.excluded_by_group.add(package.name)
            continue
        verdict = resolve_marker(package.main_marker, environments)
        if verdict is UNDETERMINED:
            out.undetermined[package.name] = package.main_marker or ""
        elif verdict:
            out.expected.add(package.name)
        else:
            out.excluded_by_marker[package.name] = package.main_marker or ""
    return out


# --------------------------------------------------------------------------
# The manifest, as an independent read on the same question
# --------------------------------------------------------------------------
def declared_runtime_dependencies(path: Path) -> dict[str, str | None]:
    """The unconditional runtime dependencies the manifest names, to their markers.

    The lock is the authority on *what gets installed*; this is a second,
    independent read on *what must be in there somewhere*. It exists to catch
    the split failing in the permissive direction: a bug that drops runtime
    packages shrinks the expectation toward empty, where a truncated install
    would pass. A direct dependency missing from the derived set means the
    derivation lost something, and that is a refusal rather than a finding.

    Two kinds of declaration are deliberately *not* runtime dependencies, and
    reading either as one would make this cross-check fire on correct trees:

    * a PEP 621 ``[project.optional-dependencies]`` extra, which is a
      separate table and simply not read here; and
    * a Poetry dependency carrying ``optional = true``, which sits in
      ``[tool.poetry.dependencies]`` beside the real ones and is reachable
      only through ``[tool.poetry.extras]``. ``services/actions`` declares
      ``vaid-mint = {version = "==0.11.0", optional = true}`` exactly so the
      badge plugin stays off by default, and ``poetry export --only main``
      does not install it.

    A dependency that carries its own environment marker is returned with it,
    because a genuinely platform-gated runtime dependency is allowed to be
    absent from an install on another platform.
    """
    try:
        document = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise GateError(f"{path}: cannot read manifest: {exc}") from exc

    declared: dict[str, str | None] = {}
    for raw in document.get("project", {}).get("dependencies", []) or []:
        text = raw.strip()
        if not text:
            continue
        requirement, _, marker = text.partition(";")
        # PEP 508: `psycopg[binary]>=3.2,<4` names `psycopg`.
        name = re.split(r"[\s<>=!~\[(@]", requirement.strip(), maxsplit=1)[0]
        if name:
            declared[canonical(name)] = marker.strip() or None

    poetry = document.get("tool", {}).get("poetry", {}).get("dependencies", {}) or {}
    for name, spec in poetry.items():
        if canonical(name) == "python":
            continue
        marker = None
        if isinstance(spec, Mapping):
            if spec.get("optional"):
                continue
            marker = spec.get("markers")
        declared[canonical(name)] = marker
    return declared


# --------------------------------------------------------------------------
# Services
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class Service:
    name: str
    root: Path

    @property
    def lock(self) -> Path:
        return self.root / "poetry.lock"

    @property
    def manifest(self) -> Path:
        return self.root / "pyproject.toml"

    @property
    def dockerfile(self) -> Path:
        return self.root / "Dockerfile"


def discover_services(root: Path, only: str | None = None) -> list[Service]:
    """Every service with a `poetry.lock`, derived from the tree."""
    base = root / SERVICES_REL
    if not base.is_dir():
        raise GateError(f"no {SERVICES_REL}/ directory under {root} — refusing to report on a tree that is not there")
    found = [
        Service(name=child.name, root=child) for child in sorted(base.iterdir()) if child.is_dir() and (child / "poetry.lock").is_file()
    ]
    if only is not None:
        found = [service for service in found if service.name == only]
        if not found:
            raise GateError(f"no service named {only!r} with a poetry.lock under {base}")
        return found
    if not found:
        raise GateError(f"found no service with a poetry.lock under {base} — refusing to report a clean result from an empty read")
    return found


def python_minor_for(service: Service) -> str:
    """The Python minor the service's own Dockerfile installs into."""
    if not service.dockerfile.is_file():
        raise GateError(
            f"{service.name}: no Dockerfile, so the interpreter its install runs on is not "
            "stated anywhere in the tree; pass --environment to grade it"
        )
    match = _BASE_IMAGE.search(service.dockerfile.read_text(encoding="utf-8"))
    if not match:
        raise GateError(
            f"{service.dockerfile}: no `FROM python:<version>` base image found, so the "
            "interpreter this service installs into is not stated in the tree"
        )
    return f"{match.group(1)}.{match.group(2)}"


def derive(service: Service, environments: Sequence[Mapping[str, str]]) -> RuntimeSet:
    """The runtime expectation for one service, cross-checked against its manifest."""
    derived = runtime_set(read_lock(service.lock), environments)

    if not derived.expected:
        raise GateError(
            f"{service.name}: the lock yields no runtime package at all. An expectation of "
            "nothing is satisfied by an install of nothing, so this is refused rather than "
            f"reported clean (considered {derived.considered} locked package(s))"
        )

    if service.manifest.is_file():
        declared = declared_runtime_dependencies(service.manifest)
        lost = sorted(
            name
            for name, marker in declared.items()
            if name not in derived.expected
            and name not in derived.undetermined
            # A runtime dependency the manifest itself gates to another
            # platform is allowed to be absent here.
            and resolve_marker(marker, environments) is not False
        )
        if lost:
            raise GateError(
                f"{service.name}: {', '.join(lost)} declared as a runtime dependency in "
                f"{service.manifest.name} but absent from the set derived from the lock — "
                "the runtime/dev split has lost a package, which would make this check vacuous"
            )
    return derived


# --------------------------------------------------------------------------
# The comparison
# --------------------------------------------------------------------------
def frozen_names(text: str) -> set[str]:
    """Distribution names out of `pip freeze` output."""
    return {canonical(match.group("name")) for match in _FROZEN.finditer(text)}


@dataclass
class Comparison:
    service: str
    expected: set[str]
    installed: set[str]
    undetermined: dict[str, str]

    @property
    def missing(self) -> list[str]:
        return sorted(self.expected - self.installed)

    @property
    def unexpected(self) -> list[str]:
        return sorted(self.installed - self.expected - set(self.undetermined))

    @property
    def ok(self) -> bool:
        return not self.missing


def compare(service: str, derived: RuntimeSet, freeze_text: str) -> Comparison:
    installed = frozen_names(freeze_text)
    if not installed:
        # Distinguished from "missing everything" on purpose: an unreadable
        # capture is a broken probe, and reporting it as a catastrophic
        # install failure would send someone to debug the wrong thing.
        raise GateError(
            f"{service}: the freeze capture names no package at all — it is empty or not pip freeze output, so nothing was compared"
        )
    return Comparison(
        service=service,
        expected=set(derived.expected),
        installed=installed,
        undetermined=dict(derived.undetermined),
    )


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------
def _report_comparison(result: Comparison) -> bool:
    print(f"{result.service}: {len(result.expected)} runtime package(s) declared by the lock, {len(result.installed)} installed")
    if result.undetermined:
        print(f"  undetermined ({len(result.undetermined)}), neither expected nor missing:")
        for name, marker in sorted(result.undetermined.items()):
            print(f"    {name}  {marker}")
    if result.unexpected:
        print(f"  present but not declared for this environment ({len(result.unexpected)}): {', '.join(result.unexpected)}")
    if result.missing:
        print(
            f"::error::{result.service}: the install is missing {len(result.missing)} of "
            f"{len(result.expected)} runtime package(s) its lock declares: {', '.join(result.missing)}"
        )
        return False
    print("  complete: every runtime package the lock declares is installed")
    return True


def _report_audit(rows: list[tuple[Service, RuntimeSet]]) -> bool:
    print(f"{'service':<16} {'runtime':>7} {'undet':>6} {'off-marker':>11} {'off-group':>10}   lock")
    for service, derived in rows:
        print(
            f"{service.name:<16} {len(derived.expected):>7} {len(derived.undetermined):>6} "
            f"{len(derived.excluded_by_marker):>11} {len(derived.excluded_by_group):>10}   "
            f"{derived.considered}"
        )
    for service, derived in rows:
        for name, marker in sorted(derived.undetermined.items()):
            print(f"  undetermined  {service.name}/{name}  {marker}")
    print(f"\nOK: {len(rows)} service lock(s) yield a non-empty runtime set that covers every runtime dependency their manifests declare")
    return True


# --------------------------------------------------------------------------
# Self-test
# --------------------------------------------------------------------------
_LINUX = [
    {
        **_SETTLED,
        "python_version": "3.11",
        "python_full_version": "3.11.14",
        "platform_machine": "x86_64",
        "platform_release": "6.1.0",
        "platform_version": "#1",
        "implementation_version": "3.11.14",
    }
]


def _lock_fixture(body: str) -> list[LockedPackage]:
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "poetry.lock"
        path.write_text(body, encoding="utf-8")
        return read_lock(path)


_REAL_SHAPE = """
[[package]]
name = "psycopg"
version = "3.3.6"
groups = ["main"]

[[package]]
name = "psycopg-binary"
version = "3.3.6"
groups = ["main"]
markers = "implementation_name != \\"pypy\\""

[[package]]
name = "typing-extensions"
version = "4.16.0"
groups = ["main"]
markers = "python_version < \\"3.13\\""

[[package]]
name = "tzdata"
version = "2026.6"
groups = ["main"]
markers = "sys_platform == \\"win32\\""

[[package]]
name = "pytest"
version = "9.2.0"
groups = ["main"]
markers = "extra == \\"dev\\""

[[package]]
name = "colorama"
version = "0.4.6"
groups = ["main"]
markers = "extra == \\"dev\\" and sys_platform == \\"win32\\""

[[package]]
name = "mypy"
version = "1.0.0"
groups = ["dev"]
"""


def _self_test_cases() -> list[tuple[str, bool]]:
    results: list[tuple[str, bool]] = []

    def case(description: str, passed: bool) -> None:
        results.append((description, passed))

    derived = runtime_set(_lock_fixture(_REAL_SHAPE), _LINUX)

    case(
        "the runtime set is exactly the three packages a Linux install receives",
        derived.expected == {"psycopg", "psycopg-binary", "typing-extensions"},
    )
    case(
        'an extras-only package (`extra == "dev"`) is not expected at runtime',
        "pytest" not in derived.expected and derived.excluded_by_marker.get("pytest") == 'extra == "dev"',
    )
    case(
        "a package in a dev group only is not expected at runtime",
        "mypy" not in derived.expected and "mypy" in derived.excluded_by_group,
    )
    case(
        "a non-optional runtime package gated to win32 is not expected on Linux",
        "tzdata" not in derived.expected,
    )

    # A marker table keyed by group: `dev` constrained, `main` unconstrained.
    keyed = _lock_fixture(
        '[[package]]\nname = "typing-extensions"\nversion = "4.16.0"\n'
        'groups = ["main", "dev"]\n[package.markers]\ndev = \'python_version < "3.15"\'\n'
    )
    case(
        "a marker table keyed by group does not apply the dev marker to main",
        keyed[0].main_marker is None and runtime_set(keyed, _LINUX).expected == {"typing-extensions"},
    )

    # Version comparison must be version-aware, not lexicographic. This is the
    # live case: `async-timeout` in services/actions carries exactly this.
    patch_gated = 'python_full_version < "3.11.3"'
    on_3_11_10 = resolve_marker(patch_gated, [{**_LINUX[0], "python_full_version": "3.11.10"}])
    case(
        '`python_full_version < "3.11.3"` is false on 3.11.10, not lexicographically true',
        on_3_11_10 is False,
    )
    case(
        "a marker the tree does not settle is undetermined, not guessed either way",
        resolve_marker(patch_gated, candidate_environments("3.11")) is UNDETERMINED,
    )

    # ---- the comparison, both directions -------------------------------
    complete = "psycopg==3.3.6\npsycopg-binary==3.3.6\ntyping-extensions==4.16.0\n"
    truncated = "psycopg==3.3.6\n"
    case(
        "a complete install passes",
        compare("fixture", derived, complete).ok,
    )
    truncated_result = compare("fixture", derived, truncated)
    case(
        "a truncated install fails and names what is missing",
        not truncated_result.ok and truncated_result.missing == ["psycopg-binary", "typing-extensions"],
    )

    # The permissive direction, stated as the failure it would cause: if the
    # split had counted the extras-only and dev-group packages as runtime, the
    # *correct* install would be reported as missing them. Proving the gate is
    # not merely lenient means watching the broken split reject a good install.
    permissive = runtime_set(_lock_fixture(_REAL_SHAPE), _LINUX)
    permissive.expected |= {"pytest", "colorama", "mypy"}
    case(
        "a split that counted dev packages as runtime would reject the real install",
        not compare("fixture", permissive, complete).ok,
    )

    # The vacuous direction: an expectation of nothing must be refused, not
    # reported clean, because an install of nothing satisfies it.
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        service_dir = root / SERVICES_REL / "hollow"
        service_dir.mkdir(parents=True)
        (service_dir / "poetry.lock").write_text('[[package]]\nname = "mypy"\nversion = "1.0.0"\ngroups = ["dev"]\n', encoding="utf-8")
        (service_dir / "Dockerfile").write_text("FROM python:3.11-slim\n", encoding="utf-8")
        service = Service(name="hollow", root=service_dir)
        refused = False
        try:
            derive(service, _LINUX)
        except GateError:
            refused = True
        case("a lock yielding an empty runtime set is refused, not reported clean", refused)

        # And the manifest cross-check: a derivation that loses a declared
        # runtime dependency is refused rather than shrinking quietly.
        lossy = root / SERVICES_REL / "lossy"
        lossy.mkdir(parents=True)
        (lossy / "poetry.lock").write_text('[[package]]\nname = "psycopg"\nversion = "3.3.6"\ngroups = ["main"]\n', encoding="utf-8")
        (lossy / "Dockerfile").write_text("FROM python:3.11-slim\n", encoding="utf-8")
        (lossy / "pyproject.toml").write_text(
            '[project]\nname = "x"\nversion = "0"\ndependencies = ["psycopg>=3", "httpx>=0.28"]\n',
            encoding="utf-8",
        )
        lost = False
        try:
            derive(Service(name="lossy", root=lossy), _LINUX)
        except GateError as exc:
            lost = "httpx" in str(exc)
        case("a declared runtime dependency missing from the derived set is refused", lost)

    case(
        "an unreadable freeze capture is refused rather than read as a failed install",
        _refuses(lambda: compare("fixture", derived, "\n# nothing here\n")),
    )
    return results


def _refuses(thunk) -> bool:
    try:
        thunk()
    except GateError:
        return True
    return False


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------
def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="audit every service lock (default)")
    parser.add_argument("--service", help="limit to one service under services/")
    parser.add_argument("--freeze", type=Path, help="a `pip freeze` capture to compare against the lock")
    parser.add_argument(
        "--environment",
        type=Path,
        help="JSON marker environment, as produced by scripts/marker_environment.py run inside the thing under test",
    )
    parser.add_argument("--print-environment", action="store_true", help="this interpreter's marker environment")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--self-test", action="store_true", help="prove this check still detects what it claims")
    args = parser.parse_args(argv)

    if args.print_environment:
        print(json.dumps(marker_environment(), indent=2, sort_keys=True))
        return 0

    if args.self_test:
        return self_test_main(SCRIPT, ["--check"], extra=_self_test_cases())

    try:
        root = repo_root()
        services = discover_services(root, args.service)

        if args.freeze is not None:
            if args.service is None:
                raise GateError("--freeze needs --service: a capture belongs to one install")
            service = services[0]
            if args.environment is not None:
                try:
                    environments = [json.loads(args.environment.read_text(encoding="utf-8"))]
                except (OSError, json.JSONDecodeError) as exc:
                    raise GateError(f"{args.environment}: cannot read marker environment: {exc}") from exc
            else:
                environments = candidate_environments(python_minor_for(service))
            derived = derive(service, environments)
            try:
                freeze_text = args.freeze.read_text(encoding="utf-8")
            except OSError as exc:
                raise GateError(f"{args.freeze}: cannot read freeze capture: {exc}") from exc
            result = compare(service.name, derived, freeze_text)
            if args.json:
                print(
                    json.dumps(
                        {
                            "service": result.service,
                            "expected": sorted(result.expected),
                            "installed": sorted(result.installed),
                            "missing": result.missing,
                            "unexpected": result.unexpected,
                            "undetermined": result.undetermined,
                            "ok": result.ok,
                        },
                        indent=2,
                    )
                )
                return 0 if result.ok else 1
            return 0 if _report_comparison(result) else 1

        rows = [(service, derive(service, candidate_environments(python_minor_for(service)))) for service in services]
        if args.json:
            print(
                json.dumps(
                    {
                        service.name: {
                            "expected": sorted(derived.expected),
                            "undetermined": derived.undetermined,
                            "excluded_by_marker": sorted(derived.excluded_by_marker),
                            "excluded_by_group": sorted(derived.excluded_by_group),
                        }
                        for service, derived in rows
                    },
                    indent=2,
                )
            )
            return 0
        return 0 if _report_audit(rows) else 1
    except GateError as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
