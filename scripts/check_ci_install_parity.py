#!/usr/bin/env python3
"""A CI job that grades a service must install what that service's image ships.

Why this exists
---------------
``services/api/Dockerfile`` installs from ``poetry.lock``, so every published
image has ``pysigma``. ``ci.yml``'s install list is hand-written, and it did
not. ``rule_engine._run_sigma`` imports ``sigma`` inside a ``try`` and falls
back to a reduced built-in evaluator on ``ImportError`` — so production ran
the real backend and CI ran the fallback. The two graded *different
engines*, and the one CI never ran was the broken one: a substring-matching
``_lucene_match`` made every multi-clause Sigma rule match nothing, and it
shipped. Installing pysigma the way the image does makes the pre-fix tree fail
five tests that had been green for as long as they existed.

That is not one package. It is the general shape:

    a dependency the image always has + a fallback keyed on its absence
    + a CI job that does not install it = CI grades a different engine

and the fallback is what makes it silent. ``_run_sigma`` returned no
matches. ``_run_yara``, 260 lines below it in the same file, returns
``([], "yara-python not installed")``. ``attck_semantic_search`` returns
``[]``. None of them raises, so a suite that asserts "nothing matched" passes
for a reason that has nothing to do with the code under test.

The repository has hit the adjacent version of this before and written it
down: CI installed ``cryptography >=41,<46`` while a service required
``>=46,<51`` — **disjoint**, so the version CI tested could never be the
version the image shipped. The Python services were then moved onto committed
``poetry.lock`` files and the pip fallbacks deleted, which fixed the
*images*. The workflow install lists stayed hand-curated, and they are the
surface that failed again.

What this gate asks
-------------------
Only of jobs that run a service's **whole** test suite — a directory argument
to pytest, not a named file. A whole-suite run is the thing that claims "this
service's tests pass", so it is the run where a missing optional dependency
silently swaps the engine underneath every assertion. A job that names one
file is narrow by construction and says what it grades.

Three directions, because a one-directional check misses whichever direction
things actually drift in:

``fallback -> ci``
    A distribution the service declares as a **runtime** dependency — so
    production always has it — whose absence its own code handles with
    ``except ImportError``. Every whole-suite job must install it. This is the
    pysigma defect exactly.

    Reachability from today's tests is deliberately *not* a condition. The
    property is that the suite runs against the software the image ships, so
    that a test added tomorrow grades the real path. Requiring reachability
    would make the gate go quiet at precisely the moment someone writes the
    first test for that code.

``ci -> manifest``
    A package a job installs that **none** of the services it runs declares.
    CI is then grading a code path that cannot exist in production. Union
    semantics across the job's services on purpose: ``python-services-wave-2``
    installs one set for eight services, and each package only has to be
    wanted by one of them.

``range``
    A version range that differs between the job and a manifest that declares
    the package. Reported in three grades, because they are not the same
    problem: ``disjoint`` (no version satisfies both — CI *cannot* be testing
    what ships), ``ci-wider`` (CI admits versions the service forbids), and
    ``ci-narrower`` (the service admits versions CI never exercises).

Nothing here is hand-listed. Which services a job exercises is read out of its
``working-directory``, its ``cd``, the paths it hands pytest, and — for a job
that reaches a service through ``scripts/`` — out of the ``sys.path`` insert
that script performs. Matrix legs are expanded. The one table that cannot be
derived, the handful of import names that do not resemble their distribution,
fails the build when a fallback resolves to nothing rather than skipping it.

Usage
-----
    python3 scripts/check_ci_install_parity.py
    python3 scripts/check_ci_install_parity.py --inventory
    python3 scripts/check_ci_install_parity.py --self-test
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import service_requirements  # noqa: E402
from gate_toolkit import repo_root  # noqa: E402

try:
    import yaml
except ImportError:  # pragma: no cover - pyyaml is installed everywhere this runs
    print("check_ci_install_parity: pyyaml is required to read the workflows", file=sys.stderr)
    raise SystemExit(2) from None

STDLIB = set(sys.stdlib_module_names)

# Installed to *perform* a build or to drive pytest itself rather than to run
# the service, so "the manifest must declare it" does not apply to them.
# `pytest` is not here: every service declares it, and the ranges disagreeing
# is a finding rather than noise.
TOOLING = {
    "pip",
    "setuptools",
    "wheel",
    "build",
    "twine",
    "poetry",
    "poetry-plugin-export",
    "uv",
    "hatchling",
    "pip-audit",
}

# Import names that do not resemble the distribution that provides them, and
# cannot be derived by the affix rules in `distribution_for`. Kept as short as
# possible: an unresolved fallback import is a *failure*, not a skip, so this
# table cannot quietly go stale.
IMPORT_ALIASES = {
    "sigma": "pysigma",
    "yaml": "pyyaml",
    "yara": "yara-python",
    "onelogin": "python3-saml",
    "jwt": "pyjwt",
    "dateutil": "python-dateutil",
    "dotenv": "python-dotenv",
    "multipart": "python-multipart",
    "opentelemetry": "opentelemetry-sdk",
}

# Import names a service's *own* source provides, or that ship with a
# dependency under a different top-level name and are therefore never a
# missing-distribution finding on their own.
NOT_A_DISTRIBUTION = {"app", "tests", "conftest"}


@dataclass(frozen=True)
class Requirement:
    """One ``pip install`` token, reduced to name / extras / specifier."""

    package: str
    extras: frozenset[str]
    spec: str
    raw: str


@dataclass
class SuiteJob:
    """A workflow job that runs at least one service's whole test suite."""

    workflow: str
    job: str
    services: set[str] = field(default_factory=set)
    installs: dict[str, Requirement] = field(default_factory=dict)
    invocations: list[str] = field(default_factory=list)
    #: service -> {distribution: exact version}, for a job that installs that
    #: service's committed `poetry.lock` rather than re-resolving its ranges.
    locked: dict[str, dict[str, str]] = field(default_factory=dict)
    #: service -> the interpreter its suite is run with, so "installed the
    #: lock" and "ran the suite against the lock" stay separate claims.
    runners: dict[str, set[str]] = field(default_factory=dict)


@dataclass
class Service:
    runtime: dict[str, str]
    dev: dict[str, str]
    fallbacks: dict[str, list[str]]

    @property
    def declared(self) -> dict[str, str]:
        return {**self.dev, **self.runtime}


# ── Name and version handling ────────────────────────────────────────────────


def canonical(name: str) -> str:
    """PEP 503 normalisation: ``PyJWT``, ``py_jwt`` and ``py-jwt`` are one name."""
    return re.sub(r"[-_.]+", "-", name).strip().lower()


def distribution_for(module: str, declared: set[str]) -> str | None:
    """Which declared distribution provides ``module``.

    Derived first — most import names are the distribution name with the
    separators swapped — then the affixes Python packaging actually uses, then
    the alias table. Resolution is *against the service's declared set* rather
    than against an installed environment, because the whole question is what
    a tree declares, and the gate has to answer it on a machine where none of
    it is installed.
    """
    base = canonical(module)
    for candidate in (
        base,
        IMPORT_ALIASES.get(module, ""),
        f"py{base}",
        f"{base}-python",
        f"python-{base}",
        f"python3-{base}",
        f"{base}-client",
    ):
        if candidate and candidate in declared:
            return candidate
    return None


# The version part tolerates a PEP 440 pre-release or local suffix — four
# manifests here declare `^0.45b0` — because `release()` reduces to the numeric
# prefix anyway. A clause this regex rejects is reported as unparsed, and an
# unparsed specifier is never treated as agreement.
_CLAUSE = re.compile(r"(?P<op>[<>=!~^]+)\s*(?P<ver>[0-9][0-9.*]*[A-Za-z0-9.*+!-]*)")


def release(version: str) -> tuple[int, ...]:
    digits = re.match(r"(\d+(?:\.\d+)*)", version)
    return tuple(int(p) for p in digits.group(1).split(".")) if digits else (0,)


def _pad(left: tuple[int, ...], right: tuple[int, ...]) -> tuple[tuple[int, ...], tuple[int, ...]]:
    width = max(len(left), len(right)) + 1
    return left + (0,) * (width - len(left)), right + (0,) * (width - len(right))


def bounds(spec: str) -> tuple[tuple[int, ...] | None, tuple[int, ...] | None] | None:
    """``spec`` as a half-open ``[low, high)`` release interval, or None.

    Poetry's ``^`` is expanded to the range it means, so ``^0.10.0`` and
    ``>=0.10,<0.11`` compare equal rather than reading as two different pins.
    Returns None for a specifier this function cannot reason about — an
    unparsed specifier is never silently treated as agreement.
    """
    text = spec.replace(" ", "")
    if not text:
        return (None, None)  # unbounded: every release
    if re.fullmatch(r"\d[\w.*+!-]*", text):
        # A bare version in a poetry manifest is an exact pin. `mcp = "1.30.0"`
        # and `mcp==1.30.0` are one constraint written two ways.
        text = f"=={text}"
    low: tuple[int, ...] | None = None
    high: tuple[int, ...] | None = None
    for clause in text.split(","):
        if not clause:
            continue
        match = _CLAUSE.fullmatch(clause)
        if not match:
            return None
        version = release(match.group("ver").rstrip("."))
        operator = match.group("op")
        if operator == "^":
            # Poetry caret: the left-most non-zero component may not change.
            parts = list(version) + [0] * (3 - len(version))
            index = next((i for i, p in enumerate(parts) if p), len(parts) - 1)
            ceiling = tuple(parts[:index] + [parts[index] + 1] + [0] * (len(parts) - index - 1))
            low = version if low is None else max(low, version)
            high = ceiling if high is None else min(high, ceiling)
        elif operator in (">=", "~="):
            low = version if low is None else max(low, version)
        elif operator == ">":
            bumped = version[:-1] + (version[-1] + 1,)
            low = bumped if low is None else max(low, bumped)
        elif operator == "<":
            high = version if high is None else min(high, version)
        elif operator == "<=":
            bumped = version[:-1] + (version[-1] + 1,)
            high = bumped if high is None else min(high, bumped)
        elif operator == "==":
            low = version
            high = version[:-1] + (version[-1] + 1,)
        else:
            return None
    return (low, high)


#: Sentinels for a half-open interval with an open end. An absent lower bound
#: is every release ever published; an absent upper bound is every release yet
#: to be. Written as comparable tuples so the four comparisons below stay
#: ordinary ``<`` and ``>`` — the first version of this used None-handling
#: helpers that conflated "unbounded above" with "lower", and reported eight
#: identical ranges as disagreements.
_FLOOR: tuple[int, ...] = (0,)
_CEILING: tuple[int, ...] = (1 << 30,)


def compare_ranges(ci: str, manifest: str) -> str | None:
    """``None`` when the two ranges are the same interval, else how they differ."""
    if ci.replace(" ", "") == manifest.replace(" ", ""):
        return None  # written identically: no parsing can make them disagree
    left, right = bounds(ci), bounds(manifest)
    if left is None or right is None:
        return "unparsed"
    ci_low, ci_high = left[0] or _FLOOR, left[1] or _CEILING
    mf_low, mf_high = right[0] or _FLOOR, right[1] or _CEILING

    def lt(a: tuple[int, ...], b: tuple[int, ...]) -> bool:
        padded = _pad(a, b)
        return padded[0] < padded[1]

    if not lt(ci_low, mf_high) or not lt(mf_low, ci_high):
        return "disjoint"
    wider = lt(ci_low, mf_low) or lt(mf_high, ci_high)
    narrower = lt(mf_low, ci_low) or lt(ci_high, mf_high)
    if wider and narrower:
        return "ci-shifted"
    if wider:
        return "ci-wider"
    if narrower:
        return "ci-narrower"
    return None


# ── Reading `pip install` out of a workflow ──────────────────────────────────

_TOKEN = re.compile(r"""^["']?(?P<name>[A-Za-z][A-Za-z0-9._-]*)(?P<extras>\[[^\]]*\])?(?P<spec>[<>=!~][^"'\s]*)?["']?$""")

_NOT_A_TOKEN = {
    "pip",
    "python",
    "python3",
    "-m",
    "install",
    "poetry",
    "set",
    "eux",
    "echo",
    "if",
    "then",
    "else",
    "fi",
    "true",
    "&&",
    "||",
    ";",
    ".",
}


def requirements_in(command: str) -> list[Requirement]:
    """Every package token on the ``pip install`` lines of a shell command.

    Comments are stripped before continuations are folded — the install steps
    in this tree carry paragraphs of prose discussing ``pip install``, and
    folding first splices that prose onto the command. Collection stops at the
    first ``&&`` / ``||`` / ``;`` because everything after one is a different
    command.
    """
    body = "\n".join(line for line in command.splitlines() if not line.lstrip().startswith("#"))
    body = re.sub(r"\\\s*\n", " ", body)
    found: list[Requirement] = []
    for line in body.splitlines():
        if "pip install" not in line:
            continue
        tail = re.sub(r"#.*", "", line.split("pip install", 1)[1])
        tail = re.split(r"&&|\|\||;", tail, maxsplit=1)[0]
        skip_next = False
        for token in tail.split():
            if skip_next:
                skip_next = False
                continue
            if token in ("-e", "--editable", "-r", "--requirement", "-c", "--constraint"):
                skip_next = True
                continue
            if not token or token.startswith("-") or token in _NOT_A_TOKEN:
                continue
            match = _TOKEN.match(token)
            if not match:
                continue
            extras = frozenset(
                part.strip().strip("\"'").lower() for part in (match.group("extras") or "").strip("[]").split(",") if part.strip()
            )
            found.append(
                Requirement(
                    canonical(match.group("name")),
                    extras,
                    (match.group("spec") or "").strip(","),
                    token,
                )
            )
    return found


_DERIVED = re.compile(r"service_requirements\.py\s+(?P<args>[^|>\n]*)")


def locked_installs(run: str, root: Path) -> dict[str, dict[str, str]]:
    """Which services this command installs from their committed ``poetry.lock``.

    ``service_requirements.py <name> --locked`` emits that lock's complete
    resolved closure as exact pins, and the workflow feeds it to
    ``pip install --no-deps``, so pip resolves nothing and the set it lands on
    is the set the image ships. Resolving it here means reading the same lock.

    A service name that does not survive as a literal — ``"${svc}"`` from a
    shell loop — resolves to nothing, and a job that installs nothing this
    reader can see is a job this gate would pass while grading an unknown
    version set. So the workflows spell each service out, and
    ``check_locked_installs`` fails any suite whose lock it could not find a
    line for.
    """
    found: dict[str, dict[str, str]] = {}
    for match in _DERIVED.finditer(run):
        if "--locked" not in match.group("args"):
            continue
        args = match.group("args").split()
        groups = "all"
        for index, arg in enumerate(args):
            if arg.strip().strip("\"'") == "--only" and index + 1 < len(args):
                groups = args[index + 1].strip().strip("\"'")
        for arg in args:
            name = arg.strip().strip("\"'()")
            if name.startswith("-") or "$" in name or not name:
                continue
            manifest = root / "services" / name / "pyproject.toml"
            if not manifest.is_file() or not (root / "services" / name / "poetry.lock").is_file():
                continue
            pins: dict[str, str] = {}
            for pin in service_requirements.locked_requirements(manifest, groups):
                package, _, version = pin.split(";")[0].strip().partition("==")
                if version:
                    pins[canonical(package)] = version
            found[name] = pins
    return found


def derived_requirements(run: str, root: Path) -> list[Requirement]:
    """What ``service_requirements.py <names> | xargs pip install`` installs.

    Three jobs now derive their install list from the manifests instead of
    carrying a copy, which is the fix for everything below. A gate that read
    only literal ``pip install`` tokens would see those jobs installing
    nothing and report every guarded import as missing.

    Resolving it by *calling the same producer the workflow calls* is not the
    gate agreeing with itself: what stays falsifiable is which services the
    step names. A job that runs the ueba suite while deriving the api's
    requirements still fails every check below, which is the mistake this
    form makes possible and the hand-written list did not.
    """
    found: list[Requirement] = []
    for match in _DERIVED.finditer(run):
        args = match.group("args").split()
        # Matched against the raw argument text, not against split tokens: the
        # `--system` call is inside a command substitution, so the token
        # arrives as `--system)"` and an equality test on it silently fails.
        flags = match.group("args")
        if "--locked" in flags:
            continue  # `locked_installs` resolves this line to exact pins instead
        if "--system" in flags:
            # Emits apt package names for the native libraries WeasyPrint
            # reaches through ctypes, and they go to `apt-get`. Reading it as
            # a pip install credits the job with installing a set it never
            # installed — which, now that the real install is `--locked`,
            # would have the matrix cells reporting range installs that do
            # not exist.
            continue
        names = [arg.strip().strip("\"'") for arg in args if not arg.startswith("-") and "$" not in arg and arg.strip().strip("\"'")]
        for name in names:
            manifest = root / "services" / name / "pyproject.toml"
            if not manifest.is_file():
                continue
            for requirement in service_requirements.requirements(manifest):
                parsed = _TOKEN.match(requirement)
                if not parsed:
                    continue
                extras = frozenset(part.strip().lower() for part in (parsed.group("extras") or "").strip("[]").split(",") if part.strip())
                found.append(Requirement(canonical(parsed.group("name")), extras, (parsed.group("spec") or "").strip(","), requirement))
    return found


def expand(text: str, env: dict, matrix: dict) -> str:
    """Substitute ``${{ env.X }}`` and ``${{ matrix.X }}`` the way Actions does."""

    def env_value(match: re.Match[str]) -> str:
        value = env.get(match.group(1))
        return str(value) if value is not None else match.group(0)

    def matrix_value(match: re.Match[str]) -> str:
        value = matrix.get(match.group(1))
        return str(value) if value is not None else match.group(0)

    text = re.sub(r"\$\{\{\s*env\.([A-Za-z0-9_]+)\s*\}\}", env_value, text)
    return re.sub(r"\$\{\{\s*matrix\.([A-Za-z0-9_]+)\s*\}\}", matrix_value, text)


def matrix_legs(job: dict, key: str) -> list[str | None]:
    """Every value ``matrix.<key>`` takes, from the list form or from ``include``."""
    matrix = (job.get("strategy") or {}).get("matrix") or {}
    values = matrix.get(key)
    legs = [v for v in values if isinstance(v, str)] if isinstance(values, list) else []
    legs += [inc[key] for inc in matrix.get("include") or [] if isinstance(inc, dict) and isinstance(inc.get(key), str)]
    return list(dict.fromkeys(legs)) or [None]


# ── Which services a job exercises ───────────────────────────────────────────

_SERVICE_PATH = re.compile(r"services/([a-z0-9][a-z0-9-]*)")
_PYTEST_LINE = re.compile(r"\bpytest\b(?P<args>.*)$")


_VENV_RUNNER = re.compile(r"\.venv-(?P<service>[a-z0-9][a-z0-9-]*)/bin/python")


def suite_runner(line: str) -> str:
    """The interpreter a suite line invokes: ``.venv-<service>`` or the default one.

    Installing a lock and running the suite against it are two claims, and a
    job can do the first and not the second — the install step is the easy
    half to get right and the easy half to leave dangling. Keeping them apart
    means ``check_locked_installs`` can say which one is missing.
    """
    match = _VENV_RUNNER.search(line)
    return f".venv-{match.group('service')}" if match else "default"


def whole_suite_targets(run: str, working_directory: str) -> set[str]:
    """Services whose *whole* suite this command collects.

    A directory argument to pytest collects everything beneath it, which is
    the run that claims the service's tests pass. A file argument names what
    it grades, so it is out of scope — the gate would otherwise demand a
    service's full dependency set from a job that deliberately runs one file.

    Only pytest counts. An earlier draft also attributed a service to any job
    that ran a ``scripts/`` gate reaching into that service's tree, which read
    plausibly and was wrong: ``ci.yml:python-lint`` runs forty such gates and
    executes none of the service's own code, and attributing them turned nine
    real findings into 364. A job that imports a service without grading it is
    a question for whichever gate owns that job, not for this one.
    """
    targets: set[str] = set()
    for line in re.sub(r"\\\s*\n", " ", run).splitlines():
        match = _PYTEST_LINE.search(line)
        if not match:
            continue
        directories = [
            arg
            for arg in match.group("args").split()
            if not arg.startswith("-") and not arg.endswith(".py") and re.fullmatch(r"[\w./-]+", arg) and ("/" in arg or arg == "tests")
        ]
        if not directories:
            continue
        found = set(_SERVICE_PATH.findall(working_directory))
        for directory in directories:
            found |= set(_SERVICE_PATH.findall(directory))
        found |= set(re.findall(r"(?:cd|pushd)\s+services/([a-z0-9-]+)", run))
        targets |= found
    return targets


def whole_suite_runs(run: str, working_directory: str) -> dict[str, set[str]]:
    """Service -> the interpreter(s) the command runs its whole suite with."""
    runs: dict[str, set[str]] = {}
    for line in re.sub(r"\\\s*\n", " ", run).splitlines():
        if not _PYTEST_LINE.search(line):
            continue
        for service in whole_suite_targets(line, working_directory) or whole_suite_targets(run, working_directory):
            runs.setdefault(service, set()).add(suite_runner(line))
    return runs


def remember(record: SuiteJob, requirement: Requirement) -> None:
    """Record an install, merging repeats the way pip resolves them.

    Two ``pip install`` steps naming one package do not mean the second wins —
    pip holds both constraints and installs their intersection. Keeping only
    the first made a correct narrow install read as the loose one beside it.
    """
    seen = record.installs.get(requirement.package)
    if seen is None:
        record.installs[requirement.package] = requirement
        return
    if not requirement.spec or requirement.spec in seen.spec:
        return
    merged = ",".join(part for part in (seen.spec, requirement.spec) if part)
    record.installs[requirement.package] = Requirement(
        seen.package, seen.extras | requirement.extras, merged, f"{seen.raw} {requirement.raw}"
    )


def read_workflows(root: Path) -> list[SuiteJob]:
    directory = root / ".github" / "workflows"
    jobs: list[SuiteJob] = []
    for path in sorted(directory.glob("*.yml")) if directory.is_dir() else []:
        try:
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError:
            continue
        if not isinstance(document, dict):
            continue
        workflow_env = document.get("env") or {}
        for job_id, job in (document.get("jobs") or {}).items():
            if not isinstance(job, dict):
                continue
            env = {**workflow_env, **(job.get("env") or {})}
            legs = matrix_legs(job, "service")
            for leg in legs:
                matrix = {"service": leg} if leg else {}
                # One record per matrix leg. A `service:` matrix runs each leg
                # as its own job with its own installs, so unioning them makes
                # eight services look like one and reports ranges as
                # irreconcilable that no single job ever has to reconcile.
                record = SuiteJob(path.name, str(job_id) + (f"[{leg}]" if leg else ""))
                for step in job.get("steps") or []:
                    if not isinstance(step, dict) or not step.get("run"):
                        continue
                    run = expand(str(step["run"]), env, matrix)
                    working_directory = expand(str(step.get("working-directory") or ""), env, matrix)
                    for requirement in requirements_in(run):
                        remember(record, requirement)
                    for requirement in derived_requirements(run, root):
                        remember(record, requirement)
                    record.locked.update(locked_installs(run, root))
                    hit = whole_suite_targets(run, working_directory)
                    if hit:
                        record.services |= hit
                        record.invocations.append(run.strip().splitlines()[-1][:90])
                        for service, runners in whole_suite_runs(run, working_directory).items():
                            record.runners.setdefault(service, set()).update(runners)
                # `${{ env.API_DEPS }}` reaches pip as arguments; the folded
                # scalar that defines it is an install path even though no
                # `pip install` appears on its lines.
                for key, value in env.items():
                    if key.endswith("DEPS") and isinstance(value, str):
                        for requirement in requirements_in("pip install " + value):
                            remember(record, requirement)
                if record.services and (record.installs or record.locked):
                    jobs.append(record)
    return jobs


# ── Reading a service ────────────────────────────────────────────────────────


def _dependency_table(table: dict) -> tuple[dict[str, str], dict[str, str]]:
    """Split a poetry dependency table into (always installed, optional).

    ``optional = true`` means an extra is the only thing that pulls the
    package in, and the Dockerfiles run ``poetry install --only main --no-root``
    with no ``--extras`` — so the image does **not** have it. Reading such a
    dependency as runtime says "production always has this", which inverts the
    question every check below asks. ``services/agents`` declares
    ``weasyprint = {version = ">=62,<71", optional = true}`` and guards the
    import; demanding CI install it would be demanding CI grade a path the
    image cannot take.
    """
    always: dict[str, str] = {}
    optional: dict[str, str] = {}
    for name, spec in (table or {}).items():
        if name == "python":
            continue
        is_optional = False
        if isinstance(spec, dict):
            is_optional = bool(spec.get("optional"))
            spec = spec.get("version", "")
        if isinstance(spec, str):
            (optional if is_optional else always)[canonical(name)] = spec.strip()
    return always, optional


def _handles_import_error(node: ast.Try) -> bool:
    for handler in node.handlers:
        declared = handler.type
        names = (
            [declared.id]
            if isinstance(declared, ast.Name)
            else [e.id for e in declared.elts if isinstance(e, ast.Name)]
            if isinstance(declared, ast.Tuple)
            else []
        )
        if any(name in {"ImportError", "ModuleNotFoundError"} for name in names):
            return True
    return False


def guarded_imports(service_dir: Path, root: Path) -> dict[str, list[str]]:
    """Top-level modules imported inside a ``try`` whose handler catches ImportError."""
    found: dict[str, list[str]] = {}
    app = service_dir / "app"
    for source in sorted(app.rglob("*.py")) if app.is_dir() else []:
        try:
            tree = ast.parse(source.read_text(encoding="utf-8", errors="ignore"))
        except (SyntaxError, OSError):
            continue
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Try) and _handles_import_error(node)):
                continue
            for statement in ast.walk(ast.Module(body=node.body, type_ignores=[])):
                modules: list[str] = []
                if isinstance(statement, ast.Import):
                    modules = [alias.name.split(".")[0] for alias in statement.names]
                elif isinstance(statement, ast.ImportFrom) and statement.module and statement.level == 0:
                    modules = [statement.module.split(".")[0]]
                for module in modules:
                    if module in STDLIB or module in NOT_A_DISTRIBUTION:
                        continue
                    where = f"{source.relative_to(root).as_posix()}:{node.lineno}"
                    found.setdefault(module, []).append(where)
    return found


_PEP508 = re.compile(r"""^\s*(?P<name>[A-Za-z][A-Za-z0-9._-]*)(?P<extras>\[[^\]]*\])?\s*(?P<spec>[^;#]*)""")


def _pep621_table(entries: list) -> dict[str, str]:
    """PEP 621 ``dependencies = ["fastapi>=0.117,<0.142", ...]``.

    Ten services in this tree declare dependencies through poetry's table and
    three — ``honeytokens``, ``purple-team``, ``ueba`` — through this one. A
    reader that knew only the first saw those three as declaring *nothing*,
    which made every package their jobs installed look undeclared and made
    every guarded import look unresolvable. "Cannot read this file" and "this
    file is empty" have to be different answers.
    """
    out: dict[str, str] = {}
    for entry in entries or []:
        if not isinstance(entry, str):
            continue
        match = _PEP508.match(entry)
        if match and match.group("name"):
            out[canonical(match.group("name"))] = match.group("spec").strip()
    return out


def read_services(root: Path) -> dict[str, Service]:
    services: dict[str, Service] = {}
    unreadable: list[str] = []
    for manifest in sorted(root.glob("services/*/pyproject.toml")):
        try:
            data = tomllib.loads(manifest.read_text(encoding="utf-8"))
        except (tomllib.TOMLDecodeError, OSError):
            unreadable.append(manifest.parent.name)
            continue
        poetry = data.get("tool", {}).get("poetry", {})
        project = data.get("project", {})
        dev: dict[str, str] = {}
        for group in (poetry.get("group") or {}).values():
            group_always, group_optional = _dependency_table(group.get("dependencies", {}))
            dev.update(group_always)
            dev.update(group_optional)
        for extra in (project.get("optional-dependencies") or {}).values():
            dev.update(_pep621_table(extra))
        # An `optional = true` runtime dependency is declared, so it still
        # resolves a guarded import to a distribution — but it is not
        # something the image always has, so it belongs beside the dev group
        # rather than in `runtime`.
        main_always, main_optional = _dependency_table(poetry.get("dependencies", {}))
        dev.update(main_optional)
        runtime = {**main_always, **_pep621_table(project.get("dependencies"))}
        if not runtime and not dev:
            unreadable.append(manifest.parent.name)
            continue
        services[manifest.parent.name] = Service(runtime=runtime, dev=dev, fallbacks=guarded_imports(manifest.parent, root))
    if unreadable:
        raise SystemExit(
            "check_ci_install_parity: "
            + ", ".join(f"services/{name}/pyproject.toml" for name in unreadable)
            + " declared no dependency this gate could read. A manifest style it does not understand reads as "
            "a service with no dependencies, which makes every comparison below agree with nothing."
        )
    return services


# ── Guarded imports that are optional on purpose ─────────────────────────────
#
# A module imported behind `except ImportError` and declared by no manifest is
# optional *by omission*: production does not have it either, so the fallback
# is the contract and CI grading it is correct. That is a legitimate state and
# the gate must not demand an install for it.
#
# But "no declared dependency provides this" is also what a *misnamed* import
# looks like, and the two have to be told apart or the backstop that keeps
# `sigma -> pysigma` honest is a backstop with a hole. So each one is named
# here with why, and the list is checked in both directions: an entry whose
# service no longer guards that import, or whose package the manifest has
# since declared, fails rather than sitting there looking like coverage.
OPTIONAL_BY_OMISSION: dict[tuple[str, str], str] = {
    ("actions", "boto3"): (
        "`_boto3_available()` is a capability probe — the AWS security-group "
        "client reports the arm unavailable rather than failing, and the "
        "manifest deliberately does not carry the SDK"
    ),
    ("api", "httpx_ws"): "the graph WebSocket client is an opt-in transport nothing in the default deployment dials",
    ("api", "reportlab"): "a second PDF backend behind WeasyPrint, reached only when a caller asks for it",
}


# ── Declared exemptions ──────────────────────────────────────────────────────
#
# A package CI genuinely cannot install belongs here with the reason, not in
# silence. Checked in both directions: an entry naming a package that is now
# installed, or a service that no longer guards it, fails the build rather
# than sitting there looking like coverage.
EXEMPT: dict[tuple[str, str], str] = {}


# ── The checks ───────────────────────────────────────────────────────────────


def check_fallbacks(jobs: list[SuiteJob], services: dict[str, Service]) -> tuple[list[str], list[str]]:
    """fallback -> ci, and the unresolved-module backstop that keeps it honest."""
    problems: list[str] = []
    unresolved: list[str] = []
    for job in jobs:
        for name in sorted(job.services):
            service = services.get(name)
            if service is None:
                continue
            runtime = set(service.runtime)
            for module, sites in sorted(service.fallbacks.items()):
                distribution = distribution_for(module, runtime | set(service.dev))
                if distribution is None:
                    if (name, module) in OPTIONAL_BY_OMISSION:
                        continue
                    unresolved.append(
                        f"services/{name}: `import {module}` is guarded by `except ImportError` at {sites[0]} "
                        f"but no declared dependency provides it. If that is deliberate, record it in "
                        f"OPTIONAL_BY_OMISSION with the reason; if the distribution is simply named differently, "
                        f"add it to IMPORT_ALIASES — a guarded import resolving to nothing is how this gate "
                        f"would go quiet about the defect it exists for"
                    )
                    continue
                if distribution not in runtime:
                    continue  # optional by declaration: the fallback is the contract
                if distribution in job.installs:
                    continue
                # Installed from the service's own lock, which is the set the
                # image ships. `check_locked_installs` asks the same question
                # of the lock, so a lock genuinely missing it is still caught.
                if distribution in job.locked.get(name, {}):
                    continue
                if (name, distribution) in EXEMPT:
                    continue
                problems.append(
                    f"{job.workflow}:{job.job} runs the whole services/{name} suite but does not install "
                    f"`{distribution}` — services/{name}/pyproject.toml declares it as a runtime dependency, so every "
                    f"image has it, and {sites[0]} handles its absence with `except ImportError`. CI grades the "
                    f"fallback; production grades the real path (fallback -> ci, {len(sites)} guarded site(s))"
                )
    return problems, sorted(set(unresolved))


def check_locked_installs(jobs: list[SuiteJob], services: dict[str, Service], root: Path) -> list[str]:
    """lock -> ci: grade the version set the image ships, not one inside its ranges.

    Deriving CI's install list from the manifests removed the hand-written
    copy, but a *range* still re-resolves at install time, so CI could land on
    a different patch release than the image. That is not hypothetical: the
    defect this direction exists for had ``services/api`` declaring
    ``opentelemetry-instrumentation-fastapi = "^0.45b0"`` and locking 0.45b0,
    while the job installed it with no bound at all, resolved 0.66b0 and
    passed — CI graded a version the image did not contain, and the one the
    image contained could not serve a request.

    So: a whole-suite job for a service with a committed lock must install
    that lock, and must run that service's suite with the interpreter it
    installed it into. The two are checked separately because a job can do
    the first and not the second, and then the pins are sitting in a
    virtualenv nothing uses.

    Three further conditions, because a pin is only parity if it is a pin of
    the right thing:

    * The locked version must satisfy the range its own manifest declares. A
      lock that has drifted from its manifest is a lock pinning something the
      service no longer permits.
    * The lock must contain every runtime distribution whose absence the
      service's own code handles with ``except ImportError`` — the pysigma
      shape, asked of the lock rather than of a list.
    * A service with **no** lock is reported as the exception it is, named,
      rather than passing silently.
    """
    problems: list[str] = []
    for job in jobs:
        for name in sorted(job.services):
            service = services.get(name)
            if service is None:
                continue
            lock = root / "services" / name / "poetry.lock"
            if not lock.is_file():
                problems.append(
                    f"{job.workflow}:{job.job} runs the whole services/{name} suite and services/{name} has no "
                    f"poetry.lock, so there is no resolved set to install — CI necessarily re-resolves and the "
                    f"version it grades is not guaranteed to be the version the image ships (lock -> ci, no lock)"
                )
                continue
            pins = job.locked.get(name)
            if pins is None:
                problems.append(
                    f"{job.workflow}:{job.job} runs the whole services/{name} suite but does not install "
                    f"services/{name}/poetry.lock — it re-resolves inside the declared ranges, so the versions it "
                    f"grades need not be the versions services/{name}/Dockerfile installs. Install with "
                    f"`service_requirements.py {name} --locked` (lock -> ci)"
                )
                continue

            runners = job.runners.get(name, set())
            if runners and runners != {f".venv-{name}"}:
                problems.append(
                    f"{job.workflow}:{job.job} installs services/{name}/poetry.lock but runs that suite with "
                    f"{', '.join(sorted(runners))} rather than .venv-{name} — the pins are installed into an "
                    f"interpreter the tests do not use (lock -> ci, unused environment)"
                )

            for package, version in sorted(pins.items()):
                declared = service.declared.get(package)
                if declared is None:
                    continue
                interval = bounds(declared)
                if interval is None:
                    continue
                low, high = interval[0] or _FLOOR, interval[1] or _CEILING
                pinned = release(version)
                if _pad(pinned, low)[0] < _pad(pinned, low)[1] or not _pad(pinned, high)[0] < _pad(pinned, high)[1]:
                    problems.append(
                        f"services/{name}/poetry.lock pins `{package}` {version}, which its own manifest "
                        f"({declared}) does not permit — the lock and the manifest have drifted, so installing "
                        f"the lock installs something the service forbids (lock -> ci, lock outside manifest)"
                    )

            for module, sites in sorted(service.fallbacks.items()):
                distribution = distribution_for(module, set(service.declared))
                if distribution is None or distribution not in service.runtime:
                    continue
                if distribution in pins or (name, distribution) in EXEMPT:
                    continue
                problems.append(
                    f"{job.workflow}:{job.job} installs services/{name}/poetry.lock, but that lock does not "
                    f"contain `{distribution}` — services/{name} declares it as a runtime dependency and "
                    f"{sites[0]} handles its absence with `except ImportError`, so the suite grades the fallback "
                    f"(lock -> ci, guarded dependency absent from the lock)"
                )
    return problems


def check_installs_are_declared(jobs: list[SuiteJob], services: dict[str, Service]) -> list[str]:
    """ci -> manifest: a package no service in the job declares."""
    problems: list[str] = []
    for job in jobs:
        declared: set[str] = set()
        for name in job.services:
            service = services.get(name)
            if service:
                declared |= set(service.declared)
        for package, requirement in sorted(job.installs.items()):
            if package in declared or package in TOOLING:
                continue
            problems.append(
                f"{job.workflow}:{job.job} installs `{requirement.raw}`, which none of the services it runs "
                f"({', '.join(sorted(job.services))}) declares — CI is grading a code path that cannot exist in "
                f"production (ci -> manifest)"
            )
    return problems


def check_ranges(jobs: list[SuiteJob], services: dict[str, Service]) -> list[str]:
    """The range direction, against the intersection rather than each service alone.

    One install step often serves several services — ``python-test`` runs the
    API and the agents suites, ``python-services-test`` runs three. The version
    such a job installs has to satisfy *every* one of them, so the thing to
    compare against is the intersection of what they declare, not each range
    in turn. Comparing one at a time reports a correct narrow install as a
    finding against whichever service declared the looser range, which is how
    a gate earns the reputation that makes people stop reading it.

    Doing it this way also surfaces something per-service comparison cannot
    say at all: when the services in one job declare ranges with **no version
    in common**, no single install can serve them. Three packages in the
    wave-2 job were in that state.
    """
    problems: list[str] = []
    for job in jobs:
        for package, requirement in sorted(job.installs.items()):
            declaring = {name: services[name].declared[package] for name in sorted(job.services) if package in services[name].declared}
            if not declaring:
                continue

            low: tuple[int, ...] | None = None
            high: tuple[int, ...] | None = None
            unparsed: list[str] = []
            for name, spec in declaring.items():
                interval = bounds(spec)
                if interval is None:
                    unparsed.append(name)
                    continue
                if interval[0] is not None:
                    low = interval[0] if low is None or _pad(interval[0], low)[0] > _pad(interval[0], low)[1] else low
                if interval[1] is not None:
                    high = interval[1] if high is None or _pad(interval[1], high)[0] < _pad(interval[1], high)[1] else high
            where = ", ".join(f"services/{n} {s or '(unbounded)'}" for n, s in declaring.items())

            if low is not None and high is not None and _pad(low, high)[0] >= _pad(low, high)[1]:
                problems.append(
                    f"{job.workflow}:{job.job} runs services that cannot agree about `{package}` — {where}. "
                    f"No version satisfies all of them, so one install path cannot serve this job: either the "
                    f"manifests converge or the job installs per service (range, empty intersection)"
                )
                continue
            if unparsed:
                problems.append(
                    f"{job.workflow}:{job.job}: `{package}` is declared by {', '.join(unparsed)} in a form this gate "
                    f"cannot compare ({where}) — an unreadable specifier is not agreement (range, unparsed)"
                )
                continue

            intersection = ",".join(
                part for part in (f">={'.'.join(map(str, low))}" if low else "", f"<{'.'.join(map(str, high))}" if high else "") if part
            )
            if not requirement.spec and intersection:
                problems.append(
                    f"{job.workflow}:{job.job} installs `{package}` with no version bound while {where} — an "
                    f"unbounded install permits every release ever published, including the ones a bound exists to "
                    f"exclude (range, ci-unbounded)"
                )
                continue
            verdict = compare_ranges(requirement.spec, intersection)
            if verdict is None:
                continue
            detail = {
                "disjoint": "no version satisfies both, so CI cannot be testing what ships",
                "ci-wider": "CI admits versions a service this job runs forbids",
                "ci-narrower": "versions that ship are never exercised by this job",
                "ci-shifted": "each admits versions the other forbids",
                "unparsed": "the two specifiers could not be compared and are not identical",
            }[verdict]
            problems.append(
                f"{job.workflow}:{job.job} installs `{package}` {requirement.spec or '(unbounded)'} while the "
                f"services it runs together admit {intersection or '(unbounded)'} ({where}) — {verdict}: {detail} (range)"
            )
    return problems


def check_exemptions(jobs: list[SuiteJob], services: dict[str, Service]) -> list[str]:
    """An exemption that no longer describes anything is a hole, not coverage."""
    problems: list[str] = []
    for (name, module), reason in sorted(OPTIONAL_BY_OMISSION.items()):
        service = services.get(name)
        if service is None:
            problems.append(f"OPTIONAL_BY_OMISSION names services/{name}, which does not exist (exemption)")
            continue
        if module not in service.fallbacks:
            problems.append(
                f"OPTIONAL_BY_OMISSION[{name}, {module}] says {reason!r} but services/{name} no longer guards "
                f"that import — remove the entry (exemption)"
            )
            continue
        if distribution_for(module, set(service.declared)) is not None:
            problems.append(
                f"OPTIONAL_BY_OMISSION[{name}, {module}] says it is undeclared, but services/{name} now declares "
                f"a package providing it — remove the entry so the fallback direction covers it again (exemption)"
            )
    for (name, distribution), reason in sorted(EXEMPT.items()):
        service = services.get(name)
        if service is None:
            problems.append(f"EXEMPT names services/{name}, which does not exist (exemption)")
            continue
        guards = {distribution_for(module, set(service.declared)) for module in service.fallbacks}
        if distribution not in guards:
            problems.append(
                f"EXEMPT[{name}, {distribution}] says {reason!r} but services/{name} no longer guards that import — "
                f"remove the entry (exemption)"
            )
            continue
        if all(distribution in job.installs for job in jobs if name in job.services):
            problems.append(
                f"EXEMPT[{name}, {distribution}] says {reason!r} but every job running that suite now installs it — "
                f"remove the entry (exemption)"
            )
    return problems


# ── Runner ───────────────────────────────────────────────────────────────────


def run(root: Path, *, inventory: bool = False, as_json: bool = False) -> tuple[int, list[str]]:
    workflows = root / ".github" / "workflows"
    if not workflows.is_dir() or not (root / "services").is_dir():
        print(
            f"check_ci_install_parity: {root} has no .github/workflows and services/ to compare — refusing to report a verdict",
            file=sys.stderr,
        )
        return 2, []

    services = read_services(root)
    jobs = read_workflows(root)

    if not services:
        print(f"check_ci_install_parity: found no service manifest under {root}/services — refusing a vacuous pass", file=sys.stderr)
        return 2, []
    if not jobs:
        print(
            f"check_ci_install_parity: no workflow job under {root}/.github/workflows runs a service's whole test suite. "
            f"Either the services are ungated or this gate can no longer read the workflows — refusing a vacuous pass",
            file=sys.stderr,
        )
        return 2, []

    fallback_problems, unresolved = check_fallbacks(jobs, services)
    problems = (
        fallback_problems
        + unresolved
        + check_locked_installs(jobs, services, root)
        + check_installs_are_declared(jobs, services)
        + check_ranges(jobs, services)
        + check_exemptions(jobs, services)
    )

    if as_json:
        print(
            json.dumps(
                {
                    "jobs": [
                        {"workflow": j.workflow, "job": j.job, "services": sorted(j.services), "installs": sorted(j.installs)} for j in jobs
                    ],
                    "problems": problems,
                },
                indent=2,
            )
        )
        return (1 if problems else 0), problems

    guarded = sum(len(s.fallbacks) for s in services.values())
    graded = {s for j in jobs for s in j.services}
    from_lock = {(j.workflow, j.job, s) for j in jobs for s in j.services if s in j.locked}
    total_suites = {(j.workflow, j.job, s) for j in jobs for s in j.services}
    print(f"check_ci_install_parity: root {root}")
    print(f"  {len(jobs)} whole-suite job(s) over {len(graded)} of {len(services)} service(s); {guarded} guarded import(s) across the tree")
    print(f"  {len(from_lock)} of {len(total_suites)} suite run(s) install the service's committed poetry.lock")
    if inventory:
        for job in jobs:
            print(f"  {job.workflow}:{job.job}")
            print(f"      services : {', '.join(sorted(job.services))}")
            print(f"      installs : {len(job.installs)} package(s) from declared ranges")
            for locked_name, pins in sorted(job.locked.items()):
                runner = ", ".join(sorted(job.runners.get(locked_name, {"?"})))
                print(f"      locked   : services/{locked_name} -> {len(pins)} exact pin(s), run by {runner}")
            for line in job.invocations:
                print(f"      runs     : {line}")
        for name, service in sorted(services.items()):
            if not service.fallbacks:
                continue
            resolved = {m: distribution_for(m, set(service.declared)) for m in service.fallbacks}
            runtime = [d for d in resolved.values() if d in service.runtime]
            print(f"  services/{name}: {len(service.fallbacks)} guarded import(s), {len(runtime)} of them runtime dependencies")
            for module, sites in sorted(service.fallbacks.items()):
                kind = "runtime" if resolved[module] in service.runtime else ("dev/undeclared" if resolved[module] else "UNRESOLVED")
                print(f"      {module:22s} -> {str(resolved[module]):28s} [{kind}] {sites[0]}")

    if problems:
        print(f"check_ci_install_parity: FAIL — {len(problems)} divergence(s)")
        for problem in problems:
            print(f"  - {problem}")
        return 1, problems
    print("check_ci_install_parity: OK")
    return 0, problems


# ── Self-test ────────────────────────────────────────────────────────────────


def _fixture(root: Path) -> None:
    """A miniature tree that passes, for each injection below to break."""
    (root / ".github" / "workflows").mkdir(parents=True)
    (root / "scripts").mkdir(parents=True, exist_ok=True)
    service = root / "services" / "demo"
    (service / "app").mkdir(parents=True)
    (service / "tests").mkdir(parents=True)
    (service / "pyproject.toml").write_text(
        '[tool.poetry]\nname = "demo"\nversion = "0.1.0"\n\n'
        '[tool.poetry.dependencies]\npython = "^3.11"\n'
        'pysigma = ">=0.11.17,<0.12"\nhttpx = ">=0.27,<0.29"\n\n'
        '[tool.poetry.group.dev.dependencies]\npytest = ">=9.0.3,<10.0"\n',
        encoding="utf-8",
    )
    (service / "app" / "engine.py").write_text(
        "def run():\n    try:\n        import sigma\n    except ImportError:\n        return []\n    return sigma.everything()\n",
        encoding="utf-8",
    )
    # The lock is what the image installs, so it is what CI must install.
    (service / "poetry.lock").write_text(
        '[[package]]\nname = "pysigma"\nversion = "0.11.31"\ngroups = ["main"]\noptional = false\n\n'
        '[[package]]\nname = "httpx"\nversion = "0.28.1"\ngroups = ["main"]\noptional = false\n\n'
        '[[package]]\nname = "pytest"\nversion = "9.1.1"\ngroups = ["dev"]\noptional = false\n\n'
        '[metadata]\nlock-version = "2.1"\n',
        encoding="utf-8",
    )
    # Two install paths, as `ci.yml:python-test` really has: a derived-range
    # install serving the repository's own gate suites, which are not a
    # service and have no lock, and the service's locked set in its own
    # virtualenv. Keeping both in the fixture is what lets the range cases
    # and the lock cases below aim at different lines.
    (root / ".github" / "workflows" / "ci.yml").write_text(
        "name: CI\n"
        "jobs:\n"
        "  demo:\n"
        "    steps:\n"
        '      - run: pip install "pysigma>=0.11.17,<0.12" "httpx>=0.27,<0.29" "pytest>=9.0.3,<10.0"\n'
        "      - run: |\n"
        "          python3 -m venv .venv-demo\n"
        "          python3 scripts/service_requirements.py demo --locked > /tmp/demo.lock.txt\n"
        "          .venv-demo/bin/pip install --no-deps -r /tmp/demo.lock.txt\n"
        "      - working-directory: services/demo\n"
        "        run: ../../.venv-demo/bin/python -m pytest tests/ -v\n",
        encoding="utf-8",
    )
    # A second job that names one test file. It is out of scope by design, so
    # it exists in the clean fixture to give the control cases something to
    # aim at — otherwise "the narrow job is ignored" and "the gate found no
    # job at all" are the same observation.
    (root / ".github" / "workflows" / "narrow.yml").write_text(
        "name: Narrow\n"
        "jobs:\n"
        "  one-file:\n"
        "    steps:\n"
        '      - run: pip install "httpx>=0.27,<0.29"\n'
        "      - working-directory: services/demo\n"
        "        run: python -m pytest tests/test_one.py -v\n",
        encoding="utf-8",
    )


def self_test() -> int:
    import shutil
    import tempfile

    def build(mutate=None) -> tuple[int, list[str]]:
        temp = Path(tempfile.mkdtemp(prefix="ci_parity_selftest_"))
        try:
            _fixture(temp)
            if mutate:
                mutate(temp)
            return run(temp)
        finally:
            shutil.rmtree(temp, ignore_errors=True)

    workflow = lambda root: root / ".github" / "workflows" / "ci.yml"  # noqa: E731
    manifest = lambda root: root / "services" / "demo" / "pyproject.toml"  # noqa: E731

    _LOCKED_STEP = (
        "          python3 scripts/service_requirements.py demo --locked > /tmp/demo.lock.txt\n"
        "          .venv-demo/bin/pip install --no-deps -r /tmp/demo.lock.txt\n"
    )

    def unlock(root: Path) -> None:
        """Put the job back on a re-resolved install, as it was before the lock.

        The `fallback -> ci` and attribution cases below are about a job whose
        environment comes from a *list*. Once the lock is installed the list
        stops mattering — the lock has pysigma whatever the list says — so
        injecting into the list alone proves nothing. These cases have to
        reproduce the world they were written for.
        """
        path = workflow(root)
        path.write_text(path.read_text().replace(_LOCKED_STEP, ""), encoding="utf-8")

    def drop_the_guarded_runtime_dependency(root: Path) -> None:
        """The pysigma defect: the image has it, CI does not, the code falls back."""
        unlock(root)
        path = workflow(root)
        path.write_text(path.read_text().replace('"pysigma>=0.11.17,<0.12" ', ""), encoding="utf-8")

    def install_something_no_service_declares(root: Path) -> None:
        path = workflow(root)
        path.write_text(path.read_text().replace("pip install ", "pip install requests "), encoding="utf-8")

    def make_the_services_unable_to_agree(root: Path) -> None:
        """Two services in one job declaring ranges with no version in common."""
        second = root / "services" / "other"
        (second / "app").mkdir(parents=True)
        (second / "pyproject.toml").write_text(
            '[tool.poetry]\nname = "other"\nversion = "0.1.0"\n\n[tool.poetry.dependencies]\npython = "^3.11"\nhttpx = "^0.26.0"\n',
            encoding="utf-8",
        )
        path = workflow(root)
        path.write_text(
            path.read_text() + "      - run: python -m pytest services/other/tests/ -v\n",
            encoding="utf-8",
        )

    def make_the_ranges_disjoint(root: Path) -> None:
        """The cryptography shape: CI cannot possibly be testing what ships."""
        path = workflow(root)
        path.write_text(path.read_text().replace('"httpx>=0.27,<0.29"', '"httpx>=0.24,<0.26"'), encoding="utf-8")

    def drop_every_version_bound(root: Path) -> None:
        """An unbounded install permits every release ever published."""
        path = workflow(root)
        path.write_text(path.read_text().replace('"httpx>=0.27,<0.29"', "httpx"), encoding="utf-8")

    def widen_the_ci_range(root: Path) -> None:
        path = workflow(root)
        path.write_text(path.read_text().replace('"pytest>=9.0.3,<10.0"', '"pytest>=7.4,<10"'), encoding="utf-8")

    def narrow_the_ci_range(root: Path) -> None:
        path = workflow(root)
        path.write_text(path.read_text().replace('"httpx>=0.27,<0.29"', '"httpx>=0.27,<0.28"'), encoding="utf-8")

    def guard_a_module_nothing_provides(root: Path) -> None:
        """An unresolvable fallback must fail rather than be skipped."""
        path = root / "services" / "demo" / "app" / "other.py"
        path.write_text("try:\n    import zzznotapackage\nexcept ImportError:\n    pass\n", encoding="utf-8")

    def reach_the_service_by_cd_instead_of_working_directory(root: Path) -> None:
        """`cd services/x && pytest tests/` is the other shape in this tree.

        `ci.yml`'s agents step is written that way, so an attribution that
        only understood `working-directory:` would miss the suite that found
        the defect this gate exists for.
        """
        unlock(root)
        path = workflow(root)
        path.write_text(
            path.read_text()
            .replace('"pysigma>=0.11.17,<0.12" ', "")
            .replace(
                "      - working-directory: services/demo\n        run: ../../.venv-demo/bin/python -m pytest tests/ -v\n",
                "      - run: |\n          cd services/demo\n          python -m pytest tests/ -v\n",
            ),
            encoding="utf-8",
        )

    def break_only_the_narrow_job(root: Path) -> None:
        """A job naming one test file is out of scope, so nothing here is a finding.

        Both directions are injected at once — a disjoint range and a package
        no service declares — because a control that only proves one of them is
        ignored would let the other quietly become a false positive.
        """
        path = root / ".github" / "workflows" / "narrow.yml"
        path.write_text(path.read_text().replace('"httpx>=0.27,<0.29"', 'requests "httpx>=0.20,<0.21"'), encoding="utf-8")

    def declare_the_guarded_package_optional(root: Path) -> None:
        """A dev-group dependency is genuinely optional: the fallback is the contract."""
        path = manifest(root)
        path.write_text(
            path.read_text()
            .replace('pysigma = ">=0.11.17,<0.12"\n', "")
            .replace("[tool.poetry.group.dev.dependencies]\n", '[tool.poetry.group.dev.dependencies]\npysigma = ">=0.11.17,<0.12"\n'),
            encoding="utf-8",
        )
        workflow_path = workflow(root)
        workflow_path.write_text(workflow_path.read_text().replace('"pysigma>=0.11.17,<0.12" ', ""), encoding="utf-8")

    def caret_and_explicit_range_are_the_same_range(root: Path) -> None:
        """`^0.27.0` and `>=0.27,<0.28` are one range written two ways.

        Both spellings are in this tree. A gate that read them as a
        disagreement would fail thirty honest install paths on notation and
        teach people to stop reading it.
        """
        path = manifest(root)
        path.write_text(path.read_text().replace('httpx = ">=0.27,<0.29"', 'httpx = "^0.27.0"'), encoding="utf-8")
        workflow_path = workflow(root)
        workflow_path.write_text(workflow_path.read_text().replace('"httpx>=0.27,<0.29"', '"httpx>=0.27,<0.28"'), encoding="utf-8")
        narrow = root / ".github" / "workflows" / "narrow.yml"
        narrow.write_text(narrow.read_text().replace('"httpx>=0.27,<0.29"', '"httpx>=0.27,<0.28"'), encoding="utf-8")
        # The lock has to move with the manifest, or this control injects a
        # second, genuine divergence and stops being a control.
        lock = root / "services" / "demo" / "poetry.lock"
        lock.write_text(
            lock.read_text().replace('name = "httpx"\nversion = "0.28.1"', 'name = "httpx"\nversion = "0.27.2"'), encoding="utf-8"
        )

    def stale_exemption(root: Path) -> None:
        EXEMPT[("demo", "httpx")] = "no reason that is still true"

    # ── The lock direction ──────────────────────────────────────────────────

    def re_resolve_instead_of_installing_the_lock(root: Path) -> None:
        """The defect this direction exists for, one notch smaller than the last.

        The job still derives its list from the manifest, so every earlier
        check passes — but it re-resolves inside the declared ranges, so the
        version it grades need not be the version the image ships.
        `^0.45b0` locking 0.45b0 while CI resolved 0.66b0 is exactly this.
        """
        path = workflow(root)
        path.write_text(
            path.read_text().replace(
                "          python3 scripts/service_requirements.py demo --locked > /tmp/demo.lock.txt\n"
                "          .venv-demo/bin/pip install --no-deps -r /tmp/demo.lock.txt\n",
                "          python3 scripts/service_requirements.py demo | xargs .venv-demo/bin/pip install\n",
            ),
            encoding="utf-8",
        )

    def install_the_lock_but_run_the_suite_elsewhere(root: Path) -> None:
        """Pins installed into a virtualenv the tests do not use."""
        path = workflow(root)
        path.write_text(path.read_text().replace("../../.venv-demo/bin/python -m pytest", "python -m pytest"), encoding="utf-8")

    def lock_drifts_outside_its_manifest(root: Path) -> None:
        """A pin the service's own manifest no longer permits."""
        path = root / "services" / "demo" / "poetry.lock"
        path.write_text(
            path.read_text().replace('name = "pysigma"\nversion = "0.11.31"', 'name = "pysigma"\nversion = "0.13.0"'), encoding="utf-8"
        )

    def lock_omits_a_guarded_runtime_dependency(root: Path) -> None:
        """The pysigma shape, asked of the lock rather than of a hand-written list."""
        path = root / "services" / "demo" / "poetry.lock"
        path.write_text(
            path.read_text().replace('[[package]]\nname = "pysigma"\nversion = "0.11.31"\ngroups = ["main"]\noptional = false\n\n', ""),
            encoding="utf-8",
        )

    def remove_the_lock_entirely(root: Path) -> None:
        """No lock is an exception to be named, not one to pass silently."""
        (root / "services" / "demo" / "poetry.lock").unlink()
        path = workflow(root)
        path.write_text(
            path.read_text().replace(
                "          python3 scripts/service_requirements.py demo --locked > /tmp/demo.lock.txt\n"
                "          .venv-demo/bin/pip install --no-deps -r /tmp/demo.lock.txt\n",
                "",
            ),
            encoding="utf-8",
        )

    def declare_the_guarded_package_optional_in_the_manifest(root: Path) -> None:
        """`optional = true` means the image does not have it either.

        `services/agents` declares WeasyPrint that way. Reading it as a
        runtime dependency would demand CI install something no image ships,
        and grade a path production cannot take — the guarded-import defect
        pointing the wrong way. So this must NOT be reported.
        """
        path = manifest(root)
        path.write_text(
            path.read_text().replace('pysigma = ">=0.11.17,<0.12"', 'pysigma = { version = ">=0.11.17,<0.12", optional = true }'),
            encoding="utf-8",
        )
        workflow_path = workflow(root)
        workflow_path.write_text(workflow_path.read_text().replace('"pysigma>=0.11.17,<0.12" ', ""), encoding="utf-8")
        lock = root / "services" / "demo" / "poetry.lock"
        lock.write_text(
            lock.read_text().replace(
                'name = "pysigma"\nversion = "0.11.31"\ngroups = ["main"]\noptional = false',
                'name = "pysigma"\nversion = "0.11.31"\ngroups = ["main"]\noptional = true',
            ),
            encoding="utf-8",
        )

    cases: list[tuple[str, object, str | None]] = [
        ("clean fixture passes", None, None),
        ("guarded runtime dependency missing from CI", drop_the_guarded_runtime_dependency, "fallback -> ci"),
        ("CI installs what no service declares", install_something_no_service_declares, "ci -> manifest"),
        ("ranges are disjoint", make_the_ranges_disjoint, "disjoint"),
        ("the services in one job cannot agree", make_the_services_unable_to_agree, "empty intersection"),
        ("an install with no version bound", drop_every_version_bound, "ci-unbounded"),
        ("CI range wider than the manifest", widen_the_ci_range, "ci-wider"),
        ("CI range narrower than the manifest", narrow_the_ci_range, "ci-narrower"),
        ("a guarded import nothing provides", guard_a_module_nothing_provides, "no declared dependency provides it"),
        ("attribution through `cd` rather than working-directory", reach_the_service_by_cd_instead_of_working_directory, "fallback -> ci"),
        ("a stale exemption", stale_exemption, "exemption"),
        ("CI re-resolves the ranges instead of installing the lock", re_resolve_instead_of_installing_the_lock, "lock -> ci"),
        (
            "the lock is installed into an environment the suite does not use",
            install_the_lock_but_run_the_suite_elsewhere,
            "unused environment",
        ),
        ("the lock pins a version its manifest forbids", lock_drifts_outside_its_manifest, "lock outside manifest"),
        ("the lock omits a guarded runtime dependency", lock_omits_a_guarded_runtime_dependency, "absent from the lock"),
        ("a service with no lock at all", remove_the_lock_entirely, "no lock"),
        # Controls: these must NOT be reported.
        ("a caret and its explicit range agree", caret_and_explicit_range_are_the_same_range, None),
        ("two divergences inside a job that names one file", break_only_the_narrow_job, None),
        ("a dev-group dependency is optional by declaration", declare_the_guarded_package_optional, None),
        ("a runtime dependency marked optional in the manifest", declare_the_guarded_package_optional_in_the_manifest, None),
    ]

    declared_optional = dict(OPTIONAL_BY_OMISSION)
    OPTIONAL_BY_OMISSION.clear()
    failures: list[str] = []
    for name, mutate, expect in cases:
        EXEMPT.clear()
        code, problems = build(mutate)
        blob = " ".join(problems)
        if expect is None:
            failure = f"{name}: expected a clean pass, got {problems}" if code != 0 else None
        elif code == 0:
            failure = f"{name}: injected divergence went UNDETECTED"
        elif expect not in blob:
            failure = f"{name}: detected something else — {problems}"
        else:
            failure = None
        if failure:
            failures.append(failure)
        print(f"  self-test [{'FAIL' if failure else 'ok'}] {name}")
    EXEMPT.clear()

    empty = Path(tempfile.mkdtemp(prefix="ci_parity_selftest_empty_"))
    try:
        code, _ = run(empty)
    finally:
        shutil.rmtree(empty, ignore_errors=True)
    refused = code != 0
    failures += [] if refused else ["non-repo root: reported a verdict about a tree with no workflows"]
    print(f"  self-test [{'ok' if refused else 'FAIL'}] refuses a tree with nothing to compare")

    # A tree with services and workflows but no whole-suite job must also
    # refuse: "nothing to check" and "everything checks out" print the same
    # word otherwise, which is how five gates in this repository certified an
    # empty tree.
    def strip_every_suite_run(root: Path) -> None:
        path = workflow(root)
        path.write_text(
            path.read_text().replace("        run: ../../.venv-demo/bin/python -m pytest tests/ -v\n", "        run: true\n"),
            encoding="utf-8",
        )

    code, _ = build(strip_every_suite_run)
    vacuous = code != 0
    failures += [] if vacuous else ["a tree where no job runs a suite reported OK"]
    print(f"  self-test [{'ok' if vacuous else 'FAIL'}] refuses a tree where no job runs a whole suite")
    OPTIONAL_BY_OMISSION.update(declared_optional)

    if failures:
        print("\ncheck_ci_install_parity --self-test: FAIL")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print(f"\ncheck_ci_install_parity --self-test: OK — {len(cases) + 2} cases, every direction detected")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo-root", type=Path, default=None, help="tree to check; defaults to this script's repository")
    parser.add_argument("--inventory", action="store_true", help="list every job, its services, and every guarded import")
    parser.add_argument("--json", action="store_true", dest="as_json", help="machine-readable output")
    parser.add_argument("--self-test", action="store_true", help="prove the gate detects each divergence, and refuses an empty tree")
    args = parser.parse_args()

    if args.self_test:
        return self_test()
    return run((args.repo_root or repo_root()).resolve(), inventory=args.inventory, as_json=args.as_json)[0]


if __name__ == "__main__":
    sys.exit(main())
