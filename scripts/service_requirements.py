#!/usr/bin/env python3
"""Print a service's declared dependencies as ``pip install`` arguments.

Why this exists
---------------
Every CI job that runs a Python service's test suite used to carry its own
hand-written copy of that service's dependency list. The lists were correct
when written and the manifests moved:

* ``ci.yml``'s API list omitted ``pysigma``, so ``rule_engine._run_sigma``
  took its ``except ImportError`` branch and CI graded a reduced evaluator
  while the image graded the real Sigma backend. The real one was broken.
* The wave-2 list installed ``pytest>=7.4,<9`` for seven services whose
  manifests all declare ``>=9.0.3,<10.0`` — **disjoint**, so the pytest CI
  graded those suites on was one none of them may ship. All seven locks
  resolve 9.1.1.
* It installed ``httpx>=0.27,<0.29`` for eight services of which two declare
  ``^0.26.0`` and lock 0.26.0, and ``prometheus-client>=0.20,<0.24`` for two
  services that lock 0.19.0 and 0.25.0 — a range satisfying neither.
* It installed ``aioredis``, ``jinja2`` and ``tenacity``, which no service in
  that job imports or declares at all.

The list is the problem, not the entries. So this derives it. A job installs
``$(python3 scripts/service_requirements.py <service>)`` and the question
"does CI install what this service declares" stops having two answers.

Ranges, and why they were not enough
------------------------------------
The first version of this emitted the declared *ranges* and left a caveat
saying so: the image installs from ``poetry.lock`` and gets one exact version
set, while a range re-resolves at install time, so CI could still land on a
different patch release than the image ships. That is the same defect one
notch smaller, and it is exactly how the last one hid — ``services/api``
declared ``opentelemetry-instrumentation-fastapi = "^0.45b0"`` and locked
0.45b0, while CI installed the package unbounded, resolved 0.66b0, and passed.
Both were "inside the declared range".

``--locked`` closes it. It reads ``poetry.lock`` — the same file
``services/<name>/Dockerfile`` installs from — and emits the **complete
resolved closure** as exact ``==`` pins, one per line, carrying each entry's
environment markers. Installed with ``pip install --no-deps -r``, pip performs
no resolution at all: the set it lands on is the set the lock names, which is
the set the image ships. Measured against the published
``ghcr.io/beenuar/aisoc-core-api:latest``: 97 main-group entries, **0 version
mismatches**.

The pip wheel cache the matrix was built around survives, because this is
still pip installing wheels — it is the *resolution* that is gone, not the
cache.

Two services' locks cannot share one environment, so jobs that grade more than
one service install each into its own virtualenv. ``api`` and ``agents``
disagree about 28 distributions; ``fusion``/``honeytokens``/``purple-team``
about ``asyncpg``. That is not a defect in either lock — they are separate
images — but it does mean one interpreter cannot hold both.

Usage
-----
    python3 scripts/service_requirements.py api
    python3 scripts/service_requirements.py api agents          # union
    python3 scripts/service_requirements.py fusion --only main
    python3 scripts/service_requirements.py api --locked        # exact pins
    python3 scripts/service_requirements.py --list
    python3 scripts/service_requirements.py --self-test
"""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root  # noqa: E402

# Native libraries that no wheel carries, and the code that needs them already
# degrades on `except (ImportError, OSError)`. Naming them here rather than in
# the workflow keeps the "what does this service need" answer in one place;
# the workflow installs the apt packages when this list is non-empty.
SYSTEM_LIBRARIES = {
    "weasyprint": ("libpango-1.0-0", "libpangocairo-1.0-0", "libcairo2", "libgdk-pixbuf-2.0-0", "shared-mime-info"),
}


def canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).strip().lower()


def caret_range(spec: str) -> str:
    """Poetry's ``^`` as the explicit range pip understands.

    pip has no caret. Expanding it here rather than passing it through is what
    lets one manifest serve both the image (via poetry) and CI (via pip)
    without the two reading different constraints.
    """
    version = spec[1:].strip()
    parts = [int(p) for p in re.findall(r"\d+", version)] or [0]
    parts += [0] * (3 - len(parts))
    index = next((i for i, p in enumerate(parts) if p), len(parts) - 1)
    ceiling = parts[:index] + [parts[index] + 1] + [0] * (len(parts) - index - 1)
    return f">={version},<{'.'.join(str(p) for p in ceiling)}"


def to_pip(spec: str) -> str:
    """One poetry version constraint as a pip specifier."""
    spec = spec.strip()
    if not spec or spec == "*":
        return ""
    if spec.startswith("^"):
        return caret_range(spec)
    if spec.startswith("~"):
        return spec  # `~=` and `~` both mean compatible-release to pip
    if re.fullmatch(r"\d[\w.*+-]*", spec):
        return f"=={spec}"  # a bare version in poetry is an exact pin
    return spec


def _merge(out: dict[str, str], name: str, spec: str) -> None:
    """Record a constraint, keeping both when a package is declared twice.

    Three manifests list a package in the runtime table *and* again, bare, in
    a dev extra — `httpx>=0.27.0` and then `httpx`. Overwriting meant the bare
    name won and the bound vanished, so the derived list asked pip for every
    httpx ever published. pip holds both constraints; so does this.
    """
    previous = out.get(name)
    if previous is None or not previous:
        out[name] = spec
    elif spec and spec not in previous:
        out[name] = f"{previous},{spec}"


_PEP508 = re.compile(r"""^\s*(?P<name>[A-Za-z][A-Za-z0-9._-]*)(?P<extras>\[[^\]]*\])?\s*(?P<spec>.*)$""")


def requirements(manifest: Path, groups: str = "all") -> list[str]:
    """Every dependency the manifest declares, as pip arguments.

    Both declaration styles in this tree are read. Ten services use poetry's
    ``[tool.poetry.dependencies]``; ``honeytokens``, ``purple-team`` and
    ``ueba`` use PEP 621 ``[project] dependencies``. A reader that knew only
    the first returned an empty list for those three — and an empty install
    list is indistinguishable from a service with no dependencies, which is
    how a gate certifies a tree it never read. ``requirements`` therefore
    raises on a manifest it understood as empty rather than returning ``[]``.
    """
    data = tomllib.loads(manifest.read_text(encoding="utf-8"))
    out: dict[str, str] = {}

    poetry = data.get("tool", {}).get("poetry", {})
    tables: list[dict] = []
    if groups in ("all", "main"):
        tables.append(poetry.get("dependencies", {}) or {})
    if groups in ("all", "dev"):
        tables += [(group.get("dependencies", {}) or {}) for group in (poetry.get("group") or {}).values()]
    for table in tables:
        for name, spec in table.items():
            if name == "python":
                continue
            extras: list[str] = []
            if isinstance(spec, dict):
                extras = [str(e) for e in spec.get("extras", []) or []]
                # A dependency declared only for another platform or another
                # python is not this environment's to install.
                if spec.get("markers") or spec.get("platform") or spec.get("optional"):
                    continue
                spec = spec.get("version", "")
            if not isinstance(spec, str):
                continue
            suffix = f"[{','.join(extras)}]" if extras else ""
            _merge(out, canonical(name) + suffix, to_pip(spec))

    project = data.get("project", {})
    pep621: list[str] = []
    if groups in ("all", "main"):
        pep621 += list(project.get("dependencies") or [])
    if groups in ("all", "dev"):
        for extra in (project.get("optional-dependencies") or {}).values():
            pep621 += list(extra)
    for requirement in pep621:
        # A PEP 508 environment marker is a condition on the installing
        # environment, so pip is the right thing to evaluate it — pass the
        # whole requirement through rather than guessing.
        match = _PEP508.match(requirement.split("#", 1)[0].strip())
        if not match or not match.group("name"):
            continue
        suffix = (match.group("extras") or "").replace(" ", "")
        _merge(out, canonical(match.group("name")) + suffix, match.group("spec").strip())

    if not out:
        raise SystemExit(
            f"service_requirements: {manifest} declares no dependency this reader could find. "
            f"That is either a manifest style it does not understand or an empty manifest, and both "
            f"must fail rather than produce an empty install list."
        )
    return [f"{name}{spec}" for name, spec in sorted(out.items())]


def service_lock(manifest: Path) -> Path:
    return manifest.parent / "poetry.lock"


def _extras_closure(packages: list[dict], extras: dict) -> set[str]:
    """Every package reachable from a root ``[extras]`` entry.

    Poetry marks a package ``optional = true`` when an extra is the only thing
    that pulls it in. For the three services declaring their dev dependencies
    the PEP 621 way — ``honeytokens``, ``purple-team``, ``ueba`` — that is
    where ``pytest`` lives: group ``main``, ``optional = true``, listed under
    the ``dev`` extra. Dropping every optional entry would hand those three
    suites an environment with no test runner in it; keeping every optional
    entry would hand ``agents`` the WeasyPrint family, which its image does
    not have and whose absence its own code handles with ``except ImportError``
    — the fallback defect with the arrow reversed.

    So the rule is reachability, transitively: an optional package is in when
    some extra names it, or when a package already in names it as a
    dependency.
    """
    by_name = {canonical(p["name"]): p for p in packages}
    frontier = [canonical(n) for names in (extras or {}).values() for n in names]
    reached: set[str] = set()
    while frontier:
        name = frontier.pop()
        if name in reached or name not in by_name:
            continue
        reached.add(name)
        frontier += [canonical(dep) for dep in (by_name[name].get("dependencies") or {})]
    return reached


_EXTRA_TERM = re.compile(r"""^\s*extra\s*==\s*['"][^'"]*['"]\s*$""")


def _without_extra_selector(marker: str) -> str:
    """Drop ``extra == "..."`` terms from a marker.

    Poetry records a package pulled in by an extra with ``extra == "dev"``,
    which is a *selector*: it is true only while a resolver is expanding that
    extra. In a plain requirements file ``extra`` is undefined, so the clause
    is **false** and pip skips the line — silently, with no warning and exit
    0. That is how the first run of this put `pytest` in the file for
    ``honeytokens``, ``purple-team`` and ``ueba`` and produced three
    virtualenvs with no test runner in them, failing three steps later with
    "No module named pytest".

    Reaching here means the extra was already selected, so the selector has
    served its purpose and any remaining condition is the real one:
    ``extra == "dev" and sys_platform == "win32"`` is a Windows-only package.

    A marker combining ``extra`` with ``or``, or parenthesised, is refused
    rather than reduced. Rewriting boolean logic by string surgery is how a
    line quietly starts meaning something else, and the failure mode this
    function exists to remove is precisely a line that silently does nothing.
    """
    if "extra" not in marker:
        return marker
    if "(" in marker or " or " in marker:
        raise SystemExit(
            f"service_requirements: cannot reduce the marker {marker!r}. It combines an `extra` selector with "
            f"`or`/parentheses, and rewriting that by string surgery risks changing what it means. Add a case "
            f"here deliberately rather than guessing."
        )
    return " and ".join(term for term in re.split(r"\s+and\s+", marker.strip()) if not _EXTRA_TERM.match(term))


def _marker_for(package: dict, wanted: set[str]) -> str | None:
    """The environment marker to emit for one lock entry, or None for unconditional.

    ``markers`` is a string on most entries and a **per-group table** on ten
    of them — ``{main = '...', dev = '...'}``. Passing the table through
    verbatim hands pip the repr of a dict and it aborts the whole install with
    `InvalidMarker`, which took out six of the matrix cells on the first run.

    A group listed in ``groups`` but absent from the table has no condition
    under that group, so selecting it makes the entry unconditional. Where
    several selected groups each carry one, the entry is needed if any of them
    applies, so they are OR-ed.
    """
    raw = package.get("markers")
    if isinstance(raw, str):
        chosen = [raw]
    elif isinstance(raw, dict):
        chosen = []
        for group in sorted(set(package.get("groups") or ["main"]) & wanted):
            if group not in raw:
                return None
            chosen.append(raw[group])
        if not chosen:
            return None
    else:
        return None

    reduced: list[str] = []
    for marker in chosen:
        text = _without_extra_selector(marker).strip()
        if not text:
            return None  # the marker was only the extra selector, already resolved
        if text not in reduced:
            reduced.append(text)
    if len(reduced) == 1:
        return reduced[0]
    return " or ".join(f"({part})" for part in reduced)


def locked_requirements(manifest: Path, groups: str = "all") -> list[str]:
    """The service's ``poetry.lock`` as exact pins, in requirements.txt form.

    This is the whole resolved closure rather than the direct dependencies,
    because that is what makes ``pip install --no-deps`` legitimate: every
    transitive requirement is already named at a pinned version, so pip has
    nothing left to resolve and cannot drift.

    ``--only main`` reproduces what the Dockerfile installs
    (``poetry install --only main``); the default adds the dev group and the
    extras, which is what a test run needs on top.

    Markers are passed through rather than evaluated here. ``brotlicffi`` is
    marked ``platform_python_implementation != "CPython"`` and ``tzdata``
    ``platform_system == "Windows"``; both are correctly absent from a Linux
    CPython image, and pip is the right thing to decide that — evaluating
    markers in this script would mean reimplementing PEP 508 and getting a
    different answer than the installer on some platform nobody tested.

    Two forms have to be reshaped before pip sees them, and both were found by
    running this against real CI rather than by reading the locks: a
    per-group ``markers`` table, which pip rejects outright, and an
    ``extra == "..."`` selector, which pip accepts and silently evaluates
    false. See ``_marker_for`` and ``_without_extra_selector``.
    """
    lock = service_lock(manifest)
    if not lock.is_file():
        raise SystemExit(
            f"service_requirements: {manifest.parent.name} has no poetry.lock at "
            f"{lock}. --locked exists so CI installs the same version set the image does; "
            f"without the lock there is no such set, and emitting the ranges instead would "
            f"silently return to re-resolving."
        )
    data = tomllib.loads(lock.read_text(encoding="utf-8"))
    packages = data.get("package") or []
    if not packages:
        raise SystemExit(f"service_requirements: {lock} names no package — refusing to emit an empty install list.")

    wanted = {"main", "dev"} if groups == "all" else {groups}
    reachable = _extras_closure(packages, data.get("extras") or {}) if groups != "main" else set()

    out: list[str] = []
    for package in packages:
        if not (set(package.get("groups") or ["main"]) & wanted):
            continue
        if package.get("optional") and canonical(package["name"]) not in reachable:
            continue
        pin = f"{canonical(package['name'])}=={package['version']}"
        marker = _marker_for(package, wanted)
        out.append(f"{pin} ; {marker}" if marker else pin)
    return sorted(out)


def system_packages(names: list[str]) -> list[str]:
    seen: list[str] = []
    for requirement in names:
        package = canonical(re.split(r"[\[<>=!~]", requirement, maxsplit=1)[0])
        for library in SYSTEM_LIBRARIES.get(package, ()):
            if library not in seen:
                seen.append(library)
    return seen


def service_manifest(root: Path, service: str) -> Path:
    manifest = root / "services" / service / "pyproject.toml"
    if not manifest.is_file():
        raise SystemExit(f"service_requirements: no manifest at {manifest.relative_to(root)}")
    return manifest


def self_test() -> int:
    import shutil
    import tempfile

    failures: list[str] = []

    def expect(name: str, got, want) -> None:
        if got != want:
            failures.append(f"{name}: got {got!r}, want {want!r}")
        print(f"  self-test [{'FAIL' if got != want else 'ok'}] {name}")

    expect("caret on a major", to_pip("^2.5.0"), ">=2.5.0,<3.0.0")
    expect("caret on a 0.x minor", to_pip("^0.11.0"), ">=0.11.0,<0.12.0")
    expect("caret on a 0.0.x patch", to_pip("^0.0.3"), ">=0.0.3,<0.0.4")
    expect("an explicit range passes through", to_pip(">=0.117,<0.142"), ">=0.117,<0.142")
    expect("a bare version is an exact pin", to_pip("1.30.0"), "==1.30.0")
    expect("a wildcard is unbounded", to_pip("*"), "")

    temp = Path(tempfile.mkdtemp(prefix="service_requirements_selftest_"))
    try:
        manifest = temp / "pyproject.toml"
        manifest.write_text(
            "[tool.poetry]\n"
            'name = "demo"\nversion = "0.1.0"\n\n'
            "[tool.poetry.dependencies]\n"
            'python = "^3.11"\n'
            'pysigma = ">=0.11.17,<0.12"\n'
            'sqlalchemy = { version = "^2.0.30", extras = ["asyncio"] }\n'
            'weasyprint = ">=62,<71"\n'
            'windows-only = { version = "^1.0", markers = "sys_platform == \'win32\'" }\n\n'
            "[tool.poetry.group.dev.dependencies]\n"
            'pytest = ">=9.0.3,<10.0"\n',
            encoding="utf-8",
        )
        everything = requirements(manifest)
        expect(
            "extras survive, carets expand, markers are excluded",
            everything,
            ["pysigma>=0.11.17,<0.12", "pytest>=9.0.3,<10.0", "sqlalchemy[asyncio]>=2.0.30,<3.0.0", "weasyprint>=62,<71"],
        )
        expect("--only main drops the dev group", requirements(manifest, "main"), [r for r in everything if "pytest" not in r])
        expect("weasyprint asks for its native libraries", system_packages(everything)[:1], ["libpango-1.0-0"])
        expect("a set without weasyprint asks for nothing", system_packages(["pysigma>=0.11.17,<0.12"]), [])

        # Three services in this tree declare dependencies the PEP 621 way.
        # A reader that knew only poetry's table returned nothing for them,
        # which reads as "no dependencies" rather than "not understood".
        pep621 = temp / "pep621.toml"
        pep621.write_text(
            '[project]\nname = "demo"\nversion = "0.1.0"\n'
            'dependencies = [\n  "fastapi>=0.117,<0.142",\n  "sqlalchemy[asyncio]>=2.0.0",\n]\n\n'
            '[project.optional-dependencies]\ndev = ["pytest", "pytest-asyncio"]\n',
            encoding="utf-8",
        )
        expect(
            "PEP 621 dependencies are read",
            requirements(pep621),
            ["fastapi>=0.117,<0.142", "pytest", "pytest-asyncio", "sqlalchemy[asyncio]>=2.0.0"],
        )

        empty = temp / "empty.toml"
        empty.write_text('[tool.poetry]\nname = "demo"\nversion = "0.1.0"\n', encoding="utf-8")
        try:
            requirements(empty)
            refused = False
        except SystemExit:
            refused = True
        expect("a manifest it cannot read fails rather than emitting nothing", refused, True)

        # ── --locked ────────────────────────────────────────────────────────
        # The lock below is the shape this tree actually has: a main group, a
        # dev group, a marker-gated entry, and an extras-gated `pytest` — the
        # form the three PEP 621 services use, where dropping optional
        # entries wholesale leaves the suite with no test runner.
        locked_dir = temp / "locked"
        locked_dir.mkdir()
        (locked_dir / "pyproject.toml").write_text(
            '[tool.poetry]\nname = "demo"\nversion = "0.1.0"\n\n[tool.poetry.dependencies]\npython = "^3.11"\nfastapi = ">=0.117,<0.142"\n',
            encoding="utf-8",
        )
        (locked_dir / "poetry.lock").write_text(
            '[[package]]\nname = "fastapi"\nversion = "0.141.1"\ngroups = ["main"]\noptional = false\n\n'
            '[[package]]\nname = "tzdata"\nversion = "2026.4"\ngroups = ["main"]\noptional = false\n'
            'markers = "platform_system == \\"Windows\\""\n\n'
            '[[package]]\nname = "mypy"\nversion = "1.2.3"\ngroups = ["dev"]\noptional = false\n\n'
            '[[package]]\nname = "pytest"\nversion = "9.1.1"\ngroups = ["main"]\noptional = true\n'
            '[package.dependencies]\npluggy = ">=1"\n\n'
            '[[package]]\nname = "pluggy"\nversion = "1.6.0"\ngroups = ["main"]\noptional = true\n\n'
            '[[package]]\nname = "weasyprint"\nversion = "66.0"\ngroups = ["main"]\noptional = true\n\n'
            '[extras]\ndev = ["pytest"]\n\n'
            '[metadata]\nlock-version = "2.1"\n',
            encoding="utf-8",
        )
        manifest_locked = locked_dir / "pyproject.toml"
        expect(
            "--locked emits exact pins, keeps markers, resolves the dev extra transitively",
            locked_requirements(manifest_locked),
            [
                "fastapi==0.141.1",
                "mypy==1.2.3",
                "pluggy==1.6.0",
                "pytest==9.1.1",
                'tzdata==2026.4 ; platform_system == "Windows"',
            ],
        )
        expect(
            "--locked --only main is what the Dockerfile installs: no dev group, no extras",
            locked_requirements(manifest_locked, "main"),
            ["fastapi==0.141.1", 'tzdata==2026.4 ; platform_system == "Windows"'],
        )
        # An optional package no extra reaches is an extra the image does not
        # have either. Installing it would give CI a code path production
        # cannot take — the guarded-import defect with the arrow reversed.
        expect(
            "an optional package no extra reaches is excluded",
            [r for r in locked_requirements(manifest_locked) if r.startswith("weasyprint")],
            [],
        )

        # ── Marker forms pip will not take at face value ────────────────────
        # Both of these were found by running the generated file through a
        # real pip, not by reading the lock. The first aborts the install; the
        # second is accepted and silently installs nothing.
        expect(
            "an `extra` selector is dropped once the extra has been chosen",
            _without_extra_selector('extra == "dev"'),
            "",
        )
        expect(
            "a real condition beside the selector survives it",
            _without_extra_selector('extra == "dev" and sys_platform == "win32"'),
            'sys_platform == "win32"',
        )
        expect(
            "a marker with no selector is untouched",
            _without_extra_selector('platform_system == "Windows" or sys_platform == "win32"'),
            'platform_system == "Windows" or sys_platform == "win32"',
        )
        try:
            _without_extra_selector('extra == "dev" or sys_platform == "win32"')
            reduced_or = False
        except SystemExit:
            reduced_or = True
        expect("a selector combined with `or` is refused, not guessed at", reduced_or, True)

        expect(
            "a string marker passes through",
            _marker_for({"markers": 'sys_platform == "win32"', "groups": ["main"]}, {"main", "dev"}),
            'sys_platform == "win32"',
        )
        expect(
            "a per-group marker table is OR-ed across the selected groups",
            _marker_for(
                {"markers": {"main": 'platform_system == "Windows"', "dev": 'sys_platform == "win32"'}, "groups": ["main", "dev"]},
                {"main", "dev"},
            ),
            '(sys_platform == "win32") or (platform_system == "Windows")',
        )
        expect(
            "a selected group absent from the table makes the entry unconditional",
            _marker_for({"markers": {"dev": 'python_version < "3.15"'}, "groups": ["main", "dev"]}, {"main", "dev"}),
            None,
        )
        expect(
            "only the selected group's condition is used",
            _marker_for({"markers": {"dev": 'python_version < "3.15"'}, "groups": ["main", "dev"]}, {"dev"}),
            'python_version < "3.15"',
        )
        expect(
            "a marker that was only a selector becomes unconditional",
            _marker_for({"markers": 'extra == "dev"', "groups": ["main"]}, {"main", "dev"}),
            None,
        )

        # Every marker this tree's locks actually contain must survive the
        # round trip into something PEP 508 accepts. A unit test on two
        # handwritten strings would not have caught either defect above.
        real = temp / "real"
        real.mkdir()
        (real / "pyproject.toml").write_text(
            '[tool.poetry]\nname = "d"\nversion = "0.1.0"\n\n[tool.poetry.dependencies]\npython = "^3.11"\nx = "*"\n', encoding="utf-8"
        )
        (real / "poetry.lock").write_text(
            '[[package]]\nname = "a"\nversion = "1.0"\ngroups = ["main", "dev"]\noptional = false\n'
            'markers = {main = \'platform_system == "Windows" or sys_platform == "win32"\', dev = \'sys_platform == "win32"\'}\n\n'
            '[[package]]\nname = "b"\nversion = "1.0"\ngroups = ["main"]\noptional = true\nmarkers = "extra == \\"dev\\""\n\n'
            '[extras]\ndev = ["b"]\n\n[metadata]\nlock-version = "2.1"\n',
            encoding="utf-8",
        )
        emitted = locked_requirements(real / "pyproject.toml")
        expect(
            "the two shapes this tree's locks really use come out installable",
            emitted,
            ['a==1.0 ; (sys_platform == "win32") or (platform_system == "Windows" or sys_platform == "win32")', "b==1.0"],
        )

        nolock = temp / "nolock"
        nolock.mkdir()
        (nolock / "pyproject.toml").write_text(
            '[tool.poetry]\nname = "d"\nversion = "0.1.0"\n\n[tool.poetry.dependencies]\npython = "^3.11"\nfastapi = "*"\n',
            encoding="utf-8",
        )
        try:
            locked_requirements(nolock / "pyproject.toml")
            refused_nolock = False
        except SystemExit:
            refused_nolock = True
        expect("--locked without a lock fails rather than falling back to ranges", refused_nolock, True)
    finally:
        shutil.rmtree(temp, ignore_errors=True)

    if failures:
        print("\nservice_requirements --self-test: FAIL")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("\nservice_requirements --self-test: OK")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("services", nargs="*", help="service directory name(s) under services/")
    parser.add_argument("--only", choices=("all", "main", "dev"), default="all", help="which dependency groups to emit")
    parser.add_argument(
        "--locked",
        action="store_true",
        help="emit the committed poetry.lock as exact pins, one per line, for `pip install --no-deps -r`",
    )
    parser.add_argument("--system", action="store_true", help="print the apt packages the set needs instead of the pip arguments")
    parser.add_argument("--list", action="store_true", dest="list_services", help="list every service with a manifest")
    parser.add_argument("--self-test", action="store_true", help="prove the conversions and the group selection")
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    root = repo_root()
    if args.list_services:
        for manifest in sorted(root.glob("services/*/pyproject.toml")):
            print(manifest.parent.name)
        return 0
    if not args.services:
        parser.error("name at least one service, or pass --list")

    if args.locked:
        # One service at a time, on purpose. Exact pins from two locks cannot
        # be merged the way ranges can — `api` and `agents` disagree about 28
        # distributions — and quietly picking one would reintroduce the exact
        # thing this mode exists to remove. A job grading two services builds
        # two environments.
        if len(args.services) != 1:
            parser.error(
                "--locked emits one service's resolved set; name exactly one. Two locks cannot share an "
                "interpreter (api and agents disagree about 28 distributions), so a job grading several "
                "services installs each into its own virtualenv."
            )
        manifest = service_manifest(root, args.services[0])
        if args.system:
            print(" ".join(system_packages(locked_requirements(manifest, args.only))))
        else:
            print("\n".join(locked_requirements(manifest, args.only)))
        return 0

    # Two services declaring one package: hand pip both constraints so it
    # installs the intersection. If they are disjoint pip fails loudly, which
    # is the honest outcome — one install path cannot serve two services that
    # cannot agree, and silence there is how CI came to test `httpx` 0.28
    # against manifests permitting only 0.26.
    merged: dict[str, str] = {}
    for service in args.services:
        for requirement in requirements(service_manifest(root, service), args.only):
            name = re.split(r"[<>=!~]", requirement, maxsplit=1)[0]
            _merge(merged, name, requirement[len(name) :].strip())
    resolved = [f"{name}{spec}" for name, spec in sorted(merged.items())]

    print(" ".join(system_packages(resolved) if args.system else resolved))
    return 0


if __name__ == "__main__":
    sys.exit(main())
