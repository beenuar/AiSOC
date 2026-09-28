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

What it is not
--------------
Not ``poetry export``. The image installs from ``poetry.lock``, so it gets one
exact version set; this re-resolves inside the declared ranges, so CI can land
on a different patch release than the image. That is a smaller gap than a
hand-written list and it is the gap this file leaves open, stated rather than
implied. Closing it means installing from the lock in CI, which costs the pip
wheel cache the matrix was built around.

Usage
-----
    python3 scripts/service_requirements.py api
    python3 scripts/service_requirements.py api agents          # union
    python3 scripts/service_requirements.py fusion --only main
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
