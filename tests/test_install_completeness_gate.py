"""The runtime/dev split, against this repository's own locks.

``check_install_completeness.py --self-test`` proves the derivation on
synthetic fixtures, which is where the awkward shapes can be constructed on
purpose. This file points the same derivation at the real tree, because a
fixture is written by the same person who wrote the parser and agrees with
them by construction.

The assertions are deliberately relational rather than numeric. "escalations
derives three packages" is true today and becomes a false failure the moment
someone adds a dependency; "escalations derives fewer than its lock holds,
and none of them are its test dependencies" stays true for as long as the
property it describes is true.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = REPO_ROOT / "scripts"


def _load():
    sys.path.insert(0, str(SCRIPTS))
    name = "check_install_completeness"
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    # Registered before execution: `@dataclass` resolves annotations through
    # `sys.modules[cls.__module__]`, which is None for a module loaded by
    # path alone, and the decorator raises during import rather than at use.
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


gate = _load()

LINUX = [
    {
        "os_name": "posix",
        "sys_platform": "linux",
        "platform_system": "Linux",
        "platform_machine": "x86_64",
        "platform_python_implementation": "CPython",
        "implementation_name": "cpython",
        "implementation_version": "3.11.14",
        "platform_release": "6.8.0",
        "platform_version": "#1",
        "python_version": "3.11",
        "python_full_version": "3.11.14",
    }
]


def _services():
    return gate.discover_services(REPO_ROOT)


def test_every_service_lock_yields_a_non_empty_runtime_set():
    """The property the build jobs depend on. An empty expectation is vacuous."""
    services = _services()
    assert len(services) >= 13, f"only {len(services)} service(s) with a lock"
    for service in services:
        derived = gate.derive(service, gate.candidate_environments(gate.python_minor_for(service)))
        assert derived.expected, f"{service.name} derives no runtime package"


def test_escalations_excludes_its_test_dependencies():
    """Its dev deps are a PEP 621 extra, so every locked package says main.

    Reading `groups` alone would expect pytest in a runtime image that
    deliberately has none — the failure that would make this gate reject
    every correct build of the service.
    """
    service = next(s for s in _services() if s.name == "escalations")
    derived = gate.derive(service, LINUX)
    locked = {p.name for p in gate.read_lock(service.lock)}

    assert {"pytest", "pytest-cov", "coverage", "pluggy", "iniconfig", "pygments"} <= locked
    assert not ({"pytest", "pytest-cov", "coverage", "pluggy", "iniconfig", "pygments"} & derived.expected)
    assert "psycopg" in derived.expected
    assert len(derived.expected) < len(locked)


def test_a_win32_only_runtime_dependency_is_not_expected_on_linux():
    """`tzdata` is non-optional and `sys_platform == "win32"`: never installed here."""
    service = next(s for s in _services() if s.name == "escalations")
    locked = {p.name: p for p in gate.read_lock(service.lock)}
    assert locked["tzdata"].main_marker == 'sys_platform == "win32"'
    assert "tzdata" not in gate.derive(service, LINUX).expected


def test_a_marker_table_keyed_by_group_does_not_constrain_main():
    """Real instance: typing-extensions carries a `dev`-only marker in four services."""
    checked = 0
    for service in _services():
        for package in gate.read_lock(service.lock):
            if package.name == "typing-extensions" and "dev" in package.groups and "main" in package.groups:
                checked += 1
                # The dev marker must not have leaked into the main slot.
                assert package.main_marker != 'python_version < "3.15"'
                assert "typing-extensions" in gate.derive(service, LINUX).expected
    assert checked, "no service pairs typing-extensions across main and dev; this test stopped measuring"


def test_a_truncated_install_is_missing_what_the_lock_declares():
    service = next(s for s in _services() if s.name == "escalations")
    derived = gate.derive(service, LINUX)
    complete = "".join(f"{name}==1.0\n" for name in sorted(derived.expected))
    assert gate.compare("escalations", derived, complete).ok

    dropped = sorted(derived.expected)[0]
    truncated = "".join(f"{name}==1.0\n" for name in sorted(derived.expected) if name != dropped)
    result = gate.compare("escalations", derived, truncated)
    assert not result.ok
    assert result.missing == [dropped]


def test_a_package_the_base_image_ships_is_not_a_failure():
    """`python:3.11-slim` preinstalls `packaging`, which is in no service lock."""
    service = next(s for s in _services() if s.name == "escalations")
    derived = gate.derive(service, LINUX)
    freeze = "packaging==26.3\n" + "".join(f"{name}==1.0\n" for name in sorted(derived.expected))
    result = gate.compare("escalations", derived, freeze)
    assert result.ok
    assert result.unexpected == ["packaging"]


def test_an_install_of_nothing_fails_against_a_real_lock():
    """The failure the fixed floor was added to catch, and could not express."""
    service = next(s for s in _services() if s.name == "escalations")
    derived = gate.derive(service, LINUX)
    result = gate.compare("escalations", derived, "packaging==26.3\n")
    assert not result.ok
    assert set(result.missing) == derived.expected


def test_an_unsettled_marker_is_undetermined_rather_than_guessed():
    """`python_full_version < "3.11.3"` on a moving `python:3.11-slim` tag."""
    unsettled = gate.resolve_marker('python_full_version < "3.11.3"', gate.candidate_environments("3.11"))
    assert unsettled is gate.UNDETERMINED
    # With the real environment there is nothing to be unsure about.
    assert gate.resolve_marker('python_full_version < "3.11.3"', LINUX) is False


def test_version_comparison_is_not_lexicographic():
    environment = [{**LINUX[0], "python_full_version": "3.11.10"}]
    assert gate.resolve_marker('python_full_version < "3.11.3"', environment) is False


@pytest.mark.parametrize("name", ["psycopg_binary", "psycopg-binary", "PSYCOPG.BINARY"])
def test_names_are_compared_after_pep503_normalisation(name):
    """`pip freeze` prints `typing_extensions`; the lock says `typing-extensions`."""
    assert gate.canonical(name) == "psycopg-binary"


def test_an_optional_poetry_dependency_is_not_a_runtime_dependency():
    """services/actions declares vaid-mint `optional = true`, reachable via an extra."""
    manifest = REPO_ROOT / "services" / "actions" / "pyproject.toml"
    declared = gate.declared_runtime_dependencies(manifest)
    assert "vaid-mint" not in declared
    assert "cryptography" in declared
