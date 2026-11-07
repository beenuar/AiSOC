"""The borrowed ``app`` tree is a real package, and it is given back.

This file exists because of a specific break rather than for completeness.
``app/core/config.py`` gained ``from app.core.version import resolve_version``
— a change with no connection to any test — and twelve tenant-scoping
assertions in ``test_backtest_lake_live.py`` stopped running, erroring at
fixture setup with::

    ModuleNotFoundError: No module named 'app.core.version';
    'app.core' is not a package

The parents were registered as bare ``types.ModuleType`` objects, which have
no ``__path__``, so the import system could not resolve *any* submodule
through them; a hand-written list of file paths was the only way a module
became reachable. The job that broke is not a required check, so it broke on
``main`` and stayed broken.

Everything below is about the mechanism, not about ClickHouse, so it runs in
the offline ``isolation.yml`` job alongside the rest of this directory and
needs nothing installed. ``find_spec`` is used for most of it deliberately:
it exercises exactly the resolution step that failed, for modules whose
dependencies this job does not have, without executing one line of them.
"""

from __future__ import annotations

import importlib
import importlib.util
import sys
from types import ModuleType

import pytest
from service_packages import ROOT_PACKAGE, service_app_tree

#: Four names spread across the tree, none of which any caller enumerates.
#: ``app.core.version`` is the module whose arrival caused the break and is
#: the reason this file exists; the others are there so the property is
#: pinned for the tree rather than for one module.
RESOLVABLE = (
    "app.core.version",
    "app.core.config",
    "app.db.clickhouse",
    "app.services.backtest",
)


def _borrowed_names() -> set[str]:
    return {name for name in sys.modules if name == ROOT_PACKAGE or name.startswith(f"{ROOT_PACKAGE}.")}


@pytest.mark.parametrize("dotted", RESOLVABLE)
def test_a_module_nobody_listed_resolves_through_the_borrowed_tree(dotted: str) -> None:
    """The regression. Each of these is found by the import system, not by a list."""
    with service_app_tree("api"):
        assert importlib.util.find_spec(dotted) is not None, (
            f"{dotted} did not resolve. If the message said 'is not a package', a parent "
            "lost its __path__ and every module under it is unreachable again."
        )


def test_the_root_and_its_subpackages_carry_a_search_path() -> None:
    """``__path__`` is the single attribute the whole fix turns on."""
    with service_app_tree("api") as package:
        assert isinstance(package, ModuleType)
        assert getattr(package, "__path__", None), "the borrowed root is not a package"
        core = importlib.import_module("app.core")
        assert getattr(core, "__path__", None), "app.core is not a package; submodules cannot resolve"


def test_the_module_that_broke_the_suite_imports_and_answers() -> None:
    """Resolution is not execution, so one module is actually run.

    ``app/core/version.py`` imports only the standard library, which is why
    it is the one chosen: this assertion stays honest in a job that installs
    nothing.
    """
    with service_app_tree("api"):
        version = importlib.import_module("app.core.version")
        assert version.resolve_version(env={}, start=version.Path("/")) == version.UNKNOWN_VERSION


def _assert_restored(before: dict[str, ModuleType]) -> None:
    """``sys.modules`` holds the same ``app`` tree, and the same objects elsewhere.

    Scoped to that rather than to equality of the whole mapping. Importing
    anything can pull in a standard-library module that legitimately stays
    behind, and whether it was already imported depends on which test ran
    first — an assertion that fails on run order is a flake, not a leak
    detector. What a leak looks like is a borrowed name surviving, or a
    module somebody else owned being dropped or swapped.
    """
    after = dict(sys.modules)
    borrowed_before = {k: v for k, v in before.items() if k == ROOT_PACKAGE or k.startswith(f"{ROOT_PACKAGE}.")}
    assert _borrowed_names() == set(borrowed_before), "the borrowed tree outlived the block"
    for name, module in borrowed_before.items():
        assert after[name] is module, f"{name} came back as a different object"
    missing = [name for name in before if name not in after]
    assert missing == [], f"modules disappeared from sys.modules: {missing}"
    swapped = [name for name, module in before.items() if name in after and after[name] is not module]
    assert swapped == [], f"modules were replaced in sys.modules: {swapped}"


def test_the_namespace_is_handed_back_exactly_as_it_was() -> None:
    """Nothing leaks to the next file in the directory.

    Restored by snapshot rather than by a list of names the caller recorded,
    which is now load-bearing: the import system registers submodules nobody
    enumerated, and a name left behind has previously broken unrelated tests
    in this repository while every test in its own file passed.
    """
    before = dict(sys.modules)
    with service_app_tree("api"):
        importlib.import_module("app.core.version")
        assert "app.core.version" in sys.modules
    _assert_restored(before)


def test_an_incumbent_app_is_restored_after_the_block() -> None:
    """Whichever service owned ``app`` first gets it back."""
    incumbent = ModuleType(ROOT_PACKAGE)
    saved = sys.modules.get(ROOT_PACKAGE)
    sys.modules[ROOT_PACKAGE] = incumbent
    try:
        with service_app_tree("api") as package:
            assert sys.modules[ROOT_PACKAGE] is package
        assert sys.modules[ROOT_PACKAGE] is incumbent
    finally:
        if saved is None:
            sys.modules.pop(ROOT_PACKAGE, None)
        else:
            sys.modules[ROOT_PACKAGE] = saved


def test_the_namespace_is_handed_back_when_the_block_raises() -> None:
    """A failing test must not leave the name borrowed for the next one.

    The raise sits in a nested function rather than directly inside a
    combined ``with pytest.raises(...), service_app_tree(...)``. Both forms
    work; this one is also readable by static analysis, which does not model
    ``pytest.raises`` as swallowing the exception and so reports everything
    after the combined form as unreachable and ``before`` as unused.
    """
    before = dict(sys.modules)

    def borrow_then_fail() -> None:
        with service_app_tree("api"):
            importlib.import_module("app.core.version")
            raise RuntimeError("deliberate")

    with pytest.raises(RuntimeError, match="deliberate"):
        borrow_then_fail()
    _assert_restored(before)


def test_a_namespace_only_package_resolves_its_children_without_running_its_init() -> None:
    """The one exception, and the property that makes it safe.

    ``app.services.retro_hunt``'s ``__init__.py`` re-exports from four
    siblings, two of which reach SQLAlchemy, which the live isolation job
    does not install. Registering it without executing that file still has
    to leave its children resolvable, or the exception would reintroduce the
    wall it is exempt from.
    """
    with service_app_tree("api", namespace_only=("app.services.retro_hunt",)):
        package = sys.modules["app.services.retro_hunt"]
        assert getattr(package, "__path__", None), "a namespace-only package still needs a search path"
        assert not hasattr(package, "__all__"), "the real __init__.py ran; it was supposed to be skipped"
        assert importlib.util.find_spec("app.services.retro_hunt.sql") is not None
        assert importlib.import_module("app.services.retro_hunt.ioc_fields").LAKE_TABLE


def test_a_service_that_does_not_package_its_code_as_app_is_refused() -> None:
    """Refuse rather than yield an empty tree every lookup then misses."""
    with pytest.raises(RuntimeError, match="does not package its code"):
        with service_app_tree("no-such-service"):
            pass  # pragma: no cover - the context manager raises on entry
