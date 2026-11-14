"""Borrow one service's ``app`` tree for the length of a test, then give it back.

``services/api``, ``services/agents``, ``services/fusion`` and ``services/connectors``
all package their code as a top-level ``app``. Only one of them can own that
name in one interpreter, and ``tests/isolation`` runs several of them in a
single pytest process, so a live test that needs the API service's modules
cannot simply put ``services/api`` on ``sys.path``: the first service to load
wins, its ``app`` stays cached, and the next file in the directory fails on a
module it has every right to expect.

What this replaces, and why the replacement is a different shape
----------------------------------------------------------------
The two live files here used to sidestep that by registering each parent —
``app``, ``app.core``, ``app.services`` — as a bare ``types.ModuleType`` and
then hand-registering every submodule the call under test reaches, loaded by
file path under its real dotted name.

A bare module is **not a package**: it has no ``__path__``, so the import
system has nowhere to look for ``app.core.anything`` and raises

    ModuleNotFoundError: No module named 'app.core.version'; 'app.core' is not a package

even though the file is right there on disk. The hand-written list was
therefore the *only* way a submodule became reachable, which made it a wall
rather than an optimisation: adding ``from app.core.version import …`` to
``app/core/config.py`` — a change with no connection to any test — broke
twelve tenant-scoping assertions at fixture setup, and the job it broke is
not a required check, so it broke on ``main``. The list could be extended
again, and the module after that would hit the same wall.

So the fix is at the level the error names. The parents become real packages
with a ``__path__`` pointing at the real directory, and the import system
resolves submodules from disk the way it does in production. There is no
allowlist to keep current, because there is no allowlist.

Still scoped, still handed back
-------------------------------
Nothing is added to ``sys.path``, so no *other* service's modules become
findable; the borrowed name is pinned to one directory. On exit every
``app`` entry the block created is removed and anything that was there
first is put back — by snapshot rather than by a list of names the caller
remembered to record, which matters now that the import system registers
submodules nobody enumerated.

Declining to run an ``__init__``
--------------------------------
``namespace_only`` names packages whose ``__init__.py`` must *not* execute.
There is exactly one today: ``app.services.retro_hunt`` re-exports from four
sibling modules, two of which reach SQLAlchemy, and the live isolation job
installs a ClickHouse client and a Kafka client and not an ORM. Importing
the package to reach one leaf module would pull in a dependency tree the
test does not use and the job does not have. Every other package here runs
its real ``__init__.py``, which is what the service does.
"""

from __future__ import annotations

import contextlib
import importlib.util
import sys
from collections.abc import Iterator
from importlib.machinery import ModuleSpec
from pathlib import Path
from types import ModuleType

REPO_ROOT = Path(__file__).resolve().parents[2]

#: The top-level package name every service shares, and therefore the one
#: that has to be borrowed rather than imported.
ROOT_PACKAGE = "app"


def _owned(name: str) -> bool:
    """Is *name* part of the borrowed namespace?"""
    return name == ROOT_PACKAGE or name.startswith(f"{ROOT_PACKAGE}.")


def _namespace_package(dotted: str, directory: Path) -> ModuleType:
    """A package whose ``__init__.py`` is deliberately not executed.

    Built through a real :class:`ModuleSpec` rather than ``types.ModuleType``
    so ``module_from_spec`` sets ``__path__`` from the search locations. That
    attribute is the whole difference between a name the import system can
    resolve submodules through and the ``is not a package`` error above.
    """
    spec = ModuleSpec(dotted, loader=None, is_package=True)
    assert spec.submodule_search_locations is not None  # is_package=True guarantees it
    spec.submodule_search_locations.append(str(directory))
    return importlib.util.module_from_spec(spec)


@contextlib.contextmanager
def service_app_tree(service: str, *, namespace_only: tuple[str, ...] = ()) -> Iterator[ModuleType]:
    """Make ``services/<service>/app`` importable as ``app``, then undo it.

    Yields the root package. Inside the block, ordinary
    ``importlib.import_module("app.services.backtest")`` works and so do the
    ``from app…`` statements inside the modules it loads, including ones
    added after this was written.

    *namespace_only* names packages (dotted, rooted at ``app``) to register
    without executing their ``__init__.py``; see the module docstring for the
    one case that needs it.
    """
    root = REPO_ROOT / "services" / service / "app"
    init = root / "__init__.py"
    if not init.is_file():
        raise RuntimeError(f"{service} does not package its code as an 'app' package at {root}")

    # Snapshot before anything moves. A peer service may already own `app`;
    # it is removed for the duration and restored on the way out, so this
    # works whichever service loaded first and leaves no trace for whichever
    # file runs next.
    saved = {name: module for name, module in sys.modules.items() if _owned(name)}
    for name in saved:
        del sys.modules[name]

    try:
        for dotted in namespace_only:
            if dotted == ROOT_PACKAGE:
                raise ValueError("the root package is loaded from its own __init__.py; it cannot be namespace-only")
            relative = dotted.split(".")[1:]
            sys.modules[dotted] = _namespace_package(dotted, root.joinpath(*relative))

        spec = importlib.util.spec_from_file_location(
            ROOT_PACKAGE,
            init,
            submodule_search_locations=[str(root)],
        )
        if spec is None or spec.loader is None:  # pragma: no cover - the path is checked above
            raise RuntimeError(f"cannot build an import spec for {init}")
        package = importlib.util.module_from_spec(spec)
        # Registered before exec so a self-referential import inside the
        # package body resolves, which is the same reason the per-module
        # loaders here register before executing.
        sys.modules[ROOT_PACKAGE] = package
        spec.loader.exec_module(package)
        yield package
    finally:
        for name in [name for name in sys.modules if _owned(name)]:
            del sys.modules[name]
        sys.modules.update(saved)
