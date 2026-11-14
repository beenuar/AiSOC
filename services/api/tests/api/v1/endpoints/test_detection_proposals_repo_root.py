"""Regression tests for the repo-root resolver in ``detection_proposals``.

This pins the fix for GH #81 / #83. The original bug was that the module
computed its repo-root with ``Path(__file__).resolve().parents[6]``, which
crashed at import time inside the slimmed API Docker image because only
``services/api/`` is copied to ``/app`` (so ``parents[6]`` doesn't exist).

The ``IndexError`` happened during ``app.api.v1.endpoints.detection_proposals``
module import, so the entire FastAPI app failed to start — every endpoint
(not just ``/run-eval``) returned 500. Tests below verify the marker-file
resolver:

1. Finds the real repo root on the host (where ``scripts/run_evals.py`` exists).
2. Falls back gracefully when the marker is absent (Docker case) without
   crashing and without resolving to ``/``.
3. Honours the ``AISOC_REPO_ROOT`` environment override.
4. Survives shallow path trees that would have triggered the original
   ``IndexError``.
"""

from __future__ import annotations

import importlib
from pathlib import Path

from app.api.v1.endpoints import detection_proposals as dp_endpoint


def test_module_imports_without_indexerror():
    """The whole point of the fix: importing the module must not raise.

    If this test fails the API service won't boot.
    """
    # Simply re-importing exercises the module-level path resolution again.
    importlib.reload(dp_endpoint)
    assert hasattr(dp_endpoint, "_REPO_ROOT")
    assert hasattr(dp_endpoint, "_EVAL_SCRIPT")


def test_resolver_finds_root_via_marker_when_present(tmp_path: Path):
    """When ``scripts/run_evals.py`` exists in some ancestor, that ancestor
    is the chosen root — not a hard-coded parent index."""
    repo = tmp_path / "fake-repo"
    deep = repo / "services" / "api" / "app" / "api" / "v1" / "endpoints"
    deep.mkdir(parents=True)
    (repo / "scripts").mkdir()
    (repo / "scripts" / "run_evals.py").write_text("# marker")

    fake_module = deep / "detection_proposals.py"
    fake_module.write_text("# stub")

    resolved = dp_endpoint._resolve_repo_root(fake_module.resolve())
    assert resolved == repo.resolve()


def test_resolver_walks_up_through_many_levels(tmp_path: Path):
    """The walk must traverse the full ancestor chain, not a fixed depth.

    Use 10 nested directories to demonstrate this is not a parents[N] hack.
    """
    repo = tmp_path / "deep-repo"
    deep = repo
    for i in range(10):
        deep = deep / f"level{i}"
    deep.mkdir(parents=True)
    (repo / "scripts").mkdir()
    (repo / "scripts" / "run_evals.py").write_text("# marker")

    leaf = deep / "detection_proposals.py"
    leaf.write_text("# stub")

    resolved = dp_endpoint._resolve_repo_root(leaf.resolve())
    assert resolved == repo.resolve()


def test_resolver_does_not_return_filesystem_root_when_marker_missing(
    tmp_path: Path,
):
    """Reproduces the Docker case: no ``scripts/run_evals.py`` anywhere
    above the file. The fallback must pick a sensible ancestor — *not*
    ``/`` — because the resolved root is later joined with ``scripts/...``
    and a ``/scripts/run_evals.py`` path would mask real bugs.
    """
    api_dir = tmp_path / "app"
    deep = api_dir / "app" / "api" / "v1" / "endpoints"
    deep.mkdir(parents=True)
    fake_module = deep / "detection_proposals.py"
    fake_module.write_text("# stub")

    resolved = dp_endpoint._resolve_repo_root(fake_module.resolve())
    # Must not be the filesystem root.
    assert resolved != Path(resolved.anchor)
    # Must be within tmp_path, i.e. a real ancestor of the start file.
    assert tmp_path in resolved.parents or resolved == tmp_path or tmp_path == resolved


def test_resolver_handles_extremely_shallow_paths(tmp_path: Path):
    """Direct reproduction of the original GH #83 IndexError condition:
    a file with fewer than 6 parents. The old ``parents[6]`` would raise
    ``IndexError: tuple index out of range`` here. The new resolver must
    return *some* path without raising.
    """
    shallow = tmp_path / "detection_proposals.py"
    shallow.write_text("# stub")

    # Must not raise — that's the whole regression.
    resolved = dp_endpoint._resolve_repo_root(shallow.resolve())
    assert isinstance(resolved, Path)


def test_repo_root_honours_env_override(monkeypatch, tmp_path: Path):
    """``AISOC_REPO_ROOT`` lets operators point at an explicit directory
    inside Docker images that ship the ``scripts/`` tree alongside the API.
    Reload the module so the env var is read at import time.
    """
    custom = tmp_path / "custom-root"
    (custom / "scripts").mkdir(parents=True)
    (custom / "scripts" / "run_evals.py").write_text("# marker")

    monkeypatch.setenv("AISOC_REPO_ROOT", str(custom))
    reloaded = importlib.reload(dp_endpoint)

    assert reloaded._REPO_ROOT == custom
    assert reloaded._EVAL_SCRIPT == custom / "scripts" / "run_evals.py"


def test_eval_script_path_is_under_resolved_root():
    """The derived ``_EVAL_SCRIPT`` must always be ``<root>/scripts/run_evals.py``.

    This guards against future refactors silently moving the script path.
    """
    importlib.reload(dp_endpoint)
    assert dp_endpoint._EVAL_SCRIPT.name == "run_evals.py"
    assert dp_endpoint._EVAL_SCRIPT.parent.name == "scripts"
    assert dp_endpoint._EVAL_SCRIPT.parent.parent == dp_endpoint._REPO_ROOT
