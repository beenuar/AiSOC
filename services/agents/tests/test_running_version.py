"""The version this service reports must be the version in the tree.

``_make_resource`` read ``os.getenv("AISOC_VERSION", "4.0.0")``, so every
span this service emitted was labelled ``service.version=4.0.0`` — a literal
that outlived eighteen majors. Traces from a v22.2.0 deployment were
attributed to a release nobody was running, which is worse than an absent
label: a dashboard grouping by version shows a tidy, confident, wrong answer.

``app/core/version.py`` is a byte-identical copy of the one in
``services/api``, vendored the way ``cors.py`` and ``_health.py`` are because
services do not share a Python path. This file is the agents-side half of the
pair: it keeps the copy honest in its own service rather than relying on the
API's suite to cover code that is compiled into a different image.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from app.core.version import UNKNOWN_VERSION, resolve_version

REPO_ROOT = Path(__file__).resolve().parents[3]
VERSION_FILE = REPO_ROOT / "VERSION"


@pytest.fixture(scope="module")
def tree_version() -> str:
    assert VERSION_FILE.is_file(), f"repo-root VERSION file is missing at {VERSION_FILE}"
    return VERSION_FILE.read_text(encoding="utf-8").strip()


def test_resolver_reports_the_tree_version(tree_version: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AISOC_VERSION", raising=False)
    assert resolve_version() == tree_version


def test_telemetry_resource_carries_the_tree_version(tree_version: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """The assertion that would have caught ``4.0.0``.

    Driven through ``_make_resource`` rather than through the resolver alone,
    because the defect was not in resolving a version — it was that this call
    site never asked for one.
    """
    monkeypatch.delenv("AISOC_VERSION", raising=False)
    from app.core.telemetry import _make_resource
    from opentelemetry.sdk.resources import SERVICE_VERSION

    assert _make_resource().attributes[SERVICE_VERSION] == tree_version


def test_a_stamped_build_arg_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AISOC_VERSION", "23.0.0-rc2")
    assert resolve_version() == "23.0.0-rc2"


def test_unknown_is_not_a_version_number() -> None:
    """A trace labelled 0.0.0 is a wrong answer; 'unknown' is an honest one."""
    assert UNKNOWN_VERSION == "unknown"
    assert not UNKNOWN_VERSION[:1].isdigit()


def test_unknown_when_nothing_declares_a_version(tmp_path: Path) -> None:
    nested = tmp_path / "app" / "core"
    nested.mkdir(parents=True)
    assert resolve_version(env={}, start=nested) == UNKNOWN_VERSION
