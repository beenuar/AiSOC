"""The version this service reports must be the version in the tree.

Why this test is shaped the way it is
-------------------------------------
``settings.APP_VERSION`` was the literal ``"0.1.0"`` and nothing populated
it, so a v22.2.0 deployment answered ``0.1.0`` on ``/health`` and published
``0.1.0`` as ``info.version`` in its OpenAPI document. Every surface agreed,
which is exactly why nobody noticed: the three of them were consistently
wrong together.

A test asserting "the version is a non-empty string" would have passed
throughout. So the assertion here is equality with the repo-root ``VERSION``
file — the one artefact ``scripts/check_release_policy.py`` already holds
``apps/web/package.json`` to. A version surface is only worth testing against
the number a release actually moved.

The unknown case is tested too, and deliberately: when no build arg was
stamped and no ``VERSION`` file is reachable, the resolver must say so rather
than return a plausible-looking number. ``0.1.0`` was not a missing value, it
was a *confident wrong* one, and an operator comparing it against a release
tag has no way to tell those apart.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from app.core.config import settings
from app.core.version import UNKNOWN_VERSION, resolve_version
from app.main import app
from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parents[3]
VERSION_FILE = REPO_ROOT / "VERSION"


@pytest.fixture(scope="module")
def tree_version() -> str:
    assert VERSION_FILE.is_file(), f"repo-root VERSION file is missing at {VERSION_FILE}"
    return VERSION_FILE.read_text(encoding="utf-8").strip()


class TestReportedVersionMatchesTheTree:
    def test_settings_app_version_is_the_tree_version(self, tree_version: str) -> None:
        assert settings.APP_VERSION == tree_version

    def test_version_alias_cannot_disagree_with_app_version(self) -> None:
        """Two fields for one fact is two chances to be wrong about it."""
        assert settings.VERSION == settings.APP_VERSION

    def test_health_reports_the_tree_version(self, tree_version: str) -> None:
        with TestClient(app) as client:
            body = client.get("/health").json()
        assert body["version"] == tree_version

    def test_openapi_info_version_is_the_tree_version(self, tree_version: str) -> None:
        assert app.openapi()["info"]["version"] == tree_version


class TestResolverPrecedence:
    """Build arg first, then the tree, then an explicit unknown."""

    def test_build_arg_wins(self, tmp_path: Path) -> None:
        (tmp_path / "VERSION").write_text("9.9.9\n", encoding="utf-8")
        resolved = resolve_version(env={"AISOC_VERSION": "22.2.0-rc1"}, start=tmp_path / "svc" / "app")
        assert resolved == "22.2.0-rc1"

    def test_falls_back_to_the_version_file(self, tmp_path: Path) -> None:
        (tmp_path / "VERSION").write_text("7.1.3\n", encoding="utf-8")
        nested = tmp_path / "services" / "api" / "app" / "core"
        nested.mkdir(parents=True)
        assert resolve_version(env={}, start=nested) == "7.1.3"

    def test_unknown_when_nothing_declares_a_version(self, tmp_path: Path) -> None:
        """No build arg and no reachable VERSION file is not version zero."""
        nested = tmp_path / "app" / "core"
        nested.mkdir(parents=True)
        resolved = resolve_version(env={}, start=nested)
        assert resolved == UNKNOWN_VERSION
        assert resolved == "unknown"

    def test_unknown_is_not_a_version_number(self) -> None:
        """Pin the shape, so a later edit cannot quietly reinstate a default.

        The failure this guards against is not "the constant changed" but
        "the constant changed to something an operator would read as a real
        release". ``0.0.0`` and ``0.1.0`` both parse as versions and both
        sort below every tag that has ever shipped, so a dashboard comparing
        them against a release would show a very old deployment rather than
        an unanswerable question.
        """
        assert not UNKNOWN_VERSION[:1].isdigit()

    @pytest.mark.parametrize("junk", ["", "   ", "latest", "not-a-version", "v1"])
    def test_a_version_file_that_is_not_a_version_is_ignored(self, tmp_path: Path, junk: str) -> None:
        """A bounded upward walk can meet somebody else's ``VERSION`` file.

        ``/VERSION`` exists on some base images and means something unrelated.
        Accepting whatever the walk finds first would report that string as
        the running release, so the content has to look like a release before
        it is believed — and when it does not, the answer is unknown.
        """
        (tmp_path / "VERSION").write_text(junk, encoding="utf-8")
        nested = tmp_path / "app" / "core"
        nested.mkdir(parents=True)
        assert resolve_version(env={}, start=nested) == UNKNOWN_VERSION

    def test_blank_build_arg_is_not_a_version(self, tmp_path: Path) -> None:
        """An unset build arg arrives as an empty string, not as absence.

        ``ARG AISOC_VERSION`` with no ``--build-arg`` produces ``""`` in the
        image's environment. Treating that as "declared" would publish an
        empty version string, which renders as nothing at all in a console
        tile and reads as a layout bug rather than a missing value.
        """
        (tmp_path / "VERSION").write_text("5.0.1\n", encoding="utf-8")
        nested = tmp_path / "app"
        nested.mkdir(parents=True)
        assert resolve_version(env={"AISOC_VERSION": "  "}, start=nested) == "5.0.1"
