"""`make up` has to be able to deliver a newer image than the one on disk.

What was observed
-----------------
All fifteen first-party services carried `pull_policy: missing` against
`${AISOC_VERSION:-latest}`, a tag that is republished on every merge. `missing`
means "use the local image if there is one", so `git pull && make up` ran
brand-new compose configuration against whatever the machine already had, and
nothing anywhere told an operator to pull. Measured on a real host:

    local  aisoc-web:latest  pulled 08:14 UTC
    GHCR   aisoc-web:latest  published 15:29 UTC, seven commits later

`make up` left the 08:14 image running. A QA pass hit exactly this and ended
up with the API on `main` and the agents service 55 commits behind, which
produced a misleading test result.

Why these assertions run the recipe
-----------------------------------
`pull_policy` being the right string is necessary and not sufficient — the
question is what `make up` *does*, and only running it answers that. The
refresh decision is therefore exercised by invoking the real `_refresh`
recipe with `COMPOSE` pointed at `echo`, so the decision is observable
without contacting a registry.
"""

from __future__ import annotations

import os
import pathlib
import re
import shutil
import subprocess

import pytest
import yaml

REPO = pathlib.Path(__file__).resolve().parents[1]
COMPOSE_FILES = (
    REPO / "docker-compose.yml",
    REPO / "infra" / "compose" / "docker-compose.demo.yml",
)

#: The form every first-party image must carry: overridable, defaulting to
#: `missing`. A bare `missing` is what could not be turned off for an
#: air-gapped host and could not be turned up for a moving tag.
EXPECTED_POLICY = "${AISOC_PULL_POLICY:-missing}"


def _services(path: pathlib.Path) -> dict:
    return (yaml.safe_load(path.read_text(encoding="utf-8")) or {}).get("services") or {}


def _first_party(services: dict) -> dict[str, dict]:
    return {name: service for name, service in services.items() if "ghcr.io/beenuar/aisoc-" in str((service or {}).get("image", ""))}


@pytest.mark.parametrize("path", COMPOSE_FILES, ids=lambda p: p.name)
class TestEveryFirstPartyImageCanBeRefreshed:
    def test_the_file_declares_some(self, path: pathlib.Path) -> None:
        """A compose file that stopped naming first-party images would pass
        every assertion below by having nothing to check."""
        assert _first_party(_services(path)), f"{path.name} names no ghcr.io/beenuar/aisoc-* image"

    def test_pull_policy_is_overridable(self, path: pathlib.Path) -> None:
        hardcoded = {
            name: service.get("pull_policy")
            for name, service in _first_party(_services(path)).items()
            if service.get("pull_policy") != EXPECTED_POLICY
        }
        assert not hardcoded, (
            f"these cannot be refreshed on a moving tag or held back on an air-gapped host: {hardcoded}. "
            f"Use `pull_policy: {EXPECTED_POLICY}`."
        )


def _run_refresh(env: dict[str, str]) -> str:
    """The real `_refresh` recipe, with `COMPOSE` replaced by `echo`.

    Substituting the command rather than mocking the decision is the point:
    the branch under test is written in the Makefile, so the Makefile has to
    be the thing that runs.
    """
    result = subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["make", "--no-print-directory", "_refresh", "COMPOSE=echo compose"],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, **env},
    )
    assert result.returncode == 0, result.stderr
    return result.stdout


@pytest.mark.skipif(shutil.which("make") is None, reason="needs make")
class TestTheRefreshDecision:
    def test_a_moving_tag_pulls(self) -> None:
        out = _run_refresh({"AISOC_VERSION": "latest", "AISOC_PULL_POLICY": ""})
        assert "moving tag" in out
        assert "compose pull" in out, f"the recipe did not reach a pull:\n{out}"

    @pytest.mark.parametrize("tag", ["main", "edge"])
    def test_the_other_moving_tags_pull_too(self, tag: str) -> None:
        assert "compose pull" in _run_refresh({"AISOC_VERSION": tag, "AISOC_PULL_POLICY": ""})

    def test_a_pinned_release_does_not(self) -> None:
        """The other direction. Pulling unconditionally would pass the test
        above and spend a registry round trip per service on every `make up`
        against an immutable tag."""
        out = _run_refresh({"AISOC_VERSION": "v12.0.0", "AISOC_PULL_POLICY": ""})
        assert "pinned and immutable" in out
        assert "compose pull" not in out, f"a pinned tag was refetched:\n{out}"

    def test_an_airgapped_host_never_reaches_a_registry(self) -> None:
        out = _run_refresh({"AISOC_VERSION": "latest", "AISOC_PULL_POLICY": "never"})
        assert "not contacting a registry" in out
        assert "compose pull" not in out, f"AISOC_PULL_POLICY=never still pulled:\n{out}"


class TestUpCannotSkipTheRefresh:
    """`_refresh` existing is worth nothing if `up` does not depend on it —
    which is the same shape as the defect: a mechanism present and uncalled.
    """

    @pytest.mark.parametrize("target", ["up", "up-full"])
    def test_the_target_depends_on_it(self, target: str) -> None:
        text = (REPO / "Makefile").read_text(encoding="utf-8")
        match = re.search(rf"^{re.escape(target)}:(.*)$", text, re.M)
        assert match, f"no `{target}:` target in the Makefile"
        assert "_refresh" in match.group(1), f"`{target}` does not depend on _refresh: {match.group(1)!r}"


class TestTheUpgradePathIsDocumented:
    """The QA pass that found this had no document to follow. A mechanism
    nobody is told about is only half a fix."""

    def test_the_deployment_page_says_how_to_upgrade(self) -> None:
        page = (REPO / "apps" / "docs" / "docs" / "deployment" / "docker.md").read_text(encoding="utf-8")
        assert "### Upgrading" in page
        assert "git pull" in page
        assert "AISOC_PULL_POLICY" in page, "the air-gapped escape hatch has to be discoverable"
