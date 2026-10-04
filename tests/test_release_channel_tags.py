"""The `stable` channel is a rule, so it is executed rather than read.

`latest` moves on every release, majors included. A deployment that pulls by
tag is therefore dragged across a breaking change by a tag whose name promises
the opposite, with no operator decision in between. `stable` exists to be the
tag that does not do that: it advances on a minor or a patch and stops at a
major until someone promotes it deliberately.

That rule lives in a shell block inside `.github/workflows/release.yml`, which
runs only on a tag push. A rule that executes a handful of times a year, in an
environment nobody can step through, is a rule that rots. So this test lifts
that exact block out of the workflow and runs it under bash with each
combination of inputs. It does not re-implement the logic: a copy would agree
with itself while the workflow drifted.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
IMAGE = "ghcr.io/beenuar/aisoc-core-api"


def _tag_script() -> str:
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    steps = workflow["jobs"]["docker-manifest"]["steps"]
    step = next((s for s in steps if s.get("id") == "image-tags"), None)
    assert step is not None, "release.yml no longer has an `image-tags` step to check"
    return step["run"]


def run_tags(
    *, version: str, republish: bool = False, promote_stable: bool = False, demo: bool = False, stable_major: str = ""
) -> list[str]:
    """Execute the workflow's own tag block and return the tags it emitted."""
    script = _tag_script()
    with tempfile.TemporaryDirectory() as tmp:
        output = Path(tmp) / "gh-output"
        output.touch()
        env = {
            **os.environ,
            "VERSION": version,
            "REPUBLISH": "true" if republish else "false",
            "PROMOTE_STABLE": "true" if promote_stable else "false",
            "IMAGE": IMAGE,
            "IS_DEMO": "true" if demo else "false",
            "STABLE_MAJOR": stable_major,
            "GITHUB_OUTPUT": str(output),
        }
        done = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True)
        assert done.returncode == 0, f"the workflow's tag block failed: {done.stderr}"
        body = output.read_text(encoding="utf-8")
    lines = body.splitlines()
    assert lines and lines[0] == "tags<<EOF", f"unexpected step output: {body!r}"
    return [line for line in lines[1:] if line and line != "EOF"]


def test_a_minor_release_moves_both_latest_and_stable() -> None:
    assert run_tags(version="v11.3.0") == [
        f"{IMAGE}:v11.3.0",
        f"{IMAGE}:latest",
        f"{IMAGE}:stable",
    ]


def test_a_patch_release_moves_both() -> None:
    assert f"{IMAGE}:stable" in run_tags(version="v11.2.1")


def test_a_major_release_moves_latest_but_not_stable() -> None:
    tags = run_tags(version="v12.0.0")
    assert f"{IMAGE}:latest" in tags
    assert f"{IMAGE}:stable" not in tags, (
        "a major moved `stable` on its own, so a tag-pulling deployment would cross a breaking change with no operator decision"
    )


def test_a_major_reaches_stable_only_when_promoted_deliberately() -> None:
    assert f"{IMAGE}:stable" in run_tags(version="v12.0.0", republish=True, promote_stable=True)


def test_repairing_an_old_tag_moves_neither_channel() -> None:
    tags = run_tags(version="v11.0.0", republish=True)
    assert tags == [f"{IMAGE}:v11.0.0"], (
        "a republish moved a channel tag, which is how a repair hands self-hosters older content than main on the tag they pull by default"
    )


def test_the_demo_bundle_never_carries_a_channel_tag() -> None:
    tags = run_tags(version="v11.3.0", demo=True)
    assert tags == [f"{IMAGE}:v11.3.0-demo", f"{IMAGE}:demo"]
    assert not any(t.endswith(":latest") or t.endswith(":stable") for t in tags), (
        "the demo console shipped on a channel tag; a self-hoster would get a console announcing daily demo resets over their real alerts"
    )


@pytest.mark.parametrize("version", ["v1.0.0", "v10.0.0", "v100.0.0"])
def test_every_x_0_0_is_recognised_as_a_major(version: str) -> None:
    assert f"{IMAGE}:stable" not in run_tags(version=version)


@pytest.mark.parametrize("version", ["v1.0.1", "v10.1.0", "v11.2.10"])
def test_nothing_else_is(version: str) -> None:
    assert f"{IMAGE}:stable" in run_tags(version=version)


def test_the_promote_stable_input_is_declared_so_the_dispatch_arm_is_reachable() -> None:
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    # PyYAML parses a bare `on:` key as the boolean True.
    triggers = workflow.get("on", workflow.get(True))
    inputs = triggers["workflow_dispatch"]["inputs"]
    assert "promote_stable" in inputs, (
        "the block reads PROMOTE_STABLE but the workflow declares no such input, so the only path "
        "by which `stable` can reach a major is unreachable"
    )


# ── The channel across a sequence of releases ────────────────────────────────
#
# Fix-pass item 5.5. Every test above asks one question of one release, and
# the channel's whole purpose is a property of a *sequence*: `stable` must not
# arrive at a major without an operator saying so. Asked one release at a time
# the answer always looked right -- `v16.0.0` correctly does not move it -- and
# `v16.1.0` then carried it across the boundary the next day, because a minor
# is not a major and nothing in the block knew which major `stable` was on.
#
# That is how `stable` reached v12, v13 and v15.


def run_ladder(versions: list[str], *, stable_major: str = "", promote_at: set[str] | None = None) -> dict[str, str | None]:
    """Replay a release ladder, carrying the channel's major between releases.

    Returns the version `stable` points at after each release, which is the
    thing a single-release test cannot observe.
    """
    promote_at = promote_at or set()
    where: str | None = None
    for version in versions:
        tags = run_tags(
            version=version,
            promote_stable=version in promote_at,
            stable_major=stable_major,
        )
        if f"{IMAGE}:stable" in tags:
            where = version
            stable_major = version.lstrip("v").split(".")[0]
    return {"stable": where, "major": stable_major}


class TestStableDoesNotCrossAMajorOnItsOwn:
    def test_the_first_minor_of_a_new_major_does_not_carry_the_channel(self) -> None:
        """The defect, stated as a ladder.

        `v15.2.0` is where `stable` sits. `v16.0.0` correctly refuses it. Then
        `v16.1.0` arrives and -- being a minor -- takes it, so a deployment
        pulling `stable` crosses the breaking change with nobody deciding to.
        """
        end = run_ladder(["v15.1.0", "v15.2.0", "v16.0.0", "v16.1.0"], stable_major="15")

        assert end["stable"] == "v15.2.0", f"stable moved to {end['stable']}, crossing into v16 with no operator action"

    def test_it_stays_put_for_the_whole_of_the_new_major(self) -> None:
        """Not just the first minor. Nothing in v16 takes it."""
        end = run_ladder(
            ["v15.2.0", "v16.0.0", "v16.1.0", "v16.1.1", "v16.2.0", "v16.3.0"],
            stable_major="15",
        )

        assert end["stable"] == "v15.2.0"

    def test_a_deliberate_promotion_moves_it_and_the_channel_follows(self) -> None:
        """The negative control, and the half that matters most.

        A guard that simply froze `stable` forever would pass the two tests
        above and make the channel useless. After an operator promotes
        `v16.0.0`, the ladder must resume: v16's own minors carry it again.
        """
        end = run_ladder(
            ["v15.2.0", "v16.0.0", "v16.1.0", "v16.2.0"],
            stable_major="15",
            promote_at={"v16.0.0"},
        )

        assert end["stable"] == "v16.2.0", "the channel did not resume inside the promoted major"
        assert end["major"] == "16"

    def test_a_first_ever_release_takes_the_channel(self) -> None:
        """A registry with no `stable` tag yet must not be read as "a different
        major", or a new deployment would never get one."""
        end = run_ladder(["v1.0.0", "v1.1.0"], stable_major="")

        assert end["stable"] == "v1.1.0"
