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
    *,
    version: str,
    republish: bool = False,
    promote_stable: bool = False,
    demo: bool = False,
    stable_major: str = "",
    stable_blocked: bool = False,
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
            "STABLE_BLOCKED": "true" if stable_blocked else "false",
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


def test_an_unreadable_channel_is_held_not_taken() -> None:
    """The v20.0.0/v20.1.0 regression, stated as a rule.

    The runner's buildx template broke, the registry read came back empty
    with stderr discarded, and "empty" was read as "first release" — so two
    consecutive publishes carried `stable` across the v19 -> v20 boundary
    the guard exists to refuse. A channel that is present but unreadable is
    now a *blocked* state: the minor publishes, `latest` moves, and `stable`
    stays exactly where it is.
    """
    assert run_tags(version="v20.1.0", stable_blocked=True) == [
        f"{IMAGE}:v20.1.0",
        f"{IMAGE}:latest",
    ]


def test_a_deliberate_promotion_overrides_a_blocked_channel() -> None:
    """Dispatching with promote_stable is the human decision; it may move a
    channel the automatic arm refuses to touch."""
    assert f"{IMAGE}:stable" in run_tags(version="v21.0.0", promote_stable=True, stable_blocked=True)


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


# ── The chart channel, graded on both version lines across a sequence ─────────
#
# #1440. The chart `stable` channel got the image rule keyed on the *chart's*
# own major — and the chart's values default every unpinned image tag to
# `Chart.AppVersion`, so chart 7.9.0 (not a chart major) carried the channel
# onto app v20.0.0, a breaking application release, while every image `stable`
# tag correctly stayed on v19. Same family as the v12/v13/v15 image crossings:
# a channel is a property of history, and the history that matters here runs
# along two version lines at once.
#
# These tests execute the workflow's own `chart-decide` block (pure shell over
# facts the `chart-state` step reads from the registry) with ladders of
# (chart version, app version) releases, carrying the channel's position
# between releases exactly as the registry would.


def _chart_decide_script() -> str:
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    steps = workflow["jobs"]["chart-publish"]["steps"]
    step = next((s for s in steps if s.get("id") == "chart-decide"), None)
    assert step is not None, "release.yml no longer has a `chart-decide` step to check"
    return step["run"]


def run_chart_decide(
    *,
    chart_version: str,
    channel_chart_version: str = "",
    channel_app_major: str = "",
    incoming_app_major: str = "",
    promote_stable: bool = False,
) -> bool:
    """Execute the workflow's own decision block; True when the channel moves."""
    script = _chart_decide_script()
    with tempfile.TemporaryDirectory() as tmp:
        output = Path(tmp) / "gh-output"
        output.touch()
        env = {
            **os.environ,
            "CHART_VERSION": chart_version,
            "PROMOTE_STABLE": "true" if promote_stable else "false",
            "CHANNEL_CHART_VERSION": channel_chart_version,
            "CHANNEL_APP_MAJOR": channel_app_major,
            "INCOMING_APP_MAJOR": incoming_app_major,
            "GITHUB_OUTPUT": str(output),
        }
        done = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True)
        assert done.returncode == 0, f"the workflow's chart-decide block failed: {done.stderr}"
        body = output.read_text(encoding="utf-8")
    moves = [line.split("=", 1)[1] for line in body.splitlines() if line.startswith("move=")]
    assert len(moves) == 1, f"chart-decide emitted {len(moves)} move= lines: {body!r}"
    return moves[0] == "true"


def _app_major(app_version: str) -> str:
    bare = app_version.lstrip("v")
    return bare.split(".")[0] if bare else ""


def run_chart_ladder(
    releases: list[tuple[str, str]],
    *,
    start: tuple[str, str] = ("", ""),
    promote_at: set[str] | None = None,
    unreadable_incoming: set[str] | None = None,
) -> dict[str, str]:
    """Replay (chart version, app version) releases, carrying channel state.

    Returns where the channel ends up on both version lines — the property a
    single-release assertion cannot observe.
    """
    promote_at = promote_at or set()
    unreadable_incoming = unreadable_incoming or set()
    channel_chart, channel_app = start
    for chart_version, app_version in releases:
        incoming = "" if chart_version in unreadable_incoming else _app_major(app_version)
        if run_chart_decide(
            chart_version=chart_version,
            channel_chart_version=channel_chart,
            channel_app_major=channel_app,
            incoming_app_major=incoming,
            promote_stable=chart_version in promote_at,
        ):
            channel_chart, channel_app = chart_version, _app_major(app_version)
    return {"chart": channel_chart, "app_major": channel_app}


class TestChartStableDoesNotCrossAnAppMajorOnItsOwn:
    def test_the_v20_crossing_replayed_is_refused(self) -> None:
        """The exact defect: chart 7.9.0 is no chart major and shares chart
        major 7 with the channel, but its appVersion crosses v19 -> v20."""
        end = run_chart_ladder([("7.8.0", "v19.0.0"), ("7.9.0", "v20.0.0")])

        assert end["chart"] == "7.8.0", (
            f"the channel moved to {end['chart']}, carrying `--version stable` operators across "
            "an application major with nobody deciding — the #1440 crossing again"
        )

    def test_it_stays_put_for_the_whole_of_the_new_app_major(self) -> None:
        end = run_chart_ladder(
            [("7.8.0", "v19.0.0"), ("7.9.0", "v20.0.0"), ("7.9.1", "v20.0.1"), ("7.10.0", "v20.1.0")],
        )

        assert end["chart"] == "7.8.0"
        assert end["app_major"] == "19"

    def test_a_deliberate_promotion_moves_it_and_the_ladder_resumes(self) -> None:
        """The negative control: a guard that froze the channel forever would
        pass the two tests above and make the channel useless."""
        end = run_chart_ladder(
            [("7.8.0", "v19.0.0"), ("7.9.0", "v20.0.0"), ("7.10.0", "v20.1.0")],
            promote_at={"7.9.0"},
        )

        assert end["chart"] == "7.10.0", "the channel did not resume inside the promoted app major"
        assert end["app_major"] == "20"

    def test_the_positive_control_a_same_major_release_still_moves_it(self) -> None:
        """Stuck-closed reads as working caution; a healthy ladder must flow."""
        end = run_chart_ladder([("7.8.0", "v19.0.0"), ("7.8.1", "v19.0.1"), ("7.9.0", "v19.1.0")])

        assert end["chart"] == "7.9.0"

    def test_a_chart_major_is_still_refused_on_its_own_line(self) -> None:
        """The original chart-major guard survives the appVersion addition."""
        end = run_chart_ladder([("7.8.0", "v19.0.0"), ("8.0.0", "v19.1.0")])

        assert end["chart"] == "7.8.0"

    def test_a_first_ever_release_takes_the_channel(self) -> None:
        """No `stable` tag yet is the ordinary first-release state, not a
        different major."""
        end = run_chart_ladder([("1.0.0", "v1.0.0"), ("1.1.0", "v1.1.0")])

        assert end["chart"] == "1.1.0"

    def test_an_unreadable_incoming_app_version_fails_closed(self) -> None:
        """Refusing is recoverable (the next release moves the channel); a
        wrong crossing is not."""
        end = run_chart_ladder(
            [("7.8.0", "v19.0.0"), ("7.8.1", "v19.0.1")],
            unreadable_incoming={"7.8.1"},
        )

        assert end["chart"] == "7.8.0"

    def test_but_not_before_the_first_promotion(self) -> None:
        """An empty *channel* app major is first-release state: an unreadable
        incoming appVersion must not brick the very first promotion."""
        end = run_chart_ladder([("1.1.0", "v1.1.0")], unreadable_incoming={"1.1.0"})

        assert end["chart"] == "1.1.0"

    def test_promotion_overrides_an_unreadable_incoming_app_version(self) -> None:
        """`promote_stable` is the human saying move it — it outranks every
        guard, including the fail-closed one."""
        end = run_chart_ladder(
            [("7.8.0", "v19.0.0"), ("7.9.0", "v20.0.0")],
            promote_at={"7.9.0"},
            unreadable_incoming={"7.9.0"},
        )

        assert end["chart"] == "7.9.0"
