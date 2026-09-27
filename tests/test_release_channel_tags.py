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


def run_tags(*, version: str, republish: bool = False, promote_stable: bool = False, demo: bool = False) -> list[str]:
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
