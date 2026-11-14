"""A skipped upload must not read as a successful publish.

On the v12.2.0 release run all 59 jobs reported success. Eight of them were
named `npm — publish <pkg>` or `PyPI — publish <pkg>`, and all eight packages
returned 404 from their registry. Only the final upload step is credential-
gated, so each job built the artefact, reached the upload, skipped it on a
missing credential, and exited 0. Nothing was red, nothing was uploaded, and
the Actions page said otherwise.

The credential gate is correct and stays. What changed is that the decision is
made once, in `package-credentials`, and then named in three places a reader
can see: the job titles in the Actions list, the log line in each job, and the
run summary written by `package-report`.

This file holds that shape in place. Two kinds of check, because they fail
differently:

* the decision itself is *executed* — the preflight's shell block is lifted
  out of the workflow and run under bash with each combination of event and
  credential, the same way `test_release_channel_tags.py` runs the tag block.
  A copy of the logic would agree with itself while the workflow drifted.

* the wiring is *structural* — every step that can upload a package must be
  guarded by that decision, and the job titles must vary with it. That is the
  direction the original defect came from: the gate was right and nothing
  carried its answer anywhere a reader would look.
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

#: The one job that decides whether an upload can happen.
DECIDER = "package-credentials"

#: The jobs whose whole purpose is to ship a package.
PUBLISH_JOBS = ("npm-publish", "pypi-publish")


def _workflow() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def _job(job_id: str) -> dict:
    jobs = _workflow()["jobs"]
    assert job_id in jobs, f"release.yml no longer has a `{job_id}` job; this test is checking a workflow that moved"
    return jobs[job_id]


def _probe_script() -> str:
    step = next((s for s in _job(DECIDER)["steps"] if s.get("id") == "probe"), None)
    assert step is not None, f"`{DECIDER}` no longer has a `probe` step"
    return step["run"]


def run_probe(*, event: str, npm_token: str = "", npm_trusted: str = "", pypi_trusted: str = "") -> dict[str, str]:
    """Execute the workflow's own credential block and return its outputs."""
    with tempfile.TemporaryDirectory() as tmp:
        output = Path(tmp) / "gh-output"
        summary = Path(tmp) / "gh-summary"
        output.touch()
        summary.touch()
        env = {
            **os.environ,
            "NPM_TOKEN": npm_token,
            "NPM_TRUSTED": npm_trusted,
            "PYPI_TRUSTED": pypi_trusted,
            # The workflow renders `github.event_name == 'push'` into this.
            "UPLOADS_POSSIBLE": "true" if event == "push" else "false",
            "GITHUB_OUTPUT": str(output),
            "GITHUB_STEP_SUMMARY": str(summary),
        }
        done = subprocess.run(["bash", "-c", _probe_script()], env=env, capture_output=True, text=True)
        assert done.returncode == 0, f"the credential block failed: {done.stderr}"
        pairs = dict(line.split("=", 1) for line in output.read_text(encoding="utf-8").splitlines() if "=" in line)
        pairs["_summary"] = summary.read_text(encoding="utf-8")
    return pairs


# --------------------------------------------------------------------------
# The decision, executed
# --------------------------------------------------------------------------


def test_no_credential_means_no_upload_on_a_tag_push() -> None:
    """The repository's state today: one secret, `FLY_API_TOKEN`, no variables."""
    decided = run_probe(event="push")
    assert decided["npm"] == "unarmed"
    assert decided["pypi"] == "unarmed"


def test_an_npm_token_arms_npm_alone() -> None:
    decided = run_probe(event="push", npm_token="npm_xxx")
    assert decided["npm"] == "armed"
    assert decided["pypi"] == "unarmed", "a token for one registry must not arm the other"


def test_trusted_publishing_arms_each_registry_independently() -> None:
    assert run_probe(event="push", npm_trusted="true")["npm"] == "armed"
    assert run_probe(event="push", pypi_trusted="true")["pypi"] == "armed"


@pytest.mark.parametrize("credentials", [{}, {"npm_token": "npm_xxx"}, {"npm_trusted": "true", "pypi_trusted": "true"}])
def test_a_dispatched_run_never_uploads_however_well_credentialled(credentials: dict) -> None:
    """A registry refuses a version it already holds, so a republish cannot work.

    Worth executing rather than reading: the packages-only dispatch exists so
    the packaging path can be exercised on demand, and an exercise that could
    reach a real upload would be a footgun rather than a test.
    """
    decided = run_probe(event="workflow_dispatch", **credentials)
    assert decided["npm"] == "unarmed"
    assert decided["pypi"] == "unarmed"


def test_the_summary_states_the_outcome_and_the_reason() -> None:
    summary = run_probe(event="push")["_summary"]
    assert "packs only" in summary
    assert "NPM_TOKEN" in summary and "AISOC_PYPI_TRUSTED_PUBLISHING" in summary, (
        "the run summary must name what is missing, or a reader learns only that something did not happen"
    )
    assert "uploads" not in summary.replace("Package uploads", ""), "the summary claimed an upload while both registries were unarmed"


# --------------------------------------------------------------------------
# The wiring, structurally
# --------------------------------------------------------------------------


def _upload_steps(job: dict) -> list[dict]:
    """Steps that can put a package on a registry."""
    found = []
    for step in job["steps"]:
        run = step.get("run") or ""
        uses = step.get("uses") or ""
        if "npm publish" in run or "gh-action-pypi-publish" in uses:
            found.append(step)
    return found


@pytest.mark.parametrize("job_id", PUBLISH_JOBS)
def test_the_job_title_changes_with_the_credential_state(job_id: str) -> None:
    """The defect in one assertion: a constant title cannot report an outcome.

    `needs` is one of the few contexts a job `name:` can read, which is the
    whole reason the decision lives in its own job — `secrets` is unavailable
    in a job-level `name:` or `if:`.
    """
    name = _job(job_id)["name"]
    assert f"needs.{DECIDER}.outputs" in name, (
        f"`{job_id}` has a fixed title, so a run that uploaded nothing is indistinguishable "
        f"in the Actions list from one that published every package"
    )
    assert "NOT uploaded" in name, f"`{job_id}`'s unarmed title does not say that nothing was uploaded"


@pytest.mark.parametrize("job_id", PUBLISH_JOBS)
def test_every_upload_step_is_guarded_by_that_same_decision(job_id: str) -> None:
    """A second upload path added later must not bypass the signal.

    The direction that matters: the title is driven by `package-credentials`,
    so an upload reachable without consulting it would publish under a title
    saying nothing was uploaded — the original defect, inverted.
    """
    job = _job(job_id)
    steps = _upload_steps(job)
    assert steps, f"`{job_id}` has no upload step at all; it cannot publish anything"
    for step in steps:
        condition = step.get("if") or ""
        assert f"needs.{DECIDER}.outputs" in condition, f"`{job_id}` step {step.get('name')!r} can upload without consulting `{DECIDER}`"


@pytest.mark.parametrize("job_id", PUBLISH_JOBS)
def test_a_job_that_uploaded_nothing_says_so_in_its_log(job_id: str) -> None:
    job = _job(job_id)
    explains = [s for s in job["steps"] if "nothing was uploaded" in (s.get("name") or "").lower()]
    assert explains, f"`{job_id}` has no step that states a skipped upload"
    for step in explains:
        assert f"needs.{DECIDER}.outputs" in (step.get("if") or ""), (
            f"`{job_id}`'s explanation step is not tied to the credential decision, so it can fire on a run that did publish"
        )


def test_the_report_asks_the_registry_rather_than_the_workflow() -> None:
    job = _job("package-report")
    runs = " ".join(s.get("run") or "" for s in job["steps"])
    assert "check_published_packages.py" in runs, "the publication report does not run the registry gate"
    assert "--require-network" in runs, "the report may skip when a registry is unreachable, which is the one question it exists to answer"
    assert "GITHUB_STEP_SUMMARY" in runs, "the report does not reach the run summary, so a reader must open a log"


def test_the_report_survives_a_failed_package_build() -> None:
    """A report that only appears on the happy path is not a report."""
    condition = _job("package-report")["if"]
    assert "always()" in condition, "the publication report is skipped whenever a package job fails"


def test_the_packages_only_input_exists_so_the_path_can_be_exercised() -> None:
    """`!inputs.packages_only` is vacuously true when no such input is declared.

    The same shape as the `promote_stable` check in
    `test_release_channel_tags.py`: a condition naming an undeclared input is
    a branch that can never be taken, and it looks identical to one that can.
    """
    workflow = _workflow()
    # PyYAML parses a bare `on:` key as the boolean True.
    triggers = workflow.get("on", workflow.get(True))
    assert triggers, "release.yml declares no triggers at all"
    assert "packages_only" in triggers["workflow_dispatch"]["inputs"]
    assert "inputs.packages_only" in workflow["jobs"]["docker-build"]["if"], (
        "a packages-only dispatch would still rebuild and re-push every image"
    )
    for job_id in (*PUBLISH_JOBS, DECIDER):
        reachable = _job(job_id)["if"]
        assert "inputs.packages_only" in reachable or "always()" in reachable, (
            f"`{job_id}` cannot run on a packages-only dispatch, so the path cannot be exercised before a tag"
        )


# --------------------------------------------------------------------------
# The neighbouring skips found in the same audit
# --------------------------------------------------------------------------


def test_a_release_cannot_ship_without_the_assets_it_advertises() -> None:
    """`action-gh-release` defaults `fail_on_unmatched_files` to false.

    A `files:` entry that matches nothing is dropped and the release is
    created without it, green — so the release page can advertise an SBOM and
    a checksum file it does not carry.
    """
    steps = _job("release")["steps"]
    create = next(s for s in steps if "action-gh-release" in (s.get("uses") or ""))
    assert create["with"].get("fail_on_unmatched_files") is True, "a missing release asset would be silently dropped from the release"
    assert any("advertised release asset" in (s.get("name") or "") for s in steps), (
        "nothing checks that the advertised assets exist before the release is created"
    )


def test_the_chart_notice_about_an_unpushed_chart_is_reachable() -> None:
    """It was not: the job's own condition reduced to "this is a push".

    `release` runs only on a push, so `github.event_name == 'push' ||
    needs.release.result == 'success'` was true exactly when the event was a
    push — leaving a step conditioned on `github.event_name != 'push'` inside
    a job that could only run on one.
    """
    job = _job("chart-publish")
    assert "github.event_name" not in job["if"], "chart-publish is gated on the event again, which makes its not-a-push branch dead"
    notice = next((s for s in job["steps"] if "unpushed chart" in (s.get("name") or "")), None)
    assert notice is not None and "!= 'push'" in notice["if"]
