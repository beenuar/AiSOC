"""A gate must be inventoried for what it does, not what it is called.

``scripts/check_gate_coverage.py`` resolves the workflow-to-check graph so an
orphaned gate cannot hide. It used to decide *which* scripts to resolve by
filename — ``check_*``, ``validate_*``, ``_conformance.py``, plus a list of
five exceptions — which is the same defect one level up: a gate named
something unexpected was not inventoried, and an uninventoried gate is
indistinguishable from one that does not exist.

Nineteen were in exactly that state. Every one is a CI gate today, eleven of
them run by a workflow with ``--check``; deleting any of those steps would
have left the script reporting full coverage over a smaller tree.

These tests pin the structural classifier, in both directions: a gate under a
name no convention would reveal must be found, and a generator that aborts on
an empty read must not be mistaken for one.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import check_gate_coverage as cgc  # noqa: E402

#: What the filename test used to accept. Kept here, in the test rather than
#: in the script, so "the classifier no longer depends on naming" is an
#: assertion instead of a claim.
_OLD_PREFIXES = ("check_", "validate_", "audit_", "lint_", "verify_")
_OLD_SUFFIXES = ("_check.py", "_gates.py", "_conformance.py", "_audit.py")
_OLD_EXTRA = {
    "connector_conformance.py",
    "detection_truth_table.py",
    "openapi_diff.py",
    "readme_gates.py",
    "security_audit.py",
}


def _named_like_a_check(name: str) -> bool:
    if name in _OLD_EXTRA or Path(name).match("sync_vendored_*.py"):
        return True
    return name.startswith(_OLD_PREFIXES) or name.endswith(_OLD_SUFFIXES)


@pytest.fixture(scope="module")
def inventory() -> dict[str, dict[str, str]]:
    return cgc.load(REPO_ROOT)["checks"]


# --------------------------------------------------------------------------
# A gate under an unconventional name
# --------------------------------------------------------------------------
UNCONVENTIONAL_GATE = '''\
#!/usr/bin/env python3
"""frobnicate_widgets.py — a gate whose name announces nothing."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    offenders = []
    for path in ROOT.glob("docs/**/*.md"):
        if "\\t" in path.read_text(encoding="utf-8", errors="replace"):
            offenders.append(str(path))
    if offenders:
        print(f"{len(offenders)} document(s) contain a literal tab:")
        for path in offenders:
            print(f"  {path}")
        return 1
    print("OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''


def test_a_gate_planted_under_an_unconventional_name_is_found() -> None:
    """The case the old classifier could not see.

    `frobnicate_widgets.py` matches no prefix, no suffix and no exception
    list, and nothing invokes it — so only an intrinsic signal can find it.
    """
    assert not _named_like_a_check("frobnicate_widgets.py")
    signals = cgc.classify_source(UNCONVENTIONAL_GATE)
    assert signals, "a script that exits non-zero on findings it collected must be inventoried"
    assert "findings-exit" in signals


def test_the_planted_gate_is_reported_as_unreachable_when_nothing_runs_it(inventory) -> None:
    """Being found is only half of it — the gate must then fail on it.

    A classifier that inventories a script but whose rules never act on the
    inventory is the vacuous case this whole script exists to disprove.
    """
    checks = {**inventory, "frobnicate_widgets.py": cgc.classify_source(UNCONVENTIONAL_GATE)}
    routes = {name: ["workflow:ci.yml"] for name in inventory}
    routes["frobnicate_widgets.py"] = []
    codes = {code for code, _ in cgc.evaluate(checks, routes, [], {})}
    assert "check-unreachable" in codes


# --------------------------------------------------------------------------
# The inverse: not everything that exits non-zero is a gate
# --------------------------------------------------------------------------
ABORTING_GENERATOR = '''\
#!/usr/bin/env python3
"""Renders a document. Exits non-zero when it has nothing to render."""

import sys
from pathlib import Path


def main() -> int:
    specs = sorted(Path("specs").glob("*.yaml"))
    if not specs:
        print("no specs found", file=sys.stderr)
        return 1
    Path("out.md").write_text("\\n".join(p.name for p in specs))
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''

NETWORK_TOOL = '''\
#!/usr/bin/env python3
"""Posts events to a running service. Not a verdict about the tree."""

import sys
import urllib.request

EVENTS = [{"a": 1}, {"b": 2}]


def main() -> int:
    sent = 0
    for event in EVENTS:
        urllib.request.urlopen("http://localhost:8000", data=b"{}")
        sent += 1
    if sent < len(EVENTS):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''


def test_a_generator_that_aborts_on_an_empty_read_is_not_a_check() -> None:
    """Polarity is the whole distinction.

    ``if not specs: return 1`` says "I could not do my job". ``if offenders:
    return 1`` says "I found something". Only the second is a verdict.
    """
    assert cgc.classify_source(ABORTING_GENERATOR) == {}


def test_a_script_that_only_talks_to_a_service_is_not_a_check() -> None:
    assert cgc.classify_source(NETWORK_TOOL) == {}


# --------------------------------------------------------------------------
# What the change did to the inventory
# --------------------------------------------------------------------------
def test_structural_classification_is_a_superset_of_the_old_names(inventory) -> None:
    """Nothing the filename test caught may be dropped.

    A classifier that traded nineteen false negatives for one is not an
    improvement, and a silently smaller inventory is how coverage is lost.
    """
    named = {p.name for p in (REPO_ROOT / "scripts").glob("*.py") if _named_like_a_check(p.name)}
    dropped = named - set(inventory)
    assert not dropped, f"structural classification lost {sorted(dropped)}"


def test_the_inventory_grew_by_the_scripts_the_names_hid(inventory) -> None:
    """The count moved, and this says by how much and why.

    Every added script is classified by an intrinsic signal — what it does —
    not by the fact that something happens to run it.
    """
    named = {p.name for p in (REPO_ROOT / "scripts").glob("*.py") if _named_like_a_check(p.name)}
    added = set(inventory) - named
    assert len(added) >= 15, f"expected the name-based test to have been hiding gates; found {sorted(added)}"
    for name in added:
        assert set(inventory[name]) - {"gates-a-workflow"}, f"{name} is inventoried only because something runs it"


def test_every_verdict_flag_invocation_in_ci_is_inventoried() -> None:
    """CLASSIFIER -> WORKFLOW, the other direction.

    If a workflow runs a script with ``--check`` it is asking for a verdict.
    A classifier that does not call that script a check has a blind spot, and
    this is the assertion that finds it rather than a reader noticing.
    """
    data = cgc.load(REPO_ROOT)
    missing = sorted(set(data["verdict_invocations"]) - set(data["checks"]))
    assert not missing, f"CI asks these for a verdict but the classifier does not inventory them: {missing}"


def test_blind_spot_rule_fires(inventory) -> None:
    codes = {
        code
        for code, _ in cgc.evaluate(
            inventory,
            {name: ["workflow:ci.yml"] for name in inventory},
            [],
            {},
            {"some_unclassified_thing.py": "ci.yml"},
        )
    }
    assert "classifier-blind-spot" in codes


def test_generated_connector_types_is_inventoried(inventory) -> None:
    """The generator this change also added must itself be under the gate."""
    assert "generate_connector_types.py" in inventory
    assert "verdict-flag" in inventory["generate_connector_types.py"]


def test_self_test_passes() -> None:
    assert cgc.self_test(REPO_ROOT) == 0


def test_a_script_named_as_a_diff_path_is_not_a_job_asking_it_for_a_verdict() -> None:
    """`gates-a-workflow` must mean the job *runs* it, not that it says its name.

    `integration.yml`'s `changes` job publishes outputs the other jobs branch
    on, and lists `scripts/backup_crypt.py` among the paths whose modification
    should run the disaster-recovery gate. The matcher looked for the bare
    path anywhere in the job's YAML, so an encryption utility was inventoried
    as a gate on the strength of appearing in a filter — the same shape as the
    matcher that counted eleven services as CI-covered because a path sat
    inside a quoted `echo`.
    """
    job = {
        "outputs": {"backup": "${{ steps.areas.outputs.backup }}"},
        "steps": [{"run": "backup_paths='scripts/backup.sh scripts/backup_crypt.py'\ngrep -q \"$p\" /tmp/changed.txt"}],
    }
    doc = {"jobs": {"changes": job, "dr": {"if": "needs.changes.outputs.backup == 'true'"}}}

    assert cgc._gating_jobs(doc, "integration.yml") == {}


def test_a_job_that_runs_a_script_and_publishes_an_output_still_counts() -> None:
    """The other direction: `wet_eval_check.py` has no intrinsic signal at all
    and is inventoried only through the job graph, so tightening the matcher
    must not drop it."""
    job = {
        "outputs": {"run": "${{ steps.pre.outputs.run }}"},
        "steps": [{"run": "python3 scripts/wet_eval_check.py --status-out /tmp/preflight.json"}],
    }
    doc = {"jobs": {"preflight": job, "eval": {"if": "needs.preflight.outputs.run == 'true'"}}}

    assert cgc._gating_jobs(doc, "wet-eval.yml") == {"wet_eval_check.py": "wet-eval.yml:preflight"}
