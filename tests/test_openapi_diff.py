"""Phase 11 — OpenAPI breaking-change detector tests.

Proves the detector flags every breaking class from an existing client's
perspective and, crucially, does NOT flag safe additive changes (a breaking-
change gate that cries wolf on every additive PR gets disabled).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import openapi_diff as od  # noqa: E402

_REPO = Path(__file__).resolve().parents[1]
_WORKFLOW = _REPO / ".github" / "workflows" / "openapi-breaking.yml"
_LABEL = "breaking-change-approved"


def _spec(paths=None, schemas=None):
    return {
        "openapi": "3.1.0",
        "paths": paths or {},
        "components": {"schemas": schemas or {}},
    }


def _kinds(changes):
    return {c.kind for c in changes if c.breaking}


# ── Breaking classes ─────────────────────────────────────────────────────────


def test_removed_path_is_breaking():
    old = _spec(paths={"/a": {"get": {}}})
    new = _spec(paths={})
    assert "path_removed" in _kinds(od.diff(old, new))


def test_removed_operation_is_breaking():
    old = _spec(paths={"/a": {"get": {}, "post": {}}})
    new = _spec(paths={"/a": {"get": {}}})
    assert "operation_removed" in _kinds(od.diff(old, new))


def test_removed_schema_is_breaking():
    old = _spec(schemas={"User": {"properties": {"id": {"type": "string"}}}})
    new = _spec(schemas={})
    assert "schema_removed" in _kinds(od.diff(old, new))


def test_removed_property_is_breaking():
    old = _spec(schemas={"User": {"properties": {"id": {"type": "string"}, "email": {"type": "string"}}}})
    new = _spec(schemas={"User": {"properties": {"id": {"type": "string"}}}})
    assert "property_removed" in _kinds(od.diff(old, new))


def test_property_type_change_is_breaking():
    old = _spec(schemas={"User": {"properties": {"id": {"type": "string"}}}})
    new = _spec(schemas={"User": {"properties": {"id": {"type": "integer"}}}})
    assert "property_type_changed" in _kinds(od.diff(old, new))


def test_optional_to_required_is_breaking():
    old = _spec(schemas={"User": {"properties": {"name": {"type": "string"}}, "required": []}})
    new = _spec(schemas={"User": {"properties": {"name": {"type": "string"}}, "required": ["name"]}})
    assert "property_now_required" in _kinds(od.diff(old, new))


def test_new_required_field_on_request_schema_is_breaking():
    old = _spec(schemas={"LoginRequest": {"properties": {"email": {"type": "string"}}, "required": ["email"]}})
    new = _spec(
        schemas={"LoginRequest": {"properties": {"email": {"type": "string"}, "otp": {"type": "string"}}, "required": ["email", "otp"]}}
    )
    assert "required_property_added" in _kinds(od.diff(old, new))


def test_enum_value_removal_is_breaking():
    old = _spec(schemas={"Sev": {"properties": {"level": {"enum": ["low", "high", "critical"]}}}})
    new = _spec(schemas={"Sev": {"properties": {"level": {"enum": ["low", "high"]}}}})
    assert "enum_value_removed" in _kinds(od.diff(old, new))


def test_new_required_parameter_is_breaking():
    old = _spec(paths={"/a": {"get": {"parameters": []}}})
    new = _spec(paths={"/a": {"get": {"parameters": [{"name": "tenant", "required": True}]}}})
    assert "required_param_added" in _kinds(od.diff(old, new))


# ── Safe additive changes must NOT be flagged ────────────────────────────────


def test_added_path_is_not_breaking():
    old = _spec(paths={"/a": {"get": {}}})
    new = _spec(paths={"/a": {"get": {}}, "/b": {"get": {}}})
    assert _kinds(od.diff(old, new)) == set()


def test_added_optional_property_is_not_breaking():
    old = _spec(schemas={"User": {"properties": {"id": {"type": "string"}}, "required": ["id"]}})
    new = _spec(schemas={"User": {"properties": {"id": {"type": "string"}, "nickname": {"type": "string"}}, "required": ["id"]}})
    assert _kinds(od.diff(old, new)) == set()


def test_new_required_field_on_response_schema_is_not_breaking():
    # A response gaining a field doesn't break a consumer; only request-shaped
    # schemas tighten callers.
    old = _spec(schemas={"UserResponse": {"properties": {"id": {"type": "string"}}, "required": ["id"]}})
    new = _spec(
        schemas={"UserResponse": {"properties": {"id": {"type": "string"}, "created": {"type": "string"}}, "required": ["id", "created"]}}
    )
    assert "required_property_added" not in _kinds(od.diff(old, new))


def test_added_enum_value_is_not_breaking():
    old = _spec(schemas={"Sev": {"properties": {"level": {"enum": ["low", "high"]}}}})
    new = _spec(schemas={"Sev": {"properties": {"level": {"enum": ["low", "high", "critical"]}}}})
    assert _kinds(od.diff(old, new)) == set()


def test_ref_type_signature_change_is_breaking():
    old = _spec(schemas={"Case": {"properties": {"owner": {"$ref": "#/components/schemas/User"}}}})
    new = _spec(schemas={"Case": {"properties": {"owner": {"$ref": "#/components/schemas/Actor"}}}})
    assert "property_type_changed" in _kinds(od.diff(old, new))


def test_identical_specs_have_no_changes():
    s = _spec(paths={"/a": {"get": {}}}, schemas={"User": {"properties": {"id": {"type": "string"}}}})
    assert od.diff(s, s) == []


# ── The deliberate-break escape hatch ────────────────────────────────────────
#
# `--allow-breaking` shipped with no caller: the workflow triggered on
# pull_request only and never passed the flag, so the documented way to ship a
# deliberate break did not exist. These cover both halves — that the flag does
# what it claims, and that the workflow actually reaches it.

_CHANGELOG_BASE = """# Changelog

## [Unreleased]

### Security

- something unrelated

## [1.0.0]

### BREAKING

- an old break, already shipped
"""

_CHANGELOG_WITH_NOTE = """# Changelog

## [Unreleased]

### BREAKING

- `Thing.health_score` is removed; it was an undefined composite.

### Security

- something unrelated

## [1.0.0]

### BREAKING

- an old break, already shipped
"""


def _write_pair(tmp_path, old_spec, new_spec):
    old = tmp_path / "old.yaml"
    new = tmp_path / "new.yaml"
    old.write_text(yaml.safe_dump(old_spec), encoding="utf-8")
    new.write_text(yaml.safe_dump(new_spec), encoding="utf-8")
    return old, new


def _breaking_pair(tmp_path):
    return _write_pair(
        tmp_path,
        _spec(schemas={"Thing": {"properties": {"id": {"type": "string"}, "health_score": {"type": "number"}}}}),
        _spec(schemas={"Thing": {"properties": {"id": {"type": "string"}}}}),
    )


def _changelogs(tmp_path, new_text):
    base = tmp_path / "base-CHANGELOG.md"
    head = tmp_path / "CHANGELOG.md"
    base.write_text(_CHANGELOG_BASE, encoding="utf-8")
    head.write_text(new_text, encoding="utf-8")
    return base, head


def test_a_break_without_approval_still_fails(tmp_path):
    old, new = _breaking_pair(tmp_path)
    assert od.main(["--old", str(old), "--new", str(new)]) == 1


def test_allow_breaking_without_changelog_evidence_is_an_argument_error(tmp_path):
    """The bypass cannot be taken on trust: the evidence is mandatory.

    Before this change `--allow-breaking` alone silently returned 0, which is
    what made it usable as an invisible bypass had anything ever called it.
    """
    old, new = _breaking_pair(tmp_path)
    with pytest.raises(SystemExit) as excinfo:
        od.main(["--old", str(old), "--new", str(new), "--allow-breaking"])
    assert excinfo.value.code == 2


def test_approved_break_passes_when_the_changelog_records_it(tmp_path):
    old, new = _breaking_pair(tmp_path)
    base_cl, head_cl = _changelogs(tmp_path, _CHANGELOG_WITH_NOTE)
    rc = od.main(
        ["--old", str(old), "--new", str(new), "--allow-breaking", "--changelog", str(head_cl), "--changelog-base", str(base_cl)]
    )
    assert rc == 0


def test_approved_break_is_refused_when_the_changelog_says_nothing(tmp_path):
    old, new = _breaking_pair(tmp_path)
    base_cl, head_cl = _changelogs(tmp_path, _CHANGELOG_BASE)
    rc = od.main(
        ["--old", str(old), "--new", str(new), "--allow-breaking", "--changelog", str(head_cl), "--changelog-base", str(base_cl)]
    )
    assert rc == 1


def test_an_inherited_note_does_not_excuse_a_later_break(tmp_path):
    """Both directions. "A BREAKING section exists" would let the first note in
    a release cycle excuse every later break in that cycle."""
    old, new = _breaking_pair(tmp_path)
    base_cl = tmp_path / "base-CHANGELOG.md"
    head_cl = tmp_path / "CHANGELOG.md"
    base_cl.write_text(_CHANGELOG_WITH_NOTE, encoding="utf-8")
    head_cl.write_text(_CHANGELOG_WITH_NOTE, encoding="utf-8")
    rc = od.main(
        ["--old", str(old), "--new", str(new), "--allow-breaking", "--changelog", str(head_cl), "--changelog-base", str(base_cl)]
    )
    assert rc == 1


def test_a_note_in_a_shipped_release_section_is_not_evidence():
    notes = od.changelog_breaking_notes(_CHANGELOG_BASE)
    assert notes == [], "a BREAKING heading under [1.0.0] describes a past break"


def test_the_approval_names_every_break_it_permits(tmp_path, capsys):
    """"Approved" must record *what* was approved, not merely that something was."""
    old, new = _write_pair(
        tmp_path,
        _spec(paths={"/gone": {"get": {}}}, schemas={"Thing": {"properties": {"id": {"type": "string"}, "score": {"type": "number"}}}}),
        _spec(paths={}, schemas={"Thing": {"properties": {"id": {"type": "string"}}}}),
    )
    base_cl, head_cl = _changelogs(tmp_path, _CHANGELOG_WITH_NOTE)
    rc = od.main(
        [
            "--old", str(old), "--new", str(new), "--allow-breaking",
            "--changelog", str(head_cl), "--changelog-base", str(base_cl),
            "--approved-by", "@maintainer at 2026-01-01T00:00:00Z",
        ]
    )
    out = capsys.readouterr().out
    assert rc == 0
    assert "@maintainer at 2026-01-01T00:00:00Z" in out
    assert "path '/gone' was removed" in out
    assert "Thing.score was removed" in out
    assert "health_score" in out, "the CHANGELOG note that justified it is part of the record"


def test_the_approval_record_reaches_the_check_run_page(tmp_path, monkeypatch):
    """A record only in the job log is one click further from a reviewer than
    the summary, and job logs age out."""
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    old, new = _breaking_pair(tmp_path)
    base_cl, head_cl = _changelogs(tmp_path, _CHANGELOG_WITH_NOTE)
    od.main(
        ["--old", str(old), "--new", str(new), "--allow-breaking", "--changelog", str(head_cl), "--changelog-base", str(base_cl)]
    )
    assert "Thing.health_score was removed" in summary.read_text(encoding="utf-8")


# ── The workflow must actually reach the flag ────────────────────────────────


def _workflow():
    doc = yaml.safe_load(_WORKFLOW.read_text(encoding="utf-8"))
    # PyYAML resolves a bare `on:` key to the boolean True (YAML 1.1).
    triggers = doc.get("on", doc.get(True))
    steps = doc["jobs"]["breaking-change"]["steps"]
    return triggers, steps


def _diff_steps():
    _, steps = _workflow()
    return [s for s in steps if "openapi_diff.py" in (s.get("run") or "")]


def test_the_workflow_passes_allow_breaking_somewhere():
    """The defect this closes: the flag existed, was tested, and had no caller."""
    assert any("--allow-breaking" in s["run"] for s in _diff_steps()), (
        "no step invokes --allow-breaking, so the documented escape hatch does not exist"
    )


def test_the_approved_path_is_guarded_by_the_label_and_presents_its_evidence():
    approved = [s for s in _diff_steps() if "--allow-breaking" in s["run"]]
    assert len(approved) == 1, "exactly one step may permit breaks"
    step = approved[0]
    assert _LABEL in str(step.get("if", "")), "the bypass must be guarded by the approval label"
    assert "--changelog " in step["run"] and "--changelog-base" in step["run"]


def test_the_unapproved_path_never_permits_a_break():
    unapproved = [s for s in _diff_steps() if "--allow-breaking" not in s["run"]]
    assert unapproved, "the ordinary blocking path must still exist"
    for step in unapproved:
        assert "--allow-breaking" not in step["run"]


def test_the_approved_path_still_runs_the_detector():
    """Approval must not short-circuit detection — otherwise the record cannot
    say what was permitted."""
    approved = [s for s in _diff_steps() if "--allow-breaking" in s["run"]][0]
    assert "--old" in approved["run"] and "--new" in approved["run"]


def test_applying_the_label_re_runs_the_gate():
    """Without `labeled`, the label would only take effect on the next push —
    a control that appears to do something and does not."""
    triggers, _ = _workflow()
    types = triggers["pull_request"]["types"]
    assert "labeled" in types and "unlabeled" in types


def test_the_label_name_the_script_tells_contributors_matches_the_workflow():
    """One-directional drift: renaming the label in CI while the instructions
    still name the old one leaves contributors following a dead procedure."""
    script = (_REPO / "scripts" / "openapi_diff.py").read_text(encoding="utf-8")
    assert _LABEL in script
    assert _LABEL in _WORKFLOW.read_text(encoding="utf-8")
