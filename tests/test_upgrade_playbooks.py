"""The upgrader the migration doc has told operators to run since v4.

The script did not exist. A migration doc that fails does so at exactly the
moment it is needed, which is why the test that matters here is not "the
function returns a dict" but "the output validates against the schema the
engine actually enforces" — checked against the real
`schemas/playbook.schema.json`, not a fixture copy of it.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import jsonschema
import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import upgrade_playbooks as up  # noqa: E402

SCHEMA = json.loads((ROOT / "schemas" / "playbook.schema.json").read_text())


def _validate(doc: dict) -> list[str]:
    return [e.message for e in jsonschema.Draft7Validator(SCHEMA).iter_errors(doc)]


def _v3(**step_overrides) -> dict:
    step = {"id": "s1", "name": "contain", "type": "isolate"}
    step.update(step_overrides)
    return {"name": "Legacy playbook", "trigger": {"on": "alert"}, "steps": [step]}


class TestTheOutputIsActuallyValid:
    def test_a_v3_playbook_upgrades_into_something_the_schema_accepts(self) -> None:
        """The whole promise in one assertion."""
        legacy = _v3(
            on_error="stop",
            timeout=120,
            retry={"max_attempts": 3, "backoff": "exponential"},
            condition={"expr": "severity == 'high'", "language": "jmespath"},
        )
        assert _validate(legacy), "fixture assumption broken: the v3 shape should NOT validate"

        upgraded, changes, blockers = up.upgrade_playbook(legacy)

        assert blockers == []
        assert _validate(upgraded) == [], f"upgrade produced something the engine rejects: {_validate(upgraded)}"
        step = upgraded["steps"][0]
        assert step["type"] == "isolate_host"
        assert step["on_failure"] == "abort"
        assert step["timeout_seconds"] == 120
        assert step["retry_max"] == 3
        assert step["condition"] == "severity == 'high'"
        assert changes

    @pytest.mark.parametrize(
        ("old", "new"),
        sorted(up.STEP_TYPE_RENAMES.items()),
    )
    def test_every_declared_rename_lands_on_a_type_the_schema_declares(self, old: str, new: str) -> None:
        """A rename onto a type the schema does not declare would produce a
        file that fails the very lint the doc tells you to run next."""
        upgraded, _, blockers = up.upgrade_playbook(_v3(type=old))
        assert blockers == []
        assert upgraded["steps"][0]["type"] == new
        assert _validate(upgraded) == []

    def test_an_already_current_playbook_is_left_alone(self) -> None:
        """Re-running the upgrader must be a no-op, or nobody can run it twice."""
        current = json.loads((ROOT / "services" / "agents" / "data" / "playbooks" / "phishing-triage.playbook.json").read_text())
        upgraded, changes, blockers = up.upgrade_playbook(current)
        assert changes == []
        assert blockers == []
        assert upgraded == current


class TestItRefusesRatherThanInvents:
    @pytest.mark.parametrize("step_type", sorted(up.UNMAPPABLE))
    def test_a_type_with_no_equivalent_is_reported_not_rewritten(self, step_type: str) -> None:
        """Mapping these onto a "nearest neighbour" is the defect that was
        removed from the NL drafter, where a `disable_user` step shipped as
        `investigate`."""
        upgraded, _, blockers = up.upgrade_playbook(_v3(type=step_type))
        assert blockers, f"{step_type} must be reported"
        assert step_type in blockers[0]
        assert upgraded["steps"][0]["type"] == step_type, "a blocked type must not be silently changed"

    def test_the_two_vocabularies_do_not_overlap(self) -> None:
        """A type in both tables would be renamed and reported at once."""
        assert not (set(up.STEP_TYPE_RENAMES) & set(up.UNMAPPABLE))

    def test_every_renamed_and_blocked_type_is_absent_from_the_current_schema(self) -> None:
        """These are v3 spellings. One still in the schema means the table
        is describing a rename that is not a rename."""
        declared = set(SCHEMA["definitions"]["PlaybookStep"]["properties"]["type"]["enum"])
        assert not (set(up.STEP_TYPE_RENAMES) & declared)
        assert not (set(up.UNMAPPABLE) & declared)


class TestTheCommandLine:
    def test_check_mode_writes_nothing(self, tmp_path: Path) -> None:
        pack = tmp_path / "playbooks"
        pack.mkdir()
        target = pack / "legacy.playbook.json"
        original = json.dumps(_v3(on_error="stop"))
        target.write_text(original)

        code = up.main(["--dir", "playbooks", "--repo-root", str(ROOT), "--dir", str(pack)])

        assert code == 1, "'would change' is a non-zero answer so a script can branch on it"
        assert target.read_text() == original

    def test_write_mode_produces_a_file_that_passes_the_real_linter(self, tmp_path: Path) -> None:
        pack = tmp_path / "playbooks"
        pack.mkdir()
        target = pack / "legacy.playbook.json"
        target.write_text(json.dumps(_v3(on_error="stop", timeout=90)))

        assert up.main(["--repo-root", str(ROOT), "--dir", str(pack), "--write"]) == 0
        assert _validate(json.loads(target.read_text())) == []

    def test_a_blocked_file_exits_two_and_is_not_rewritten(self, tmp_path: Path) -> None:
        pack = tmp_path / "playbooks"
        pack.mkdir()
        target = pack / "loopy.playbook.json"
        original = json.dumps(_v3(type="loop"))
        target.write_text(original)

        assert up.main(["--repo-root", str(ROOT), "--dir", str(pack), "--write"]) == 2
        assert target.read_text() == original

    def test_finding_no_files_is_a_broken_scan_not_a_clean_bill_of_health(self, tmp_path: Path) -> None:
        """The same defect that let the lint job report "2/2 passed" over 62
        unchecked packs."""
        empty = tmp_path / "nothing"
        empty.mkdir()
        assert up.main(["--repo-root", str(ROOT), "--dir", str(empty)]) == 1

    def test_the_shipped_packs_need_no_upgrade(self) -> None:
        """They are v4 already; a non-zero answer here would mean the
        upgrader disagrees with the schema the packs pass."""
        assert up.main(["--repo-root", str(ROOT), "--dir", "playbooks"]) == 0
