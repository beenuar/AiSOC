"""Case folding in the string operators (issue #1240).

Windows paths and process names, DNS labels and registry keys are all
case-insensitive namespaces. A rule written against one of them with a
case-sensitive operator is evaded by renaming the case, which costs an
attacker nothing: `PROCDUMP64.EXE -ma lsass.exe` ran the same binary
`procdump64.exe` did.

Half the string operators already folded (`contains_any`, `contains_all`,
`has_any`, `match`, `pattern_match`) and half did not, so this was also a
split a rule author had no way to see from the condition they wrote. These
tests pin both halves of the resulting invariant: the prefix/suffix/substring
operators fold, and `eq` / `in` / `not_in` do not.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from app.services.derived_fields import enrich, requested_derived_fields
from app.services.detection_matcher import matches

_REPO = Path(__file__).resolve().parents[3]

# Every operator whose comparison is a prefix, suffix or substring of a
# string. `_split_op` takes the longest matching suffix, so a bare field
# name plus the suffix is the condition key a rule author writes.
_FOLDING_CASES: list[tuple[str, object, str, str, bool]] = [
    # (op suffix, expected value, matching actual, case-flipped actual, fires?)
    ("_endswith", "procdump.exe", "c:\\tools\\procdump.exe", "C:\\TOOLS\\PROCDUMP.EXE", True),
    ("_endswith_any", ["procdump.exe", "mimikatz.exe"], "x\\procdump.exe", "X\\PROCDUMP.EXE", True),
    ("_startswith", "c:\\users\\", "c:\\users\\bob", "C:\\Users\\Bob", True),
    ("_startswith_any", ["c:\\users\\"], "c:\\users\\bob", "C:\\Users\\Bob", True),
    ("_contains", "lsass", "dump lsass now", "DUMP LSASS NOW", True),
    # Negations are the same comparison with the verdict inverted: an
    # exclusion must also survive a case rename, or the carve-out it
    # encodes stops applying to the very name it was written for.
    ("_not_endswith", "procdump.exe", "c:\\tools\\procdump.exe", "C:\\TOOLS\\PROCDUMP.EXE", False),
    ("_not_endswith_any", ["procdump.exe"], "x\\procdump.exe", "X\\PROCDUMP.EXE", False),
    ("_not_startswith", "c:\\windows\\", "c:\\windows\\x", "C:\\Windows\\X", False),
    ("_not_startswith_any", ["c:\\windows\\"], "c:\\windows\\x", "C:\\Windows\\X", False),
]


@pytest.mark.parametrize(("suffix", "expected", "actual", "flipped", "fires"), _FOLDING_CASES)
def test_string_operators_fold_case(suffix: str, expected: object, actual: str, flipped: str, *, fires: bool) -> None:
    clause = {f"process_name{suffix}": expected}
    assert matches(clause, {"process_name": actual}) is fires
    assert matches(clause, {"process_name": flipped}) is fires, (
        f"{suffix} did not fold case: flipping the case of {actual!r} changed the verdict"
    )


def test_contains_folds_case_for_list_values() -> None:
    clause = {"tags_contains": "Admin"}
    assert matches(clause, {"tags": ["admin", "prod"]})
    assert matches(clause, {"tags": ["ADMIN"]})


@pytest.mark.parametrize(
    ("clause", "event"),
    [
        ({"event_name": "CreateAccessKey"}, {"event_name": "createaccesskey"}),
        ({"status_in": ["Success"]}, {"status": "success"}),
    ],
)
def test_equality_and_membership_stay_case_sensitive(clause: dict, event: dict) -> None:
    """`eq` / `in` carry enum and identifier values, where case is meaning.

    Folding them would make `CreateAccessKey` and `createaccesskey` the same
    API call name, which is a different claim from two spellings of one file.
    """
    assert not matches(clause, event)


def test_procdump_rule_fires_on_an_uppercase_rename() -> None:
    """The reported symptom, replayed through the shipped rule.

    `win-procdump-lsass` is curated critical / T1003.001. Reading it from the
    compiled ruleset rather than restating its condition keeps this test
    pointed at what the engine loads, so a later edit to the rule cannot
    leave the test passing against a condition nobody runs.
    """
    ruleset = _REPO / "services" / "fusion" / "app" / "data" / "detection_ruleset.json"
    all_rules = json.loads(ruleset.read_text())["rules"]
    match_when = next(r["match_when"] for r in all_rules if r["slug"] == "win-procdump-lsass")
    wanted = requested_derived_fields(all_rules)

    for name in ("procdump.exe", "PROCDUMP.EXE", "ProcDump.exe"):
        event = enrich(
            {
                "event_id": 1,
                "log_source": "windows_sysmon",
                "process_name": name,
                "process_command_line": f"{name} -accepteula -ma lsass.exe out.dmp",
            },
            wanted,
        )
        assert matches(match_when, event), f"rule missed a rename to {name!r}"
