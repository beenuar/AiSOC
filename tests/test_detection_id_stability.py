"""A detection rule's id must not depend on where it sits in a list.

Rule ids were positional — ``det-{category}-{index}`` — so inserting a rule
anywhere but the end renumbered every rule after it. Re-running the generator
on a clean checkout reassigned ids and tripped the marketplace gate, and the
workaround was "append new rules, never insert", which is a rule nobody
remembers and nothing enforced.

A renumbered id is not a cosmetic problem. Ids appear in alert rows, in
suppression priors and in customer-written exceptions; reassigning one makes
a historical alert reference a different rule than the one that fired.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

LOCK_PATH = REPO_ROOT / "detections" / "rule-ids.lock.json"

# One import style for this module throughout: the tests need both the
# functions and the module object (to patch ID_LOCK), and mixing
# `import X` with `from X import y` for the same module is what
# py/import-and-import-from flags.
import generate_detections  # noqa: E402


@pytest.fixture(scope="module")
def categories() -> dict:
    from detection_specs_index import CATEGORIES

    return CATEGORIES


@pytest.fixture(scope="module")
def lock() -> dict[str, str]:
    if not LOCK_PATH.exists():
        pytest.skip("rule-ids.lock.json not present in this checkout")
    return json.loads(LOCK_PATH.read_text(encoding="utf-8"))


def test_regeneration_assigns_no_new_ids(categories: dict, lock: dict[str, str]) -> None:
    """The committed lock must already cover every spec.

    A spec with no locked id means the lock was not regenerated after a rule
    was added, and the next run would write one — which is a diff nobody
    reviewed.
    """
    resolved, newly = generate_detections.assign_ids(categories)
    assert not newly, (
        f"{len(newly)} spec(s) have no locked id: {', '.join(sorted(newly)[:8])}. "
        f"Run scripts/generate_detections.py and commit detections/rule-ids.lock.json."
    )
    assert resolved == lock


def test_inserting_a_rule_does_not_renumber_the_others(categories: dict, lock: dict[str, str]) -> None:
    """The exact bug. Insertion at the front used to move 81 network ids."""
    mutated = {k: list(v) for k, v in categories.items()}
    mutated["network"].insert(0, {"slug": "zzz-test-inserted-first"})

    resolved, newly = generate_detections.assign_ids(mutated)

    moved = {k: (lock[k], resolved[k]) for k in lock if resolved.get(k) != lock[k]}
    assert not moved, f"inserting one rule moved {len(moved)} existing ids: " f"{list(moved.items())[:3]}"
    assert newly == ["network/zzz-test-inserted-first"]


def test_a_new_rule_takes_the_next_free_number(categories: dict, lock: dict[str, str]) -> None:
    mutated = {k: list(v) for k, v in categories.items()}
    mutated["network"].append({"slug": "zzz-test-appended"})
    resolved, _ = generate_detections.assign_ids(mutated)

    existing = {int(v.rsplit("-", 1)[1]) for k, v in lock.items() if k.startswith("network/")}
    assigned = int(resolved["network/zzz-test-appended"].rsplit("-", 1)[1])
    assert assigned == max(existing) + 1


def test_a_deleted_rule_does_not_recycle_its_id(lock: dict[str, str]) -> None:
    """A recycled id makes a historical alert reference the wrong rule.

    The lock is never pruned, so a removed rule's id stays burned.
    """
    reduced = {"network": [{"slug": "zzz-test-only-rule"}]}
    resolved, _ = generate_detections.assign_ids(reduced)

    burned = {v for k, v in lock.items() if k.startswith("network/")}
    assert resolved["network/zzz-test-only-rule"] not in burned, "a new rule was given an id that a previous rule already used"


def test_every_locked_id_is_unique() -> None:
    """Two slugs sharing an id is worse than a renumber; it is a collision."""
    if not LOCK_PATH.exists():
        pytest.skip("rule-ids.lock.json not present in this checkout")
    lock = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
    seen: dict[str, str] = {}
    for slug, rule_id in sorted(lock.items()):
        assert rule_id not in seen, f"{rule_id} is assigned to both {seen[rule_id]} and {slug}"
        seen[rule_id] = slug


def test_a_corrupt_lock_refuses_rather_than_renumbering(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Silently treating an unreadable lock as empty would reassign every id."""
    bad = tmp_path / "rule-ids.lock.json"
    bad.write_text("{not json", encoding="utf-8")
    # setattr on the module object reached through sys.modules, so the file
    # keeps a single import style — mixing `import X as m` with `from X
    # import y` for the same module is what CodeQL flags.
    monkeypatch.setattr(generate_detections, "ID_LOCK", bad)

    with pytest.raises(SystemExit, match="unreadable"):
        generate_detections.load_id_lock()
