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


# ── The lock against what is actually published ────────────────────────────
#
# Every test above compares `assign_ids()` output against the lock — and
# `assign_ids()` reads the lock, so for the property that matters the
# comparison is circular. None of them looks at what is *published*: the YAML
# catalogue, the engine ruleset the live worker loads, or the marketplace
# index. So the lock sat 45 network ids out of step with the committed YAML,
# the engine and the catalogue named different rules for the same id, and this
# file passed throughout — under a docstring stating that exact failure.
#
# These compare the surfaces against each other, in both directions.

ENGINE_RULESET = REPO_ROOT / "services" / "fusion" / "app" / "data" / "detection_ruleset.json"
DETECTIONS_DIR = REPO_ROOT / "detections"


@pytest.fixture(scope="module")
def engine_rules() -> list[dict]:
    if not ENGINE_RULESET.exists():
        pytest.skip("detection_ruleset.json not present in this checkout")
    return list(json.loads(ENGINE_RULESET.read_text(encoding="utf-8"))["rules"])


@pytest.fixture(scope="module")
def committed_yaml() -> list[dict]:
    yaml = pytest.importorskip("yaml")
    rules = []
    for path in sorted(DETECTIONS_DIR.glob("*/*.yaml")):
        if "_quarantine" in path.parts or "fixtures" in path.parts:
            continue
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
        if isinstance(loaded, dict) and "id" in loaded:
            rules.append({"path": path, "id": loaded["id"], "name": loaded.get("name", "")})
    if not rules:
        pytest.skip("no committed detection YAML in this checkout")
    return rules


def test_engine_ids_come_from_the_lock(engine_rules: list[dict], lock: dict[str, str]) -> None:
    """The exporter used to number rules positionally.

    Its comment said the id "mirrors generate_detections.py" — true when
    written, false once the generator moved to the lock. Two generators with
    two numbering schemes means the id on an alert and the id in the catalogue
    describe different rules.
    """
    wrong = [
        (rule["id"], lock[f"{rule['category']}/{rule['slug']}"])
        for rule in engine_rules
        if lock.get(f"{rule['category']}/{rule['slug']}") not in (None, rule["id"])
    ]
    assert not wrong, f"{len(wrong)} engine rule id(s) disagree with the lock: {wrong[:3]}"


def test_reordering_specs_does_not_renumber_the_engine(monkeypatch: pytest.MonkeyPatch) -> None:
    """Position-independence has to hold for the engine, not just the YAML.

    Asserting that a plain re-export is a no-op would not catch a positional
    exporter, because the lock was seeded from the current spec order — the two
    schemes agree until the day someone inserts a rule. So this reorders the
    specs and asserts every id stays put. A positional exporter shifts all of
    them; a lock-based one shifts none.
    """
    import detection_specs_index
    import export_detection_ruleset

    original = list(detection_specs_index.all_specs())
    network = [pair for pair in original if pair[0] == "network"]
    if len(network) < 2:
        pytest.skip("need at least two network specs to reorder")
    rest = [pair for pair in original if pair[0] != "network"]
    reordered = rest + [network[-1]] + network[:-1]

    monkeypatch.setattr(detection_specs_index, "all_specs", lambda: iter(reordered))

    resolved = {f"{r['category']}/{r['slug']}": r["id"] for r in export_detection_ruleset._build()}
    baseline = {f"{r['category']}/{r['slug']}": r["id"] for r in _build_from(original)}
    moved = {k: (baseline[k], resolved[k]) for k in baseline if resolved.get(k) != baseline[k]}
    assert not moved, f"reordering the spec list moved {len(moved)} engine rule id(s): {list(moved.items())[:3]}"


def _build_from(specs: list[tuple[str, dict]]) -> list[dict]:
    """Export the ruleset from an explicit spec order."""
    import detection_specs_index
    import export_detection_ruleset

    saved = detection_specs_index.all_specs
    detection_specs_index.all_specs = lambda: iter(specs)
    try:
        return list(export_detection_ruleset._build())
    finally:
        detection_specs_index.all_specs = saved


def test_committed_yaml_ids_match_the_lock(committed_yaml: list[dict], lock: dict[str, str]) -> None:
    """The published catalogue must carry the locked id, not a stale one."""
    by_slug = {}
    for rule in committed_yaml:
        by_slug[f"{rule['path'].parent.name}/{rule['path'].stem}"] = rule["id"]
    wrong = [(slug, rid, lock[slug]) for slug, rid in by_slug.items() if slug in lock and lock[slug] != rid]
    assert not wrong, (
        f"{len(wrong)} committed YAML rule id(s) differ from the lock: {wrong[:3]}. "
        f"Run scripts/generate_detections.py and commit the result."
    )


def test_an_id_names_the_same_rule_in_the_engine_and_the_catalogue(
    engine_rules: list[dict], committed_yaml: list[dict]
) -> None:
    """The user-visible property, stated directly.

    An analyst takes a rule id off an alert (stamped by the engine) and looks
    it up in the catalogue. If the two disagree they read the wrong rule's
    description, false-positive notes and playbook. This was live for 45
    network rules: det-network-037 fired as "DNS TXT Response Over 250 Bytes
    From Non-Resolver Host" and published as "DNS Tunnel Indicator: Long Hex
    Subdomain Sequence".
    """
    engine_names = {r["id"]: r.get("name", "") for r in engine_rules}
    disagree = [
        (rule["id"], rule["name"], engine_names[rule["id"]])
        for rule in committed_yaml
        if rule["id"] in engine_names and engine_names[rule["id"]].strip() != rule["name"].strip()
    ]
    assert not disagree, f"{len(disagree)} id(s) name a different rule in the engine than in the catalogue: {disagree[:3]}"


def test_the_committed_pack_is_what_the_generator_emits() -> None:
    """`--check` must pass on a clean checkout.

    Drift here is how the id disagreement arose: the generator was correct and
    the committed pack was months behind it, with nothing comparing the two.
    """
    assert generate_detections.check_pack() == 0, "the committed detection pack differs from the specs; run scripts/generate_detections.py"
