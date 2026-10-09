#!/usr/bin/env python3
"""Every shipped pack resolves against the corpus this build ships.

Gap-closure wave 10.

A pack that references a rule id nobody ships is the exact failure the
format exists to prevent: an operator adopts it, nothing fires, and no
error appears anywhere. That is not hypothetical — rule ids were
positional until `detections/rule-ids.lock.json` pinned them, so an
insertion used to renumber everything after it.

So the references are checked against the **compiled ruleset the
engine loads**, not against the YAML on disk. The YAML is a
projection: `detections/*.yaml` carries thousands of rules the engine
never loads, and validating against it would certify a pack whose
detections cannot fire.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "packages" / "aisoc-packs"))

from gate_toolkit import repo_root, self_test_if_requested  # noqa: E402

self_test_if_requested(__file__)

from pack_schema import ContentPack, validate_pack  # noqa: E402

ROOT = repo_root()
PACKS_DIR = ROOT / "packages" / "aisoc-packs" / "packs"
RULESET = ROOT / "services" / "fusion" / "app" / "data" / "detection_ruleset.json"
#: The sliding-window corpus, loaded by the second engine in the same worker.
WINDOWED_RULESET = ROOT / "services" / "fusion" / "app" / "data" / "windowed_ruleset.json"
PLAYBOOKS = ROOT / "detections" / "playbooks"


def _executable_rule_ids() -> frozenset[str]:
    """Ids the engines actually load.

    Not the YAML on disk: that is a projection carrying thousands of
    rules the engine never compiles, so a pack validated against it
    could reference a detection that cannot fire.

    Both engines, because the fusion worker runs both. Reading only the
    stateless corpus made a pack naming a windowed rule unreferenceable —
    and when a rule was translated into windowed form, the pack that had
    always named it started failing for a rule that had become *more*
    able to fire, not less.
    """
    ids: set[str] = set()
    for path in (RULESET, WINDOWED_RULESET):
        if not path.is_file():
            continue
        raw = json.loads(path.read_text(encoding="utf-8"))
        rules = raw if isinstance(raw, list) else raw.get("rules", [])
        ids |= {str(rule.get("id")) for rule in rules if rule.get("id")}
    return frozenset(ids)


def main() -> int:
    if not PACKS_DIR.is_dir():
        print(f"check_content_packs: no packs directory at {PACKS_DIR}")
        return 0

    manifests = sorted(PACKS_DIR.glob("*.json"))
    if not manifests:
        print("check_content_packs: no packs found — refusing to report a tree clean")
        return 2

    rule_ids = _executable_rule_ids()
    if not rule_ids:
        print("check_content_packs: the compiled ruleset is empty; this gate would certify anything")
        return 2
    playbook_ids = frozenset(p.stem for p in PLAYBOOKS.glob("*.yaml"))

    failures = 0
    for manifest in manifests:
        pack = ContentPack.from_dict(json.loads(manifest.read_text(encoding="utf-8")))
        problems = validate_pack(pack, known_rule_ids=rule_ids, known_playbook_ids=playbook_ids)
        rel = manifest.relative_to(ROOT)
        if problems:
            failures += 1
            print(f"FAIL {rel}")
            for problem in problems:
                print(f"  {problem}")
        else:
            print(
                f"OK   {rel}  scenario={pack.scenario} "
                f"detections={len(pack.detections)} plan={len(pack.investigation_plan)} "
                f"validation={len(pack.validation)}"
            )

    print(f"check_content_packs: {len(manifests)} pack(s) against {len(rule_ids)} executable rules and {len(playbook_ids)} playbooks")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
