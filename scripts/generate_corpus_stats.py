#!/usr/bin/env python3
"""Generate the single source of truth for AiSOC's detection / marketplace counts.

Why this exists
---------------
``generate_connector_count.py`` already proved the shape: derive the number
from the tree, commit the artefact, gate the artefact. Every *other* corpus
figure on the landing page was still hand-typed, and every one of them had
drifted:

  * ``Hero.tsx``               "6,998 detections ... 57 plugins"
  * ``ConnectorsMarquee.tsx``  "6,998 detections"
  * ``FeatureGrid.tsx``        "6,998 YAML rules", "7,117 community items"
  * ``Pillars.tsx``            stat "6,998" / "public detection rules"
  * ``ContributorLeaderboard.tsx``  "218 rules across 5 categories"

Three different wrong answers to one question, and no gate covering any of
them. Worse than stale: "6,998 detections" counts the imported corpus, ~85% of
which sits under ``detections/*/\\_quarantine/`` and is never loaded. Quoting it
as the detection capability presents quarantined rules as executable, which
this repository has a standing rule against.

So the artefact separates the two figures rather than picking one:

``executable``
    What the engine loads — ``services/fusion/app/data/detection_ruleset.json``.
    This is the capability number and the one the UI leads with.
``on_disk`` / ``quarantined``
    The corpus as indexed by ``marketplace/index.json``. Real, published, and
    only ever quoted *as* a corpus.

Cross-checking, in both directions
----------------------------------
The recurring defect in this tree's gates is the one-directional comparison:
it checks A against B, never B against A, so drift in the direction things
actually change slips through while the gate prints OK. Three independent
places count detections here — the compiled engine ruleset, the generated
truth table, and the marketplace index — so this reconciles all three against
each other before writing anything. A disagreement is a hard error, not a
silently-preferred source.

Outputs
-------
  * ``apps/web/src/data/corpus-stats.json``  — machine-readable payload.
  * ``apps/web/src/data/corpusStats.ts``     — TypeScript constants imported by
    every landing / marketplace / detections surface.

Usage
-----

    python3 scripts/generate_corpus_stats.py             # write outputs
    python3 scripts/generate_corpus_stats.py --check     # fail if drift
    python3 scripts/generate_corpus_stats.py --self-test # prove the gate works
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

# `scripts/` is on sys.path when this file is run as a program, but not when a
# test loads it by path with importlib. gate_toolkit sits beside it either way.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_main

REPO_ROOT = repo_root()
RULESET = REPO_ROOT / "services" / "fusion" / "app" / "data" / "detection_ruleset.json"
MARKETPLACE = REPO_ROOT / "marketplace" / "index.json"
TRUTH_TABLE = REPO_ROOT / "docs" / "detections" / "truth-table.md"
JSON_OUT = REPO_ROOT / "apps" / "web" / "src" / "data" / "corpus-stats.json"
TS_OUT = REPO_ROOT / "apps" / "web" / "src" / "data" / "corpusStats.ts"

#: Prose that quotes the executable-rule count outside the TypeScript surfaces.
#: Same contract as ``generate_connector_count.py``: each regex must match, and
#: the ``n`` group is rewritten in place (or reported, under ``--check``).
COUNT_BEARING_FILES: tuple[tuple[Path, tuple[re.Pattern[str], ...]], ...] = (
    (
        REPO_ROOT / "README.md",
        (
            re.compile(r"(?P<pre>fusion runs )(?P<n>\d+)(?P<post> executable detection rules)"),
            re.compile(r"(?P<pre>\| Detection engine \()(?P<n>\d+)(?P<post> executable rules\))"),
        ),
    ),
    (
        REPO_ROOT / "ROADMAP.md",
        (re.compile(r"(?P<pre>detection-evaluation worker \()(?P<n>\d+)(?P<post> executable rules on the stream\))"),),
    ),
)


def _read_json(path: Path, label: str) -> Any:
    if not path.is_file():
        raise SystemExit(f"{Path(sys.argv[0]).name}: {label} missing at {path} — nothing to count")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{Path(sys.argv[0]).name}: {label} is not valid JSON: {exc}") from exc


def read_engine_ruleset() -> tuple[int, dict[str, int]]:
    """Executable rule count and per-category split, from the compiled ruleset."""
    data = _read_json(RULESET, "detection ruleset")
    rules = data.get("rules")
    if not isinstance(rules, list) or not rules:
        raise SystemExit(f"{Path(sys.argv[0]).name}: {RULESET} declares no rules — refusing to publish a zero corpus")
    declared = data.get("count")
    if isinstance(declared, int) and declared != len(rules):
        raise SystemExit(f"{Path(sys.argv[0]).name}: ruleset `count` is {declared} but it holds {len(rules)} rules")
    categories = Counter(str(rule.get("category", "uncategorized")) for rule in rules)
    return len(rules), dict(sorted(categories.items()))


def read_marketplace() -> dict[str, int]:
    """Corpus figures from the marketplace index's own published stats.

    The stats block is read rather than recomputed from ``items`` so the
    artefact and the marketplace page can never disagree, and the two are
    reconciled below so a broken ``build_marketplace.py`` cannot pass either.
    """
    data = _read_json(MARKETPLACE, "marketplace index")
    stats = data.get("stats")
    items = data.get("items")
    if not isinstance(stats, dict) or not isinstance(items, list) or not items:
        raise SystemExit(f"{Path(sys.argv[0]).name}: {MARKETPLACE} has no stats/items — refusing to publish a zero corpus")

    counted = Counter(str(item.get("type", "")) for item in items)
    for key, kind in (("detections", "detection"), ("plugins", "plugin"), ("playbooks", "playbook")):
        published = stats.get(key)
        if published != counted[kind]:
            raise SystemExit(
                f"{Path(sys.argv[0]).name}: marketplace stats.{key}={published} but {counted[kind]} "
                f"{kind!r} items are indexed — regenerate with `python3 scripts/build_marketplace.py`"
            )

    out = {
        "on_disk": int(stats["detections"]),
        "quarantined": int(stats.get("quarantined", 0)),
        "plugins": int(stats["plugins"]),
        "playbook_packs": int(stats["playbooks"]),
        "marketplace_items": int(stats.get("total", len(items))),
    }
    if out["marketplace_items"] != len(items):
        raise SystemExit(f"{Path(sys.argv[0]).name}: marketplace stats.total={out['marketplace_items']} but {len(items)} items are indexed")
    return out


_TRUTH_TABLE_EXECUTABLE = re.compile(r"\|\s*\*\*executable \(loaded by the engine\)\*\*\s*\|\s*\*\*(?P<n>\d+)\*\*\s*\|")


def read_truth_table_executable() -> int:
    """The executable count as published in ``docs/detections/truth-table.md``.

    A third opinion on the same number. The truth table is itself generated
    (``scripts/detection_truth_table.py``), so this is not belt-and-braces: it
    catches the case where one generator has been re-run and the other has not.
    """
    if not TRUTH_TABLE.is_file():
        raise SystemExit(f"{Path(sys.argv[0]).name}: detection truth table missing at {TRUTH_TABLE}")
    match = _TRUTH_TABLE_EXECUTABLE.search(TRUTH_TABLE.read_text(encoding="utf-8"))
    if match is None:
        raise SystemExit(f"{Path(sys.argv[0]).name}: could not find the executable row in {TRUTH_TABLE.relative_to(REPO_ROOT)}")
    return int(match.group("n"))


def build_payload() -> dict[str, Any]:
    executable, categories = read_engine_ruleset()
    corpus = read_marketplace()
    documented = read_truth_table_executable()

    if documented != executable:
        raise SystemExit(
            f"{Path(sys.argv[0]).name}: the engine loads {executable} rules but "
            f"docs/detections/truth-table.md publishes {documented}. Re-run "
            "`python3 scripts/detection_truth_table.py` and `python3 scripts/export_detection_ruleset.py`."
        )
    if executable > corpus["on_disk"]:
        raise SystemExit(f"{Path(sys.argv[0]).name}: {executable} executable rules exceeds {corpus['on_disk']} indexed on disk")
    if corpus["quarantined"] > corpus["on_disk"]:
        raise SystemExit(f"{Path(sys.argv[0]).name}: {corpus['quarantined']} quarantined exceeds {corpus['on_disk']} on disk")

    return {
        "executable": executable,
        "onDisk": corpus["on_disk"],
        "quarantined": corpus["quarantined"],
        "plugins": corpus["plugins"],
        "playbookPacks": corpus["playbook_packs"],
        "marketplaceItems": corpus["marketplace_items"],
        "categories": categories,
        "generatedFrom": [
            "services/fusion/app/data/detection_ruleset.json",
            "marketplace/index.json",
            "docs/detections/truth-table.md",
        ],
        "regenerateWith": "python3 scripts/generate_corpus_stats.py",
    }


def render_typescript(payload: dict[str, Any]) -> str:
    """Render the TS constants module imported by the landing / detections UI."""
    return (
        "// AUTO-GENERATED by scripts/generate_corpus_stats.py.\n"
        "// Do not edit by hand. Run the script (or `make corpus-stats`) instead.\n"
        "//\n"
        "// Single source of truth for every published detection / marketplace count.\n"
        "//\n"
        "// EXECUTABLE_DETECTION_COUNT is the capability number: rules the fusion\n"
        "// engine actually loads. DETECTIONS_ON_DISK is the indexed corpus, most of\n"
        "// which is quarantined and never evaluated -- it is a corpus figure and must\n"
        "// never be presented as what the product executes.\n"
        "\n"
        "import data from './corpus-stats.json';\n"
        "\n"
        "/** Rules the fusion engine loads and evaluates. */\n"
        "export const EXECUTABLE_DETECTION_COUNT: number = data.executable;\n"
        "\n"
        "/** Detection YAML indexed in the marketplace, quarantined rules included. */\n"
        "export const DETECTIONS_ON_DISK: number = data.onDisk;\n"
        "\n"
        "/** Imported rules held under `_quarantine/`: on disk, never loaded. */\n"
        "export const QUARANTINED_DETECTIONS: number = data.quarantined;\n"
        "\n"
        "export const PLUGIN_COUNT: number = data.plugins;\n"
        "export const PLAYBOOK_PACK_COUNT: number = data.playbookPacks;\n"
        "export const MARKETPLACE_ITEM_COUNT: number = data.marketplaceItems;\n"
        "\n"
        "/** Executable rules per detection category. */\n"
        "export const DETECTION_CATEGORIES: Readonly<Record<string, number>> = data.categories;\n"
        "export const DETECTION_CATEGORY_COUNT: number = Object.keys(data.categories).length;\n"
        "\n"
        "/** Locale-formatted labels, so no surface re-implements the separator. */\n"
        "export const EXECUTABLE_DETECTIONS_LABEL = `${EXECUTABLE_DETECTION_COUNT.toLocaleString()} executable detections`;\n"
        "export const MARKETPLACE_ITEMS_LABEL = `${MARKETPLACE_ITEM_COUNT.toLocaleString()} marketplace items`;\n"
    )


def write_outputs(payload: dict[str, Any]) -> None:
    JSON_OUT.parent.mkdir(parents=True, exist_ok=True)
    JSON_OUT.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    TS_OUT.write_text(render_typescript(payload), encoding="utf-8")


def artefact_drift(payload: dict[str, Any], existing_json: str | None, existing_ts: str | None) -> list[str]:
    """Drift between a freshly-derived payload and what is committed.

    Pure, so ``--self-test`` can drive it with a hand-edited copy instead of
    mutating the working tree to prove the gate still bites.
    """
    drift: list[str] = []
    want_json = json.dumps(payload, indent=2) + "\n"
    if existing_json != want_json:
        drift.append(f"{JSON_OUT.relative_to(REPO_ROOT)}: regenerate with `python3 scripts/generate_corpus_stats.py`")
    if existing_ts != render_typescript(payload):
        drift.append(f"{TS_OUT.relative_to(REPO_ROOT)}: regenerate with `python3 scripts/generate_corpus_stats.py`")
    return drift


def reconcile_prose(executable: int, *, check_only: bool) -> list[str]:
    """Rewrite or verify every COUNT_BEARING_FILES entry."""
    drift: list[str] = []
    for path, patterns in COUNT_BEARING_FILES:
        if not path.exists():
            drift.append(f"missing file {path.relative_to(REPO_ROOT)}")
            continue
        before = path.read_text(encoding="utf-8")
        after = before
        for pattern in patterns:
            matches = list(pattern.finditer(after))
            if not matches:
                drift.append(f"{path.relative_to(REPO_ROOT)}: pattern {pattern.pattern!r} did not match")
                continue
            # Rewrite right-to-left so earlier match offsets stay valid.
            for match in reversed(matches):
                if match.group("n") != str(executable):
                    after = after[: match.start("n")] + str(executable) + after[match.end("n") :]
        if after != before:
            if check_only:
                drift.append(f"{path.relative_to(REPO_ROOT)}: executable-rule count drift (expected {executable})")
            else:
                path.write_text(after, encoding="utf-8")
    return drift


def _self_test() -> int:
    """Prove the gate detects a hand edit, then that it refuses an empty tree."""
    payload = build_payload()
    committed_json = JSON_OUT.read_text(encoding="utf-8") if JSON_OUT.exists() else None
    committed_ts = TS_OUT.read_text(encoding="utf-8") if TS_OUT.exists() else None

    tampered = dict(payload)
    tampered["executable"] = int(payload["executable"]) + 1
    hand_edited_json = json.dumps(tampered, indent=2) + "\n"

    # The TS module reads its numbers from the JSON, so tampering with the
    # payload leaves the rendered TS byte-identical. A hand edit to that file
    # therefore means editing the *text* — the shape this catches is someone
    # pinning a literal to stop the import "changing under them".
    hand_edited_ts = render_typescript(payload).replace(
        "export const EXECUTABLE_DETECTION_COUNT: number = data.executable;",
        "export const EXECUTABLE_DETECTION_COUNT: number = 6998;",
    )

    extra = [
        (
            "flags a hand-edited count in corpus-stats.json",
            bool(artefact_drift(payload, hand_edited_json, committed_ts)),
        ),
        (
            "flags a hand-edited literal in corpusStats.ts",
            bool(artefact_drift(payload, committed_json, hand_edited_ts)),
        ),
        (
            "passes on the committed artefact",
            not artefact_drift(payload, committed_json, committed_ts),
        ),
    ]
    return self_test_main(Path(__file__).name, ["--check"], extra)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Fail (exit 1) on any drift instead of rewriting files.")
    parser.add_argument("--self-test", action="store_true", help="Prove this gate detects the drift it claims to.")
    args = parser.parse_args(argv)

    if args.self_test:
        return _self_test()

    payload = build_payload()
    executable = int(payload["executable"])
    drift: list[str] = []

    if args.check:
        drift.extend(
            artefact_drift(
                payload,
                JSON_OUT.read_text(encoding="utf-8") if JSON_OUT.exists() else None,
                TS_OUT.read_text(encoding="utf-8") if TS_OUT.exists() else None,
            )
        )
    else:
        write_outputs(payload)

    drift.extend(reconcile_prose(executable, check_only=args.check))

    if drift:
        print(f"corpus-stats drift detected (executable={executable}):", file=sys.stderr)
        for line in drift:
            print(f"  - {line}", file=sys.stderr)
        return 1

    print(
        f"corpus-stats OK — {executable} executable across {len(payload['categories'])} categories, "
        f"{payload['onDisk']} indexed on disk ({payload['quarantined']} quarantined), "
        f"{payload['plugins']} plugins, {payload['playbookPacks']} playbook packs"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
