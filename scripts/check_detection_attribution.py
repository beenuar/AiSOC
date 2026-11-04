#!/usr/bin/env python3
"""CI gate: a DRL-1.1 rule must name the person who wrote it.

The Detection Rule License 1.1, which every rule imported from SigmaHQ is
licensed under, permits redistribution in modified form — a translation into
this engine's matcher language is exactly that — on condition that *author
identification* travels with the copy, and that messages produced by a match
identify the author too. A link to the upstream repository is not author
identification: the repository is the publisher, the author is the person.

This gate exists because that obligation was documented and left open. The
compiler's own generated report carried a section headed "Known gap: the
author is not the person", which is an honest note and is not compliance — a
caveat reads as modesty and functions as an exemption. Florian Roth, who
created Sigma, reported it as issue #1680.

Four surfaces carry the attribution and each can drift from the others, so
each is checked separately rather than one standing in for the rest:

* the vendored upstream YAML under ``detections/sigma-imports/`` — a shared
  copy in its own right, and the input the compiler reads,
* the compiled rulesets the engines load, in ``services/fusion`` and the
  byte-identical copy the API image carries,
* ``marketplace/index.json`` and its two mirrors, which is what the console
  renders — and which is where the sharpest form of the defect lived, since
  an item-level ``author`` defaulting to ``AiSOC`` does not omit the upstream
  author, it replaces them.

The author is checked, deliberately, for *presence* rather than against a
list of expected names. A gate holding its own copy of 749 author strings
would be a second source of truth that drifts from upstream on the next
import; ``scripts/sync_sigma_authors.py --check`` is what proves the names
match the pinned commit.

A rule whose upstream genuinely carries no ``author:`` is a real case the
licence does not require us to invent a name for. None exist in the corpus at
the pinned commit, but ``_ABSENT`` records the honest spelling for one that
does, and such a rule passes.

Usage:
    python3 scripts/check_detection_attribution.py
    python3 scripts/check_detection_attribution.py --list
    python3 scripts/check_detection_attribution.py --self-test
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_main

ROOT = repo_root()

#: The licence whose attribution clause this gate enforces. Apache-2.0 content
#: (splunk/security_content, chronicle/detection-rules, mitre-attack/car) sits
#: in the same corpus under a licence whose attribution obligation is a NOTICE
#: file rather than a per-rule author, so it is deliberately out of scope here
#: rather than silently swept in.
LICENCE = "DRL-1.1"

#: The spelling for a rule whose upstream carries no ``author:`` at all. An
#: explicit marker, never an empty string: empty is what the defect looked
#: like, and a reader has to be able to tell "upstream credits nobody" apart
#: from "we dropped it".
_ABSENT = "(no author recorded upstream)"

SIGMA_YAML = ROOT / "detections" / "sigma-imports"

COMPILED = (
    ROOT / "services" / "fusion" / "app" / "data" / "detection_ruleset_imported.json",
    ROOT / "services" / "api" / "app" / "data" / "detections" / "detection_ruleset_imported.json",
)

MARKETPLACE = (
    ROOT / "marketplace" / "index.json",
    ROOT / "apps" / "web" / "public" / "marketplace" / "index.json",
    ROOT / "services" / "api" / "app" / "data" / "marketplace" / "index.json",
)

#: Item-level ``author`` values that must never appear on imported content.
#: The marketplace builder defaulted to ``AiSOC`` for anything without an
#: author of its own, which on 3,132 Sigma rules read as this project having
#: written them.
_NOT_OURS = frozenset({"aisoc", "", "unknown", "n/a"})


def _attributed(value: Any) -> bool:
    """Whether ``value`` identifies an author."""
    return bool(str(value or "").strip())


def _yaml_provenance(text: str) -> dict[str, str]:
    """The ``provenance:`` block of a vendored rule, read without a YAML parser.

    The gate is run in CI jobs that install no dependencies, and PyYAML is not
    guaranteed there. The block is machine-written by the importer with a
    fixed two-space indent, so a line reader is sufficient and is pinned by
    the self-test against a sample of real files.
    """
    block: dict[str, str] = {}
    inside = False
    for line in text.splitlines():
        if line.startswith("provenance:"):
            inside = True
            continue
        if inside:
            if line[:1] not in {" ", "\t"}:
                break
            stripped = line.strip()
            if not stripped or ":" not in stripped:
                continue
            key, _, value = stripped.partition(":")
            block[key.strip()] = value.strip().strip("'\"")
    return block


def _scan_yaml() -> tuple[int, list[str]]:
    """DRL-1.1 vendored rules, and those of them with no author."""
    total = 0
    missing: list[str] = []
    if not SIGMA_YAML.exists():
        return 0, []
    for path in sorted(SIGMA_YAML.rglob("*.yaml")):
        prov = _yaml_provenance(path.read_text(encoding="utf-8"))
        if prov.get("license") != LICENCE:
            continue
        total += 1
        if not _attributed(prov.get("author")):
            missing.append(path.relative_to(ROOT).as_posix())
    return total, missing


def _rules_of(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        return data.get("rules") or data.get("items") or []
    return data


def _scan_compiled(path: Path) -> tuple[int, list[str]]:
    total = 0
    missing: list[str] = []
    for rule in _rules_of(path):
        prov = rule.get("provenance") or {}
        if prov.get("license") != LICENCE:
            continue
        total += 1
        if not _attributed(prov.get("author")):
            missing.append(str(rule.get("id") or prov.get("source_id") or "?"))
    return total, missing


def _scan_marketplace(path: Path) -> tuple[int, list[str], list[str]]:
    """Returns (DRL items, those with no provenance author, those credited to us)."""
    total = 0
    missing: list[str] = []
    misattributed: list[str] = []
    for item in _rules_of(path):
        prov = item.get("provenance") or {}
        if prov.get("license") != LICENCE:
            continue
        total += 1
        ident = str(item.get("id") or prov.get("source_id") or "?")
        if not _attributed(prov.get("author")):
            missing.append(ident)
        if str(item.get("author") or "").strip().lower() in _NOT_OURS:
            misattributed.append(ident)
    return total, missing, misattributed


def check(*, show: bool) -> int:
    failures = 0
    checked_any = False

    total, missing = _scan_yaml()
    if total:
        checked_any = True
        status = "OK" if not missing else f"FAIL — {len(missing):,} with no author"
        print(f"  vendored YAML        {total:,} {LICENCE} rules — {status}")
        if missing:
            failures += 1
            _show(missing, show)
    else:
        print(f"  vendored YAML        no {LICENCE} rules found at {SIGMA_YAML.relative_to(ROOT)}")

    for path in COMPILED:
        if not path.exists():
            print(f"  FAIL  missing compiled ruleset: {path.relative_to(ROOT)}")
            failures += 1
            continue
        total, missing = _scan_compiled(path)
        if not total:
            continue
        checked_any = True
        status = "OK" if not missing else f"FAIL — {len(missing):,} with no author"
        print(f"  {path.relative_to(ROOT).as_posix()[:48]:<48} {total:,} — {status}")
        if missing:
            failures += 1
            _show(missing, show)

    for path in MARKETPLACE:
        if not path.exists():
            continue
        total, missing, misattributed = _scan_marketplace(path)
        if not total:
            continue
        checked_any = True
        bad = []
        if missing:
            bad.append(f"{len(missing):,} with no provenance author")
        if misattributed:
            bad.append(f"{len(misattributed):,} credited to this project")
        status = "OK" if not bad else "FAIL — " + ", ".join(bad)
        print(f"  {path.relative_to(ROOT).as_posix()[:48]:<48} {total:,} — {status}")
        if bad:
            failures += 1
            _show(missing or misattributed, show)

    if not checked_any:
        # An empty tree must not read as compliant. This is the vacuous-pass
        # case every gate here has to refuse.
        print(f"check_detection_attribution: FAIL — no {LICENCE} content found to check")
        return 1

    print()
    if failures:
        print(
            f"check_detection_attribution: FAIL — {failures} surface(s) ship {LICENCE} rules "
            "without naming their author. DRL-1.1 requires author identification to travel "
            "with a shared copy and to appear in messages produced by a match."
        )
        return 1
    print(f"check_detection_attribution: OK — every {LICENCE} rule names its author")
    return 0


def _show(idents: list[str], show: bool) -> None:
    sample = idents if show else idents[:5]
    for ident in sample:
        print(f"        {ident}")
    if not show and len(idents) > len(sample):
        print(f"        … and {len(idents) - len(sample):,} more (--list for all)")


def _self_test() -> int:
    """Prove the gate detects the violation it exists to catch.

    Three injected cases rather than one, because the defect had three
    distinct shapes and a gate that caught only the empty string would have
    passed the tree where the console credited this project instead.
    """
    extra = []

    # 1. empty author on a compiled rule
    rule = {"id": "x", "provenance": {"license": LICENCE, "author": ""}}
    caught = bool(_probe_compiled([rule])[1])
    extra.append(("detects an empty author on a compiled rule", caught))

    # 2. the key absent entirely
    rule = {"id": "x", "provenance": {"license": LICENCE}}
    caught = bool(_probe_compiled([rule])[1])
    extra.append(("detects a provenance block with no author key", caught))

    # 3. the item credited to this project
    item = {"id": "x", "author": "AiSOC", "provenance": {"license": LICENCE, "author": "Tim Shelton"}}
    caught = bool(_probe_marketplace([item])[2])
    extra.append(("detects an imported item credited to this project", caught))

    # 4. a real author passes — a gate that fails everything is not a gate
    item = {"id": "x", "author": "Tim Shelton", "provenance": {"license": LICENCE, "author": "Tim Shelton"}}
    _, miss, mis = _probe_marketplace([item])
    extra.append(("passes a rule that names its author", not miss and not mis))

    # 5. upstream genuinely crediting nobody is recorded, not invented
    rule = {"id": "x", "provenance": {"license": LICENCE, "author": _ABSENT}}
    extra.append(("passes a rule upstream credits to nobody", not _probe_compiled([rule])[1]))

    # 6. the dependency-free YAML reader agrees with the files on disk
    extra.append(("reads the vendored YAML provenance block", _probe_yaml_reader()))

    return self_test_main(Path(__file__).name, extra=extra)


def _probe_compiled(rules: list[dict[str, Any]]) -> tuple[int, list[str]]:
    total, missing = 0, []
    for rule in rules:
        prov = rule.get("provenance") or {}
        if prov.get("license") != LICENCE:
            continue
        total += 1
        if not _attributed(prov.get("author")):
            missing.append(str(rule.get("id")))
    return total, missing


def _probe_marketplace(items: list[dict[str, Any]]) -> tuple[int, list[str], list[str]]:
    total, missing, mis = 0, [], []
    for item in items:
        prov = item.get("provenance") or {}
        if prov.get("license") != LICENCE:
            continue
        total += 1
        if not _attributed(prov.get("author")):
            missing.append(str(item.get("id")))
        if str(item.get("author") or "").strip().lower() in _NOT_OURS:
            mis.append(str(item.get("id")))
    return total, missing, mis


def _probe_yaml_reader() -> bool:
    """The line reader must agree with the files, not with a fixture of itself."""
    if not SIGMA_YAML.exists():
        return False
    sampled = 0
    for path in sorted(SIGMA_YAML.rglob("*.yaml"))[:50]:
        prov = _yaml_provenance(path.read_text(encoding="utf-8"))
        if prov.get("source") != "SigmaHQ/sigma" or not prov.get("source_id"):
            return False
        sampled += 1
    return sampled > 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="print every offending rule")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return _self_test()
    return check(show=args.list)


if __name__ == "__main__":
    raise SystemExit(main())
