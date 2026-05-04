#!/usr/bin/env python3
"""Build the AiSOC marketplace index from on-disk content.

This script walks the canonical content directories and emits a single
authoritative ``marketplace/index.json`` describing every detection,
playbook, and plugin shipped with this repo.

Sources walked:

- ``detections/<category>/*.yaml``        - curated AiSOC detection rules
- ``playbooks/packs/v1/<category>/*.json`` - production playbook pack v1
- ``plugins/<plugin-id>/plugin.yaml``     - reference plugin manifests

The output schema is consumed by:

- ``apps/web/public/marketplace/index.json`` (UI fetches this directly)
- ``apps/web/src/components/marketplace/MarketplaceView.tsx``
- The "Sync Marketplace Index" CI workflow

The schema deliberately captures MITRE ATT&CK technique IDs so the
marketplace UI can offer a real coverage filter (the plan calls for a
"MITRE filter" specifically).

Usage:

    python3 scripts/build_marketplace.py             # build & write
    python3 scripts/build_marketplace.py --check     # fail if drift
    python3 scripts/build_marketplace.py --print     # write to stdout
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
DETECTIONS_DIR = REPO_ROOT / "detections"
PLAYBOOKS_PACKS_DIR = REPO_ROOT / "playbooks" / "packs"
PLUGINS_DIR = REPO_ROOT / "plugins"
COMMUNITY_DETECTIONS_DIR = REPO_ROOT / "detections" / "community"
COMMUNITY_PLAYBOOKS_DIR = REPO_ROOT / "playbooks" / "community"
COMMUNITY_PLUGINS_DIR = REPO_ROOT / "plugins" / "community"

OUTPUT_PRIMARY = REPO_ROOT / "marketplace" / "index.json"
OUTPUT_PUBLIC = REPO_ROOT / "apps" / "web" / "public" / "marketplace" / "index.json"

DETECTION_CATEGORIES = {
    "cloud",
    "identity",
    "endpoint",
    "network",
    "application",
    "data-exfil",
}

# Skip these top-level dirs under detections/ when walking - they are
# not curated rules.
DETECTION_SKIP_DIRS = {"fixtures", "sigma-imports", "community"}

MITRE_RE = re.compile(r"mitre\.attack\.(t\d{4}(?:\.\d{3})?)", re.IGNORECASE)
MITRE_LOOSE_RE = re.compile(r"mitre\.(t\d{4}(?:\.\d{3})?)", re.IGNORECASE)


def extract_mitre(tags: Iterable[str]) -> list[str]:
    """Extract uppercase MITRE technique IDs from a tag list.

    Accepts both the strict ``mitre.attack.tXXXX[.YYY]`` form and the
    looser ``mitre.tXXXX[.YYY]`` form that some playbooks use.
    """
    out: list[str] = []
    for tag in tags or []:
        if not isinstance(tag, str):
            continue
        m = MITRE_RE.search(tag) or MITRE_LOOSE_RE.search(tag)
        if m:
            tid = m.group(1).upper()
            if tid not in out:
                out.append(tid)
    return out


def detection_files() -> list[Path]:
    files: list[Path] = []
    if not DETECTIONS_DIR.exists():
        return files
    for child in sorted(DETECTIONS_DIR.iterdir()):
        if not child.is_dir() or child.name in DETECTION_SKIP_DIRS:
            continue
        for f in sorted(child.rglob("*.yaml")):
            files.append(f)
    return files


def playbook_files() -> list[Path]:
    if not PLAYBOOKS_PACKS_DIR.exists():
        return []
    return sorted(PLAYBOOKS_PACKS_DIR.rglob("*.playbook.json"))


def plugin_manifests() -> list[Path]:
    if not PLUGINS_DIR.exists():
        return []
    out: list[Path] = []
    for child in sorted(PLUGINS_DIR.iterdir()):
        if not child.is_dir() or child.name == "community":
            continue
        manifest = child / "plugin.yaml"
        if manifest.exists():
            out.append(manifest)
    return out


def community_detection_files() -> list[Path]:
    if not COMMUNITY_DETECTIONS_DIR.exists():
        return []
    return sorted(COMMUNITY_DETECTIONS_DIR.rglob("*.yaml"))


def community_playbook_files() -> list[Path]:
    if not COMMUNITY_PLAYBOOKS_DIR.exists():
        return []
    return sorted(COMMUNITY_PLAYBOOKS_DIR.rglob("*.playbook.json"))


def community_plugin_manifests() -> list[Path]:
    if not COMMUNITY_PLUGINS_DIR.exists():
        return []
    out: list[Path] = []
    for child in sorted(COMMUNITY_PLUGINS_DIR.iterdir()):
        if not child.is_dir():
            continue
        manifest = child / "plugin.yaml"
        if manifest.exists():
            out.append(manifest)
    return out


def build_detection_item(path: Path, *, source: str) -> dict[str, Any] | None:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"WARN: could not parse {path}: {exc}", file=sys.stderr)
        return None
    if not isinstance(data, dict):
        return None
    tags = list(data.get("tags") or [])
    mitre = extract_mitre(tags)
    category = data.get("category") or path.parent.name
    return {
        "id": data.get("id") or path.stem,
        "type": "detection",
        "name": data.get("name") or data.get("id") or path.stem,
        "description": (data.get("description") or "").strip(),
        "version": data.get("version", "1.0.0"),
        "author": data.get("author", "AiSOC"),
        "tags": [t for t in tags if not t.lower().startswith("mitre.")],
        "severity": data.get("severity"),
        "category": category,
        "mitre_techniques": mitre,
        "log_source": (data.get("log_source") or {}).get("product"),
        "playbook": data.get("playbook"),
        "verified": source == "core",
        "source": source,
        "path": str(path.relative_to(REPO_ROOT)),
    }


def build_playbook_item(path: Path, *, source: str) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"WARN: could not parse {path}: {exc}", file=sys.stderr)
        return None
    if not isinstance(data, dict):
        return None
    tags = list(data.get("tags") or [])
    mitre = extract_mitre(tags)
    trigger_block = data.get("trigger") or {}
    trigger = trigger_block.get("on") if isinstance(trigger_block, dict) else None
    severities = (
        trigger_block.get("severity") if isinstance(trigger_block, dict) else None
    )
    severity: str | None = None
    if isinstance(severities, list) and severities:
        # Pick the highest declared severity for display.
        order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        severity = max(
            severities,
            key=lambda s: order.get(str(s).lower(), 0),
        )
    return {
        "id": data.get("id") or path.stem,
        "type": "playbook",
        "name": data.get("name") or path.stem,
        "description": (data.get("description") or "").strip(),
        "version": data.get("version", "1.0.0"),
        "author": data.get("author", "AiSOC"),
        "tags": [t for t in tags if not t.lower().startswith("mitre.")],
        "severity": severity,
        "trigger": trigger,
        "steps": len(data.get("steps") or []),
        "category": path.parent.name,
        "mitre_techniques": mitre,
        "verified": source == "core",
        "source": source,
        "path": str(path.relative_to(REPO_ROOT)),
    }


def build_plugin_item(path: Path, *, source: str) -> dict[str, Any] | None:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"WARN: could not parse {path}: {exc}", file=sys.stderr)
        return None
    if not isinstance(data, dict):
        return None
    tags = list(data.get("tags") or [])
    plugin_dir = path.parent
    has_python = (plugin_dir / "plugin.py").exists()
    has_go = (plugin_dir / "go" / "main.go").exists()
    sdks: list[str] = []
    if has_python:
        sdks.append("python")
    if has_go:
        sdks.append("go")
    return {
        "id": data.get("id") or plugin_dir.name,
        "type": "plugin",
        "name": data.get("name") or plugin_dir.name,
        "description": (data.get("description") or "").strip(),
        "version": data.get("version", "1.0.0"),
        "author": data.get("author", "AiSOC"),
        "tags": tags,
        "plugin_type": data.get("plugin_type"),
        "license": data.get("license"),
        "homepage": data.get("homepage"),
        "min_aisoc_version": data.get("min_aisoc_version"),
        "sdks": sdks,
        "mitre_techniques": [],
        "verified": source == "core",
        "source": source,
        "path": str(path.relative_to(REPO_ROOT)),
    }


def collect_items() -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for f in detection_files():
        item = build_detection_item(f, source="core")
        if item:
            items.append(item)
    for f in community_detection_files():
        item = build_detection_item(f, source="community")
        if item:
            items.append(item)
    for f in playbook_files():
        item = build_playbook_item(f, source="core")
        if item:
            items.append(item)
    for f in community_playbook_files():
        item = build_playbook_item(f, source="community")
        if item:
            items.append(item)
    for f in plugin_manifests():
        item = build_plugin_item(f, source="core")
        if item:
            items.append(item)
    for f in community_plugin_manifests():
        item = build_plugin_item(f, source="community")
        if item:
            items.append(item)
    return items


def categories_block(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "id": "playbooks",
            "label": "Response Playbooks",
            "description": (
                "Automated incident-response workflows triggered by "
                "alerts or manual invocation."
            ),
        },
        {
            "id": "detections",
            "label": "Detection Rules",
            "description": (
                "Curated YAML rules for identifying malicious or "
                "suspicious activity across cloud, identity, endpoint, "
                "network, application, and data-exfil categories."
            ),
        },
        {
            "id": "plugins",
            "label": "Plugins",
            "description": (
                "Reference connectors, enrichers, actions, and "
                "widgets shipped with both Python and Go SDK "
                "implementations for cross-language parity."
            ),
        },
    ]


def coverage_block(items: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute MITRE ATT&CK coverage across detections + playbooks."""
    techniques: dict[str, int] = {}
    for item in items:
        for tid in item.get("mitre_techniques") or []:
            techniques[tid] = techniques.get(tid, 0) + 1
    return {
        "techniques": dict(sorted(techniques.items())),
        "unique_techniques": len(techniques),
        "total_with_mitre": sum(
            1 for i in items if i.get("mitre_techniques")
        ),
    }


def build_index() -> dict[str, Any]:
    items = collect_items()
    items.sort(key=lambda i: (i["type"], i.get("id", "")))
    return {
        "$schema": "https://aisoc.dev/schemas/marketplace/v1.json",
        "version": "1.0.0",
        "generated": dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "categories": categories_block(items),
        "stats": {
            "total": len(items),
            "playbooks": sum(1 for i in items if i["type"] == "playbook"),
            "detections": sum(1 for i in items if i["type"] == "detection"),
            "plugins": sum(1 for i in items if i["type"] == "plugin"),
            "verified": sum(1 for i in items if i.get("verified")),
            "community": sum(1 for i in items if i.get("source") == "community"),
        },
        "mitre_coverage": coverage_block(items),
        "items": items,
    }


def write_index(index: dict[str, Any]) -> None:
    payload = json.dumps(index, indent=2, sort_keys=False) + "\n"
    OUTPUT_PRIMARY.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PUBLIC.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PRIMARY.write_text(payload, encoding="utf-8")
    OUTPUT_PUBLIC.write_text(payload, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit non-zero if the on-disk index does not match the build.",
    )
    parser.add_argument(
        "--print",
        dest="print_only",
        action="store_true",
        help="Print built index to stdout instead of writing files.",
    )
    args = parser.parse_args()

    index = build_index()
    serialised = json.dumps(index, indent=2, sort_keys=False) + "\n"

    if args.print_only:
        sys.stdout.write(serialised)
        return 0

    if args.check:
        existing_primary = (
            OUTPUT_PRIMARY.read_text(encoding="utf-8")
            if OUTPUT_PRIMARY.exists()
            else ""
        )
        existing_public = (
            OUTPUT_PUBLIC.read_text(encoding="utf-8")
            if OUTPUT_PUBLIC.exists()
            else ""
        )

        # Compare ignoring `generated` timestamp.
        def _strip_generated(s: str) -> str:
            if not s:
                return s
            try:
                obj = json.loads(s)
            except Exception:
                return s
            obj.pop("generated", None)
            return json.dumps(obj, indent=2, sort_keys=False) + "\n"

        rebuilt_no_ts = _strip_generated(serialised)
        if (
            _strip_generated(existing_primary) != rebuilt_no_ts
            or _strip_generated(existing_public) != rebuilt_no_ts
        ):
            print(
                "marketplace/index.json is stale. Run: "
                "pnpm marketplace:build",
                file=sys.stderr,
            )
            return 1
        print(
            f"marketplace/index.json is up to date "
            f"({index['stats']['total']} items)."
        )
        return 0

    write_index(index)
    print(
        f"Wrote marketplace index: total={index['stats']['total']} "
        f"detections={index['stats']['detections']} "
        f"playbooks={index['stats']['playbooks']} "
        f"plugins={index['stats']['plugins']} "
        f"mitre_techniques={index['mitre_coverage']['unique_techniques']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
