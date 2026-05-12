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
from collections.abc import Iterable
from pathlib import Path
from typing import Any

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

# Top-level dirs under detections/ that are NOT native rule directories
# but contain rules in some tier (we walk these separately).
DETECTION_NATIVE_SKIP = {
    "fixtures",
    "community",
    "sigma-imports",
    "car-imports",
    "splunk-imports",
    "chronicle-imports",
}

# Imported detection tiers: directory name -> source name used in the
# `provenance.source` field of the rule (and the `source` we project
# into the marketplace item).
IMPORTED_TIER_DIRS: dict[str, str] = {
    "sigma-imports": "sigmahq",
    "car-imports": "mitre-car",
    "splunk-imports": "splunk-security-content",
    "chronicle-imports": "chronicle-detection-rules",
}

MITRE_RE = re.compile(r"mitre\.attack\.(t\d{4}(?:\.\d{3})?)", re.IGNORECASE)
MITRE_LOOSE_RE = re.compile(r"mitre\.(t\d{4}(?:\.\d{3})?)", re.IGNORECASE)
MITRE_BARE_RE = re.compile(r"^t\d{4}(?:\.\d{3})?$", re.IGNORECASE)


def normalise_tags(raw: Any) -> list[str]:
    """Flatten the ``tags`` block into a list of dotted strings.

    Native rules emit ``['mitre.attack.t1234', 'tlp.white']``. The detection
    importers emit a dict shape: ``{'mitre': ['T1234'], 'categories': ['endpoint']}``.
    Downstream code expects strings, so we project the dict shape into the
    same dotted form (``mitre.attack.t1234``, ``categories.endpoint``).
    """
    if raw is None:
        return []
    if isinstance(raw, list):
        return [str(t) for t in raw if isinstance(t, str)]
    if isinstance(raw, dict):
        out: list[str] = []
        for key, values in raw.items():
            if not isinstance(values, list):
                continue
            for v in values:
                if not isinstance(v, str):
                    continue
                if str(key).lower() == "mitre":
                    out.append(f"mitre.attack.{v.lower()}")
                else:
                    out.append(f"{key}.{v}")
        return out
    return []


def extract_mitre(tags: Iterable[Any]) -> list[str]:
    """Extract uppercase MITRE technique IDs from a tag block.

    Accepts:
      * the strict ``mitre.attack.tXXXX[.YYY]`` form,
      * the looser ``mitre.tXXXX[.YYY]`` form that some playbooks use,
      * bare ``T1234`` IDs as emitted by the detection importers under
        ``tags.mitre``.

    The argument may be a list of strings *or* a dict like
    ``{'mitre': ['T1234'], 'categories': ['endpoint']}``.
    """
    out: list[str] = []

    def _add(tid: str) -> None:
        u = tid.upper()
        if u not in out:
            out.append(u)

    if isinstance(tags, dict):
        # Fast path for the importer shape — just consume tags['mitre'].
        for v in tags.get("mitre") or []:
            if isinstance(v, str) and MITRE_BARE_RE.match(v):
                _add(v)

    iterable = tags if isinstance(tags, (list, tuple)) else normalise_tags(tags)
    for tag in iterable or []:
        if not isinstance(tag, str):
            continue
        m = MITRE_RE.search(tag) or MITRE_LOOSE_RE.search(tag)
        if m:
            _add(m.group(1))
            continue
        if MITRE_BARE_RE.match(tag):
            _add(tag)
    return out


def detection_files() -> list[Path]:
    """Walk only the native detection tier (``detections/<category>/``)."""
    files: list[Path] = []
    if not DETECTIONS_DIR.exists():
        return files
    for child in sorted(DETECTIONS_DIR.iterdir()):
        if not child.is_dir() or child.name in DETECTION_NATIVE_SKIP:
            continue
        for f in sorted(child.rglob("*.yaml")):
            files.append(f)
    return files


def imported_detection_files() -> list[tuple[Path, str, bool]]:
    """Return (path, source_name, is_quarantined) for every imported rule.

    Walks the tier directories declared in :data:`IMPORTED_TIER_DIRS`.
    Rules nested under a ``_quarantine/`` directory are returned with
    ``is_quarantined=True`` so the marketplace can surface them as
    "imported, requires translation" instead of pretending they execute.
    """
    out: list[tuple[Path, str, bool]] = []
    if not DETECTIONS_DIR.exists():
        return out
    for tier_dir, source_name in IMPORTED_TIER_DIRS.items():
        root = DETECTIONS_DIR / tier_dir
        if not root.exists():
            continue
        for f in sorted(root.rglob("*.yaml")):
            try:
                rel = f.relative_to(root).parts
            except ValueError:
                continue
            quarantined = bool(rel) and rel[0] == "_quarantine"
            out.append((f, source_name, quarantined))
    return out


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


def build_detection_item(
    path: Path,
    *,
    source: str,
    tier: str,
    quarantined: bool = False,
) -> dict[str, Any] | None:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"WARN: could not parse {path}: {exc}", file=sys.stderr)
        return None
    if not isinstance(data, dict):
        return None
    raw_tags = data.get("tags")
    mitre = extract_mitre(raw_tags or [])
    tags = normalise_tags(raw_tags)
    category = data.get("category") or path.parent.name
    enabled = data.get("enabled")
    if quarantined:
        # Quarantine directory layout has the category two levels below the
        # tier root (e.g. sigma-imports/_quarantine/cloud/foo.yaml).
        if not data.get("category"):
            try:
                rel = path.relative_to(DETECTIONS_DIR).parts
                if len(rel) >= 4 and rel[1] == "_quarantine":
                    category = rel[2]
            except ValueError:
                pass  # path is not relative to DETECTIONS_DIR; category stays None

    item: dict[str, Any] = {
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
        "verified": tier == "stable",
        "source": source,
        "tier": tier,
        "enabled": False if (quarantined or enabled is False) else True,
        "path": str(path.relative_to(REPO_ROOT)),
    }
    if quarantined:
        item["quarantine_reason"] = data.get("quarantine_reason") or (
            "imported rule; upstream query language not directly executable "
            "by the AiSOC engine yet"
        )
    provenance = data.get("provenance")
    if isinstance(provenance, dict):
        item["provenance"] = {
            "source": provenance.get("source"),
            "source_id": provenance.get("source_id"),
            "source_commit": provenance.get("source_commit"),
            "license": provenance.get("license"),
            "license_url": provenance.get("license_url"),
            "imported_at": provenance.get("imported_at"),
            "upstream_path": provenance.get("upstream_path"),
        }
    return item


def build_playbook_item(
    path: Path, *, source: str, tier: str
) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"WARN: could not parse {path}: {exc}", file=sys.stderr)
        return None
    if not isinstance(data, dict):
        return None
    raw_tags = data.get("tags")
    mitre = extract_mitre(raw_tags or [])
    tags = normalise_tags(raw_tags)
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
        "verified": tier == "stable",
        "source": source,
        "tier": tier,
        "enabled": True,
        "path": str(path.relative_to(REPO_ROOT)),
    }


def build_plugin_item(
    path: Path, *, source: str, tier: str | None = None
) -> dict[str, Any] | None:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"WARN: could not parse {path}: {exc}", file=sys.stderr)
        return None
    if not isinstance(data, dict):
        return None
    tags = normalise_tags(data.get("tags"))
    plugin_dir = path.parent
    has_python = (plugin_dir / "plugin.py").exists()
    has_go = (plugin_dir / "go" / "main.go").exists()
    sdks: list[str] = []
    if has_python:
        sdks.append("python")
    if has_go:
        sdks.append("go")

    # Resolve tier. A plugin manifest can self-declare ``tier:`` to mark
    # itself as ``beta`` or ``community``. Otherwise we infer from source
    # and how complete the implementation is. Manifest-only plugins (no
    # plugin.py + no go/main.go) get demoted to ``beta`` so we don't pass
    # off scaffolds as production-ready.
    declared_tier = (data.get("tier") or "").strip().lower() or None
    if declared_tier in {"stable", "beta", "community"}:
        resolved_tier = declared_tier
    elif tier is not None:
        resolved_tier = tier
    elif source == "community":
        resolved_tier = "community"
    elif not (has_python or has_go):
        resolved_tier = "beta"
    else:
        resolved_tier = "stable"

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
        "verified": resolved_tier == "stable",
        "source": source,
        "tier": resolved_tier,
        "path": str(path.relative_to(REPO_ROOT)),
    }


def collect_items() -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []

    # Detections — native (stable) tier
    for f in detection_files():
        item = build_detection_item(f, source="core", tier="stable")
        if item:
            items.append(item)

    # Detections — imported tiers (one per upstream corpus)
    for f, src_name, quarantined in imported_detection_files():
        item = build_detection_item(
            f, source=src_name, tier="imported", quarantined=quarantined
        )
        if item:
            items.append(item)

    # Detections — community tier
    for f in community_detection_files():
        item = build_detection_item(f, source="community", tier="community")
        if item:
            items.append(item)

    # Playbooks
    for f in playbook_files():
        item = build_playbook_item(f, source="core", tier="stable")
        if item:
            items.append(item)
    for f in community_playbook_files():
        item = build_playbook_item(f, source="community", tier="community")
        if item:
            items.append(item)

    # Plugins
    for f in plugin_manifests():
        item = build_plugin_item(f, source="core")
        if item:
            items.append(item)
    for f in community_plugin_manifests():
        item = build_plugin_item(f, source="community", tier="community")
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


def _tier_breakdown(items: list[dict[str, Any]]) -> dict[str, int]:
    """Count items per tier (stable, beta, imported, community)."""
    counts: dict[str, int] = {}
    for item in items:
        tier = item.get("tier") or "stable"
        counts[tier] = counts.get(tier, 0) + 1
    return dict(sorted(counts.items()))


def _detection_tier_breakdown(items: list[dict[str, Any]]) -> dict[str, int]:
    """Count detection items per tier — the main 'are we Wazuh-scale' headline."""
    counts: dict[str, int] = {}
    for item in items:
        if item.get("type") != "detection":
            continue
        tier = item.get("tier") or "stable"
        counts[tier] = counts.get(tier, 0) + 1
    return dict(sorted(counts.items()))


def coverage_block(items: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute MITRE ATT&CK coverage across detections + playbooks.

    Returns aggregate counts per technique plus a per-tier breakdown so the
    UI can render a stacked coverage matrix (native vs imported vs community)
    rather than a single flat number.
    """
    techniques: dict[str, int] = {}
    by_tier: dict[str, dict[str, int]] = {}
    for item in items:
        tier = item.get("tier") or "stable"
        for tid in item.get("mitre_techniques") or []:
            techniques[tid] = techniques.get(tid, 0) + 1
            tier_map = by_tier.setdefault(tier, {})
            tier_map[tid] = tier_map.get(tid, 0) + 1

    return {
        "techniques": dict(sorted(techniques.items())),
        "unique_techniques": len(techniques),
        "total_with_mitre": sum(
            1 for i in items if i.get("mitre_techniques")
        ),
        "by_tier": {
            tier: dict(sorted(tids.items())) for tier, tids in by_tier.items()
        },
    }


def build_index() -> dict[str, Any]:
    items = collect_items()
    items.sort(key=lambda i: (i["type"], i.get("id", "")))
    return {
        "$schema": "https://example.com/schemas/marketplace/v1.json",
        "version": "1.0.0",
        "generated": dt.datetime.now(dt.UTC)
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
            "by_tier": _tier_breakdown(items),
            "detections_by_tier": _detection_tier_breakdown(items),
            "quarantined": sum(
                1 for i in items if i.get("quarantine_reason")
            ),
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
