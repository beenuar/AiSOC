"""Splunk Security Content → AiSOC importer.

Pulls detections from
`splunk/security_content <https://github.com/splunk/security_content>`_ at a
pinned commit and converts each YAML detection into AiSOC's internal
Sigma-inspired schema with a populated ``provenance`` block.

Splunk's content ships SPL search strings (and often a Splunk Common
Information Model dependency). A 100% lossless SPL → Sigma transpile is
out of scope; instead we:

* keep the upstream SPL verbatim under ``detection.splunk_spl``,
* extract the technique list from ``tags.mitre_attack_id`` (already MITRE
  IDs in Splunk's schema),
* mark the rule ``enabled: false`` and quarantine it with a clear
  ``quarantine_reason`` so analysts review and translate the SPL before
  enabling. This is the honest path — better than auto-disabling silently.

The orchestrator (``import_orchestrator.py``) clones the repo and calls
:func:`import_rules` with the pinned commit.
"""

from __future__ import annotations

import logging
from pathlib import Path

import yaml

from tools.detection_import.common import (
    IMPORT_CACHE,
    REPO_ROOT,
    ImportedRule,
    ensure_repo,
    map_severity,
    normalise_categories,
    short_sha,
    slugify,
    stable_id,
    today_iso,
    write_rule,
)

logger = logging.getLogger(__name__)

SPLUNK_REPO_URL = "https://github.com/splunk/security_content.git"
SPLUNK_LICENSE = "Apache-2.0"
SPLUNK_LICENSE_URL = "https://github.com/splunk/security_content/blob/develop/LICENSE"

# Splunk ships detections under ``detections/<category>/*.yml`` plus
# additional sub-bundles. We import from the top-level ``detections`` tree.
SPLUNK_DETECTIONS_DIR = "detections"

# Splunk uses ``status`` values like ``production``, ``experimental``,
# ``deprecated``. We map them to AiSOC's enabled/quarantine states.
SPLUNK_SKIP_STATUSES = {"deprecated"}
SPLUNK_QUARANTINE_STATUSES = {"experimental", "validation", "draft"}


def _extract_techniques(tags: dict | None) -> list[str]:
    """Pull MITRE technique IDs from a Splunk ``tags.mitre_attack_id`` list."""
    if not isinstance(tags, dict):
        return []
    raw_ids = tags.get("mitre_attack_id") or []
    techniques: list[str] = []
    seen: set[str] = set()
    for tech in raw_ids:
        canonical = str(tech).strip().upper()
        if not canonical or canonical in seen:
            continue
        techniques.append(canonical)
        seen.add(canonical)
    return techniques


def _category_for(upstream_path: Path) -> str:
    """Pick an AiSOC category from the path
    (``detections/cloud/foo.yml`` -> ``cloud``)."""
    parts = upstream_path.parts
    if SPLUNK_DETECTIONS_DIR in parts:
        idx = parts.index(SPLUNK_DETECTIONS_DIR)
        if idx + 1 < len(parts):
            return normalise_categories(parts[idx + 1])
    return "endpoint"


def _convert_rule(
    raw: dict,
    upstream_path: Path,
    repo_root: Path,
    commit: str,
) -> ImportedRule | None:
    """Convert one Splunk detection YAML into an :class:`ImportedRule`."""
    upstream_id = str(raw.get("id") or "").strip()
    title = str(raw.get("name") or "").strip()
    if not upstream_id or not title:
        return None

    status = str(raw.get("status") or "").strip().lower()
    if status in SPLUNK_SKIP_STATUSES:
        return None

    spl = str(raw.get("search") or "").strip()
    if not spl:
        # Some entries are templates/placeholders without a usable search.
        return None

    description = str(raw.get("description") or title).strip()
    severity = map_severity(raw.get("severity") or raw.get("risk_score"))
    references = [str(ref) for ref in raw.get("references") or [] if ref]

    tags = raw.get("tags") or {}
    techniques = _extract_techniques(tags)
    category = _category_for(upstream_path)

    detection: dict = {
        "splunk_spl": spl,
        "schedule": raw.get("schedule") or "",
        "search_window": raw.get("search_window") or "",
    }
    # Drop empty optional keys to keep YAML readable.
    detection = {k: v for k, v in detection.items() if v}

    relative_path = upstream_path.relative_to(repo_root).as_posix()
    rule_id = stable_id("splunk-security-content", upstream_id)
    output_filename = f"{slugify(title) or slugify(upstream_id)}.yaml"

    provenance = {
        "source": "splunk/security_content",
        "source_id": upstream_id,
        "source_commit": short_sha(commit),
        "license": SPLUNK_LICENSE,
        "license_url": SPLUNK_LICENSE_URL,
        "imported_at": today_iso(),
        "imported_by": "splunk_importer",
        "upstream_path": relative_path,
    }

    quarantine_reason = (
        f"upstream status: {status}"
        if status in SPLUNK_QUARANTINE_STATUSES
        else "raw SPL — needs translation to AiSOC detection schema"
    )

    return ImportedRule(
        rule_id=rule_id,
        title=title,
        description=description,
        severity=severity,
        # Always disabled: SPL doesn't run on AiSOC's pipeline as-is.
        enabled=False,
        tags={"mitre": techniques, "categories": [category]},
        references=references,
        logsource={"product": "splunk"},
        detection=detection,
        provenance=provenance,
        output_category=category,
        output_filename=output_filename,
        quarantine_reason=quarantine_reason,
        extra={
            "notes": {
                "splunk_status": status or "unspecified",
                "splunk_data_source": tags.get("data_source", []),
            }
        },
    )


def import_rules(
    commit: str,
    *,
    output_root: Path | None = None,
    repo_path: Path | None = None,
) -> list[ImportedRule]:
    """Import Splunk Security Content detections at ``commit``.

    Args:
        commit: full SHA of the upstream commit to import from.
        output_root: where to write converted rules. Defaults to
            ``detections/splunk-imports``.
        repo_path: where to clone/find the Splunk repo. Defaults to
            ``.import-cache/splunk-security-content``.
    """
    output_root = output_root or REPO_ROOT / "detections" / "splunk-imports"
    repo_path = repo_path or IMPORT_CACHE / "splunk-security-content"

    ensure_repo(SPLUNK_REPO_URL, repo_path, commit)

    rules: list[ImportedRule] = []
    seen_ids: set[str] = set()

    scan_root = repo_path / SPLUNK_DETECTIONS_DIR
    if not scan_root.exists():
        logger.warning("Splunk detections dir missing: %s", scan_root)
        return rules

    for path in sorted(scan_root.rglob("*.yml")):
        try:
            with path.open("r", encoding="utf-8") as fh:
                raw = yaml.safe_load(fh)
        except (OSError, yaml.YAMLError) as exc:
            logger.debug("Skipping %s: %s", path, exc)
            continue
        if not isinstance(raw, dict):
            continue

        rule = _convert_rule(raw, path, repo_path, commit)
        if rule is None:
            continue
        if rule.rule_id in seen_ids:
            continue
        seen_ids.add(rule.rule_id)
        write_rule(rule, output_root)
        rules.append(rule)

    logger.info(
        "Splunk importer: wrote %d rules to %s (commit %s)",
        len(rules),
        output_root.relative_to(REPO_ROOT),
        short_sha(commit),
    )
    return rules


__all__ = ["import_rules", "SPLUNK_REPO_URL", "SPLUNK_LICENSE"]
