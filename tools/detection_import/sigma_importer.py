"""SigmaHQ → AiSOC detection importer.

Pulls rules from `SigmaHQ/sigma <https://github.com/SigmaHQ/sigma>`_ at a
pinned commit and converts each rule into AiSOC's internal Sigma-inspired
schema with a populated ``provenance`` block.

The Sigma format is already very close to what AiSOC ships natively, so the
conversion is mostly:

* normalise category to AiSOC's six-folder taxonomy (cloud / endpoint /
  identity / network / application / data-exfil),
* keep the upstream ``detection:`` block verbatim,
* extract MITRE ATT&CK technique IDs from ``tags:``,
* compute a stable AiSOC rule id (``sigmahq-sigma-<slug>``),
* drop deprecated and test rules, quarantine experimental ones.

Run via ``python3 -m tools.detection_import.import_orchestrator`` from the
repo root — that orchestrator clones the repo for us and passes the right
commit SHA.
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

SIGMA_REPO_URL = "https://github.com/SigmaHQ/sigma.git"
SIGMA_LICENSE = "DRL-1.1"
SIGMA_LICENSE_URL = "https://github.com/SigmaHQ/Detection-Rule-License"

# Sigma ships rules under ``rules/`` (stable + curated) and ``rules-emerging-threats/``
# / ``rules-threat-hunting/`` etc.  We only import from ``rules/`` for the
# default corpus to keep quality predictable.  Bumping this list is a deliberate
# decision recorded in the importer's commit message.
SIGMA_INCLUDE_DIRS = ("rules",)

# Deprecated, test, and unsupported rules don't ship.  Experimental rules go to
# the quarantine bucket (``enabled: false``) so users can opt in but they don't
# pollute the default rule corpus.
SIGMA_SKIP_STATUSES = {"deprecated", "unsupported"}
SIGMA_QUARANTINE_STATUSES = {"experimental", "test"}


def _extract_mitre_techniques(tags: list[str]) -> list[str]:
    """Pull MITRE ATT&CK technique IDs from a Sigma ``tags`` list.

    Sigma uses ``attack.t1078`` and ``attack.t1078.004`` style tags; we
    canonicalise to upper-case (``T1078``).
    """
    techniques: list[str] = []
    for tag in tags or []:
        if not isinstance(tag, str):
            continue
        tag = tag.strip().lower()
        if not tag.startswith("attack.t"):
            continue
        # ``attack.t1078`` -> ``t1078``
        technique = tag.split(".", 1)[1]
        # ``t1078.004`` stays as-is, just upper-case.
        techniques.append(technique.upper())
    # Preserve order, dedupe.
    seen: set[str] = set()
    out: list[str] = []
    for tech in techniques:
        if tech not in seen:
            out.append(tech)
            seen.add(tech)
    return out


def _category_for(logsource: dict, upstream_path: Path) -> str:
    """Map a Sigma rule to one of AiSOC's six categories.

    Tries ``logsource.product`` first, then ``logsource.category``, and finally
    falls back to the top-level rules subdirectory in the upstream repo
    (``rules/cloud/...`` -> ``cloud``).
    """
    if not isinstance(logsource, dict):
        logsource = {}

    candidate = (
        logsource.get("product")
        or logsource.get("category")
        or logsource.get("service")
        or ""
    )
    candidate = str(candidate).lower()
    if candidate:
        return normalise_categories(candidate)

    # Fall back to ``rules/<top-level>/...`` if logsource is empty.
    parts = upstream_path.parts
    if "rules" in parts:
        idx = parts.index("rules")
        if idx + 1 < len(parts):
            return normalise_categories(parts[idx + 1])
    return "endpoint"


def _convert_rule(
    raw: dict,
    upstream_path: Path,
    repo_root: Path,
    commit: str,
) -> ImportedRule | None:
    """Convert a single Sigma YAML dict into an ImportedRule.

    Returns ``None`` if the rule should be dropped (deprecated/test/etc.).
    """
    upstream_id = str(raw.get("id") or "").strip()
    title = str(raw.get("title") or "").strip()
    if not upstream_id or not title:
        logger.debug("Skipping %s: missing id or title", upstream_path)
        return None

    status = str(raw.get("status") or "").strip().lower()
    if status in SIGMA_SKIP_STATUSES:
        logger.debug("Skipping %s: status=%s", upstream_path, status)
        return None

    quarantine_reason: str | None = None
    if status in SIGMA_QUARANTINE_STATUSES:
        quarantine_reason = f"upstream status: {status}"

    description = str(raw.get("description") or title).strip()
    severity = map_severity(raw.get("level"))
    references = [str(ref) for ref in raw.get("references") or [] if ref]

    logsource = raw.get("logsource") or {}
    detection = raw.get("detection") or {}
    if not isinstance(detection, dict) or not detection:
        # No detection block ⇒ unusable.
        return None

    techniques = _extract_mitre_techniques(raw.get("tags") or [])
    category = _category_for(logsource, upstream_path)

    relative_path = upstream_path.relative_to(repo_root).as_posix()
    rule_id = stable_id("sigmahq-sigma", upstream_id)
    output_filename = f"{slugify(title) or slugify(upstream_id)}.yaml"

    provenance = {
        "source": "SigmaHQ/sigma",
        "source_id": upstream_id,
        "source_commit": short_sha(commit),
        "license": SIGMA_LICENSE,
        "license_url": SIGMA_LICENSE_URL,
        "imported_at": today_iso(),
        "imported_by": "sigma_importer",
        "upstream_path": relative_path,
    }

    tags = {"mitre": techniques, "categories": [category]}
    falsepositives = raw.get("falsepositives") or []
    extra: dict = {}
    if falsepositives:
        extra["falsepositives"] = [str(fp) for fp in falsepositives]

    return ImportedRule(
        rule_id=rule_id,
        title=title,
        description=description,
        severity=severity,
        enabled=quarantine_reason is None,
        tags=tags,
        references=references,
        logsource={
            str(k): str(v)
            for k, v in (logsource.items() if isinstance(logsource, dict) else [])
        },
        detection=detection,
        provenance=provenance,
        output_category=category,
        output_filename=output_filename,
        quarantine_reason=quarantine_reason,
        extra=extra,
    )


def import_rules(
    commit: str,
    *,
    output_root: Path | None = None,
    repo_path: Path | None = None,
) -> list[ImportedRule]:
    """Import SigmaHQ rules at ``commit`` and write them to disk.

    Args:
        commit: full SHA of the upstream commit to import from. Pinned
            in :mod:`tools.detection_import.import_orchestrator` so that runs
            are reproducible.
        output_root: where to write converted rules. Defaults to
            ``detections/sigma-imports``.
        repo_path: where to clone/find the SigmaHQ repo. Defaults to
            ``.import-cache/sigmahq-sigma``.

    Returns:
        The list of :class:`ImportedRule` objects that were written.
    """
    output_root = output_root or REPO_ROOT / "detections" / "sigma-imports"
    repo_path = repo_path or IMPORT_CACHE / "sigmahq-sigma"

    ensure_repo(SIGMA_REPO_URL, repo_path, commit)

    rules: list[ImportedRule] = []
    seen_ids: set[str] = set()

    for include_dir in SIGMA_INCLUDE_DIRS:
        scan_root = repo_path / include_dir
        if not scan_root.exists():
            logger.warning("Sigma include dir missing: %s", scan_root)
            continue
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
            # Dedup by AiSOC rule id (collisions are extremely rare since we
            # incorporate the upstream UUID).
            if rule.rule_id in seen_ids:
                continue
            seen_ids.add(rule.rule_id)
            write_rule(rule, output_root)
            rules.append(rule)

    logger.info(
        "SigmaHQ importer: wrote %d rules to %s (commit %s)",
        len(rules),
        output_root.relative_to(REPO_ROOT),
        short_sha(commit),
    )
    return rules


__all__ = ["import_rules", "SIGMA_REPO_URL", "SIGMA_LICENSE"]
