"""Google Chronicle detection-rules → AiSOC importer.

Pulls detections from
`chronicle/detection-rules <https://github.com/chronicle/detection-rules>`_
at a pinned commit and converts each YARA-L 2.0 file into AiSOC's internal
Sigma-inspired schema with a populated ``provenance`` block.

YARA-L 2.0 is a procedural rule language with ``meta {}``, ``events {}``,
``match {}``, and ``condition {}`` blocks. A 100% lossless YARA-L → Sigma
transpile is out of scope; we instead:

* keep the raw rule text under ``detection.chronicle_yaral`` so analysts
  can review the original logic,
* extract metadata (``author``, ``severity``, MITRE techniques) from the
  ``meta {}`` block,
* mark each rule ``enabled: false`` and quarantine it with a clear reason —
  Chronicle rules need translation before they can run on AiSOC's pipeline.

The orchestrator (``import_orchestrator.py``) clones the repo and calls
:func:`import_rules` with the pinned commit.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

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

CHRONICLE_REPO_URL = "https://github.com/chronicle/detection-rules.git"
CHRONICLE_LICENSE = "Apache-2.0"
CHRONICLE_LICENSE_URL = (
    "https://github.com/chronicle/detection-rules/blob/main/LICENSE"
)

# Chronicle ships rules under ``rules/<vendor>/...``. Each ``.yaral`` file
# is a single rule.
CHRONICLE_RULES_DIR = "rules"

_RULE_NAME_RE = re.compile(r"^rule\s+([A-Za-z0-9_]+)\s*\{", re.MULTILINE)
_META_BLOCK_RE = re.compile(r"meta\s*:\s*\{(.*?)\}", re.DOTALL)
_META_LINE_RE = re.compile(r'^\s*([A-Za-z0-9_]+)\s*=\s*"((?:[^"\\]|\\.)*)"\s*$')
_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def _parse_meta(yaral: str) -> dict[str, str]:
    """Parse the ``meta:`` block from a YARA-L rule into a flat dict.

    YARA-L's ``meta:`` accepts simple ``key = "value"`` pairs. We tolerate
    multi-line strings via ``re.DOTALL`` on the block boundary.
    """
    match = _META_BLOCK_RE.search(yaral)
    if not match:
        return {}
    block = match.group(1)
    meta: dict[str, str] = {}
    for line in block.splitlines():
        m = _META_LINE_RE.match(line)
        if not m:
            continue
        key = m.group(1).strip().lower()
        value = m.group(2)
        meta[key] = value
    return meta


def _extract_techniques(meta: dict[str, str]) -> list[str]:
    """Pull MITRE technique IDs from a ``meta`` dict.

    Chronicle rules usually carry ``mitre_attack_technique_id = "T1078"`` or
    embed them in free-text fields. We do both — explicit field first, then
    a regex sweep over technique-ish meta values.
    """
    seen: set[str] = set()
    out: list[str] = []
    explicit = meta.get("mitre_attack_technique_id") or meta.get("mitre_attack_id")
    if explicit:
        for tech in re.split(r"[,\s]+", explicit):
            t = tech.strip().upper()
            if _TECHNIQUE_RE.match(t) and t not in seen:
                out.append(t)
                seen.add(t)
    # Sweep all meta values as a fallback.
    for value in meta.values():
        for found in _TECHNIQUE_RE.findall(value or ""):
            t = found.upper()
            if t not in seen:
                out.append(t)
                seen.add(t)
    return out


def _category_for(upstream_path: Path) -> str:
    """Pick an AiSOC category from the path
    (``rules/aws/...`` -> ``cloud``)."""
    parts = upstream_path.parts
    if CHRONICLE_RULES_DIR in parts:
        idx = parts.index(CHRONICLE_RULES_DIR)
        if idx + 1 < len(parts):
            vendor = parts[idx + 1].lower()
            return normalise_categories(vendor)
    return "endpoint"


def _convert_rule(
    yaral: str,
    upstream_path: Path,
    repo_root: Path,
    commit: str,
) -> ImportedRule | None:
    """Convert a single ``.yaral`` file into an :class:`ImportedRule`."""
    name_match = _RULE_NAME_RE.search(yaral)
    if not name_match:
        return None
    rule_name = name_match.group(1).strip()

    meta = _parse_meta(yaral)
    title = meta.get("description") or meta.get("name") or rule_name
    description = meta.get("description") or title
    severity = map_severity(meta.get("severity") or meta.get("priority"))
    references_raw = meta.get("reference") or meta.get("references") or ""
    references = [
        ref.strip() for ref in re.split(r"[\s,]+", references_raw) if ref.strip()
    ]

    techniques = _extract_techniques(meta)
    category = _category_for(upstream_path)

    relative_path = upstream_path.relative_to(repo_root).as_posix()
    upstream_id = meta.get("rule_id") or rule_name
    rule_id = stable_id("chronicle-detection-rules", upstream_id)
    output_filename = f"{slugify(rule_name) or slugify(upstream_id)}.yaml"

    provenance = {
        "source": "chronicle/detection-rules",
        "source_id": upstream_id,
        "source_commit": short_sha(commit),
        "license": CHRONICLE_LICENSE,
        "license_url": CHRONICLE_LICENSE_URL,
        "imported_at": today_iso(),
        "imported_by": "chronicle_importer",
        "upstream_path": relative_path,
    }

    detection = {
        "chronicle_yaral": yaral.strip(),
        # Surface the YARA-L rule name so analysts can grep for it after
        # translation.
        "chronicle_rule_name": rule_name,
    }

    return ImportedRule(
        rule_id=rule_id,
        title=str(title),
        description=str(description),
        severity=severity,
        enabled=False,
        tags={"mitre": techniques, "categories": [category]},
        references=references,
        logsource={"product": "chronicle"},
        detection=detection,
        provenance=provenance,
        output_category=category,
        output_filename=output_filename,
        quarantine_reason="raw YARA-L — needs translation to AiSOC schema",
        extra={
            "notes": {
                "chronicle_meta": meta,
            }
        },
    )


def import_rules(
    commit: str,
    *,
    output_root: Path | None = None,
    repo_path: Path | None = None,
) -> list[ImportedRule]:
    """Import Chronicle detection rules at ``commit``.

    Args:
        commit: full SHA of the upstream commit to import from.
        output_root: where to write converted rules. Defaults to
            ``detections/chronicle-imports``.
        repo_path: where to clone/find the Chronicle repo. Defaults to
            ``.import-cache/chronicle-detection-rules``.
    """
    output_root = output_root or REPO_ROOT / "detections" / "chronicle-imports"
    repo_path = repo_path or IMPORT_CACHE / "chronicle-detection-rules"

    ensure_repo(CHRONICLE_REPO_URL, repo_path, commit)

    rules: list[ImportedRule] = []
    seen_ids: set[str] = set()

    scan_root = repo_path / CHRONICLE_RULES_DIR
    if not scan_root.exists():
        logger.warning("Chronicle rules dir missing: %s", scan_root)
        return rules

    for path in sorted(scan_root.rglob("*.yaral")):
        try:
            yaral = path.read_text(encoding="utf-8")
        except OSError as exc:
            logger.debug("Skipping %s: %s", path, exc)
            continue

        rule = _convert_rule(yaral, path, repo_path, commit)
        if rule is None:
            continue
        if rule.rule_id in seen_ids:
            continue
        seen_ids.add(rule.rule_id)
        write_rule(rule, output_root)
        rules.append(rule)

    logger.info(
        "Chronicle importer: wrote %d rules to %s (commit %s)",
        len(rules),
        output_root.relative_to(REPO_ROOT),
        short_sha(commit),
    )
    return rules


__all__ = ["import_rules", "CHRONICLE_REPO_URL", "CHRONICLE_LICENSE"]
