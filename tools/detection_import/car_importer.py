"""MITRE Cyber Analytics Repository (CAR) → AiSOC importer.

Pulls analytics from `mitre-attack/car <https://github.com/mitre-attack/car>`_
at a pinned commit and converts each YAML analytic into AiSOC's internal
Sigma-inspired schema with a populated ``provenance`` block.

CAR analytics are smaller and more conceptual than Sigma rules: they describe
*what to look for* with pseudo-code, often without a ready-to-run query. We
keep the upstream pseudo-code in ``detection.car_pseudocode`` for reference,
record the technique mapping under ``tags.mitre``, and mark the rule as
``enabled: false`` by default so analysts opt in only after wiring the
analytic to a concrete log source.

The orchestrator (`import_orchestrator.py`) clones the repo and calls
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
    normalise_categories,
    short_sha,
    slugify,
    stable_id,
    today_iso,
    write_rule,
)

logger = logging.getLogger(__name__)

CAR_REPO_URL = "https://github.com/mitre-attack/car.git"
CAR_LICENSE = "Apache-2.0"
CAR_LICENSE_URL = "https://github.com/mitre-attack/car/blob/master/LICENSE.txt"

# CAR ships analytics under ``analytics/*.yaml`` (one file per analytic).
CAR_ANALYTICS_DIR = "analytics"


def _extract_techniques(coverage: list[dict] | None) -> list[str]:
    """Pull MITRE technique IDs from a CAR ``coverage:`` block.

    CAR's coverage entries look like::

        - technique: T1003.001
          tactics: [credential-access]
          coverage: Moderate

    We canonicalise to upper-case and dedupe while preserving order.
    """
    techniques: list[str] = []
    seen: set[str] = set()
    for entry in coverage or []:
        if not isinstance(entry, dict):
            continue
        technique = entry.get("technique")
        if not technique:
            continue
        tech = str(technique).strip().upper()
        if tech not in seen:
            techniques.append(tech)
            seen.add(tech)
    return techniques


def _category_for(coverage: list[dict] | None) -> str:
    """Pick an AiSOC category from CAR ``coverage[*].tactics``.

    Most CAR analytics target endpoint telemetry; we use the first tactic that
    cleanly maps and fall back to ``endpoint``.
    """
    tactic_to_category = {
        "initial-access": "network",
        "execution": "endpoint",
        "persistence": "endpoint",
        "privilege-escalation": "endpoint",
        "defense-evasion": "endpoint",
        "credential-access": "identity",
        "discovery": "endpoint",
        "lateral-movement": "network",
        "collection": "endpoint",
        "command-and-control": "network",
        "exfiltration": "data-exfil",
        "impact": "endpoint",
    }
    for entry in coverage or []:
        if not isinstance(entry, dict):
            continue
        for tactic in entry.get("tactics") or []:
            cat = tactic_to_category.get(str(tactic).strip().lower())
            if cat:
                return normalise_categories(cat)
    return "endpoint"


def _convert_rule(
    raw: dict,
    upstream_path: Path,
    repo_root: Path,
    commit: str,
) -> ImportedRule | None:
    """Convert a single CAR YAML analytic into an ImportedRule."""
    upstream_id = str(raw.get("id") or "").strip()
    title = str(raw.get("title") or "").strip()
    if not upstream_id or not title:
        return None

    description = str(raw.get("description") or title).strip()
    coverage = raw.get("coverage") or []
    techniques = _extract_techniques(coverage)
    category = _category_for(coverage)

    # CAR analytics ship pseudocode under ``pseudocode`` and sometimes
    # implementations under ``implementations:`` (a list of {name, type, code}).
    # We keep both verbatim under ``detection`` for the engine and humans to
    # consume; CAR rules ship disabled-by-default.
    detection: dict = {}
    if "pseudocode" in raw:
        detection["car_pseudocode"] = str(raw["pseudocode"]).strip()
    impls = raw.get("implementations") or []
    if impls:
        detection["implementations"] = [
            {
                "name": str(i.get("name", "")),
                "type": str(i.get("type", "")),
                "code": str(i.get("code", "")),
            }
            for i in impls
            if isinstance(i, dict)
        ]
    if not detection:
        # Nothing actionable to import.
        return None

    references = [str(ref) for ref in raw.get("references") or [] if ref]
    relative_path = upstream_path.relative_to(repo_root).as_posix()
    rule_id = stable_id("mitre-car", upstream_id)
    output_filename = f"{slugify(upstream_id) or slugify(title)}.yaml"

    provenance = {
        "source": "mitre-attack/car",
        "source_id": upstream_id,
        "source_commit": short_sha(commit),
        "license": CAR_LICENSE,
        "license_url": CAR_LICENSE_URL,
        "imported_at": today_iso(),
        "imported_by": "car_importer",
        "upstream_path": relative_path,
    }

    tags = {"mitre": techniques, "categories": [category]}
    logsource: dict[str, str] = {}
    if subtypes := raw.get("subtypes"):
        # CAR uses ``subtypes`` to scope to ``host`` / ``network`` / etc.
        logsource["category"] = ",".join(str(s) for s in subtypes)

    return ImportedRule(
        rule_id=rule_id,
        title=title,
        description=description,
        # CAR doesn't provide a severity. Default to medium and let analysts
        # promote on import.
        severity="medium",
        # Ship disabled-by-default — these are analytic descriptions, not
        # ready-to-run queries. Analysts wire them up before turning them on.
        enabled=False,
        tags=tags,
        references=references,
        logsource=logsource,
        detection=detection,
        provenance=provenance,
        output_category=category,
        output_filename=output_filename,
        quarantine_reason=None,
        extra={"notes": {"car_status": "needs_implementation"}},
    )


def import_rules(
    commit: str,
    *,
    output_root: Path | None = None,
    repo_path: Path | None = None,
) -> list[ImportedRule]:
    """Import MITRE CAR analytics at ``commit`` and write them to disk.

    Args:
        commit: full SHA of the upstream commit to import from.
        output_root: where to write converted rules. Defaults to
            ``detections/car-imports``.
        repo_path: where to clone/find the CAR repo. Defaults to
            ``.import-cache/mitre-car``.
    """
    output_root = output_root or REPO_ROOT / "detections" / "car-imports"
    repo_path = repo_path or IMPORT_CACHE / "mitre-car"

    ensure_repo(CAR_REPO_URL, repo_path, commit)

    rules: list[ImportedRule] = []
    seen_ids: set[str] = set()

    scan_root = repo_path / CAR_ANALYTICS_DIR
    if not scan_root.exists():
        logger.warning("CAR analytics dir missing: %s", scan_root)
        return rules

    for path in sorted(scan_root.glob("*.yaml")):
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
        "CAR importer: wrote %d rules to %s (commit %s)",
        len(rules),
        output_root.relative_to(REPO_ROOT),
        short_sha(commit),
    )
    return rules


__all__ = ["import_rules", "CAR_REPO_URL", "CAR_LICENSE"]
