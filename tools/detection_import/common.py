"""Shared helpers for detection importers.

Every importer in this directory emits AiSOC's internal Sigma-inspired YAML
schema.  The shape we write is::

    id: <slug-id>                  # human-readable, prefixed by source
    name: <upstream title>         # required by validate_detections.py; same field as native rules
    description: <upstream description>
    severity: low | medium | high | critical
    enabled: true | false
    tags:
      mitre:
        - T1078
        - T1078.004
      categories:
        - cloud
    references:
      - https://...
    logsource:
      product: <upstream product>
      service: <upstream service>
      category: <upstream category>
    detection:
      # raw upstream detection block, kept verbatim for round-tripping
      ...
    provenance:
      source: SigmaHQ/sigma
      source_id: <upstream uuid>
      source_commit: <short sha>
      license: DRL-1.1
      license_url: https://...
      imported_at: 2026-05-04
      imported_by: sigma_importer
      upstream_path: rules/cloud/aws/aws_root_login.yml

The native AiSOC schema (``detections/cloud/...`` etc.) uses ``match_when``
blocks tied to ``RawAlert`` fields and is fixture-tested.  Imported rules keep
the upstream ``detection`` block untouched so we can advertise honest
attribution; the engine evaluates them through a Sigma-compat interpreter at
runtime (see ``services/fusion/detection_engine.py``).
"""

from __future__ import annotations

import hashlib
import re
import subprocess
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
IMPORT_CACHE = REPO_ROOT / ".import-cache"

SEVERITY_MAP = {
    "informational": "low",
    "info": "low",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}


@dataclass
class ImportedRule:
    """One imported detection rule.

    Importers return a list of these; the orchestrator writes them to disk.
    """

    rule_id: str
    title: str
    description: str
    severity: str
    enabled: bool
    tags: dict[str, list[str]]
    references: list[str]
    logsource: dict[str, str]
    detection: dict
    provenance: dict
    output_category: str
    output_filename: str
    quarantine_reason: str | None = None
    extra: dict = field(default_factory=dict)

    def to_yaml_dict(self) -> dict:
        """Render to the dict shape that gets dumped to YAML.

        Uses ``name`` (not ``title``) so imported rules match the native
        AiSOC schema and pass ``scripts/validate_detections.py``.  The
        upstream ``title`` is preserved verbatim under that key for human
        readability.
        """
        out: dict = {
            "id": self.rule_id,
            "name": self.title,
            "description": self.description,
            "severity": self.severity,
            "enabled": self.enabled,
            "tags": self.tags,
            "references": self.references,
            "logsource": self.logsource,
            "detection": self.detection,
            "provenance": self.provenance,
        }
        if self.extra:
            out.update(self.extra)
        return out


def slugify(value: str, max_len: int = 80) -> str:
    """Convert an arbitrary string into a kebab-case slug for use in IDs."""
    value = value.lower()
    value = re.sub(r"[^a-z0-9]+", "-", value)
    value = value.strip("-")
    if len(value) > max_len:
        value = value[:max_len].rstrip("-")
    return value or "rule"


def short_sha(sha: str) -> str:
    """Trim a git SHA to its 7-char short form."""
    return sha[:7] if sha else ""


def stable_id(source: str, upstream_id: str) -> str:
    """Build a deterministic AiSOC rule id from a source + upstream id.

    Sigma uses UUIDs which are unfriendly in URLs; CAR uses ``CAR-YYYY-MM-NNN``
    which is fine.  We always prefix with the source name to make
    cross-source collisions impossible.
    """
    if not upstream_id:
        digest = hashlib.sha256(source.encode()).hexdigest()[:8]
        return f"{slugify(source)}-{digest}"
    return f"{slugify(source)}-{slugify(upstream_id)}"


def map_severity(value: str | None) -> str:
    """Coerce upstream severity strings into AiSOC's enum."""
    if not value:
        return "medium"
    return SEVERITY_MAP.get(str(value).strip().lower(), "medium")


def today_iso() -> str:
    return date.today().isoformat()


def ensure_repo(repo_url: str, target: Path, commit: str) -> Path:
    """Clone or fetch ``repo_url`` into ``target`` and check out ``commit``.

    Idempotent — if the directory already exists at the right commit we skip.
    The orchestrator caches under ``.import-cache/`` (gitignored).
    """
    target.parent.mkdir(parents=True, exist_ok=True)

    if not target.exists():
        subprocess.run(
            ["git", "clone", "--quiet", repo_url, str(target)],
            check=True,
        )
    else:
        subprocess.run(
            ["git", "-C", str(target), "fetch", "--quiet", "origin"],
            check=True,
        )

    subprocess.run(
        ["git", "-C", str(target), "checkout", "--quiet", commit],
        check=True,
    )
    return target


def write_rule(rule: ImportedRule, output_root: Path) -> Path:
    """Serialise an ImportedRule to disk under ``output_root/<category>/``.

    Returns the path that was written.
    """
    import yaml  # local import; only the importer pipeline depends on PyYAML

    if rule.quarantine_reason:
        category_dir = output_root / "_quarantine"
    else:
        category_dir = output_root / rule.output_category

    category_dir.mkdir(parents=True, exist_ok=True)
    path = category_dir / rule.output_filename

    payload = rule.to_yaml_dict()
    if rule.quarantine_reason:
        payload["enabled"] = False
        payload.setdefault("notes", {})["quarantine_reason"] = rule.quarantine_reason

    with path.open("w", encoding="utf-8") as fh:
        yaml.safe_dump(payload, fh, sort_keys=False, allow_unicode=True)

    return path


def normalise_categories(category: str) -> str:
    """Map upstream category buckets to AiSOC's six native folders."""
    category = category.strip().lower()
    aliases = {
        "aws": "cloud",
        "azure": "cloud",
        "gcp": "cloud",
        "m365": "cloud",
        "okta": "identity",
        "auth": "identity",
        "authentication": "identity",
        "windows": "endpoint",
        "linux": "endpoint",
        "macos": "endpoint",
        "process_creation": "endpoint",
        "proxy": "network",
        "firewall": "network",
        "dns": "network",
        "webserver": "application",
        "web": "application",
        "exfiltration": "data-exfil",
    }
    if category in aliases:
        return aliases[category]
    if category in {
        "cloud",
        "identity",
        "endpoint",
        "network",
        "application",
        "data-exfil",
    }:
        return category
    return "endpoint"  # safe default for unmapped buckets


__all__ = [
    "REPO_ROOT",
    "IMPORT_CACHE",
    "ImportedRule",
    "ensure_repo",
    "map_severity",
    "normalise_categories",
    "short_sha",
    "slugify",
    "stable_id",
    "today_iso",
    "write_rule",
]
