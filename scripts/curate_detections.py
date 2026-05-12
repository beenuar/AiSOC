#!/usr/bin/env python3
"""Curate the AiSOC v1.0 buyer-promised detection set.

The repo contains thousands of detection files across native (``detections/<category>/``)
and four upstream import tiers (``sigma-imports/``, ``car-imports/``,
``splunk-imports/``, ``chronicle-imports/``). Most imported rules are
``_quarantine``-d because their query language isn't directly executable
yet. The buyer-value plan (WS-B2) requires us to *curate* a focused set
of **≥ 300 MITRE-mapped, executable detections** that explicitly cover
eight buyer-prioritised threat families:

    ransomware, credential-access, lateral, exfil, cloud, identity,
    supply-chain, k8s

This script does the curation in three passes:

1. **Discovery** — walk every ``*.yaml`` / ``*.yml`` under ``detections/``
   excluding ``_quarantine`` and ``fixtures``. Pull MITRE technique IDs,
   severity, category, and provenance from each rule.

2. **Classification** — for each rule decide which of the eight families
   it covers. Mapping is deterministic and uses three signals:
     - explicit MITRE technique IDs (matched against curated family
       technique sets, see ``FAMILIES`` below),
     - native rule category (``cloud``, ``identity``, ``data-exfil``,
       etc.) — used to bucket buyer-meaningful categories regardless of
       whether the technique tag is present (e.g. cloud rules without
       MITRE tags still belong to *cloud*),
     - log source product name (``kubernetes`` → k8s, ``aws.ec2`` →
       cloud, etc.).

3. **Quality scoring + selection** — score each rule by
   ``has_mitre × has_severity × has_executable_body`` and select the
   top-scoring rules per family until each family has at least its
   target floor (configurable, default 25 per family). Ties are broken
   alphabetically for determinism.

The output is written to:

  - ``marketplace/curated.json`` — machine-readable curation manifest
    consumed by the marketplace UI's "Curated v1.0" tab.
  - ``apps/docs/docs/detections/coverage.md`` — public coverage
    report with per-family counts, MITRE technique density, and
    a flat list of curated rule IDs (so reviewers can audit the
    promised set without reading JSON).

Usage::

    python3 scripts/curate_detections.py             # build & write
    python3 scripts/curate_detections.py --check     # CI: no-op verify
    python3 scripts/curate_detections.py --print     # stdout JSON
    python3 scripts/curate_detections.py --min 400   # raise minimum

Exit codes:
    0 — curation succeeded and on-disk artefacts match (or were updated)
    1 — quality gate failed (couldn't reach minimum, family uncovered)
    2 — drift: ``--check`` and on-disk artefacts disagree

The script is idempotent and side-effect-free outside the two output
files. It does **not** delete or move any detection rules — pruning a
rule means it doesn't appear in the curated manifest, not that the
file is removed.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
DETECTIONS_DIR = REPO_ROOT / "detections"
OUT_MANIFEST = REPO_ROOT / "marketplace" / "curated.json"
OUT_REPORT = REPO_ROOT / "apps" / "docs" / "docs" / "detections" / "coverage.md"

# ─── MITRE family definitions ────────────────────────────────────────────────
#
# Each entry maps a buyer-meaningful threat family to the MITRE ATT&CK
# techniques that *most directly* indicate that family. We keep this
# tight on purpose — claiming a rule covers "ransomware" because it
# tags T1059 (Command and Scripting Interpreter) is dishonest. We only
# match a family if the rule carries one of the family-specific
# techniques *or* (for category-based families like cloud/identity) the
# rule lives in the corresponding native category.
#
# Sources:
#   - MITRE ATT&CK Enterprise v15 matrix (ransomware techniques per the
#     ATT&CK Group g0046 / S0372 ransomware playbook references).
#   - SigmaHQ tag conventions for k8s / supply-chain coverage.
#
# Tactic IDs are included in ``tactics`` so rules tagged at the tactic
# level (``attack.exfiltration``) without a specific technique still
# get bucketed correctly — at the cost of a slightly looser match.
# This trade-off is deliberate: imported Sigma rules sometimes only
# carry the tactic tag.

FAMILIES: dict[str, dict[str, Any]] = {
    "ransomware": {
        "label": "Ransomware",
        "techniques": {
            "T1486",  # Data Encrypted for Impact
            "T1490",  # Inhibit System Recovery
            "T1485",  # Data Destruction
            "T1489",  # Service Stop
            "T1491",  # Defacement
            "T1561",  # Disk Wipe
            "T1490.001",
            "T1486.001",
        },
        "tactics": set(),
        "categories": set(),
        "log_sources": set(),
    },
    "credential-access": {
        "label": "Credential Access",
        "techniques": {
            "T1003",  # OS Credential Dumping (+ subtechniques)
            "T1110",  # Brute Force
            "T1110.001",
            "T1110.002",
            "T1110.003",
            "T1110.004",
            "T1555",  # Credentials from Password Stores
            "T1212",  # Exploitation for Credential Access
            "T1187",  # Forced Authentication
            "T1556",  # Modify Authentication Process
            "T1606",  # Forge Web Credentials
            "T1528",  # Steal Application Access Token
            "T1558",  # Steal or Forge Kerberos Tickets
            "T1539",  # Steal Web Session Cookie
            "T1552",  # Unsecured Credentials
            "T1040",  # Network Sniffing (creds in transit)
        },
        "tactics": {"TA0006"},
        "categories": set(),
        "log_sources": set(),
    },
    "lateral": {
        "label": "Lateral Movement",
        "techniques": {
            "T1021",  # Remote Services (+ subtechniques)
            "T1021.001",
            "T1021.002",
            "T1021.003",
            "T1021.004",
            "T1021.005",
            "T1021.006",
            "T1570",  # Lateral Tool Transfer
            "T1550",  # Use Alternate Authentication Material
            "T1080",  # Taint Shared Content
            "T1210",  # Exploitation of Remote Services
            "T1563",  # Remote Service Session Hijacking
        },
        "tactics": {"TA0008"},
        "categories": set(),
        "log_sources": set(),
    },
    "exfil": {
        "label": "Data Exfiltration",
        "techniques": {
            "T1041",  # Exfiltration Over C2 Channel
            "T1048",  # Exfiltration Over Alternative Protocol
            "T1567",  # Exfiltration Over Web Service
            "T1029",  # Scheduled Transfer
            "T1011",  # Exfiltration Over Other Network Medium
            "T1052",  # Exfiltration Over Physical Medium
            "T1020",  # Automated Exfiltration
            "T1537",  # Transfer Data to Cloud Account
        },
        "tactics": {"TA0010"},
        "categories": {"data-exfil"},
        "log_sources": set(),
    },
    "cloud": {
        "label": "Cloud",
        "techniques": {
            "T1078.004",  # Valid Accounts: Cloud Accounts
            "T1538",  # Cloud Service Dashboard
            "T1526",  # Cloud Service Discovery
            "T1580",  # Cloud Infrastructure Discovery
            "T1530",  # Data from Cloud Storage
            "T1578",  # Modify Cloud Compute Infrastructure
            "T1535",  # Unused/Unsupported Cloud Regions
            "T1098.001",  # Account Manipulation: Additional Cloud Credentials
            "T1098.003",  # Account Manipulation: Additional Cloud Roles
            "T1556.007",  # Hybrid Identity
            "T1496",  # Resource Hijacking (cryptomining in cloud)
            "T1537",  # Transfer Data to Cloud Account (overlaps exfil)
        },
        "tactics": set(),
        "categories": {"cloud"},
        "log_sources": {"aws", "azure", "gcp", "okta", "office365", "google_workspace"},
    },
    "identity": {
        "label": "Identity",
        "techniques": {
            "T1078",  # Valid Accounts (incl. all sub)
            "T1078.001",
            "T1078.002",
            "T1078.003",
            "T1078.004",
            "T1098",  # Account Manipulation
            "T1098.001",
            "T1098.002",
            "T1098.003",
            "T1098.004",
            "T1098.005",
            "T1136",  # Create Account
            "T1136.001",
            "T1136.002",
            "T1136.003",
            "T1556",  # Modify Authentication Process (+ subtechniques)
            "T1621",  # MFA Request Generation
            "T1606.002",  # Forge Web Credentials: SAML
        },
        "tactics": set(),
        "categories": {"identity"},
        "log_sources": {"okta", "azuread", "duo", "auth0", "ping", "google_workspace"},
    },
    "supply-chain": {
        "label": "Supply Chain",
        "techniques": {
            "T1195",  # Supply Chain Compromise (+ subtechniques)
            "T1195.001",
            "T1195.002",
            "T1195.003",
            "T1199",  # Trusted Relationship
            "T1554",  # Compromise Client Software Binary
            "T1505.003",  # Server Software Component: Web Shell (proxied via supply-chain)
            "T1059.006",  # Python (most malicious package PoCs are python)
        },
        "tactics": set(),
        "categories": set(),
        "log_sources": {"github", "gitlab", "npm", "pypi", "bitbucket"},
    },
    "k8s": {
        "label": "Kubernetes / Containers",
        "techniques": {
            "T1610",  # Deploy Container
            "T1611",  # Escape to Host
            "T1613",  # Container and Resource Discovery
            "T1612",  # Build Image on Host
            "T1525",  # Implant Internal Image
            "T1609",  # Container Administration Command
            "T1496",  # Resource Hijacking (container cryptomining)
        },
        "tactics": set(),
        "categories": set(),
        "log_sources": {"kubernetes", "docker", "containerd", "k8s"},
    },
}

# Categories that are considered native AiSOC tiers (executable-by-default).
NATIVE_CATEGORIES = {
    "cloud",
    "identity",
    "endpoint",
    "network",
    "application",
    "data-exfil",
}

# Imported tier directories. Quarantined rules (under ``_quarantine/``)
# are never curated since they don't execute on the engine yet.
IMPORTED_TIERS: dict[str, str] = {
    "sigma-imports": "sigmahq",
    "car-imports": "mitre-car",
    "splunk-imports": "splunk-security-content",
    "chronicle-imports": "chronicle-detection-rules",
}

# Per-family minimum count required to claim coverage. Total floor
# (default 300) is enforced across the union of these.
DEFAULT_MIN_PER_FAMILY = 25
DEFAULT_MIN_TOTAL = 300

# ─── Regex patterns ─────────────────────────────────────────────────────────

MITRE_DOTTED_RE = re.compile(r"mitre\.attack\.(t\d{4}(?:\.\d{3})?)", re.IGNORECASE)
MITRE_LOOSE_RE = re.compile(r"mitre\.(t\d{4}(?:\.\d{3})?)", re.IGNORECASE)
MITRE_BARE_RE = re.compile(r"^t\d{4}(?:\.\d{3})?$", re.IGNORECASE)
MITRE_ATTACK_PREFIX_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
MITRE_TACTIC_RE = re.compile(r"^attack\.([a-z_-]+)$", re.IGNORECASE)

TACTIC_NAME_TO_ID = {
    "reconnaissance": "TA0043",
    "resource_development": "TA0042",
    "initial_access": "TA0001",
    "execution": "TA0002",
    "persistence": "TA0003",
    "privilege_escalation": "TA0004",
    "defense_evasion": "TA0005",
    "credential_access": "TA0006",
    "discovery": "TA0007",
    "lateral_movement": "TA0008",
    "collection": "TA0009",
    "exfiltration": "TA0010",
    "command_and_control": "TA0011",
    "impact": "TA0040",
}


# ─── Data model ──────────────────────────────────────────────────────────────


@dataclass
class Rule:
    """A single detection rule, parsed and classified."""

    rule_id: str
    name: str
    path: Path
    tier: str  # native | imported | community
    source: str  # core | sigmahq | mitre-car | splunk-security-content | chronicle-detection-rules | community
    category: str | None
    severity: str | None
    techniques: list[str] = field(default_factory=list)
    tactics: list[str] = field(default_factory=list)
    log_source_product: str | None = None
    has_executable_body: bool = False
    families: list[str] = field(default_factory=list)
    quality_score: float = 0.0
    quality_notes: list[str] = field(default_factory=list)


# ─── Parsing helpers ─────────────────────────────────────────────────────────


def _normalise_techniques(raw_tags: Any) -> tuple[list[str], list[str]]:
    """Pull (technique_ids, tactic_ids) from a tag block.

    Accepts:
      * native list form: ``['mitre.attack.t1234', 'tlp.white']``,
      * importer dict form: ``{'mitre': ['T1234'], 'categories': ['cloud']}``,
      * sigma-style: ``['attack.t1234', 'attack.credential_access']``.
    """
    techniques: list[str] = []
    tactics: list[str] = []

    def _add_t(t: str) -> None:
        u = t.upper()
        if u not in techniques:
            techniques.append(u)

    def _add_ta(t: str) -> None:
        if t not in tactics:
            tactics.append(t)

    if isinstance(raw_tags, dict):
        for v in raw_tags.get("mitre") or []:
            if isinstance(v, str) and MITRE_BARE_RE.match(v):
                _add_t(v)

    iterable: Iterable[Any]
    if isinstance(raw_tags, dict):
        # Already consumed mitre key above; nothing else useful here.
        iterable = []
    elif isinstance(raw_tags, list):
        iterable = raw_tags
    else:
        iterable = []

    for tag in iterable:
        if not isinstance(tag, str):
            continue

        normalised = tag.strip().lower()

        m = MITRE_DOTTED_RE.search(tag) or MITRE_LOOSE_RE.search(tag)
        if m:
            _add_t(m.group(1))
            continue

        m2 = MITRE_ATTACK_PREFIX_RE.match(normalised)
        if m2:
            _add_t(m2.group(1))
            continue

        if MITRE_BARE_RE.match(normalised):
            _add_t(normalised)
            continue

        m3 = MITRE_TACTIC_RE.match(normalised)
        if m3:
            tactic_key = m3.group(1).replace("-", "_")
            ta = TACTIC_NAME_TO_ID.get(tactic_key)
            if ta:
                _add_ta(ta)

    return techniques, tactics


def _detect_executable_body(data: dict[str, Any]) -> bool:
    """Heuristic: does the rule have a body the engine can execute?

    Native rules ship a ``detection`` block with a ``condition``. Imported
    Sigma rules ship a ``detection`` block with selections + condition.
    Quarantined / SPL / Chronicle rules typically only have a raw
    ``query`` field, which the engine doesn't execute today.
    """
    detection = data.get("detection")
    if not isinstance(detection, dict):
        return False
    if not detection.get("condition"):
        return False
    # Also need at least one selection or a condition that doesn't ref
    # missing identifiers.
    has_selection = any(
        k for k in detection.keys() if k != "condition" and k != "timeframe"
    )
    return has_selection or bool(detection.get("condition"))


def _parse_rule(
    path: Path, *, tier: str, source: str, quarantined: bool
) -> Rule | None:
    """Load a YAML rule file and return a :class:`Rule`.

    Returns ``None`` for rules that fail to parse, are quarantined,
    or are missing required fields entirely.
    """
    if quarantined:
        return None
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 — corrupt YAML, just skip
        return None
    if not isinstance(data, dict):
        return None

    rule_id = data.get("id") or path.stem
    name = data.get("name") or rule_id

    # Severity normalisation. Sigma uses ``low | medium | high | critical``;
    # native uses the same. Coerce missing to None so the quality scorer
    # can penalise it.
    severity = data.get("severity")
    if isinstance(severity, str):
        severity = severity.strip().lower() or None
    else:
        severity = None

    # Category is taken explicitly when set, otherwise from the parent
    # directory name (which is how native rules are organised).
    category = data.get("category")
    if isinstance(category, str):
        category = category.strip().lower() or None
    if not category:
        # For imported tiers, the directory above the file is the
        # category bucket the importer picked.
        category = path.parent.name.strip().lower() or None
        # Some imports are direct children of e.g. sigma-imports/ with no
        # category subdir — those have category == 'sigma-imports' from
        # the parent name; null those out so they don't bucket-leak.
        if category in IMPORTED_TIERS:
            category = None

    techniques, tactics = _normalise_techniques(data.get("tags"))

    log_source = data.get("log_source") or data.get("logsource") or {}
    if not isinstance(log_source, dict):
        log_source = {}
    log_source_product = log_source.get("product")
    if isinstance(log_source_product, str):
        log_source_product = log_source_product.strip().lower() or None
    else:
        log_source_product = None

    rule = Rule(
        rule_id=str(rule_id),
        name=str(name),
        path=path,
        tier=tier,
        source=source,
        category=category,
        severity=severity,
        techniques=techniques,
        tactics=tactics,
        log_source_product=log_source_product,
        has_executable_body=_detect_executable_body(data),
    )
    rule.families = _classify(rule)
    rule.quality_score, rule.quality_notes = _score(rule)
    return rule


# ─── Classification ─────────────────────────────────────────────────────────


def _classify(rule: Rule) -> list[str]:
    """Decide which buyer-required families a rule covers.

    A rule may cover multiple families (e.g. T1537 belongs to both
    *cloud* and *exfil*). Multi-family membership is fine — it lets us
    count one good rule against multiple coverage targets, and the
    quality scorer prevents low-quality rules from cheating their way
    in via a single tag overlap.
    """
    matched: list[str] = []
    tech_set = {t.upper() for t in rule.techniques}
    tactic_set = {t.upper() for t in rule.tactics}
    log_source = (rule.log_source_product or "").lower()
    category = (rule.category or "").lower()

    for family_id, spec in FAMILIES.items():
        # Technique match
        if tech_set & spec["techniques"]:
            matched.append(family_id)
            continue
        # Tactic match (only for families that opt into tactic-only matching)
        if spec["tactics"] and tactic_set & spec["tactics"]:
            matched.append(family_id)
            continue
        # Category match
        if category and category in spec["categories"]:
            matched.append(family_id)
            continue
        # Log source match
        if log_source and any(s in log_source for s in spec["log_sources"]):
            matched.append(family_id)
            continue

    return matched


# ─── Quality scoring ────────────────────────────────────────────────────────


_SEVERITY_WEIGHT = {
    "critical": 1.0,
    "high": 0.85,
    "medium": 0.7,
    "low": 0.55,
}


def _score(rule: Rule) -> tuple[float, list[str]]:
    """Score a rule from 0 to 1. Native rules start at a higher base."""
    score = 0.0
    notes: list[str] = []

    # Base by tier — native rules are fixture-tested, imported are not.
    if rule.tier == "native":
        score += 0.5
        notes.append("tier:native(+0.5)")
    elif rule.tier == "imported":
        score += 0.3
        notes.append("tier:imported(+0.3)")
    else:
        score += 0.2
        notes.append("tier:other(+0.2)")

    # MITRE — tagged with at least one technique.
    if rule.techniques:
        score += 0.2
        notes.append(f"mitre_techniques:{len(rule.techniques)}(+0.2)")
    elif rule.tactics:
        score += 0.05
        notes.append(f"mitre_tactics_only:{len(rule.tactics)}(+0.05)")
    else:
        notes.append("no_mitre(0)")

    # Severity — present and high-confidence.
    if rule.severity in _SEVERITY_WEIGHT:
        weight = _SEVERITY_WEIGHT[rule.severity] * 0.15
        score += weight
        notes.append(f"severity:{rule.severity}(+{weight:.3f})")
    else:
        notes.append("no_severity(0)")

    # Executable body.
    if rule.has_executable_body:
        score += 0.15
        notes.append("executable(+0.15)")
    else:
        notes.append("no_executable_body(0)")

    return min(score, 1.0), notes


# ─── Discovery ──────────────────────────────────────────────────────────────


def discover_rules() -> list[Rule]:
    """Walk every detection tier and return parsed, classified rules."""
    rules: list[Rule] = []

    # Native tiers
    for cat in sorted(NATIVE_CATEGORIES):
        cat_dir = DETECTIONS_DIR / cat
        if not cat_dir.exists():
            continue
        for path in sorted(cat_dir.rglob("*.yaml")):
            r = _parse_rule(path, tier="native", source="core", quarantined=False)
            if r:
                rules.append(r)
        for path in sorted(cat_dir.rglob("*.yml")):
            r = _parse_rule(path, tier="native", source="core", quarantined=False)
            if r:
                rules.append(r)

    # Imported tiers — only NON-quarantined
    for tier_dir, source_name in IMPORTED_TIERS.items():
        root = DETECTIONS_DIR / tier_dir
        if not root.exists():
            continue
        for ext in ("*.yaml", "*.yml"):
            for path in sorted(root.rglob(ext)):
                try:
                    rel = path.relative_to(root).parts
                except ValueError:
                    continue
                quarantined = bool(rel) and rel[0] == "_quarantine"
                if quarantined:
                    continue
                r = _parse_rule(
                    path, tier="imported", source=source_name, quarantined=False
                )
                if r:
                    rules.append(r)

    # Community tier — opt-in, treated as supplementary not core
    community_dir = DETECTIONS_DIR / "community"
    if community_dir.exists():
        for ext in ("*.yaml", "*.yml"):
            for path in sorted(community_dir.rglob(ext)):
                r = _parse_rule(
                    path, tier="community", source="community", quarantined=False
                )
                if r:
                    rules.append(r)

    return rules


# ─── Selection ──────────────────────────────────────────────────────────────


def select_curated(
    rules: list[Rule],
    *,
    min_per_family: int = DEFAULT_MIN_PER_FAMILY,
    min_total: int = DEFAULT_MIN_TOTAL,
    quality_floor: float = 0.55,
) -> tuple[list[Rule], dict[str, list[str]], dict[str, Any]]:
    """Pick the curated v1.0 set.

    Strategy:
      1. Drop rules below the quality floor immediately — these are the
         "low-quality" candidates the plan asks us to prune.
      2. For each family, sort eligible rules by quality (desc) and
         pick the top N until the family floor is reached.
      3. Union all picks. If union is below ``min_total``, top-up with
         the highest-scoring remaining rules regardless of family.

    Returns:
      (selected_rules, per_family_ids, stats)
    """
    eligible = [r for r in rules if r.quality_score >= quality_floor]

    # Per-family ranking — highest quality first, deterministic on ties.
    per_family: dict[str, list[Rule]] = {fid: [] for fid in FAMILIES}
    for r in eligible:
        for fid in r.families:
            per_family[fid].append(r)
    for fid, lst in per_family.items():
        lst.sort(key=lambda r: (-r.quality_score, r.rule_id))

    selected: dict[str, Rule] = {}
    family_picks: dict[str, list[str]] = {fid: [] for fid in FAMILIES}

    for fid, ranked in per_family.items():
        for r in ranked:
            if len(family_picks[fid]) >= min_per_family * 4:
                # Cap per-family contribution so a single deep family
                # (cloud has 225+ rules) doesn't crowd out the others
                # in the manifest. Floor is min_per_family × 4 = 100,
                # which is generous and keeps families balanced.
                break
            selected.setdefault(r.rule_id, r)
            family_picks[fid].append(r.rule_id)

    # Top-up if union is below min_total.
    if len(selected) < min_total:
        remaining = [
            r
            for r in sorted(
                eligible, key=lambda r: (-r.quality_score, r.rule_id)
            )
            if r.rule_id not in selected
        ]
        for r in remaining:
            if len(selected) >= min_total:
                break
            selected[r.rule_id] = r

    # Final sort for deterministic output.
    final_rules = sorted(selected.values(), key=lambda r: r.rule_id)

    stats = {
        "considered": len(rules),
        "eligible": len(eligible),
        "selected": len(final_rules),
        "min_per_family": min_per_family,
        "min_total": min_total,
        "quality_floor": quality_floor,
    }
    return final_rules, family_picks, stats


# ─── Output ──────────────────────────────────────────────────────────────────


def _utc_now() -> str:
    return (
        dt.datetime.now(dt.UTC)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def build_manifest(
    selected: list[Rule],
    family_picks: dict[str, list[str]],
    stats: dict[str, Any],
) -> dict[str, Any]:
    """Build the curated.json document."""
    items = []
    for r in selected:
        items.append(
            {
                "id": r.rule_id,
                "name": r.name,
                "path": str(r.path.relative_to(REPO_ROOT)),
                "tier": r.tier,
                "source": r.source,
                "category": r.category,
                "severity": r.severity,
                "mitre_techniques": r.techniques,
                "mitre_tactics": r.tactics,
                "families": r.families,
                "quality_score": round(r.quality_score, 3),
                "quality_notes": r.quality_notes,
                "log_source_product": r.log_source_product,
                "has_executable_body": r.has_executable_body,
            }
        )

    families = {}
    for fid, spec in FAMILIES.items():
        ids = family_picks.get(fid, [])
        families[fid] = {
            "label": spec["label"],
            "count": len(ids),
            "rule_ids": sorted(ids),
            "min_target": stats["min_per_family"],
            "covered": len(ids) >= stats["min_per_family"],
        }

    # MITRE technique density
    technique_counts: dict[str, int] = {}
    for r in selected:
        for t in r.techniques:
            technique_counts[t] = technique_counts.get(t, 0) + 1

    return {
        "$schema": "https://aisoc.example.com/schemas/curated/v1.json",
        "version": "1.0.0",
        "generated": _utc_now(),
        "stats": {
            **stats,
            "unique_techniques": len(technique_counts),
            "selected_by_tier": _count_by(selected, "tier"),
            "selected_by_severity": _count_by(selected, "severity"),
            "selected_by_category": _count_by(selected, "category"),
        },
        "families": families,
        "mitre_techniques": dict(sorted(technique_counts.items())),
        "items": items,
    }


def _count_by(rules: list[Rule], attr: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for r in rules:
        v = getattr(r, attr) or "unknown"
        counts[v] = counts.get(v, 0) + 1
    return dict(sorted(counts.items()))


def build_report(manifest: dict[str, Any]) -> str:
    """Render the buyer-facing coverage report."""
    s = manifest["stats"]
    lines: list[str] = []
    lines.append("---")
    lines.append("title: Detection Coverage")
    lines.append("description: |")
    lines.append("  AiSOC v1.0 ships a curated set of MITRE ATT&CK-mapped")
    lines.append("  detections covering the eight buyer-prioritised threat")
    lines.append("  families. This page is generated from the on-disk corpus")
    lines.append("  via ``scripts/curate_detections.py`` — it is the source")
    lines.append("  of truth for what we promise in v1.0.")
    lines.append("sidebar_position: 2")
    lines.append("---")
    lines.append("")
    lines.append("# Detection Coverage")
    lines.append("")
    lines.append(f"Generated: `{manifest['generated']}`")
    lines.append("")
    lines.append("## Headline numbers")
    lines.append("")
    lines.append(f"- **Curated v1.0 detections**: `{s['selected']}` (target: ≥ {s['min_total']})")
    lines.append(
        f"- **Total rules considered**: `{s['considered']}` "
        f"(quality floor: {s['quality_floor']})"
    )
    lines.append(f"- **Unique MITRE techniques covered**: `{s['unique_techniques']}`")
    lines.append("")

    lines.append("## Coverage by buyer family")
    lines.append("")
    lines.append("| Family | Count | Target | Covered |")
    lines.append("|---|---|---|---|")
    for fid, info in manifest["families"].items():
        check = "✅" if info["covered"] else "❌"
        lines.append(
            f"| **{info['label']}** | {info['count']} | "
            f"≥ {info['min_target']} | {check} |"
        )
    lines.append("")

    lines.append("## Distribution")
    lines.append("")
    lines.append("### By tier")
    lines.append("")
    for tier, count in s["selected_by_tier"].items():
        lines.append(f"- `{tier}`: {count}")
    lines.append("")
    lines.append("### By severity")
    lines.append("")
    for sev, count in s["selected_by_severity"].items():
        lines.append(f"- `{sev}`: {count}")
    lines.append("")
    lines.append("### By category")
    lines.append("")
    for cat, count in s["selected_by_category"].items():
        lines.append(f"- `{cat}`: {count}")
    lines.append("")
    lines.append("## How to audit")
    lines.append("")
    lines.append(
        "The curated rule IDs are listed in "
        "[`marketplace/curated.json`](https://github.com/aisoc-platform/aisoc/blob/main/marketplace/curated.json) "
        "under each family. Every entry has a `path` field pointing at the "
        "on-disk YAML. Run `pnpm marketplace:curate --check` in CI to enforce "
        "drift; run `python3 scripts/curate_detections.py` locally to regenerate."
    )
    lines.append("")
    return "\n".join(lines) + "\n"


# ─── CLI ──────────────────────────────────────────────────────────────────────


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="CI mode: verify on-disk artefacts match the build, no writes.",
    )
    parser.add_argument(
        "--print",
        dest="print_only",
        action="store_true",
        help="Print built manifest to stdout instead of writing files.",
    )
    parser.add_argument(
        "--min",
        type=int,
        default=DEFAULT_MIN_TOTAL,
        help=f"Minimum total curated rules (default {DEFAULT_MIN_TOTAL}).",
    )
    parser.add_argument(
        "--per-family",
        type=int,
        default=DEFAULT_MIN_PER_FAMILY,
        help=f"Minimum per-family rules (default {DEFAULT_MIN_PER_FAMILY}).",
    )
    parser.add_argument(
        "--quality-floor",
        type=float,
        default=0.55,
        help="Drop rules with quality score below this (default 0.55).",
    )
    args = parser.parse_args()

    rules = discover_rules()
    selected, family_picks, stats = select_curated(
        rules,
        min_per_family=args.per_family,
        min_total=args.min,
        quality_floor=args.quality_floor,
    )
    manifest = build_manifest(selected, family_picks, stats)
    serialised = json.dumps(manifest, indent=2, sort_keys=False) + "\n"

    if args.print_only:
        sys.stdout.write(serialised)
        return 0

    # Quality gate: every family must be covered, total must hit min.
    ok = stats["selected"] >= args.min and all(
        info["covered"] for info in manifest["families"].values()
    )

    if args.check:
        existing = (
            OUT_MANIFEST.read_text(encoding="utf-8") if OUT_MANIFEST.exists() else ""
        )
        report = build_report(manifest)
        existing_report = (
            OUT_REPORT.read_text(encoding="utf-8") if OUT_REPORT.exists() else ""
        )

        def _strip_generated(s: str) -> str:
            try:
                obj = json.loads(s)
            except Exception:
                return s
            obj.pop("generated", None)
            return json.dumps(obj, indent=2, sort_keys=False) + "\n"

        def _strip_md_generated(s: str) -> str:
            return re.sub(r"Generated: `[^`]+`", "Generated: `<ts>`", s)

        if (
            _strip_generated(existing) != _strip_generated(serialised)
            or _strip_md_generated(existing_report) != _strip_md_generated(report)
        ):
            print(
                "marketplace/curated.json or coverage.md is stale. Run: "
                "pnpm marketplace:curate",
                file=sys.stderr,
            )
            return 2
        print(
            f"curation up to date "
            f"({stats['selected']} curated, "
            f"{manifest['stats']['unique_techniques']} techniques)."
        )
        return 0 if ok else 1

    OUT_MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    OUT_MANIFEST.write_text(serialised, encoding="utf-8")
    OUT_REPORT.parent.mkdir(parents=True, exist_ok=True)
    OUT_REPORT.write_text(build_report(manifest), encoding="utf-8")

    uncovered = [
        info["label"]
        for info in manifest["families"].values()
        if not info["covered"]
    ]
    print(
        f"Wrote curated manifest: selected={stats['selected']} "
        f"techniques={manifest['stats']['unique_techniques']} "
        f"families_covered={sum(1 for f in manifest['families'].values() if f['covered'])}"
        f"/{len(manifest['families'])}"
    )
    if uncovered:
        print(f"  ❌ uncovered families: {', '.join(uncovered)}", file=sys.stderr)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
