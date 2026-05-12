#!/usr/bin/env python3
"""
AiSOC Detection Rule Validator
================================
Validates all YAML detection rules under ``detections/`` for:

  - Valid YAML syntax
  - Required fields (``id``, ``name``, ``severity``, ``detection``)
  - Severity is one of: ``low | medium | high | critical``
  - Category is one of:
    ``network | endpoint | cloud | identity | application | data-exfil``
  - No duplicate ``id`` values across all tiers
  - ``id`` prefix matches the rule's tier (``det-`` for native,
    ``<source>-...`` for imported tiers)
  - For native rules: matching positive + negative fixtures under
    ``detections/fixtures/`` and successful fixture replay against the
    canonical ``match_when`` spec
  - For imported rules: a populated ``provenance`` block with the required
    fields documented in ``tools/detection_import/README.md``

Tiering
-------
* **native** — ``detections/{network,endpoint,cloud,identity,application,
  data-exfil}/*.yaml``. Strict: fixtures + provenance optional.
* **imported** — ``detections/{sigma,car,splunk,chronicle}-imports/<category>
  /*.yaml`` (and ``.../_quarantine/<category>/*.yaml`` for rules that
  parsed but cannot run as-is). Provenance required, fixtures optional.
* **community** — ``detections/community/<category>/*.yaml``. Permissive;
  provenance encouraged but not required.

Exit codes
----------
* ``0`` — all rules valid
* ``1`` — one or more validation errors

Run ``python3 scripts/validate_detections.py --strict-fixtures`` to promote
fixture warnings into hard failures (used by CI for native rules).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML not installed. Run: pip install pyyaml")
    sys.exit(1)

ROOT = Path(__file__).parent.parent
DETECTIONS_DIR = ROOT / "detections"
FIXTURES_DIR = DETECTIONS_DIR / "fixtures"
SCRIPTS_DIR = ROOT / "scripts"

if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from detection_specs_index import all_specs  # noqa: E402
from generate_detections import matches  # noqa: E402

VALID_SEVERITIES = {"low", "medium", "high", "critical"}
VALID_CATEGORIES = {
    "network",
    "endpoint",
    "cloud",
    "identity",
    "application",
    "data-exfil",
}

REQUIRED_FIELDS = ["id", "name", "severity", "detection"]

# Provenance fields required on every imported rule. License and
# license_url should be present so we can prove the redistribution chain;
# imported_by is the importer module so future audits can grep for the
# tool that produced the file.
REQUIRED_PROVENANCE_FIELDS = (
    "source",
    "source_id",
    "source_commit",
    "license",
    "imported_at",
    "imported_by",
    "upstream_path",
)

# Each imported tier directory maps to (display name, expected id prefix).
# The id prefix matches what ``tools.detection_import.common.stable_id``
# produces for that tier. Bumping importer source names? Update these too.
IMPORTED_TIERS: dict[str, dict[str, str]] = {
    "sigma-imports": {
        "name": "sigmahq",
        "id_prefix": "sigmahq-sigma-",
    },
    "car-imports": {
        "name": "mitre-car",
        "id_prefix": "mitre-car-",
    },
    "splunk-imports": {
        "name": "splunk-security-content",
        "id_prefix": "splunk-security-content-",
    },
    "chronicle-imports": {
        "name": "chronicle-detection-rules",
        "id_prefix": "chronicle-detection-rules-",
    },
}


# =============================================================================
# Spec lookup — for native fixture replay only.
# =============================================================================

_SPEC_BY_KEY: dict[tuple[str, str], dict[str, Any]] = {
    (cat, spec["slug"]): spec for cat, spec in all_specs()
}


# =============================================================================
# Tier classification
# =============================================================================


def classify(path: Path) -> dict[str, Any]:
    """Classify a rule file by tier from its on-disk path.

    Returns a dict with keys:

    * ``tier`` — ``"native" | "imported" | "community" | "unknown"``
    * ``source`` — short source name for imported rules, else ``None``
    * ``id_prefix`` — required id prefix for the tier, else ``None``
    * ``category`` — the AiSOC category this rule belongs to (e.g.
      ``cloud``), inferred from the directory layout
    * ``is_quarantined`` — true if the rule lives under ``_quarantine/``
    """
    try:
        rel_parts = path.relative_to(DETECTIONS_DIR).parts
    except ValueError:
        return {
            "tier": "unknown",
            "source": None,
            "id_prefix": None,
            "category": None,
            "is_quarantined": False,
        }

    if not rel_parts:
        return {
            "tier": "unknown",
            "source": None,
            "id_prefix": None,
            "category": None,
            "is_quarantined": False,
        }

    head = rel_parts[0]

    # Native: detections/<category>/<rule>.yaml
    if head in VALID_CATEGORIES:
        return {
            "tier": "native",
            "source": None,
            "id_prefix": "det-",
            "category": head,
            "is_quarantined": False,
        }

    # Imported: detections/<source>-imports/[<_quarantine>/]<category>/<rule>.yaml
    if head in IMPORTED_TIERS:
        tier_meta = IMPORTED_TIERS[head]
        is_quarantined = len(rel_parts) >= 2 and rel_parts[1] == "_quarantine"
        if is_quarantined and len(rel_parts) >= 3:
            category = rel_parts[2]
        elif len(rel_parts) >= 2:
            category = rel_parts[1]
        else:
            category = None
        return {
            "tier": "imported",
            "source": tier_meta["name"],
            "id_prefix": tier_meta["id_prefix"],
            "category": category,
            "is_quarantined": is_quarantined,
        }

    if head == "community":
        category = rel_parts[1] if len(rel_parts) >= 2 else None
        return {
            "tier": "community",
            "source": "community",
            "id_prefix": None,
            "category": category,
            "is_quarantined": False,
        }

    return {
        "tier": "unknown",
        "source": None,
        "id_prefix": None,
        "category": None,
        "is_quarantined": False,
    }


# =============================================================================
# Validation
# =============================================================================


def validate_rule(
    path: Path,
    seen_ids: dict[str, Path],
    classification: dict[str, Any],
) -> tuple[list[str], dict[str, Any] | None]:
    """Validate a single detection rule file.

    Returns ``(errors, parsed_rule)``. ``parsed_rule`` is ``None`` if YAML
    parsing failed.
    """
    errors: list[str] = []

    try:
        with open(path) as f:
            rule = yaml.safe_load(f)
    except yaml.YAMLError as exc:
        return [f"YAML parse error: {exc}"], None

    if not isinstance(rule, dict):
        return [
            "Rule is not a YAML mapping (expected key: value pairs at top level)"
        ], None

    for field in REQUIRED_FIELDS:
        if field not in rule:
            errors.append(f"Missing required field: '{field}'")

    if errors:
        return errors, rule

    if rule["severity"] not in VALID_SEVERITIES:
        errors.append(
            f"Invalid severity '{rule['severity']}'; must be one of: "
            f"{', '.join(sorted(VALID_SEVERITIES))}"
        )

    rule_category = rule.get("category")
    if rule_category and rule_category not in VALID_CATEGORIES:
        errors.append(
            f"Invalid category '{rule_category}'; must be one of: "
            f"{', '.join(sorted(VALID_CATEGORIES))}"
        )

    expected_category = classification["category"]
    if (
        rule_category
        and expected_category
        and rule_category != expected_category
    ):
        errors.append(
            f"Rule category '{rule_category}' does not match directory "
            f"'{expected_category}'"
        )

    rule_id = str(rule["id"])
    expected_prefix = classification["id_prefix"]
    if expected_prefix and not rule_id.startswith(expected_prefix):
        errors.append(
            f"Rule id '{rule_id}' must start with '{expected_prefix}' "
            f"(tier: {classification['tier']})"
        )

    if rule_id in seen_ids:
        errors.append(
            f"Duplicate id '{rule_id}' — already defined in "
            f"{seen_ids[rule_id]}"
        )
    else:
        seen_ids[rule_id] = path

    detection = rule.get("detection")
    if not isinstance(detection, dict):
        errors.append(
            "'detection' field must be a YAML mapping with 'condition', "
            "'keywords', or a tier-specific block (e.g. 'splunk_spl', "
            "'chronicle_yaral')"
        )

    if classification["tier"] == "imported":
        errors.extend(_validate_provenance(rule))

    return errors, rule


def _validate_provenance(rule: dict[str, Any]) -> list[str]:
    """Validate the ``provenance`` block on an imported rule."""
    errors: list[str] = []
    provenance = rule.get("provenance")
    if not isinstance(provenance, dict):
        return [
            "Imported rule is missing required 'provenance' block "
            "(see tools/detection_import/README.md)"
        ]
    for field in REQUIRED_PROVENANCE_FIELDS:
        value = provenance.get(field)
        if value in (None, ""):
            errors.append(f"provenance.{field} is required and must be non-empty")
    return errors


def replay_fixture(
    rule_path: Path, rule: dict[str, Any], strict: bool
) -> list[str]:
    """Replay positive + negative fixtures against the canonical spec.

    Native tier only. Looks up the spec for this rule by ``(category,
    slug)``, then evaluates the structured ``match_when`` dict against the
    on-disk fixtures using the same ``matches()`` function the runtime
    engine would use.

    Returns a list of error messages. If ``strict`` is ``False``, missing
    fixtures or missing specs degrade to soft warnings (``WARN: ...``).
    """
    errors: list[str] = []
    slug = rule_path.stem
    category = rule_path.parent.name
    pos_path = FIXTURES_DIR / "positive" / f"{slug}.json"
    neg_path = FIXTURES_DIR / "negative" / f"{slug}.json"

    pos_missing = not pos_path.exists()
    neg_missing = not neg_path.exists()

    if pos_missing or neg_missing:
        msg_parts = []
        if pos_missing:
            msg_parts.append(
                f"missing positive fixture {pos_path.relative_to(ROOT)}"
            )
        if neg_missing:
            msg_parts.append(
                f"missing negative fixture {neg_path.relative_to(ROOT)}"
            )
        msg = "; ".join(msg_parts)
        if strict:
            errors.append(msg)
        else:
            errors.append(f"WARN: {msg}")
        return errors

    spec = _SPEC_BY_KEY.get((category, slug))
    if spec is None:
        msg = (
            f"no canonical spec found for ({category}, {slug}); "
            f"hand-authored rule — fixture replay skipped"
        )
        errors.append(f"WARN: {msg}")
        return errors

    match_when = spec.get("match_when")
    if not match_when:
        return errors

    try:
        with open(pos_path) as f:
            pos_event = json.load(f)
        with open(neg_path) as f:
            neg_event = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"fixture load error: {exc}")
        return errors

    if not matches(match_when, pos_event):
        errors.append(
            "positive fixture did NOT match match_when (expected match)"
        )
    if matches(match_when, neg_event):
        errors.append(
            "negative fixture DID match match_when (expected no match)"
        )
    return errors


def main() -> int:
    strict = "--strict-fixtures" in sys.argv
    if not DETECTIONS_DIR.exists():
        print(f"ERROR: detections/ directory not found at {DETECTIONS_DIR}")
        return 1

    yaml_files = sorted(DETECTIONS_DIR.rglob("*.yaml"))
    if not yaml_files:
        print("WARNING: No .yaml files found under detections/")
        return 0

    seen_ids: dict[str, Path] = {}
    total = 0
    failed = 0
    fixture_warnings = 0
    tier_counts: dict[str, int] = {
        "native": 0,
        "imported": 0,
        "community": 0,
        "unknown": 0,
    }
    quarantine_count = 0

    for path in yaml_files:
        rel = path.relative_to(ROOT)

        # Skip the meta/index files at the top of detections/, e.g.
        # detections/coverage.yaml, that aren't rule files. Those live
        # directly under detections/ with no category dir.
        try:
            rel_under = path.relative_to(DETECTIONS_DIR)
        except ValueError:
            continue
        if len(rel_under.parts) < 2:
            continue
        if rel_under.parts[0] in ("fixtures", "playbooks"):
            continue

        classification = classify(path)
        tier = classification["tier"]
        tier_counts[tier] = tier_counts.get(tier, 0) + 1
        if classification["is_quarantined"]:
            quarantine_count += 1

        total += 1

        errors, rule = validate_rule(path, seen_ids, classification)
        rule_failed = bool(errors)

        replay_errors: list[str] = []
        if (
            rule
            and not rule_failed
            and tier == "native"
            and path.parent.name in VALID_CATEGORIES
        ):
            replay_errors = replay_fixture(path, rule, strict=strict)

        warnings = [e for e in replay_errors if e.startswith("WARN:")]
        hard = [e for e in replay_errors if not e.startswith("WARN:")]
        fixture_warnings += len(warnings)
        if hard:
            rule_failed = True
            errors.extend(hard)

        if rule_failed:
            failed += 1
            print(f"\nFAIL  [{tier}] {rel}")
            for e in errors:
                print(f"    - {e}")
        else:
            warn_suffix = f" ({len(warnings)} warn)" if warnings else ""
            quarantine_suffix = "  [quarantined]" if classification["is_quarantined"] else ""
            print(f"PASS  [{tier}] {rel}{warn_suffix}{quarantine_suffix}")
            for w in warnings:
                print(f"    {w}")

    print(f"\n{'─' * 60}")
    print(
        f"Validated {total} rules — {total - failed} passed, {failed} failed, "
        f"{fixture_warnings} fixture warnings"
    )
    print(
        "  Tiers: "
        + ", ".join(
            f"{tier}={count}"
            for tier, count in sorted(tier_counts.items())
            if count > 0
        )
    )
    if quarantine_count:
        print(f"  Quarantined (parsed-but-disabled): {quarantine_count}")

    return 1 if failed > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
