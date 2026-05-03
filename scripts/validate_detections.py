#!/usr/bin/env python3
"""
AiSOC Detection Rule Validator
================================
Validates all YAML detection rules under detections/ for:
  - Valid YAML syntax
  - Required fields (id, name, severity, detection)
  - Severity is one of: low | medium | high | critical
  - Category is one of: network | endpoint | cloud | identity | application
  - No duplicate `id` values across all rules
  - id prefix matches the category directory

Exit code 0 = all rules valid
Exit code 1 = one or more validation errors
"""

from __future__ import annotations

import sys
import os
from pathlib import Path

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML not installed. Run: pip install pyyaml")
    sys.exit(1)

ROOT = Path(__file__).parent.parent
DETECTIONS_DIR = ROOT / "detections"

VALID_SEVERITIES = {"low", "medium", "high", "critical"}
VALID_CATEGORIES = {"network", "endpoint", "cloud", "identity", "application"}

REQUIRED_FIELDS = ["id", "name", "severity", "detection"]


def validate_rule(path: Path, seen_ids: dict[str, Path]) -> list[str]:
    """Validate a single detection rule file. Returns list of error messages."""
    errors: list[str] = []

    # 1. Valid YAML
    try:
        with open(path) as f:
            rule = yaml.safe_load(f)
    except yaml.YAMLError as exc:
        return [f"YAML parse error: {exc}"]

    if not isinstance(rule, dict):
        return ["Rule is not a YAML mapping (expected key: value pairs at top level)"]

    # 2. Required fields
    for field in REQUIRED_FIELDS:
        if field not in rule:
            errors.append(f"Missing required field: '{field}'")

    if errors:
        return errors  # Can't do further checks without required fields

    # 3. Severity
    if rule["severity"] not in VALID_SEVERITIES:
        errors.append(
            f"Invalid severity '{rule['severity']}'; must be one of: {', '.join(sorted(VALID_SEVERITIES))}"
        )

    # 4. Category
    category = rule.get("category")
    if category and category not in VALID_CATEGORIES:
        errors.append(
            f"Invalid category '{category}'; must be one of: {', '.join(sorted(VALID_CATEGORIES))}"
        )

    # 5. Category dir matches category field
    category_dir = path.parent.name
    if category and category != category_dir:
        errors.append(
            f"Rule category '{category}' does not match directory '{category_dir}'"
        )

    # 6. ID format: must start with 'det-'
    rule_id = rule["id"]
    if not str(rule_id).startswith("det-"):
        errors.append(f"Rule id '{rule_id}' must start with 'det-'")

    # 7. Duplicate ID
    if rule_id in seen_ids:
        errors.append(
            f"Duplicate id '{rule_id}' — already defined in {seen_ids[rule_id]}"
        )
    else:
        seen_ids[rule_id] = path

    # 8. Detection block must be a mapping
    detection = rule.get("detection")
    if not isinstance(detection, dict):
        errors.append("'detection' field must be a YAML mapping with 'condition' or 'keywords'")

    return errors


def main() -> int:
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

    for path in yaml_files:
        rel = path.relative_to(ROOT)
        total += 1
        errors = validate_rule(path, seen_ids)
        if errors:
            failed += 1
            print(f"\n❌  {rel}")
            for e in errors:
                print(f"    • {e}")
        else:
            print(f"✓  {rel}")

    print(f"\n{'─' * 50}")
    print(f"Validated {total} rules — {total - failed} passed, {failed} failed")

    return 1 if failed > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
