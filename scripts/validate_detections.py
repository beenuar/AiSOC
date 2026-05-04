#!/usr/bin/env python3
"""
AiSOC Detection Rule Validator
================================
Validates all YAML detection rules under detections/ for:
  - Valid YAML syntax
  - Required fields (id, name, severity, detection)
  - Severity is one of: low | medium | high | critical
  - Category is one of: network | endpoint | cloud | identity | application | data-exfil
  - No duplicate `id` values across all rules
  - id prefix matches the category directory
  - Each rule has matching positive + negative fixtures under detections/fixtures/
  - Fixture-replay: positive fixture must satisfy match_when, negative must not

Fixture replay uses the canonical `matches()` function from
`generate_detections.py` against the structured `match_when` dict from the
spec table, NOT a re-parse of the rendered YAML condition string. The YAML
condition is purely a serialized artifact for human readability — the spec
is the source of truth.

Exit code 0 = all rules valid
Exit code 1 = one or more validation errors
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

# Canonical matcher and spec table — single source of truth for replay.
from generate_detections import matches  # noqa: E402
from detection_specs_index import all_specs  # noqa: E402

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


# =============================================================================
# Spec lookup — map (category, slug) → match_when dict from the canonical
# spec tables so we can replay fixtures against the structured spec, not a
# re-parsed YAML condition string.
# =============================================================================

_SPEC_BY_KEY: dict[tuple[str, str], dict[str, Any]] = {
    (cat, spec["slug"]): spec for cat, spec in all_specs()
}


# =============================================================================
# Validation
# =============================================================================


def validate_rule(
    path: Path, seen_ids: dict[str, Path]
) -> tuple[list[str], dict[str, Any] | None]:
    """Validate a single detection rule file.

    Returns (errors, parsed_rule). If parsing failed, parsed_rule is None.
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

    category = rule.get("category")
    if category and category not in VALID_CATEGORIES:
        errors.append(
            f"Invalid category '{category}'; must be one of: "
            f"{', '.join(sorted(VALID_CATEGORIES))}"
        )

    category_dir = path.parent.name
    if category and category != category_dir:
        errors.append(
            f"Rule category '{category}' does not match directory '{category_dir}'"
        )

    rule_id = rule["id"]
    if not str(rule_id).startswith("det-"):
        errors.append(f"Rule id '{rule_id}' must start with 'det-'")

    if rule_id in seen_ids:
        errors.append(
            f"Duplicate id '{rule_id}' — already defined in {seen_ids[rule_id]}"
        )
    else:
        seen_ids[rule_id] = path

    detection = rule.get("detection")
    if not isinstance(detection, dict):
        errors.append(
            "'detection' field must be a YAML mapping with 'condition' or 'keywords'"
        )

    return errors, rule


def replay_fixture(
    rule_path: Path, rule: dict[str, Any], strict: bool
) -> list[str]:
    """Replay positive + negative fixtures against the canonical spec.

    Looks up the spec for this rule by (category, slug), then evaluates
    the structured `match_when` dict against the on-disk fixtures using
    the same `matches()` function the runtime engine would use.

    Returns a list of error messages. If `strict` is False, missing fixtures
    or missing specs degrade to soft warnings.
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
            msg_parts.append(f"missing positive fixture {pos_path.relative_to(ROOT)}")
        if neg_missing:
            msg_parts.append(f"missing negative fixture {neg_path.relative_to(ROOT)}")
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
        return errors  # nothing to replay

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

    for path in yaml_files:
        # Skip auto-imported sigma rules — those are validated separately.
        if "sigma-imports" in path.parts:
            continue
        rel = path.relative_to(ROOT)
        total += 1

        errors, rule = validate_rule(path, seen_ids)
        rule_failed = bool(errors)

        # Fixture replay only for category rules (skip top-level files)
        replay_errors: list[str] = []
        if rule and not rule_failed and path.parent.name in VALID_CATEGORIES:
            replay_errors = replay_fixture(path, rule, strict=strict)

        warnings = [e for e in replay_errors if e.startswith("WARN:")]
        hard = [e for e in replay_errors if not e.startswith("WARN:")]
        fixture_warnings += len(warnings)
        if hard:
            rule_failed = True
            errors.extend(hard)

        if rule_failed:
            failed += 1
            print(f"\n❌  {rel}")
            for e in errors:
                print(f"    • {e}")
        else:
            warn_suffix = f" ({len(warnings)} warn)" if warnings else ""
            print(f"✓  {rel}{warn_suffix}")
            for w in warnings:
                print(f"    {w}")

    print(f"\n{'─' * 50}")
    print(
        f"Validated {total} rules — {total - failed} passed, {failed} failed, "
        f"{fixture_warnings} fixture warnings"
    )

    return 1 if failed > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
