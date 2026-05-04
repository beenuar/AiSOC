#!/usr/bin/env python3
"""
AiSOC Detection Pack v1 - Generator
====================================

Walks the canonical specifications in `detection_specs.py` and
`detection_specs_part2.py` and emits:

  detections/<category>/<slug>.yaml
  detections/fixtures/positive/<slug>.json
  detections/fixtures/negative/<slug>.json

The rendered YAML follows the same shape as the hand-authored seed rules
(`detections/cloud/aws-root-account-login.yaml` etc.) so the existing
`validate_detections.py` checks all pass.

Run:
    python3 scripts/generate_detections.py

The generator is idempotent: running it twice produces byte-identical
output, so it is safe to invoke from CI to verify "the on-disk pack matches
the spec table" (drift check).

Design notes
------------
*   IDs are deterministic: `det-<category>-<NNN>` zero-padded to 3 digits,
    assigned in the order the spec table is iterated. This makes the
    marketplace stable across regenerations as long as the spec list order
    is preserved.
*   `match_when` operators (eq / `_in` / `_gt` / `_lt` / `_contains_any` /
    `_match_any`) are rendered into a human-readable condition string that
    mirrors the seed rules.
*   The same `match_when` is what `validate_detections.py` evaluates
    against the positive/negative fixtures (fixture-replay).
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML not installed. Run: pip install pyyaml", file=sys.stderr)
    sys.exit(1)

ROOT = Path(__file__).parent.parent
DETECTIONS_DIR = ROOT / "detections"
SCRIPTS_DIR = ROOT / "scripts"

if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from detection_specs_index import CATEGORIES  # noqa: E402  (after sys.path tweak)


# -----------------------------------------------------------------------------
# Operator table — single source of truth for matcher AND condition rendering.
# -----------------------------------------------------------------------------
#
# Order matters: longer suffixes MUST be checked before shorter ones, otherwise
# `_pattern_match_any` would be eaten by `_match_any`, and `_not_in` would be
# eaten by `_in`. We sort by descending suffix length at module import.
#
# Each entry: (suffix, op_name, condition_token).
# `condition_token` is the human-readable infix used in YAML rendering.
# -----------------------------------------------------------------------------

OPERATORS: list[tuple[str, str, str]] = sorted(
    [
        ("_pattern_match_any", "pattern_match_any", "PATTERN_MATCH_ANY"),
        ("_not_endswith_any", "not_endswith_any", "NOT ENDSWITH_ANY"),
        ("_not_contains_any", "not_contains_any", "NOT CONTAINS_ANY"),
        ("_pattern_match", "pattern_match", "PATTERN_MATCH"),
        ("_not_startswith", "not_startswith", "NOT STARTSWITH"),
        ("_startswith_any", "startswith_any", "STARTSWITH_ANY"),
        ("_endswith_any", "endswith_any", "ENDSWITH_ANY"),
        ("_contains_any", "contains_any", "CONTAINS_ANY"),
        ("_contains_all", "contains_all", "CONTAINS_ALL"),
        ("_startswith", "startswith", "STARTSWITH"),
        ("_match_any", "match_any", "MATCH_ANY"),
        ("_endswith", "endswith", "ENDSWITH"),
        ("_contains", "contains", "CONTAINS"),
        ("_has_any", "has_any", "HAS_ANY"),
        ("_not_in", "not_in", "NOT IN"),
        ("_match", "match", "MATCH"),
        ("_gte", "gte", ">="),
        ("_lte", "lte", "<="),
        ("_in", "in", "IN"),
        ("_gt", "gt", ">"),
        ("_lt", "lt", "<"),
    ],
    key=lambda x: -len(x[0]),
)


def _split_op(key: str) -> tuple[str, str]:
    """Return (field, op_name). Plain equality / null check ⇒ op == 'eq'."""
    for suffix, op_name, _ in OPERATORS:
        if key.endswith(suffix):
            return key[: -len(suffix)], op_name
    return key, "eq"


# -----------------------------------------------------------------------------
# Condition rendering
# -----------------------------------------------------------------------------


def _format_value(value: Any) -> str:
    if value is None:
        return "NULL"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return f'"{value}"'


def _format_list(values: list[Any]) -> str:
    return "[" + ", ".join(_format_value(v) for v in values) + "]"


_OP_TOKEN: dict[str, str] = {op: token for _, op, token in OPERATORS}


def _render_clause_part(key: str, value: Any) -> str:
    """Render a single clause entry into one human-readable line."""
    if key == "any_of" and isinstance(value, list):
        sub_lines = [f"  - {_render_subclause(sub)}" for sub in value]
        return "ANY OF:\n" + "\n".join(sub_lines)
    if key == "all_of" and isinstance(value, list):
        sub_lines = [f"  - {_render_subclause(sub)}" for sub in value]
        return "ALL OF:\n" + "\n".join(sub_lines)
    field, op = _split_op(key)
    if op == "eq":
        if value is None:
            return f"{field} IS NULL"
        return f"{field} == {_format_value(value)}"
    token = _OP_TOKEN[op]
    if op in {"gt", "gte", "lt", "lte"}:
        return f"{field} {token} {_format_value(value)}"
    if isinstance(value, list):
        return f"{field} {token} {_format_list(value)}"
    return f"{field} {token} {_format_value(value)}"


def _render_subclause(clause: dict[str, Any]) -> str:
    """Render a sub-clause of any_of/all_of as a single inline AND-joined string."""
    parts = [_render_clause_part(k, v) for k, v in clause.items()]
    return " AND ".join(parts)


def render_condition(match_when: dict[str, Any]) -> str:
    """Render the spec's match_when into a human-readable condition string."""
    parts = [_render_clause_part(k, v) for k, v in match_when.items()]
    return "\nAND ".join(parts)


# -----------------------------------------------------------------------------
# Fixture-replay matcher
# -----------------------------------------------------------------------------
#
# Single source of truth for evaluating a `match_when` dict against an event
# dict. The validator imports this so the YAML on disk is purely a serialized
# artifact — the spec is the truth.
# -----------------------------------------------------------------------------


def _to_lc_str(value: Any) -> str:
    return str(value).lower() if value is not None else ""


def _check(field: str, op: str, expected: Any, event: dict[str, Any]) -> bool:
    actual = event.get(field)

    if op == "eq":
        if expected is None:
            return actual is None
        return actual == expected

    if op in {"gt", "gte", "lt", "lte"}:
        if not isinstance(actual, (int, float)) or isinstance(actual, bool):
            return False
        if op == "gt":
            return actual > expected
        if op == "gte":
            return actual >= expected
        if op == "lt":
            return actual < expected
        return actual <= expected

    if op == "in":
        return actual in expected if isinstance(expected, list) else False

    if op == "not_in":
        return actual not in expected if isinstance(expected, list) else False

    if op == "contains_any":
        # Dual mode: list-intersect if `actual` is a list, else substring.
        if isinstance(actual, list):
            actual_lc = {_to_lc_str(x) for x in actual}
            return any(_to_lc_str(n) in actual_lc for n in expected)
        haystack = _to_lc_str(actual)
        return any(_to_lc_str(n) in haystack for n in expected)

    if op == "contains_all":
        if isinstance(actual, list):
            actual_lc = {_to_lc_str(x) for x in actual}
            return all(_to_lc_str(n) in actual_lc for n in expected)
        haystack = _to_lc_str(actual)
        return all(_to_lc_str(n) in haystack for n in expected)

    if op == "match_any":
        # Glob-style ('host-1*') OR exact equality. Wildcards = '*'.
        if not isinstance(expected, list):
            return False
        actual_str = "" if actual is None else str(actual)
        for pat in expected:
            pat_str = str(pat)
            if "*" in pat_str:
                regex = "^" + re.escape(pat_str).replace(r"\*", ".*") + "$"
                if re.match(regex, actual_str):
                    return True
            elif actual_str == pat_str:
                return True
        return False

    if op == "pattern_match_any":
        # Regex match against string actual. Used for SQLi/XSS payloads,
        # secret patterns (AKIA[A-Z0-9]{16}), JNDI strings, etc.
        if not isinstance(expected, list) or actual is None:
            return False
        actual_str = str(actual)
        for pat in expected:
            try:
                if re.search(str(pat), actual_str, re.IGNORECASE):
                    return True
            except re.error:
                # Treat as literal substring on regex compile error.
                if str(pat).lower() in actual_str.lower():
                    return True
        return False

    if op == "endswith":
        return isinstance(actual, str) and actual.endswith(str(expected))

    if op == "endswith_any":
        if not isinstance(expected, list) or not isinstance(actual, str):
            return False
        return any(actual.endswith(str(s)) for s in expected)

    if op == "startswith":
        return isinstance(actual, str) and actual.startswith(str(expected))

    if op == "startswith_any":
        if not isinstance(expected, list) or not isinstance(actual, str):
            return False
        return any(actual.startswith(str(s)) for s in expected)

    if op == "not_startswith":
        if not isinstance(actual, str):
            return False
        return not actual.startswith(str(expected))

    if op == "contains":
        # Single substring contains. List actual ⇒ membership; string ⇒ substring.
        if isinstance(actual, list):
            return expected in actual
        if isinstance(actual, str):
            return str(expected) in actual
        return False

    if op == "has_any":
        # List intersection. Used when `actual` is a list of tokens (perms, tags).
        if not isinstance(expected, list) or not isinstance(actual, list):
            return False
        actual_lc = {_to_lc_str(x) for x in actual}
        return any(_to_lc_str(n) in actual_lc for n in expected)

    if op == "match":
        # Single regex pattern, case-insensitive search.
        if actual is None:
            return False
        try:
            return bool(re.search(str(expected), str(actual), re.IGNORECASE))
        except re.error:
            return str(expected).lower() in str(actual).lower()

    if op == "pattern_match":
        # Single regex pattern (alias of `match` for spec-readability).
        if actual is None:
            return False
        try:
            return bool(re.search(str(expected), str(actual), re.IGNORECASE))
        except re.error:
            return str(expected).lower() in str(actual).lower()

    if op == "not_endswith_any":
        # Allowlist negation: rule fires only when `actual` does NOT end with any
        # of the supplied suffixes. Used to carve out legit-binary basenames in
        # otherwise-broad endpoint rules (e.g. browser-credential-grabber).
        if not isinstance(expected, list) or not isinstance(actual, str):
            return False
        return not any(actual.endswith(str(s)) for s in expected)

    if op == "not_contains_any":
        if not isinstance(expected, list):
            return False
        if isinstance(actual, list):
            actual_lc = {_to_lc_str(x) for x in actual}
            return not any(_to_lc_str(n) in actual_lc for n in expected)
        haystack = _to_lc_str(actual)
        return not any(_to_lc_str(n) in haystack for n in expected)

    return False


def _eval_clause(clause: dict[str, Any], event: dict[str, Any]) -> bool:
    """Evaluate a clause dict (possibly nested) against an event."""
    for key, expected in clause.items():
        if key == "any_of":
            if not isinstance(expected, list) or not any(
                _eval_clause(sub, event) for sub in expected
            ):
                return False
            continue
        if key == "all_of":
            if not isinstance(expected, list) or not all(
                _eval_clause(sub, event) for sub in expected
            ):
                return False
            continue
        field, op = _split_op(key)
        if not _check(field, op, expected, event):
            return False
    return True


def matches(match_when: dict[str, Any], event: dict[str, Any]) -> bool:
    """Return True if `event` satisfies every clause in `match_when`."""
    return _eval_clause(match_when, event)


# -----------------------------------------------------------------------------
# YAML rendering
# -----------------------------------------------------------------------------


def _description_for(spec: dict, category: str) -> str:
    """Return the spec's description override or generate a deterministic one.

    Specs may provide a richer hand-authored `description` (preferred for the
    11 original seed rules and any flagship rule). When absent, fall back to a
    deterministic blurb derived from name + false-positive count so every rule
    has at least a usable description.
    """
    override = spec.get("description")
    if override:
        return str(override).strip()

    name = spec["name"]
    fp_count = len(spec.get("fp", []))
    plural = "s" if fp_count != 1 else ""
    fp_clause = (
        f" Watch the {fp_count} documented false-positive case{plural} "
        f"before tuning."
        if fp_count
        else ""
    )
    return (
        f"AiSOC v1 curated detection. Triggers on the {category} signal "
        f"described by '{name}'.{fp_clause}"
    )


def _yaml_safe_value(value: Any) -> Any:
    if isinstance(value, set):
        return sorted(value)
    return value


class _LiteralStr(str):
    """Marker subclass so PyYAML emits the value as a literal block scalar."""


def _literal_str_representer(dumper: yaml.Dumper, data: _LiteralStr):  # type: ignore[name-defined]
    return dumper.represent_scalar(
        "tag:yaml.org,2002:str", str(data), style="|"
    )


yaml.add_representer(_LiteralStr, _literal_str_representer)  # type: ignore[arg-type]


def render_rule_yaml(
    *, rule_id: str, category: str, spec: dict
) -> str:
    """Render the canonical YAML for one detection rule."""
    name: str = spec["name"]
    severity: str = spec["severity"]
    mitre: list[str] = list(spec.get("mitre", []))
    log_source: dict = dict(spec["log_source"])
    fp: list[str] = list(spec.get("fp", []))
    playbook = spec.get("playbook")
    match_when = spec["match_when"]

    tags = [f"mitre.attack.{t}" for t in mitre] + ["tlp.white"]

    condition_text = render_condition(match_when) + "\n"

    rule: dict[str, Any] = {
        "id": rule_id,
        "name": name,
        "description": _description_for(spec, category),
        "version": "1.0.0",
        "severity": severity,
        "tags": tags,
        "category": category,
        "log_source": log_source,
        "detection": {"condition": _LiteralStr(condition_text)},
        "false_positives": fp,
    }
    if playbook:
        rule["playbook"] = playbook
    rule["enabled"] = True
    rule["author"] = "AiSOC"
    rule["created"] = "2026-05-03"
    rule["modified"] = "2026-05-03"

    text = yaml.dump(
        {k: _yaml_safe_value(v) for k, v in rule.items()},
        sort_keys=False,
        default_flow_style=False,
        width=100,
        allow_unicode=True,
    )
    return text


# -----------------------------------------------------------------------------
# Filesystem layout
# -----------------------------------------------------------------------------


def _ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def write_pack(*, dry_run: bool = False) -> dict[str, int]:
    """Generate the full pack to disk. Returns counts per category."""
    counts: dict[str, int] = {}
    for category, specs in sorted(CATEGORIES.items()):
        cat_dir = DETECTIONS_DIR / category
        pos_dir = DETECTIONS_DIR / "fixtures" / "positive"
        neg_dir = DETECTIONS_DIR / "fixtures" / "negative"
        if not dry_run:
            _ensure_dir(cat_dir)
            _ensure_dir(pos_dir)
            _ensure_dir(neg_dir)

        for idx, spec in enumerate(specs, start=1):
            slug = spec["slug"]
            rule_id = f"det-{category}-{idx:03d}"

            yaml_text = render_rule_yaml(
                rule_id=rule_id, category=category, spec=spec
            )
            yaml_path = cat_dir / f"{slug}.yaml"

            pos_path = pos_dir / f"{slug}.json"
            neg_path = neg_dir / f"{slug}.json"

            if dry_run:
                continue

            yaml_path.write_text(yaml_text, encoding="utf-8")
            pos_path.write_text(
                json.dumps(spec["positive"], indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            neg_path.write_text(
                json.dumps(spec["negative"], indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )

        counts[category] = len(specs)
    return counts


def main() -> int:
    counts = write_pack(dry_run=False)
    total = sum(counts.values())
    print("AiSOC detection pack regenerated:")
    for category, count in sorted(counts.items()):
        print(f"  {category:14s} {count:4d}")
    print(f"  {'TOTAL':14s} {total:4d}")
    print(f"  output: {DETECTIONS_DIR.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
