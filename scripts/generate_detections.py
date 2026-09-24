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

import argparse
import json
import re
from datetime import datetime
import sys
from pathlib import Path
from typing import Any

# `scripts/` is on sys.path when this file is run as a program, but not when a
# test loads it by path with importlib. gate_toolkit sits beside it either way.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_if_requested

self_test_if_requested(__file__)

try:
    import yaml
except ImportError:
    if __name__ == "__main__":
        print("ERROR: PyYAML not installed. Run: pip install pyyaml", file=sys.stderr)
        sys.exit(1)
    raise

ROOT = repo_root()
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
        # `neq` is used by rules in the shipped corpus and had no
        # operator, so `approver_role_neq: "codeowner"` was read as a
        # field literally named `approver_role_neq` — which nothing
        # emits, so the rule could not fire. There is deliberately no
        # `_eq` counterpart: bare equality is already the default, and
        # adding the suffix would split any field whose name happens to
        # end in `_eq` for no gain.
        ("_neq", "neq", "!="),
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

    if op == "neq":
        # A missing field is not "different from X". Returning True would
        # make every neq rule fire on every event lacking the field.
        if actual is None:
            return False
        return actual != expected

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
            if not isinstance(expected, list) or not any(_eval_clause(sub, event) for sub in expected):
                return False
            continue
        if key == "all_of":
            if not isinstance(expected, list) or not all(_eval_clause(sub, event) for sub in expected):
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
    fp_clause = f" Watch the {fp_count} documented false-positive case{plural} " f"before tuning." if fp_count else ""
    return f"AiSOC v1 curated detection. Triggers on the {category} signal " f"described by '{name}'.{fp_clause}"


def _yaml_safe_value(value: Any) -> Any:
    if isinstance(value, set):
        return sorted(value)
    return value


class _LiteralStr(str):
    """Marker subclass so PyYAML emits the value as a literal block scalar."""


def _literal_str_representer(dumper: yaml.Dumper, data: _LiteralStr):  # type: ignore[name-defined]
    return dumper.represent_scalar("tag:yaml.org,2002:str", str(data), style="|")


yaml.add_representer(_LiteralStr, _literal_str_representer)  # type: ignore[arg-type]


def render_rule_yaml(*, rule_id: str, category: str, spec: dict) -> str:
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


#: Slug → rule id, so a rule's id never depends on where it sits in the spec
#: list. Ids were positional (``det-{category}-{index}``), which meant
#: inserting a rule anywhere but the end silently renumbered every rule after
#: it — re-running the generator on a clean checkout reassigned ids and
#: tripped the marketplace gate, and the workaround was "append, never
#: insert", which is a rule nobody remembers.
#:
#: The lock is append-only in effect: an existing slug keeps its id forever,
#: a new slug takes the next free number in its category. Deleting a rule
#: leaves its id burned rather than recycling it onto something else, because
#: a recycled id makes a historical alert reference the wrong rule.
ID_LOCK = DETECTIONS_DIR / "rule-ids.lock.json"


def load_id_lock() -> dict[str, str]:
    if not ID_LOCK.exists():
        return {}
    try:
        return dict(json.loads(ID_LOCK.read_text(encoding="utf-8")))
    except Exception:  # noqa: BLE001 - a corrupt lock must not silently renumber
        raise SystemExit(
            f"{ID_LOCK} is unreadable. Fix or delete it deliberately — " f"regenerating without it reassigns every rule id."
        ) from None


def assign_ids(categories: dict) -> tuple[dict[str, str], list[str]]:
    """Resolve a stable id for every spec. Returns (lock, newly assigned).

    Reads the lock, keeps every id it already holds, and allocates the next
    free number per category for anything new.
    """
    lock = load_id_lock()
    newly: list[str] = []

    for category, specs in sorted(categories.items()):
        used = {
            int(rid.rsplit("-", 1)[1]) for key, rid in lock.items() if key.startswith(f"{category}/") and rid.rsplit("-", 1)[-1].isdigit()
        }
        next_free = max(used) + 1 if used else 1

        for spec in specs:
            key = f"{category}/{spec['slug']}"
            if key in lock:
                continue
            while next_free in used:
                next_free += 1
            lock[key] = f"det-{category}-{next_free:03d}"
            used.add(next_free)
            newly.append(key)

    return lock, newly


# ─── Derived fields ──────────────────────────────────────────────────────────
#
# Vendored into `services/fusion/app/services/derived_fields.py`, and kept in
# parity by `services/fusion/tests/test_detection_matcher_parity.py` — the
# same arrangement as `matches()` itself, for the same reason: services
# cannot import repo-root scripts at runtime, and two copies that can drift
# silently are worse than one copy plus a gate.
#
# These compute fields the engine can derive from an event it already has,
# so a rule matching `actor_eq_target` or `is_business_hours` is reachable
# even though no connector emits either.

_COMPARISON_RE = re.compile(r"^(?P<left>.+?)_(?P<op>eq|neq)_(?P<right>.+)$")

DEFAULT_BUSINESS_START_HOUR = 8
DEFAULT_BUSINESS_END_HOUR = 18

_TIME_FIELDS = ("event_time", "timestamp", "time", "@timestamp", "ingest_time")


def _parse_event_time(event: dict[str, Any]) -> datetime | None:
    for field in _TIME_FIELDS:
        raw = event.get(field)
        if raw is None:
            continue
        if isinstance(raw, datetime):
            return raw
        if isinstance(raw, (int, float)) and not isinstance(raw, bool):
            try:
                seconds = raw / 1000 if raw > 1e11 else raw
                return datetime.fromtimestamp(seconds)  # noqa: DTZ006
            except (OSError, ValueError, OverflowError):
                continue
        if isinstance(raw, str):
            try:
                return datetime.fromisoformat(raw.replace("Z", "+00:00"))
            except ValueError:
                continue
    return None


def _normalise_operand(value: Any) -> Any:
    return value.strip().lower() if isinstance(value, str) else value


def comparison_fields(event: dict[str, Any], requested: set[str] | None = None) -> dict[str, bool]:
    """`<a>_eq_<b>` / `<a>_neq_<b>` for the names some rule asks for.

    A missing operand yields no key rather than False: a rule must not fire
    because we did not know.
    """
    if not requested:
        return {}
    out: dict[str, bool] = {}
    for name in requested:
        match = _COMPARISON_RE.match(name)
        if not match:
            continue
        left = event.get(match.group("left"))
        right = event.get(match.group("right"))
        if left is None or right is None:
            continue
        equal = _normalise_operand(left) == _normalise_operand(right)
        out[name] = equal if match.group("op") == "eq" else not equal
    return out


def time_of_day_fields(
    event: dict[str, Any],
    *,
    business_start: int = DEFAULT_BUSINESS_START_HOUR,
    business_end: int = DEFAULT_BUSINESS_END_HOUR,
) -> dict[str, bool]:
    """`is_business_hours` / `is_after_hours` / `is_weekend`.

    Nothing when the event has no parseable timestamp: an unknown time is
    not "outside business hours".
    """
    when = _parse_event_time(event)
    if when is None:
        return {}
    weekend = when.weekday() >= 5
    in_hours = (not weekend) and business_start <= when.hour < business_end
    return {
        "is_business_hours": in_hours,
        "is_after_hours": not in_hours,
        "is_weekend": weekend,
    }


def enrich(
    event: dict[str, Any],
    requested: set[str] | None = None,
    *,
    business_start: int = DEFAULT_BUSINESS_START_HOUR,
    business_end: int = DEFAULT_BUSINESS_END_HOUR,
) -> dict[str, Any]:
    """`event` plus every derivable field the rules ask for.

    A derived key never overwrites one the connector supplied: a vendor's
    own answer about its own tenant's hours beats ours.
    """
    derived: dict[str, Any] = {}
    derived.update(time_of_day_fields(event, business_start=business_start, business_end=business_end))
    derived.update(comparison_fields(event, requested))
    return event if not derived else {**derived, **event}


def requested_derived_fields(rules: list[dict[str, Any]]) -> set[str]:
    """Derivable field names the ruleset matches on.

    Computed once per ruleset rather than per event: the set changes when
    rules change, not when traffic arrives.
    """
    names: set[str] = set()

    def walk(clause: Any) -> None:
        if isinstance(clause, dict):
            for key, value in clause.items():
                if key in {"any_of", "all_of", "not"}:
                    walk(value)
                    continue
                field, _ = _split_op(key)
                if _COMPARISON_RE.match(field) or field.startswith("is_"):
                    names.add(field)
        elif isinstance(clause, list):
            for item in clause:
                walk(item)

    for rule in rules:
        walk(rule.get("match_when") or {})
    return names


def render_pack(id_lock: dict[str, str]) -> tuple[dict[Path, str], dict[str, int]]:
    """Render every artifact in memory. Returns (path → content, counts).

    Rendering is separated from writing so ``--check`` compares exactly the
    bytes ``main()`` would have written, rather than re-deriving them through a
    second code path that can disagree with the first.
    """
    artifacts: dict[Path, str] = {}
    counts: dict[str, int] = {}
    pos_dir = DETECTIONS_DIR / "fixtures" / "positive"
    neg_dir = DETECTIONS_DIR / "fixtures" / "negative"

    for category, specs in sorted(CATEGORIES.items()):
        cat_dir = DETECTIONS_DIR / category
        for spec in specs:
            slug = spec["slug"]
            # Looked up, not computed from position. See ID_LOCK.
            rule_id = id_lock[f"{category}/{slug}"]

            artifacts[cat_dir / f"{slug}.yaml"] = render_rule_yaml(rule_id=rule_id, category=category, spec=spec)
            artifacts[pos_dir / f"{slug}.json"] = json.dumps(spec["positive"], indent=2, sort_keys=True) + "\n"
            artifacts[neg_dir / f"{slug}.json"] = json.dumps(spec["negative"], indent=2, sort_keys=True) + "\n"

        counts[category] = len(specs)
    return artifacts, counts


def write_pack(*, dry_run: bool = False) -> dict[str, int]:
    """Generate the full pack to disk. Returns counts per category."""
    id_lock, newly_assigned = assign_ids(CATEGORIES)
    if newly_assigned and not dry_run:
        ID_LOCK.write_text(json.dumps(id_lock, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"  assigned {len(newly_assigned)} new rule id(s)")

    artifacts, counts = render_pack(id_lock)
    if dry_run:
        return counts

    for path in {DETECTIONS_DIR / c for c in counts} | {
        DETECTIONS_DIR / "fixtures" / "positive",
        DETECTIONS_DIR / "fixtures" / "negative",
    }:
        _ensure_dir(path)
    for path, content in artifacts.items():
        path.write_text(content, encoding="utf-8")

    return counts


def check_pack() -> int:
    """Fail if regenerating would change anything already committed.

    Without this, the generator and the committed pack drift silently, and the
    drift is not cosmetic: the id is the join key between an alert and its
    catalogue entry. The committed projection had fallen 45 rule ids out of
    step with the lock, so a rule id taken off an alert resolved to a different
    rule's description, false-positive notes and playbook.
    """
    id_lock, newly_assigned = assign_ids(CATEGORIES)
    if newly_assigned:
        print(f"error: {len(newly_assigned)} spec(s) have no locked rule id:")
        for key in sorted(newly_assigned)[:10]:
            print(f"  {key}")
        print("Run `python3 scripts/generate_detections.py` and commit the result.")
        return 1

    artifacts, _ = render_pack(id_lock)
    moved: list[tuple[str, str, str]] = []
    changed: list[Path] = []
    missing: list[Path] = []

    for path, content in sorted(artifacts.items()):
        if not path.exists():
            missing.append(path)
            continue
        on_disk = path.read_text(encoding="utf-8")
        if on_disk == content:
            continue
        changed.append(path)
        if path.suffix == ".yaml":
            before = _yaml_id(on_disk)
            after = _yaml_id(content)
            if before and after and before != after:
                moved.append((str(path.relative_to(ROOT)), before, after))

    if not (moved or changed or missing):
        print(f"generate_detections --check: OK — {len(artifacts)} artifacts match the specs")
        return 0

    if moved:
        print(f"error: regenerating would MOVE {len(moved)} rule id(s).")
        print("An id is the join key between an alert and its catalogue entry, so")
        print("moving one makes historical alerts reference the wrong rule.")
        for rel, before, after in moved[:10]:
            print(f"  {rel}: {before} -> {after}")
        if len(moved) > 10:
            print(f"  ... and {len(moved) - 10} more")
    if missing:
        print(f"error: {len(missing)} generated artifact(s) are not committed, e.g.")
        for path in missing[:5]:
            print(f"  {path.relative_to(ROOT)}")
    other = [p for p in changed if str(p.relative_to(ROOT)) not in {m[0] for m in moved}]
    if other:
        print(f"error: {len(other)} committed artifact(s) differ from the specs, e.g.")
        for path in other[:5]:
            print(f"  {path.relative_to(ROOT)}")
    print("Run `python3 scripts/generate_detections.py` and commit the result.")
    return 1


def _yaml_id(text: str) -> str | None:
    for line in text.splitlines():
        if line.startswith("id:"):
            return line.split(":", 1)[1].strip()
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate the AiSOC detection pack.")
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail if regenerating would change the committed pack",
    )
    args = parser.parse_args()
    if args.check:
        return check_pack()

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
