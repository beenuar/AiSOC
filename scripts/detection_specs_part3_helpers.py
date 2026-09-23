"""
Detection Pack v1 - Part 3 Helpers
==================================

Shared helpers for the 600 new native specs that scale the pack from
200 to 800 rules. Builds positive/negative fixtures from a single
``match_when`` clause so each spec stays compact.

Auto-fixture rules
------------------
*   Auto-generation only handles flat clauses (no ``any_of`` / ``all_of``).
    Specs with nested clauses must pass explicit ``positive=`` / ``negative=``
    fixtures.
*   The negative is the positive with one chosen field flipped to break the
    clause. By default we flip the first non-compound clause; pass
    ``neg_field=`` to override.
*   ``pattern_match`` / ``pattern_match_any`` clauses must supply a positive
    sample because regex inversion is undecidable in general.
"""

from __future__ import annotations

from collections.abc import Iterable
import re
from typing import Any

# Operator suffixes - kept in sync with scripts/generate_detections.py.
# We don't import OPERATORS to avoid bootstrapping yaml at module import time
# (the spec files are loaded by the validator before yaml is available in
# some CI shells).
_OP_SUFFIXES: tuple[tuple[str, str], ...] = tuple(
    sorted(
        [
            # `neq` was used by eleven rules and was not an operator, so
            # `actor_uid_neq: 0` was read as a field literally named
            # `actor_uid_neq` — and the synthesized fixture then contained
            # that field, so the rule matched itself and nothing else.
            ("_neq", "neq"),
            ("_pattern_match_any", "pattern_match_any"),
            ("_not_endswith_any", "not_endswith_any"),
            ("_not_contains_any", "not_contains_any"),
            ("_pattern_match", "pattern_match"),
            ("_not_startswith", "not_startswith"),
            ("_startswith_any", "startswith_any"),
            ("_endswith_any", "endswith_any"),
            ("_contains_any", "contains_any"),
            ("_contains_all", "contains_all"),
            ("_startswith", "startswith"),
            ("_match_any", "match_any"),
            ("_endswith", "endswith"),
            ("_contains", "contains"),
            ("_has_any", "has_any"),
            ("_not_in", "not_in"),
            ("_match", "match"),
            ("_gte", "gte"),
            ("_lte", "lte"),
            ("_in", "in"),
            ("_gt", "gt"),
            ("_lt", "lt"),
        ],
        key=lambda x: -len(x[0]),
    )
)


def split_op(key: str) -> tuple[str, str]:
    """Split a match_when key into (field, op_name). Plain key ⇒ op == 'eq'."""
    for suffix, op_name in _OP_SUFFIXES:
        if key.endswith(suffix):
            return key[: -len(suffix)], op_name
    return key, "eq"


# Sample value pool for negation. Uses values unlikely to collide with
# realistic field domains.
_SENTINEL_STR = "__benign__"


def _pos_for(op: str, expected: Any) -> Any:
    """Return a value satisfying the (op, expected) clause."""
    if op == "eq":
        return expected
    if op == "neq":
        # Anything but `expected`. Numeric fields get a number rather than
        # the string sentinel: `actor_uid: "__benign__"` is not a uid, and
        # a fixture that could not exist is a fixture that tests nothing.
        if isinstance(expected, bool):
            return not expected
        if isinstance(expected, (int, float)):
            return expected + 1000
        return f"not-{expected}"
    if op == "in":
        return expected[0] if isinstance(expected, list) and expected else None
    if op == "not_in":
        return _SENTINEL_STR
    if op == "match_any":
        if isinstance(expected, list) and expected:
            sample = str(expected[0])
            return sample.replace("*", "x")
        return _SENTINEL_STR
    if op == "contains_any":
        if isinstance(expected, list) and expected:
            return f"prefix-{expected[0]}-suffix"
        return _SENTINEL_STR
    if op == "contains_all":
        if isinstance(expected, list) and expected:
            return " ".join(str(e) for e in expected)
        return _SENTINEL_STR
    if op == "contains":
        return f"prefix-{expected}-suffix"
    if op == "startswith":
        return f"{expected}-tail"
    if op == "startswith_any":
        if isinstance(expected, list) and expected:
            return f"{expected[0]}-tail"
        return _SENTINEL_STR
    if op == "endswith":
        return f"head-{expected}"
    if op == "endswith_any":
        if isinstance(expected, list) and expected:
            return f"head-{expected[0]}"
        return _SENTINEL_STR
    if op == "not_endswith_any":
        return _SENTINEL_STR
    if op == "not_contains_any":
        return _SENTINEL_STR
    if op == "not_startswith":
        return _SENTINEL_STR
    if op == "has_any":
        if isinstance(expected, list) and expected:
            return list(expected[:1])
        return [_SENTINEL_STR]
    if op == "match" or op == "pattern_match":
        # Cannot reliably synthesise regex match. Caller must supply pos= override.
        return _SENTINEL_STR
    if op == "pattern_match_any":
        return _SENTINEL_STR
    if op in {"gt", "gte"}:
        return float(expected) + 100 if isinstance(expected, (int, float)) else 100
    if op in {"lt", "lte"}:
        return float(expected) - 100 if isinstance(expected, (int, float)) else -100
    return expected


def _neg_for(op: str, expected: Any) -> Any:
    """Return a value that breaks the (op, expected) clause."""
    if op == "neq":
        # The inverse of neq is equality, so the negative carries the
        # excluded value. That is the clause the rule is *about*, which is
        # what a negative should invert — the generator used to flip an
        # unrelated field and never test the condition in either direction.
        return expected
    if op == "eq":
        if expected is None:
            return _SENTINEL_STR
        if isinstance(expected, bool):
            return not expected
        if isinstance(expected, (int, float)):
            return float(expected) + 1
        return f"not-{expected}"
    if op == "in":
        return _SENTINEL_STR
    if op == "not_in":
        return expected[0] if isinstance(expected, list) and expected else _SENTINEL_STR
    if op == "match_any":
        return _SENTINEL_STR
    if op == "contains_any":
        return _SENTINEL_STR
    if op == "contains_all":
        return _SENTINEL_STR
    if op == "contains":
        return _SENTINEL_STR
    if op == "startswith":
        return f"x-{expected}"
    if op == "startswith_any":
        return _SENTINEL_STR
    if op == "endswith":
        return f"{expected}-x"
    if op == "endswith_any":
        return _SENTINEL_STR
    if op == "not_endswith_any":
        if isinstance(expected, list) and expected:
            return f"head{expected[0]}"
        return _SENTINEL_STR
    if op == "not_contains_any":
        if isinstance(expected, list) and expected:
            return f"prefix-{expected[0]}-suffix"
        return _SENTINEL_STR
    if op == "not_startswith":
        return f"{expected}-tail"
    if op == "has_any":
        return [_SENTINEL_STR]
    if op == "match" or op == "pattern_match":
        return _SENTINEL_STR
    if op == "pattern_match_any":
        return _SENTINEL_STR
    if op in {"gt", "gte"}:
        return float(expected) - 100 if isinstance(expected, (int, float)) else -100
    if op in {"lt", "lte"}:
        return float(expected) + 100 if isinstance(expected, (int, float)) else 100
    return expected


def _has_compound(when: dict[str, Any]) -> bool:
    return any(k in {"any_of", "all_of"} for k in when.keys())


def _fields_used(when: dict[str, Any]) -> set[str]:
    fields: set[str] = set()
    for key, val in when.items():
        if key == "any_of" or key == "all_of":
            if isinstance(val, list):
                for sub in val:
                    if isinstance(sub, dict):
                        fields.update(_fields_used(sub))
            continue
        field, _ = split_op(key)
        fields.add(field)
    return fields


def _compose_field_value(constraints: list[tuple[str, Any]]) -> Any:
    """Compose a single value satisfying all (op, expected) constraints on one field.

    Behaviour:
    *   Numeric ops (gt/gte/lt/lte) collapse to a value strictly inside the
        intersected interval.
    *   `eq` and `in` short-circuit (the value must equal the expected literal).
    *   `has_any` returns a list containing the first allowed element.
    *   String ops compose ``startswith * contains * endswith``: the result
        starts with any ``startswith[_any]`` value, ends with any
        ``endswith[_any]`` value, and includes every ``contains*`` substring
        in between. This lets a single value satisfy clauses like
        ``path_startswith='/tmp/' + path_endswith_any=['.tar']``.
    *   Negation ops (``not_*``) and regex ops (``match*``, ``pattern_match*``)
        are not actively enforced — the synthetic sentinel parts we glue in
        won't accidentally match common deny-list values, so the engine sees
        them as benign.
    """
    if not constraints:
        return _SENTINEL_STR

    # Numeric ops: compute the open intersection (lo, hi) and pick a midpoint.
    nums = [(op, exp) for op, exp in constraints if op in {"gt", "gte", "lt", "lte"}]
    if nums and all(isinstance(exp, (int, float)) for _, exp in nums):
        lo: float = float("-inf")
        hi: float = float("inf")
        for op, exp in nums:
            if op == "gt":
                lo = max(lo, float(exp) + 1)
            elif op == "gte":
                lo = max(lo, float(exp))
            elif op == "lt":
                hi = min(hi, float(exp) - 1)
            elif op == "lte":
                hi = min(hi, float(exp))
        if lo == float("-inf") and hi == float("inf"):
            return 0
        if lo == float("-inf"):
            return hi - 1
        if hi == float("inf"):
            return lo + 1
        # Pick midpoint within (lo, hi). Using floats keeps the math simple.
        mid = (lo + hi) / 2.0
        return mid

    # eq / in short-circuit
    eqs = [exp for op, exp in constraints if op == "eq"]
    if eqs:
        return eqs[0]
    ins = [exp for op, exp in constraints if op == "in"]
    if ins:
        first = ins[0]
        if isinstance(first, list) and first:
            return first[0]
        return first

    has_anys = [exp for op, exp in constraints if op == "has_any"]
    if has_anys:
        first = has_anys[0]
        if isinstance(first, list) and first:
            return list(first[:1])
        return [_SENTINEL_STR]

    # String composition: collect prefix, suffix, and "contains" parts.
    prefix = ""
    suffix = ""
    middle_parts: list[str] = []
    for op, exp in constraints:
        if op == "startswith":
            prefix = str(exp)
        elif op == "startswith_any":
            if isinstance(exp, list) and exp:
                prefix = str(exp[0])
        elif op == "endswith":
            suffix = str(exp)
        elif op == "endswith_any":
            if isinstance(exp, list) and exp:
                suffix = str(exp[0])
        elif op == "contains":
            middle_parts.append(str(exp))
        elif op == "contains_any":
            if isinstance(exp, list) and exp:
                middle_parts.append(str(exp[0]))
        elif op == "contains_all":
            if isinstance(exp, list):
                middle_parts.extend(str(e) for e in exp)
        elif op == "match_any":
            if isinstance(exp, list) and exp:
                middle_parts.append(str(exp[0]).replace("*", "x"))
        # All other ops (not_in, not_contains_any, not_endswith_any, not_startswith,
        # match, pattern_match, pattern_match_any) intentionally fall through —
        # the sentinel parts above are unlikely to satisfy a deny-pattern.

    if not (prefix or suffix or middle_parts):
        return _SENTINEL_STR

    middle = "".join(middle_parts)
    if not middle and (prefix or suffix):
        # When there's no required substring, glue prefix+suffix directly.
        return f"{prefix}{suffix}"
    return f"{prefix}{middle}{suffix}"


#: `<left>_eq_<right>` / `<left>_neq_<right>` — the engine derives these by
#: comparing two fields of the same event, so a fixture needs both operands
#: rather than one field named after the comparison.
_COMPARISON_KEY_RE = re.compile(r"^(?P<left>.+?)_(?P<op>eq|neq)_(?P<right>.+)$")


def _comparison_operands(key: str, want_value: bool) -> dict[str, Any] | None:
    """Two real fields whose comparison satisfies or breaks the clause.

    Returns None when `key` is not a comparison, so callers fall through to
    the ordinary operator path.
    """
    match = _COMPARISON_KEY_RE.match(key)
    if not match:
        return None
    left, right, op = match.group("left"), match.group("right"), match.group("op")
    # `want_value` is what the derived field should evaluate to, not
    # whether the clause is satisfied. Conflating the two made the negative
    # fixture identical to the positive for `actor_eq_target: false`: both
    # asked for "operands differ", so the rule matched its own negative.
    want_equal = (op == "eq") == want_value

    if left.endswith(("uid", "gid", "_id", "port")):
        return {left: 1000, right: 1000 if want_equal else 0}
    return {left: "principal-a", right: "principal-a" if want_equal else "principal-b"}


def _alternative_value(field: str, constraints: list[tuple[str, Any]], avoid: Any) -> Any:
    """Another value for `field` that still satisfies its own clauses.

    Used when a comparison needs two operands to differ and both are
    already pinned by other clauses. Returns `avoid` unchanged when no
    alternative exists, so the caller can report rather than silently
    emit a fixture that cannot satisfy its rule.
    """
    for op, expected in constraints:
        if op in {"in", "match_any", "contains_any", "startswith_any", "endswith_any"} and isinstance(
            expected, list
        ):
            for candidate in expected:
                value = _pos_for(op, [candidate])
                if value != avoid:
                    return value
    if isinstance(avoid, bool):
        return not avoid
    if isinstance(avoid, (int, float)):
        return avoid + 1
    if isinstance(avoid, str):
        return f"other-{avoid}"
    return avoid


def _resolve_comparison(
    key: str,
    want_value: bool,
    pos: dict[str, Any],
    by_field: dict[str, list[tuple[str, Any]]],
) -> dict[str, Any]:
    """Operand values satisfying a comparison, respecting existing clauses."""
    match = _COMPARISON_KEY_RE.match(key)
    assert match is not None
    left, right, op = match.group("left"), match.group("right"), match.group("op")
    want_equal = (op == "eq") == want_value

    left_value = pos.get(left)
    right_value = pos.get(right)

    # Neither operand constrained elsewhere: pick a clean pair.
    if left_value is None and right_value is None:
        operands = _comparison_operands(key, want_value)
        return operands or {}

    if left_value is None:
        left_value = right_value if want_equal else _alternative_value(
            left, by_field.get(left, []), right_value
        )
        return {left: left_value}

    if right_value is None:
        right_value = left_value if want_equal else _alternative_value(
            right, by_field.get(right, []), left_value
        )
        return {right: right_value}

    # Both pinned. Adjust the right side only, so the left keeps whatever
    # the rule's other clauses asked for.
    if want_equal:
        return {right: left_value}
    if left_value != right_value:
        return {}
    return {right: _alternative_value(right, by_field.get(right, []), left_value)}


def build_positive(when: dict[str, Any]) -> dict[str, Any]:
    """Build a synthetic positive fixture from a flat match_when.

    Multiple operators on the same field are composed into a single value.
    For example, ``path_startswith='/tmp/'`` plus ``path_endswith_any=['.tar']``
    yield ``path='/tmp/.tar'`` — satisfying both clauses.
    """
    if _has_compound(when):
        raise ValueError(
            "build_positive cannot auto-generate fixtures for any_of/all_of clauses. "
            "Pass an explicit positive= to S()."
        )
    by_field: dict[str, list[tuple[str, Any]]] = {}
    comparisons: list[tuple[str, bool]] = []
    for key, val in when.items():
        if _COMPARISON_KEY_RE.match(key):
            comparisons.append((key, bool(val)))
            continue
        field, op = split_op(key)
        by_field.setdefault(field, []).append((op, val))

    pos: dict[str, Any] = {}
    for field, constraints in by_field.items():
        if len(constraints) == 1:
            op, exp = constraints[0]
            pos[field] = _pos_for(op, exp)
        else:
            pos[field] = _compose_field_value(constraints)

    # Comparisons resolve last, because an operand can also be constrained
    # by an ordinary clause. `src_cloud_in: [aws, azure, gcp]` alongside
    # `src_cloud_neq_dst_cloud: true` put "aws" in both fields and the
    # comparison then evaluated false — the rule's own fixture could not
    # satisfy the rule.
    for key, want_value in comparisons:
        pos.update(_resolve_comparison(key, want_value, pos, by_field))

    return pos


def build_negative(
    when: dict[str, Any],
    *,
    neg_field: str | None = None,
) -> dict[str, Any]:
    """Build a synthetic negative by flipping one clause of a flat match_when."""
    if _has_compound(when):
        raise ValueError(
            "build_negative cannot auto-generate fixtures for any_of/all_of clauses. "
            "Pass an explicit negative= to S()."
        )
    neg = build_positive(when)
    target_key: str | None = None
    target_op: str | None = None
    target_expected: Any = None
    if neg_field is not None:
        for key in when.keys():
            field, op = split_op(key)
            if field == neg_field:
                target_key, target_op, target_expected = key, op, when[key]
                break
        if target_key is None:
            raise ValueError(
                f"neg_field={neg_field!r} not found in match_when keys: {list(when.keys())}"
            )
    else:
        # Prefer the clause the rule is *about*. Taking the first key made
        # every negative flip whatever happened to be written first — for
        # /etc/shadow-read-by-non-root that was `syscall`, so the negative
        # was "a syscall that does not exist" and the non-root condition
        # was never tested in either direction.
        #
        # A comparison or neq clause is the discriminating one by
        # construction: the other clauses say *where* to look, this one
        # says what makes it suspicious.
        comparison_key = next(
            (k for k in when if _COMPARISON_KEY_RE.match(k)), None
        )
        if comparison_key is not None:
            # Through the resolver, not the raw operand picker: the
            # operands may also be constrained by other clauses, and a
            # negative carrying a value the rule's own `_in` list forbids
            # is not a negative, it is a malformed event.
            by_field: dict[str, list[tuple[str, Any]]] = {}
            for key in when:
                if _COMPARISON_KEY_RE.match(key):
                    continue
                field, op = split_op(key)
                by_field.setdefault(field, []).append((op, when[key]))
            neg.update(
                _resolve_comparison(
                    comparison_key, not bool(when[comparison_key]), neg, by_field
                )
            )
            return neg

        neq_key = next(
            (k for k in when if split_op(k)[1] == "neq"), None
        )
        first_key = neq_key or next(iter(when.keys()))
        neg_field, target_op = split_op(first_key)
        target_expected = when[first_key]

    neg[neg_field] = _neg_for(target_op, target_expected)
    return neg


# Re-usable false-positive snippets to keep specs concise.
FP_TUNING = "Confirmed test/tuning activity"
FP_AUTOMATION = "Sanctioned automation/IaC pipeline"
FP_BREAK_GLASS = "Documented break-glass procedure"
FP_PENTEST = "Authorised red-team or penetration test"
FP_BACKUP = "Routine backup/disaster-recovery exercise"
FP_FORENSIC = "DFIR responder running a documented playbook"
FP_PATCH = "Approved patch / maintenance window activity"
FP_ONBOARD = "First-time provisioning / new-user onboarding"


def S(
    *,
    slug: str,
    name: str,
    severity: str,
    mitre: Iterable[str],
    product: str,
    service: str,
    when: dict[str, Any],
    fp: Iterable[str],
    playbook: str = "tpl-triage",
    description: str | None = None,
    positive: dict[str, Any] | None = None,
    negative: dict[str, Any] | None = None,
    pos_extra: dict[str, Any] | None = None,
    neg_extra: dict[str, Any] | None = None,
    neg_field: str | None = None,
) -> dict[str, Any]:
    """Build a detection spec entry with auto-generated fixtures.

    Parameters
    ----------
    slug : Filesystem slug (must be unique within the category).
    name : Human-readable rule name.
    severity : low | medium | high | critical.
    mitre : Iterable of MITRE technique IDs (lowercased dotted form, e.g. "t1078.004").
    product, service : log_source keys.
    when : The match_when dict (flat for auto-fixtures, nested for explicit).
    fp : Iterable of false-positive bullets (≥1 strongly recommended).
    playbook : Template playbook ID (`tpl-...`).
    description : Optional long description (otherwise auto-generated by the renderer).
    positive, negative : Override fixtures (skip auto-gen).
    pos_extra, neg_extra : Extra context fields appended to fixtures.
    neg_field : Override the default flip target when auto-generating negative.
    """
    if positive is None:
        pos = build_positive(when)
    else:
        pos = dict(positive)
    if pos_extra:
        pos.update(pos_extra)

    if negative is None:
        neg = build_negative(when, neg_field=neg_field)
    else:
        neg = dict(negative)
    if neg_extra:
        neg.update(neg_extra)

    spec: dict[str, Any] = {
        "slug": slug,
        "name": name,
        "severity": severity,
        "mitre": [t.lower() for t in mitre],
        "log_source": {"product": product, "service": service},
        "fields": _fields_used(when),
        "match_when": when,
        "fp": list(fp),
        "playbook": playbook,
        "positive": pos,
        "negative": neg,
    }
    if description:
        spec["description"] = description
    return spec
