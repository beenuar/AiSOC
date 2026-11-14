"""Tests for declarative pre-ingest filter rules.

These rules run on every normalized event before it leaves the connector
service. Getting the semantics right is critical: a buggy rule engine could
silently drop alerts that should have been triaged. The tests here pin down:

* default behaviour (no rules → keep)
* each operator (eq, ne, contains, starts_with, ends_with, in)
* drop vs. keep actions
* malformed rules don't crash and don't drop events
* missing fields don't match (so a renamed upstream field doesn't
  accidentally match every rule and discard everything)
"""

from __future__ import annotations

from app.pipeline.filter_rules import FilterDecision, apply_filter_rules


def test_no_rules_keeps_event() -> None:
    decision = apply_filter_rules({"severity": "info"}, None)
    assert decision == FilterDecision(action="keep", rule_index=None)


def test_empty_rules_keeps_event() -> None:
    decision = apply_filter_rules({"severity": "info"}, [])
    assert decision == FilterDecision(action="keep", rule_index=None)


def test_eq_drops_matching_event() -> None:
    rules = [{"field": "severity", "op": "eq", "value": "info", "action": "drop"}]
    decision = apply_filter_rules({"severity": "info"}, rules)
    assert decision.action == "drop"
    assert decision.rule_index == 0


def test_eq_keeps_non_matching_event() -> None:
    rules = [{"field": "severity", "op": "eq", "value": "info", "action": "drop"}]
    decision = apply_filter_rules({"severity": "high"}, rules)
    assert decision.action == "keep"
    assert decision.rule_index is None


def test_contains_is_case_insensitive() -> None:
    rules = [{"field": "rule_name", "op": "contains", "value": "TEST", "action": "drop"}]
    decision = apply_filter_rules({"rule_name": "lab test alert"}, rules)
    assert decision.action == "drop"


def test_starts_with_and_ends_with() -> None:
    starts = [{"field": "host", "op": "starts_with", "value": "lab-", "action": "drop"}]
    ends = [{"field": "host", "op": "ends_with", "value": "-stage", "action": "drop"}]

    assert apply_filter_rules({"host": "lab-web-01"}, starts).action == "drop"
    assert apply_filter_rules({"host": "prod-web-01"}, starts).action == "keep"
    assert apply_filter_rules({"host": "web-01-stage"}, ends).action == "drop"


def test_in_operator_with_list() -> None:
    rules = [{"field": "severity", "op": "in", "value": ["info", "low"], "action": "drop"}]
    assert apply_filter_rules({"severity": "info"}, rules).action == "drop"
    assert apply_filter_rules({"severity": "low"}, rules).action == "drop"
    assert apply_filter_rules({"severity": "high"}, rules).action == "keep"


def test_in_operator_with_scalar_falls_back_to_eq() -> None:
    rules = [{"field": "severity", "op": "in", "value": "info", "action": "drop"}]
    assert apply_filter_rules({"severity": "info"}, rules).action == "drop"
    assert apply_filter_rules({"severity": "low"}, rules).action == "keep"


def test_ne_drops_when_field_differs() -> None:
    rules = [{"field": "tenant", "op": "ne", "value": "acme", "action": "drop"}]
    assert apply_filter_rules({"tenant": "evil-corp"}, rules).action == "drop"
    assert apply_filter_rules({"tenant": "acme"}, rules).action == "keep"


def test_first_match_wins() -> None:
    rules = [
        {"field": "severity", "op": "eq", "value": "info", "action": "keep"},
        {"field": "severity", "op": "eq", "value": "info", "action": "drop"},
    ]
    decision = apply_filter_rules({"severity": "info"}, rules)
    assert decision.action == "keep"
    assert decision.rule_index == 0


def test_keep_action_overrides_later_drop() -> None:
    rules = [
        {"field": "rule_name", "op": "contains", "value": "important", "action": "keep"},
        {"field": "severity", "op": "eq", "value": "info", "action": "drop"},
    ]
    decision = apply_filter_rules(
        {"rule_name": "important info alert", "severity": "info"},
        rules,
    )
    assert decision.action == "keep"
    assert decision.rule_index == 0


def test_missing_field_does_not_match() -> None:
    # If a rule references a field the event doesn't have, the rule should
    # be ignored rather than matching (which would silently drop everything
    # when an upstream vendor renames a field).
    rules = [{"field": "definitely_missing", "op": "eq", "value": "x", "action": "drop"}]
    decision = apply_filter_rules({"severity": "high"}, rules)
    assert decision.action == "keep"


def test_malformed_rule_skipped() -> None:
    rules = [
        "not a dict",  # type: ignore[list-item]
        {"field": ""},
        {"field": "severity", "op": "bogus_op", "value": "info", "action": "drop"},
        {"field": "severity", "op": "eq", "value": "info", "action": "delete"},
        {"field": "severity", "op": "eq", "value": "info", "action": "drop"},
    ]
    decision = apply_filter_rules({"severity": "info"}, rules)
    # Only the last rule is well-formed; that's the one that should fire.
    assert decision.action == "drop"
    assert decision.rule_index == 4


def test_string_op_coerces_non_string_actuals() -> None:
    # Some upstreams report severity as an int; rule authors usually write
    # the value as a string. Coercing both sides to str avoids the
    # surprise of "5".contains("5") not matching int 5.
    rules = [{"field": "severity", "op": "contains", "value": "5", "action": "drop"}]
    decision = apply_filter_rules({"severity": 5}, rules)
    assert decision.action == "drop"
