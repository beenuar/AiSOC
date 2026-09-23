"""The two business-context evaluators must agree on the grammar (T3.5).

Business-context rules are parsed twice by two different implementations: the
console authors and validates them with
``services/api/app/services/business_context/models.py``, and the triage worker
re-parses the stored YAML with ``services/agents/app/workers/business_context``.

They disagreed on ``not``. The console requires a mapping — a single negated
condition — and the worker iterated every aggregator as a list. Iterating a
mapping yields its string keys, so ``_parse_condition("field")`` called
``.get()`` on a ``str`` and raised ``AttributeError``, which the caller's catch
turned into ``rules = []``.

The consequence was not a broken rule. **One console-accepted ``not`` rule
silently discarded that tenant's entire rule set at triage**, suppressions
included, logged at ``warning``. A rule that suppresses known-benign noise
stops suppressing, and nothing on the console says so.
"""

from __future__ import annotations

import ast
from pathlib import Path

from app.workers.business_context import (
    _ALLOWED_ROUTES,
    apply_rules,
    load_rules_from_yaml,
)

NOT_RULE_YAML = """
rules:
  - id: payments-not-info
    when:
      all:
        - {field: asset.tags, op: contains, value: payments}
        - not: {field: severity, op: eq, value: info}
    then:
      set_severity: critical
  - id: suppress-known-scanner
    when: {field: source_ip, op: eq, value: 10.1.2.3}
    then:
      suppress: true
"""


def test_a_not_rule_parses_at_all() -> None:
    """The regression: this raised AttributeError."""
    rules = load_rules_from_yaml(NOT_RULE_YAML)
    assert [r.id for r in rules] == ["payments-not-info", "suppress-known-scanner"]


def test_a_not_rule_does_not_take_the_rest_of_the_tenants_rules_with_it() -> None:
    """The severe part. The suppression rule is unrelated to the `not` rule
    and used to stop working because of it."""
    rules = load_rules_from_yaml(NOT_RULE_YAML)
    suppressors = [r for r in rules if r.then.suppress]
    assert len(suppressors) == 1, "the suppression rule was dropped"


def test_the_negation_actually_negates() -> None:
    """Parsing is not enough — a `not` that always evaluated False would be a
    rule that silently never fires."""
    rules = load_rules_from_yaml(NOT_RULE_YAML)

    high = apply_rules({"asset": {"tags": ["payments"]}, "severity": "high"}, rules)
    assert high.alert["severity"] == "critical"
    assert "payments-not-info" in high.matched_rule_ids

    info = apply_rules({"asset": {"tags": ["payments"]}, "severity": "info"}, rules)
    assert info.alert["severity"] == "info", "the negated branch matched when it should not have"
    assert "payments-not-info" not in info.matched_rule_ids


def test_not_also_accepts_a_list_meaning_none_of_these() -> None:
    """Kept for the shape the old evaluator's `not` branch implied."""
    rules = load_rules_from_yaml(
        """
rules:
  - id: neither
    when:
      not:
        - {field: severity, op: eq, value: info}
        - {field: severity, op: eq, value: low}
    then:
      tag: escalated
"""
    )
    assert apply_rules({"severity": "high"}, rules).matched_rule_ids == ["neither"]
    assert apply_rules({"severity": "low"}, rules).matched_rule_ids == []


def test_one_malformed_rule_is_skipped_and_the_others_survive() -> None:
    """The blast radius of a bad rule should be that rule."""
    rules = load_rules_from_yaml(
        """
rules:
  - id: broken
    when:
      all: {not: a list}
    then:
      set_severity: high
  - id: fine
    when: {field: source, op: eq, value: okta}
    then:
      tag: identity
"""
    )
    assert [r.id for r in rules] == ["fine"]


def test_an_unknown_route_is_dropped_rather_than_applied() -> None:
    """The console validates route_to; the worker did not, so a route the
    authoring grammar rejects could still reach the hot path."""
    rules = load_rules_from_yaml(
        """
rules:
  - id: bad-route
    when: {field: source, op: eq, value: okta}
    then:
      route_to: not-a-real-queue
"""
    )
    assert rules[0].then.route_to is None


def test_a_known_route_still_applies() -> None:
    rules = load_rules_from_yaml(
        """
rules:
  - id: good-route
    when: {field: source, op: eq, value: okta}
    then:
      route_to: identity
"""
    )
    assert rules[0].then.route_to == "identity"


def test_the_worker_route_list_matches_the_console_route_list() -> None:
    """Two copies of one grammar drift unless something pins them together.

    Read out of the API's source rather than imported: the two services ship
    as separate images and ``services/api`` is not importable from the agents
    test environment. An ``importorskip`` here would make this a gate that
    passes by skipping, which is the failure mode it exists to prevent — so it
    parses the literal instead, and fails loudly if the file moves.
    """
    services_dir = Path(__file__).resolve().parents[2]
    models_py = services_dir / "api" / "app" / "services" / "business_context" / "models.py"
    assert models_py.exists(), f"the console's grammar moved; update this path ({models_py})"

    tree = ast.parse(models_py.read_text(encoding="utf-8"))
    console_routes: set[str] | None = None
    for node in ast.walk(tree):
        if not isinstance(node, ast.AnnAssign) or not isinstance(node.target, ast.Name):
            continue
        if node.target.id != "ALLOWED_ROUTES" or node.value is None:
            continue
        # frozenset({...}) — pull the set literal out of the call.
        literal = node.value.args[0] if isinstance(node.value, ast.Call) and node.value.args else node.value
        console_routes = {elt.value for elt in literal.elts if isinstance(elt, ast.Constant)}
        break

    assert console_routes, "could not read ALLOWED_ROUTES out of the console's models.py"
    assert set(_ALLOWED_ROUTES) == console_routes
