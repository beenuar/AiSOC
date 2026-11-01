"""The worker's parser must reject an operator it cannot evaluate — depth2 4.3.

The console's authoring grammar
(:mod:`app.services.business_context.models` in ``services/api``) rejects an
unknown operator at parse time. The worker ships its own, more lenient parser,
and it validated two of the three value domains: a ``set_severity`` outside the
ladder was dropped, a ``route_to`` outside the queue list was dropped *and
warned*, and an ``op`` outside the comparator set was stored verbatim.

``_cmp`` then falls through every branch and returns ``False``, so the rule
parses, loads, sits in the tenant's rule set, and matches nothing — with no
diagnostic anywhere. ``neq`` is the operator that makes this concrete: it is
not in either engine (the spelling is ``ne``), it is the single most plausible
typo in the grammar, and a tenant writing "escalate anything *not* on the jump
box" gets silence rather than an escalation.

The worker's own docstring already concedes the gap it does not close: "The
console validates this; the worker did not, so a route the authoring grammar
would have rejected could reach the hot path if the row was written by
anything else." The same sentence is true of the operator, and the operator is
the one that decides whether the rule fires at all.
"""

from __future__ import annotations

from app.workers.business_context import (
    COMPARATOR_OPS,
    BusinessContextRule,
    RuleAction,
    RuleCondition,
    apply_rules,
    load_rules_from_yaml,
)
from structlog.testing import capture_logs

# The rule a tenant means to write: "anything on a host that is not the
# jump box is worth escalating". Spelled with the typo the grammar invites.
_NEQ_YAML = """
rules:
  - id: off-jumpbox-escalate
    when: {field: host, op: neq, value: jump-01}
    then: {set_severity: critical}
"""


def test_unknown_operator_is_rejected_not_stored_verbatim() -> None:
    """A rule whose operator cannot be evaluated must not load as a live rule."""
    rules = load_rules_from_yaml(_NEQ_YAML)
    assert rules == [], (
        f"a rule using an operator no evaluator implements loaded into the hot path; it can only ever match nothing. Parsed: {rules}"
    )


def test_unknown_operator_is_diagnosed() -> None:
    """Dropping the rule silently would trade one silent failure for another.

    ``capture_logs`` rather than ``caplog`` because these are structlog events
    and do not reach the stdlib handler ``caplog`` installs — asserting
    through ``caplog`` reports "no diagnostic" against a worker that is in
    fact emitting one.
    """
    with capture_logs() as events:
        load_rules_from_yaml(_NEQ_YAML)
    rejected = [e for e in events if e.get("event") == "business_context.rule_op_rejected"]
    assert rejected, f"an out-of-grammar route_to is warned about; an out-of-grammar op was not. Events: {events}"
    # The operator and the rule are both needed to act on it: one says what
    # to correct, the other says where.
    assert rejected[0]["op"] == "neq"
    assert rejected[0]["rule_id"] == "off-jumpbox-escalate"
    assert rejected[0]["log_level"] == "warning"


def test_rejecting_one_rule_does_not_disable_the_others() -> None:
    """Blast radius of a bad rule is that rule — the file's existing contract."""
    rules = load_rules_from_yaml(
        _NEQ_YAML
        + """
  - id: crown-jewels
    when: {field: host, op: eq, value: dc-01}
    then: {set_severity: critical}
"""
    )
    assert [r.id for r in rules] == ["crown-jewels"]


def test_nested_unknown_operator_is_caught_too() -> None:
    """An aggregator must not smuggle an unevaluable leaf past the check.

    The leaf is the thing ``_cmp`` cannot answer, and it is reachable from
    arbitrary depth, so a check that only inspects the top-level node would
    pass this rule straight through.
    """
    rules = load_rules_from_yaml(
        """
rules:
  - id: nested-typo
    when:
      all:
        - {field: severity, op: eq, value: high}
        - any:
            - {field: host, op: neq, value: jump-01}
    then: {set_severity: critical}
"""
    )
    assert rules == [], f"an unevaluable leaf nested two levels down still loaded: {rules}"


def test_every_published_operator_is_actually_evaluable() -> None:
    """A name in the set that ``_cmp`` cannot evaluate is the same bug, inverted.

    ``scripts/check_business_context_grammar.py`` asserts the same property
    statically across both services; this asserts it by *firing* each
    operator, so the claim is "this evaluated", not "this parsed".
    """
    alert = {"host": "dc-01", "score": 5, "tags": ["prod", "crown"], "absent": None}
    cases: dict[str, tuple[str, object]] = {
        "eq": ("host", "dc-01"),
        "ne": ("host", "web-07"),
        "lt": ("score", 9),
        "lte": ("score", 5),
        "gt": ("score", 1),
        "gte": ("score", 5),
        "contains": ("tags", "prod"),
        "startswith": ("host", "dc-"),
        "endswith": ("host", "-01"),
        "in": ("host", ["dc-01", "dc-02"]),
        "not_in": ("host", ["web-07"]),
        "exists": ("host", None),
        "not_exists": ("absent", None),
    }
    assert set(cases) == set(COMPARATOR_OPS), "a published operator has no evidence case here"

    for op, (field_name, value) in cases.items():
        rule = BusinessContextRule(
            id=f"probe-{op}",
            when=RuleCondition(field=field_name, op=op, value=value),
            then=RuleAction(tag="fired"),
        )
        result = apply_rules(alert, [rule])
        assert result.matched_rule_ids == [f"probe-{op}"], f"operator {op!r} is published but did not evaluate"


def test_neq_is_not_quietly_added_as_an_alias() -> None:
    """Accepting the typo would make the two engines disagree again.

    The fix is to reject and say so, not to teach one engine a spelling the
    other has never heard of.
    """
    assert "neq" not in COMPARATOR_OPS
