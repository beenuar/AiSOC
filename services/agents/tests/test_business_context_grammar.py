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

from structlog.testing import capture_logs

from app.workers.business_context import load_rules_from_yaml

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
        "a rule using an operator no evaluator implements loaded into the hot "
        f"path; it can only ever match nothing. Parsed: {rules}"
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
    assert rejected, (
        f"an out-of-grammar route_to is warned about; an out-of-grammar op was not. Events: {events}"
    )
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
