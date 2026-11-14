"""Pre-ingest filter rules — Security Data Pipeline (MVP).

The data-pipeline feature is a "drop or keep before it costs you anything"
layer: every connector instance can carry a small list of declarative rules
in its ``connector_config["filter_rules"]`` array. The scheduler runs these
rules over each normalized batch *before* shipping events to the ingest
service, so a noisy informational alert can be discarded at the connector
edge instead of consuming hot-tier storage and triage capacity.

Rule shape (kept intentionally tiny so it's safe to author by hand):

.. code-block:: yaml

    filter_rules:
      - field: severity
        op: eq
        value: info
        action: drop
      - field: rule_name
        op: contains
        value: "test alert"
        action: drop

The same operator vocabulary as ``federated.query`` is reused so SOC
operators don't have to learn two filter dialects.

Supported actions:

* ``drop`` — discard the event entirely. It never reaches ingest.
* ``keep`` — explicitly retain (used to override a later catch-all drop).

Anything that doesn't match any rule is kept by default. Rules are
evaluated top-to-bottom; first match wins. This is the same semantics
``iptables`` and most firewall vendors use, so it's familiar and
debuggable.

The function is pure — it does not log, ingest, or mutate the events.
The scheduler is responsible for incrementing ``events_dropped`` and for
writing a structured log line per drop so an operator can audit which
events were filtered.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# Operator vocabulary mirrors federated/query.py to avoid teaching the
# user two slightly different dialects of "this field equals that value".
_VALID_OPS: frozenset[str] = frozenset({"eq", "ne", "contains", "starts_with", "ends_with", "in"})
_VALID_ACTIONS: frozenset[str] = frozenset({"drop", "keep"})


@dataclass(slots=True)
class FilterDecision:
    """Result of running rules over a single event.

    ``action`` is always either ``"drop"`` or ``"keep"`` (never None) so
    the caller can branch unambiguously. ``rule_index`` is the 0-based
    index of the rule that matched, or ``None`` if the default
    keep-everything fallback fired. ``rule_index`` is logged so an
    operator can audit which rule discarded which event.
    """

    action: str
    rule_index: int | None


def _matches(event: dict[str, Any], field: str, op: str, value: Any) -> bool:
    """Evaluate a single ``field <op> value`` predicate against an event.

    Missing fields are treated as a non-match (return False) for every
    operator. We don't raise: a poorly authored rule referencing a field
    that an upstream vendor renamed shouldn't blow up the polling loop.
    """
    actual = event.get(field)
    if actual is None:
        return False

    # Cheapest comparisons first.
    if op == "eq":
        return actual == value
    if op == "ne":
        return actual != value
    if op == "in":
        # Caller is expected to pass a list/tuple/set for `value`. If they
        # passed a scalar, fall back to `==` so we don't crash.
        if isinstance(value, list | tuple | set):
            return actual in value
        return actual == value

    # String operators — coerce to str so "severity == 5" with a string
    # rule still does the obvious thing.
    actual_str = str(actual)
    value_str = str(value)
    if op == "contains":
        return value_str.lower() in actual_str.lower()
    if op == "starts_with":
        return actual_str.lower().startswith(value_str.lower())
    if op == "ends_with":
        return actual_str.lower().endswith(value_str.lower())

    # Unknown operator: refuse to drop. Better to over-keep than to silently
    # discard events because someone fat-fingered the operator.
    return False


def apply_filter_rules(
    event: dict[str, Any],
    rules: list[dict[str, Any]] | None,
) -> FilterDecision:
    """Evaluate the rule list against one event and return the decision.

    Iterates rules top-to-bottom; the first rule whose predicate matches
    decides the action (drop or keep). If no rule matches, the default
    is to keep the event — the scheduler must not silently discard
    everything just because a tenant left their rule list empty.

    Malformed rules (missing keys, bad operator, bad action) are skipped
    silently. We log noisily about this elsewhere (the scheduler emits a
    structured warning the first time a malformed rule is seen) so the
    user gets visibility without each evaluation costing log spam.
    """
    if not rules:
        return FilterDecision(action="keep", rule_index=None)

    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue
        field = rule.get("field")
        op = rule.get("op")
        value = rule.get("value")
        action = rule.get("action", "drop")

        if not isinstance(field, str) or not field:
            continue
        if op not in _VALID_OPS:
            continue
        if action not in _VALID_ACTIONS:
            continue

        if _matches(event, field, op, value):
            return FilterDecision(action=action, rule_index=index)

    # No rule matched: default keep.
    return FilterDecision(action="keep", rule_index=None)


__all__ = ["FilterDecision", "apply_filter_rules"]
