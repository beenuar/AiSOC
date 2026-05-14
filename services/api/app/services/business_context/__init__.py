"""Business Context Rules — Track 3, T3.5.

A YAML-based mutator that runs **between fusion and the triage agent**.
The platform fusion pipeline (``services/fusion``) emits a normalised,
de-duplicated, ML-scored ``FusedAlert``. Before that alert reaches the
triage agent, this module gives the customer a chance to apply their
own business context — bumping severity for prod, routing AWS alerts
to the cloud team, suppressing alerts that fire during a known
maintenance window, etc.

Example rule
~~~~~~~~~~~~

.. code-block:: yaml

    id: prod-iam-touch-is-critical
    description: Anything touching prod IAM during business hours wakes tier-2.
    when:
      all:
        - field: alert.target.tag
          op: eq
          value: prod
        - field: alert.time.is_business_hours
          op: eq
          value: true
    then:
      set_severity: critical
      route_to: tier2
      tag: business-hours-prod

The engine compiles each rule into a small predicate DAG keyed on the
fields it touches, so evaluation against an alert is O(rules * fields)
without YAML reparsing on the hot path.

Public surface
~~~~~~~~~~~~~~

* :class:`BusinessContextEngine` — load + evaluate rules, hot-reload on
  rule change.
* :class:`BusinessContextRule` — parsed rule wire shape.
* :class:`AlertEvaluation` — one alert's before/after diff for the
  preview UI.
* :func:`load_rules_from_yaml` — pure parser; raises
  :class:`RuleParseError` on grammar errors.
"""

from __future__ import annotations

from .engine import (
    AlertEvaluation,
    BusinessContextEngine,
    EngineSnapshot,
    RuleAction,
)
from .models import (
    BusinessContextRule,
    RuleCondition,
    RuleParseError,
    load_rules_from_yaml,
)

__all__ = [
    "AlertEvaluation",
    "BusinessContextEngine",
    "BusinessContextRule",
    "EngineSnapshot",
    "RuleAction",
    "RuleCondition",
    "RuleParseError",
    "load_rules_from_yaml",
]
