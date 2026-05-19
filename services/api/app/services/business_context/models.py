"""Business context rule data model + YAML parser — T3.5.

The wire shape mirrors the playbook-engine ``condition_expr`` grammar
in :file:`playbook.schema.json` so analysts who already understand
playbook conditions feel at home (``field / op / value`` with
``and / or / not`` aggregators). The evaluator lives in
:mod:`app.services.business_context.engine`; this module is pure data
+ parsing so we can re-use it from the API layer (CRUD validation),
the dry-run preview, and the hot-path evaluator without circularity.

Why YAML and not JSON? The settings page exposes a Monaco editor and
analysts overwhelmingly prefer YAML for rule authoring (comments, no
quoted keys, multiline strings for ``description``). The CRUD layer
parses YAML→model on write and stores the structured model as JSONB,
so the wire format on the API is always JSON; YAML is only the input
language the editor speaks.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from dataclasses import field as dc_field
from typing import Any, Literal

import yaml

# ---------------------------------------------------------------------------
# Public errors
# ---------------------------------------------------------------------------


class RuleParseError(ValueError):
    """Raised when a rule definition fails structural validation.

    We deliberately use ``ValueError`` (not a Pydantic validation error)
    so callers in the API layer can catch this single class and return a
    422 with the message verbatim — the message is already shaped for an
    end-user (e.g. "rule 'x': 'set_severity' must be one of ...").
    """


# ---------------------------------------------------------------------------
# Constants — kept inline so callers can introspect them (UI builder hints).
# ---------------------------------------------------------------------------

ALLOWED_OPS: frozenset[str] = frozenset(
    {
        "eq",
        "ne",
        "lt",
        "lte",
        "gt",
        "gte",
        "contains",
        "startswith",
        "endswith",
        "in",
        "not_in",
        "exists",
        "not_exists",
    }
)

ALLOWED_SEVERITIES: tuple[str, ...] = ("info", "low", "medium", "high", "critical")

# Routing destinations the platform recognises today. The triage agent
# uses these to decide which queue to drop the alert into; an unknown
# destination is rejected at parse-time so a typo in YAML doesn't
# silently route alerts to nowhere.
ALLOWED_ROUTES: frozenset[str] = frozenset(
    {
        "tier1",
        "tier2",
        "tier3",
        "ic",
        "cloud",
        "identity",
        "appsec",
        "soc-night",
        "soc-emea",
    }
)

# A rule id is a kebab-case slug; mirrors the playbook id pattern in
# :file:`playbook.schema.json` so the two surfaces stay consistent.
_RULE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,62}$")
# Tags + route destinations follow the same shape so they can be used
# as-is in downstream tools (slack channels, jira labels, etc.).
_TAG_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")


# ---------------------------------------------------------------------------
# Conditions
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RuleCondition:
    """One node of a condition expression.

    Exactly one of:

    * ``field/op/value`` — the leaf comparator.
    * ``logical`` + ``children`` — an aggregator (``all`` / ``any`` / ``not``).

    The dataclass is frozen so the engine can keep references in caches
    keyed on (rule_id, condition_index) without worrying about mutation.
    """

    # Leaf form
    field: str | None = None
    op: str | None = None
    value: Any = None

    # Aggregator form
    logical: Literal["all", "any", "not", None] = None
    children: tuple[RuleCondition, ...] = dc_field(default_factory=tuple)

    def fields_referenced(self) -> set[str]:
        """All distinct field names the condition pulls out of the alert.

        Used by the engine to build a quick "which rules need re-eval if
        this field changes?" reverse-index; also used by the UI builder
        side-panel to surface the fields a rule depends on.
        """
        if self.field is not None:
            return {self.field}
        out: set[str] = set()
        for c in self.children:
            out |= c.fields_referenced()
        return out


# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RuleAction:
    """The mutation a matching rule applies to the alert.

    All fields are optional; an action with everything ``None`` is a
    no-op (allowed at parse time so an analyst can stub a rule and fill
    in the action later).
    """

    set_severity: str | None = None  # one of ALLOWED_SEVERITIES
    route_to: str | None = None  # one of ALLOWED_ROUTES
    tag: str | None = None  # appended to alert.tags
    suppress: bool = False  # if true, alert is dropped before triage

    def is_noop(self) -> bool:
        return self.set_severity is None and self.route_to is None and self.tag is None and not self.suppress


# ---------------------------------------------------------------------------
# Rule
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BusinessContextRule:
    """A parsed business-context rule.

    Frozen + hashable so the engine can compile and cache them in a
    dict keyed on ``id``. The original YAML source is kept on
    ``raw_yaml`` for round-tripping into the editor without losing
    comments / formatting.
    """

    id: str
    description: str
    when: RuleCondition
    then: RuleAction
    enabled: bool = True
    priority: int = 100  # lower runs first; ties broken by id for determinism
    raw_yaml: str = ""


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def _parse_condition(raw: Any, *, path: str) -> RuleCondition:
    """Turn the raw mapping into a :class:`RuleCondition`.

    Recursive: the aggregator forms (``all`` / ``any`` / ``not``) loop
    back through this same function on each child. ``path`` is a dotted
    breadcrumb used in error messages so authors can find the offending
    node when the rule has nested conditions.
    """
    if not isinstance(raw, dict):
        raise RuleParseError(f"{path}: expected a mapping, got {type(raw).__name__}")

    # Aggregator forms first — they win over leaf detection so a
    # mapping like ``{all: [...], field: 'x'}`` isn't ambiguous.
    for key in ("all", "any", "not"):
        if key in raw:
            children_raw = raw[key]
            if key == "not":
                if not isinstance(children_raw, dict):
                    raise RuleParseError(f"{path}.not: expected a mapping for the negated condition")
                child = _parse_condition(children_raw, path=f"{path}.not")
                return RuleCondition(logical="not", children=(child,))
            if not isinstance(children_raw, list) or not children_raw:
                raise RuleParseError(f"{path}.{key}: must be a non-empty list of conditions")
            children = tuple(_parse_condition(c, path=f"{path}.{key}[{i}]") for i, c in enumerate(children_raw))
            return RuleCondition(logical=key, children=children)

    # Leaf form
    field_name = raw.get("field")
    op = raw.get("op")
    if field_name is None or op is None:
        raise RuleParseError(f"{path}: leaf condition must include 'field' and 'op' (got {sorted(raw.keys())})")
    if not isinstance(field_name, str) or not field_name:
        raise RuleParseError(f"{path}.field: must be a non-empty string")
    if op not in ALLOWED_OPS:
        raise RuleParseError(f"{path}.op: {op!r} is not one of {sorted(ALLOWED_OPS)}")

    # ``exists`` / ``not_exists`` are unary — value is ignored if present.
    if op in {"exists", "not_exists"}:
        return RuleCondition(field=field_name, op=op, value=None)

    if "value" not in raw:
        raise RuleParseError(f"{path}.value: required for op={op!r}")
    value = raw["value"]
    # ``in`` / ``not_in`` require a sequence; coerce single string to a
    # one-element list to be analyst-friendly.
    if op in {"in", "not_in"}:
        if isinstance(value, str | bytes):
            value = [value]
        if not isinstance(value, list | tuple) or not value:
            raise RuleParseError(f"{path}.value: op={op!r} requires a non-empty list")
        value = list(value)
    return RuleCondition(field=field_name, op=op, value=value)


def _parse_action(raw: Any, *, rule_id: str) -> RuleAction:
    if not isinstance(raw, dict):
        raise RuleParseError(f"rule {rule_id!r}: 'then' must be a mapping (got {type(raw).__name__})")

    sev = raw.get("set_severity")
    if sev is not None:
        if not isinstance(sev, str) or sev not in ALLOWED_SEVERITIES:
            raise RuleParseError(f"rule {rule_id!r}: 'set_severity' must be one of {ALLOWED_SEVERITIES}")

    route = raw.get("route_to")
    if route is not None:
        if not isinstance(route, str) or route not in ALLOWED_ROUTES:
            raise RuleParseError(f"rule {rule_id!r}: 'route_to' must be one of {sorted(ALLOWED_ROUTES)}")

    tag = raw.get("tag")
    if tag is not None:
        if not isinstance(tag, str) or not _TAG_RE.match(tag):
            raise RuleParseError(f"rule {rule_id!r}: 'tag' must be a kebab-case slug (got {tag!r})")

    suppress = raw.get("suppress", False)
    if not isinstance(suppress, bool):
        raise RuleParseError(f"rule {rule_id!r}: 'suppress' must be a boolean (got {type(suppress).__name__})")

    return RuleAction(
        set_severity=sev,
        route_to=route,
        tag=tag,
        suppress=suppress,
    )


def _parse_one_rule(raw: Any, *, source_yaml: str) -> BusinessContextRule:
    if not isinstance(raw, dict):
        raise RuleParseError(f"top-level rule must be a mapping, got {type(raw).__name__}")

    rid = raw.get("id")
    if not isinstance(rid, str) or not _RULE_ID_RE.match(rid):
        raise RuleParseError("rule.id must be a kebab-case slug 3-63 chars (e.g. 'prod-iam-critical')")

    description = raw.get("description", "") or ""
    if not isinstance(description, str):
        raise RuleParseError(f"rule {rid!r}: 'description' must be a string")

    when_raw = raw.get("when")
    if when_raw is None:
        raise RuleParseError(f"rule {rid!r}: 'when' clause is required")
    when = _parse_condition(when_raw, path=f"rule[{rid}].when")

    then_raw = raw.get("then")
    if then_raw is None:
        raise RuleParseError(f"rule {rid!r}: 'then' clause is required")
    then = _parse_action(then_raw, rule_id=rid)
    if then.is_noop():
        raise RuleParseError(f"rule {rid!r}: 'then' clause must set at least one of " "set_severity / route_to / tag / suppress")

    enabled = raw.get("enabled", True)
    if not isinstance(enabled, bool):
        raise RuleParseError(f"rule {rid!r}: 'enabled' must be a boolean")

    priority = raw.get("priority", 100)
    if not isinstance(priority, int) or not 0 <= priority <= 1000:
        raise RuleParseError(f"rule {rid!r}: 'priority' must be an int in [0, 1000]")

    return BusinessContextRule(
        id=rid,
        description=description,
        when=when,
        then=then,
        enabled=enabled,
        priority=priority,
        raw_yaml=source_yaml,
    )


def load_rules_from_yaml(source: str) -> list[BusinessContextRule]:
    """Parse a YAML document into a list of rules.

    Accepts either a single rule mapping or a top-level ``rules:`` list:

    .. code-block:: yaml

        rules:
          - id: rule-a
            ...
          - id: rule-b
            ...

    The single-mapping form is convenient when authoring a rule one at
    a time in the Monaco editor; the list form is what the API stores
    on the tenant after all rules have been concatenated.

    Duplicate IDs are rejected (the engine keys on ``id``); empty input
    returns an empty list (an analyst clearing the editor is a valid
    "disable all rules" action).
    """
    if not isinstance(source, str):
        raise RuleParseError("YAML source must be a string")
    text = source.strip()
    if not text:
        return []

    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise RuleParseError(f"YAML parse error: {exc}") from exc

    if data is None:
        return []
    if isinstance(data, dict) and "rules" in data:
        rules_raw = data["rules"]
        if not isinstance(rules_raw, list):
            raise RuleParseError("'rules' must be a list")
    elif isinstance(data, list):
        rules_raw = data
    elif isinstance(data, dict):
        # Single-rule shorthand.
        rules_raw = [data]
    else:
        raise RuleParseError(f"top-level YAML must be a list or mapping, got {type(data).__name__}")

    parsed: list[BusinessContextRule] = []
    seen_ids: set[str] = set()
    for raw in rules_raw:
        rule = _parse_one_rule(raw, source_yaml=text)
        if rule.id in seen_ids:
            raise RuleParseError(f"duplicate rule id {rule.id!r} (rule ids must be unique)")
        seen_ids.add(rule.id)
        parsed.append(rule)

    return parsed
