"""Business-context rules in the auto-triage hot path (Phase B4).

The leading AI-SOCs win a lot of their "80% noise reduction" from
*environment-specific* rules: suppress alerts during a known maintenance
window, bump severity for production assets, route cloud alerts to the cloud
team. AiSOC has a Business Context Rules **engine + authoring UI** in
``services/api``, but it was never applied on the live path — it only ran in a
dry-run preview. This module applies it post-fusion → pre-triage.

Placement: the auto-triage worker (``fused_alert_consumer.triage``) is exactly
the post-fusion → pre-triage seam. A **suppress** rule drops the alert before
any (possibly LLM) triage spend; **severity / route / tag** rules mutate the
alert the agent then reasons over.

Why a self-contained evaluator here rather than importing the API engine: the
agents service image ships only its own ``app/`` subtree, so it can't import
``services/api``. This module re-implements the same small, documented
``when`` (dotted-path + comparators + all/any/not) / ``then``
(set_severity / route_to / tag / suppress) semantics, loads rules from a YAML
file (``AISOC_BUSINESS_CONTEXT_RULES_FILE``), and is unit-tested against those
semantics. (Unifying both call sites behind a shared package is a follow-up.)

Everything is fail-soft: a missing/invalid rules file or a bad rule degrades to
"no business context applied", never an error into triage.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from dataclasses import field as dc_field
from pathlib import Path
from typing import Any

import structlog
import yaml

logger = structlog.get_logger()

_ALLOWED_SEVERITIES = {"info", "low", "medium", "high", "critical"}
_ENABLED_ENV = "AISOC_BUSINESS_CONTEXT_ENABLED"
_RULES_FILE_ENV = "AISOC_BUSINESS_CONTEXT_RULES_FILE"


def is_enabled() -> bool:
    """Default-on; disable with AISOC_BUSINESS_CONTEXT_ENABLED=0."""
    raw = os.environ.get(_ENABLED_ENV)
    if raw is None:
        return True
    return raw.strip().lower() not in {"0", "false", "no", "off"}


# ── Rule model (faithful to services/api business_context) ────────────────────


@dataclass(frozen=True)
class RuleAction:
    set_severity: str | None = None
    route_to: str | None = None
    tag: str | None = None
    suppress: bool = False


@dataclass(frozen=True)
class RuleCondition:
    field: str | None = None
    op: str | None = None
    value: Any = None
    logical: str | None = None  # "all" | "any" | "not"
    children: tuple[RuleCondition, ...] = dc_field(default_factory=tuple)


@dataclass(frozen=True)
class BusinessContextRule:
    id: str
    when: RuleCondition
    then: RuleAction
    enabled: bool = True
    priority: int = 100


def _dotted(alert: dict[str, Any], path: str) -> Any:
    cur: Any = alert
    for part in path.split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
    return cur


def _cmp(op: str, actual: Any, expected: Any) -> bool:  # noqa: PLR0911
    try:
        if op == "eq":
            return actual == expected
        if op == "ne":
            return actual != expected
        if op == "lt":
            return actual < expected
        if op == "lte":
            return actual <= expected
        if op == "gt":
            return actual > expected
        if op == "gte":
            return actual >= expected
        if op == "contains":
            return expected in actual if actual is not None else False
        if op == "startswith":
            return isinstance(actual, str) and actual.startswith(str(expected))
        if op == "endswith":
            return isinstance(actual, str) and actual.endswith(str(expected))
        if op == "in":
            return actual in expected if isinstance(expected, list) else False
        if op == "not_in":
            return actual not in expected if isinstance(expected, list) else False
        if op == "exists":
            return actual is not None
        if op == "not_exists":
            return actual is None
    except TypeError:
        return False
    return False


def evaluate_condition(cond: RuleCondition, alert: dict[str, Any]) -> bool:
    if cond.logical == "all":
        return all(evaluate_condition(c, alert) for c in cond.children)
    if cond.logical == "any":
        return any(evaluate_condition(c, alert) for c in cond.children)
    if cond.logical == "not":
        return not any(evaluate_condition(c, alert) for c in cond.children)
    if cond.field and cond.op:
        return _cmp(cond.op, _dotted(alert, cond.field), cond.value)
    return False


def _parse_condition(node: dict[str, Any]) -> RuleCondition:
    for logical in ("all", "any", "not"):
        if logical in node:
            kids = node[logical] or []
            return RuleCondition(logical=logical, children=tuple(_parse_condition(k) for k in kids))
    return RuleCondition(field=node.get("field"), op=node.get("op"), value=node.get("value"))


def load_rules_from_yaml(source: str) -> list[BusinessContextRule]:
    """Parse rules YAML (single mapping or top-level ``rules:`` list)."""
    if not source or not source.strip():
        return []
    doc = yaml.safe_load(source)
    if doc is None:
        return []
    raw_rules = doc.get("rules", doc) if isinstance(doc, dict) else doc
    if isinstance(raw_rules, dict):
        raw_rules = [raw_rules]
    rules: list[BusinessContextRule] = []
    seen: set[str] = set()
    for entry in raw_rules or []:
        if not isinstance(entry, dict) or "id" not in entry:
            continue
        rid = str(entry["id"])
        if rid in seen:
            continue
        seen.add(rid)
        action = entry.get("then") or {}
        sev = action.get("set_severity")
        if sev is not None and sev not in _ALLOWED_SEVERITIES:
            sev = None
        rules.append(
            BusinessContextRule(
                id=rid,
                when=_parse_condition(entry.get("when") or {}),
                then=RuleAction(
                    set_severity=sev,
                    route_to=action.get("route_to"),
                    tag=action.get("tag"),
                    suppress=bool(action.get("suppress", False)),
                ),
                enabled=bool(entry.get("enabled", True)),
                priority=int(entry.get("priority", 100)),
            )
        )
    return rules


@dataclass
class BusinessContextResult:
    alert: dict[str, Any]
    matched_rule_ids: list[str]
    suppressed: bool
    severity_before: Any
    severity_after: Any

    @property
    def changed(self) -> bool:
        return self.suppressed or bool(self.matched_rule_ids)


def apply_rules(alert: dict[str, Any], rules: list[BusinessContextRule]) -> BusinessContextResult:
    """Apply enabled rules (priority order) to a copy of ``alert``.

    Suppress short-circuits (once suppressed, downstream rules can't un-suppress),
    matching the API engine's deterministic contract.
    """
    out = dict(alert)
    severity_before = out.get("severity")
    matched: list[str] = []
    for rule in sorted((r for r in rules if r.enabled), key=lambda r: (r.priority, r.id)):
        if not evaluate_condition(rule.when, out):
            continue
        matched.append(rule.id)
        act = rule.then
        if act.set_severity is not None:
            out["severity"] = act.set_severity
        if act.route_to is not None:
            out["route_to"] = act.route_to
        if act.tag is not None:
            tags = list(out.get("tags") or [])
            if act.tag not in tags:
                tags.append(act.tag)
            out["tags"] = tags
        if act.suppress:
            out["__suppressed__"] = True
            return BusinessContextResult(out, matched, True, severity_before, out.get("severity"))
    return BusinessContextResult(out, matched, False, severity_before, out.get("severity"))


class BusinessContextApplier:
    """Loads rules from a YAML file (mtime-reloaded) and applies them."""

    def __init__(self, rules_file: str | None = None) -> None:
        self._path = rules_file or os.environ.get(_RULES_FILE_ENV, "")
        self._rules: list[BusinessContextRule] = []
        self._mtime: float | None = None
        self._load()

    def _load(self) -> None:
        if not self._path:
            self._rules = []
            return
        try:
            p = Path(self._path)
            if not p.exists():
                self._rules = []
                return
            mtime = p.stat().st_mtime
            if mtime == self._mtime:
                return
            self._rules = load_rules_from_yaml(p.read_text(encoding="utf-8"))
            self._mtime = mtime
            logger.info("business_context.rules_loaded", count=len(self._rules), path=self._path)
        except Exception as exc:  # noqa: BLE001 — fail-soft: no rules applied
            logger.warning("business_context.load_failed", error=str(exc), path=self._path)
            self._rules = []

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    def apply(self, alert: dict[str, Any]) -> BusinessContextResult:
        self._load()  # cheap mtime check; reload only when the file changed
        if not self._rules:
            return BusinessContextResult(dict(alert), [], False, alert.get("severity"), alert.get("severity"))
        try:
            return apply_rules(alert, self._rules)
        except Exception as exc:  # noqa: BLE001 — never break triage
            logger.warning("business_context.apply_failed", error=str(exc))
            return BusinessContextResult(dict(alert), [], False, alert.get("severity"), alert.get("severity"))
