"""Business-context engine — evaluator + hot-reload + dry-run preview.

The engine is a pure-Python in-memory DAG: each rule's ``when`` is
compiled once into a flat predicate that maps an alert dict to True /
False, and matching rules are applied in priority order to produce a
mutated alert + a diff for the analyst UI.

Hot-reload contract
~~~~~~~~~~~~~~~~~~~

The CRUD endpoint persists the rule set as JSONB on
``business_context_rule_sets`` and bumps a ``version`` integer on every
save. The engine caches the parsed rule set keyed on ``(tenant_id,
version)``; the ``BusinessContextEngine.replace`` call swaps the cached
entry under a single lock so callers either see the pre-save or
post-save snapshot, never a torn intermediate. Callers are expected to
invoke ``replace`` from the same task that handled the write, so the
"save → preview" round-trip stays well under the 1s budget the task
spec requires.

Dry-run preview
~~~~~~~~~~~~~~~

The settings page wants to show "if I save this YAML, what would
happen to the last 100 alerts?" without persisting anything. We
expose :meth:`preview_against` which takes an arbitrary list of
alerts and returns one :class:`AlertEvaluation` per alert, with the
before / after severity / route + the list of matched rule ids.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

from .models import (
    BusinessContextRule,
    RuleAction,
    RuleCondition,
)

# ---------------------------------------------------------------------------
# Field accessor — flatten the alert into a dotted-path lookup.
# ---------------------------------------------------------------------------


def _resolve_field(alert: Mapping[str, Any], path: str) -> Any:
    """Walk a dotted path into ``alert``.

    Returns the sentinel :class:`_Missing` when the path does not exist
    (so ``exists`` / ``not_exists`` ops can distinguish a missing key
    from an explicit ``None``).
    """
    cur: Any = alert
    for part in path.split("."):
        if isinstance(cur, Mapping):
            if part not in cur:
                return _MISSING
            cur = cur[part]
        else:
            return _MISSING
    return cur


class _Missing:
    """Sentinel for missing dotted-path lookups."""

    def __bool__(self) -> bool:  # pragma: no cover - sentinel never coerced
        return False

    def __repr__(self) -> str:  # pragma: no cover - debug only
        return "<missing>"


_MISSING = _Missing()


# ---------------------------------------------------------------------------
# Predicate compilation
# ---------------------------------------------------------------------------


def _eval_op(op: str, lhs: Any, rhs: Any) -> bool:
    """Apply one comparator. Missing LHS short-circuits to False except
    for the unary ``exists`` / ``not_exists`` ops, which are handled by
    the caller.
    """
    if op == "eq":
        return lhs == rhs
    if op == "ne":
        return lhs != rhs
    if op == "lt":
        try:
            return lhs < rhs
        except TypeError:
            return False
    if op == "lte":
        try:
            return lhs <= rhs
        except TypeError:
            return False
    if op == "gt":
        try:
            return lhs > rhs
        except TypeError:
            return False
    if op == "gte":
        try:
            return lhs >= rhs
        except TypeError:
            return False
    if op == "contains":
        try:
            return rhs in lhs
        except TypeError:
            return False
    if op == "startswith":
        return isinstance(lhs, str) and isinstance(rhs, str) and lhs.startswith(rhs)
    if op == "endswith":
        return isinstance(lhs, str) and isinstance(rhs, str) and lhs.endswith(rhs)
    if op == "in":
        return lhs in rhs if isinstance(rhs, list | tuple | set) else False
    if op == "not_in":
        return lhs not in rhs if isinstance(rhs, list | tuple | set) else False
    return False


def evaluate_condition(cond: RuleCondition, alert: Mapping[str, Any]) -> bool:
    """Recursively evaluate a parsed condition against an alert dict.

    Exposed at module scope so the dry-run preview can inspect *which*
    sub-conditions matched if we ever expose that in the UI; today
    callers should prefer :meth:`BusinessContextEngine.evaluate`.
    """
    # Aggregator forms
    if cond.logical == "all":
        return all(evaluate_condition(c, alert) for c in cond.children)
    if cond.logical == "any":
        return any(evaluate_condition(c, alert) for c in cond.children)
    if cond.logical == "not":
        return not evaluate_condition(cond.children[0], alert)

    # Leaf form
    assert cond.field is not None and cond.op is not None
    val = _resolve_field(alert, cond.field)
    if cond.op == "exists":
        return val is not _MISSING
    if cond.op == "not_exists":
        return val is _MISSING
    if val is _MISSING:
        return False
    return _eval_op(cond.op, val, cond.value)


# ---------------------------------------------------------------------------
# Per-alert evaluation result
# ---------------------------------------------------------------------------


@dataclass
class AlertEvaluation:
    """One alert's before/after result rendered by the dry-run preview.

    ``alert_id`` is opaque (whatever ``id`` field was on the input
    alert); the UI uses it to row-key the table. ``before`` and
    ``after`` are the *materialised* state — the UI compares severity /
    route_to / tags / suppressed flags directly without re-deriving the
    diff itself.
    """

    alert_id: str
    matched_rule_ids: list[str] = field(default_factory=list)
    before: dict[str, Any] = field(default_factory=dict)
    after: dict[str, Any] = field(default_factory=dict)
    suppressed: bool = False

    @property
    def changed(self) -> bool:
        """True when this alert was mutated (or suppressed)."""
        if self.suppressed:
            return True
        return self.before != self.after


# ---------------------------------------------------------------------------
# Compiled snapshot — what we cache per tenant.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EngineSnapshot:
    """Frozen snapshot of one tenant's rule set after parsing.

    The snapshot is what the hot path holds onto; ``BusinessContextEngine``
    swaps the snapshot pointer atomically on hot-reload so an in-flight
    eval never sees a half-updated rule list.
    """

    tenant_id: UUID
    version: int
    rules: tuple[BusinessContextRule, ...]
    field_index: dict[str, tuple[str, ...]]
    """Reverse index: field path → ids of rules that depend on it.

    Currently informational (used by the UI builder to surface "this
    field is referenced by X rules"); the evaluator iterates rules in
    priority order rather than walking the index, which keeps the hot
    path branch-free and predictable in the Nrules×Nalerts profile.
    """

    @property
    def enabled_rules(self) -> tuple[BusinessContextRule, ...]:
        return tuple(r for r in self.rules if r.enabled)


def _compile_snapshot(tenant_id: UUID, version: int, rules: Iterable[BusinessContextRule]) -> EngineSnapshot:
    sorted_rules = tuple(sorted(rules, key=lambda r: (r.priority, r.id)))
    idx: dict[str, list[str]] = {}
    for r in sorted_rules:
        for f in r.when.fields_referenced():
            idx.setdefault(f, []).append(r.id)
    return EngineSnapshot(
        tenant_id=tenant_id,
        version=version,
        rules=sorted_rules,
        field_index={k: tuple(v) for k, v in idx.items()},
    )


# ---------------------------------------------------------------------------
# Action application
# ---------------------------------------------------------------------------


def _apply_action(alert: dict[str, Any], action: RuleAction) -> dict[str, Any]:
    """Return a mutated copy of ``alert``.

    Mutations layer rather than overwrite — multiple matching rules
    each contribute their action; the *last* (highest priority number)
    win for severity / route_to so an analyst can express "default to
    medium, but bump to critical for prod". Tags accumulate.
    """
    out = dict(alert)
    if action.set_severity is not None:
        out["severity"] = action.set_severity
    if action.route_to is not None:
        out["route_to"] = action.route_to
    if action.tag is not None:
        existing = list(out.get("tags") or [])
        if action.tag not in existing:
            existing.append(action.tag)
        out["tags"] = existing
    if action.suppress:
        out["__suppressed__"] = True
    return out


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class BusinessContextEngine:
    """Per-process registry of compiled rule snapshots, keyed by tenant.

    Designed to be a process-singleton (the FastAPI app caches one) so
    every request sees the same rule set and a single ``replace`` call
    is sufficient to roll the whole pool to a new version. Thread-safe
    via a single lock guarding the snapshot dict; reads grab the
    snapshot pointer once and then operate on the immutable
    :class:`EngineSnapshot` without holding the lock, so hot-path
    contention is bounded.
    """

    def __init__(self) -> None:
        self._snapshots: dict[UUID, EngineSnapshot] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Snapshot management
    # ------------------------------------------------------------------

    def replace(
        self,
        tenant_id: UUID,
        rules: Iterable[BusinessContextRule],
        *,
        version: int | None = None,
    ) -> EngineSnapshot:
        """Atomically swap the rule set for ``tenant_id``.

        Returns the new snapshot so the caller can confirm what landed
        (useful for the "save → preview" round-trip).
        """
        with self._lock:
            old = self._snapshots.get(tenant_id)
            new_version = version if version is not None else (old.version + 1 if old else 1)
            snap = _compile_snapshot(tenant_id, new_version, rules)
            self._snapshots[tenant_id] = snap
            return snap

    def snapshot_for(self, tenant_id: UUID) -> EngineSnapshot | None:
        """Read the current snapshot without holding the lock."""
        return self._snapshots.get(tenant_id)

    def clear(self, tenant_id: UUID | None = None) -> None:
        """Forget cached snapshots — used by tests + the "delete all
        rules" path."""
        with self._lock:
            if tenant_id is None:
                self._snapshots.clear()
            else:
                self._snapshots.pop(tenant_id, None)

    # ------------------------------------------------------------------
    # Hot path: evaluate one alert against the cached snapshot.
    # ------------------------------------------------------------------

    def evaluate(
        self,
        tenant_id: UUID,
        alert: Mapping[str, Any],
    ) -> AlertEvaluation:
        """Run the rules registered for ``tenant_id`` against ``alert``.

        ``alert`` may carry an ``id`` field (used for the response
        ``alert_id``); otherwise an empty string is returned, matching
        the dry-run preview wire shape.
        """
        snap = self.snapshot_for(tenant_id)
        before = _projection(alert)
        result = AlertEvaluation(
            alert_id=str(alert.get("id", "")),
            before=dict(before),
            after=dict(before),
        )

        if snap is None:
            return result

        current = dict(alert)
        for rule in snap.enabled_rules:
            if not evaluate_condition(rule.when, current):
                continue
            current = _apply_action(current, rule.then)
            result.matched_rule_ids.append(rule.id)
            if current.get("__suppressed__"):
                # Once an alert is suppressed, downstream rules can't
                # un-suppress — short-circuit so the final state is
                # deterministic.
                result.suppressed = True
                result.after = _projection(current)
                return result

        result.after = _projection(current)
        return result

    # ------------------------------------------------------------------
    # Dry-run preview (Settings page)
    # ------------------------------------------------------------------

    def preview_against(
        self,
        tenant_id: UUID,
        alerts: Iterable[Mapping[str, Any]],
        *,
        rules: Iterable[BusinessContextRule] | None = None,
    ) -> list[AlertEvaluation]:
        """Run a (possibly hypothetical) rule set against ``alerts``.

        When ``rules`` is provided, the engine builds a *transient*
        snapshot for the duration of the call and never registers it.
        This is the path the settings page hits on every keystroke
        debounce: "show me what these unsaved YAML rules would do to
        the last 100 alerts." Latency per call is bounded by
        Nrules×Nalerts × O(condition complexity), which for the spec'd
        50-alert preview easily fits inside the 1s budget.
        """
        if rules is None:
            return [self.evaluate(tenant_id, a) for a in alerts]

        # Build a transient snapshot and evaluate against it directly
        # (don't mutate ``self._snapshots``). Use a sentinel version
        # of -1 so anything that accidentally caches it can detect the
        # "preview-only" origin.
        transient = _compile_snapshot(tenant_id, version=-1, rules=rules)

        out: list[AlertEvaluation] = []
        for alert in alerts:
            before = _projection(alert)
            result = AlertEvaluation(
                alert_id=str(alert.get("id", "")),
                before=dict(before),
                after=dict(before),
            )
            current = dict(alert)
            for rule in transient.enabled_rules:
                if not evaluate_condition(rule.when, current):
                    continue
                current = _apply_action(current, rule.then)
                result.matched_rule_ids.append(rule.id)
                if current.get("__suppressed__"):
                    result.suppressed = True
                    break
            result.after = _projection(current)
            out.append(result)
        return out


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _projection(alert: Mapping[str, Any]) -> dict[str, Any]:
    """Pull the four fields the preview UI cares about out of an alert.

    Kept narrow on purpose — the alert payload itself can be many KB
    and the diff renderer only ever shows these four columns.
    """
    return {
        "severity": alert.get("severity"),
        "route_to": alert.get("route_to"),
        "tags": list(alert.get("tags") or []),
        "suppressed": bool(alert.get("__suppressed__", False)),
    }


# ---------------------------------------------------------------------------
# Process singleton
# ---------------------------------------------------------------------------


_default_engine: BusinessContextEngine | None = None


def get_engine() -> BusinessContextEngine:
    """Lazy process-singleton accessor."""
    global _default_engine
    if _default_engine is None:
        _default_engine = BusinessContextEngine()
    return _default_engine


def reset_engine_for_tests() -> None:
    """Reset the singleton — only safe in test code."""
    global _default_engine
    _default_engine = None


__all__ = [
    "AlertEvaluation",
    "BusinessContextEngine",
    "EngineSnapshot",
    "RuleAction",
    "evaluate_condition",
    "get_engine",
    "reset_engine_for_tests",
    "_apply_action",
    "_projection",
]


# ---------------------------------------------------------------------------
# Convenience timer for the API "save → preview" latency assertion. Imported
# by tests; cheap helper that sidesteps having to add an extra dependency.
# ---------------------------------------------------------------------------


def measure_evaluation_latency(
    engine: BusinessContextEngine,
    tenant_id: UUID,
    alerts: list[Mapping[str, Any]],
) -> float:
    """Return the wall-clock seconds taken to evaluate ``alerts`` once."""
    start = time.perf_counter()
    for a in alerts:
        engine.evaluate(tenant_id, a)
    return time.perf_counter() - start
