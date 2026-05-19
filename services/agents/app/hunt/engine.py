"""Hunt engine — match YAML hypotheses against a stream of events.

The engine is intentionally small and deterministic so it can run inside the
eval harness without a live event warehouse. ``run`` takes any iterable of
JSON-shaped events (one per row) and returns a :class:`HuntRunResult`
containing the findings the indicators matched.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from .loader import HuntDefinition, HuntIndicator

logger = logging.getLogger("aisoc.hunt.engine")


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass
class HuntFindingDraft:
    """A single hunt match. Persisted via ``store.record_finding``."""

    hunt_id: str
    severity: str
    title: str
    summary: str
    evidence: dict[str, Any]
    primary_entity: str | None
    primary_log_source: str | None
    match_score: float
    mitre_techniques: list[str] = field(default_factory=list)


@dataclass
class HuntRunResult:
    hunt_id: str
    events_scanned: int
    findings: list[HuntFindingDraft]
    match_score: float  # 0.0..1.0 — best individual match in this run
    error: str | None = None


# ---------------------------------------------------------------------------
# Indicator matching
# ---------------------------------------------------------------------------


def _get_field(event: dict[str, Any], dotted: str) -> Any:
    """Resolve ``a.b.c`` against an event dict; missing keys -> ``None``."""
    cur: Any = event
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _coerce_number(value: Any) -> float | None:
    if isinstance(value, bool):  # bool is a subclass of int — exclude on purpose
        return None
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def _indicator_matches(event: dict[str, Any], ind: HuntIndicator) -> bool:
    val = _get_field(event, ind.field)

    if ind.exists is not None:
        present = val is not None
        return present == ind.exists

    if val is None:
        return False

    if ind.equals is not None:
        return val == ind.equals

    if ind.in_ is not None:
        return val in ind.in_

    if ind.regex is not None:
        try:
            return re.search(ind.regex, str(val)) is not None
        except re.error:
            return False

    if ind.gte is not None:
        num = _coerce_number(val)
        return num is not None and num >= ind.gte

    if ind.lte is not None:
        num = _coerce_number(val)
        return num is not None and num <= ind.lte

    if ind.contains_any is not None:
        if isinstance(val, list | tuple | set):
            haystack = list(val)
        else:
            haystack = [val]
        return any(needle in haystack for needle in ind.contains_any)

    if ind.iendswith is not None:
        return str(val).lower().endswith(ind.iendswith.lower())

    # Indicator with only a ``field`` is treated as ``exists: true``.
    return True


def _match_event(event: dict[str, Any], hunt: HuntDefinition) -> tuple[bool, float]:
    """Return ``(matched, score)`` for one event against one hunt.

    Score is the fraction of indicators that fired. A hunt with zero
    indicators is treated as a no-op and never matches.
    """
    indicators = hunt.hypothesis.indicators
    if not indicators:
        return False, 0.0
    hits = sum(1 for ind in indicators if _indicator_matches(event, ind))
    score = hits / len(indicators)
    matched = hits == len(indicators)
    return matched, score


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


_PRIMARY_ENTITY_FIELDS = (
    "TargetUserName",
    "user_name",
    "user",
    "principalEmail",
    "actor",
    "actor.id",
    "src_ip",
    "src",
    "asset_id",
    "computer_name",
    "host",
    "user_id",
)


def _pick_primary_entity(event: dict[str, Any]) -> str | None:
    for f in _PRIMARY_ENTITY_FIELDS:
        v = _get_field(event, f)
        if v:
            return str(v)
    return None


def _pick_log_source(event: dict[str, Any], hunt: HuntDefinition) -> str | None:
    src = event.get("source") or event.get("log_source")
    if src:
        return str(src)
    return hunt.log_sources[0] if hunt.log_sources else None


class HuntEngine:
    """Stateless matcher. ``run`` iterates events once and returns findings."""

    def __init__(self, *, max_findings_per_run: int = 50) -> None:
        self._cap = max_findings_per_run

    def run(
        self,
        hunt: HuntDefinition,
        events: Iterable[dict[str, Any]],
    ) -> HuntRunResult:
        findings: list[HuntFindingDraft] = []
        events_scanned = 0
        best_score = 0.0

        for event in events:
            events_scanned += 1
            matched, score = _match_event(event, hunt)
            if score > best_score:
                best_score = score
            if not matched:
                continue
            if len(findings) >= self._cap:
                continue
            findings.append(self._draft_finding(hunt, event, score))

        return HuntRunResult(
            hunt_id=hunt.id,
            events_scanned=events_scanned,
            findings=findings,
            match_score=best_score,
        )

    def _draft_finding(
        self,
        hunt: HuntDefinition,
        event: dict[str, Any],
        score: float,
    ) -> HuntFindingDraft:
        primary_entity = _pick_primary_entity(event)
        log_source = _pick_log_source(event, hunt)
        title = f"{hunt.name} matched {primary_entity}" if primary_entity else hunt.name
        summary = hunt.hypothesis.question.strip() or hunt.description.strip() or hunt.name
        return HuntFindingDraft(
            hunt_id=hunt.id,
            severity=hunt.severity,
            title=title,
            summary=summary,
            evidence={
                "matched_event": event,
                "indicators": [ind.model_dump(by_alias=True) for ind in hunt.hypothesis.indicators],
                "match_score": round(score, 3),
            },
            primary_entity=primary_entity,
            primary_log_source=log_source,
            match_score=round(score, 3),
            mitre_techniques=hunt.mitre_techniques,
        )
