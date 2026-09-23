"""Stateful / windowed detection engine (Wave 2).

The live :class:`app.services.detection_engine.DetectionEngine` is stateless: it
matches one event at a time. Whole classes of real attacks are only visible
across MULTIPLE events in a time window — brute force, password spray, port
scans, data-staging bursts. This engine adds sliding-window threshold detection:
count events matching a rule, grouped by an entity, and fire once when the count
crosses a threshold inside the window.

State lives in Redis sorted sets (member = event id, score = epoch seconds) so
the window is a cheap ``ZREMRANGEBYSCORE`` + ``ZCARD``, and a short-lived
"fired" marker suppresses duplicate alerts for the same window. Everything is
fail-soft: a Redis outage degrades to "windowed detections are skipped for the
outage", never crashing the fusion pipeline.

Only security-relevant bursts fire — a benign event that doesn't match a rule's
``match_when`` never even touches Redis.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import structlog

from app.models.alert import AlertSeverity, RawAlert
from app.services.detection_engine import DetectionHit
from app.services.detection_matcher import matches
from app.services.provenance import extract_provenance

logger = structlog.get_logger()

_SEVERITY_MAP = {
    "critical": AlertSeverity.CRITICAL,
    "high": AlertSeverity.HIGH,
    "medium": AlertSeverity.MEDIUM,
    "low": AlertSeverity.LOW,
    "info": AlertSeverity.INFO,
}


@dataclass(frozen=True)
class WindowRule:
    id: str
    name: str
    severity: str
    category: str
    mitre: list[str]
    # Selects the events this rule counts (evaluated against recovered flat fields).
    match_when: dict[str, Any]
    # Flat field whose value is the entity the count is grouped by.
    group_by: str
    threshold: int
    window_seconds: int
    # When set, count DISTINCT values of this field rather than events.
    #
    # "Fifty requests from one source" and "fifty *different* secrets read by
    # one principal" are different detections, and the second is the one that
    # says enumeration. Counting events conflates a script retrying once with
    # a script walking a vault: the first is noise, the second is the
    # incident. Twenty-one of the rules the reachability gate lists as
    # needing a windowed evaluator name a `distinct_*` field, so without this
    # they had nowhere to go even after the engine existed.
    distinct_by: str = ""


# Built-in windowed rules. Intentionally small + high-signal; the corpus can grow
# via the same JSON export path as the stateless engine later.
_BUILTIN_RULES: tuple[WindowRule, ...] = (
    WindowRule(
        id="wd-bruteforce-auth",
        name="Brute-force: repeated authentication failures",
        severity="high",
        category="identity",
        mitre=["T1110"],
        # Un-suffixed fields are plain-equality clauses in the matcher DSL.
        match_when={"event_type": "authentication", "outcome": "failure"},
        group_by="user",
        threshold=5,
        window_seconds=600,
    ),
    WindowRule(
        id="wd-password-spray",
        name="Password spray: auth failures across many accounts from one source",
        severity="high",
        category="identity",
        mitre=["T1110.003"],
        match_when={"event_type": "authentication", "outcome": "failure"},
        group_by="src_ip",
        threshold=10,
        window_seconds=600,
    ),
    WindowRule(
        id="wd-port-scan",
        name="Port scan: many distinct connections from one source",
        severity="medium",
        category="network",
        mitre=["T1046"],
        match_when={"event_type": "network"},
        group_by="src_ip",
        threshold=50,
        window_seconds=120,
    ),
)


#: Windowed rules exported from the spec modules, mirroring the stateless
#: engine's `detection_ruleset.json`. Absent the file, only the builtins load.
#:
#: This exists because the windowed engine had three hardcoded rules and no way
#: to add a fourth without editing this module. That mattered beyond
#: inconvenience: a large share of the 2,005 quarantined Splunk rules are
#: `| stats count ... by` aggregations, which cannot be expressed in the
#: stateless `match_when` at all and have nowhere else to go. The quarantine
#: README now tells contributors to skip them "until it has one" — this is it.
_WINDOWED_RULESET_PATH = Path(__file__).resolve().parent.parent / "data" / "windowed_ruleset.json"


def load_window_rules(path: Path | None = None) -> tuple[WindowRule, ...]:
    """Builtins plus any exported windowed rules.

    Fail-soft by design: a missing or malformed ruleset yields the builtins
    rather than an empty corpus, because silently detecting nothing is worse
    than detecting only the high-signal three. A malformed entry is skipped
    individually so one bad rule cannot disable the rest.
    """
    target = path or _WINDOWED_RULESET_PATH
    if not target.exists():
        return _BUILTIN_RULES

    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except (ValueError, OSError) as exc:
        logger.warning("windowed_detection.ruleset_load_failed", path=str(target), error=str(exc))
        return _BUILTIN_RULES

    loaded: list[WindowRule] = list(_BUILTIN_RULES)
    seen = {rule.id for rule in _BUILTIN_RULES}
    for entry in payload.get("rules") or []:
        if not isinstance(entry, dict):
            continue
        rule_id = str(entry.get("id") or "")
        if not rule_id or rule_id in seen:
            continue
        try:
            rule = WindowRule(
                id=rule_id,
                name=str(entry["name"]),
                severity=str(entry["severity"]),
                category=str(entry["category"]),
                mitre=[str(m).upper() for m in entry.get("mitre") or []],
                match_when=dict(entry["match_when"]),
                group_by=str(entry["group_by"]),
                threshold=int(entry["threshold"]),
                window_seconds=int(entry["window_seconds"]),
                distinct_by=str(entry.get("distinct_by") or ""),
            )
        except (KeyError, TypeError, ValueError) as exc:
            logger.warning("windowed_detection.rule_skipped", rule_id=rule_id, error=str(exc))
            continue
        if rule.threshold < 1 or rule.window_seconds < 1:
            # A zero threshold fires on the first event, which is a stateless
            # rule wearing a windowed rule's clothes, and a zero window never
            # accumulates. Both are authoring mistakes, not policies.
            logger.warning("windowed_detection.rule_bounds_invalid", rule_id=rule_id)
            continue
        loaded.append(rule)
        seen.add(rule_id)

    logger.info("windowed_detection.ruleset_loaded", count=len(loaded), builtins=len(_BUILTIN_RULES))
    return tuple(loaded)


class WindowedDetectionEngine:
    """Redis-backed sliding-window threshold detections."""

    def __init__(self, redis: Any, rules: tuple[WindowRule, ...] | None = None, *, key_prefix: str = "aisoc:wd") -> None:
        self._redis = redis
        # None means "whatever is declared", so a deployment picks up exported
        # rules without a code change. An explicit tuple still wins, which is
        # what the tests rely on.
        self._rules = rules if rules is not None else load_window_rules()
        self._prefix = key_prefix

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    @staticmethod
    def _fields(message: dict[str, Any]) -> dict[str, Any]:
        """Flat field namespace, matching the stateless engine exactly.

        Carries the same fix: `raw_data` holds the connector's normalized dict
        and connectors put the untouched vendor payload one level down under
        `raw_event`, so a rule naming a vendor field read None and could never
        fire. Both engines must agree on the namespace, or a rule that works
        stateless would silently not work windowed.

        Connector-normalized keys win on collision, for the same reason: a
        connector that mapped a vendor's severity ladder onto AiSOC's five
        tiers must not have that undone by the raw vendor value.
        """
        ocsf = message.get("ocsf_event")
        if not isinstance(ocsf, dict):
            return {}
        fields = ocsf
        raw = ocsf.get("raw_data")
        if isinstance(raw, str) and raw.strip():
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, dict):
                    fields = parsed
            except (ValueError, TypeError):
                # raw_data isn't valid JSON — fall back to the OCSF envelope.
                pass
        nested = fields.get("raw_event")
        if isinstance(nested, dict):
            merged = {k: v for k, v in nested.items() if isinstance(k, str)}
            merged.update(fields)
            return merged
        return fields

    async def evaluate(self, message: dict[str, Any]) -> list[DetectionHit]:
        """Count this event into any matching window; return threshold-crossing hits."""
        ocsf = message.get("ocsf_event")
        if not isinstance(ocsf, dict):
            return []
        tenant = str(message.get("tenant_id") or ocsf.get("tenant_uid") or "")
        if not tenant:
            return []
        fields = self._fields(message)
        now = time.time()
        hits: list[DetectionHit] = []
        for rule in self._rules:
            try:
                if not matches(rule.match_when, fields):
                    continue
                entity = fields.get(rule.group_by)
                if not entity:
                    continue
                observed = str(entity)
                member: str | None = None
                if rule.distinct_by:
                    value = fields.get(rule.distinct_by)
                    if not value:
                        # A distinct rule with nothing to be distinct about
                        # must not fall back to counting events — that is a
                        # different, louder detection wearing this one's id.
                        continue
                    member = str(value)
                if await self._observe_and_check(rule, tenant, observed, now, member=member):
                    hits.append(
                        DetectionHit(
                            rule_id=rule.id,
                            name=rule.name,
                            severity=rule.severity,
                            category=rule.category,
                            mitre=list(rule.mitre),
                        )
                    )
            except Exception as exc:  # noqa: BLE001 — one rule/Redis error must not wedge detection
                logger.debug("windowed_detection.rule_error", rule=rule.id, error=str(exc))
        return hits

    async def _observe_and_check(
        self,
        rule: WindowRule,
        tenant: str,
        entity: str,
        now: float,
        *,
        member: str | None = None,
    ) -> bool:
        key = f"{self._prefix}:{tenant}:{rule.id}:{entity}"
        # A random member counts events; the observed value counts distinct
        # ones, because ZADD on an existing member updates its score instead
        # of adding a row. So the same sorted set serves both, and a repeated
        # value refreshes its recency rather than inflating the count.
        member = member if member is not None else uuid.uuid4().hex
        await self._redis.zadd(key, {member: now})
        await self._redis.zremrangebyscore(key, 0, now - rule.window_seconds)
        # Expire the key a window after the last event so idle entities are reaped.
        await self._redis.expire(key, rule.window_seconds + 60)
        count = await self._redis.zcard(key)
        if count < rule.threshold:
            return False
        # Fire once per window: a short-lived marker suppresses re-firing on every
        # subsequent event until the window rolls.
        fired_key = f"{key}:fired"
        already = await self._redis.set(fired_key, "1", nx=True, ex=rule.window_seconds)
        return bool(already)

    def build_alert(self, message: dict[str, Any], hit: DetectionHit) -> RawAlert | None:
        ocsf = message.get("ocsf_event") or {}
        tenant_raw = message.get("tenant_id") or ocsf.get("tenant_uid")
        try:
            tenant_id = uuid.UUID(str(tenant_raw))
        except (ValueError, TypeError):
            return None
        fields = self._fields(message)
        connector_id, connector_type, class_uid = extract_provenance(message, ocsf)
        return RawAlert(
            tenant_id=tenant_id,
            source=f"detection:{hit.rule_id}",
            title=hit.name,
            description=f"Windowed detection {hit.rule_id} ({hit.category}) crossed its threshold.",
            severity=_SEVERITY_MAP.get(hit.severity, AlertSeverity.MEDIUM),
            src_ip=fields.get("src_ip"),
            hostname=fields.get("hostname") or fields.get("host"),
            username=fields.get("user"),
            mitre_techniques=hit.mitre,
            raw_event=ocsf,
            connector_id=connector_id,
            connector_type=connector_type,
            ocsf_class_uid=class_uid,
            rule_id=hit.rule_id,
            rule_name=hit.name,
        )
