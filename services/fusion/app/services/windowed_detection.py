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
from app.services.derived_fields import enrich, parse_event_time, requested_derived_fields
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


@dataclass(frozen=True)
class SequenceRule:
    """A then B (then C) by the same entity, ordered by event time.

    A threshold cannot express an ordering, and the ordering is usually the
    detection: "fifty failed logons" is an attempt, "failed logons then a
    success for the same account" is a compromise. Every sequence detection in
    the corpus had nowhere to go, because the counting engine sees each event
    alone and remembers only how many there were.

    The stages are ordered and disjoint in time: a stage advances only from an
    earlier event *by event time*, and one event advances at most one stage,
    so a rule whose stages overlap still needs as many events as it has
    stages.
    """

    id: str
    name: str
    severity: str
    category: str
    mitre: list[str]
    #: Ordered selectors, one per stage. Two or more.
    sequence: tuple[dict[str, Any], ...]
    #: Flat field naming the entity every stage must share.
    group_by: str
    #: The whole sequence must fit in this, measured from the first stage.
    #: Measured from the first and not from the previous stage, so a slow
    #: drip cannot walk a sequence forward indefinitely.
    window_seconds: int
    #: When False the stages may occur in any order inside the window, which
    #: is what Sigma's `temporal` correlation means as against
    #: `temporal_ordered`. Kept as a flag on one rule type rather than a
    #: second type, because every other property — entity, window, staging,
    #: one-event-one-stage — is identical and duplicating them is how the two
    #: drift apart.
    ordered: bool = True


#: How far out of order an event may arrive and still be stitched into a
#: sequence. A connector polling a vendor delivers the vendor's order, not the
#: clock's, so arrival order is not evidence of event order — but holding
#: state forever to accommodate that would be a memory leak with a detection
#: attached. An event older than this relative to what the entity has already
#: shown is counted for its own stage and does not re-open an earlier one.
#:
#: The plan this implements says "with the existing watermark". There is no
#: watermark in this pipeline — the only ones in the tree belong to the
#: shadow-reconcile router and the dead-letter replay, which are unrelated
#: subsystems — so the bound is stated here rather than inherited from
#: something that does not exist.
SEQUENCE_REORDER_TOLERANCE_SECONDS = 300


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
        if entry.get("sequence"):
            # A sequence rule lives in the same artefact and is loaded by
            # `load_sequence_rules`. Skipped silently rather than warned
            # about: a warning per sequence rule on every boot would train
            # operators to ignore the log line that means something.
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


def load_sequence_rules(path: Path | None = None) -> tuple[SequenceRule, ...]:
    """Ordered-sequence rules from the same artefact.

    Fail-soft the same way the counting loader is, and for the same reason: a
    malformed entry is skipped individually so one authoring mistake cannot
    empty the corpus. There are no built-in sequences, so a missing file
    yields none — which is the honest answer rather than a fallback.
    """
    target = path or _WINDOWED_RULESET_PATH
    if not target.exists():
        return ()
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except (ValueError, OSError) as exc:
        logger.warning("windowed_detection.sequence_ruleset_load_failed", path=str(target), error=str(exc))
        return ()

    loaded: list[SequenceRule] = []
    seen: set[str] = set()
    for entry in payload.get("rules") or []:
        if not isinstance(entry, dict) or not entry.get("sequence"):
            continue
        rule_id = str(entry.get("id") or "")
        if not rule_id or rule_id in seen:
            continue
        try:
            stages = tuple(dict(stage) for stage in entry["sequence"])
            rule = SequenceRule(
                id=rule_id,
                name=str(entry["name"]),
                severity=str(entry["severity"]),
                category=str(entry["category"]),
                mitre=[str(m).upper() for m in entry.get("mitre") or []],
                sequence=stages,
                group_by=str(entry["group_by"]),
                window_seconds=int(entry["window_seconds"]),
                ordered=bool(entry.get("ordered", True)),
            )
        except (KeyError, TypeError, ValueError) as exc:
            logger.warning("windowed_detection.sequence_skipped", rule_id=rule_id, error=str(exc))
            continue
        if len(rule.sequence) < 2:
            # One stage is a stateless rule paying for Redis state.
            logger.warning("windowed_detection.sequence_too_short", rule_id=rule_id, stages=len(rule.sequence))
            continue
        if any(not stage for stage in rule.sequence):
            # An empty stage matches every event, so the sequence collapses
            # to whichever stages remain — a different detection under this
            # one's name.
            logger.warning("windowed_detection.sequence_stage_empty", rule_id=rule_id)
            continue
        if rule.window_seconds < 1:
            logger.warning("windowed_detection.sequence_bounds_invalid", rule_id=rule_id)
            continue
        loaded.append(rule)
        seen.add(rule_id)

    if loaded:
        logger.info("windowed_detection.sequence_ruleset_loaded", count=len(loaded))
    return tuple(loaded)


def _unordered_set_exists(observations: list[list[tuple[float, str]]], window_seconds: int) -> bool:
    """Is there one *distinct* event per stage inside one window, any order?

    The distinctness is the subtle half. Without it a single event matching
    every stage satisfies the rule on its own, which for an unordered
    correlation is not a near-miss but the common case: unordered stages are
    usually written as variations on one activity.
    """
    if not observations or any(not stage for stage in observations):
        return False
    merged = sorted({entry for stage in observations for entry in stage})
    for start in merged:
        window = [entry for entry in merged if start[0] <= entry[0] <= start[0] + window_seconds]
        # One event per stage, no event used twice: a bipartite matching,
        # small enough (stages are two or three) to settle by trying each
        # stage's candidates in turn.
        if _matching_exists([[e for e in stage if e in set(window)] for stage in observations], set()):
            return True
    return False


def _matching_exists(candidates: list[list[tuple[float, str]]], used: set[tuple[float, str]]) -> bool:
    if not candidates:
        return True
    for entry in candidates[0]:
        if entry in used:
            continue
        if _matching_exists(candidates[1:], used | {entry}):
            return True
    return False


def _chain_exists(observations: list[list[tuple[float, str]]], window_seconds: int) -> bool:
    """Is there one event per stage, strictly increasing, inside the window?

    Ordered by ``(event time, event token)``. The token is the tie-breaker and
    it is load-bearing rather than tidy: two distinct events routinely share a
    second, and one event that satisfies two stages must never complete a
    sequence by itself. Comparing times alone would allow both mistakes in
    opposite directions.

    Candidate starts are tried newest-first because the latest feasible start
    gives the tightest span, so the first chain found is the one most likely
    to fit the window.
    """
    if not observations or any(not stage for stage in observations):
        return False
    for start in reversed(observations[0]):
        cursor = start
        for stage in observations[1:]:
            nxt = next((entry for entry in stage if entry > cursor), None)
            if nxt is None:
                cursor = None  # type: ignore[assignment]
                break
            cursor = nxt
        if cursor is not None and cursor[0] - start[0] <= window_seconds:
            return True
    return False


class WindowedDetectionEngine:
    """Redis-backed sliding-window threshold detections."""

    def __init__(
        self,
        redis: Any,
        rules: tuple[WindowRule, ...] | None = None,
        *,
        sequences: tuple[SequenceRule, ...] | None = None,
        key_prefix: str = "aisoc:wd",
    ) -> None:
        self._redis = redis
        # None means "whatever is declared", so a deployment picks up exported
        # rules without a code change. An explicit tuple still wins, which is
        # what the tests rely on.
        self._rules = rules if rules is not None else load_window_rules()
        self._sequences = sequences if sequences is not None else load_sequence_rules()
        self._prefix = key_prefix
        # Same contract as the stateless engine: computed once at load,
        # because the set changes when rules change and not when traffic
        # arrives.
        clauses: list[dict[str, Any]] = [{"match_when": rule.match_when} for rule in self._rules]
        clauses += [{"match_when": stage} for rule in self._sequences for stage in rule.sequence]
        self._derived_wanted: set[str] = requested_derived_fields(clauses)

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    @property
    def sequence_count(self) -> int:
        return len(self._sequences)

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

    async def evaluate(self, message: dict[str, Any], overlay: Any | None = None) -> list[DetectionHit]:
        """Count this event into any matching window; return threshold-crossing hits."""
        ocsf = message.get("ocsf_event")
        if not isinstance(ocsf, dict):
            return []
        tenant = str(message.get("tenant_id") or ocsf.get("tenant_uid") or "")
        if not tenant:
            return []
        fields = self._fields(message)
        # The same two enrichment passes the stateless engine runs, for the
        # same reason it runs them. `_fields` has always claimed to match that
        # engine's namespace "exactly" and did not: it recovered the raw
        # fields and stopped, so a windowed rule reading `is_business_hours`
        # or a per-tenant `<x>_in_allowlist` boolean saw nothing and could not
        # fire. Two of the rules translated out of the stateless corpus carry
        # an allowlist clause, so without this they would have been moved from
        # one engine that could not fire them to another.
        fields = enrich(fields, self._derived_wanted)
        if overlay is not None:
            # Per tenant rather than in the shared pass: a global allowlist
            # would make one tenant's exceptions apply to everybody. An
            # unconfigured allowlist contributes no key at all rather than
            # False, because a `not_in_allowlist` clause against a missing key
            # is true for every event.
            derived = overlay.derived_allowlist_fields(fields)
            if derived:
                fields = {**fields, **derived}
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

        if self._sequences:
            # One token per event, shared by every stage it matches, so two
            # stages satisfied by the *same* event can never be mistaken for
            # two events. Timestamps alone cannot carry that: two genuinely
            # distinct events routinely share a second.
            token = uuid.uuid4().hex
            for sequence in self._sequences:
                try:
                    hit = await self._advance_sequence(sequence, tenant, fields, now, token)
                    if hit is not None:
                        hits.append(hit)
                except Exception as exc:  # noqa: BLE001 — same fail-soft contract
                    logger.debug("windowed_detection.sequence_error", rule=sequence.id, error=str(exc))
        return hits

    @staticmethod
    def _event_seconds(fields: dict[str, Any], now: float) -> float:
        """When the event happened, falling back to when we heard about it.

        Ordering a sequence by arrival would make it a different detection on
        every poll cadence, so event time wins wherever a source provides
        one. A source that stamps nothing must still be able to fire a
        sequence, which is what the fallback is for.
        """
        when = parse_event_time(fields)
        return when.timestamp() if when is not None else now

    async def _advance_sequence(
        self, rule: SequenceRule, tenant: str, fields: dict[str, Any], now: float, token: str
    ) -> DetectionHit | None:
        """Record what this event satisfies, then look for a complete chain.

        Recording first and searching second is what makes the ordering a
        property of **event time** rather than of arrival. The obvious
        implementation — a cursor that only moves forward as events arrive —
        is wrong for this platform: almost every connector here polls, so a
        batch arrives in the vendor's order and the event that starts a
        sequence routinely lands after the one that finishes it. That
        implementation would silently detect nothing on exactly the sources
        the corpus is thinnest on.
        """
        entity = fields.get(rule.group_by)
        if not entity:
            return None
        matched = [index for index, stage in enumerate(rule.sequence) if matches(stage, fields)]
        if not matched:
            return None

        when = self._event_seconds(fields, now)
        retain = rule.window_seconds + SEQUENCE_REORDER_TOLERANCE_SECONDS
        base = f"{self._prefix}:seq:{tenant}:{rule.id}:{entity}"

        for index in matched:
            key = f"{base}:{index}"
            await self._redis.zadd(key, {token: when})
            # Trimmed against this event's own time, not the wall clock: an
            # event that arrives late is old by construction, and trimming it
            # against now would discard the observation it just made.
            await self._redis.zremrangebyscore(key, 0, when - retain)
            await self._redis.expire(key, retain)

        observations: list[list[tuple[float, str]]] = []
        for index in range(len(rule.sequence)):
            entries = await self._redis.zrangebyscore(f"{base}:{index}", when - retain, when + retain, withscores=True)
            stage: list[tuple[float, str]] = []
            for member, score in entries or []:
                name = member.decode() if isinstance(member, bytes | bytearray) else str(member)
                stage.append((float(score), name))
            stage.sort()
            observations.append(stage)

        complete = (
            _chain_exists(observations, rule.window_seconds) if rule.ordered else _unordered_set_exists(observations, rule.window_seconds)
        )
        if not complete:
            return None
        if not await self._redis.set(f"{base}:fired", "1", nx=True, ex=rule.window_seconds):
            return None
        return DetectionHit(
            rule_id=rule.id,
            name=rule.name,
            severity=rule.severity,
            category=rule.category,
            mitre=list(rule.mitre),
        )

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
