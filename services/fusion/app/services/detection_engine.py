"""Live detection-evaluation engine (Phase A2).

The reality audit's second SIEM gap: ~939 executable detection rules existed
but only ran in CI fixture-replay — **nothing evaluated them against the live
event stream**, so telemetry that wasn't a vendor-asserted finding (the
promoter's job) never became an alert.

This engine closes that. It loads the exported native ruleset
(``app/data/detection_ruleset.json``, produced by
``scripts/export_detection_ruleset.py``) and evaluates each ingested event's
recovered raw fields against every relevant rule's ``match_when`` (via the
vendored :func:`app.services.detection_matcher.matches`). A match becomes a
:class:`DetectionHit` that the fusion consumer turns into a ``RawAlert`` and
routes through the normal dedup/correlate/persist pipeline.

Field alignment (verified against the normalizer): the ingest pipeline
preserves the connector-normalized flat event under ``ocsf_event["raw_data"]``
as a JSON string. The native ``match_when`` specs were authored against exactly
those flat connector fields, so ``matches(rule.match_when, json.loads(raw_data))``
is the correct evaluation contract.

Performance: parity plan 6.9 / depth plan 4.4. Events are routed through
``app.services.rule_index``, which maps an event's field *names* to the
rules that could possibly match it.

Not by log source, which is what the plan asks for and what this module
previously recorded as unsafe: connector product names do not line up
with spec products (``aws_cloudtrail`` against ``aws``,
``crowdstrike_falcon`` against ``edr``), a product-based pre-filter was
tried and reverted for silently dropping real matches, and a mapping
table would leave every new connector one missing entry away from a
detection that stops firing. The index is on required fields instead,
which is strictly more selective *and* provably lossless: ``match_when``
is an AND at the top level, so a rule that requires a field an event does
not carry cannot match it, whatever the product names say. ADR-0012
records the decision.

The engine is pure and synchronous; the consumer calls it inline.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import structlog

from app.models.alert import AlertSeverity, RawAlert
from app.services.derived_fields import enrich, requested_derived_fields
from app.services.detection_matcher import matches
from app.services.provenance import extract_provenance
from app.services.raw_data import decode_raw_data
from app.services.rule_index import RuleIndex

logger = structlog.get_logger()

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"
_RULESET_PATH = _DATA_DIR / "detection_ruleset.json"
#: Imported rules translated into `match_when` by `scripts/compile_sigma_ruleset.py`.
#: Held in a second file rather than merged into the one above so that the
#: exporter's drift check keeps comparing the hand-authored specs against
#: exactly what they generate. Both are loaded here, so "executable" still
#: means "the engine loads it".
_IMPORTED_RULESET_PATH = _DATA_DIR / "detection_ruleset_imported.json"

_SEVERITY_MAP = {
    "critical": AlertSeverity.CRITICAL,
    "high": AlertSeverity.HIGH,
    "medium": AlertSeverity.MEDIUM,
    "low": AlertSeverity.LOW,
    "info": AlertSeverity.INFO,
}


@dataclass(frozen=True)
class DetectionHit:
    rule_id: str
    name: str
    severity: str
    category: str
    mitre: list[str]
    #: Upstream credit for a rule translated from an imported corpus, empty for
    #: AiSOC's own. DRL-1.1 — which the imported Sigma corpus is licensed under
    #: — requires not only that redistribution keep attribution, but that
    #: *messages produced by a match* identify the rule's author. An alert is
    #: such a message, so the attribution has to reach it.
    attribution: str = ""


def _get(obj: Any, *path: str) -> Any:
    cur: Any = obj
    for key in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


class DetectionEngine:
    """Evaluates the native executable corpus against live events."""

    def __init__(self, rules: list[dict[str, Any]] | None = None) -> None:
        self._rules: list[dict[str, Any]] = rules if rules is not None else _load_ruleset()
        # Computed once at load, not per event: the set changes when rules
        # change, not when traffic arrives. Doing it per event would mean a
        # regex over every rule's clauses for every ingested event.
        self._derived_wanted: set[str] = requested_derived_fields(self._rules)
        # Parity 6.9. Built once at load for the same reason.
        self._index = RuleIndex(self._rules)
        logger.info(
            "detection_engine.rule_index_built",
            rules=self._index.stats.rules,
            indexed=self._index.stats.indexed,
            always_evaluated=self._index.stats.always_evaluated,
            distinct_pivot_fields=self._index.stats.distinct_fields,
        )

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    @property
    def rules(self) -> list[dict[str, Any]]:
        """The loaded corpus, in order.

        Exposed so the index's losslessness test can replay every
        fixture through the unindexed path and compare. A test that
        reached into ``_rules`` would be asserting against a private
        name, and the comparison is the only thing making the index
        safe to ship.
        """
        return self._rules

    def _candidates(self, fields: dict[str, Any]) -> list[dict[str, Any]]:
        """Rules this event could possibly match, in corpus order.

        Lossless by construction rather than by configuration: a rule is
        only skipped when the event lacks a field the rule's own clause
        cannot be satisfied without, which the index establishes by
        running the real matcher against an empty event. Rules with no
        such field are in every candidate list.

        ``index_stats`` and the parity test
        (``test_rule_index_is_lossless.py``) are what keep that true: the
        test replays the whole corpus both ways over every fixture and
        requires identical hits.
        """
        return self._index.candidates(fields)

    @property
    def index_stats(self):
        """What the index did, for the log line and for the gate."""
        return self._index.stats

    @staticmethod
    def _raw_fields(ocsf: dict[str, Any]) -> dict[str, Any]:
        """Recover the flat field namespace the specs match on.

        `raw_data` carries the connector's own normalized dict, and connectors
        put the untouched vendor payload under `raw_event`. The matcher does a
        plain `event.get(field)` with no path traversal, so a rule naming a
        vendor field — `request_uri`, `target_image`, `call_trace` — read
        `None` and could never fire, however correct the rule was.

        The scale of that was not obvious: 663 of the 825 loaded rules
        referenced at least one field that was not visible, and fixture replay
        could not catch any of them because fixtures are synthesized from the
        rule rather than from real telemetry.

        The workaround in use was per-field hoisting inside individual
        connectors, e.g. in `llm_usage.normalize()`:

            # Emit the dotted event_type at the TOP LEVEL so the llm-*
            # detection rules (which match on `event_type`) fire

        which only ever fixed the one field someone noticed. Merging the nested
        payload once, here, fixes the class.

        Connector-normalized keys win on collision. The connector has already
        made a deliberate decision about `severity` or `title`, and a vendor
        field of the same name must not silently override it.
        """
        fields = DetectionEngine._decode_raw_data(ocsf)

        nested = fields.get("raw_event")
        if isinstance(nested, dict):
            merged = {k: v for k, v in nested.items() if isinstance(k, str)}
            merged.update(fields)
            fields = merged
        return DetectionEngine._with_activity_location(ocsf, fields)

    #: Keys the ingest activity projection carries that rules match on. The
    #: anonymizer and hosting class is stamped in Go at ingest from a pinned
    #: local dataset, and lands at `activity.location.ip_class` -- nested,
    #: where the matcher's plain `event.get(field)` cannot see it. A rule
    #: naming `ip_class` would read None and could never fire, which is the
    #: same defect the `raw_event` merge above was written to end, one level
    #: further out.
    _ACTIVITY_LOCATION_KEYS = ("ip_class", "ip_class_source", "ip_class_dataset_version")

    @staticmethod
    def _with_activity_location(ocsf: dict[str, Any], fields: dict[str, Any]) -> dict[str, Any]:
        """Lift the activity projection's location keys into the flat namespace.

        Connector-supplied keys win, for the same reason they win over the
        vendor payload above: a connector that genuinely emits `ip_class` has
        made a deliberate decision about its own source.
        """
        activity = ocsf.get("activity") if isinstance(ocsf, dict) else None
        if not isinstance(activity, dict):
            return fields
        location = activity.get("location")
        if not isinstance(location, dict):
            return fields
        lifted = {
            key: location[key] for key in DetectionEngine._ACTIVITY_LOCATION_KEYS if isinstance(location.get(key), str) and location[key]
        }
        if not lifted:
            return fields
        lifted.update(fields)
        return lifted

    @staticmethod
    def _decode_raw_data(ocsf: dict[str, Any]) -> dict[str, Any]:
        """The connector's normalized dict, or the OCSF top level as fallback."""
        decoded = decode_raw_data(ocsf)
        if decoded is not None:
            return decoded
        # Fall back to the OCSF top level (some connectors emit flat OCSF).
        return ocsf if isinstance(ocsf, dict) else {}

    async def evaluate_async(
        self,
        message: dict[str, Any],
        overlay: Any | None = None,
        first_seen: Any | None = None,
        baselines: Any | None = None,
    ) -> list[DetectionHit]:
        """`evaluate`, plus the enrichments that need Redis.

        A second entry point rather than making `evaluate` async: the
        synchronous one has callers throughout the tests and the replay
        harness, and turning it async would be a wide change for an
        enrichment a handful of rules read. The two share everything below
        the extra pass.

        `baselines` is the depth plan 3.4 behavioural store. It is folded in
        beside first-seen rather than behind it because the two answer
        different questions about the same event — "have we seen this value
        before" and "how usual is it for this principal" — and a rule may
        read one, the other or both.
        """
        extra: dict[str, Any] = {}
        ocsf = message.get("ocsf_event")
        if (first_seen is not None or baselines is not None) and isinstance(ocsf, dict):
            tenant = str(message.get("tenant_id") or ocsf.get("tenant_uid") or "")
            if tenant:
                fields = self._raw_fields(ocsf)
                if first_seen is not None:
                    extra.update(await first_seen.derived_fields(tenant, fields))
                if baselines is not None:
                    extra.update(await baselines.derived_fields(tenant, fields))
        return self.evaluate(message, overlay, _extra_fields=extra)

    def evaluate(
        self, message: dict[str, Any], overlay: Any | None = None, *, _extra_fields: dict[str, Any] | None = None
    ) -> list[DetectionHit]:
        """Return every rule that fires on this normalized-event message.

        `overlay` is the tenant's tuning (parity 5.4). Without it this
        engine evaluated the shared corpus and nothing else, so a tenant
        who disabled a noisy rule in the console kept receiving its alerts
        while the console showed it disabled.

        Applied **after** the match rather than by filtering the candidate
        list, so a suppressed hit can be recorded with the tuning that
        suppressed it. "No alert" with no explanation is indistinguishable
        from a rule that simply did not match.
        """
        ocsf = message.get("ocsf_event")
        if not isinstance(ocsf, dict):
            return []
        fields = self._raw_fields(ocsf)
        # 17 rules match on comparisons between two fields of the same event
        # (actor_eq_target, actor_uid_neq_owner_uid) or on time of day. Both
        # values were already present and nothing was computing the answer,
        # so those rules could never fire.
        fields = enrich(fields, self._derived_wanted)

        # Parity 5.5. 15 rules read an `<x>_in_allowlist` boolean that
        # nothing computed, so they could never fire. The answer is per
        # tenant, which is why it comes from the overlay rather than from
        # the shared derived-field pass: a global allowlist would make one
        # tenant's exceptions apply to everybody.
        #
        # An unconfigured allowlist contributes **no key**, not False. A
        # `not_in_allowlist` clause against a missing key would be true for
        # every event, which is the negation-flips-on-absence failure the
        # Sigma import already recorded.
        if overlay is not None:
            derived = overlay.derived_allowlist_fields(fields)
            if derived:
                fields = {**fields, **derived}
            # Depth plan 3.3. 18 rules read a `*_priv` / `*_is_admin`
            # boolean that nothing computed, so each read None on that
            # clause and could never fire. Per tenant for the same reason
            # the allowlist is: one tenant's administrators are not
            # another's, and an unknown subject contributes no key rather
            # than `False`.
            privileged = overlay.derived_identity_fields(fields)
            if privileged:
                fields = {**fields, **privileged}

        # Depth plan 3.3. Resolved by the caller because it needs Redis and
        # this method is synchronous; passed in rather than fetched here so
        # one event costs one round trip whatever the corpus reads.
        if _extra_fields:
            fields = {**fields, **_extra_fields}

        hits: list[DetectionHit] = []
        for rule in self._candidates(fields):
            try:
                if matches(rule["match_when"], fields):
                    if overlay is not None:
                        suppressed = overlay.suppresses(rule["id"], fields)
                        if suppressed is None:
                            suppressed = overlay.raises_severity_floor(rule["id"], str(rule.get("severity") or ""))
                        if suppressed:
                            # Info, not debug. A tenant asking why they
                            # stopped seeing a detection gets the tuning,
                            # its author and its reason from the log.
                            logger.info(
                                "detection_engine.suppressed_by_tenant_tuning",
                                rule=rule["id"],
                                tenant=getattr(overlay, "tenant_id", ""),
                                reason=suppressed,
                            )
                            continue
                    hits.append(
                        DetectionHit(
                            rule_id=rule["id"],
                            name=rule["name"],
                            severity=rule["severity"],
                            category=rule["category"],
                            mitre=list(rule.get("mitre") or []),
                            attribution=_attribution(rule),
                        )
                    )
            except Exception as exc:  # noqa: BLE001 — one bad rule must not wedge detection
                logger.debug("detection_engine.rule_error", rule=rule.get("id"), error=str(exc))
        return hits

    def build_alert(self, message: dict[str, Any], hit: DetectionHit) -> RawAlert | None:
        """Turn a detection hit into a RawAlert for the fusion pipeline."""
        ocsf = message.get("ocsf_event") or {}
        tenant_raw = message.get("tenant_id") or ocsf.get("tenant_uid")
        try:
            tenant_id = uuid.UUID(str(tenant_raw))
        except (ValueError, TypeError):
            return None
        connector_id, connector_type, class_uid = extract_provenance(message, ocsf)
        return RawAlert(
            tenant_id=tenant_id,
            source=f"detection:{hit.rule_id}",
            title=hit.name,
            description=(
                f"Detection rule {hit.rule_id} ({hit.category}) fired on ingested telemetry."
                + (f" {hit.attribution}" if hit.attribution else "")
            ),
            severity=_SEVERITY_MAP.get(hit.severity, AlertSeverity.MEDIUM),
            src_ip=_get(ocsf, "src_endpoint", "ip"),
            dst_ip=_get(ocsf, "dst_endpoint", "ip"),
            hostname=_get(ocsf, "device", "name"),
            username=_get(ocsf, "actor", "user", "name"),
            mitre_techniques=hit.mitre,
            raw_event=ocsf,
            connector_id=connector_id,
            connector_type=connector_type,
            ocsf_class_uid=class_uid,
            rule_id=hit.rule_id,
            rule_name=hit.name,
        )


def _attribution(rule: dict[str, Any]) -> str:
    """One sentence crediting an imported rule's upstream, or empty.

    Built from whatever the provenance block actually holds rather than from a
    template with blanks, so a missing author reads as a shorter sentence
    instead of as an author called "".
    """
    prov = rule.get("provenance")
    if not isinstance(prov, dict) or not prov.get("source"):
        return ""
    parts = [f"Translated from {prov['source']}"]
    if prov.get("author"):
        parts.append(f"by {prov['author']}")
    if prov.get("upstream_path"):
        parts.append(f"({prov['upstream_path']})")
    licence = prov.get("license")
    tail = f", licensed under {licence}" if licence else ""
    url = prov.get("license_url")
    return " ".join(parts) + tail + (f" <{url}>" if url else "") + "."


def _read_ruleset(path: Path, *, required: bool) -> list[dict[str, Any]]:
    if not path.exists():
        if required:
            logger.warning("detection_engine.ruleset_missing", path=str(path))
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data.get("rules") or []
    except (ValueError, OSError) as exc:
        logger.error("detection_engine.ruleset_load_failed", path=str(path), error=str(exc))
        return []


@lru_cache(maxsize=1)
def _load_ruleset() -> list[dict[str, Any]]:
    native = _read_ruleset(_RULESET_PATH, required=True)
    imported = _read_ruleset(_IMPORTED_RULESET_PATH, required=False)
    logger.info(
        "detection_engine.ruleset_loaded",
        count=len(native) + len(imported),
        native=len(native),
        imported=len(imported),
    )
    return native + imported
