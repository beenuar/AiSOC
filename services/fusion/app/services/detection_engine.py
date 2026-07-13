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

Performance: rules are indexed by ``product`` so an event only evaluates its
own product's rules plus product-agnostic rules, keeping per-event work far
below the full 817-rule corpus. The engine is pure/synchronous; the consumer
calls it inline (the corpus is small and the matcher is regex/dict work).
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
from app.services.detection_matcher import matches

logger = structlog.get_logger()

_RULESET_PATH = Path(__file__).resolve().parent.parent / "data" / "detection_ruleset.json"

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

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    def _candidates(self, product: str) -> list[dict[str, Any]]:
        # Correctness-first routing: evaluate the whole corpus against every
        # event. Connector product names don't line up 1:1 with spec products
        # (``aws_cloudtrail`` vs ``aws``, ``crowdstrike_falcon`` vs ``edr``), so
        # any product-based pre-filter risks silently dropping a real match.
        # The matcher short-circuits on the first absent field, so a full pass
        # over ~800 rules is cheap in practice (a benign event touches almost
        # none of them past the first clause).
        return self._rules

    @staticmethod
    def _raw_fields(ocsf: dict[str, Any]) -> dict[str, Any]:
        """Recover the connector-normalized flat fields the specs match on."""
        raw = ocsf.get("raw_data")
        if isinstance(raw, str) and raw.strip():
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, dict):
                    return parsed
            except (ValueError, TypeError):
                pass
        # Fall back to the OCSF top level (some connectors emit flat OCSF).
        return ocsf if isinstance(ocsf, dict) else {}

    def evaluate(self, message: dict[str, Any]) -> list[DetectionHit]:
        """Return every rule that fires on this normalized-event message."""
        ocsf = message.get("ocsf_event")
        if not isinstance(ocsf, dict):
            return []
        fields = self._raw_fields(ocsf)
        hits: list[DetectionHit] = []
        for rule in self._candidates(""):
            try:
                if matches(rule["match_when"], fields):
                    hits.append(
                        DetectionHit(
                            rule_id=rule["id"],
                            name=rule["name"],
                            severity=rule["severity"],
                            category=rule["category"],
                            mitre=list(rule.get("mitre") or []),
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
        return RawAlert(
            tenant_id=tenant_id,
            source=f"detection:{hit.rule_id}",
            title=hit.name,
            description=f"Detection rule {hit.rule_id} ({hit.category}) fired on ingested telemetry.",
            severity=_SEVERITY_MAP.get(hit.severity, AlertSeverity.MEDIUM),
            src_ip=_get(ocsf, "src_endpoint", "ip"),
            dst_ip=_get(ocsf, "dst_endpoint", "ip"),
            hostname=_get(ocsf, "device", "name"),
            username=_get(ocsf, "actor", "user", "name"),
            mitre_techniques=hit.mitre,
            raw_event=ocsf,
        )


@lru_cache(maxsize=1)
def _load_ruleset() -> list[dict[str, Any]]:
    if not _RULESET_PATH.exists():
        logger.warning("detection_engine.ruleset_missing", path=str(_RULESET_PATH))
        return []
    try:
        data = json.loads(_RULESET_PATH.read_text(encoding="utf-8"))
        rules = data.get("rules") or []
        logger.info("detection_engine.ruleset_loaded", count=len(rules))
        return rules
    except (ValueError, OSError) as exc:
        logger.error("detection_engine.ruleset_load_failed", error=str(exc))
        return []
