"""Evidence fingerprinting: when are two alerts "the same"?

One definition, two readers. `services/agents` uses it to match a repeat
alert against a stored outcome prior; `services/api` uses the vendored copy
to write a **human-authored** prior under the same key when an analyst
dispositions an alert, which parity plan 2.3 requires.

The key has to match exactly or the prior lands somewhere nothing looks.
That is not hypothetical: this fingerprint once hashed the alert row id and
the whole raw event, so every alert produced a unique key, no repeat ever
matched, and `repeat_alerts_suppressed` could only report zero while its
test passed on a hardcoded signature.

Kept in step by `scripts/sync_vendored_fingerprint.py --check`.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

_EVIDENCE_FIELDS = (
    # rule / detection identity
    "rule_id",
    "rule_name",
    "detection_id",
    "signature",
    "title",
    "category",
    "severity",
    # entity identity
    "hostname",
    "host",
    "username",
    "user",
    "src_ip",
    "source_ip",
    "dst_ip",
    "dest_ip",
    "domain",
    "url",
    "file_hash",
    "process_name",
    # provenance
    "connector_type",
    "mitre_techniques",
)

#: Fields that must never contribute to a fingerprint because they differ
#: between two occurrences of the same alert. Used only on the fallback path
#: below, for alert shapes this module does not recognise.
_VOLATILE_FIELDS = frozenset(
    {
        "id",
        "alert_id",
        "uuid",
        "run_id",
        "incident_id",
        "source_event_ids",
        "raw_event",
        "confidence",
        "confidence_score",
        "risk_score",
        "score",
        "created_at",
        "updated_at",
        "timestamp",
        "ts",
        "time",
        "first_seen",
        "last_seen",
        "detected_at",
        "occurred_at",
        "ingested_at",
        "fusion_decision",
    }
)


def _normalise(value: Any) -> Any:
    if isinstance(value, list):
        # Order of techniques or entities is not evidence.
        return sorted(str(v).strip().lower() for v in value)
    if isinstance(value, str):
        return value.strip().lower()
    return value


def canonical_evidence(alert: dict[str, Any]) -> dict[str, Any]:
    """Reduce an alert to the evidence that makes two alerts "the same".

    Excludes everything volatile — the alert row id, source event ids, the raw
    event payload, timestamps, and per-run scores like `confidence` and
    `risk_score` that drift between otherwise identical alerts.

    Two failure directions, and they are not equally bad. Keeping a volatile
    field means a repeat never matches, so suppression silently does nothing.
    Dropping an evidence-bearing field means two different alerts share a
    fingerprint, so a benign prior for one suppresses the other — a false
    negative. The second is much worse, so an alert shape this module does not
    recognise falls back to hashing everything except known volatile keys,
    rather than collapsing into a single bucket.
    """
    evidence = {name: _normalise(alert[name]) for name in _EVIDENCE_FIELDS if alert.get(name) not in (None, "", [], {})}
    if evidence:
        return evidence
    return {key: _normalise(value) for key, value in alert.items() if key not in _VOLATILE_FIELDS}


def evidence_fingerprint(tenant_id: str, alert: Any) -> str:
    """Stable hash of the investigation-relevant evidence.

    Identical alerts (same tenant, same canonical evidence) collapse to the
    same fingerprint, which is what lets a repeat hit the dedup cache and
    match a stored outcome prior.
    """
    canonical_subset = canonical_evidence(alert) if isinstance(alert, dict) else alert
    try:
        canonical = json.dumps(canonical_subset, sort_keys=True, default=str)
    except (TypeError, ValueError):
        canonical = str(canonical_subset)
    return hashlib.sha256(f"{tenant_id}\x00{canonical}".encode()).hexdigest()
