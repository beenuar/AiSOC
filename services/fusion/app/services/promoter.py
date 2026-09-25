"""Promotion of ingest-normalized OCSF events into fusion RawAlerts.

Phase 3.1 (world-class program) closed the first of the two spine gaps the
reality audit exposed: ``services/ingest`` publishes normalized OCSF events to
``aisoc.raw_events`` and — before this module — **nothing consumed them**. The
fusion worker now subscribes to that topic and runs every message through
:func:`promote_normalized_event`.

Promotion policy (deterministic, no LLM, documented honestly):

* **Vendor-asserted findings are promoted.** Any event in the OCSF *Findings*
  category (``class_uid`` 2000–2999 — Security Finding, Detection Finding,
  etc.) is already an alert in the source product's judgment; dropping it on
  the floor would be silent data loss.
* **High/critical telemetry is promoted.** Non-finding events with
  ``severity_id >= 4`` (High / Critical / Fatal on the OCSF ladder) are
  promoted so a critical Okta or K8s event is never invisible to the SOC.
* **Everything else is NOT promoted.** Turning raw Medium-and-below telemetry
  into alerts is the job of the detection engine, not this bridge — promoting
  it here would destroy the alert-reduction property the fusion stage exists
  to provide.

Events whose ``tenant_id`` is not a UUID are skipped (the alert store keys
tenants by UUID; a non-UUID tenant header is a mis-configured connector, and
we log it rather than crash the consumer).

Non-promotion used to be **completely silent**: :func:`promote_normalized_event`
returned ``None`` and the consumer incremented a ``not_promoted`` counter. The
aggregate reached ``/metrics``, so an operator could see that events were being
dropped and nothing else — not which connector, not what shape, not why. "I
connected my SIEM and no alerts appeared" is the first question a new user asks
and the counter cannot answer it. See :func:`_note_not_promoted` for what is
logged and how its volume is bounded.
"""

from __future__ import annotations

import os
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import structlog

from app.models.alert import AlertSeverity, RawAlert
from app.services.provenance import extract_provenance, product_label

logger = structlog.get_logger()

# OCSF category 2 = Findings (Security Finding 2001, Vulnerability Finding
# 2002, Compliance Finding 2003, Detection Finding 2004, ...).
_FINDINGS_CATEGORY = 2

# OCSF severity_id >= 4 means High(4) / Critical(5) / Fatal(6).
_PROMOTE_SEVERITY_FLOOR = 4

_SEVERITY_BY_ID: dict[int, AlertSeverity] = {
    6: AlertSeverity.CRITICAL,  # OCSF Fatal collapses onto our critical tier
    5: AlertSeverity.CRITICAL,
    4: AlertSeverity.HIGH,
    3: AlertSeverity.MEDIUM,
    2: AlertSeverity.LOW,
    1: AlertSeverity.INFO,
    0: AlertSeverity.MEDIUM,  # Unknown — median tier, never silently info
}


def _get_nested(obj: dict[str, Any], *path: str) -> Any:
    cur: Any = obj
    for key in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


def _first_file_hash(ocsf: dict[str, Any]) -> str | None:
    fingerprints = _get_nested(ocsf, "file", "fingerprints")
    if isinstance(fingerprints, list) and fingerprints:
        first = fingerprints[0]
        if isinstance(first, dict):
            value = first.get("value")
            if isinstance(value, str) and value:
                return value
    return None


def _mitre(ocsf: dict[str, Any]) -> tuple[list[str], list[str]]:
    """Extract (tactics, techniques) from the ingest ATT&CK enrichment block."""
    tactics: list[str] = []
    techniques: list[str] = []
    block = ocsf.get("mitre_attck")
    if isinstance(block, list):
        for entry in block:
            if not isinstance(entry, dict):
                continue
            tid = entry.get("technique_id")
            if isinstance(tid, str) and tid and tid not in techniques:
                techniques.append(tid)
            names = entry.get("tactic_names")
            if isinstance(names, list):
                for name in names:
                    if isinstance(name, str) and name and name not in tactics:
                        tactics.append(name)
    return tactics, techniques


def _title(ocsf: dict[str, Any]) -> str:
    for key in ("message", "activity_name"):
        val = ocsf.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()[:500]
    class_name = ocsf.get("class_name") or "Security event"
    product = _get_nested(ocsf, "metadata", "product", "name")
    if isinstance(product, str) and product:
        return f"{class_name} from {product}"[:500]
    return str(class_name)[:500]


def _source(ocsf: dict[str, Any]) -> str:
    """Human-readable origin, e.g. "CrowdStrike Falcon" or "crowdstrike".

    Delegates to `provenance.product_label` so the vendor/product join exists
    once. Two copies of it used to exist, and fixing only this one left
    `connector_type` still reading "crowdstrike crowdstrike" on the alert row.
    """
    return product_label(ocsf) or "ingest"


def _description(ocsf: dict[str, Any]) -> str:
    """Prefer a human sentence over a serialized payload.

    This used to be `str(ocsf.get("raw_data"))`, so every alert's description
    was the whole event dumped as a Python dict repr — unreadable in the
    console, and it discarded the vendor's own description even when one was
    supplied. Verified against a live stack: a CrowdStrike event carrying
    "powershell.exe -enc ... spawned by winword.exe" produced a description
    that began `{"command_line": "powershell.exe ...`.

    The raw payload is not lost: it stays on the alert's `raw_event`, which is
    what the investigation surfaces read.
    """
    raw = ocsf.get("raw_data")
    if isinstance(raw, dict):
        for key in ("description", "message", "summary", "detail", "reason"):
            value = raw.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()[:2000]
    finding_desc = _get_nested(ocsf, "finding", "desc")
    if isinstance(finding_desc, str) and finding_desc.strip():
        return finding_desc.strip()[:2000]
    message = ocsf.get("message")
    if isinstance(message, str) and message.strip():
        return message.strip()[:2000]
    # Nothing human-authored anywhere. An empty description is more honest
    # than a dict repr pretending to be prose; the console renders the raw
    # event beneath it either way.
    return ""


def _event_time(ocsf: dict[str, Any]) -> datetime | None:
    raw = ocsf.get("time")
    if isinstance(raw, str) and raw:
        try:
            return datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


def _external_id(ocsf: dict) -> str | None:
    """The vendor's own id for this finding, from OCSF ``finding.uid``.

    This is the join key the two-way SIEM loop needs: without it an alert
    cannot be traced back to the notable, signal or offense that raised it.
    ``metadata.uid`` is the fallback for profiles that carry the vendor id
    there instead, and both are bounded because the column is indexed and a
    vendor that puts a whole document in the field should not break the write.
    """
    for path in (("finding", "uid"), ("metadata", "uid")):
        value = _get_nested(ocsf, *path)
        if isinstance(value, str) and value.strip():
            return value.strip()[:512]
    return None


def should_promote(ocsf: dict[str, Any]) -> bool:
    """Deterministic promotion decision — see module docstring for policy."""
    class_uid = ocsf.get("class_uid")
    if isinstance(class_uid, int) and class_uid // 1000 == _FINDINGS_CATEGORY:
        return True
    severity_id = ocsf.get("severity_id")
    return isinstance(severity_id, int) and severity_id >= _PROMOTE_SEVERITY_FLOOR


# ─── Explaining a non-promotion, without drowning the log ────────────────────

#: Seconds between aggregated rollups of everything that was not promoted.
_ROLLUP_SECONDS = float(os.getenv("AISOC_NOT_PROMOTED_ROLLUP_SECONDS", "60"))

#: Ceiling on distinct shapes tracked at once. The natural cardinality is
#: (connectors x OCSF classes x 7 severities), which is small; the cap exists
#: so a connector emitting a garbage `class_uid` per event cannot grow this
#: without bound.
_MAX_TRACKED_SHAPES = 500

#: A shape is one distinct reason a class of event is being dropped.
_Shape = tuple[str, int | None, int | None, str]


@dataclass
class _Sampler:
    """Per-process state for the non-promotion log.

    A small object rather than three module-level names and a ``global``
    statement in two functions: the mutation is then an attribute write, which
    both reads better and gives the static analysers nothing to flag about
    rebinding module state from inside a function.
    """

    #: Shapes already explained in full, so the explanation is printed once.
    explained: set[_Shape] = field(default_factory=set)
    #: Occurrences per shape since the last rollup.
    pending: dict[_Shape, int] = field(default_factory=dict)
    #: ``time.monotonic()`` at the last rollup; 0.0 before the first event.
    last_rollup: float = 0.0

    def reset(self) -> None:
        self.explained.clear()
        self.pending.clear()
        self.last_rollup = 0.0


_sampler = _Sampler()


def _not_promoted_reason(class_uid: int | None, severity_id: int | None) -> str:
    """Which promotion condition failed, in a string an operator can act on.

    Both conditions have to fail for an event to land here, so the reason
    always names the class *and* says what happened to severity — the two are
    different fixes (a connector profile's `classUID`, or its severity map).
    """
    category = class_uid // 1000 if isinstance(class_uid, int) else None
    class_part = (
        f"OCSF class {class_uid} is category {category}, not {_FINDINGS_CATEGORY} (Findings)"
        if category is not None
        else "OCSF class_uid is absent or not an integer, so the Findings check could not pass"
    )
    if not isinstance(severity_id, int):
        # The single most common cause, and the most actionable: a connector
        # profile with an empty severity map yields no severity_id at all.
        sev_part = "and severity_id is absent, so the severity check could not pass either"
    else:
        sev_part = f"and severity_id {severity_id} is below the promote floor of {_PROMOTE_SEVERITY_FLOOR}"
    return f"{class_part}, {sev_part}"


def _note_not_promoted(message: dict[str, Any], ocsf: dict[str, Any]) -> None:
    """Explain a non-promotion once per shape, then count it.

    **Volume decision.** This is the hot path: on a normal tenant the large
    majority of ingested telemetry is correctly not promoted, so a line per
    event would be the highest-volume log in the platform and would cost more
    than the pipeline it describes. A pure time-sampled rollup, though, is
    wrong in the other direction — somebody who has just connected a source
    and is watching the logs needs the answer in seconds, not at the end of a
    window.

    So both, split by novelty: the **first** event of each distinct
    ``(connector, OCSF class, severity, reason)`` shape is explained
    immediately and in full, and every subsequent one is counted into a
    rollup emitted at most once per ``_ROLLUP_SECONDS``. Steady-state cost is
    therefore one line per minute regardless of throughput, while a
    newly-misconfigured connector announces itself on its first event.

    No lock: the fusion consumer drives this from a single asyncio task and
    there is no ``await`` between the reads and writes below, so the
    sequence is atomic with respect to other events.
    """
    connector_id, connector_type, class_uid = extract_provenance(message, ocsf)
    severity_raw = ocsf.get("severity_id")
    severity_id = severity_raw if isinstance(severity_raw, int) else None
    reason = _not_promoted_reason(class_uid, severity_id)
    shape: _Shape = (connector_type or "unknown", class_uid, severity_id, reason)

    if shape not in _sampler.explained and len(_sampler.explained) < _MAX_TRACKED_SHAPES:
        _sampler.explained.add(shape)
        logger.info(
            "promoter.not_promoted",
            connector_type=connector_type or "unknown",
            connector_id=str(connector_id) if connector_id else None,
            ocsf_class_uid=class_uid,
            ocsf_category=(class_uid // 1000 if isinstance(class_uid, int) else None),
            severity_id=severity_id,
            promote_severity_floor=_PROMOTE_SEVERITY_FLOOR,
            reason=reason,
            # The event is in the lake either way; this is the pointer to it.
            event_id=str(message.get("id") or "")[:64] or None,
            note="archived to the lake, not raised as an alert; further events of this shape are counted in promoter.not_promoted_rollup",
        )

    if len(_sampler.pending) < _MAX_TRACKED_SHAPES or shape in _sampler.pending:
        _sampler.pending[shape] = _sampler.pending.get(shape, 0) + 1

    now = time.monotonic()
    if _sampler.last_rollup == 0.0:
        _sampler.last_rollup = now
        return
    if now - _sampler.last_rollup < _ROLLUP_SECONDS or not _sampler.pending:
        return

    top = sorted(_sampler.pending.items(), key=lambda kv: kv[1], reverse=True)[:10]
    logger.info(
        "promoter.not_promoted_rollup",
        window_seconds=round(now - _sampler.last_rollup, 1),
        total=sum(_sampler.pending.values()),
        distinct_shapes=len(_sampler.pending),
        top=[
            {
                "connector_type": ctype,
                "ocsf_class_uid": cuid,
                "severity_id": sev,
                "reason": why,
                "count": count,
            }
            for (ctype, cuid, sev, why), count in top
        ],
    )
    _sampler.pending.clear()
    _sampler.last_rollup = now


def reset_not_promoted_state() -> None:
    """Clear the sampler. Tests only — the state is per-process by design."""
    _sampler.reset()


def promote_normalized_event(message: dict[str, Any]) -> RawAlert | None:
    """Convert one ``aisoc.raw_events`` message into a RawAlert, or ``None``.

    ``message`` is the JSON body ``services/ingest`` publishes — a
    ``NormalizedEvent`` with ``ocsf_event`` carrying the OCSF payload.
    Returns ``None`` when the event doesn't meet the promotion policy or the
    message is malformed (logged, never raised — one bad event must not wedge
    the consumer; the Phase 5 DLQ takes over from there).
    """
    ocsf = message.get("ocsf_event")
    if not isinstance(ocsf, dict):
        logger.warning("promoter.malformed_message", keys=sorted(message.keys()))
        return None

    if not should_promote(ocsf):
        _note_not_promoted(message, ocsf)
        return None

    tenant_raw = message.get("tenant_id") or ocsf.get("tenant_uid")
    try:
        tenant_id = uuid.UUID(str(tenant_raw))
    except (ValueError, TypeError):
        logger.warning("promoter.non_uuid_tenant", tenant_id=str(tenant_raw)[:64])
        return None

    severity_id = ocsf.get("severity_id")
    severity = _SEVERITY_BY_ID.get(severity_id if isinstance(severity_id, int) else 0, AlertSeverity.MEDIUM)

    tactics, techniques = _mitre(ocsf)
    connector_id, connector_type, class_uid = extract_provenance(message, ocsf)

    return RawAlert(
        tenant_id=tenant_id,
        source=_source(ocsf),
        title=_title(ocsf),
        description=_description(ocsf),
        severity=severity,
        src_ip=_get_nested(ocsf, "src_endpoint", "ip"),
        dst_ip=_get_nested(ocsf, "dst_endpoint", "ip"),
        hostname=_get_nested(ocsf, "device", "name"),
        username=_get_nested(ocsf, "actor", "user", "name"),
        file_hash=_first_file_hash(ocsf),
        mitre_tactics=tactics,
        mitre_techniques=techniques,
        raw_event=ocsf,
        event_time=_event_time(ocsf),
        connector_id=connector_id,
        connector_type=connector_type,
        ocsf_class_uid=class_uid,
        external_id=_external_id(ocsf),
    )
