"""Project an ORM ``Alert`` row into ``NarrativeInputs``.

The fusion service constructs ``NarrativeInputs`` from its native
``FusedAlert`` Pydantic model at fusion time (see
``services/fusion/app/services/fusion_engine.py::_to_narrative_inputs``).
The API service can't reuse that adapter — it never sees ``FusedAlert``;
it only ever sees the ORM ``Alert`` row that fusion already persisted.

This module is the API's counterpart. It pulls every input the narrative
builder needs out of:

* the ``Alert`` row itself (``severity``, ``title``, ``confidence``,
  ``confidence_label``, ``confidence_rationale``, ``mitre_tactics``,
  ``mitre_techniques``, ``tags``, ``case_id``);
* the denormalised entity columns (``affected_ips``, ``affected_hosts``,
  ``affected_users``); and
* the ``raw_event`` / ``enrichment_data`` JSONB blobs for everything the
  flat columns don't carry (``dst_ip``, ``file_hash``, ``domain``,
  ``url``, RBA promotion, ``exploit_in_wild``).

We're deliberately conservative: any field that can't be pulled cleanly
stays ``None`` and the narrative builder skips that signal — it is
designed to degrade gracefully.

AiSOC — open-source AI Security Operations Center (MIT License)
Author: Beenu Arora <beenu@cyble.com>
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from app.models.alert import Alert
from app.services.narrative_loader import NarrativeFactor, NarrativeInputs

# ─── Helpers ─────────────────────────────────────────────────────────────────


_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_VALID_BANDS = {"high", "medium", "low"}


def _first_str(values: Iterable[Any]) -> str | None:
    """Return the first non-empty trimmed string from ``values``, else None."""
    for value in values:
        if isinstance(value, str):
            stripped = value.strip()
            if stripped:
                return stripped
    return None


def _from_blob(blob: Any, keys: Iterable[str]) -> str | None:
    """Pull the first non-empty string at any of ``keys`` from a JSONB blob.

    Accepts a ``dict`` (the usual case) and silently returns ``None`` for
    anything else, including the empty default ``{}``. We never raise —
    the JSONB shape varies wildly across connectors and the narrative is
    expected to degrade gracefully when a signal isn't present.
    """
    if not isinstance(blob, dict):
        return None
    for key in keys:
        value = blob.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _mitre_names(items: Any) -> tuple[str, ...]:
    """Normalise a JSONB MITRE list into a tuple of bare names.

    The fusion service stores MITRE coverage as either ``["execution",
    …]`` or ``[{"name": "execution", "id": "TA0002"}, …]`` depending on
    the connector. The narrative builder only needs the kebab-case name
    so we flatten both shapes here.
    """
    if not isinstance(items, list):
        return ()
    out: list[str] = []
    for item in items:
        if isinstance(item, str):
            stripped = item.strip()
            if stripped:
                out.append(stripped)
        elif isinstance(item, dict):
            name = item.get("name") or item.get("id")
            if isinstance(name, str) and name.strip():
                out.append(name.strip())
    return tuple(out)


def _rationale_factors(rationale: Any) -> tuple[NarrativeFactor, ...]:
    """Project the JSONB confidence rationale into ``NarrativeFactor`` rows.

    The fusion service stores the rationale as a list of dicts with the
    shape ``{"factor": "severity", "label": "…", "value": "…",
    "contribution": 0.4, "weight": 0.25}``. The narrative builder only
    consumes ``label``, ``value``, ``contribution``, and ``weight`` so
    we silently drop unrecognised entries.
    """
    if not isinstance(rationale, list):
        return ()
    factors: list[NarrativeFactor] = []
    for row in rationale:
        if not isinstance(row, dict):
            continue
        label = row.get("label")
        value = row.get("value")
        contribution = row.get("contribution")
        weight = row.get("weight")
        if not isinstance(label, str) or not isinstance(value, str):
            continue
        try:
            contribution_f = float(contribution) if contribution is not None else 0.0
            weight_f = float(weight) if weight is not None else 0.0
        except (TypeError, ValueError):
            continue
        factors.append(
            NarrativeFactor(
                label=label,
                value=value,
                contribution=contribution_f,
                weight=weight_f,
            )
        )
    return tuple(factors)


def _rba_promotion(enrichment: Any) -> tuple[str | None, float | None]:
    """Extract the RBA top-promotion entity + score from enrichment_data.

    The fusion service writes a small ``rba_top_promotion`` block into
    ``enrichment_data`` when the alert tipped an entity's score above
    its risk threshold. Shape::

        {
            "rba_top_promotion": {
                "entity": "host:web-01",
                "score": 78.3,
            }
        }

    Any other shape returns ``(None, None)`` so the narrative builder
    simply skips the RBA mention.
    """
    if not isinstance(enrichment, dict):
        return None, None
    rba = enrichment.get("rba_top_promotion") or enrichment.get("rba")
    if not isinstance(rba, dict):
        return None, None
    entity = rba.get("entity")
    score = rba.get("score")
    if not isinstance(entity, str) or not entity.strip():
        entity = None
    if isinstance(score, int | float):
        score_f: float | None = float(score)
    else:
        score_f = None
    return (entity or None), score_f


def _exploit_in_wild(alert: Alert) -> bool:
    """True iff the alert touches an asset vulnerability marked exploited.

    Surfaced via the ``exploit_in_wild`` flag on ``enrichment_data`` (set
    by ``services/fusion/app/services/vuln_boost.py``) or the
    ``exploit-in-wild`` tag. We accept either shape so the narrative
    keeps working if vuln_boost evolves.
    """
    if isinstance(alert.enrichment_data, dict):
        flag = alert.enrichment_data.get("exploit_in_wild")
        if isinstance(flag, bool) and flag:
            return True
    for tag in alert.tags or ():
        if isinstance(tag, str) and tag.lower() in {"exploit-in-wild", "exploit_in_wild"}:
            return True
    return False


def _correlation_decision(alert: Alert) -> str | None:
    """Return ``correlated`` if the alert is attached to a case, else ``None``.

    The API doesn't preserve the original ``FusionDecision`` enum (DUPLICATE
    rows never reach the alerts table; NEW_INCIDENT and CORRELATED are
    both surfaced as alerts with a ``case_id``). For the narrative's
    "Correlated activity" block we only need to know that *some*
    incident grouping happened — the prose itself reads naturally in
    both directions.
    """
    if alert.case_id is not None:
        return "correlated"
    return None


# ─── Public API ──────────────────────────────────────────────────────────────


def project_alert_to_narrative_inputs(alert: Alert) -> NarrativeInputs:
    """Build a ``NarrativeInputs`` dataclass from an ORM ``Alert`` row.

    The function is pure: same row → same output. It performs no I/O.
    Callers (the alerts endpoint's lazy-fill path) feed the result to
    :func:`app.services.narrative_loader.build_narrative` and persist
    the returned string back to ``alert.narrative``.
    """
    raw_event = alert.raw_event if isinstance(alert.raw_event, dict) else {}
    enrichment = alert.enrichment_data if isinstance(alert.enrichment_data, dict) else {}

    # Severity / confidence_label are stored lower-case by the fusion
    # service but the API is permissive about case. Normalise here so
    # the narrative builder's Literal type-hints are honoured.
    severity = (alert.severity or "info").lower()
    if severity not in _VALID_SEVERITIES:
        severity = "info"
    confidence_label = alert.confidence_label.lower() if alert.confidence_label else None
    if confidence_label is not None and confidence_label not in _VALID_BANDS:
        confidence_label = None

    # Entity precedence — prefer the denormalised columns (which the
    # fusion service curated at correlation time) and fall back to the
    # raw event blob for shapes we don't promote to first-class columns.
    src_ip = _first_str(alert.affected_ips or ()) or _from_blob(raw_event, ("src_ip", "source_ip", "client_ip"))
    dst_ip = _from_blob(raw_event, ("dst_ip", "destination_ip", "remote_ip"))
    hostname = _first_str(alert.affected_hosts or ()) or _from_blob(
        raw_event, ("host", "hostname", "device_name", "device", "computer_name")
    )
    username = _first_str(alert.affected_users or ()) or _from_blob(raw_event, ("user", "username", "user_name", "account_name", "account"))
    file_hash = _from_blob(raw_event, ("file_hash", "sha256", "sha1", "md5", "hash"))
    domain = _from_blob(raw_event, ("domain", "target_domain", "host_domain"))
    url = _from_blob(raw_event, ("url", "request_url", "uri"))

    source = alert.connector_type or _from_blob(raw_event, ("source", "connector", "vendor"))

    rba_entity, rba_score = _rba_promotion(enrichment)

    return NarrativeInputs(
        severity=severity,  # type: ignore[arg-type]
        title=alert.title,
        confidence=alert.confidence,
        confidence_label=confidence_label,  # type: ignore[arg-type]
        rationale=_rationale_factors(alert.confidence_rationale),
        src_ip=src_ip,
        dst_ip=dst_ip,
        hostname=hostname,
        username=username,
        file_hash=file_hash,
        domain=domain,
        url=url,
        mitre_tactics=_mitre_names(alert.mitre_tactics),
        mitre_techniques=_mitre_names(alert.mitre_techniques),
        # The API can't recompute the incident's total alert count
        # without an extra query. The narrative gracefully omits the
        # "n alerts on this incident" suffix when this is None, which
        # is the right behaviour for the lazy-fill path.
        incident_alert_count=None,
        correlation_decision=_correlation_decision(alert),
        rba_entity=rba_entity,
        rba_score=rba_score,
        exploit_in_wild=_exploit_in_wild(alert),
        source=source,
        tags=tuple(t for t in (alert.tags or ()) if isinstance(t, str)),
    )


__all__ = ["project_alert_to_narrative_inputs"]
