"""Turn a closed vendor finding into the message production triage consumes.

Gap-closure Phase 1.2.

The plan's requirement is "normalize each finding with the same connector
``normalize()`` production uses", and the reason is the one Phase 1.1 wrote
into ``ClosedFinding.raw``: grading the agent on an input shape it never sees
in production measures a pipeline nobody runs.

Where the boundary actually falls
---------------------------------
Production's chain is::

    connector.fetch_alerts -> connector.normalize -> services/ingest (OCSF)
      -> Kafka raw_events -> services/fusion (promote + fuse)
      -> aisoc.alerts.fused -> build_state -> triage

This module covers the first and last links and is explicit that it does not
cover the middle. :class:`ConnectorNormalizer` calls the **real** connector
object, duck-typed on the one method connectors expose for this
(``normalize(raw) -> dict``), so there is no second copy of any vendor's field
mapping here. :func:`to_fused_envelope` then builds the
``aisoc.alerts.fused`` message that ``build_state`` reads.

What is missing between those two is everything fusion adds on live traffic:
correlation across events, the fused confidence score, the deterministic
narrative, and entity resolution. A replay is therefore a measurement of
triage on a single normalized finding, not of the whole pipeline, and
:data:`ENVELOPE_LIMITS` says so in the report rather than in a comment nobody
reads. Calling it a full-pipeline number would be the more flattering claim
and the false one.

Why the normalizer is injected rather than imported
---------------------------------------------------
The connector classes live in ``services/connectors`` and this is
``services/agents``. They are separate deployables with separate lockfiles and
neither can import the other. So the port is what this module defines, and the
caller supplies the connector: the CLI and the evaluation job both run where a
checkout is present and can hand in the real class.

There is deliberately no fallback normalizer. A replay that cannot reach the
production mapping raises :class:`NormalizerUnavailable` and names what is
missing. The alternative, a "close enough" mapping written here, is exactly
the second implementation the plan forbids, and it would be invisible in the
report because its output has the same shape as the real thing.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol, runtime_checkable

from app.replay.findings import HistoricalFinding

__all__ = [
    "ENVELOPE_LIMITS",
    "ConnectorNormalizer",
    "FindingNormalizer",
    "NormalizerUnavailable",
    "to_fused_envelope",
]

#: Published in every replay report's method section. These are the fusion
#: enrichments a live alert carries and a replayed finding does not.
ENVELOPE_LIMITS: tuple[str, ...] = (
    "Correlation across related events is not applied: each finding is replayed on its own.",
    "The fused confidence score is absent, so triage sees no prior fusion confidence.",
    "The deterministic correlation narrative is absent.",
    "Entity resolution and graph context from the live pipeline are absent.",
)


class NormalizerUnavailable(RuntimeError):
    """No production connector normalizer could be reached for a vendor.

    Raised rather than substituted. A replay run that silently normalized its
    own way would publish a number about a pipeline the product does not have.
    """


@runtime_checkable
class FindingNormalizer(Protocol):
    """The one method every connector in this tree exposes for this job."""

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Map a raw vendor row to the canonical connector envelope."""


class ConnectorNormalizer:
    """Adapter over a real connector instance.

    Holds the connector rather than subclassing it, so the object graded
    against is the object production constructs. ``connector_id`` is read off
    it for provenance: a report that says which connector produced its input
    can be checked, and one that says "splunk" because a caller typed it
    cannot.
    """

    def __init__(self, connector: FindingNormalizer, *, connector_id: str | None = None) -> None:
        if not hasattr(connector, "normalize"):
            raise NormalizerUnavailable(f"{type(connector).__name__} has no normalize(); replay will not substitute its own mapping")
        self._connector = connector
        self.connector_id = connector_id or str(getattr(connector, "connector_id", "") or "")

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        return self._connector.normalize(dict(raw))


def _first(row: Mapping[str, Any], *keys: str) -> Any:
    for key in keys:
        value = row.get(key)
        if value not in (None, ""):
            return value
    return None


def to_fused_envelope(
    finding: HistoricalFinding,
    normalized: Mapping[str, Any],
    *,
    tenant_id: str,
    connector_id: str = "",
) -> dict[str, Any]:
    """Build the ``aisoc.alerts.fused`` message ``build_state`` consumes.

    Field selection follows ``build_state`` exactly: every key set here is one
    that function reads, and nothing is set that it ignores. The IOC fields
    are read from the connector envelope first and from the untouched vendor
    row second, because a connector lifts only the fields it has a canonical
    home for and the rest stay in ``raw_event``.

    ``confidence_score`` is left unset on purpose. Fusion computes it from
    correlated evidence that a single replayed finding does not have, and
    inventing a number for it would put a fabricated confidence into the
    prompt that decides the verdict being graded.
    """
    raw_event = normalized.get("raw_event")
    vendor_row: Mapping[str, Any] = raw_event if isinstance(raw_event, Mapping) else finding.raw

    def pick(*keys: str) -> Any:
        return _first(normalized, *keys) or _first(vendor_row, *keys)

    alert: dict[str, Any] = {
        "id": finding.finding_id,
        "title": normalized.get("title") or finding.title,
        "rule_id": finding.rule_id or pick("rule_id", "search_name"),
        "rule_name": pick("rule_name", "search_name", "title"),
        "severity": normalized.get("severity") or finding.severity,
        "src_ip": pick("src_ip", "src"),
        "dst_ip": pick("dst_ip", "dest", "dest_ip"),
        "hostname": pick("hostname", "host", "dvc"),
        "username": pick("username", "user", "src_user"),
        "file_hash": pick("file_hash", "file_hash_sha256", "sha256"),
        "domain": pick("domain"),
        "url": pick("url"),
        "mitre_techniques": pick("mitre_techniques", "annotations.mitre_attack") or [],
        "risk_score": pick("risk_score") or 0.0,
        "raw_event": dict(vendor_row),
        "connector_id": connector_id,
        "connector_type": finding.vendor,
        "source_event_ids": [finding.finding_id] if finding.finding_id else [],
        "tenant_id": tenant_id,
    }
    return {
        "id": finding.finding_id,
        "alert_row_id": finding.finding_id,
        "tenant_id": tenant_id,
        "incident_id": finding.finding_id,
        "alert": alert,
    }
