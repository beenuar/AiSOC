"""Federated SIEM search, shaped for an agent rather than for a console.

Gap-closure Phase 4.1.

This does **not** build a federated search. ``/federated/search`` already
fans a ``UnifiedQuery`` out to every federated-capable connector a tenant has
enabled, decrypting per-tenant credentials from the vault and isolating each
backend's failure so one dead SIEM cannot cancel the answer. That is reused:
``_fetch_target_connectors`` and ``_query_one_backend`` are imported from the
endpoint that owns them, not reimplemented here.

What this adds is the three things an agent needs and a console does not.

**A typed query.** The caller names an indicator type from a closed set and
this resolves the field per backend, so the model never names a field and
never supplies query text. See ``indicators`` for why that is a security
boundary and not a style preference.

**A bounded, projected result.** A console renders every column of every row
and lets a human scroll. A model pays for every token and cannot skim, so
rows are projected to the fields that carry signal, capped in count, and
capped again in serialized size. The caps are reported when they bite, so a
truncated answer is legible as truncated rather than as the whole picture.

**An honest account of what could not be checked.** A backend that errored,
a backend with no field mapping for the indicator type, and a backend that
genuinely holds no matching rows are three different facts. They are kept
apart all the way to the caller, because an agent that reads the first as the
third concludes a host is clean on evidence nobody gathered.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from typing import Any

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.endpoints.federated import (
    _fetch_target_connectors,
    _query_one_backend,
)
from app.core.config import settings
from app.services.agent_tools.indicators import (
    IndicatorTypeError,
    fields_for,
    validate_value,
)

logger = logging.getLogger(__name__)

#: Rows returned to the model, after merging every backend and field.
#:
#: A console default of 100 is reasonable for a human with a scrollbar. For a
#: model this is context it pays for on every subsequent turn of the tool
#: loop, and the marginal value of row 40 in answering "has this indicator
#: been seen here" is close to nil. A caller may ask for less, never more.
MAX_ROWS = 40

#: Ceiling on the serialized result, independent of the row count. A row cap
#: alone is not a size cap: one Sentinel row carrying a base64 payload can be
#: larger than forty ordinary ones, and a single tool result that fills the
#: context window ends the investigation as surely as an error would.
MAX_RESULT_BYTES = 24_000

#: Per-backend timeout. Shorter than the console's, because this runs inside a
#: tool loop that has its own wall-clock budget: a pivot that takes 30 seconds
#: has spent a quarter of the investigation's budget on one question.
PER_BACKEND_TIMEOUT_SECONDS = 12.0

#: Fields worth returning, in the order a reader wants them. Every backend
#: has its own schema, so this is a union across the four rather than a
#: mapping, and a row that carries none of them falls back to its first few
#: keys so a caller is never handed an empty object.
_PROJECT_KEYS: tuple[str, ...] = (
    "_time",
    "@timestamp",
    "TimeGenerated",
    "starttime",
    "host",
    "host.name",
    "Computer",
    "SrcHostname",
    "DstHostname",
    "identityhostname",
    "user",
    "user.name",
    "ActorUsername",
    "TargetUsername",
    "username",
    "src_ip",
    "dest_ip",
    "source.ip",
    "destination.ip",
    "SrcIpAddr",
    "DstIpAddr",
    "sourceip",
    "destinationip",
    "process_name",
    "process.name",
    "Process",
    "processname",
    "file_hash",
    "file.hash.sha256",
    "url",
    "url.full",
    "Url",
    "query",
    "dns.question.name",
    "DnsQuery",
    "domainname",
    "signature",
    "rule.name",
    "AlertName",
    "eventname",
    "action",
    "event.action",
    "severity",
    "_raw_summary",
)

#: How many keys a row with no recognised field falls back to. Enough to say
#: what the row is about, not enough to be a full record.
_FALLBACK_KEYS = 6


@dataclass
class SourceOutcome:
    """What one backend did, kept separate from what it returned."""

    connector_type: str
    connector_name: str
    status: str
    row_count: int = 0
    fields_searched: tuple[str, ...] = ()
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "source": self.connector_type,
            "name": self.connector_name,
            "status": self.status,
            "rows": self.row_count,
        }
        if self.fields_searched:
            out["fields_searched"] = list(self.fields_searched)
        if self.error:
            out["error"] = self.error
        return out


@dataclass
class SiemSearchResult:
    rows: list[dict[str, Any]] = field(default_factory=list)
    sources: list[SourceOutcome] = field(default_factory=list)
    truncated_rows: bool = False
    truncated_bytes: bool = False

    @property
    def any_source_failed(self) -> bool:
        return any(s.status == "error" for s in self.sources)

    @property
    def any_source_answered(self) -> bool:
        return any(s.status == "ok" for s in self.sources)


def _project(row: dict[str, Any]) -> dict[str, Any]:
    """Reduce one SIEM row to the fields that carry signal.

    Two jobs, and the second is the one that is easy to forget. It bounds
    token cost, and it bounds how much attacker-influenced vendor text
    reaches a prompt: a SIEM row can carry a whole command line or a whole
    email body, and every byte of it is content an attacker may have chosen.
    """
    source = row.get("_aisoc_source")
    kept: dict[str, Any] = {}
    for key in _PROJECT_KEYS:
        if key in row and row[key] not in (None, ""):
            kept[key] = row[key]
    if not kept:
        for key, value in list(row.items())[:_FALLBACK_KEYS]:
            if key != "_aisoc_source":
                kept[key] = value
    if isinstance(source, dict):
        # Which SIEM answered is part of the evidence, not decoration: an
        # indicator seen in one source and not another is a different finding
        # from one seen in both.
        kept["_source"] = source.get("connector_type")
    return kept


async def search_indicator(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    indicator_type: str,
    value: str,
    since_hours: int = 24,
    limit: int = MAX_ROWS,
    actor: str = "aisoc-agent",
) -> SiemSearchResult:
    """Search every configured SIEM for one indicator.

    Raises ``IndicatorTypeError`` when the type or the value is refused. That
    is a caller error and is deliberately not folded into an empty result:
    the caller must be able to tell "your query was wrong" from "nothing
    matched".
    """
    checked = validate_value(indicator_type, value)
    window = max(1, min(int(since_hours), 7 * 24))
    row_cap = max(1, min(int(limit), MAX_ROWS))

    connectors = await _fetch_target_connectors(db, tenant_id, requested_ids=None)
    result = SiemSearchResult()
    if not connectors:
        return result

    timeout = httpx.Timeout(
        PER_BACKEND_TIMEOUT_SECONDS,
        connect=min(5.0, PER_BACKEND_TIMEOUT_SECONDS),
    )

    # One call per (backend, field). The federated layer AND-joins the
    # indicators in a single UnifiedQuery, so "source.ip OR destination.ip"
    # cannot be expressed as one query, and asking for only one of the two
    # would silently answer half the question. Grouped and awaited together
    # so the added calls cost latency once rather than serially.
    plans: list[tuple[Any, str, dict[str, Any]]] = []
    for connector in connectors:
        tokens = fields_for(indicator_type, connector.connector_type)
        if not tokens:
            result.sources.append(
                SourceOutcome(
                    connector_type=connector.connector_type,
                    connector_name=connector.name,
                    status="no_field_mapping",
                    error=(
                        f"AiSOC has no field mapping for a {indicator_type} on {connector.connector_type}, "
                        f"so this source was NOT searched. This is a coverage gap, not an absence of the indicator."
                    ),
                )
            )
            continue
        for token in tokens:
            plans.append(
                (
                    connector,
                    token,
                    {
                        "free_text": "",
                        "indicators": [{"field": token, "operator": "eq", "value": checked}],
                        "since_seconds": window * 3600,
                        "limit": row_cap,
                    },
                )
            )

    if not plans:
        return result

    outcomes = await asyncio.gather(
        *(_query_one_backend(connector, payload, timeout) for connector, _, payload in plans),
        return_exceptions=False,
    )

    # Collapse the per-field calls back into one outcome per backend, because
    # "Splunk was searched on two fields and one of them errored" is noise to
    # a model. An error on any field makes the backend's outcome an error,
    # which is the safe direction: it says part of this source was not
    # checked rather than implying the whole of it was.
    merged: dict[str, SourceOutcome] = {}
    seen: set[str] = set()
    for (connector, token, _), (verdict, rows) in zip(plans, outcomes, strict=True):
        key = str(connector.id)
        outcome = merged.get(key)
        if outcome is None:
            outcome = SourceOutcome(
                connector_type=connector.connector_type,
                connector_name=connector.name,
                status=verdict.status,
            )
            merged[key] = outcome
        outcome.fields_searched = (*outcome.fields_searched, token)
        if verdict.status == "error":
            outcome.status = "error"
            outcome.error = verdict.error or "the source could not be searched"
        elif outcome.status != "error" and verdict.status == "unsupported":
            outcome.status = "unsupported"
            outcome.error = verdict.error

        for row in rows:
            if not isinstance(row, dict):
                continue
            projected = _project(row)
            # Two fields on one backend can both match the same event, and a
            # duplicate row is context the model pays for twice while making
            # a single sighting look like two.
            fingerprint = repr(sorted(projected.items()))
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            result.rows.append(projected)
            outcome.row_count += 1

    result.sources = list(merged.values()) + [s for s in result.sources if s.status == "no_field_mapping"]

    if len(result.rows) > row_cap:
        result.rows = result.rows[:row_cap]
        result.truncated_rows = True

    # Byte cap applied after the row cap, dropping from the end, so what
    # survives is the rows the backends ranked first.
    while result.rows and len(repr(result.rows)) > MAX_RESULT_BYTES:
        result.rows.pop()
        result.truncated_bytes = True

    logger.info(
        "agent_tools.siem_search tenant=%s type=%s sources=%d rows=%d actor=%s",
        tenant_id,
        indicator_type,
        len(result.sources),
        len(result.rows),
        str(actor).replace("\r", "").replace("\n", " ")[:64],
    )
    return result


def feature_enabled() -> bool:
    """Whether federated search is switched on for this deployment."""
    return bool(settings.AISOC_FEATURE_FED_SEARCH)


__all__ = [
    "MAX_RESULT_BYTES",
    "MAX_ROWS",
    "IndicatorTypeError",
    "SiemSearchResult",
    "SourceOutcome",
    "feature_enabled",
    "search_indicator",
]
