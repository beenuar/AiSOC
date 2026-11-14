"""Read a tenant's recorded events out of the ClickHouse lake.

Parity 6.1. Before this, the only implemented telemetry provider was
`synthetic`, so every scheduled hunt on every deployment ran against
`services/agents/tests/eval_data/synthetic_telemetry.jsonl` — a fixture
corpus. The hunts produced findings about events no customer had, and
found nothing about the events they did have. `ingest` existed as a name
and returned an empty list.

Two rules shape this module, and both are about honesty rather than
correctness:

**An unreachable lake returns nothing and says so.** There is no fallback
to the fixture. A scheduled hunt that quietly reports findings from
synthetic telemetry is worse than one that reports nothing, because an
operator cannot tell the two apart and one of them is fabricated data
presented as their own estate.

**The tenant predicate is bound, not formatted.** The same reasoning the
API's lake reader records: a tenant filter assembled by string
interpolation is one escaping bug away from reading every tenant's
events, and the whole point of the query is that it must not.
"""

from __future__ import annotations

import json
import os
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

#: How far back a scheduled hunt looks. Hunts run on a cadence, so the
#: window only has to cover the gap between ticks with room for a late
#: arrival; reading the whole history every tick would be expensive and
#: would re-report the same finding forever.
DEFAULT_LOOKBACK_HOURS = 24

#: A ceiling, so one tenant's busy hour cannot exhaust the scheduler's
#: memory or stall every other tenant's hunt behind it.
DEFAULT_ROW_CAP = 50_000

#: A much tighter ceiling for interactive search. A person is waiting on this
#: one, and a page renders a screenful; the scheduled hunt's budget exists to
#: match rules across a whole window and is the wrong budget here.
DEFAULT_SEARCH_CAP = 500

_QUERY = """
SELECT
    event_time,
    class_uid,
    severity,
    src_hostname,
    dst_hostname,
    user_name,
    process_name,
    file_path,
    -- Cast in the query rather than in Python. `source_ip` and
    -- `dest_ip` are IPv6 columns, and clickhouse-driver raises
    -- AddressValueError decoding a zero-length packed address, which is
    -- what an unset column yields. A row with no IP is the common case
    -- for identity and SaaS events, so the natural read crashed on
    -- ordinary data.
    IPv6NumToString(source_ip) AS source_ip,
    IPv6NumToString(dest_ip) AS dest_ip,
    connector_type,
    raw_payload
FROM aisoc.raw_events
WHERE tenant_id = %(tenant_id)s
  AND event_time >= now() - INTERVAL %(hours)s HOUR
ORDER BY event_time DESC
LIMIT %(cap)s
"""


#: Free-text search over one tenant's recorded events.
#:
#: Separate from `_QUERY` rather than a parameter on it because the two have
#: different budgets: a scheduled hunt reads a whole window to match rules
#: against, an analyst's search wants the newest few matches quickly.
#:
#: The needle is **bound, not formatted**, for the same reason the tenant
#: predicate is. A search term is the one value on this path that comes
#: straight from a text box, and a term spliced into SQL is a lake-wide read
#: one quote away. `positionCaseInsensitive` over the concatenated searchable
#: columns is a substring match and is described to the caller as exactly
#: that — the endpoint does not claim to execute Lucene, EQL, Sigma or SPL.
#:
#: `raw_payload` is deliberately in the haystack: connectors nest the vendor
#: document there, so excluding it would make a search for a field the
#: console displays return nothing.
_SEARCH_QUERY = """
SELECT
    event_time,
    class_uid,
    severity,
    src_hostname,
    dst_hostname,
    user_name,
    process_name,
    file_path,
    IPv6NumToString(source_ip) AS source_ip,
    IPv6NumToString(dest_ip) AS dest_ip,
    connector_type,
    raw_payload
FROM aisoc.raw_events
WHERE tenant_id = %(tenant_id)s
  AND event_time >= now() - INTERVAL %(hours)s HOUR
  AND (
    %(term)s = ''
    OR positionCaseInsensitive(
        concatWithSeparator(
            ' ',
            src_hostname, dst_hostname, user_name, process_name, file_path,
            hash_sha256, connector_type, severity, raw_payload
        ),
        %(term)s
    ) > 0
  )
ORDER BY event_time DESC
LIMIT %(cap)s
"""


def _client():  # noqa: ANN202
    """A ClickHouse client built from the same settings the writer uses.

    `CLICKHOUSE_HOST`/`PORT`/`USER`/`PASSWORD`/`DATABASE` rather than a
    URL, because that is what `services/fusion`'s lake writer and the
    API read, and a second spelling would be a second thing to get wrong.
    """
    from clickhouse_driver import Client

    return Client(
        host=os.environ.get("CLICKHOUSE_HOST", "clickhouse"),
        port=int(os.environ.get("CLICKHOUSE_PORT", "9000")),
        user=os.environ.get("CLICKHOUSE_USER", "aisoc"),
        password=os.environ.get("CLICKHOUSE_PASSWORD", ""),
        database=os.environ.get("CLICKHOUSE_DATABASE", "aisoc"),
    )


def fetch_recent_events(
    tenant_ref: str,
    *,
    hours: int = DEFAULT_LOOKBACK_HOURS,
    cap: int = DEFAULT_ROW_CAP,
) -> list[dict[str, Any]]:
    """This tenant's events from the last ``hours``, flattened for matching.

    Raises rather than returning an empty list when the lake is
    unreachable: the caller logs it and records an empty run, so "the
    lake is down" and "this tenant had no events" stay distinguishable.
    Collapsing them here would hide an outage behind a quiet result.
    """
    client = _client()
    rows = client.execute(
        _QUERY,
        {"tenant_id": tenant_ref, "hours": int(hours), "cap": int(cap)},
        with_column_types=False,
    )
    return _flatten(rows, tenant_ref=tenant_ref, hours=hours)


def search_events(
    tenant_ref: str,
    term: str,
    *,
    hours: int = DEFAULT_LOOKBACK_HOURS,
    cap: int = DEFAULT_SEARCH_CAP,
) -> list[dict[str, Any]]:
    """This tenant's events from the last ``hours`` matching ``term``.

    The interactive half of the same read. The filter runs **in ClickHouse**
    rather than over a 50,000-row window pulled into this process: an
    analyst's search is a request a person is waiting on, and reading the
    whole window to discard most of it would make the page's latency a
    function of how busy the tenant's estate is.

    Raises when the lake is unreachable, exactly like
    :func:`fetch_recent_events`, so the caller can tell "we could not look"
    from "nothing matched". Those two must never render as the same screen.
    """
    client = _client()
    rows = client.execute(
        _SEARCH_QUERY,
        {"tenant_id": tenant_ref, "term": term.strip(), "hours": int(hours), "cap": int(cap)},
        with_column_types=False,
    )
    return _flatten(rows, tenant_ref=tenant_ref, hours=hours)


def _flatten(rows: Any, *, tenant_ref: str, hours: int) -> list[dict[str, Any]]:
    """Shared row projection, so the two readers cannot disagree about shape."""
    events: list[dict[str, Any]] = []
    for row in rows:
        (
            event_time,
            class_uid,
            severity,
            src_hostname,
            dst_hostname,
            user_name,
            process_name,
            file_path,
            source_ip,
            dest_ip,
            connector_type,
            raw_payload,
        ) = row

        event: dict[str, Any] = {
            "event_time": event_time.isoformat() if event_time else None,
            "class_uid": class_uid,
            "severity": severity,
            "host": src_hostname or dst_hostname or "",
            "src_hostname": src_hostname or "",
            "dst_hostname": dst_hostname or "",
            "user": user_name or "",
            "process": process_name or "",
            "file_path": file_path or "",
            # Already strings, and `::` is what an unset IPv6 renders as.
            "src_ip": "" if source_ip in (None, "::") else str(source_ip),
            "dst_ip": "" if dest_ip in (None, "::") else str(dest_ip),
            "connector_type": connector_type or "",
        }

        # The vendor payload is flattened *under* the canonical fields
        # rather than over them. Connectors nest their payload, and a
        # matcher doing a flat lookup reads None — which is how 663 of
        # 825 loaded rules once matched on fields that were never
        # visible. Canonical keys win so a vendor cannot shadow them.
        if raw_payload:
            try:
                nested = json.loads(raw_payload)
            except (TypeError, ValueError):
                nested = None
            if isinstance(nested, dict):
                for key, value in nested.items():
                    event.setdefault(key, value)

        events.append(event)

    logger.info("hunt.telemetry.lake.loaded", tenant_ref=tenant_ref, events=len(events), hours=hours)
    return events
