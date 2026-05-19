"""Deterministic NL → query translator with optional LLM enhancement.

The translator parses a natural-language security question into a small set
of structured *intents* (filters, group-bys, aggregations, sort, limit, time
range) and then renders those intents into ES|QL, KQL, and SPL. This is the
core of the air-gapped story: by going through a structured intermediate
representation we can:

1. Emit consistent, dialect-correct queries without calling out to an LLM,
2. Validate every emitted query against :mod:`grammar`, and
3. Score the translator on a frozen eval set in CI.

Callers that have an LLM available can use :func:`enhance_with_llm` to
attempt a richer translation; we always fall back to the deterministic
output if the LLM call fails or its result fails grammar validation.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

from .grammar import GrammarError, validate_esql, validate_kql, validate_spl

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NLQuery:
    """The plain-English question plus enough context to render queries."""

    question: str
    index_pattern: str = "logs-*"
    time_range_hours: int = 24


@dataclass(frozen=True)
class TranslatedQuery:
    """Translation result: one query per dialect plus a short explanation."""

    esql: str
    kql: str
    spl: str
    explanation: str
    intents: QueryIntents

    def as_dict(self) -> dict[str, str]:
        return {
            "esql": self.esql,
            "kql": self.kql,
            "spl": self.spl,
            "explanation": self.explanation,
        }


@dataclass
class QueryIntents:
    """Structured intermediate representation parsed from the NL question."""

    filters: list[tuple[str, str, str]] = field(default_factory=list)  # (field, op, value)
    group_by: list[str] = field(default_factory=list)
    aggregations: list[tuple[str, str | None, str]] = field(default_factory=list)
    # ^ (function, arg_field_or_None, alias)
    sort_by: tuple[str, str] | None = None  # (field, direction)
    limit: int = 500
    distinct: str | None = None
    time_field: str = "@timestamp"


# ---------------------------------------------------------------------------
# Field aliases & vocabulary
# ---------------------------------------------------------------------------


# Map natural-language references to canonical ECS-ish field names. We keep
# the source text on the left so the parser can do simple word lookups.
_FIELD_ALIASES: dict[str, str] = {
    "user": "user.name",
    "username": "user.name",
    "account": "user.name",
    "src ip": "source.ip",
    "source ip": "source.ip",
    "source_ip": "source.ip",
    "src_ip": "source.ip",
    "destination ip": "destination.ip",
    "dest ip": "destination.ip",
    "destination_ip": "destination.ip",
    "dest_ip": "destination.ip",
    "host": "host.name",
    "hostname": "host.name",
    "process": "process.name",
    "process name": "process.name",
    "command": "process.command_line",
    "command line": "process.command_line",
    "url": "url.full",
    "domain": "destination.domain",
    "country": "source.geo.country_iso_code",
    "status": "event.outcome",
    "outcome": "event.outcome",
    "action": "event.action",
    "category": "event.category",
    "severity": "event.severity",
    "rule": "rule.name",
    "rule name": "rule.name",
    "agent": "user_agent.original",
    "user agent": "user_agent.original",
    "country code": "source.geo.country_iso_code",
    "bytes": "network.bytes",
    "port": "destination.port",
    "destination port": "destination.port",
    "dest port": "destination.port",
    "source port": "source.port",
    "src port": "source.port",
    "user account": "user.name",
}


# Country names → ISO 3166-1 alpha-2 codes. Used by the geo-from filter so a
# question like *"Did we get any new attacks from Iran?"* gets translated to
# ``source.geo.country_iso_code == "IR"`` instead of being misparsed as a
# bare hostname filter. Lowercase keys so the matcher can do a single-pass
# lookup against the normalised question.
#
# We deliberately limit the table to ~50 high-traffic-for-SOC entries (G20 +
# common attack-source nations) rather than pulling a full 250-entry library.
# The translator still falls back to "no results, but here's the parsed query"
# for misses, so a lookup miss never breaks the UX — it just gives us less
# useful filtering. New entries are fine to add as they come up; keep the
# file deterministic by hand-curating.
_COUNTRY_TO_ISO: dict[str, str] = {
    "afghanistan": "AF",
    "argentina": "AR",
    "australia": "AU",
    "austria": "AT",
    "belarus": "BY",
    "belgium": "BE",
    "brazil": "BR",
    "canada": "CA",
    "china": "CN",
    "colombia": "CO",
    "cuba": "CU",
    "czech republic": "CZ",
    "denmark": "DK",
    "egypt": "EG",
    "estonia": "EE",
    "finland": "FI",
    "france": "FR",
    "germany": "DE",
    "greece": "GR",
    "hong kong": "HK",
    "hungary": "HU",
    "india": "IN",
    "indonesia": "ID",
    "iran": "IR",
    "iraq": "IQ",
    "ireland": "IE",
    "israel": "IL",
    "italy": "IT",
    "japan": "JP",
    "kazakhstan": "KZ",
    "lebanon": "LB",
    "libya": "LY",
    "malaysia": "MY",
    "mexico": "MX",
    "myanmar": "MM",
    "netherlands": "NL",
    "new zealand": "NZ",
    "nigeria": "NG",
    "north korea": "KP",
    "norway": "NO",
    "pakistan": "PK",
    "philippines": "PH",
    "poland": "PL",
    "portugal": "PT",
    "qatar": "QA",
    "romania": "RO",
    "russia": "RU",
    "saudi arabia": "SA",
    "singapore": "SG",
    "south africa": "ZA",
    "south korea": "KR",
    "spain": "ES",
    "sweden": "SE",
    "switzerland": "CH",
    "syria": "SY",
    "taiwan": "TW",
    "thailand": "TH",
    "turkey": "TR",
    "ukraine": "UA",
    "united arab emirates": "AE",
    "united kingdom": "GB",
    "uk": "GB",
    "britain": "GB",
    "united states": "US",
    "usa": "US",
    "us": "US",
    "america": "US",
    "venezuela": "VE",
    "vietnam": "VN",
    "yemen": "YE",
}


# Words that signal an event category. The values are the canonical
# ``event.category`` filters we'll add when one of these keywords appears.
_CATEGORY_KEYWORDS: dict[str, str] = {
    "login": "authentication",
    "logon": "authentication",
    "auth": "authentication",
    "authentication": "authentication",
    "ssh": "authentication",
    "process": "process",
    "execution": "process",
    "network": "network",
    "dns": "network",
    "firewall": "network",
    "file": "file",
    "filesystem": "file",
    "registry": "registry",
}


# Words that signal an event outcome filter.
_OUTCOME_KEYWORDS: dict[str, str] = {
    "failed": "failure",
    "failure": "failure",
    "denied": "failure",
    "blocked": "failure",
    "rejected": "failure",
    "successful": "success",
    "succeeded": "success",
    "allowed": "success",
}


_ORDER_KEYWORDS: dict[str, str] = {
    "top": "DESC",
    "highest": "DESC",
    "most": "DESC",
    "largest": "DESC",
    "biggest": "DESC",
    "lowest": "ASC",
    "smallest": "ASC",
    "least": "ASC",
}


_TIME_REGEX = re.compile(
    r"\b(?:last|past|previous)\s+(\d+)\s*(minute|minutes|hour|hours|day|days|week|weeks|month|months)\b",
    re.IGNORECASE,
)
# Time phrases without an explicit count: ``last hour``, ``past day``.
# We treat the count as 1 in that case.
_TIME_REGEX_SINGULAR = re.compile(
    r"\b(?:last|past|previous)\s+(minute|hour|day|week|month)\b",
    re.IGNORECASE,
)


# Numeric aggregation patterns. The lookahead stops at the next clause
# boundary so we don't drag the rest of the question into the field name.
_NUMERIC_AGG_PATTERNS: list[tuple[str, str]] = [
    (
        r"\b(?:average|avg|mean)\s+([a-z][a-z _\.]+?)" r"(?=\b(?:by|per|in|over|with|where|and|having|,|$))",
        "AVG",
    ),
    (
        r"\b(?:sum(?:\s+of)?|total(?:\s+of)?)\s+([a-z][a-z _\.]+?)" r"(?=\b(?:by|per|in|over|with|where|and|having|,|$))",
        "SUM",
    ),
    (
        r"\b(?:max|maximum|largest|highest)\s+([a-z][a-z _\.]+?)" r"(?=\b(?:by|per|in|over|with|where|and|having|,|$))",
        "MAX",
    ),
    (
        r"\b(?:min|minimum|lowest|smallest)\s+([a-z][a-z _\.]+?)" r"(?=\b(?:by|per|in|over|with|where|and|having|,|$))",
        "MIN",
    ),
]


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def _normalise(question: str) -> str:
    return re.sub(r"\s+", " ", question.strip().lower())


def _resolve_field(token: str) -> str | None:
    token = token.strip().lower()
    if token in _FIELD_ALIASES:
        return _FIELD_ALIASES[token]
    # Trim trailing 's' for trivial plurals (``hosts`` → ``host``,
    # ``users`` → ``user``). Not perfect, but it covers the common cases
    # without dragging in an inflection library.
    if token.endswith("s") and token[:-1] in _FIELD_ALIASES:
        return _FIELD_ALIASES[token[:-1]]
    # ``processes`` → ``process``, ``addresses`` → ``address``: handle the
    # ``-es`` suffix where naive ``-s`` stripping leaves an unresolvable stem.
    if token.endswith("es") and token[:-2] in _FIELD_ALIASES:
        return _FIELD_ALIASES[token[:-2]]
    # ``queries`` → ``query``, ``identities`` → ``identity``.
    if token.endswith("ies") and (token[:-3] + "y") in _FIELD_ALIASES:
        return _FIELD_ALIASES[token[:-3] + "y"]
    # Last resort: if the user typed a dotted ECS field, accept it.
    if re.fullmatch(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+", token):
        return token
    return None


def _extract_country_filter(text: str, intents: QueryIntents) -> set[str]:
    """Detect natural-language country mentions and add a geo filter.

    Returns the set of *raw country tokens* matched in ``text`` so the
    downstream ``from <hostname>`` matcher can skip them and avoid
    double-classifying e.g. "Iran" as a hostname.

    Triggers on either:

    * Explicit prepositional phrasing — "from Iran", "in Russia",
      "originating from China", "out of North Korea" — which is the
      common SOC-analyst voice.
    * Bare country mentions when the question contains a category keyword
      that implies geo provenance (``attacks``, ``traffic``, ``logins``,
      ``sessions``, ``connections``, ``activity``, ``hits``).

    The matcher walks the country table longest-first so multi-word names
    ("united states", "united kingdom", "north korea") win over their
    single-word substrings ("united", "korea").
    """
    matched_tokens: set[str] = set()
    seen_iso: set[str] = set()

    # Sort longest-first so "north korea" beats the substrings "north" and
    # "korea". The table is small (<100 entries) so the cost is irrelevant.
    countries = sorted(_COUNTRY_TO_ISO.keys(), key=len, reverse=True)

    geo_preps = (
        "from",
        "in",
        "out of",
        "originating from",
        "originated from",
        "based in",
        "located in",
        "coming from",
    )
    geo_categories = (
        "attack",
        "attacks",
        "traffic",
        "login",
        "logins",
        "session",
        "sessions",
        "connection",
        "connections",
        "activity",
        "hits",
        "request",
        "requests",
        "scan",
        "scans",
    )
    has_geo_category = any(re.search(rf"\b{kw}\b", text) for kw in geo_categories)

    for country in countries:
        iso = _COUNTRY_TO_ISO[country]
        # Explicit "from <country>" / "in <country>" / etc.
        for prep in geo_preps:
            if re.search(rf"\b{prep}\s+{re.escape(country)}\b", text):
                if iso not in seen_iso:
                    intents.filters.append(("source.geo.country_iso_code", "==", iso))
                    seen_iso.add(iso)
                matched_tokens.add(country)
                # Also add the trailing word so the bare-hostname loop
                # downstream skips e.g. "korea" when it saw "north korea".
                matched_tokens.update(country.split())
                break
        # Bare mention when the question reads like a geo question.
        if country in matched_tokens:
            continue
        if has_geo_category and re.search(rf"\b{re.escape(country)}\b", text):
            if iso not in seen_iso:
                intents.filters.append(("source.geo.country_iso_code", "==", iso))
                seen_iso.add(iso)
            matched_tokens.add(country)
            matched_tokens.update(country.split())

    return matched_tokens


def _extract_filters(question: str, intents: QueryIntents) -> None:
    text = _normalise(question)

    # Geo-from filter (must run before the bare ``from <hostname>`` matcher
    # at the bottom of this function so "from Iran" doesn't become a
    # ``host.name`` filter against the literal string "iran").
    country_tokens = _extract_country_filter(text, intents)

    # event.outcome filter (failed / successful / etc.)
    for kw, outcome in _OUTCOME_KEYWORDS.items():
        if re.search(rf"\b{kw}\b", text):
            intents.filters.append(("event.outcome", "==", outcome))
            break

    # event.category filter (login, dns, file, ...). Match plurals too
    # (``logins``, ``logons``, ``authentications``, ``processes``).
    for kw, category in _CATEGORY_KEYWORDS.items():
        if re.search(rf"\b{kw}s?\b", text) or re.search(rf"\b{kw}es\b", text):
            intents.filters.append(("event.category", "==", category))
            break

    # Quoted string literals → match against ``message`` (best-effort).
    for match in re.finditer(r'"([^"]+)"', question):
        intents.filters.append(("message", "LIKE", match.group(1)))

    # Field-comparison patterns: ``user is alice``, ``host = web01``,
    # ``port equals 22``. To avoid the regex engine swallowing whole prefixes
    # into the field name (a Python regex pitfall with lazy quantifiers in
    # ``finditer``), we anchor on the known aliases first. The right-hand
    # side accepts a single word/value token.
    _value_re = r"([a-z0-9_\-\.@\*]+)"
    _ops_re = r"(?:is|=|==|equals?|matches?)"
    seen_pairs: set[tuple[str, str]] = set()
    # Build alias patterns longest-first so multi-word aliases match before
    # their single-word substrings (``destination ip`` before ``ip``).
    for alias in sorted(_FIELD_ALIASES, key=len, reverse=True):
        canonical = _FIELD_ALIASES[alias]
        pattern = rf"\b{re.escape(alias)}\s+{_ops_re}\s+{_value_re}\b"
        for m in re.finditer(pattern, text):
            value = m.group(1).strip()
            if value in {"the", "a", "an", "any", "all", "in", "and", "or"}:
                continue
            key = (canonical, value)
            if key in seen_pairs:
                continue
            seen_pairs.add(key)
            intents.filters.append((canonical, "==", value))

    # ``failed login from <ip>``
    ip_match = re.search(r"\bfrom\s+(\d{1,3}(?:\.\d{1,3}){3})\b", text)
    if ip_match:
        intents.filters.append(("source.ip", "==", ip_match.group(1)))

    # ``from host X`` / ``for user X`` / ``on container X`` style filters
    # where the relationship is implicit. We scope this to a small set of
    # safe prepositions and field aliases so we don't accidentally swallow
    # other clauses like ``from the last hour``.
    _IMPLICIT_PREPS = ("from", "for", "on", "by")
    _IMPLICIT_FIELDS = (
        "host",
        "hostname",
        "user",
        "username",
        "container",
        "service",
        "process",
        "domain",
    )
    for prep in _IMPLICIT_PREPS:
        for field_name in _IMPLICIT_FIELDS:
            resolved = _resolve_field(field_name)
            if not resolved:
                continue
            pattern = rf"\b{prep}\s+{re.escape(field_name)}\s+([a-z0-9_\-\.@\*]+)\b"
            for m in re.finditer(pattern, text):
                value = m.group(1).strip()
                if value in {
                    "the",
                    "a",
                    "an",
                    "any",
                    "all",
                    "in",
                    "and",
                    "or",
                    "is",
                    "with",
                    "where",
                    "having",
                }:
                    continue
                # Avoid double-adding a filter we already extracted via the
                # explicit ``field is value`` path.
                key = (resolved, value)
                if key in seen_pairs:
                    continue
                seen_pairs.add(key)
                intents.filters.append((resolved, "==", value))

    # Bare ``from <hostname>`` — no explicit field word but the token looks
    # like a hostname (alphanumeric with at least one digit, or contains a
    # dot like an FQDN). We deliberately require a digit-or-dot so we don't
    # collide with prose like ``from the last hour`` or ``from authentication``.
    for m in re.finditer(
        r"\bfrom\s+([a-z][a-z0-9_\-]*\d[a-z0-9_\-]*|[a-z][a-z0-9_\-]*\.[a-z0-9_\-\.]+)\b",
        text,
    ):
        value = m.group(1).strip()
        # Skip values already captured (the explicit-field loop above runs
        # first) and skip anything that looks like an IPv4 address — that's
        # handled by the dedicated source.ip extractor higher up.
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", value):
            continue
        # Skip country names already handled by the geo filter above.
        if value in country_tokens:
            continue
        key = ("host.name", value)
        if key in seen_pairs:
            continue
        seen_pairs.add(key)
        intents.filters.append(("host.name", "==", value))


def _extract_time_range(question: str, default_hours: int) -> int:
    match = _TIME_REGEX.search(question)
    if match:
        quantity = int(match.group(1))
        unit = match.group(2).lower()
    else:
        singular = _TIME_REGEX_SINGULAR.search(question)
        if not singular:
            return default_hours
        quantity = 1
        unit = singular.group(1).lower()
    if unit.startswith("minute"):
        # Round up to at least one hour for dialects that work in hours.
        return max(1, (quantity + 59) // 60)
    if unit.startswith("hour"):
        return max(1, quantity)
    if unit.startswith("day"):
        return max(1, quantity * 24)
    if unit.startswith("week"):
        return max(1, quantity * 24 * 7)
    if unit.startswith("month"):
        return max(1, quantity * 24 * 30)
    return default_hours


def _extract_group_by(question: str, intents: QueryIntents) -> None:
    text = _normalise(question)
    # Expand ``by X and Y`` / ``per X and Y`` into ``by X, by Y`` so the
    # single-field regex below picks up both halves. We only expand once
    # to keep behaviour predictable for runs with three or more fields.
    text = re.sub(
        r"\b(by|per)\s+([a-z][a-z _\.]+?)\s+and\s+([a-z][a-z _\.]+?)"
        r"(?=\b(?:in|over|for|with|where|having|in the|last|past|previous|,|$))",
        r"\1 \2, \1 \3",
        text + " ,",
    )
    for m in re.finditer(
        r"\b(?:by|per|grouped by|group by)\s+([a-z][a-z _\.]+?)"
        r"(?=\b(?:in|over|for|with|where|having|in the|and|last|past|previous|,|$))",
        text,
    ):
        candidate = m.group(1).strip().rstrip(",")
        canonical = _resolve_field(candidate)
        if canonical and canonical not in intents.group_by:
            intents.group_by.append(canonical)


def _extract_aggregations(question: str, intents: QueryIntents) -> None:
    text = _normalise(question)

    # "count of failed logins by user"
    if re.search(r"\b(count|how many|number of)\b", text):
        intents.aggregations.append(("COUNT", None, "event_count"))

    # Numeric aggregations: "average bytes", "sum of bytes", "max bytes".
    seen_aggs: set[tuple[str, str]] = set()
    for pattern, func in _NUMERIC_AGG_PATTERNS:
        for m in re.finditer(pattern, text + " ,"):
            candidate = m.group(1).strip().rstrip(",")
            canonical = _resolve_field(candidate)
            if not canonical:
                continue
            key = (func, canonical)
            if key in seen_aggs:
                continue
            seen_aggs.add(key)
            alias = f"{func.lower()}_{canonical.replace('.', '_')}"
            intents.aggregations.append((func, canonical, alias))

    # "unique users", "distinct hosts" — the lookahead lets us stop at the
    # next clause boundary (``with``, ``having``, ``in the last 24h`` etc.)
    # without dragging the whole tail of the question into the field name.
    for m in re.finditer(
        r"\b(?:unique|distinct)\s+([a-z _]+?)" r"(?=\b(?:by|per|in|over|with|where|having|from|and|,|$))",
        text + " ,",
    ):
        candidate = m.group(1).strip().rstrip(",")
        canonical = _resolve_field(candidate)
        if canonical:
            intents.aggregations.append(("DISTINCT_COUNT", canonical, f"unique_{canonical.replace('.', '_')}"))
            intents.distinct = canonical

    # "top 10 hosts" / "top hosts"
    top_m = re.search(r"\btop\s+(\d+)?\s*([a-z _\.]+?)(?=\b(?:by|in|over|with|where|and|,|$))", text + " ,")
    if top_m:
        try:
            limit = int(top_m.group(1)) if top_m.group(1) else 10
        except ValueError:
            limit = 10
        intents.limit = limit
        candidate = top_m.group(2).strip().rstrip(",")
        canonical = _resolve_field(candidate)
        if canonical and canonical not in intents.group_by:
            intents.group_by.append(canonical)
        if not any(agg[0] == "COUNT" for agg in intents.aggregations):
            intents.aggregations.append(("COUNT", None, "event_count"))
        intents.sort_by = ("event_count", "DESC")

    # "show me last 100 events" / "limit 50". Carefully require that the
    # number is *not* immediately followed by a time unit, otherwise
    # ``in the last 24 hours`` would be misinterpreted as a row limit.
    lim_m = re.search(
        r"\b(?:limit|last|first)\s+(\d+)\b(?!\s*(?:minute|minutes|hour|hours|day|days|week|weeks|month|months))",
        text,
    )
    if lim_m and not top_m:
        try:
            intents.limit = int(lim_m.group(1))
        except ValueError as exc:
            # Regex group is `\d+`, so int() should never fail here. If it
            # somehow does (e.g. an upstream regex change), keep the dataclass
            # default rather than failing the whole NL → ES|QL parse.
            logger.debug("nl_query.limit_parse_failed value=%r err=%s", lim_m.group(1), exc)

    # Sort hints (highest, lowest)
    for kw, direction in _ORDER_KEYWORDS.items():
        if re.search(rf"\b{kw}\b", text):
            if intents.sort_by is None and intents.aggregations:
                intents.sort_by = (intents.aggregations[0][2], direction)
            break


def parse_intents(query: NLQuery) -> QueryIntents:
    """Parse *query* into a :class:`QueryIntents` IR."""

    intents = QueryIntents()
    _extract_filters(query.question, intents)
    _extract_aggregations(query.question, intents)
    _extract_group_by(query.question, intents)
    # If the user grouped by something (``per host``, ``by user``) but never
    # named an explicit aggregation, default to ``COUNT(*)`` — the only thing
    # you can sensibly compute over a grouping with no measure.
    if intents.group_by and not intents.aggregations:
        intents.aggregations.append(("COUNT", None, "event_count"))
        if intents.sort_by is None:
            intents.sort_by = ("event_count", "DESC")
    intents.time_field = "@timestamp"
    return intents


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------


def _render_esql_value(value: str) -> str:
    if re.fullmatch(r"-?\d+(?:\.\d+)?", value):
        return value
    return '"' + value.replace('"', '\\"') + '"'


def _render_esql(query: NLQuery, intents: QueryIntents) -> str:
    lines = [f"FROM {query.index_pattern}"]
    lines.append(f"| WHERE {intents.time_field} > NOW() - {query.time_range_hours}h")

    for fld, op, value in intents.filters:
        if op == "LIKE":
            lines.append(f'| WHERE {fld} LIKE "*{value}*"')
        else:
            lines.append(f"| WHERE {fld} == {_render_esql_value(value)}")

    if intents.aggregations:
        agg_parts: list[str] = []
        for func, arg, alias in intents.aggregations:
            if func == "COUNT":
                agg_parts.append(f"{alias} = COUNT(*)")
            elif func == "DISTINCT_COUNT" and arg:
                agg_parts.append(f"{alias} = COUNT_DISTINCT({arg})")
            elif arg:
                agg_parts.append(f"{alias} = {func}({arg})")
        stats_line = "| STATS " + ", ".join(agg_parts)
        if intents.group_by:
            stats_line += " BY " + ", ".join(intents.group_by)
        lines.append(stats_line)

    if intents.sort_by:
        fld, direction = intents.sort_by
        lines.append(f"| SORT {fld} {direction}")

    lines.append(f"| LIMIT {intents.limit}")
    return "\n".join(lines)


def _render_kql(query: NLQuery, intents: QueryIntents) -> str:
    table = _kql_table_for(query.index_pattern)
    lines = [table]
    lines.append(f"| where {intents.time_field.lstrip('@')} > ago({query.time_range_hours}h)")

    for fld, op, value in intents.filters:
        kfld = fld.replace(".", "_")
        if op == "LIKE":
            lines.append(f'| where {kfld} contains "{value}"')
        elif re.fullmatch(r"-?\d+(?:\.\d+)?", value):
            lines.append(f"| where {kfld} == {value}")
        else:
            lines.append(f'| where {kfld} == "{value}"')

    if intents.aggregations:
        agg_parts: list[str] = []
        for func, arg, alias in intents.aggregations:
            if func == "COUNT":
                agg_parts.append(f"{alias} = count()")
            elif func == "DISTINCT_COUNT" and arg:
                agg_parts.append(f"{alias} = dcount({arg.replace('.', '_')})")
            elif arg:
                agg_parts.append(f"{alias} = {func.lower()}({arg.replace('.', '_')})")
        summarize_line = "| summarize " + ", ".join(agg_parts)
        if intents.group_by:
            summarize_line += " by " + ", ".join(g.replace(".", "_") for g in intents.group_by)
        lines.append(summarize_line)

    if intents.sort_by:
        fld, direction = intents.sort_by
        lines.append(f"| order by {fld} {direction.lower()}")

    lines.append(f"| take {intents.limit}")
    return "\n".join(lines)


def _kql_table_for(index_pattern: str) -> str:
    pattern = index_pattern.lower()
    if "winlog" in pattern or "windows" in pattern:
        return "SecurityEvent"
    if "syslog" in pattern or "linux" in pattern:
        return "Syslog"
    if "firewall" in pattern or "fw-" in pattern:
        return "CommonSecurityLog"
    if "auth" in pattern:
        return "SigninLogs"
    return "SecurityEvent"


def _render_spl(query: NLQuery, intents: QueryIntents) -> str:
    parts = [f"index=* earliest=-{query.time_range_hours}h"]

    filter_terms: list[str] = []
    for fld, op, value in intents.filters:
        sfld = fld.replace(".", "_")
        if op == "LIKE":
            filter_terms.append(f'{sfld}="*{value}*"')
        elif re.fullmatch(r"-?\d+(?:\.\d+)?", value):
            filter_terms.append(f"{sfld}={value}")
        else:
            filter_terms.append(f'{sfld}="{value}"')
    if filter_terms:
        parts[0] += " " + " ".join(filter_terms)

    if intents.aggregations:
        agg_parts: list[str] = []
        for func, arg, alias in intents.aggregations:
            if func == "COUNT":
                agg_parts.append(f"count as {alias}")
            elif func == "DISTINCT_COUNT" and arg:
                agg_parts.append(f"dc({arg.replace('.', '_')}) as {alias}")
            elif arg:
                agg_parts.append(f"{func.lower()}({arg.replace('.', '_')}) as {alias}")
        stats_line = "stats " + " ".join(agg_parts)
        if intents.group_by:
            stats_line += " by " + " ".join(g.replace(".", "_") for g in intents.group_by)
        parts.append(stats_line)

    if intents.sort_by:
        fld, direction = intents.sort_by
        prefix = "-" if direction == "DESC" else "+"
        parts.append(f"sort {prefix}{fld}")

    parts.append(f"head {intents.limit}")
    return " | ".join(parts)


def _explain(intents: QueryIntents, query: NLQuery) -> str:
    fragments: list[str] = []
    if intents.filters:
        rendered = ", ".join(f"{f}={v}" for f, _, v in intents.filters)
        fragments.append(f"filtering events where {rendered}")
    if intents.aggregations:
        agg_text = ", ".join(f"{func.lower()}({arg or '*'}) as {alias}" for func, arg, alias in intents.aggregations)
        fragments.append(f"computing {agg_text}")
    if intents.group_by:
        fragments.append(f"grouped by {', '.join(intents.group_by)}")
    if intents.sort_by:
        fld, direction = intents.sort_by
        fragments.append(f"sorted by {fld} {direction.lower()}")
    fragments.append(f"limited to {intents.limit} rows")
    fragments.append(f"over the last {query.time_range_hours}h")
    return "Translates the question by " + "; ".join(fragments) + "."


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


class Translator:
    """Stateless translator. Kept as a class so callers can DI a custom one."""

    def translate(self, query: NLQuery) -> TranslatedQuery:
        intents = parse_intents(query)

        # Apply time-range hints from the question itself, e.g. "last 7 days".
        effective_hours = _extract_time_range(query.question, query.time_range_hours)
        if effective_hours != query.time_range_hours:
            query = NLQuery(
                question=query.question,
                index_pattern=query.index_pattern,
                time_range_hours=effective_hours,
            )

        esql = _render_esql(query, intents)
        kql = _render_kql(query, intents)
        spl = _render_spl(query, intents)

        # Validate every emitted query — bail loudly if our renderer is broken.
        validate_esql(esql)
        validate_kql(kql)
        validate_spl(spl)

        return TranslatedQuery(
            esql=esql,
            kql=kql,
            spl=spl,
            explanation=_explain(intents, query),
            intents=intents,
        )


_default_translator = Translator()


def translate(
    question: str,
    *,
    index_pattern: str = "logs-*",
    time_range_hours: int = 24,
) -> TranslatedQuery:
    """Module-level convenience wrapper around :class:`Translator`."""

    return _default_translator.translate(NLQuery(question=question, index_pattern=index_pattern, time_range_hours=time_range_hours))


# ---------------------------------------------------------------------------
# Optional LLM enhancement
# ---------------------------------------------------------------------------


async def enhance_with_llm(
    query: NLQuery,
    *,
    api_key: str,
    model: str = "gpt-4o-mini",
    timeout: float = 30.0,
    fallback: TranslatedQuery | None = None,
) -> TranslatedQuery:
    """Try to obtain a richer translation from an LLM, falling back on errors.

    The LLM call is best-effort. If the model returns invalid JSON, queries
    that fail grammar validation, or simply fails to respond in time, we
    return *fallback* (or the deterministic translation if not provided).
    """

    deterministic = fallback or _default_translator.translate(query)

    try:
        import json
        import textwrap

        import httpx  # local import — keeps the offline path zero-dependency

        prompt = textwrap.dedent(
            f"""
            Translate the following security question into ES|QL, KQL, and SPL.
            Return JSON only with keys esql, kql, spl, explanation.

            Question: {query.question}
            Index: {query.index_pattern}
            Time range: last {query.time_range_hours} hours
            """
        ).strip()

        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json={
                    "model": model,
                    "response_format": {"type": "json_object"},
                    "temperature": 0,
                    "messages": [
                        {"role": "system", "content": "You translate security questions into queries."},
                        {"role": "user", "content": prompt},
                    ],
                },
            )
        if resp.status_code != 200:
            logger.info("nl_query LLM call failed: status=%s", resp.status_code)
            return deterministic

        payload = resp.json()
        content = payload["choices"][0]["message"]["content"]
        parsed = json.loads(content)
        esql = str(parsed.get("esql", "")).strip()
        kql = str(parsed.get("kql", "")).strip()
        spl = str(parsed.get("spl", "")).strip()
        if not (esql and kql and spl):
            return deterministic
        validate_esql(esql)
        validate_kql(kql)
        validate_spl(spl)
        return TranslatedQuery(
            esql=esql,
            kql=kql,
            spl=spl,
            explanation=str(parsed.get("explanation", deterministic.explanation)),
            intents=deterministic.intents,
        )
    except (GrammarError, ValueError, KeyError, TypeError) as exc:
        logger.info("nl_query LLM result rejected by grammar: %s", exc)
        return deterministic
    except Exception as exc:  # pragma: no cover - network / import issues
        logger.info("nl_query LLM enhancement failed: %s", exc)
        return deterministic


__all__ = [
    "NLQuery",
    "QueryIntents",
    "TranslatedQuery",
    "Translator",
    "translate",
    "parse_intents",
    "enhance_with_llm",
]
