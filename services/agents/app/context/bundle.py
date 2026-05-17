"""ContextBundle model + builder — T2.1.

A :class:`ContextBundle` is the *pre-fetched* context object that the four
public agents (Detect / Triage / Hunt / Respond) and their internal
capability shims (phishing, identity, cloud, insider-threat) consume in
place of issuing their own primary-discovery tool calls.

The builder fans out to four read-only context sources concurrently:

* graph neighbourhood (``services/api`` — depth-N walk per principal entity),
* institutional memory (``aisoc_institutional_memory`` — similar-case
  verdicts keyed by template / category / IOC tag),
* UEBA baselines (``services/ueba`` — per-entity peer baseline + deviation),
* threat intel (``services/enrichment`` — per-IOC reputation + risk).

Every field is optional and the bundle is allowed to be partial — a
context source that times out, errors, or is unavailable populates the
``errors`` list and leaves its slot empty so the consumer can fall back
to its own primary-discovery code path. Tests gate the *build latency*
(p95 < 5s across the 200-incident benchmark), not the *contents*, because
the eval harness runs offline against substrate stubs.

The model is the *only* shape an agent should hand to the LLM-input
contract (T2.3) — its ``summary_for_llm`` method returns a dict whose
keys are explicitly enumerated as allowed by ``LLMInputContract``.
"""

from __future__ import annotations

import asyncio
import os
import re
import time
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# ---------------------------------------------------------------------------
# Entity extraction
# ---------------------------------------------------------------------------

# Map of raw_alert key → entity type. Order matters only insofar as it controls
# which alias is preferred when several keys point at the same logical entity.
_HOST_KEYS = (
    "host",
    "hostname",
    "Computer",
    "computer",
    "device",
    "asset",
    "endpoint",
)
_USER_KEYS = (
    "user",
    "username",
    "user_email",
    "UserId",
    "principal",
    "actor",
    "sender",
    "recipient",
)
_IP_KEYS = (
    "src_ip",
    "source_ip",
    "ClientIP",
    "client_ip",
    "dst_ip",
    "dest_ip",
    "destination_ip",
    "remote_ip",
    "ip",
)
_DOMAIN_KEYS = ("domain", "sender_domain", "fqdn", "host_domain")
_HASH_KEYS = ("file_hash", "sha256", "md5", "sha1", "hash")
_URL_KEYS = ("url", "primary_url")

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.IGNORECASE)
_HASH_RE = re.compile(r"\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b", re.IGNORECASE)


class EntityRef(BaseModel):
    """Stable reference to an entity in the alert.

    ``key`` is the canonical join key used as the dict key in
    ``entity_neighborhoods`` / ``peer_baselines`` / ``threat_intel``.
    """

    type: str  # host | user | ip | domain | hash | url | email
    value: str

    @property
    def key(self) -> str:
        return f"{self.type}:{self.value}"


def _string_field(raw: dict[str, Any], keys: tuple[str, ...]) -> list[str]:
    out: list[str] = []
    for key in keys:
        val = raw.get(key)
        if isinstance(val, str) and val.strip():
            out.append(val.strip())
        elif isinstance(val, (list, tuple)):
            for v in val:
                if isinstance(v, str) and v.strip():
                    out.append(v.strip())
    return out


def extract_entities(raw_alert: dict[str, Any], *, summary: str = "") -> list[EntityRef]:
    """Extract a deduplicated list of entities from the raw alert + summary.

    Pulled out into a top-level function so the builder's tests can hit it
    directly without spinning up the full builder.
    """
    found: dict[str, EntityRef] = {}

    def _add(etype: str, value: str) -> None:
        value = value.strip()
        if not value:
            return
        ref = EntityRef(type=etype, value=value)
        found.setdefault(ref.key, ref)

    for v in _string_field(raw_alert, _HOST_KEYS):
        _add("host", v)
    for v in _string_field(raw_alert, _USER_KEYS):
        # Distinguish email-shaped users from bare usernames so the bundle
        # can be cross-joined with the email-channel TI sources downstream.
        etype = "email" if "@" in v else "user"
        _add(etype, v)
    for v in _string_field(raw_alert, _IP_KEYS):
        _add("ip", v)
    for v in _string_field(raw_alert, _DOMAIN_KEYS):
        _add("domain", v.lower())
    for v in _string_field(raw_alert, _HASH_KEYS):
        _add("hash", v.lower())
    for v in _string_field(raw_alert, _URL_KEYS):
        _add("url", v)

    # Best-effort regex sweep over the alert summary so generic alerts that
    # only carry a free-text description still get an entity vector. The
    # summary regexes run on the joined text so we don't miss IOCs that
    # straddle a boundary.
    text = " ".join([summary or "", str(raw_alert.get("description", "")), str(raw_alert.get("title", ""))])
    for ip in _IPV4_RE.findall(text):
        _add("ip", ip)
    for h in _HASH_RE.findall(text):
        _add("hash", h.lower())
    for d in _DOMAIN_RE.findall(text):
        # Filter out things that look like file extensions / version numbers
        # by requiring a TLD of length >= 2 and a body of length >= 4.
        if len(d) >= 6 and "." in d:
            _add("domain", d.lower())

    return list(found.values())


# ---------------------------------------------------------------------------
# Sub-models
# ---------------------------------------------------------------------------


class EntityNeighborhood(BaseModel):
    """Result of a depth-N graph walk centred on a single entity."""

    entity: EntityRef
    depth: int = 2
    nodes: list[dict[str, Any]] = Field(default_factory=list)
    edges: list[dict[str, Any]] = Field(default_factory=list)
    blast_radius_score: float | None = None
    summary: str = ""

    @property
    def node_count(self) -> int:
        return len(self.nodes)


class HistoricalCase(BaseModel):
    """A previously-closed case judged similar to the current alert.

    Pulled from ``aisoc_institutional_memory`` (PostgreSQL with an in-process
    fallback). ``similarity_score`` is computed by the builder using a
    deterministic Jaccard over template_id / response_class / IOC tags so
    eval runs are reproducible.
    """

    key: str
    verdict: str
    confidence: float = 0.0
    template_id: str | None = None
    response_class: str | None = None
    similarity_score: float = 0.0
    rationale: str | None = None
    closed_at: str | None = None


class UEBABaseline(BaseModel):
    """Per-entity UEBA baseline + peer-group deviation.

    Mirrors the shape returned by ``services/ueba`` ``/api/v1/ueba/baselines``
    so the bundle can pass through what the UEBA service computed without
    re-deriving it.
    """

    entity: EntityRef
    peer_group_id: str | None = None
    activity_window_days: int = 30
    baseline: dict[str, float] = Field(default_factory=dict)
    deviation_score: float = 0.0
    notes: str = ""


class ThreatIntelMatch(BaseModel):
    """Per-IOC enrichment record."""

    ioc: str
    ioc_type: str
    sources: list[str] = Field(default_factory=list)
    risk: str = "unknown"  # low | medium | high | unknown
    first_seen: str | None = None
    last_seen: str | None = None
    summary: str = ""


# ---------------------------------------------------------------------------
# ContextBundle
# ---------------------------------------------------------------------------


# Allowed top-level keys in ``summary_for_llm`` — kept here (not in
# ``app/llm/contract.py``) so the model is the source of truth and the
# contract validator can import this whitelist. Public (no leading
# underscore) because it is imported by tests and by external contract
# validators; the previous private-with-suppression form tripped CodeQL
# ``py/unused-global-variable`` because the inline suppression marker
# was not honoured by the analyzer.
LLM_SAFE_KEYS = (
    "incident_id",
    "alert_summary",
    "entity_count",
    "entity_types",
    "entity_keys",
    "neighborhood_summaries",
    "blast_radius_max",
    "historical_similar_count",
    "historical_verdicts",
    "ueba_max_deviation",
    "ueba_entities_with_baseline",
    "threat_intel_high_risk_iocs",
    "threat_intel_match_count",
    "threat_intel_sources",
    "build_latency_ms",
    "sources_called",
    "errors",
)


class ContextBundle(BaseModel):
    """Pre-fetched, structured context handed to every sub-agent."""

    bundle_id: UUID = Field(default_factory=uuid4)
    incident_id: UUID
    tenant_id: str = "default"
    alert_summary: str = ""

    # Discovered entities + per-entity context, keyed by ``EntityRef.key``.
    entities: list[EntityRef] = Field(default_factory=list)
    entity_neighborhoods: dict[str, EntityNeighborhood] = Field(default_factory=dict)
    peer_baselines: dict[str, UEBABaseline] = Field(default_factory=dict)
    threat_intel: dict[str, ThreatIntelMatch] = Field(default_factory=dict)

    # Memory (institutional tier) recall.
    historical_similar_cases: list[HistoricalCase] = Field(default_factory=list)

    # Provenance / health.
    build_started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    build_completed_at: datetime | None = None
    build_latency_ms: int = 0
    sources_called: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    depth: int = 2

    @property
    def is_complete(self) -> bool:
        """True when at least one source returned data and there are no errors."""
        return self.build_completed_at is not None and not self.errors

    @property
    def has_any_context(self) -> bool:
        """True when *any* slot in the bundle has actual content.

        Used by sub-agents to decide whether to short-circuit to the
        bundle-aware prompt or fall back to bare-alert reasoning.
        """
        return bool(
            self.entity_neighborhoods
            or self.peer_baselines
            or self.threat_intel
            or self.historical_similar_cases
        )

    def prompt_context_lines(self) -> list[str]:
        """Render the bundle's safe summary fields as prompt-ready lines.

        Sub-agents call this to inject pre-fetched context (entity
        neighbourhood, historical verdicts, UEBA deviation, TI matches)
        instead of re-discovering the same facts via primary tool calls.
        Only fields enumerated by ``summary_for_llm`` are surfaced — never
        raw OCSF or log payloads.
        """
        if not self.has_any_context:
            return []
        s = self.summary_for_llm()
        parts: list[str] = ["", "Pre-fetched investigation context (ContextBundle):"]
        if s.get("entity_count"):
            parts.append(
                f"- Entities resolved: {s['entity_count']} "
                f"({', '.join(s.get('entity_types') or []) or 'unknown'})"
            )
        if s.get("neighborhood_summaries"):
            parts.append("- Graph neighbourhood:")
            for line in s["neighborhood_summaries"]:
                parts.append(f"    * {line}")
        if s.get("blast_radius_max"):
            parts.append(f"- Max blast-radius score: {s['blast_radius_max']:.2f}")
        if s.get("historical_similar_count"):
            top = max(
                (h["similarity"] for h in s.get("historical_verdicts") or []),
                default=0.0,
            )
            parts.append(
                f"- Similar historical cases: {s['historical_similar_count']} "
                f"(top similarity={top:.2f})"
            )
            for h in (s.get("historical_verdicts") or [])[:3]:
                parts.append(f"    * {h['key']} → {h['verdict']} (sim={h['similarity']:.2f})")
        if s.get("ueba_entities_with_baseline"):
            parts.append(
                f"- UEBA: {s['ueba_entities_with_baseline']} entities with baseline, "
                f"max deviation={s.get('ueba_max_deviation', 0.0):.2f}"
            )
        if s.get("threat_intel_match_count"):
            parts.append(
                f"- Threat-intel matches: {s['threat_intel_match_count']} "
                f"(high-risk IOCs: {', '.join(s.get('threat_intel_high_risk_iocs') or []) or 'none'})"
            )
        return parts

    def summary_for_llm(self) -> dict[str, Any]:
        """Pre-digested, contract-safe summary for LLM prompts.

        Every key returned here is on ``LLM_SAFE_KEYS`` and contains either
        a scalar, a small list of scalars, or a list of short string summaries
        — never raw OCSF / log payloads. ``LLMInputContract`` (T2.3) treats
        the output of this method as the canonical safe shape.
        """
        neigh_summaries = [
            f"{key}: {nbr.node_count} nodes (depth={nbr.depth})"
            + (f", blast_radius={nbr.blast_radius_score:.2f}" if nbr.blast_radius_score is not None else "")
            for key, nbr in sorted(self.entity_neighborhoods.items())
        ]
        blast_scores = [
            n.blast_radius_score
            for n in self.entity_neighborhoods.values()
            if n.blast_radius_score is not None
        ]
        ueba_devs = [b.deviation_score for b in self.peer_baselines.values()]
        high_risk = sorted(
            ti.ioc for ti in self.threat_intel.values() if ti.risk == "high"
        )
        ti_sources: set[str] = set()
        for ti in self.threat_intel.values():
            ti_sources.update(ti.sources)
        return {
            "incident_id": str(self.incident_id),
            "alert_summary": self.alert_summary,
            "entity_count": len(self.entities),
            "entity_types": sorted({e.type for e in self.entities}),
            "entity_keys": sorted(e.key for e in self.entities)[:25],
            "neighborhood_summaries": neigh_summaries[:25],
            "blast_radius_max": max(blast_scores) if blast_scores else 0.0,
            "historical_similar_count": len(self.historical_similar_cases),
            "historical_verdicts": [
                {
                    "key": h.key,
                    "verdict": h.verdict,
                    "similarity": round(h.similarity_score, 3),
                }
                for h in self.historical_similar_cases[:10]
            ],
            "ueba_max_deviation": max(ueba_devs) if ueba_devs else 0.0,
            "ueba_entities_with_baseline": len(self.peer_baselines),
            "threat_intel_high_risk_iocs": high_risk[:20],
            "threat_intel_match_count": len(self.threat_intel),
            "threat_intel_sources": sorted(ti_sources)[:20],
            "build_latency_ms": self.build_latency_ms,
            "sources_called": sorted(self.sources_called),
            "errors": self.errors[:5],
        }


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------


def _ti_risk_from_enrichment(payload: dict[str, Any]) -> str:
    """Best-effort risk-bucket extraction from the enrichment service payload."""
    if not isinstance(payload, dict) or payload.get("error"):
        return "unknown"
    score = payload.get("risk_score") or payload.get("score") or 0.0
    try:
        score = float(score)
    except (TypeError, ValueError):
        score = 0.0
    if score >= 0.7:
        return "high"
    if score >= 0.4:
        return "medium"
    if score > 0:
        return "low"
    explicit = payload.get("risk") or payload.get("severity")
    if isinstance(explicit, str) and explicit.lower() in {"low", "medium", "high"}:
        return explicit.lower()
    return "unknown"


def _ti_sources(payload: dict[str, Any]) -> list[str]:
    if not isinstance(payload, dict):
        return []
    sources = payload.get("sources") or payload.get("providers") or []
    if isinstance(sources, list):
        return [str(s) for s in sources][:10]
    if isinstance(sources, dict):
        return list(sorted(sources.keys()))[:10]
    return []


class ContextBundleBuilder:
    """Builds a :class:`ContextBundle` for an investigation in parallel.

    The builder is constructed with timeouts/limits — it never raises, only
    appends to ``bundle.errors`` if a context source misbehaves. Sub-agent
    code paths therefore stay deterministic regardless of substrate health.
    """

    DEFAULT_DEPTH = 2

    def __init__(
        self,
        *,
        depth: int | None = None,
        max_neighborhood_nodes: int = 30,
        history_limit: int = 5,
        ti_concurrency: int = 8,
        per_source_timeout: float = 3.5,
        api_token: str | None = None,
    ) -> None:
        self.depth = depth if depth is not None else int(
            os.getenv("AISOC_CONTEXT_BUNDLE_DEPTH", str(self.DEFAULT_DEPTH))
        )
        self.max_neighborhood_nodes = max_neighborhood_nodes
        self.history_limit = history_limit
        self.ti_concurrency = ti_concurrency
        self.per_source_timeout = per_source_timeout
        self.api_token = api_token

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def build(self, state: Any) -> ContextBundle:
        """Construct a bundle for the given ``InvestigationState``.

        ``state`` is typed as ``Any`` so this module doesn't import the
        heavyweight ``InvestigationState`` at module-load time and so a
        thin dict can be passed in tests.
        """
        t0 = time.monotonic()
        incident_id = getattr(state, "incident_id", None) or uuid4()
        tenant_id = str(getattr(state, "tenant_id", "default"))
        alert_summary = getattr(state, "alert_summary", "") or ""
        raw_alert = getattr(state, "raw_alert", {}) or {}

        bundle = ContextBundle(
            incident_id=incident_id,
            tenant_id=tenant_id,
            alert_summary=alert_summary,
            depth=self.depth,
        )

        bundle.entities = extract_entities(raw_alert, summary=alert_summary)

        # Fan out — every coroutine is wrapped in ``_safe`` so a single
        # exception can't poison the bundle.
        results = await asyncio.gather(
            self._safe(
                "graph",
                self._fetch_neighborhoods(bundle.entities),
                bundle,
            ),
            self._safe(
                "memory",
                self._fetch_history(tenant_id, raw_alert, alert_summary),
                bundle,
            ),
            self._safe(
                "ueba",
                self._fetch_baselines(tenant_id, bundle.entities),
                bundle,
            ),
            self._safe(
                "threat_intel",
                self._fetch_threat_intel(bundle.entities),
                bundle,
            ),
            return_exceptions=False,
        )

        neigh_result, history_result, ueba_result, ti_result = results
        if isinstance(neigh_result, dict):
            bundle.entity_neighborhoods = neigh_result
        if isinstance(history_result, list):
            bundle.historical_similar_cases = history_result
        if isinstance(ueba_result, dict):
            bundle.peer_baselines = ueba_result
        if isinstance(ti_result, dict):
            bundle.threat_intel = ti_result

        bundle.build_completed_at = datetime.now(UTC)
        bundle.build_latency_ms = int((time.monotonic() - t0) * 1000)
        return bundle

    # ------------------------------------------------------------------
    # Source fetchers — each returns its own slice of the bundle
    # ------------------------------------------------------------------

    async def _fetch_neighborhoods(
        self, entities: list[EntityRef]
    ) -> dict[str, EntityNeighborhood]:
        """Walk the graph for each principal entity, depth-N."""
        # Lazy import so ``services/agents`` modules without the API tool
        # installed (e.g. eval harness) can still import this builder.
        try:
            from app.tools.graph import get_blast_radius, get_entity_neighbors
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(f"graph tool unavailable: {exc}") from exc

        # Only walk principal entities — IPs, domains, hashes are TI input,
        # not graph principals.
        principals = [e for e in entities if e.type in ("host", "user", "email")]
        if not principals:
            self._record_source("graph")
            return {}

        async def _walk(entity: EntityRef) -> tuple[str, EntityNeighborhood]:
            nbr_payload, blast_payload = await asyncio.gather(
                get_entity_neighbors(entity.type, entity.value, api_token=self.api_token),
                get_blast_radius(entity.type, entity.value, api_token=self.api_token, hops=self.depth),
            )
            nodes = nbr_payload.get("neighbors", []) if isinstance(nbr_payload, dict) else []
            edges = nbr_payload.get("edges", []) if isinstance(nbr_payload, dict) else []
            blast = None
            if isinstance(blast_payload, dict):
                blast = blast_payload.get("blast_radius_score")
            summary = (
                f"{len(nodes)} neighbors at depth {self.depth}"
                + (f", blast_radius={float(blast):.2f}" if blast is not None else "")
            )
            return entity.key, EntityNeighborhood(
                entity=entity,
                depth=self.depth,
                nodes=nodes[: self.max_neighborhood_nodes],
                edges=edges[: self.max_neighborhood_nodes],
                blast_radius_score=float(blast) if blast is not None else None,
                summary=summary,
            )

        out: dict[str, EntityNeighborhood] = {}
        results = await asyncio.gather(*[_walk(e) for e in principals], return_exceptions=True)
        for r in results:
            if isinstance(r, Exception):
                logger.debug("context.neighborhood.failed", error=str(r))
                continue
            key, nbr = r
            out[key] = nbr
        self._record_source("graph")
        return out

    async def _fetch_history(
        self,
        tenant_id: str,
        raw_alert: dict[str, Any],
        alert_summary: str,
    ) -> list[HistoricalCase]:
        """Pull similar-case verdicts from the institutional memory tier."""
        try:
            from app.memory.institutional import institutional_search
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(f"institutional memory unavailable: {exc}") from exc

        # Tag candidates: template_id, response_class, severity, plus a small
        # set of category tokens derived from the summary. Memory is queried
        # by tag so this is best-effort but fully deterministic for tests.
        tags: list[str] = []
        for k in ("template_id", "response_class", "category", "severity"):
            v = raw_alert.get(k)
            if isinstance(v, str) and v:
                tags.append(v)

        rows = await institutional_search(tenant_id, tags=tags or None, limit=self.history_limit)

        own_set = {t.lower() for t in tags}
        out: list[HistoricalCase] = []
        for row in rows or []:
            value = row.get("value") if isinstance(row, dict) else {}
            if not isinstance(value, dict):
                value = {}
            row_tags = {str(t).lower() for t in (row.get("tags") or [])}
            jaccard = (
                len(own_set & row_tags) / max(1, len(own_set | row_tags))
                if own_set or row_tags
                else 0.0
            )
            out.append(
                HistoricalCase(
                    key=str(row.get("key", "")),
                    verdict=str(value.get("verdict", "unknown")),
                    confidence=float(value.get("confidence", 0.0) or 0.0),
                    template_id=value.get("template_id"),
                    response_class=value.get("response_class"),
                    similarity_score=round(jaccard, 4),
                    rationale=(value.get("rationale") or value.get("summary") or None),
                    closed_at=row.get("created_at"),
                )
            )
        # Sort by similarity desc so the head of the list is most-relevant.
        out.sort(key=lambda h: h.similarity_score, reverse=True)
        self._record_source("memory")
        return out[: self.history_limit]

    async def _fetch_baselines(
        self,
        tenant_id: str,
        entities: list[EntityRef],
    ) -> dict[str, UEBABaseline]:
        """Pull per-entity UEBA baselines from the UEBA service."""
        try:
            import httpx  # type: ignore
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(f"httpx unavailable: {exc}") from exc

        ueba_url = os.getenv("AISOC_UEBA_URL", "http://ueba:8086")
        principals = [
            e for e in entities if e.type in ("user", "email", "host", "ip")
        ]
        if not principals:
            self._record_source("ueba")
            return {}

        out: dict[str, UEBABaseline] = {}

        async with httpx.AsyncClient(timeout=self.per_source_timeout) as client:
            async def _one(entity: EntityRef) -> tuple[str, UEBABaseline] | None:
                # The UEBA list endpoint takes tenant + entity_type, then we
                # filter client-side. We accept that this is over-fetching
                # for now; the bundle is still bounded by ``history_limit``.
                try:
                    resp = await client.get(
                        f"{ueba_url}/api/v1/ueba/baselines",
                        params={"tenant_id": tenant_id, "entity_type": entity.type, "limit": 50},
                    )
                    resp.raise_for_status()
                    rows = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else []
                except Exception as exc:  # noqa: BLE001
                    logger.debug("context.ueba.failed", entity=entity.key, error=str(exc))
                    return None
                if not isinstance(rows, list):
                    return None
                for row in rows:
                    if not isinstance(row, dict):
                        continue
                    if row.get("entity_id") != entity.value:
                        continue
                    return entity.key, UEBABaseline(
                        entity=entity,
                        peer_group_id=row.get("peer_group_id"),
                        activity_window_days=int(row.get("window_days", 30)),
                        baseline=row.get("baseline_features", {}) or {},
                        deviation_score=float(row.get("deviation_score", 0.0) or 0.0),
                        notes=str(row.get("notes", "")),
                    )
                return None

            results = await asyncio.gather(*[_one(e) for e in principals], return_exceptions=True)
            for r in results:
                if isinstance(r, Exception) or r is None:
                    continue
                key, baseline = r
                out[key] = baseline
        self._record_source("ueba")
        return out

    async def _fetch_threat_intel(
        self, entities: list[EntityRef]
    ) -> dict[str, ThreatIntelMatch]:
        """Bulk-enrich every IOC-shaped entity in the alert."""
        try:
            from app.tools.enrichment import bulk_enrich_iocs
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(f"enrichment tool unavailable: {exc}") from exc

        ioc_entities = [
            e for e in entities if e.type in ("ip", "domain", "hash", "url")
        ]
        if not ioc_entities:
            self._record_source("threat_intel")
            return {}

        # Bulk endpoint takes a list of {value, ioc_type} — chunk so a single
        # giant alert can't fan out >1k items.
        batch = [{"value": e.value, "ioc_type": e.type} for e in ioc_entities[:64]]
        rows = await bulk_enrich_iocs(batch)

        out: dict[str, ThreatIntelMatch] = {}
        for row in rows or []:
            if not isinstance(row, dict):
                continue
            value = row.get("value") or row.get("ioc")
            ioc_type = row.get("ioc_type") or row.get("type")
            if not value or not ioc_type:
                continue
            risk = _ti_risk_from_enrichment(row)
            out[f"{ioc_type}:{value}"] = ThreatIntelMatch(
                ioc=str(value),
                ioc_type=str(ioc_type),
                sources=_ti_sources(row),
                risk=risk,
                first_seen=row.get("first_seen"),
                last_seen=row.get("last_seen"),
                summary=str(row.get("summary") or row.get("description") or ""),
            )
        self._record_source("threat_intel")
        return out

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def _safe(self, name: str, coro: Any, bundle: ContextBundle) -> Any:
        """Run ``coro`` with a per-source timeout; record errors instead of raising."""
        try:
            return await asyncio.wait_for(coro, timeout=self.per_source_timeout)
        except asyncio.TimeoutError:
            bundle.errors.append(f"{name}:timeout")
            return None
        except Exception as exc:  # noqa: BLE001
            bundle.errors.append(f"{name}:{type(exc).__name__}")
            logger.debug("context.source.failed", source=name, error=str(exc))
            return None

    def _record_source(self, name: str) -> None:
        # Sources are recorded on the bundle by the caller via the safe-wrap;
        # this method exists for future per-source instrumentation hooks.
        pass


# Module-level convenience for callers that just want a one-shot build.
async def build_context_bundle(state: Any, **kwargs: Any) -> ContextBundle:
    """Build a :class:`ContextBundle` for the given investigation state."""
    builder = ContextBundleBuilder(**kwargs)
    bundle = await builder.build(state)
    # The fan-out itself never appends source names because the safe-wrap
    # owns the success/failure path. Add them here so ``sources_called``
    # always reflects what the builder actually attempted.
    if not bundle.sources_called:
        bundle.sources_called = sorted(["graph", "memory", "ueba", "threat_intel"])
    return bundle
