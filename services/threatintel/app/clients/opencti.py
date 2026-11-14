"""
OpenCTI GraphQL client.

Talks to an OpenCTI platform over its GraphQL API (`POST /graphql`), using
the current 6.x/7.x `FilterGroup` filter format and cursor pagination to
pull recently-updated `Indicator` objects incrementally.

The GraphQL document was validated against a live OpenCTI platform
(version 7.261008.0): one real request/response pair is captured as
`tests/fixtures/opencti_stix_core_objects.json` and replayed by
`tests/test_opencti_client.py`. Two details of that capture are worth
recording because the printed schema alone does not settle them:

- the incremental filter key is `updated_at` (the bare `updated` key is
  silently accepted and matches nothing), and
- on this build `objectLabel` and `killChainPhases` resolve to flat lists
  while `externalReferences` is a relay-style connection with `edges`.

AiSOC — open-source AI Security Operations Center (MIT License)
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

logger = structlog.get_logger(__name__)

# Cursor-paginated incremental pull of Indicator objects. Inline fragment is
# required: stixCoreObjects returns the StixCoreObject interface, so
# Indicator-only fields must be selected through `... on Indicator`.
STIX_CORE_INDICATORS_QUERY = """
query AiSocIndicators($first: Int!, $after: ID, $filters: FilterGroup) {
  stixCoreObjects(
    types: ["Indicator"]
    first: $first
    after: $after
    orderBy: updated_at
    orderMode: asc
    filters: $filters
  ) {
    edges {
      cursor
      node {
        id
        standard_id
        entity_type
        ... on Indicator {
          name
          description
          pattern
          pattern_type
          pattern_version
          revoked
          confidence
          indicator_types
          x_opencti_score
          x_opencti_main_observable_type
          created
          modified
          objectLabel { value }
          killChainPhases { kill_chain_name phase_name }
          externalReferences { edges { node { source_name url } } }
        }
      }
    }
    pageInfo { hasNextPage endCursor }
  }
}
"""

# One STIX comparison clause inside a pattern: <type>:<prop> = '<value>'.
# Leading '[' excluded: pattern strings arrive as "[ipv4-addr:value = '...']"
# and the bracket must not leak into the observable-type capture.
_PATTERN_CLAUSE_RE = re.compile(r"([^\s\[]+?):([^\s=]+?)\s*=\s*'([^']+)'")

# (observable-type, property) -> AiSOC IOC vocabulary, mirroring
# app.parsers.stix.StixParser._map_stix_type so every feed produces the
# same type strings into pipeline.ingest_iocs.
_CLAUSE_TYPE_MAP: dict[tuple[str, str], str] = {
    ("ipv4-addr", "value"): "ipv4-addr",
    ("ipv6-addr", "value"): "ipv6-addr",
    ("domain-name", "value"): "domain-name",
    ("url", "value"): "url",
    ("email-addr", "value"): "email-addr",
    ("directory", "path"): "directory",
    ("mutex", "name"): "mutex",
    ("mac-address", "value"): "mac-addr",
}

# x_opencti_main_observable_type -> fallback IOC type when a pattern clause
# does not map (e.g. patterns with composite observables).
_MAIN_OBSERVABLE_MAP: dict[str, str] = {
    "ipv4-addr": "ipv4-addr",
    "ipv6-addr": "ipv6-addr",
    "domain-name": "domain-name",
    "url": "url",
    "email-addr": "email-addr",
    "file": "file-hash:SHA-256",
    "stixfile": "file-hash:SHA-256",
    "artifact": "file-hash:SHA-256",
    "mac-address": "mac-addr",
    "mutex": "mutex",
    "autonomous-system": "asn",
    "cryptocurrency-wallet": "cryptowallet",
    "text": "other",
}


def parse_pattern(pattern: str) -> list[tuple[str, str]]:
    """Extract ``[(ioc_type, value), ...]`` from a STIX indicator pattern.

    Handles single- and multi-clause patterns
    (``[ipv4-addr:value = '1.2.3.4' OR ipv4-addr:value = '5.6.7.8']``) and
    file hash properties (``file:hashes.'SHA-256' = '<hex>'``). Unmapped
    clause types fall back to the raw ``type:property`` string so nothing is
    silently dropped.
    """
    out: list[tuple[str, str]] = []
    for obj_type, prop, value in _PATTERN_CLAUSE_RE.findall(pattern or ""):
        norm_type = obj_type.lower()
        if norm_type == "file" and prop.lower().startswith("hashes"):
            hash_name = prop.split(".")[-1].strip("'").upper()
            ioc_type = f"file-hash:{hash_name}"
        else:
            ioc_type = _CLAUSE_TYPE_MAP.get((norm_type, prop), f"{norm_type}:{prop}")
        if value:
            out.append((ioc_type, value))
    return out


def score_to_reliability(score: int | None) -> str:
    """Map an OpenCTI confidence score (0-100) to STIX confidence bands."""
    if score is None:
        return "C"
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 50:
        return "C"
    if score >= 25:
        return "D"
    return "E"


def _label_values(node: dict[str, Any]) -> list[str]:
    # Schema: Indicator-side selection resolves objectLabel to [Label!]!
    # where Label.value is String! (flat list, no relay edges on this build).
    return [lbl.get("value", "") for lbl in (node.get("objectLabel") or []) if isinstance(lbl, dict)]


class OpenCtiClient:
    """
    Async OpenCTI GraphQL client.

    Fetches recently-updated Indicator objects with cursor pagination,
    filters revoked indicators, and normalizes them into the MISP-vocabulary
    IOC dicts consumed by ``ThreatIntelPipeline.ingest_iocs``.
    """

    def __init__(
        self,
        url: str,
        token: str,
        verify_ssl: bool = True,
        page_size: int = 500,
    ) -> None:
        base = url.rstrip("/")
        self._graphql_url = base if base.endswith("/graphql") else f"{base}/graphql"
        self._verify_ssl = verify_ssl
        self._page_size = max(1, min(page_size, 1000))
        self._headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        self._last_sync: datetime | None = None

    @staticmethod
    def _filters(since: datetime) -> dict[str, Any]:
        return {
            "mode": "and",
            "filters": [
                {
                    "key": ["updated_at"],
                    "values": [since.strftime("%Y-%m-%dT%H:%M:%SZ")],
                    "operator": "gt",
                }
            ],
            "filterGroups": [],
        }

    async def get_recent_indicators(self, since_hours: int = 24) -> list[dict[str, Any]]:
        """Fetch non-revoked Indicator nodes updated since the last sync.

        The first call looks back ``since_hours``; subsequent calls resume
        from the previous successful sync watermark.
        """
        since = self._last_sync or (datetime.now(UTC) - timedelta(hours=since_hours))
        nodes: list[dict[str, Any]] = []
        after: str | None = None

        async with httpx.AsyncClient(headers=self._headers, verify=self._verify_ssl, timeout=60.0) as client:
            while True:
                resp = await client.post(
                    self._graphql_url,
                    json={
                        "query": STIX_CORE_INDICATORS_QUERY,
                        "variables": {
                            "first": self._page_size,
                            "after": after,
                            "filters": self._filters(since),
                        },
                    },
                )
                resp.raise_for_status()
                body = resp.json()
                if "errors" in body:
                    # Fail loudly: a silently-wrong query looks like an empty
                    # feed, which is the worst possible failure mode for a TI
                    # source.
                    raise RuntimeError(f"OpenCTI GraphQL errors: {body['errors'][:2]}")
                block = (body.get("data") or {}).get("stixCoreObjects") or {}
                for edge in block.get("edges") or []:
                    node = edge.get("node") or {}
                    if node.get("revoked"):
                        continue
                    nodes.append(node)
                page = block.get("pageInfo") or {}
                if not page.get("hasNextPage") or not page.get("endCursor"):
                    break
                after = page["endCursor"]

        self._last_sync = datetime.now(UTC)
        logger.info("OpenCTI indicators fetched", count=len(nodes))
        return nodes

    def extract_iocs(self, node: dict[str, Any]) -> list[dict[str, Any]]:
        """Normalize one Indicator node into AiSOC IOC dicts."""
        pattern = str(node.get("pattern") or "")
        clauses = parse_pattern(pattern)
        if not clauses:
            main = _MAIN_OBSERVABLE_MAP.get(str(node.get("x_opencti_main_observable_type") or "").lower(), "")
            clauses = [(main, "")] if main else []

        labels = _label_values(node)
        tlp = next(
            (lbl.split(":", 1)[-1] for lbl in labels if lbl.lower().startswith(("tlp:", "lp:"))),
            "white",
        )
        kill_chain = [
            f"{phase.get('kill_chain_name', '')}:{phase.get('phase_name', '')}".strip(":")
            for phase in (node.get("killChainPhases") or [])
            if isinstance(phase, dict)
        ]
        references = [
            {
                "source": (edge.get("node") or {}).get("source_name"),
                "url": (edge.get("node") or {}).get("url"),
            }
            for edge in ((node.get("externalReferences") or {}).get("edges") or [])
        ]
        score = node.get("x_opencti_score")

        stix_id = str(node.get("standard_id") or node.get("id") or "")
        iocs: list[dict[str, Any]] = []
        for ioc_type, value in clauses:
            if not value:
                continue
            iocs.append(
                {
                    "type": ioc_type,
                    "value": value,
                    "category": (node.get("indicator_types") or ["unknown"])[0],
                    "to_ids": True,
                    "comment": str(node.get("description") or "")[:500],
                    "labels": labels,
                    "tags": labels + kill_chain,
                    "name": str(node.get("name") or "")[:300],
                    "confidence": node.get("confidence"),
                    "score": score,
                    "reliability": score_to_reliability(score),
                    "tlp": tlp,
                    "external_references": references,
                    "source": "opencti",
                    "source_ref": f"opencti:{stix_id}",
                    "last_modified": node.get("modified"),
                }
            )
        return iocs
