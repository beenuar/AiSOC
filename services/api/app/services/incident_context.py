"""Incident context traversal: one query, five dimensions, tenant-scoped.

An investigation needs to answer five questions about an alert, and until now
each was a separate round trip or was not answerable at all:

    identity  Which person is behind the account, what team, who is their
              manager, are they still employed?
    asset     What host, who owns it, what does it run, what is exploitable
              on it right now?
    cloud     Which account, which workload, what secrets does it reach?
    business  Which business application, how critical, what data class,
              who is accountable?
    threat    Which indicators, which malware family, which campaign, which
              actor, which techniques?

``get_blast_radius`` answers "what is reachable" but not "what does any of it
mean" — it returns a node set, unlabelled by dimension, so a caller has to
re-derive the structure. This returns the five dimensions separately, which
is what a narrative and a prompt both need.

Three properties are load-bearing:

**Tenant scoping on every node of every path.** Not just the start node: an
expansion through a shared entity (a public IP both tenants have seen) is how
a traversal leaves its tenant. Global reference labels — MITRE technique and
tactic vocabulary, public malware and actor intel — are exempt, because
requiring a tenant_id on them makes them unreachable for everyone.

**Bounded fan-out.** Every leg has its own LIMIT. An unbounded traversal from
a busy host is not slow, it is unbounded, and this sits on the hot path of
every escalated alert.

**Partial results are reported as partial.** One dimension failing returns
the other four with the failure named, rather than an empty bundle that reads
as "no context exists" — which is the same output an agent gets for a genuinely
isolated alert, and the two must not be confused.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import asdict, dataclass, field
from typing import Any

from app.db.neo4j import get_session

logger = logging.getLogger("aisoc.incident_context")

#: Reference entities shared across tenants. Must match
#: ``graph.GlobalNodeLabels`` in services/ingest/internal/graph/schema.go.
GLOBAL_LABELS = (
    "Technique",
    "Tactic",
    "Mitigation",
    "Malware",
    "Campaign",
    "ThreatActor",
    # A CVE is the same fact in every tenant and the node carries no
    # tenant data. What is tenant-specific is the AFFECTED_BY edge from a
    # scoped Resource, so the node is global and only ever reached as a
    # terminal hop — never traversed *through*, which would make it a
    # bridge between two tenants' estates.
    "Vulnerability",
)

_SCOPED = "({v}.tenant_id = $tenant_id OR any(l IN labels({v}) WHERE l IN $global_labels))"

# Per-dimension caps. A traversal from a jump host or a shared service
# account can otherwise fan out across the estate.
LIMIT_IDENTITIES = 25
LIMIT_ASSETS = 25
LIMIT_VULNS = 20
LIMIT_CLOUD = 15
LIMIT_BUSINESS = 15
LIMIT_THREAT = 25

# Neo4j default timeout is unbounded. On the hot path of every escalated
# alert, an unbounded read is an outage waiting for its busiest tenant.
QUERY_TIMEOUT_SECONDS = 8.0


def _scoped(var: str) -> str:
    return _SCOPED.format(v=var)


@dataclass
class IncidentContext:
    """The five dimensions, plus what failed while gathering them."""

    alert_id: str
    tenant_id: str
    identities: list[dict[str, Any]] = field(default_factory=list)
    assets: list[dict[str, Any]] = field(default_factory=list)
    cloud: list[dict[str, Any]] = field(default_factory=list)
    business: list[dict[str, Any]] = field(default_factory=list)
    threat: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def dimensions_resolved(self) -> int:
        return sum(1 for d in (self.identities, self.assets, self.cloud, self.business, self.threat) if d)

    @property
    def is_partial(self) -> bool:
        return bool(self.errors)

    def as_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["dimensions_resolved"] = self.dimensions_resolved
        payload["partial"] = self.is_partial
        return payload

    def narrative_lines(self) -> list[str]:
        """Render as prompt-ready lines.

        Deliberately omits anything an agent should not reason over: secret
        *values* are never in the graph, and node internals are not useful to
        a model. What is included is what changes a verdict.
        """
        lines: list[str] = []

        for person in self.identities[:5]:
            bits = [f"account {person.get('account') or 'unknown'}"]
            if person.get("employee"):
                bits.append(f"held by {person['employee']}")
            if person.get("title"):
                bits.append(person["title"])
            if person.get("department"):
                bits.append(f"in {person['department']}")
            if person.get("manager"):
                bits.append(f"reports to {person['manager']}")
            # A departed employee with a live account is the single
            # highest-signal fact this traversal can surface.
            if person.get("is_active") is False:
                bits.append("**employee is no longer active**")
            lines.append("- Identity: " + ", ".join(bits))

        for asset in self.assets[:5]:
            bits = [asset.get("name") or asset.get("id") or "unknown host"]
            if asset.get("owner"):
                bits.append(f"owned by {asset['owner']}")
            vulns = asset.get("vulnerabilities") or []
            if vulns:
                kev = [v for v in vulns if v.get("known_exploited")]
                bits.append(f"{len(vulns)} known vulnerabilities" + (f", {len(kev)} known-exploited" if kev else ""))
            lines.append("- Asset: " + ", ".join(bits))

        for account in self.cloud[:5]:
            bits = [f"{account.get('provider') or 'cloud'} account {account.get('account_id')}"]
            if account.get("environment"):
                bits.append(account["environment"])
            if account.get("secret_count"):
                bits.append(f"{account['secret_count']} reachable secret references")
            lines.append("- Cloud: " + ", ".join(bits))

        for app in self.business[:5]:
            bits = [app.get("name") or "unknown application"]
            if app.get("criticality"):
                bits.append(f"criticality {app['criticality']}")
            if app.get("data_classification"):
                bits.append(f"data {app['data_classification']}")
            if app.get("owner"):
                bits.append(f"business owner {app['owner']}")
            if app.get("internet_facing"):
                bits.append("internet-facing")
            lines.append("- Business: " + ", ".join(bits))

        for threat in self.threat[:5]:
            bits = [f"{threat.get('ioc_type') or 'indicator'} {threat.get('ioc')}"]
            if threat.get("malware"):
                bits.append(f"associated with {threat['malware']}")
            if threat.get("actor"):
                confidence = threat.get("attribution_confidence")
                # Attribution is contested and frequently revised, so it is
                # never rendered as fact.
                suffix = f" (attribution confidence {confidence})" if confidence else " (attribution unconfirmed)"
                bits.append(f"attributed to {threat['actor']}{suffix}")
            if threat.get("techniques"):
                bits.append("techniques " + ", ".join(threat["techniques"][:4]))
            lines.append("- Threat: " + ", ".join(bits))

        if self.errors:
            lines.append("- NOTE: context is partial; these dimensions could not be read: " + ", ".join(self.errors))
        return lines


# ── Cypher, one query per dimension ─────────────────────────────────────────
# Split rather than combined: a single query would make one slow leg slow
# everything, and one failing leg fail everything.

_IDENTITY_CYPHER = f"""
MATCH (a:Alert {{id: $alert_id}})
WHERE {_scoped("a")}
MATCH (a)-[:OCCURRED_ON|INVOLVES*1..2]-(i:Identity)
WHERE {_scoped("i")}
OPTIONAL MATCH (e:Employee)-[:AUTHENTICATES_AS]->(i)
WHERE {_scoped("e")}
OPTIONAL MATCH (e)-[:BELONGS_TO]->(d:Department)
WHERE {_scoped("d")}
OPTIONAL MATCH (mgr:Employee)-[:MANAGES]->(e)
WHERE {_scoped("mgr")}
RETURN DISTINCT
    i.external_id      AS account,
    i.provider         AS provider,
    e.display_name     AS employee,
    e.title            AS title,
    e.is_active        AS is_active,
    d.name             AS department,
    mgr.display_name   AS manager,
    mgr.email          AS manager_email
LIMIT $limit
"""

_ASSET_CYPHER = f"""
MATCH (a:Alert {{id: $alert_id}})
WHERE {_scoped("a")}
MATCH (a)-[:OCCURRED_ON|INVOLVES*1..2]-(r:Resource)
WHERE {_scoped("r")}
OPTIONAL MATCH (owner:Identity)-[:OWNS]->(r)
WHERE {_scoped("owner")}
OPTIONAL MATCH (r)-[:AFFECTED_BY]->(v:Vulnerability)
WITH r, owner, v
ORDER BY coalesce(v.known_exploited, false) DESC, coalesce(v.cvss_score, 0) DESC
WITH r, owner, collect(DISTINCT {{
    cve_id: v.cve_id,
    cvss_score: v.cvss_score,
    known_exploited: v.known_exploited
}})[..$vuln_limit] AS vulns
RETURN DISTINCT
    r.id                 AS id,
    coalesce(r.name, r.hostname) AS name,
    r.resource_type      AS resource_type,
    owner.display_name   AS owner,
    [x IN vulns WHERE x.cve_id IS NOT NULL] AS vulnerabilities
LIMIT $limit
"""

_CLOUD_CYPHER = f"""
MATCH (a:Alert {{id: $alert_id}})
WHERE {_scoped("a")}
MATCH (a)-[:OCCURRED_ON|INVOLVES*1..2]-(r:Resource)
WHERE {_scoped("r")}
MATCH (r)-[:IN_ACCOUNT]->(ca:CloudAccount)
WHERE {_scoped("ca")}
OPTIONAL MATCH (r)-[:STORES]->(s:Secret)
WHERE {_scoped("s")}
RETURN DISTINCT
    ca.account_id  AS account_id,
    ca.provider    AS provider,
    ca.name        AS name,
    ca.environment AS environment,
    count(DISTINCT s) AS secret_count
LIMIT $limit
"""

_BUSINESS_CYPHER = f"""
MATCH (a:Alert {{id: $alert_id}})
WHERE {_scoped("a")}
MATCH (a)-[:OCCURRED_ON|INVOLVES*1..2]-(r:Resource)
WHERE {_scoped("r")}
MATCH (r)-[:RUNS]->(app:Application)
WHERE {_scoped("app")}
OPTIONAL MATCH (app)-[:OWNED_BY]->(bo:Employee)
WHERE {_scoped("bo")}
RETURN DISTINCT
    app.name                AS name,
    app.criticality         AS criticality,
    app.data_classification AS data_classification,
    app.revenue_impact      AS revenue_impact,
    app.environment         AS environment,
    app.internet_facing     AS internet_facing,
    app.compliance_scope    AS compliance_scope,
    bo.display_name         AS owner,
    bo.email                AS owner_email
LIMIT $limit
"""

_THREAT_CYPHER = f"""
MATCH (a:Alert {{id: $alert_id}})
WHERE {_scoped("a")}
MATCH (a)-[:OBSERVED_IOC]->(ioc:IOC)
WHERE {_scoped("ioc")}
OPTIONAL MATCH (ioc)-[:INDICATES]->(m:Malware)
OPTIONAL MATCH (m)-[:PART_OF]->(c:Campaign)
OPTIONAL MATCH (c)-[attr:ATTRIBUTED_TO]->(actor:ThreatActor)
OPTIONAL MATCH (m)-[:USES_TECHNIQUE]->(t:Technique)
RETURN DISTINCT
    ioc.value  AS ioc,
    ioc.type   AS ioc_type,
    m.name     AS malware,
    c.name     AS campaign,
    actor.name AS actor,
    attr.confidence AS attribution_confidence,
    collect(DISTINCT t.id)[..6] AS techniques
LIMIT $limit
"""

_DIMENSIONS: tuple[tuple[str, str, dict[str, int]], ...] = (
    ("identities", _IDENTITY_CYPHER, {"limit": LIMIT_IDENTITIES}),
    ("assets", _ASSET_CYPHER, {"limit": LIMIT_ASSETS, "vuln_limit": LIMIT_VULNS}),
    ("cloud", _CLOUD_CYPHER, {"limit": LIMIT_CLOUD}),
    ("business", _BUSINESS_CYPHER, {"limit": LIMIT_BUSINESS}),
    ("threat", _THREAT_CYPHER, {"limit": LIMIT_THREAT}),
)


async def _run_dimension(session: Any, cypher: str, params: dict[str, Any]) -> list[dict[str, Any]]:
    result = await session.run(cypher, **params)
    rows = await result.data()
    # Neo4j returns every RETURN key even when the OPTIONAL MATCH produced
    # nothing, so a row can be entirely nulls. Dropping empty keys keeps the
    # payload readable and stops a prompt rendering "manager: None".
    return [{k: v for k, v in row.items() if v not in (None, [], "")} for row in rows]


async def get_incident_context(
    alert_id: str,
    tenant_id: str,
    *,
    session: Any | None = None,
) -> IncidentContext:
    """Traverse an alert into all five context dimensions.

    Dimensions run concurrently and independently: one failure names itself in
    ``errors`` and the rest still return. An empty bundle with no errors means
    the alert genuinely has no context, which is a different finding from a
    graph that was unreachable.
    """
    context = IncidentContext(alert_id=alert_id, tenant_id=tenant_id)

    async def _gather(sess: Any) -> None:
        base = {
            "alert_id": alert_id,
            "tenant_id": tenant_id,
            "global_labels": list(GLOBAL_LABELS),
        }

        async def one(name: str, cypher: str, extra: dict[str, int]) -> tuple[str, Any]:
            try:
                rows = await asyncio.wait_for(
                    _run_dimension(sess, cypher, {**base, **extra}),
                    timeout=QUERY_TIMEOUT_SECONDS,
                )
                return name, rows
            except TimeoutError:
                logger.warning(
                    "incident_context.%s timed out after %.1fs alert=%s",
                    name,
                    QUERY_TIMEOUT_SECONDS,
                    alert_id,
                )
                return name, TimeoutError(f"{name}: timeout")
            except Exception as exc:
                logger.warning(
                    "incident_context.%s failed alert=%s err=%s",
                    name,
                    alert_id,
                    type(exc).__name__,
                )
                return name, exc

        results = await asyncio.gather(*(one(name, cypher, extra) for name, cypher, extra in _DIMENSIONS))
        for name, value in results:
            if isinstance(value, Exception):
                context.errors.append(f"{name} ({type(value).__name__})")
            else:
                setattr(context, name, value)

    try:
        if session is not None:
            await _gather(session)
        else:
            async with get_session() as sess:
                await _gather(sess)
    except Exception as exc:
        # The graph being unreachable must not be indistinguishable from an
        # alert with no context.
        context.errors.append(f"graph unavailable ({type(exc).__name__})")
        logger.warning("incident_context.unavailable alert=%s err=%s", alert_id, type(exc).__name__)

    logger.info(
        "incident_context alert=%s tenant=%s dimensions=%d partial=%s",
        alert_id,
        tenant_id,
        context.dimensions_resolved,
        context.is_partial,
    )
    return context
