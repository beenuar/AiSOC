"""Structured result types for the Attack-Path Agent (todo ``t2g-attack-path``).

The agent returns rich, JSON-serialisable results because the API
endpoint, the WebSocket case feed, and the UI all consume them. Keeping
these as plain dataclasses (rather than SQLModel rows) means the agent
can run in-memory, decide what's worth persisting as a ``Case``, and
emit a structured payload to callers — without coupling the API
contract to the graph table layout.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class AttackPathHop:
    """One hop along a discovered pre-attack path.

    Each hop names the graph node we reached, why we reached it, and
    what evidence (raw connector payload subset) supports the hop. The
    Investigator UI renders these as a vertical "kill chain"-style
    timeline so the analyst can spot the toxic-combination at a glance.
    """

    # ``NodeType`` value as a string (kept untyped to keep this dataclass
    # JSON-friendly without circular imports).
    node_type: str
    # Graph ``key`` — for IAM: ARN, for assets: hostname, for exposures:
    # ``"<kind>:<asset>"``, etc.
    node_key: str
    # Human-friendly label for the UI.
    label: str = ""
    # ``EdgeType`` describing how we got from the previous hop to here
    # (omitted on the first hop).
    edge_type: str | None = None
    # Short "why this hop is dangerous" reason — usually pulled from the
    # underlying connector's own ``reasons`` field.
    reason: str = ""
    # Subset of the connector payload that justifies this hop. Kept
    # small (<2 kB) so the UI can render it inline; the full evidence
    # lives in tool-call audit log.
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackPath:
    """A ranked pre-attack path from exposure surface to high-value asset.

    ``risk_score`` is a 0-1 composite: hop-level anomaly scores, presence
    of MFA-less identities, wildcard policies, abandoned credentials,
    unverified-publisher OAuth grants, and freshness of the binding.
    Anything ≥ 0.7 should open a HIGH-severity proactive case.

    ``mitre_techniques`` is the ATT&CK mapping so the proactive case
    feeds the same heatmap as reactive cases — the SOC sees "T1078.004
    Valid Accounts: Cloud Accounts" lit up *before* it gets exploited,
    not after.
    """

    # Stable id derived from hop keys — lets the agent dedupe identical
    # paths discovered on two consecutive runs.
    path_id: str
    name: str
    risk_score: float
    hops: list[AttackPathHop] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    rationale: list[str] = field(default_factory=list)
    # If a proactive case was opened for this path, this is the case id.
    # ``None`` means the path was discovered but didn't meet the case
    # threshold on this run.
    case_id: int | None = None

    @property
    def depth(self) -> int:
        return len(self.hops)


@dataclass
class AttackPathScanResult:
    """Aggregate result of one scheduled (or API-triggered) scan."""

    tenant_id: str
    paths_discovered: int = 0
    cases_opened: int = 0
    nodes_upserted: int = 0
    edges_upserted: int = 0
    paths: list[AttackPath] = field(default_factory=list)
    # Connector-kind → ok/error so the API can surface "we couldn't
    # reach AWS today; cloud-side paths in this run are best-effort".
    connector_health: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "paths_discovered": self.paths_discovered,
            "cases_opened": self.cases_opened,
            "nodes_upserted": self.nodes_upserted,
            "edges_upserted": self.edges_upserted,
            "connector_health": dict(self.connector_health),
            "paths": [
                {
                    "path_id": p.path_id,
                    "name": p.name,
                    "risk_score": p.risk_score,
                    "depth": p.depth,
                    "mitre_techniques": list(p.mitre_techniques),
                    "rationale": list(p.rationale),
                    "case_id": p.case_id,
                    "hops": [
                        {
                            "node_type": h.node_type,
                            "node_key": h.node_key,
                            "label": h.label,
                            "edge_type": h.edge_type,
                            "reason": h.reason,
                            "evidence": h.evidence,
                        }
                        for h in p.hops
                    ],
                }
                for p in self.paths
            ],
        }
