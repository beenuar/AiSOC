"""Threat graph: entities and relationships across cases.

The graph stitches IOCs, assets, actors, techniques, and campaigns into a
single navigable knowledge structure. It answers questions like "what
else have we seen this C2 talk to?", "which assets has this actor
touched?", or "what techniques cluster around this campaign?".

We model it as a property graph in SQLModel so it always works, even
without Neo4j. When a real graph DB is configured (``AISOC_GRAPH_BACKEND
= neo4j``) writes mirror into both stores and reads prefer the graph DB.

Tenancy: every node and edge carries ``tenant_id``. A node identity is
``(tenant_id, type, key)`` so two tenants can independently track the
same IOC without colliding. ``tenant_id="__global__"`` is reserved for
Cyble's shared CTI graph (e.g. known threat actor relationships) and is
readable across tenants — same convention as :class:`IOC`.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from sqlmodel import JSON, Column, Field, SQLModel, UniqueConstraint


class NodeType(str, Enum):
    """High-level categories. ``key`` is type-specific (see ``GraphNode.key``)."""

    IOC = "ioc"  # key = "<ioc_type>:<value>", e.g. "ip:1.2.3.4"
    ASSET = "asset"  # key = hostname / device id / user-principal
    USER = "user"  # key = user principal (kept distinct from asset)
    ACTOR = "actor"  # key = threat-actor handle (e.g. "APT29")
    CAMPAIGN = "campaign"  # key = campaign name / id
    TECHNIQUE = "technique"  # key = ATT&CK technique id (e.g. "T1059.001")
    TOOL = "tool"  # key = malware/tool name
    VULNERABILITY = "vulnerability"  # key = CVE id
    CASE = "case"  # key = case id (links graph back to investigations)
    # Theme 2g: attack-path-graph node types. Used by the pre-attack-path
    # agent to stitch ASM exposures → identities → roles → permissions →
    # high-value targets across AWS IAM, Kubernetes RBAC, and IdP data.
    # Adding here is schema-safe because NodeType is a string enum stored
    # as TEXT in SQLite; existing rows are unaffected.
    EXPOSURE = "exposure"  # key = "<kind>:<asset>", ASM/CVE/public-share/etc.
    ROLE = "role"  # key = IAM role ARN, K8s RoleBinding name, etc.
    PERMISSION = "permission"  # key = "<service>:<action>" or scope/grant id
    GROUP = "group"  # key = IdP / IAM group name
    # Theme 3f: third-party / supply-chain risk fusion. The Vendor node
    # ties a tenant's declared third-party dependency (CRM SaaS, payroll
    # provider, OEM hardware vendor, npm publisher) to the breach signals
    # the Supply-Chain agent observes against it (dark-web mentions of
    # leaked vendor data, ASM exposures on the vendor's perimeter,
    # vuln-intel against the vendor's tech stack). Adding here is
    # schema-safe — NodeType is stored as TEXT, existing rows unaffected.
    VENDOR = "vendor"  # key = vendor slug, e.g. "okta", "snowflake"


class EdgeType(str, Enum):
    """Relationship verbs. Keep this set small and meaningful."""

    COMMUNICATES_WITH = "communicates_with"  # asset → ioc, ioc → ioc
    OBSERVED_ON = "observed_on"  # ioc → asset
    ATTRIBUTED_TO = "attributed_to"  # ioc/tool/campaign → actor
    USES = "uses"  # actor → tool/technique
    EXPLOITS = "exploits"  # actor/tool → vulnerability
    PART_OF = "part_of"  # technique/ioc → campaign
    RELATED_TO = "related_to"  # generic fallback (use sparingly)
    INVOLVED_IN = "involved_in"  # ioc/asset/user → case
    AUTHENTICATED_AS = "authenticated_as"  # asset → user
    OWNED_BY = "owned_by"  # asset → user (CMDB ownership / accountable party)
    # Theme 2g: attack-path-graph edge verbs.
    EXPOSED_AS = "exposed_as"  # asset → exposure
    CAN_ASSUME_ROLE = "can_assume_role"  # user/role → role (STS chain hop)
    HAS_PERMISSION = "has_permission"  # role/user → permission
    MEMBER_OF = "member_of"  # user → group, group → group
    CAN_REACH = "can_reach"  # asset → asset (network reachability)
    CAN_PRIVESC_TO = "can_privesc_to"  # user/role → user/role (BloodHound-style)
    # Theme 3f: tenant assets/users depending on a third-party vendor.
    # Direction: asset/user → vendor (the dependent depends on the
    # provider). When a vendor breach signal fires, the agent walks the
    # reverse edges to surface "which assets/users does this blast?".
    DEPENDS_ON = "depends_on"


class GraphNode(SQLModel, table=True):
    """A node in the threat graph.

    The natural key is ``(tenant_id, type, key)``. We keep an integer
    ``id`` for fast edge joins in SQLite. ``key`` is the type-specific
    stable identifier (IP for ip-iocs, hostname for assets, MITRE id for
    techniques, etc.) — see :class:`NodeType` for the convention.
    """

    __table_args__ = (
        UniqueConstraint("tenant_id", "type", "key", name="uq_graphnode_tenant_type_key"),
    )

    id: Optional[int] = Field(default=None, primary_key=True)
    tenant_id: str = Field(default="demo-tenant", index=True)
    type: NodeType = Field(index=True)
    key: str = Field(index=True)
    label: str = ""  # display name; falls back to ``key``
    props: dict = Field(default_factory=dict, sa_column=Column(JSON))
    tags: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class GraphEdge(SQLModel, table=True):
    """A directed, typed edge between two graph nodes.

    Uniqueness is ``(tenant_id, src_id, dst_id, type)`` — re-asserting the
    same edge upgrades ``last_seen`` and merges ``props`` instead of
    inserting a duplicate.
    """

    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "src_id",
            "dst_id",
            "type",
            name="uq_graphedge_tenant_pair_type",
        ),
    )

    id: Optional[int] = Field(default=None, primary_key=True)
    tenant_id: str = Field(default="demo-tenant", index=True)
    src_id: int = Field(foreign_key="graphnode.id", index=True)
    dst_id: int = Field(foreign_key="graphnode.id", index=True)
    type: EdgeType = Field(index=True)
    weight: float = 1.0  # confidence / observation count
    props: dict = Field(default_factory=dict, sa_column=Column(JSON))
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
