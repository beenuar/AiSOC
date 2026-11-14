"""Asset/CMDB record (todo ``t2i-asset-cmdb``).

The Triager, Hunter, Investigator and Attack-Path agents all need a
shared definition of "what is this thing the alert mentions?" — the
hostname/user/cloud-resource/SaaS-app at the center of the case — and
*how much it matters*: criticality, owner, environment tier, compliance
scope, business unit.

Previously this metadata was either absent, hard-coded into prompts, or
inferred lossily from the threat graph's ``ASSET``/``USER`` nodes. The
graph is the right place for *relationships* between assets and other
entities, but a small relational table is the right place for the
authoritative CMDB record. This module is that table.

Identity model
--------------
``(tenant_id, asset_type, key)`` is the natural key. ``key`` is the
canonical identifier for the asset's type:

* ``HOST``      → hostname (e.g. ``WIN-FIN-0044``)
* ``USER``      → user principal (e.g. ``tina.lee``)
* ``CLOUD``     → cloud resource ARN/URN (``arn:aws:ec2:...``)
* ``SAAS_APP``  → app id (``m365``, ``github``, ``salesforce``)
* ``NETWORK``   → network device id (e.g. ``fw-edge-01``)
* ``SERVICE``   → service identifier (``svc-payments``)

Anything that isn't the canonical key (IP addresses, MAC addresses,
display names, AD object SIDs) lives in ``aliases`` or ``ip_addresses``
so :func:`app.cmdb.resolve_asset` can match on whichever identifier the
alert/connector happens to surface.

Why not just hang properties off ``GraphNode``?
-----------------------------------------------
``GraphNode`` is a generic ``(tenant_id, type, key, props)`` row with a
JSON props bag. That's perfect for the threat graph but bad for the
CMDB:

* CMDB rows are read constantly by every agent — indexed columns matter.
* Criticality / compliance scope are query filters, not blob lookups.
* Connectors (CrowdStrike, M365, AWS Config, ServiceNow) need a typed
  upsert path that's clearly *not* the threat-graph mirror.

So this table is the *system of record*, and ``populate_from_asset()``
mirrors the most important fields into the threat graph as
``GraphNode(ASSET|USER)`` props for graph-aware queries.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from sqlmodel import Column, Field, JSON, SQLModel, UniqueConstraint


class AssetType(str, Enum):
    """What kind of thing this asset is."""

    HOST = "host"
    USER = "user"
    CLOUD = "cloud_resource"
    SAAS_APP = "saas_app"
    NETWORK = "network_device"
    SERVICE = "service"
    OTHER = "other"


class AssetCriticality(str, Enum):
    """Business criticality tier. Drives HITL escalation thresholds and
    blast-radius scoring."""

    CROWN_JEWEL = "crown_jewel"  # payments DB, root account, CEO laptop
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class AssetEnvironment(str, Enum):
    """Environment tier. Used by Responder to gate destructive actions —
    isolating PROD without HITL is a hard "no", isolating DEV may be
    auto-approved."""

    PROD = "prod"
    STAGING = "staging"
    DEV = "dev"
    SANDBOX = "sandbox"
    DR = "dr"
    UNKNOWN = "unknown"


class Asset(SQLModel, table=True):
    """Authoritative CMDB record.

    Indexed on ``(tenant_id, asset_type, key)`` because that's the
    canonical lookup path. Secondary lookups (by IP, by alias, by
    owner) walk the JSON columns; SQLite is fine with that at our
    expected fleet size for now.
    """

    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "asset_type", "key", name="uq_asset_tenant_type_key"
        ),
    )

    id: Optional[int] = Field(default=None, primary_key=True)
    tenant_id: str = Field(default="demo-tenant", index=True)

    # ── Identity ───────────────────────────────────────────────────────
    asset_type: AssetType = Field(index=True)
    # Canonical identifier — see module docstring.
    key: str = Field(index=True)
    # Display name (defaults to ``key`` if unset).
    name: str = ""
    # Alternative identifiers this asset is known by. Connectors emit a
    # variety of names (FQDN vs hostname, UPN vs sAMAccountName, AWS
    # instance-id vs ARN). The resolver tries each in turn.
    aliases: list[str] = Field(default_factory=list, sa_column=Column(JSON))

    # ── Business context ──────────────────────────────────────────────
    criticality: AssetCriticality = Field(
        default=AssetCriticality.UNKNOWN, index=True
    )
    environment: AssetEnvironment = Field(
        default=AssetEnvironment.UNKNOWN, index=True
    )
    owner: str = ""  # email or username of the responsible owner
    business_unit: str = ""  # "finance", "engineering", "sales", ...
    location: str = ""  # "us-east-1", "office-sjc", "remote", ...
    cost_center: str = ""

    # ── Compliance ────────────────────────────────────────────────────
    # ``compliance_scopes`` enumerates which regulatory regimes apply
    # to this asset. Reporter's compliance sub-mode (t4-compliance) and
    # Responder's pre-action gate both read this list.
    # Common values: "pci", "soc2", "hipaa", "gdpr", "iso27001", "ferpa".
    compliance_scopes: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    # Data classification rolled up onto the asset (e.g. "phi", "pii",
    # "confidential", "public"). Used for blast-radius scoring.
    data_classifications: list[str] = Field(
        default_factory=list, sa_column=Column(JSON)
    )

    # ── Technical context (typed-but-sparse) ──────────────────────────
    ip_addresses: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    mac_addresses: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    os: str = ""  # "Windows 10 22H2", "Ubuntu 22.04", "macOS 14.x"
    os_version: str = ""
    cloud_provider: str = ""  # "aws" / "azure" / "gcp" / ""
    cloud_account_id: str = ""  # the account/subscription/project hosting it
    region: str = ""  # cloud region or on-prem site

    # ── Provenance ────────────────────────────────────────────────────
    # Which connector(s) sourced this record. Useful for "this came from
    # ServiceNow CMDB — trust criticality" vs "we synthesised this from
    # the alert stream — criticality is unknown".
    sources: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    tags: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    notes: str = ""

    # ── Bookkeeping ───────────────────────────────────────────────────
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), index=True
    )
    decommissioned_at: datetime | None = None

    # Free-form attribute bag for properties that don't justify their
    # own column (BIOS revision, AD distinguished name, AWS instance
    # state, ServiceNow sys_id, ...). Mirrored into the threat graph as
    # GraphNode.props.
    attributes: dict = Field(default_factory=dict, sa_column=Column(JSON))
