"""Asset/CMDB intelligence helpers (todo ``t2i-asset-cmdb``).

Why this module exists
----------------------

The threat graph (``app.memory.graph``) already keeps an ``asset`` node
type for any hostname or user observed in an alert, but those nodes only
carry whatever the original event happened to mention. That is *not*
enough to make decisions like:

* "Is this host a crown jewel? → require HITL on isolate."
* "Is it PROD? → never auto-restart without approval."
* "Is it in PCI scope? → escalate, attach evidence."
* "Who owns it? → page them."

The authoritative answers live in the :class:`Asset` SQL table. This
module is the read/write surface every agent (Triager, Investigator,
Responder, Reporter, Attack-Path, BAS) goes through to talk to it.

Design rules
~~~~~~~~~~~~

* **Tenant-scoped, always.** Every public function takes a
  ``tenant_id``; we never leak across tenants.
* **Idempotent writes.** ``upsert_asset`` is safe to call from every
  connector ingest; the natural key is ``(tenant_id, asset_type, key)``.
* **Graph mirrored, never primary.** The graph keeps an ``asset`` node
  in lock-step so existing graph queries (Attack-Path, blast-radius)
  keep working. The SQL ``Asset`` row remains the source of truth.
* **Fuzzy resolution.** Alerts say ``"finance-laptop-04"``; CMDB might
  store the FQDN ``"finance-laptop-04.corp.example.com"`` plus aliases.
  ``resolve_asset`` does best-effort matching so agents don't have to
  guess.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

from sqlalchemy import or_
from sqlmodel import select

from app.db import session_scope
from app.memory.graph import (
    EdgeType,
    NodeType,
    graph_neighbors,
    graph_upsert_edge,
    graph_upsert_node,
)
from app.models.asset import Asset, AssetCriticality, AssetEnvironment, AssetType
from app.models.case import Case


# ──────────────────────────────────────────────────────────────────────
# Public dataclasses (what tools/agents see)
# ──────────────────────────────────────────────────────────────────────


@dataclass
class AssetRef:
    """Lightweight handle returned by :func:`resolve_asset`."""

    asset_id: int
    tenant_id: str
    asset_type: AssetType
    key: str
    name: str
    criticality: AssetCriticality
    environment: AssetEnvironment
    matched_on: str  # "key" | "alias" | "ip" | "name" | "graph"


@dataclass
class AssetContext:
    """Rich context payload exposed via ``asset.get_context``.

    Returned shape is intentionally JSON-serialisable: agents take this
    as ToolCall output and shove it directly into the LLM prompt.
    """

    asset: dict[str, Any]
    recent_cases: list[dict[str, Any]] = field(default_factory=list)
    graph_neighbors: list[dict[str, Any]] = field(default_factory=list)
    last_activity: dict[str, Any] = field(default_factory=dict)
    compliance: dict[str, Any] = field(default_factory=dict)
    risk_profile: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset": self.asset,
            "recent_cases": self.recent_cases,
            "graph_neighbors": self.graph_neighbors,
            "last_activity": self.last_activity,
            "compliance": self.compliance,
            "risk_profile": self.risk_profile,
        }


# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────


_CRITICALITY_WEIGHT = {
    AssetCriticality.CROWN_JEWEL: 1.0,
    AssetCriticality.HIGH: 0.75,
    AssetCriticality.MEDIUM: 0.5,
    AssetCriticality.LOW: 0.25,
    AssetCriticality.UNKNOWN: 0.4,
}

_ENV_WEIGHT = {
    AssetEnvironment.PROD: 1.0,
    AssetEnvironment.STAGING: 0.7,
    AssetEnvironment.DR: 0.7,
    AssetEnvironment.DEV: 0.3,
    AssetEnvironment.SANDBOX: 0.1,
    AssetEnvironment.UNKNOWN: 0.4,
}


def _asset_to_dict(asset: Asset) -> dict[str, Any]:
    return {
        "id": asset.id,
        "tenant_id": asset.tenant_id,
        "asset_type": asset.asset_type.value,
        "key": asset.key,
        "name": asset.name,
        "aliases": list(asset.aliases or []),
        "criticality": asset.criticality.value,
        "environment": asset.environment.value,
        "owner": asset.owner,
        "business_unit": asset.business_unit,
        "location": asset.location,
        "cost_center": asset.cost_center,
        "compliance_scopes": list(asset.compliance_scopes or []),
        "data_classifications": list(asset.data_classifications or []),
        "ip_addresses": list(asset.ip_addresses or []),
        "mac_addresses": list(asset.mac_addresses or []),
        "os": asset.os,
        "os_version": asset.os_version,
        "cloud_provider": asset.cloud_provider,
        "cloud_account_id": asset.cloud_account_id,
        "region": asset.region,
        "sources": list(asset.sources or []),
        "tags": list(asset.tags or []),
        "notes": asset.notes,
        "first_seen": asset.first_seen.isoformat() if asset.first_seen else None,
        "last_seen": asset.last_seen.isoformat() if asset.last_seen else None,
        "decommissioned_at": (
            asset.decommissioned_at.isoformat() if asset.decommissioned_at else None
        ),
        "attributes": dict(asset.attributes or {}),
    }


def _coerce_type(value: AssetType | str | None) -> AssetType | None:
    if value is None:
        return None
    if isinstance(value, AssetType):
        return value
    try:
        return AssetType(value)
    except ValueError:
        return AssetType.OTHER


def _coerce_criticality(value: AssetCriticality | str | None) -> AssetCriticality:
    if value is None:
        return AssetCriticality.UNKNOWN
    if isinstance(value, AssetCriticality):
        return value
    try:
        return AssetCriticality(value)
    except ValueError:
        return AssetCriticality.UNKNOWN


def _coerce_environment(value: AssetEnvironment | str | None) -> AssetEnvironment:
    if value is None:
        return AssetEnvironment.UNKNOWN
    if isinstance(value, AssetEnvironment):
        return value
    try:
        return AssetEnvironment(value)
    except ValueError:
        return AssetEnvironment.UNKNOWN


def _dedup(values: Iterable[str] | None) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for v in values or []:
        if not v:
            continue
        if v in seen:
            continue
        seen.add(v)
        out.append(v)
    return out


# ──────────────────────────────────────────────────────────────────────
# Resolve
# ──────────────────────────────────────────────────────────────────────


def resolve_asset(
    *,
    tenant_id: str,
    identifier: str,
    asset_type: AssetType | str | None = None,
) -> Optional[AssetRef]:
    """Best-effort match a free-form identifier to a CMDB row.

    Tries, in order:
      1. exact key (most common — alert.src_host is the row key)
      2. case-insensitive key (hostnames frequently arrive lowercased
         from one source and uppercased from another — we don't want
         that to drop into "unknown asset")
      3. exact alias / case-insensitive alias (in the ``aliases`` JSON
         array)
      4. exact IP match (in the ``ip_addresses`` JSON array)
      5. case-insensitive name
      6. case-insensitive key prefix (laptop-04 → laptop-04.corp.…)

    Returns ``None`` if nothing matches — *callers must handle that*.
    The Triager should still proceed; an "unknown asset" is itself
    actionable signal (probably needs onboarding).
    """
    if not identifier:
        return None

    needle = identifier.strip()
    if not needle:
        return None

    coerced_type = _coerce_type(asset_type) if asset_type is not None else None

    with session_scope() as s:
        # 1. exact key
        stmt = select(Asset).where(
            Asset.tenant_id == tenant_id, Asset.key == needle
        )
        if coerced_type is not None:
            stmt = stmt.where(Asset.asset_type == coerced_type)
        row = s.exec(stmt).first()
        if row is not None:
            return _ref(row, "key")

        # 2 + 3. alias / IP — SQLite JSON contains is brittle, so we
        # scan candidates of the right tenant. The tables are small
        # enough (CMDB grows slowly), and we keep indexes on tenant_id
        # + asset_type so this stays cheap.
        stmt = select(Asset).where(Asset.tenant_id == tenant_id)
        if coerced_type is not None:
            stmt = stmt.where(Asset.asset_type == coerced_type)
        candidates = list(s.exec(stmt).all())

        needle_lower = needle.lower()

        # 2. case-insensitive key match.
        for row in candidates:
            if row.key and row.key.lower() == needle_lower:
                return _ref(row, "key")

        # 3. alias — exact first, then case-insensitive.
        for row in candidates:
            aliases = row.aliases or []
            if needle in aliases:
                return _ref(row, "alias")
            if any(a.lower() == needle_lower for a in aliases if isinstance(a, str)):
                return _ref(row, "alias")

        for row in candidates:
            if needle in (row.ip_addresses or []):
                return _ref(row, "ip")

        for row in candidates:
            if row.name and row.name.lower() == needle_lower:
                return _ref(row, "name")

        # 5. prefix match on key — last resort, useful for short
        # hostnames vs FQDN cases.
        for row in candidates:
            if row.key and row.key.lower().startswith(needle_lower + "."):
                return _ref(row, "key")
            if row.key and needle_lower.startswith(row.key.lower() + "."):
                return _ref(row, "key")

    return None


def _ref(row: Asset, matched_on: str) -> AssetRef:
    return AssetRef(
        asset_id=row.id or 0,
        tenant_id=row.tenant_id,
        asset_type=row.asset_type,
        key=row.key,
        name=row.name or row.key,
        criticality=row.criticality,
        environment=row.environment,
        matched_on=matched_on,
    )


# ──────────────────────────────────────────────────────────────────────
# Context
# ──────────────────────────────────────────────────────────────────────


def get_asset_context(
    *,
    tenant_id: str,
    identifier: str,
    asset_type: AssetType | str | None = None,
    recent_case_limit: int = 5,
    graph_depth: int = 1,
    graph_limit: int = 25,
) -> Optional[AssetContext]:
    """Return the full :class:`AssetContext` for one asset.

    Used by every agent that needs to reason about *which* asset is on
    fire. Returns ``None`` if the asset cannot be resolved.
    """
    ref = resolve_asset(
        tenant_id=tenant_id, identifier=identifier, asset_type=asset_type
    )
    if ref is None:
        return None

    with session_scope() as s:
        asset = s.get(Asset, ref.asset_id)
        if asset is None:
            return None

        asset_dict = _asset_to_dict(asset)

        # Snapshot the fields _risk_profile needs *before* the session
        # closes — otherwise SQLAlchemy lazy-loads on a detached instance
        # and blows up with DetachedInstanceError.
        risk_inputs = {
            "criticality": asset.criticality,
            "environment": asset.environment,
            "compliance_scopes": list(asset.compliance_scopes or []),
        }

        # Recent cases that mention this asset by key/name/alias.
        haystacks = {asset.key, asset.name, *(asset.aliases or [])}
        haystacks.discard("")

        recent_cases: list[dict[str, Any]] = []
        if haystacks:
            stmt = (
                select(Case)
                .where(Case.tenant_id == tenant_id)
                .order_by(Case.created_at.desc())
                .limit(50)
            )
            # We over-fetch and filter in-Python because SQLite JSON
            # column queries are awkward; case volume is bounded by
            # the 50-row cap.
            for case in s.exec(stmt).all():
                hosts = set(case.affected_hosts or [])
                users = set(case.affected_users or [])
                if haystacks & hosts or haystacks & users:
                    recent_cases.append(
                        {
                            "id": case.id,
                            "title": case.title,
                            "status": case.status.value,
                            "severity": case.severity.value,
                            "verdict": case.verdict.value,
                            "confidence": case.confidence,
                            "created_at": case.created_at.isoformat(),
                            "closed_at": (
                                case.closed_at.isoformat() if case.closed_at else None
                            ),
                        }
                    )
                if len(recent_cases) >= recent_case_limit:
                    break

    # Graph neighbours — done outside the session because the graph
    # backend manages its own session.
    neighbors = graph_neighbors(
        tenant_id=tenant_id,
        type=NodeType.ASSET,
        key=ref.key,
        depth=graph_depth,
        limit=graph_limit,
    )

    # Last activity = max(last_seen, most recent case created_at).
    last_seen_iso = asset_dict.get("last_seen")
    last_case_iso = recent_cases[0]["created_at"] if recent_cases else None
    last_activity = {
        "last_seen": last_seen_iso,
        "last_case_at": last_case_iso,
        "open_cases": sum(
            1 for c in recent_cases if c.get("status") not in {"closed", "false_positive"}
        ),
    }

    compliance = {
        "scopes": asset_dict["compliance_scopes"],
        "data_classifications": asset_dict["data_classifications"],
        "in_regulated_scope": bool(asset_dict["compliance_scopes"]),
    }

    risk_profile = _risk_profile(
        criticality=risk_inputs["criticality"],
        environment=risk_inputs["environment"],
        compliance_scopes=risk_inputs["compliance_scopes"],
        open_case_count=last_activity["open_cases"],
    )

    return AssetContext(
        asset=asset_dict,
        recent_cases=recent_cases,
        graph_neighbors=neighbors,
        last_activity=last_activity,
        compliance=compliance,
        risk_profile=risk_profile,
    )


def _risk_profile(
    *,
    criticality: AssetCriticality,
    environment: AssetEnvironment,
    compliance_scopes: list[str],
    open_case_count: int,
) -> dict[str, Any]:
    """Compose the per-asset blast-radius/risk hint.

    This is intentionally cheap and explainable — no ML, just a few
    weighted signals so Responder/HITL can read it. Numbers are 0..1.

    Takes primitives rather than an ``Asset`` instance so the caller can
    snapshot fields inside its session and call us after the session has
    closed without tripping ``DetachedInstanceError``.
    """
    crit = _CRITICALITY_WEIGHT.get(criticality, 0.4)
    env = _ENV_WEIGHT.get(environment, 0.4)
    case_pressure = min(1.0, open_case_count * 0.25)

    # Compliance bumps blast radius — losing a PCI host costs more.
    compliance_bump = 0.2 if compliance_scopes else 0.0

    score = min(1.0, 0.5 * crit + 0.3 * env + 0.1 * case_pressure + compliance_bump)

    # Responder gate: anything crown jewel OR prod requires HITL by
    # default. Sandbox/dev assets may auto-approve reversible actions.
    requires_hitl = (
        criticality in {AssetCriticality.CROWN_JEWEL, AssetCriticality.HIGH}
        or environment in {AssetEnvironment.PROD, AssetEnvironment.DR}
        or bool(compliance_scopes)
    )

    return {
        "score": round(score, 3),
        "criticality_weight": crit,
        "environment_weight": env,
        "open_case_pressure": round(case_pressure, 3),
        "compliance_bump": compliance_bump,
        "requires_hitl_for_destructive": requires_hitl,
    }


# ──────────────────────────────────────────────────────────────────────
# Upsert + graph mirroring
# ──────────────────────────────────────────────────────────────────────


def upsert_asset(
    *,
    tenant_id: str,
    asset_type: AssetType | str,
    key: str,
    name: str | None = None,
    aliases: Iterable[str] | None = None,
    criticality: AssetCriticality | str | None = None,
    environment: AssetEnvironment | str | None = None,
    owner: str | None = None,
    business_unit: str | None = None,
    location: str | None = None,
    cost_center: str | None = None,
    compliance_scopes: Iterable[str] | None = None,
    data_classifications: Iterable[str] | None = None,
    ip_addresses: Iterable[str] | None = None,
    mac_addresses: Iterable[str] | None = None,
    os: str | None = None,
    os_version: str | None = None,
    cloud_provider: str | None = None,
    cloud_account_id: str | None = None,
    region: str | None = None,
    sources: Iterable[str] | None = None,
    tags: Iterable[str] | None = None,
    notes: str | None = None,
    attributes: dict[str, Any] | None = None,
    mirror_graph: bool = True,
) -> AssetRef:
    """Idempotently insert/update a CMDB row.

    Connectors call this when they ingest assets. The natural key is
    ``(tenant_id, asset_type, key)``; everything else is merged.

    Set ``mirror_graph=False`` to skip the threat-graph mirror (useful
    in tests, or when the caller is itself a graph writer that would
    otherwise loop).
    """
    coerced_type = _coerce_type(asset_type) or AssetType.OTHER
    coerced_crit = _coerce_criticality(criticality) if criticality is not None else None
    coerced_env = _coerce_environment(environment) if environment is not None else None
    now = datetime.now(timezone.utc)

    with session_scope() as s:
        stmt = select(Asset).where(
            Asset.tenant_id == tenant_id,
            Asset.asset_type == coerced_type,
            Asset.key == key,
        )
        asset = s.exec(stmt).first()

        if asset is None:
            asset = Asset(
                tenant_id=tenant_id,
                asset_type=coerced_type,
                key=key,
                name=name or key,
                aliases=_dedup(aliases),
                criticality=coerced_crit or AssetCriticality.UNKNOWN,
                environment=coerced_env or AssetEnvironment.UNKNOWN,
                owner=owner or "",
                business_unit=business_unit or "",
                location=location or "",
                cost_center=cost_center or "",
                compliance_scopes=_dedup(compliance_scopes),
                data_classifications=_dedup(data_classifications),
                ip_addresses=_dedup(ip_addresses),
                mac_addresses=_dedup(mac_addresses),
                os=os or "",
                os_version=os_version or "",
                cloud_provider=cloud_provider or "",
                cloud_account_id=cloud_account_id or "",
                region=region or "",
                sources=_dedup(sources),
                tags=_dedup(tags),
                notes=notes or "",
                first_seen=now,
                last_seen=now,
                attributes=dict(attributes or {}),
            )
            s.add(asset)
        else:
            # Merge — scalars overwrite only when supplied; lists union.
            if name:
                asset.name = name
            if aliases is not None:
                asset.aliases = _dedup(list(asset.aliases or []) + list(aliases))
            if coerced_crit is not None:
                asset.criticality = coerced_crit
            if coerced_env is not None:
                asset.environment = coerced_env
            if owner is not None:
                asset.owner = owner
            if business_unit is not None:
                asset.business_unit = business_unit
            if location is not None:
                asset.location = location
            if cost_center is not None:
                asset.cost_center = cost_center
            if compliance_scopes is not None:
                asset.compliance_scopes = _dedup(
                    list(asset.compliance_scopes or []) + list(compliance_scopes)
                )
            if data_classifications is not None:
                asset.data_classifications = _dedup(
                    list(asset.data_classifications or []) + list(data_classifications)
                )
            if ip_addresses is not None:
                asset.ip_addresses = _dedup(
                    list(asset.ip_addresses or []) + list(ip_addresses)
                )
            if mac_addresses is not None:
                asset.mac_addresses = _dedup(
                    list(asset.mac_addresses or []) + list(mac_addresses)
                )
            if os is not None:
                asset.os = os
            if os_version is not None:
                asset.os_version = os_version
            if cloud_provider is not None:
                asset.cloud_provider = cloud_provider
            if cloud_account_id is not None:
                asset.cloud_account_id = cloud_account_id
            if region is not None:
                asset.region = region
            if sources is not None:
                asset.sources = _dedup(list(asset.sources or []) + list(sources))
            if tags is not None:
                asset.tags = _dedup(list(asset.tags or []) + list(tags))
            if notes is not None:
                asset.notes = notes
            if attributes:
                merged = dict(asset.attributes or {})
                merged.update(attributes)
                asset.attributes = merged
            asset.last_seen = now

        s.flush()  # populate asset.id
        ref = _ref(asset, "key")
        snapshot = _asset_to_dict(asset)

    if mirror_graph:
        mirror_asset_into_graph(snapshot)

    return ref


def list_assets(
    *,
    tenant_id: str,
    asset_type: AssetType | str | None = None,
    criticality: AssetCriticality | str | None = None,
    environment: AssetEnvironment | str | None = None,
    query: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """Paginated CMDB list, with light filtering for the /assets API."""
    coerced_type = _coerce_type(asset_type) if asset_type else None
    coerced_crit = _coerce_criticality(criticality) if criticality else None
    coerced_env = _coerce_environment(environment) if environment else None

    with session_scope() as s:
        stmt = select(Asset).where(Asset.tenant_id == tenant_id)
        if coerced_type is not None:
            stmt = stmt.where(Asset.asset_type == coerced_type)
        if coerced_crit is not None:
            stmt = stmt.where(Asset.criticality == coerced_crit)
        if coerced_env is not None:
            stmt = stmt.where(Asset.environment == coerced_env)
        if query:
            like = f"%{query}%"
            stmt = stmt.where(
                or_(
                    Asset.key.like(like),
                    Asset.name.like(like),
                    Asset.owner.like(like),
                )
            )
        stmt = stmt.order_by(Asset.last_seen.desc()).offset(offset).limit(limit)
        rows = list(s.exec(stmt).all())
        return [_asset_to_dict(r) for r in rows]


def mirror_asset_into_graph(asset_dict: dict[str, Any]) -> None:
    """Push a SQL :class:`Asset` snapshot into the threat graph.

    Keeps node ``props`` in sync so existing graph queries
    (Attack-Path, blast-radius) automatically see the new business
    context fields without having to JOIN the SQL table.
    """
    tenant_id = asset_dict.get("tenant_id")
    key = asset_dict.get("key")
    if not tenant_id or not key:
        return

    props = {
        "asset_type": asset_dict.get("asset_type"),
        "criticality": asset_dict.get("criticality"),
        "environment": asset_dict.get("environment"),
        "owner": asset_dict.get("owner"),
        "business_unit": asset_dict.get("business_unit"),
        "compliance_scopes": asset_dict.get("compliance_scopes") or [],
        "ip_addresses": asset_dict.get("ip_addresses") or [],
        "os": asset_dict.get("os"),
        "cloud_provider": asset_dict.get("cloud_provider"),
        "cloud_account_id": asset_dict.get("cloud_account_id"),
        "region": asset_dict.get("region"),
        "cmdb_id": asset_dict.get("id"),
    }
    # Strip empties so the node JSON stays small.
    props = {k: v for k, v in props.items() if v not in (None, "", [], {})}

    tags = list(asset_dict.get("tags") or [])
    if asset_dict.get("criticality") == AssetCriticality.CROWN_JEWEL.value:
        tags = list({*tags, "crown_jewel"})

    label = asset_dict.get("name") or key

    graph_upsert_node(
        tenant_id=tenant_id,
        type=NodeType.ASSET,
        key=key,
        label=label,
        props=props,
        tags=tags,
    )

    owner = asset_dict.get("owner")
    if owner:
        # asset --owned_by--> user(owner). Owner mirroring is best-effort:
        # the primary CMDB write must never be blocked by graph hiccups.
        try:
            graph_upsert_edge(
                tenant_id=tenant_id,
                src=(NodeType.ASSET, key),
                dst=(NodeType.USER, owner),
                type=EdgeType.OWNED_BY,
            )
        except Exception:
            pass
