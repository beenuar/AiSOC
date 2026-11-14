"""Marketplace catalog (read-only, derived).

The catalog is built on every request from the live in-process registries:

- :data:`app.tools.registry.registry` — every callable agent tool, with
  its MCP-aligned schema and risk classification.
- :func:`app.connectors.sdk.registry.list_registered_factories` — every
  connector vendor compiled into this build.

By deriving the catalog from the registries we make it impossible for the
marketplace listing to drift away from what the platform can actually
execute. A tool that disappears from the registry disappears from the
marketplace on the next request, and a new connector vendor lights up the
moment its `@register_connector_factory` decorator runs.

This module owns the *enrichment* layer: per-entry curator metadata
(category, vendor display name, verification badge, install URL,
required scopes, contact info). The enrichment overlay lives in module
constants here so it travels with the source repo and can be reviewed
in PRs — that is the curated-marketplace policy from the plan
(48-hour SLA, no untrusted code reaching customer SIEMs).
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Iterable, Optional

from app.connectors.sdk.base import ConnectorKind
from app.connectors.sdk.registry import (
    _ensure_builtins_loaded,
    list_registered_factories,
)
from app.models.tool_call import RiskClass
from app.tools.registry import ToolDef, registry as tool_registry


# ─── Curator overlay ────────────────────────────────────────────────────


@dataclass(frozen=True)
class _ToolOverlay:
    """Curator-managed metadata for a marketplace tool entry.

    Fields here are added by the marketplace operator (Cyble) and signed
    into the source repo. They are not derived from the registry because
    the registry only knows what the tool *does*, not who maintains it
    or how an integrator should install it.
    """

    category: str
    vendor: str
    verified: bool = False
    docs_url: Optional[str] = None
    source_url: Optional[str] = None


@dataclass(frozen=True)
class _ConnectorOverlay:
    """Curator-managed metadata for a marketplace connector entry."""

    display_name: str
    category: str
    vendor: str
    verified: bool = False
    docs_url: Optional[str] = None
    source_url: Optional[str] = None
    required_scopes: tuple[str, ...] = ()


# Tool overlay — keyed by ToolDef.name. Anything not listed here still
# appears in the marketplace as an "unverified, internal" entry so the
# catalog is exhaustive even when a curator forgets to file the row.
_TOOL_OVERLAY: dict[str, _ToolOverlay] = {
    # Cyble-native CTI moat
    "cti.enrich_ioc": _ToolOverlay(
        category="cti",
        vendor="Cyble",
        verified=True,
        docs_url="https://docs.tryaisoc.com/tools/cti.enrich_ioc",
        source_url="https://github.com/beenuar/AiSOC/tree/main/services/api/app/tools/cti.py",
    ),
    "cti.actor_lookup": _ToolOverlay(
        category="cti",
        vendor="Cyble",
        verified=True,
        docs_url="https://docs.tryaisoc.com/tools/cti.actor_lookup",
    ),
    "cti.darkweb_search": _ToolOverlay(
        category="cti",
        vendor="Cyble",
        verified=True,
        docs_url="https://docs.tryaisoc.com/tools/cti.darkweb_search",
    ),
    "cti.brand_intel": _ToolOverlay(
        category="cti",
        vendor="Cyble",
        verified=True,
        docs_url="https://docs.tryaisoc.com/tools/cti.brand_intel",
    ),
    "cti.asm_lookup": _ToolOverlay(
        category="exposure",
        vendor="Cyble",
        verified=True,
        docs_url="https://docs.tryaisoc.com/tools/cti.asm_lookup",
    ),
    "cti.vuln_intel": _ToolOverlay(
        category="vulnerability",
        vendor="Cyble",
        verified=True,
        docs_url="https://docs.tryaisoc.com/tools/cti.vuln_intel",
    ),
    # Cyble-native enrichment + decisions
    "cti.lookup": _ToolOverlay(
        category="cti",
        vendor="Cyble",
        verified=True,
    ),
    "cti.lookup_actor": _ToolOverlay(
        category="cti",
        vendor="Cyble",
        verified=True,
    ),
    # SIEM
    "siem.search": _ToolOverlay(
        category="siem",
        vendor="Splunk / Sentinel / Chronicle",
        verified=True,
        docs_url="https://docs.tryaisoc.com/tools/siem.search",
    ),
    "siem.lookup_user_history": _ToolOverlay(
        category="siem",
        vendor="Splunk / Sentinel / Chronicle",
        verified=True,
    ),
    # EDR
    "edr.isolate_host": _ToolOverlay(
        category="edr",
        vendor="CrowdStrike / SentinelOne",
        verified=True,
        docs_url="https://docs.tryaisoc.com/tools/edr.isolate_host",
    ),
    "edr.release_host": _ToolOverlay(
        category="edr",
        vendor="CrowdStrike / SentinelOne",
        verified=True,
    ),
    "edr.kill_process": _ToolOverlay(
        category="edr",
        vendor="CrowdStrike / SentinelOne",
        verified=True,
    ),
    # IDP
    "idp.disable_user": _ToolOverlay(
        category="idp",
        vendor="Okta / Entra ID",
        verified=True,
        docs_url="https://docs.tryaisoc.com/tools/idp.disable_user",
    ),
    "idp.enable_user": _ToolOverlay(
        category="idp",
        vendor="Okta / Entra ID",
        verified=True,
    ),
    "idp.revoke_sessions": _ToolOverlay(
        category="idp",
        vendor="Okta / Entra ID",
        verified=True,
    ),
    "idp.reset_password": _ToolOverlay(
        category="idp",
        vendor="Okta / Entra ID",
        verified=True,
    ),
}


_CONNECTOR_OVERLAY: dict[tuple[ConnectorKind, str], _ConnectorOverlay] = {
    (ConnectorKind.SIEM, "splunk"): _ConnectorOverlay(
        display_name="Splunk Cloud / Splunk Enterprise",
        category="siem",
        vendor="Splunk",
        verified=True,
        docs_url="https://docs.tryaisoc.com/connectors/splunk",
        required_scopes=("search:read",),
    ),
    (ConnectorKind.SIEM, "sentinel"): _ConnectorOverlay(
        display_name="Microsoft Sentinel",
        category="siem",
        vendor="Microsoft",
        verified=True,
        docs_url="https://docs.tryaisoc.com/connectors/sentinel",
        required_scopes=("LogAnalytics.Read",),
    ),
    (ConnectorKind.EDR, "crowdstrike"): _ConnectorOverlay(
        display_name="CrowdStrike Falcon",
        category="edr",
        vendor="CrowdStrike",
        verified=True,
        docs_url="https://docs.tryaisoc.com/connectors/crowdstrike",
        required_scopes=("hosts:read", "hosts:write", "rtr:write"),
    ),
    (ConnectorKind.EDR, "sentinelone"): _ConnectorOverlay(
        display_name="SentinelOne Singularity",
        category="edr",
        vendor="SentinelOne",
        verified=True,
        docs_url="https://docs.tryaisoc.com/connectors/sentinelone",
        required_scopes=("agents:read", "agents:isolate"),
    ),
    (ConnectorKind.IDP, "okta"): _ConnectorOverlay(
        display_name="Okta Workforce Identity",
        category="idp",
        vendor="Okta",
        verified=True,
        docs_url="https://docs.tryaisoc.com/connectors/okta",
        required_scopes=("users.read", "users.manage", "sessions.manage"),
    ),
    (ConnectorKind.IDP, "m365"): _ConnectorOverlay(
        display_name="Microsoft Entra ID",
        category="idp",
        vendor="Microsoft",
        verified=True,
        docs_url="https://docs.tryaisoc.com/connectors/m365",
        required_scopes=("User.ReadWrite.All", "Directory.AccessAsUser.All"),
    ),
    (ConnectorKind.FORENSICS, "velociraptor"): _ConnectorOverlay(
        display_name="Velociraptor DFIR",
        category="forensics",
        vendor="Rapid7",
        verified=True,
        docs_url="https://docs.tryaisoc.com/connectors/velociraptor",
    ),
}


# ─── Public DTOs ────────────────────────────────────────────────────────


@dataclass
class ToolEntry:
    """One tool listing in the marketplace (MCP-aligned)."""

    name: str
    integration: str
    category: str
    vendor: str
    description: str
    risk_class: str
    cyble_native: bool
    verified: bool
    tags: list[str]
    params_schema: dict[str, Any]
    result_schema: dict[str, Any]
    docs_url: Optional[str] = None
    source_url: Optional[str] = None
    reverse_tool: Optional[str] = None
    forward_only_reason: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ConnectorEntry:
    """One connector listing in the marketplace."""

    kind: str
    vendor_slug: str
    display_name: str
    category: str
    vendor: str
    verified: bool
    docs_url: Optional[str] = None
    source_url: Optional[str] = None
    required_scopes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ─── Catalog ────────────────────────────────────────────────────────────


def _tool_entry_from_def(td: ToolDef) -> ToolEntry:
    overlay = _TOOL_OVERLAY.get(td.name)
    if overlay is None:
        # Default overlay: tool exists in the registry but a curator
        # hasn't written marketplace metadata yet. Surface it as
        # category "internal" / unverified so customers know it's not
        # been through review.
        overlay = _ToolOverlay(
            category="internal",
            vendor=td.integration,
            verified=False,
        )
    return ToolEntry(
        name=td.name,
        integration=td.integration,
        category=overlay.category,
        vendor=overlay.vendor,
        description=td.description,
        risk_class=td.risk_class.value
        if isinstance(td.risk_class, RiskClass)
        else str(td.risk_class),
        cyble_native=td.cyble_native,
        verified=overlay.verified,
        tags=list(td.tags),
        params_schema=dict(td.params_schema),
        result_schema=dict(td.result_schema),
        docs_url=overlay.docs_url,
        source_url=overlay.source_url,
        reverse_tool=td.reverse_tool,
        forward_only_reason=td.forward_only_reason,
    )


def _connector_entry(kind: ConnectorKind, vendor: str) -> ConnectorEntry:
    overlay = _CONNECTOR_OVERLAY.get((kind, vendor))
    if overlay is None:
        overlay = _ConnectorOverlay(
            display_name=f"{vendor.title()} ({kind.value})",
            category=kind.value,
            vendor=vendor.title(),
            verified=False,
        )
    return ConnectorEntry(
        kind=kind.value,
        vendor_slug=vendor,
        display_name=overlay.display_name,
        category=overlay.category,
        vendor=overlay.vendor,
        verified=overlay.verified,
        docs_url=overlay.docs_url,
        source_url=overlay.source_url,
        required_scopes=list(overlay.required_scopes),
    )


class MarketplaceCatalog:
    """Compute the marketplace listing on demand from live registries.

    Stateless by design — every call rescans the registries. Cheap
    enough to skip caching for now (sub-millisecond on the demo
    registry), and the freshness is worth more than the cycles.
    """

    def list_tools(
        self,
        *,
        category: Optional[str] = None,
        verified_only: bool = False,
        cyble_native_only: bool = False,
        max_risk: Optional[RiskClass] = None,
    ) -> list[ToolEntry]:
        if max_risk is not None:
            tools: Iterable[ToolDef] = tool_registry.by_risk(max_risk)
        else:
            tools = tool_registry.all()

        entries = [_tool_entry_from_def(t) for t in tools]
        if category is not None:
            entries = [e for e in entries if e.category == category]
        if verified_only:
            entries = [e for e in entries if e.verified]
        if cyble_native_only:
            entries = [e for e in entries if e.cyble_native]
        entries.sort(key=lambda e: (not e.verified, e.category, e.name))
        return entries

    def list_connectors(
        self,
        *,
        category: Optional[str] = None,
        verified_only: bool = False,
    ) -> list[ConnectorEntry]:
        _ensure_builtins_loaded()
        pairs = list_registered_factories()
        entries = [_connector_entry(kind, vendor) for kind, vendor in pairs]
        # Hide the "mock" vendor from the public catalog — it's not
        # something a customer should be installing.
        entries = [e for e in entries if e.vendor_slug != "mock"]
        if category is not None:
            entries = [e for e in entries if e.category == category]
        if verified_only:
            entries = [e for e in entries if e.verified]
        entries.sort(key=lambda e: (not e.verified, e.category, e.vendor_slug))
        return entries

    def categories(self) -> list[str]:
        cats: set[str] = set()
        for entry in self.list_tools():
            cats.add(entry.category)
        for entry in self.list_connectors():
            cats.add(entry.category)
        return sorted(cats)

    def stats(self) -> dict[str, Any]:
        tools = self.list_tools()
        connectors = self.list_connectors()
        return {
            "tools_total": len(tools),
            "tools_verified": sum(1 for t in tools if t.verified),
            "tools_cyble_native": sum(1 for t in tools if t.cyble_native),
            "connectors_total": len(connectors),
            "connectors_verified": sum(1 for c in connectors if c.verified),
            "categories": self.categories(),
        }


catalog = MarketplaceCatalog()
