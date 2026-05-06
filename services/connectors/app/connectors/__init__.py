"""
Connector registry.

Every concrete ``BaseConnector`` subclass imported from this package is
auto-registered by ``connector_id`` so the FastAPI router can resolve a
connector class without a hand-maintained dispatch table.

Why eager imports here (instead of dynamic ``pkgutil.iter_modules`` discovery):
  * Keeps imports auditable in code review — adding a connector means adding it
    to this list, which is exactly the visibility we want for a security tool.
  * Surfaces import errors at service startup, not at first request.
  * Plays nicely with mypy / IDE goto-definition.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from app.connectors.aws_security_hub import AWSSecurityHubConnector
from app.connectors.azure_activity import AzureActivityConnector
from app.connectors.azure_defender import AzureDefenderConnector
from app.connectors.azure_entra import AzureEntraConnector
from app.connectors.base import BaseConnector, ConnectorSchema, Field, OAuthHints
from app.connectors.cloudflare import CloudflareConnector
from app.connectors.crowdstrike import CrowdStrikeConnector
from app.connectors.elastic import ElasticConnector
from app.connectors.gcp_cloud_audit import GCPCloudAuditConnector
from app.connectors.gcp_scc import GCPSCCConnector
from app.connectors.github import GitHubConnector
from app.connectors.google_workspace import GoogleWorkspaceConnector
from app.connectors.m365_audit import M365AuditConnector
from app.connectors.microsoft_sentinel import MicrosoftSentinelConnector
from app.connectors.okta import OktaConnector
from app.connectors.splunk import SplunkConnector
from app.connectors.tailscale import TailscaleConnector

if TYPE_CHECKING:
    pass


# Source of truth for "which connectors does this build know about".
# Keep alphabetised by connector_id for predictable diffs.
_CONNECTOR_CLASSES: tuple[type[BaseConnector], ...] = (
    AWSSecurityHubConnector,
    AzureActivityConnector,
    AzureDefenderConnector,
    AzureEntraConnector,
    CloudflareConnector,
    CrowdStrikeConnector,
    ElasticConnector,
    GCPCloudAuditConnector,
    GCPSCCConnector,
    GitHubConnector,
    GoogleWorkspaceConnector,
    M365AuditConnector,
    MicrosoftSentinelConnector,
    OktaConnector,
    SplunkConnector,
    TailscaleConnector,
)


def _build_registry() -> dict[str, type[BaseConnector]]:
    registry: dict[str, type[BaseConnector]] = {}
    for cls in _CONNECTOR_CLASSES:
        if not cls.connector_id:
            raise RuntimeError(f"connector class {cls.__name__} has empty connector_id; refusing to register")
        if cls.connector_id in registry:
            raise RuntimeError(
                f"duplicate connector_id '{cls.connector_id}' between {registry[cls.connector_id].__name__} and {cls.__name__}"
            )
        registry[cls.connector_id] = cls
    return registry


CONNECTOR_REGISTRY: dict[str, type[BaseConnector]] = _build_registry()


def get_connector_class(connector_id: str) -> type[BaseConnector] | None:
    """Look up a connector class by ``connector_id``."""
    return CONNECTOR_REGISTRY.get(connector_id)


def list_connector_schemas() -> list[dict]:
    """Return every registered connector's schema in JSON-serialisable form."""
    return [cls.schema().to_dict() for cls in CONNECTOR_REGISTRY.values()]


__all__ = [
    "AWSSecurityHubConnector",
    "AzureActivityConnector",
    "AzureDefenderConnector",
    "AzureEntraConnector",
    "BaseConnector",
    "CONNECTOR_REGISTRY",
    "CloudflareConnector",
    "ConnectorSchema",
    "CrowdStrikeConnector",
    "ElasticConnector",
    "Field",
    "GCPCloudAuditConnector",
    "GCPSCCConnector",
    "GitHubConnector",
    "GoogleWorkspaceConnector",
    "M365AuditConnector",
    "MicrosoftSentinelConnector",
    "OAuthHints",
    "OktaConnector",
    "SplunkConnector",
    "TailscaleConnector",
    "get_connector_class",
    "list_connector_schemas",
]
