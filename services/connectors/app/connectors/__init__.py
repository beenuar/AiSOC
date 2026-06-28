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

from app.connectors.abnormal_security import AbnormalSecurityConnector
from app.connectors.auditd import AuditdConnector
from app.connectors.auth0 import Auth0Connector
from app.connectors.aws_cloudtrail import AWSCloudTrailConnector
from app.connectors.aws_guardduty import AWSGuardDutyConnector
from app.connectors.aws_security_hub import AWSSecurityHubConnector
from app.connectors.aws_vpc_flow import AWSVPCFlowLogsConnector
from app.connectors.azure_activity import AzureActivityConnector
from app.connectors.azure_defender import AzureDefenderConnector
from app.connectors.azure_entra import AzureEntraConnector
from app.connectors.base import BaseConnector, ConnectorSchema, Field, OAuthHints
from app.connectors.box import BoxConnector
from app.connectors.carbon_black import CarbonBlackConnector
from app.connectors.chronicle import ChronicleConnector
from app.connectors.cisco_umbrella import CiscoUmbrellaConnector
from app.connectors.cloudflare import CloudflareConnector
from app.connectors.cloudflare_zt import CloudflareZTConnector
from app.connectors.confluence_audit import ConfluenceAuditConnector
from app.connectors.cortex_xdr import CortexXDRConnector
from app.connectors.cortex_xsiam import CortexXSIAMConnector
from app.connectors.crowdstrike import CrowdStrikeConnector
from app.connectors.datadog import DatadogConnector
from app.connectors.datadog_cloud_siem import DatadogCloudSIEMConnector
from app.connectors.dropbox import DropboxConnector
from app.connectors.duo_security import DuoSecurityConnector
from app.connectors.elastic import ElasticConnector
from app.connectors.email_inbox import EmailInboxConnector
from app.connectors.falco import FalcoConnector
from app.connectors.fleetdm import FleetDMConnector
from app.connectors.gcp_cloud_audit import GCPCloudAuditConnector
from app.connectors.gcp_scc import GCPSCCConnector
from app.connectors.github import GitHubConnector
from app.connectors.gitlab import GitLabConnector
from app.connectors.google_workspace import GoogleWorkspaceConnector
from app.connectors.jira_connector import JiraConnector
from app.connectors.kubernetes_audit import KubernetesAuditConnector
from app.connectors.lacework import LaceworkConnector
from app.connectors.m365_audit import M365AuditConnector
from app.connectors.microsoft_sentinel import MicrosoftSentinelConnector
from app.connectors.mimecast import MimecastConnector
from app.connectors.oci import OCIConnector
from app.connectors.okta import OktaConnector
from app.connectors.onepassword import OnePasswordConnector
from app.connectors.opsgenie import OpsgenieConnector
from app.connectors.orca import OrcaConnector
from app.connectors.osctrl import OsctrlConnector
from app.connectors.pagerduty import PagerDutyConnector
from app.connectors.prisma_cloud import PrismaCloudConnector
from app.connectors.proofpoint import ProofpointConnector
from app.connectors.rapid7_insightidr import Rapid7InsightIDRConnector
from app.connectors.salesforce import SalesforceConnector
from app.connectors.sentinelone import SentinelOneConnector
from app.connectors.servicenow import ServiceNowConnector
from app.connectors.slack_audit import SlackAuditConnector
from app.connectors.snowflake import SnowflakeConnector
from app.connectors.snyk import SnykConnector
from app.connectors.splunk import SplunkConnector
from app.connectors.sublime_security import SublimeSecurityConnector
from app.connectors.sumo_logic import SumoLogicConnector
from app.connectors.sysdig import SysdigConnector
from app.connectors.tailscale import TailscaleConnector
from app.connectors.tenable import TenableConnector
from app.connectors.tines import TinesConnector
from app.connectors.torq import TorqConnector
from app.connectors.trellix_helix import TrellixHelixConnector
from app.connectors.trend_vision_one import TrendVisionOneConnector
from app.connectors.vault import VaultConnector
from app.connectors.wazuh import WazuhConnector
from app.connectors.wiz import WizConnector
from app.connectors.zscaler import ZscalerConnector

if TYPE_CHECKING:
    pass


# Source of truth for "which connectors does this build know about".
# Keep alphabetised by connector_id for predictable diffs.
_CONNECTOR_CLASSES: tuple[type[BaseConnector], ...] = (
    AWSCloudTrailConnector,
    AWSGuardDutyConnector,
    AWSSecurityHubConnector,
    AWSVPCFlowLogsConnector,
    AbnormalSecurityConnector,
    Auth0Connector,
    AuditdConnector,
    AzureActivityConnector,
    AzureDefenderConnector,
    AzureEntraConnector,
    BoxConnector,
    CarbonBlackConnector,
    ChronicleConnector,
    CiscoUmbrellaConnector,
    CloudflareConnector,
    CloudflareZTConnector,
    ConfluenceAuditConnector,
    CortexXDRConnector,
    CortexXSIAMConnector,
    CrowdStrikeConnector,
    DatadogConnector,
    DatadogCloudSIEMConnector,
    DropboxConnector,
    DuoSecurityConnector,
    ElasticConnector,
    EmailInboxConnector,
    FalcoConnector,
    FleetDMConnector,
    GCPCloudAuditConnector,
    GCPSCCConnector,
    GitHubConnector,
    GitLabConnector,
    GoogleWorkspaceConnector,
    JiraConnector,
    KubernetesAuditConnector,
    LaceworkConnector,
    M365AuditConnector,
    MicrosoftSentinelConnector,
    MimecastConnector,
    OCIConnector,
    OktaConnector,
    OnePasswordConnector,
    OpsgenieConnector,
    OrcaConnector,
    OsctrlConnector,
    PagerDutyConnector,
    PrismaCloudConnector,
    ProofpointConnector,
    Rapid7InsightIDRConnector,
    SalesforceConnector,
    SentinelOneConnector,
    ServiceNowConnector,
    SlackAuditConnector,
    SnowflakeConnector,
    SnykConnector,
    SplunkConnector,
    SublimeSecurityConnector,
    SumoLogicConnector,
    SysdigConnector,
    TailscaleConnector,
    TenableConnector,
    TinesConnector,
    TorqConnector,
    TrellixHelixConnector,
    TrendVisionOneConnector,
    VaultConnector,
    WazuhConnector,
    WizConnector,
    ZscalerConnector,
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
    """Return every registered connector's schema in JSON-serialisable form.

    This is also the injection point for Workstream 4 capabilities. Connector
    authors can either pass ``capabilities=cls.capabilities()`` explicitly to
    :class:`ConnectorSchema`, or leave it empty and we'll backfill from the
    ``capabilities()`` classmethod here. Backfill makes the migration
    incremental — we add ``capabilities()`` to each connector class without
    having to touch its ``schema()`` body in the same change.
    """
    out: list[dict] = []
    for cls in CONNECTOR_REGISTRY.values():
        d = cls.schema().to_dict()
        if not d.get("capabilities"):
            d["capabilities"] = [c.value for c in cls.capabilities()]
        out.append(d)
    return out


__all__ = [
    "AWSCloudTrailConnector",
    "AWSGuardDutyConnector",
    "AWSSecurityHubConnector",
    "AWSVPCFlowLogsConnector",
    "AbnormalSecurityConnector",
    "Auth0Connector",
    "AuditdConnector",
    "AzureActivityConnector",
    "AzureDefenderConnector",
    "AzureEntraConnector",
    "BaseConnector",
    "BoxConnector",
    "CONNECTOR_REGISTRY",
    "CarbonBlackConnector",
    "ChronicleConnector",
    "CiscoUmbrellaConnector",
    "CloudflareConnector",
    "CloudflareZTConnector",
    "ConfluenceAuditConnector",
    "ConnectorSchema",
    "CortexXDRConnector",
    "CortexXSIAMConnector",
    "CrowdStrikeConnector",
    "DatadogCloudSIEMConnector",
    "DatadogConnector",
    "DropboxConnector",
    "DuoSecurityConnector",
    "ElasticConnector",
    "EmailInboxConnector",
    "FalcoConnector",
    "Field",
    "FleetDMConnector",
    "GCPCloudAuditConnector",
    "GCPSCCConnector",
    "GitHubConnector",
    "GoogleWorkspaceConnector",
    "JiraConnector",
    "KubernetesAuditConnector",
    "LaceworkConnector",
    "M365AuditConnector",
    "MicrosoftSentinelConnector",
    "MimecastConnector",
    "OAuthHints",
    "OCIConnector",
    "OktaConnector",
    "OnePasswordConnector",
    "OpsgenieConnector",
    "OrcaConnector",
    "OsctrlConnector",
    "PagerDutyConnector",
    "PrismaCloudConnector",
    "ProofpointConnector",
    "Rapid7InsightIDRConnector",
    "SalesforceConnector",
    "SentinelOneConnector",
    "ServiceNowConnector",
    "SlackAuditConnector",
    "SnowflakeConnector",
    "SnykConnector",
    "SplunkConnector",
    "SublimeSecurityConnector",
    "SumoLogicConnector",
    "SysdigConnector",
    "TailscaleConnector",
    "TenableConnector",
    "TinesConnector",
    "TorqConnector",
    "TrellixHelixConnector",
    "TrendVisionOneConnector",
    "VaultConnector",
    "WazuhConnector",
    "WizConnector",
    "ZscalerConnector",
    "get_connector_class",
    "list_connector_schemas",
]
