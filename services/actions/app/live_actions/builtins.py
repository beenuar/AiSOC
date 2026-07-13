"""
Builtin :class:`LiveActionExecutor` adapters for in-tree executors.

The existing ``services/actions/app/executors/*`` modules expose
vendor-aware executors keyed by ``ActionType``. They auto-select a
vendor at call time based on which credentials appear in
``ActionRequest.parameters`` (e.g. ``cs_client_id`` => CrowdStrike,
``mde_tenant_id`` => Microsoft Defender). That dispatch model worked
for the ActionType-based registry but it doesn't expose a clean
``(vendor_id, capability)`` mapping that the agent layer wants.

This module wraps each (vendor, capability) pair as its own
:class:`LiveActionExecutor`, so the live-action registry can answer
"who can isolate a host?" with a specific list of vendors instead
of one fuzzy "isolate_host" entry that may or may not have credentials.

Why adapters instead of porting the executors:
  The legacy executors are exercised by a substantial test suite
  (``services/actions/tests/``) and called from the Action Execution
  REST API. Rewriting them carries regression risk for zero functional
  benefit at this stage. The adapter layer is a thin bridge: it
  constructs the legacy ``ActionRequest``, calls the legacy executor,
  and translates the result into a :class:`LiveActionResult`.

Naming convention for ``vendor_id``:
  We use the matching ``connector_id`` from ``services/connectors``
  whenever one exists (``crowdstrike``, ``defender``, ``okta``,
  ``aws_security_groups``, ``splunk``, ``elastic``, ``slack``,
  ``jira``, ``servicenow``). For built-in actions that don't map to
  a single connector (e.g. the generic ``block_domain`` simulation),
  we use a descriptive vendor like ``"generic"`` so the agent loop
  has *some* vendor to plan against rather than failing the lookup.
"""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from app.executors.base import BaseExecutor
from app.executors.endpoint import (
    IsolateHostExecutor,
    KillProcessExecutor,
    QuarantineFileExecutor,
    RunAVScanExecutor,
    RunScriptExecutor,
)
from app.executors.identity import (
    DisableUserExecutor,
    ForceMFAExecutor,
    ResetPasswordExecutor,
    SuspendSessionExecutor,
)
from app.executors.network import (
    AllowIPExecutor,
    BlockDomainExecutor,
    BlockIPExecutor,
)
from app.executors.notification import (
    CreateTicketExecutor,
    NotifySlackExecutor,
)
from app.executors.siem import (
    BlockIOCExecutor,
    CreateNotableEventExecutor,
    SearchSIEMExecutor,
    SyncDetectionRuleExecutor,
    UpdateWatcherExecutor,
)
from app.models.action import ActionRequest, ActionStatus, ActionType

from . import registry
from .executor import LiveActionExecutor
from .models import LiveActionRequest, LiveActionResult, LiveActionStatus

logger = structlog.get_logger(__name__)


def _detect_simulation(output: dict[str, Any]) -> bool:
    """Best-effort: legacy executors signal simulation via a ``note`` string.

    This is a documented contract — every simulation branch in
    ``services/actions/app/executors/*.py`` writes a ``note`` field
    that begins with ``"Simulation mode"``. We detect that here so
    callers see ``LiveActionStatus.SIMULATED`` instead of having to
    parse output dicts themselves.
    """
    note = output.get("note", "")
    return isinstance(note, str) and note.startswith("Simulation mode")


def _to_live_status(legacy_status: ActionStatus, output: dict[str, Any]) -> LiveActionStatus:
    """Translate a legacy ``ActionStatus`` into a :class:`LiveActionStatus`.

    Legacy status has more states (PENDING, AWAITING_APPROVAL, ...) but
    only three are reachable from a synchronous executor call: COMPLETED,
    FAILED, and (rarely) ROLLED_BACK. We collapse ROLLED_BACK into
    SUCCEEDED because rollback is out-of-scope for the live-action layer
    — see :class:`LiveActionExecutor` docstring for the rationale.
    """
    if legacy_status == ActionStatus.FAILED:
        return LiveActionStatus.FAILED
    if _detect_simulation(output):
        return LiveActionStatus.SIMULATED
    return LiveActionStatus.SUCCEEDED


class _LegacyExecutorAdapter(LiveActionExecutor):
    """Wrap a legacy :class:`BaseExecutor` as a :class:`LiveActionExecutor`.

    Subclasses set ``vendor_id``, ``capability``, ``description``,
    ``requires_credentials``, ``_legacy_executor``, and the optional
    ``_credential_keys`` / ``_blast_radius_action_type`` fields. Doing
    the wrapping in a base class keeps the per-vendor adapters tiny
    (one class with three class-level attributes).
    """

    #: The legacy executor instance this adapter delegates to.
    _legacy_executor: BaseExecutor = None  # type: ignore[assignment]

    #: ``ActionType`` used to compute blast radius + bridge into the legacy
    #: simulation gating. Required because the legacy ``ActionRequest``
    #: schema mandates an ``action_type`` field.
    _legacy_action_type: ActionType = None  # type: ignore[assignment]

    #: Keys in ``request.params`` that signal "credentials present, this
    #: would talk to the real vendor". Used by the discovery API so the
    #: UI can show "credentials missing — will simulate" badges and by
    #: ``execute()`` to set ``requires_credentials`` correctly per call.
    #: An empty tuple means "no credentials are required at any point"
    #: (e.g. notifications via webhook URL only).
    _credential_keys: tuple[str, ...] = ()

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        # Legacy executors expect an ``ActionRequest`` populated with
        # ``incident_id`` / ``tenant_id`` / ``action_type``. The live-action
        # layer is incident-agnostic by design (it can be called from the
        # agent loop, a playbook, or an ad-hoc CLI), so we synthesise
        # placeholder UUIDs when the caller doesn't provide them. This
        # preserves the legacy contract without forcing every caller to
        # invent fake context.
        legacy_request = ActionRequest(
            incident_id=request.case_id or uuid4(),
            tenant_id=request.tenant_id or uuid4(),
            action_type=self._legacy_action_type,
            target=request.target,
            parameters=request.params,
            requested_by=request.requested_by,
            rationale="",
        )

        # ``dry_run`` short-circuit: the legacy executors don't all honour
        # a dry-run flag, so we enforce it here by stripping credentials.
        # The legacy executor will then fall through to its simulation
        # branch and we tag the result as SIMULATED. This is the safest
        # interpretation of "dry_run" — even a credentialed call must
        # not touch the real vendor.
        if request.dry_run:
            stripped = {k: v for k, v in request.params.items() if k not in self._credential_keys}
            legacy_request = legacy_request.model_copy(update={"parameters": stripped})

        legacy_result = await self._legacy_executor.execute(legacy_request)

        live_status = _to_live_status(legacy_result.status, legacy_result.output)

        summary = self._summarise(legacy_result.output, live_status)
        return LiveActionResult(
            request_id=request.request_id,
            status=live_status,
            capability=self.capability,
            vendor_id=self.vendor_id,
            summary=summary,
            details=dict(legacy_result.output),
            error=legacy_result.error,
        )

    def _summarise(self, output: dict[str, Any], status: LiveActionStatus) -> str:
        """Produce a one-line human-readable summary for the UI / audit log.

        Subclasses can override for vendor-specific shape, but the default
        captures the common case: ``<verb> <target> (<status>)``.
        """
        verb = self.capability.replace("_", " ")
        target = output.get("hostname") or output.get("ip") or output.get("user") or output.get("domain") or ""
        if status == LiveActionStatus.SIMULATED:
            return f"Simulated {verb} {target}".strip()
        if status == LiveActionStatus.FAILED:
            return f"Failed to {verb} {target}".strip()
        return f"{verb.capitalize()} {target}".strip()


# ---------------------------------------------------------------------------
# Endpoint vendor adapters
# ---------------------------------------------------------------------------
#
# Both CrowdStrike and Defender share the legacy ``IsolateHostExecutor``;
# the executor picks vendor at runtime based on which credential block
# is present. Each adapter declares the credential keys it cares about so
# the discovery API can surface "credentials missing" accurately and so
# ``dry_run`` strips the right keys.


class CrowdStrikeIsolateHost(_LegacyExecutorAdapter):
    vendor_id = "crowdstrike"
    capability = "isolate_host"
    description = "Contain a host on CrowdStrike Falcon (network containment)."
    requires_credentials = True
    _legacy_executor = IsolateHostExecutor()
    _legacy_action_type = ActionType.ISOLATE_HOST
    _credential_keys = ("cs_client_id", "cs_client_secret", "cs_base_url")


class DefenderIsolateHost(_LegacyExecutorAdapter):
    vendor_id = "defender"
    capability = "isolate_host"
    description = "Isolate a machine on Microsoft Defender for Endpoint."
    requires_credentials = True
    _legacy_executor = IsolateHostExecutor()
    _legacy_action_type = ActionType.ISOLATE_HOST
    _credential_keys = ("mde_tenant_id", "mde_client_id", "mde_client_secret")


class CrowdStrikeQuarantineFile(_LegacyExecutorAdapter):
    vendor_id = "crowdstrike"
    capability = "quarantine_file"
    description = "Quarantine a file via CrowdStrike Real-Time Response."
    requires_credentials = True
    _legacy_executor = QuarantineFileExecutor()
    _legacy_action_type = ActionType.QUARANTINE_FILE
    _credential_keys = ("cs_client_id", "cs_client_secret", "cs_base_url")


class CrowdStrikeKillProcess(_LegacyExecutorAdapter):
    vendor_id = "crowdstrike"
    capability = "kill_process"
    description = "Terminate a running process via CrowdStrike RTR."
    requires_credentials = True
    _legacy_executor = KillProcessExecutor()
    _legacy_action_type = ActionType.KILL_PROCESS
    _credential_keys = ("cs_client_id", "cs_client_secret", "cs_base_url")


class CrowdStrikeRunScript(_LegacyExecutorAdapter):
    vendor_id = "crowdstrike"
    capability = "run_script"
    description = "Run a pre-staged RTR script against a host."
    requires_credentials = True
    _legacy_executor = RunScriptExecutor()
    _legacy_action_type = ActionType.RUN_SCRIPT
    _credential_keys = ("cs_client_id", "cs_client_secret", "cs_base_url")


class DefenderRunAVScan(_LegacyExecutorAdapter):
    vendor_id = "defender"
    capability = "run_av_scan"
    description = "Trigger an antivirus scan via Microsoft Defender for Endpoint."
    requires_credentials = True
    _legacy_executor = RunAVScanExecutor()
    _legacy_action_type = ActionType.RUN_AV_SCAN
    _credential_keys = ("mde_tenant_id", "mde_client_id", "mde_client_secret")


# ---------------------------------------------------------------------------
# Identity vendor adapters (Okta)
# ---------------------------------------------------------------------------


_OKTA_KEYS = ("okta_domain", "okta_api_token")


class OktaDisableUser(_LegacyExecutorAdapter):
    vendor_id = "okta"
    capability = "disable_user"
    description = "Deactivate (disable) a user account in Okta."
    requires_credentials = True
    _legacy_executor = DisableUserExecutor()
    _legacy_action_type = ActionType.DISABLE_USER
    _credential_keys = _OKTA_KEYS


class OktaResetPassword(_LegacyExecutorAdapter):
    vendor_id = "okta"
    capability = "reset_password"
    description = "Force a password reset for an Okta user."
    requires_credentials = True
    _legacy_executor = ResetPasswordExecutor()
    _legacy_action_type = ActionType.RESET_PASSWORD
    _credential_keys = _OKTA_KEYS


class OktaSuspendSession(_LegacyExecutorAdapter):
    vendor_id = "okta"
    capability = "suspend_session"
    description = "Clear sessions and suspend an Okta user."
    requires_credentials = True
    _legacy_executor = SuspendSessionExecutor()
    _legacy_action_type = ActionType.SUSPEND_SESSION
    _credential_keys = _OKTA_KEYS


class OktaForceMFA(_LegacyExecutorAdapter):
    vendor_id = "okta"
    capability = "force_mfa"
    description = "Force MFA re-enrollment for an Okta user."
    requires_credentials = True
    _legacy_executor = ForceMFAExecutor()
    _legacy_action_type = ActionType.FORCE_MFA
    _credential_keys = _OKTA_KEYS


# ---------------------------------------------------------------------------
# Network vendor adapters
# ---------------------------------------------------------------------------


_AWS_SG_KEYS = (
    "aws_access_key_id",
    "aws_secret_access_key",
    "aws_security_group_id",
    "aws_role_arn",
)


class AwsSecurityGroupBlockIP(_LegacyExecutorAdapter):
    vendor_id = "aws_security_groups"
    capability = "block_ip"
    description = "Add a deny rule for an IP to an AWS Security Group."
    requires_credentials = True
    _legacy_executor = BlockIPExecutor()
    _legacy_action_type = ActionType.BLOCK_IP
    _credential_keys = _AWS_SG_KEYS


class AwsSecurityGroupAllowIP(_LegacyExecutorAdapter):
    vendor_id = "aws_security_groups"
    capability = "allow_ip"
    description = "Remove a previously added deny rule from an AWS Security Group."
    requires_credentials = True
    _legacy_executor = AllowIPExecutor()
    _legacy_action_type = ActionType.ALLOW_IP
    _credential_keys = _AWS_SG_KEYS


class GenericBlockDomain(_LegacyExecutorAdapter):
    vendor_id = "generic"
    capability = "block_domain"
    description = "Generic DNS-block placeholder; integrate with Route53 / Umbrella for live execution."
    requires_credentials = False
    _legacy_executor = BlockDomainExecutor()
    _legacy_action_type = ActionType.BLOCK_DOMAIN
    _credential_keys = ()


# ---------------------------------------------------------------------------
# SIEM vendor adapters
# ---------------------------------------------------------------------------
#
# The SIEM executors handle both Splunk and Elastic — the legacy
# implementation chooses based on which credential block is present.
# We register the same legacy executor under each vendor with
# vendor-specific credential keys so dry-run + discovery work correctly.


_SPLUNK_KEYS = ("splunk_host", "splunk_token", "splunk_index")
_ELASTIC_KEYS = ("elastic_host", "elastic_api_key", "elastic_index")
_DEFENDER_IOC_KEYS = ("mde_tenant_id", "mde_client_id", "mde_client_secret")


class SplunkSearchSIEM(_LegacyExecutorAdapter):
    vendor_id = "splunk"
    capability = "search_siem"
    description = "Run a search against Splunk and return results."
    requires_credentials = True
    _legacy_executor = SearchSIEMExecutor()
    _legacy_action_type = ActionType.SEARCH_SIEM
    _credential_keys = _SPLUNK_KEYS


class ElasticSearchSIEM(_LegacyExecutorAdapter):
    vendor_id = "elastic"
    capability = "search_siem"
    description = "Run an ES|QL or KQL search against Elasticsearch."
    requires_credentials = True
    _legacy_executor = SearchSIEMExecutor()
    _legacy_action_type = ActionType.SEARCH_SIEM
    _credential_keys = _ELASTIC_KEYS


class SplunkCreateNotable(_LegacyExecutorAdapter):
    vendor_id = "splunk"
    capability = "create_notable_event"
    description = "Create a notable event in Splunk Enterprise Security."
    requires_credentials = True
    _legacy_executor = CreateNotableEventExecutor()
    _legacy_action_type = ActionType.CREATE_NOTABLE_EVENT
    _credential_keys = _SPLUNK_KEYS


class SplunkSyncDetectionRule(_LegacyExecutorAdapter):
    vendor_id = "splunk"
    capability = "sync_detection_rule"
    description = "Create or update a Splunk saved search from an AiSOC detection."
    requires_credentials = True
    _legacy_executor = SyncDetectionRuleExecutor()
    _legacy_action_type = ActionType.SYNC_DETECTION_RULE
    _credential_keys = _SPLUNK_KEYS


class ElasticUpdateWatcher(_LegacyExecutorAdapter):
    vendor_id = "elastic"
    capability = "update_watcher"
    description = "Create or update an Elasticsearch Watcher rule."
    requires_credentials = True
    _legacy_executor = UpdateWatcherExecutor()
    _legacy_action_type = ActionType.UPDATE_WATCHER
    _credential_keys = _ELASTIC_KEYS


class DefenderBlockIOC(_LegacyExecutorAdapter):
    vendor_id = "defender"
    capability = "block_ioc"
    description = "Add an IoC to the Microsoft Defender block list."
    requires_credentials = True
    _legacy_executor = BlockIOCExecutor()
    _legacy_action_type = ActionType.BLOCK_IOC
    _credential_keys = _DEFENDER_IOC_KEYS


# ---------------------------------------------------------------------------
# Phase B2 — previously-unregistered vendor adapters.
#
# The legacy executors already speak these vendors (they pick the client at
# call time from which credential block is present), but the live-action
# registry had no (vendor, capability) entry for them — so the agent layer
# could never plan against SentinelOne / Entra / GWS / PAN-OS / FortiGate /
# Cloudflare / Jira / ServiceNow / PagerDuty / Slack. Registering them here
# (with the exact credential keys their client builders read) completes the
# discovery surface; the credential_resolver maps connector auth_config onto
# these keys.
# ---------------------------------------------------------------------------


class SentinelOneIsolateHost(_LegacyExecutorAdapter):
    vendor_id = "sentinelone"
    capability = "isolate_host"
    description = "Disconnect an endpoint from the network on SentinelOne."
    requires_credentials = True
    _legacy_executor = IsolateHostExecutor()
    _legacy_action_type = ActionType.ISOLATE_HOST
    _credential_keys = ("s1_console_url", "s1_api_token")


class EntraDisableUser(_LegacyExecutorAdapter):
    vendor_id = "azure_entra"
    capability = "disable_user"
    description = "Disable a user account in Microsoft Entra ID."
    requires_credentials = True
    _legacy_executor = DisableUserExecutor()
    _legacy_action_type = ActionType.DISABLE_USER
    _credential_keys = ("azure_tenant_id", "azure_client_id", "azure_client_secret")


class GoogleWorkspaceDisableUser(_LegacyExecutorAdapter):
    vendor_id = "google_workspace"
    capability = "disable_user"
    description = "Suspend a user account in Google Workspace."
    requires_credentials = True
    _legacy_executor = DisableUserExecutor()
    _legacy_action_type = ActionType.DISABLE_USER
    _credential_keys = ("gws_service_account_key", "gws_subject_email")


class PanOsBlockIP(_LegacyExecutorAdapter):
    vendor_id = "panos"
    capability = "block_ip"
    description = "Block an IP on a Palo Alto NGFW via a dynamic address group tag."
    requires_credentials = True
    _legacy_executor = BlockIPExecutor()
    _legacy_action_type = ActionType.BLOCK_IP
    _credential_keys = ("panos_host", "panos_api_key", "panos_tag")


class FortiGateBlockIP(_LegacyExecutorAdapter):
    vendor_id = "fortigate"
    capability = "block_ip"
    description = "Block an IP on a FortiGate firewall via an address group."
    requires_credentials = True
    _legacy_executor = BlockIPExecutor()
    _legacy_action_type = ActionType.BLOCK_IP
    _credential_keys = ("fgt_host", "fgt_api_token", "fgt_address_group")


class CloudflareBlockIP(_LegacyExecutorAdapter):
    vendor_id = "cloudflare"
    capability = "block_ip"
    description = "Block an IP at the Cloudflare edge (zone firewall access rule)."
    requires_credentials = True
    _legacy_executor = BlockIPExecutor()
    _legacy_action_type = ActionType.BLOCK_IP
    _credential_keys = ("cf_api_token", "cf_zone_id")


class JiraCreateTicket(_LegacyExecutorAdapter):
    vendor_id = "jira"
    capability = "create_ticket"
    description = "Create a Jira issue for the incident."
    requires_credentials = True
    _legacy_executor = CreateTicketExecutor()
    _legacy_action_type = ActionType.CREATE_TICKET
    _credential_keys = ("jira_base_url", "jira_email", "jira_api_token")


class ServiceNowCreateTicket(_LegacyExecutorAdapter):
    vendor_id = "servicenow"
    capability = "create_ticket"
    description = "Create a ServiceNow incident record."
    requires_credentials = True
    _legacy_executor = CreateTicketExecutor()
    _legacy_action_type = ActionType.CREATE_TICKET
    _credential_keys = ("snow_instance_url", "snow_username", "snow_password")


class PagerDutyCreateTicket(_LegacyExecutorAdapter):
    vendor_id = "pagerduty"
    capability = "create_ticket"
    description = "Trigger a PagerDuty incident (Events API v2)."
    requires_credentials = True
    _legacy_executor = CreateTicketExecutor()
    _legacy_action_type = ActionType.CREATE_TICKET
    _credential_keys = ("pd_routing_key",)


class SlackNotify(_LegacyExecutorAdapter):
    vendor_id = "slack"
    capability = "notify"
    description = "Post an incident notification to a Slack channel."
    requires_credentials = True
    _legacy_executor = NotifySlackExecutor()
    _legacy_action_type = ActionType.NOTIFY_SLACK
    _credential_keys = ("webhook_url",)


# ---------------------------------------------------------------------------
# Registration entry point
# ---------------------------------------------------------------------------


_BUILTIN_ADAPTERS: tuple[type[LiveActionExecutor], ...] = (
    # Endpoint
    CrowdStrikeIsolateHost,
    DefenderIsolateHost,
    CrowdStrikeQuarantineFile,
    CrowdStrikeKillProcess,
    CrowdStrikeRunScript,
    DefenderRunAVScan,
    # Identity (Okta)
    OktaDisableUser,
    OktaResetPassword,
    OktaSuspendSession,
    OktaForceMFA,
    # Network
    AwsSecurityGroupBlockIP,
    AwsSecurityGroupAllowIP,
    GenericBlockDomain,
    # SIEM
    SplunkSearchSIEM,
    ElasticSearchSIEM,
    SplunkCreateNotable,
    SplunkSyncDetectionRule,
    ElasticUpdateWatcher,
    DefenderBlockIOC,
    # Phase B2 — previously-unregistered vendors
    SentinelOneIsolateHost,
    EntraDisableUser,
    GoogleWorkspaceDisableUser,
    PanOsBlockIP,
    FortiGateBlockIP,
    CloudflareBlockIP,
    JiraCreateTicket,
    ServiceNowCreateTicket,
    PagerDutyCreateTicket,
    SlackNotify,
)


def register_builtin_executors(*, overwrite: bool = False) -> int:
    """Register every builtin adapter with the live-action registry.

    Idempotent when ``overwrite=True`` — useful in tests that want a
    clean baseline. In production, called once at app startup from
    ``main.py``. Returns the number of executors registered so the
    startup log can show ``"live_action.builtins_registered count=19"``.
    """
    count = 0
    for adapter_cls in _BUILTIN_ADAPTERS:
        registry.register_executor(adapter_cls(), source="builtin", overwrite=overwrite)
        count += 1
    logger.info("live_action.builtins_registered", count=count)
    return count
