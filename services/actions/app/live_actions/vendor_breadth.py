"""Vendor capabilities the clients implement and the registry could not reach.

Seventeen vendors are wired and most expose exactly one verb, so the action
registry looked like breadth and behaved like a single button per product.
The reason is not that the integrations are shallow: `SentinelOneClient`
implements seven operations and one was reachable; `AzureEntraClient`
implements six and one was reachable. The work was done and nothing
connected it — the same pattern v8.0 spent a release removing, at the scale
of a whole capability surface.

Every executor here calls a method that already existed. Nothing was
stubbed, and nothing is declared that a client cannot do.

Several are the reverse actions the contract already promised. `enable_user`
was declared as `disable_user`'s reverse and had no implementation on any
vendor, so an account disabled during an incident had no route back through
the platform that disabled it. `allow_ip`, `allow_domain` and
`revoke_session` were in the same state.

The shared rules, both inherited from `investigation_reads.py`:

**A read or action failure is reported, never silently absorbed.** An
executor returns FAILED with the vendor's own message rather than a
success that means "we asked".

**Credentials absent is not the same as the action failing.** Missing
configuration says so explicitly, because "we could not reach the vendor"
and "the vendor refused" send an operator to different places.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

import structlog

from app.clients.factories import (
    _cloudflare_client,
    _entra_client,
    _fortigate_client,
    _gws_client,
    _panos_client,
    _s1_client,
)
from app.live_actions.capability_contracts import apply_contract
from app.live_actions.executor import LiveActionExecutor
from app.live_actions.models import LiveActionRequest, LiveActionResult, LiveActionStatus

logger = structlog.get_logger(__name__)


def _result(
    executor: LiveActionExecutor,
    request: LiveActionRequest,
    status: LiveActionStatus,
    summary: str,
    *,
    details: dict[str, Any] | None = None,
    error: str | None = None,
) -> LiveActionResult:
    return LiveActionResult(
        request_id=request.request_id,
        status=status,
        capability=executor.capability,
        vendor_id=executor.vendor_id,
        summary=summary,
        details=details or {},
        error=error,
    )


async def _run(
    executor: LiveActionExecutor,
    request: LiveActionRequest,
    vendor: str,
    factory: Callable[[dict[str, Any]], Any],
    call: Callable[[Any, str, dict[str, Any]], Awaitable[dict[str, Any]]],
    summary: str,
) -> LiveActionResult:
    """Shared execute body: dry-run, credentials, call, error handling.

    Extracted because seventeen executors repeating it is seventeen chances
    to forget the dry-run check or to let an exception escape — and an
    exception escaping the executor is how a single bad action wedges the
    agent loop.
    """
    params: dict[str, Any] = request.params or {}
    target = str(request.target or "")

    if request.dry_run:
        return _result(
            executor,
            request,
            LiveActionStatus.SIMULATED,
            f"would {executor.capability} {target} on {vendor}",
            details={"would_run": executor.capability, "target": target, "vendor": vendor},
        )

    client = factory(params)
    if client is None:
        return _result(
            executor,
            request,
            LiveActionStatus.FAILED,
            f"{vendor} credentials not configured",
            error=(
                f"{vendor} credentials are not configured, so {executor.capability} "
                f"was not attempted. This is not a statement about the target."
            ),
        )

    try:
        response = await call(client, target, params)
    except Exception as exc:  # noqa: BLE001 - a vendor error is FAILED, never silent
        logger.warning(
            "vendor_action.failed",
            vendor=executor.vendor_id,
            capability=executor.capability,
            error=str(exc),
        )
        return _result(
            executor,
            request,
            LiveActionStatus.FAILED,
            f"{vendor} {executor.capability} failed",
            error=f"{vendor} {executor.capability} failed: {exc}",
        )

    return _result(
        executor,
        request,
        LiveActionStatus.SUCCEEDED,
        summary.format(target=target),
        details={"target": target, "vendor_response": response},
    )


# ─── SentinelOne ─────────────────────────────────────────────────────────────
#
# Seven client methods, one reachable. `lift_containment` is the one that
# mattered: containment with no release means an incident closes and the
# host stays off the network until someone remembers.


@apply_contract
class SentinelOneUnisolateHost(LiveActionExecutor):
    vendor_id = "sentinelone"
    capability = "unisolate_host"
    description = "Lift network containment on a SentinelOne agent."
    requires_credentials = True

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "SentinelOne",
            _s1_client,
            lambda c, t, p: c.lift_containment(t),
            "containment lifted on {target}",
        )


@apply_contract
class SentinelOneKillProcess(LiveActionExecutor):
    vendor_id = "sentinelone"
    capability = "kill_process"
    description = "Terminate a process on a SentinelOne-managed host."
    requires_credentials = True

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "SentinelOne",
            _s1_client,
            lambda c, t, p: c.kill_process(t, pid=p.get("pid"), process_name=p.get("process_name")),
            "process terminated on {target}",
        )


@apply_contract
class SentinelOneQuarantineFile(LiveActionExecutor):
    vendor_id = "sentinelone"
    capability = "quarantine_file"
    description = "Quarantine a file on a SentinelOne-managed host."
    requires_credentials = True

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "SentinelOne",
            _s1_client,
            lambda c, t, p: c.quarantine_file(t, str(p.get("file_path", ""))),
            "file quarantined on {target}",
        )


@apply_contract
class SentinelOneRunAVScan(LiveActionExecutor):
    vendor_id = "sentinelone"
    capability = "run_av_scan"
    description = "Start an on-demand scan on a SentinelOne-managed host."
    requires_credentials = True

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "SentinelOne",
            _s1_client,
            lambda c, t, p: c.run_av_scan(t, scan_type=str(p.get("scan_type", "Full"))),
            "scan started on {target}",
        )


@apply_contract
class SentinelOneRunScript(LiveActionExecutor):
    vendor_id = "sentinelone"
    capability = "run_script"
    description = "Run a remote script on a SentinelOne-managed host."
    requires_credentials = True

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "SentinelOne",
            _s1_client,
            lambda c, t, p: c.run_script(t, str(p.get("script_content", ""))),
            "script dispatched to {target}",
        )


# ─── Microsoft Entra ─────────────────────────────────────────────────────────


@apply_contract
class EntraEnableUser(LiveActionExecutor):
    vendor_id = "azure_entra"
    capability = "enable_user"
    description = "Re-enable an account in Microsoft Entra ID."
    requires_credentials = True

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "Entra",
            _entra_client,
            lambda c, t, p: c.enable_user(t),
            "{target} re-enabled",
        )


@apply_contract
class EntraRevokeSession(LiveActionExecutor):
    vendor_id = "azure_entra"
    capability = "revoke_session"
    description = "Revoke all refresh tokens for an Entra ID account."
    requires_credentials = True

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "Entra",
            _entra_client,
            lambda c, t, p: c.revoke_sessions(t),
            "sessions revoked for {target}",
        )


@apply_contract
class EntraResetPassword(LiveActionExecutor):
    vendor_id = "azure_entra"
    capability = "reset_password"
    description = "Force a password reset on an Entra ID account."
    requires_credentials = True

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "Entra",
            _entra_client,
            lambda c, t, p: c.reset_password(t),
            "password reset forced for {target}",
        )


@apply_contract
class EntraForceMFA(LiveActionExecutor):
    vendor_id = "azure_entra"
    capability = "force_mfa"
    description = "Require MFA re-registration for an Entra ID account."
    requires_credentials = True

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "Entra",
            _entra_client,
            lambda c, t, p: c.require_mfa(t),
            "MFA re-registration required for {target}",
        )


# ─── Google Workspace ────────────────────────────────────────────────────────


@apply_contract
class GoogleWorkspaceEnableUser(LiveActionExecutor):
    vendor_id = "google_workspace"
    capability = "enable_user"
    description = "Un-suspend a Google Workspace account."
    requires_credentials = True

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "Google Workspace",
            _gws_client,
            lambda c, t, p: c.unsuspend_user(t),
            "{target} un-suspended",
        )


@apply_contract
class GoogleWorkspaceRevokeSession(LiveActionExecutor):
    vendor_id = "google_workspace"
    capability = "revoke_session"
    description = "Revoke sign-in cookies for a Google Workspace account."
    requires_credentials = True

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "Google Workspace",
            _gws_client,
            lambda c, t, p: c.revoke_sessions(t),
            "sessions revoked for {target}",
        )


@apply_contract
class GoogleWorkspaceResetPassword(LiveActionExecutor):
    vendor_id = "google_workspace"
    capability = "reset_password"
    description = "Force a password change on a Google Workspace account."
    requires_credentials = True

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "Google Workspace",
            _gws_client,
            lambda c, t, p: c.reset_password(t),
            "password reset forced for {target}",
        )


# ─── Network ─────────────────────────────────────────────────────────────────
#
# Every block had no unblock. A perimeter block with no release is a
# permanent one, applied during an incident by an automation nobody
# revisits — and the address is usually reassigned within weeks.


@apply_contract
class CloudflareAllowIP(LiveActionExecutor):
    vendor_id = "cloudflare"
    capability = "allow_ip"
    description = "Remove a Cloudflare zone-level IP block."
    requires_credentials = True

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "Cloudflare",
            _cloudflare_client,
            lambda c, t, p: c.unblock_ip_zone(str(p.get("rule_id", "")), str(p.get("cf_zone_id", ""))),
            "block removed for {target}",
        )


@apply_contract
class CloudflareBlockDomain(LiveActionExecutor):
    vendor_id = "cloudflare"
    capability = "block_domain"
    description = "Sinkhole a domain via Cloudflare Gateway."
    requires_credentials = True

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "Cloudflare",
            _cloudflare_client,
            lambda c, t, p: c.sinkhole_domain(t, str(p.get("cf_account_id", "")), str(p.get("cf_list_id", ""))),
            "{target} sinkholed",
        )


@apply_contract
class CloudflareAllowDomain(LiveActionExecutor):
    vendor_id = "cloudflare"
    capability = "allow_domain"
    description = "Remove a Cloudflare Gateway domain sinkhole."
    requires_credentials = True

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "Cloudflare",
            _cloudflare_client,
            lambda c, t, p: c.unsinkhole_domain(t, str(p.get("cf_account_id", "")), str(p.get("cf_list_id", ""))),
            "sinkhole removed for {target}",
        )


@apply_contract
class PanOsAllowIP(LiveActionExecutor):
    vendor_id = "panos"
    capability = "allow_ip"
    description = "Remove a PAN-OS dynamic address-group tag from an IP."
    requires_credentials = True

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "PAN-OS",
            _panos_client,
            lambda c, t, p: c.unblock_ip(t, str(p.get("pan_tag", "aisoc-blocked"))),
            "tag removed from {target}",
        )


@apply_contract
class FortiGateAllowIP(LiveActionExecutor):
    vendor_id = "fortigate"
    capability = "allow_ip"
    description = "Remove an IP from the FortiGate block address group."
    requires_credentials = True

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "FortiGate",
            _fortigate_client,
            lambda c, t, p: c.unblock_ip(t, str(p.get("fgt_address_group", ""))),
            "{target} removed from the block group",
        )


VENDOR_BREADTH_EXECUTORS: tuple[type[LiveActionExecutor], ...] = (
    SentinelOneUnisolateHost,
    SentinelOneKillProcess,
    SentinelOneQuarantineFile,
    SentinelOneRunAVScan,
    SentinelOneRunScript,
    EntraEnableUser,
    EntraRevokeSession,
    EntraResetPassword,
    EntraForceMFA,
    GoogleWorkspaceEnableUser,
    GoogleWorkspaceRevokeSession,
    GoogleWorkspaceResetPassword,
    CloudflareAllowIP,
    CloudflareBlockDomain,
    CloudflareAllowDomain,
    PanOsAllowIP,
    FortiGateAllowIP,
)
