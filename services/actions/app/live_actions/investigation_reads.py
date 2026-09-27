"""Read-only vendor verbs, for investigation rather than response.

Twenty-nine executors could change the estate and exactly one — `search_siem`
— could ask it a question. That shapes an agent more than it looks: with no
way to read a vendor, an investigation can only reach the lake, so anything
the lake did not ingest is invisible, and the pivot chain Pillar 2 built has
nowhere to pivot to.

These change nothing, so the contract writes itself: read-only, automatic,
no reversal, no verification probe. Gating a read behind an analyst is how
an agent learns to conclude without looking.

Two rules the implementations share, both learned the hard way here:

**A read failure is not an empty result.** An investigation concluding a
host is clean because the API was down is worse than one that says it could
not check. Every executor below distinguishes the two, and the distinction
reaches the caller.

**Vendor payloads are projected, not forwarded.** A CrowdStrike device
record carries around ninety fields. Handing the whole thing to a model is
an unbounded token cost for a bounded amount of signal, and it buries the
four fields that matter.
"""

from __future__ import annotations

from typing import Any

import structlog

from app.clients.aws_cloudtrail_client import CloudTrailLookupError
from app.clients.defender_client import _HUNT_TEMPLATES
from app.clients.factories import (
    _cloudtrail_client,
    _cs_client,
    _entra_client,
    _gws_client,
    _mde_client,
    _okta_client,
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
    """Build a result with the identity fields the model requires.

    Wrapped because those four fields are pure boilerplate and forgetting
    one is a validation error at dispatch rather than at import — which
    means a read verb that works in simulation and raises the first time a
    credential exists.
    """
    return LiveActionResult(
        request_id=request.request_id,
        status=status,
        capability=executor.capability,
        vendor_id=executor.vendor_id,
        summary=summary,
        details=details or {},
        error=error,
    )


def _missing_credentials(executor: LiveActionExecutor, request: LiveActionRequest, vendor: str) -> LiveActionResult:
    """Honest failure when the vendor cannot be reached at all."""
    return _result(
        executor,
        request,
        LiveActionStatus.FAILED,
        f"{vendor} credentials not configured",
        error=(
            f"{vendor} credentials are not configured, so {executor.capability} "
            f"could not read anything. This is not a statement about the target."
        ),
    )


def _preview(executor: LiveActionExecutor, request: LiveActionRequest, target: str, vendor: str) -> LiveActionResult:
    """Dry-run response.

    A read has no side effect, so honouring dry_run buys nothing in safety.
    It is honoured anyway so a plan can be costed without calling a vendor
    API on every step of a preview, and so every executor behaves the same
    way under the same flag.
    """
    return _result(
        executor,
        request,
        LiveActionStatus.SIMULATED,
        f"would read {executor.capability} for {target} from {vendor}",
        details={"would_read": executor.capability, "target": target, "vendor": vendor},
    )


@apply_contract
class CrowdStrikeGetHost(LiveActionExecutor):
    vendor_id = "crowdstrike"
    capability = "get_host"
    description = "Read a device record from CrowdStrike Falcon."
    requires_credentials = True

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        params: dict[str, Any] = request.params or {}
        target = str(request.target or params.get("hostname") or "")
        if request.dry_run:
            return _preview(self, request, target, "CrowdStrike")

        client = _cs_client(params)
        if client is None:
            return _missing_credentials(self, request, "CrowdStrike")

        try:
            device_id = params.get("device_id") or await client.get_device_id(target)
            if not device_id:
                # Not found is a real answer, and a different one from a
                # failed read. A renamed or decommissioned host is not an
                # outage.
                return _result(
                    self,
                    request,
                    LiveActionStatus.SUCCEEDED,
                    f"no CrowdStrike device matches {target}",
                    details={"found": False, "hostname": target},
                )
            device = await client.get_device(str(device_id))
            if device is None:
                return _result(
                    self,
                    request,
                    LiveActionStatus.FAILED,
                    "device resolved but could not be read",
                    error=f"device {device_id} resolved but could not be read",
                )
            return _result(
                self,
                request,
                LiveActionStatus.SUCCEEDED,
                f"{target}: {device.get('platform') or 'unknown platform'}, containment {device.get('containment_status') or 'unknown'}",
                details={"found": True, **device},
            )
        except Exception as exc:  # noqa: BLE001 - a vendor error is FAILED, never empty
            logger.warning("get_host.failed", vendor="crowdstrike", error=str(exc))
            return _result(
                self,
                request,
                LiveActionStatus.FAILED,
                "CrowdStrike read failed",
                error=f"CrowdStrike read failed: {exc}",
            )


@apply_contract
class CrowdStrikeGetDetections(LiveActionExecutor):
    vendor_id = "crowdstrike"
    capability = "get_detections"
    description = "Read recent CrowdStrike detections for a host."
    requires_credentials = True

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        params: dict[str, Any] = request.params or {}
        target = str(request.target or params.get("hostname") or "")
        if request.dry_run:
            return _preview(self, request, target, "CrowdStrike")

        client = _cs_client(params)
        if client is None:
            return _missing_credentials(self, request, "CrowdStrike")

        try:
            device_id = params.get("device_id") or await client.get_device_id(target)
            if not device_id:
                return _result(
                    self,
                    request,
                    LiveActionStatus.SUCCEEDED,
                    f"no CrowdStrike device matches {target}",
                    details={"found": False, "hostname": target, "detections": []},
                )
            detections = await client.get_detections(str(device_id), limit=int(params.get("limit", 20)))
            return _result(
                self,
                request,
                LiveActionStatus.SUCCEEDED,
                f"{len(detections)} recent detection(s) on {target}",
                details={
                    "found": True,
                    "hostname": target,
                    "count": len(detections),
                    "detections": detections,
                },
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("get_detections.failed", vendor="crowdstrike", error=str(exc))
            return _result(
                self,
                request,
                LiveActionStatus.FAILED,
                "CrowdStrike read failed",
                error=f"CrowdStrike read failed: {exc}",
            )


@apply_contract
class DefenderGetHost(LiveActionExecutor):
    vendor_id = "defender"
    capability = "get_host"
    description = "Read a machine record from Microsoft Defender for Endpoint."
    requires_credentials = True

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        params: dict[str, Any] = request.params or {}
        target = str(request.target or params.get("hostname") or "")
        if request.dry_run:
            return _preview(self, request, target, "Defender")

        client = _mde_client(params)
        if client is None:
            return _missing_credentials(self, request, "Defender")

        try:
            machine = await client.find_machine(target)
            if not machine:
                return _result(
                    self,
                    request,
                    LiveActionStatus.SUCCEEDED,
                    f"no Defender machine matches {target}",
                    details={"found": False, "hostname": target},
                )
            return _result(
                self,
                request,
                LiveActionStatus.SUCCEEDED,
                f"{target}: risk {machine.get('riskScore') or 'unknown'}, health {machine.get('healthStatus') or 'unknown'}",
                details={
                    "found": True,
                    "device_id": machine.get("id"),
                    "hostname": machine.get("computerDnsName"),
                    "platform": machine.get("osPlatform"),
                    "os_version": machine.get("version"),
                    "local_ip": machine.get("lastIpAddress"),
                    "external_ip": machine.get("lastExternalIpAddress"),
                    "last_seen": machine.get("lastSeen"),
                    "first_seen": machine.get("firstSeen"),
                    "health_status": machine.get("healthStatus"),
                    "risk_score": machine.get("riskScore"),
                    "exposure_level": machine.get("exposureLevel"),
                },
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("get_host.failed", vendor="defender", error=str(exc))
            return _result(
                self,
                request,
                LiveActionStatus.FAILED,
                "Defender read failed",
                error=f"Defender read failed: {exc}",
            )


@apply_contract
class OktaGetUserActivity(LiveActionExecutor):
    vendor_id = "okta"
    capability = "get_user_activity"
    description = "Read a user's current state and recent sign-in status from Okta."
    requires_credentials = True

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        params: dict[str, Any] = request.params or {}
        target = str(request.target or params.get("login") or "")
        if request.dry_run:
            return _preview(self, request, target, "Okta")

        client = _okta_client(params)
        if client is None:
            return _missing_credentials(self, request, "Okta")

        try:
            status = await client.get_user_status(target)
            if status is None:
                # Deliberately FAILED rather than an empty record: "we could
                # not read this account" and "this account is fine" are
                # different, and only one of them should let an
                # investigation move on.
                return _result(
                    self,
                    request,
                    LiveActionStatus.FAILED,
                    f"could not read Okta user {target}",
                    error=f"could not read Okta user {target}",
                )
            blocked = status.upper() in {"SUSPENDED", "DEPROVISIONED", "LOCKED_OUT"}
            return _result(
                self,
                request,
                LiveActionStatus.SUCCEEDED,
                f"{target} is {status}" + (" (sign-in blocked)" if blocked else " (sign-in permitted)"),
                details={
                    "login": target,
                    "status": status,
                    "sign_in_blocked": blocked,
                },
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("get_user_activity.failed", vendor="okta", error=str(exc))
            return _result(
                self,
                request,
                LiveActionStatus.FAILED,
                "Okta read failed",
                error=f"Okta read failed: {exc}",
            )


# ─── Phase 4.2: the vendors an investigation could not reach ─────────────────
#
# Three verbs with one vendor arm each is not a vendor-read surface, it is a
# CrowdStrike-and-Okta surface. A tenant on SentinelOne and Entra ID had the
# same investigation reach as a tenant with no EDR at all, because the verb
# existed and nothing implemented it for them: dispatch answered
# `executor_not_found`, which reads as a broken deployment rather than as a
# capability nobody wrote.
#
# Five of the seven executors below are new *vendor arms on existing verbs*,
# which is the whole point of declaring a contract per capability rather than
# per vendor: they inherit `get_host` / `get_detections` / `get_user_activity`
# classifications automatically and cannot drift low. Only the two verbs whose
# subject is neither a host nor a principal needed a new contract.


@apply_contract
class SentinelOneGetHost(LiveActionExecutor):
    vendor_id = "sentinelone"
    capability = "get_host"
    description = "Read an agent record from SentinelOne."
    requires_credentials = True

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        params: dict[str, Any] = request.params or {}
        target = str(request.target or params.get("hostname") or "")
        if request.dry_run:
            return _preview(self, request, target, "SentinelOne")

        client = _s1_client(params)
        if client is None:
            return _missing_credentials(self, request, "SentinelOne")

        try:
            agent = await client.find_agent(target)
            if agent is None:
                return _result(
                    self,
                    request,
                    LiveActionStatus.SUCCEEDED,
                    f"no SentinelOne agent matches {target}",
                    details={"found": False, "hostname": target},
                )
            return _result(
                self,
                request,
                LiveActionStatus.SUCCEEDED,
                (
                    f"{target}: {agent.get('osName') or 'unknown platform'}, "
                    f"network {'disconnected' if agent.get('networkStatus') == 'disconnected' else agent.get('networkStatus') or 'unknown'}"
                ),
                details={
                    "found": True,
                    "agent_uuid": agent.get("uuid"),
                    "hostname": agent.get("computerName"),
                    "platform": agent.get("osName"),
                    "os_version": agent.get("osRevision"),
                    "agent_version": agent.get("agentVersion"),
                    "local_ip": agent.get("lastIpToMgmt"),
                    "external_ip": agent.get("externalIp"),
                    "last_seen": agent.get("lastActiveDate"),
                    "network_status": agent.get("networkStatus"),
                    "infected": agent.get("infected"),
                    "active_threats": agent.get("activeThreats"),
                    "is_up_to_date": agent.get("isUpToDate"),
                },
            )
        except Exception as exc:  # noqa: BLE001 - a vendor error is FAILED, never empty
            logger.warning("get_host.failed", vendor="sentinelone", error=str(exc))
            return _result(
                self,
                request,
                LiveActionStatus.FAILED,
                "SentinelOne read failed",
                error=f"SentinelOne read failed: {exc}",
            )


@apply_contract
class SentinelOneGetDetections(LiveActionExecutor):
    vendor_id = "sentinelone"
    capability = "get_detections"
    description = "Read recent SentinelOne threats for a host."
    requires_credentials = True

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        params: dict[str, Any] = request.params or {}
        target = str(request.target or params.get("hostname") or "")
        if request.dry_run:
            return _preview(self, request, target, "SentinelOne")

        client = _s1_client(params)
        if client is None:
            return _missing_credentials(self, request, "SentinelOne")

        try:
            threats = await client.list_threats(target, limit=int(params.get("limit", 20)))
            return _result(
                self,
                request,
                LiveActionStatus.SUCCEEDED,
                f"{len(threats)} recent threat(s) on {target}",
                details={"found": True, "hostname": target, "count": len(threats), "detections": threats},
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("get_detections.failed", vendor="sentinelone", error=str(exc))
            return _result(
                self,
                request,
                LiveActionStatus.FAILED,
                "SentinelOne read failed",
                error=f"SentinelOne read failed: {exc}",
            )


@apply_contract
class DefenderGetDetections(LiveActionExecutor):
    vendor_id = "defender"
    capability = "get_detections"
    description = "Read recent Microsoft Defender alerts for a host."
    requires_credentials = True

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        params: dict[str, Any] = request.params or {}
        target = str(request.target or params.get("hostname") or "")
        if request.dry_run:
            return _preview(self, request, target, "Defender")

        client = _mde_client(params)
        if client is None:
            return _missing_credentials(self, request, "Defender")

        try:
            # `list_alerts_for_host` resolves the machine first and returns an
            # empty list when there is none. That is indistinguishable from a
            # machine with no alerts, and the two are different answers, so the
            # resolution is done here where it can be reported.
            machine = await client.find_machine(target)
            if machine is None:
                return _result(
                    self,
                    request,
                    LiveActionStatus.SUCCEEDED,
                    f"no Defender machine matches {target}",
                    details={"found": False, "hostname": target, "detections": []},
                )
            alerts = await client.list_alerts_for_host(target, limit=int(params.get("limit", 20)))
            return _result(
                self,
                request,
                LiveActionStatus.SUCCEEDED,
                f"{len(alerts)} recent Defender alert(s) on {target}",
                details={"found": True, "hostname": target, "count": len(alerts), "detections": alerts},
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("get_detections.failed", vendor="defender", error=str(exc))
            return _result(
                self,
                request,
                LiveActionStatus.FAILED,
                "Defender read failed",
                error=f"Defender read failed: {exc}",
            )


@apply_contract
class EntraGetUserActivity(LiveActionExecutor):
    vendor_id = "entra"
    capability = "get_user_activity"
    description = "Read recent sign-ins and the risk assessment for an Entra ID principal."
    requires_credentials = True

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        params: dict[str, Any] = request.params or {}
        target = str(request.target or params.get("user_principal_name") or params.get("user_name") or "")
        if request.dry_run:
            return _preview(self, request, target, "Entra ID")

        client = _entra_client(params)
        if client is None:
            return _missing_credentials(self, request, "Entra ID")

        try:
            sign_ins = await client.list_sign_ins(
                target,
                hours=int(params.get("hours", 24)),
                limit=int(params.get("limit", 50)),
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("get_user_activity.failed", vendor="entra", error=str(exc))
            return _result(
                self,
                request,
                LiveActionStatus.FAILED,
                "Entra ID read failed",
                error=f"Entra ID sign-in read failed: {exc}",
            )

        # The risk record is a second call against a beta endpoint, and it is
        # allowed to fail without taking the sign-ins with it. Its absence is
        # reported as unknown rather than as "not at risk", because ID
        # Protection is a licensed feature and a tenant without it would
        # otherwise read as a tenant with a clean principal.
        risk: dict[str, Any] | None = None
        risk_error: str | None = None
        try:
            risk = await client.get_risky_user(target)
        except Exception as exc:  # noqa: BLE001
            risk_error = f"{type(exc).__name__}: {exc}"
            logger.warning("get_user_activity.risk_unavailable", vendor="entra", error=risk_error)

        distinct_ips = sorted({str(row.get("ip")) for row in sign_ins if row.get("ip")})
        failures = sum(1 for row in sign_ins if row.get("succeeded") is False)
        details: dict[str, Any] = {
            "found": True,
            "user": target,
            "count": len(sign_ins),
            "sign_ins": sign_ins,
            "distinct_source_ips": distinct_ips,
            "failed_sign_ins": failures,
        }
        if risk is not None:
            details["risk"] = risk
        else:
            details["risk"] = None
            details["risk_unavailable_reason"] = risk_error or (
                "Entra ID Protection holds no risk record for this principal, which may mean "
                "no risk was detected or that the tenant is not licensed for it. Treat as "
                "unknown rather than clear."
            )
        return _result(
            self,
            request,
            LiveActionStatus.SUCCEEDED,
            (f"{len(sign_ins)} sign-in(s) for {target} from {len(distinct_ips)} distinct address(es), {failures} failed"),
            details=details,
        )


@apply_contract
class GoogleWorkspaceGetUserActivity(LiveActionExecutor):
    vendor_id = "google_workspace"
    capability = "get_user_activity"
    description = "Read recent Google Workspace login audit events for an account."
    requires_credentials = True

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        params: dict[str, Any] = request.params or {}
        target = str(request.target or params.get("user_email") or params.get("user_name") or "")
        if request.dry_run:
            return _preview(self, request, target, "Google Workspace")

        client = _gws_client(params)
        if client is None:
            return _missing_credentials(self, request, "Google Workspace")

        try:
            events = await client.list_login_events(
                target,
                hours=int(params.get("hours", 24)),
                limit=int(params.get("limit", 50)),
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("get_user_activity.failed", vendor="google_workspace", error=str(exc))
            return _result(
                self,
                request,
                LiveActionStatus.FAILED,
                "Google Workspace read failed",
                error=(
                    f"Google Workspace login audit read failed: {exc}. A 403 here usually means the "
                    f"service account has not been granted admin.reports.audit.readonly domain-wide, "
                    f"which is a configuration gap and not a statement about this account."
                ),
            )

        distinct_ips = sorted({str(row.get("ip")) for row in events if row.get("ip")})
        suspicious = sum(1 for row in events if row.get("is_suspicious") in (True, "true"))
        return _result(
            self,
            request,
            LiveActionStatus.SUCCEEDED,
            (f"{len(events)} login event(s) for {target} from {len(distinct_ips)} distinct address(es)"),
            details={
                "found": True,
                "user": target,
                "count": len(events),
                "logins": events,
                "distinct_source_ips": distinct_ips,
                "flagged_suspicious_by_google": suspicious,
            },
        )


@apply_contract
class AWSLookupCloudAudit(LiveActionExecutor):
    vendor_id = "aws"
    capability = "lookup_cloud_audit"
    description = "Look up AWS CloudTrail management events for a principal, resource or API call."
    requires_credentials = True

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        params: dict[str, Any] = request.params or {}
        attribute_key = str(params.get("attribute_key") or "Username")
        target = str(request.target or params.get("attribute_value") or "")
        if request.dry_run:
            return _preview(self, request, f"{attribute_key}={target}", "AWS CloudTrail")

        client = _cloudtrail_client(params)
        if client is None:
            return _missing_credentials(self, request, "AWS CloudTrail")

        try:
            events = await client.lookup_events(
                attribute_key=attribute_key,
                attribute_value=target,
                hours=int(params.get("hours", 24)),
                limit=int(params.get("limit", 50)),
            )
        except CloudTrailLookupError as exc:
            # Deliberately FAILED, including for a refused attribute key. An
            # empty list here would be read as "this principal made no API
            # calls", which is a statement about the customer's account rather
            # than about our request.
            logger.warning("lookup_cloud_audit.failed", vendor="aws", error=str(exc))
            return _result(self, request, LiveActionStatus.FAILED, "CloudTrail lookup failed", error=str(exc))
        except Exception as exc:  # noqa: BLE001
            logger.warning("lookup_cloud_audit.failed", vendor="aws", error=str(exc))
            return _result(
                self,
                request,
                LiveActionStatus.FAILED,
                "CloudTrail lookup failed",
                error=f"CloudTrail lookup failed: {exc}",
            )

        errors = sorted({str(row["error_code"]) for row in events if row.get("error_code")})
        return _result(
            self,
            request,
            LiveActionStatus.SUCCEEDED,
            f"{len(events)} CloudTrail event(s) for {attribute_key} {target}",
            details={
                "found": True,
                "attribute_key": attribute_key,
                "attribute_value": target,
                "count": len(events),
                "events": events,
                "api_error_codes": errors,
            },
        )


@apply_contract
class DefenderLookupEndpointTelemetry(LiveActionExecutor):
    vendor_id = "defender"
    capability = "lookup_endpoint_telemetry"
    description = "Search Microsoft Defender endpoint telemetry for sightings of one indicator."
    requires_credentials = True

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        params: dict[str, Any] = request.params or {}
        template = str(params.get("template") or "")
        target = str(request.target or params.get("indicator") or "")
        if request.dry_run:
            return _preview(self, request, f"{template}:{target}", "Defender")

        # Checked before the credential, because an unknown template is a
        # caller error and reporting it as a credential problem would send an
        # operator to look at their Azure app registration.
        if template not in _HUNT_TEMPLATES:
            return _result(
                self,
                request,
                LiveActionStatus.FAILED,
                "unknown telemetry template",
                error=(
                    f"{template!r} is not one of the telemetry templates this verb can run. "
                    f"Known templates: {', '.join(sorted(_HUNT_TEMPLATES))}. Query text is not accepted."
                ),
            )

        client = _mde_client(params)
        if client is None:
            return _missing_credentials(self, request, "Defender")

        try:
            rows = await client.hunt_indicator(
                template,
                target,
                hours=int(params.get("hours", 24)),
                limit=int(params.get("limit", 50)),
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("lookup_endpoint_telemetry.failed", vendor="defender", error=str(exc))
            return _result(
                self,
                request,
                LiveActionStatus.FAILED,
                "Defender telemetry search failed",
                error=f"Defender telemetry search failed: {exc}",
            )

        hosts = sorted({str(row["DeviceName"]) for row in rows if row.get("DeviceName")})
        return _result(
            self,
            request,
            LiveActionStatus.SUCCEEDED,
            f"{len(rows)} sighting(s) of {target} across {len(hosts)} host(s)",
            details={
                "found": True,
                "template": template,
                "indicator": target,
                "count": len(rows),
                "distinct_hosts": hosts,
                "sightings": rows,
            },
        )


# ─── Rollback ────────────────────────────────────────────────────────────────
#
# `unisolate_host` was declared as the reverse of `isolate_host` and had no
# executor. The rollback path for the platform's most disruptive action
# therefore resolved to nothing: the contract said a route back existed, the
# UI offered it, and dispatch answered executor_not_found — which reads as a
# misconfiguration rather than a capability that was never built.
#
# Both clients already supported it. Nothing was missing but the executor.


@apply_contract
class CrowdStrikeUnisolateHost(LiveActionExecutor):
    vendor_id = "crowdstrike"
    capability = "unisolate_host"
    description = "Lift network containment on a CrowdStrike Falcon host."
    requires_credentials = True

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        params: dict[str, Any] = request.params or {}
        target = str(request.target or params.get("hostname") or "")
        if request.dry_run:
            return _preview(self, request, target, "CrowdStrike")

        client = _cs_client(params)
        if client is None:
            return _missing_credentials(self, request, "CrowdStrike")

        try:
            device_id = params.get("device_id") or await client.get_device_id(target)
            if not device_id:
                # A host that cannot be resolved cannot be released, and
                # reporting success would leave it contained with the
                # incident closed.
                return _result(
                    self,
                    request,
                    LiveActionStatus.FAILED,
                    f"host {target} could not be resolved",
                    error=f"host {target} could not be resolved, so containment was not lifted",
                )
            vendor_response = await client.lift_containment(str(device_id))
            return _result(
                self,
                request,
                LiveActionStatus.SUCCEEDED,
                f"containment lifted on {target}",
                details={
                    "device_id": device_id,
                    "hostname": target,
                    "vendor_response": vendor_response,
                },
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("unisolate_host.failed", vendor="crowdstrike", error=str(exc))
            return _result(
                self,
                request,
                LiveActionStatus.FAILED,
                "CrowdStrike lift failed",
                error=f"CrowdStrike lift failed: {exc}",
            )


@apply_contract
class DefenderUnisolateHost(LiveActionExecutor):
    vendor_id = "defender"
    capability = "unisolate_host"
    description = "Release a machine from isolation on Microsoft Defender for Endpoint."
    requires_credentials = True

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        params: dict[str, Any] = request.params or {}
        target = str(request.target or params.get("hostname") or "")
        if request.dry_run:
            return _preview(self, request, target, "Defender")

        client = _mde_client(params)
        if client is None:
            return _missing_credentials(self, request, "Defender")

        try:
            vendor_response = await client.unisolate_machine(target)
            return _result(
                self,
                request,
                LiveActionStatus.SUCCEEDED,
                f"isolation released on {target}",
                details={"hostname": target, "vendor_response": vendor_response},
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("unisolate_host.failed", vendor="defender", error=str(exc))
            return _result(
                self,
                request,
                LiveActionStatus.FAILED,
                "Defender release failed",
                error=f"Defender release failed: {exc}",
            )
