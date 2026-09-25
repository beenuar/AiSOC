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

from app.clients.factories import _cs_client, _mde_client, _okta_client
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
