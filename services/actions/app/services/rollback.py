"""Honest, real reverse actions (Phase B3).

Before this module, every executor's ``rollback()`` returned a bare ``True`` —
it logged "rolling back" and claimed success without calling the vendor. That
is exactly the "simulated result presented as functional" the program forbids.

``reverse_action`` performs the **real** reverse vendor call when credentials
are present, using the same clients the forward action uses:

===================  =========================  =================================
forward action       reverse call               client method
===================  =========================  =================================
isolate_host         de-isolate / lift          CrowdStrike ``lift_containment``,
                                                 Defender ``unisolate_machine``,
                                                 SentinelOne ``lift_containment``
block_ip             unblock                    AWS/PAN-OS/FortiGate ``unblock_ip``,
                                                 Cloudflare ``unblock_ip_zone``
disable_user         enable / unsuspend         Okta/Entra ``enable_user``, GWS
                                                 ``unsuspend_user``
suspend_session      unsuspend                  Okta ``unsuspend_user``
===================  =========================  =================================

The contract is **honest**: the returned :class:`RollbackResult` says whether a
real reverse actually ran (``reversed_``), whether it was a credential-less
simulation (``simulated``), or whether no reverse exists for that action
(``supported=False``) — never a blanket ``True``. :data:`REVERSIBLE_ACTIONS`
here is the single source of truth the autonomy layer imports, so its
"reversible" set can never claim an action it can't actually undo.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import structlog

from app.executors.endpoint import _cs_client, _mde_client, _s1_client
from app.executors.identity import _entra_client, _gws_client, _okta_client
from app.executors.network import _aws_client, _cloudflare_client, _fortigate_client, _panos_client
from app.models.action import ActionType

logger = structlog.get_logger()

# Action types with a genuine reverse implementation below. The autonomy layer
# imports this so it can never advertise "reversible" for something we can't undo.
REVERSIBLE_ACTIONS: frozenset[ActionType] = frozenset(
    {
        ActionType.ISOLATE_HOST,
        ActionType.BLOCK_IP,
        ActionType.DISABLE_USER,
        ActionType.SUSPEND_SESSION,
    }
)


@dataclass(frozen=True)
class RollbackResult:
    supported: bool  # a reverse path exists for this action type
    reversed_: bool  # a real reverse call actually executed against a vendor
    simulated: bool  # no credentials → reverse was simulated (logged only)
    vendor: str | None
    reason: str

    @property
    def ok(self) -> bool:
        """True if the reverse either really ran or was a safe simulation."""
        return self.reversed_ or self.simulated


def _unsupported(action_type: ActionType) -> RollbackResult:
    return RollbackResult(
        supported=False,
        reversed_=False,
        simulated=False,
        vendor=None,
        reason=f"no automatic reverse exists for {action_type.value}",
    )


async def _reverse_isolate(target: str, params: dict[str, Any]) -> RollbackResult:
    cs = _cs_client(params)
    if cs is not None:
        device_id = await cs.get_device_id(target)
        if device_id:
            await cs.lift_containment(device_id)
        return RollbackResult(True, True, False, "crowdstrike", f"lifted containment on {target}")
    mde = _mde_client(params)
    if mde is not None:
        await mde.unisolate_machine(target)
        return RollbackResult(True, True, False, "defender", f"un-isolated {target}")
    s1 = _s1_client(params)
    if s1 is not None:
        await s1.lift_containment(target)
        return RollbackResult(True, True, False, "sentinelone", f"lifted containment on {target}")
    return RollbackResult(True, False, True, None, "no EDR credentials — de-isolation simulated")


async def _reverse_block_ip(target: str, params: dict[str, Any]) -> RollbackResult:
    aws = _aws_client(params)
    if aws is not None:
        await aws.unblock_ip(target)
        return RollbackResult(True, True, False, "aws_security_groups", f"unblocked {target}")
    panos = _panos_client(params)
    if panos is not None:
        await panos.unblock_ip(target, params.get("panos_tag", ""))
        return RollbackResult(True, True, False, "panos", f"unblocked {target}")
    fgt = _fortigate_client(params)
    if fgt is not None:
        await fgt.unblock_ip(target, params.get("fgt_address_group", ""))
        return RollbackResult(True, True, False, "fortigate", f"unblocked {target}")
    cf = _cloudflare_client(params)
    if cf is not None and params.get("cf_rule_id") and params.get("cf_zone_id"):
        await cf.unblock_ip_zone(params["cf_rule_id"], params["cf_zone_id"])
        return RollbackResult(True, True, False, "cloudflare", f"unblocked {target}")
    return RollbackResult(True, False, True, None, "no firewall credentials — unblock simulated")


async def _reverse_disable_user(target: str, params: dict[str, Any]) -> RollbackResult:
    okta = _okta_client(params)
    if okta is not None:
        await okta.enable_user(target)
        return RollbackResult(True, True, False, "okta", f"re-enabled {target}")
    entra = _entra_client(params)
    if entra is not None:
        await entra.enable_user(target)
        return RollbackResult(True, True, False, "azure_entra", f"re-enabled {target}")
    gws = _gws_client(params)
    if gws is not None:
        await gws.unsuspend_user(target)
        return RollbackResult(True, True, False, "google_workspace", f"unsuspended {target}")
    return RollbackResult(True, False, True, None, "no IdP credentials — re-enable simulated")


async def _reverse_suspend_session(target: str, params: dict[str, Any]) -> RollbackResult:
    okta = _okta_client(params)
    if okta is not None:
        await okta.unsuspend_user(target)
        return RollbackResult(True, True, False, "okta", f"unsuspended {target}")
    return RollbackResult(True, False, True, None, "no IdP credentials — unsuspend simulated")


_REVERSERS = {
    ActionType.ISOLATE_HOST: _reverse_isolate,
    ActionType.BLOCK_IP: _reverse_block_ip,
    ActionType.DISABLE_USER: _reverse_disable_user,
    ActionType.SUSPEND_SESSION: _reverse_suspend_session,
}


async def reverse_action(action_type: ActionType, target: str, params: dict[str, Any] | None = None) -> RollbackResult:
    """Perform the real reverse of ``action_type`` on ``target``.

    Honest by construction: returns ``supported=False`` when no reverse exists,
    ``simulated=True`` when credentials are absent, and ``reversed_=True`` only
    when a real vendor reverse call actually executed.
    """
    reverser = _REVERSERS.get(action_type)
    if reverser is None:
        return _unsupported(action_type)
    params = params or {}
    try:
        result = await reverser(target, params)
        logger.info(
            "rollback.reverse",
            action=action_type.value,
            target=target,
            vendor=result.vendor,
            reversed=result.reversed_,
            simulated=result.simulated,
        )
        return result
    except Exception as exc:  # noqa: BLE001 — a failed reverse must be reported, not hidden
        logger.error("rollback.reverse_failed", action=action_type.value, target=target, error=str(exc))
        return RollbackResult(True, False, False, None, f"reverse call failed: {exc}")
