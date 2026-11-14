"""Read-only vendor verbs, scoped to what a tenant has actually configured.

Gap-closure Phase 4.2 and 4.3, the API half.

``services/actions`` holds the executors and ``services/api`` holds the vault
and the tenant session, so a read has to cross a service boundary. That hop
already exists and is already correct: ``playbook_step_dispatch.dispatch_step``
resolves which vendor implements a verb by asking the live registry, picks the
tenant's enabled connector for it, honours the per-instance
``allowed_capabilities`` downscoping a tenant may have set, decrypts the
credential, dispatches under governance, and returns a report that keeps every
non-execution apart from every other. None of that is rebuilt here.

What this module adds is the two things a read surface needs that a playbook
step does not.

**A read-only door.** ``dispatch_step`` will dispatch any capability, which is
correct for a playbook step: a playbook may legitimately isolate a host. This
door may not. So it carries its own closed allowlist of agent-reachable read
verbs **and** verifies against the live registry that the verb is declared
``read_only`` before dispatching. Two independent checks: the allowlist means a
verb cannot become agent-reachable by being added somewhere else, and the
registry check means a verb that changes classification stops flowing even if
the allowlist is stale. A gate asserts the allowlist is a subset of the
contract's read-only set, in the direction that drifts.

**Per-tenant advertisement.** 4.3 requires that only tools whose backend is
configured for the tenant are advertised. That is not cosmetic. A model offered
a CrowdStrike tool on a tenant with no CrowdStrike will call it, read
``no_integration``, and spend a turn of a bounded loop learning something the
deployment already knew. Worse, some models will narrate the attempt as though
it had returned something.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.connector import Connector
from app.services import actions_client
from app.services.agent_tools import vendor_aliases
from app.services.playbook_step_dispatch import StepDispatchReport, dispatch_step

logger = logging.getLogger(__name__)

#: The verbs an investigation agent may reach through this door.
#:
#: A closed set, maintained here rather than derived, so a capability cannot
#: become agent-reachable as a side effect of being added to the contract
#: file. ``scripts/check_agent_read_tools.py`` asserts every entry is declared
#: ``READ_ONLY`` upstream, which is the direction that can go wrong: this list
#: being narrower than the contract is safe, being wider is not.
AGENT_READ_CAPABILITIES: frozenset[str] = frozenset(
    {
        "get_host",
        "get_detections",
        "get_user_activity",
        "lookup_cloud_audit",
        "lookup_endpoint_telemetry",
    }
)

#: Parameters a caller may pass, per verb. Everything else is dropped rather
#: than forwarded: a caller that can add arbitrary keys to ``params`` can
#: reach past the typed surface into whatever an executor happens to read,
#: and the executors read their credentials out of the same dictionary.
#:
#: That last clause is the whole reason this exists. ``params`` carries the
#: decrypted ``auth_config`` by the time it reaches the actions service, so an
#: unfiltered pass-through would let a caller supply ``cs_client_secret`` and
#: have a read run against **their** CrowdStrike rather than the tenant's.
ALLOWED_PARAMS: dict[str, frozenset[str]] = {
    "get_host": frozenset({"limit"}),
    "get_detections": frozenset({"limit"}),
    "get_user_activity": frozenset({"hours", "limit"}),
    "lookup_cloud_audit": frozenset({"attribute_key", "hours", "limit"}),
    "lookup_endpoint_telemetry": frozenset({"template", "hours", "limit"}),
}

#: Numeric parameters, with their ceilings. Applied here as well as in the
#: executors, because a caller should be refused at the door rather than
#: silently clamped three services away.
_NUMERIC_CEILINGS: dict[str, int] = {"limit": 50, "hours": 720}


class VendorReadError(ValueError):
    """The request was refused before any vendor was contacted."""


@dataclass(frozen=True)
class AvailableRead:
    """One (capability, vendor) pair this tenant can actually use."""

    capability: str
    vendor_id: str
    connector_name: str

    def as_dict(self) -> dict[str, Any]:
        return {"capability": self.capability, "vendor": self.vendor_id, "connector": self.connector_name}


def _sanitise_params(capability: str, params: dict[str, Any] | None) -> dict[str, Any]:
    allowed = ALLOWED_PARAMS.get(capability, frozenset())
    clean: dict[str, Any] = {}
    for key, value in (params or {}).items():
        if key not in allowed:
            # Dropped loudly. A silently ignored parameter is how a caller
            # comes to believe it set a window it did not set.
            logger.info(
                "agent_tools.param_dropped capability=%s key=%s",
                str(capability).replace("\r", "").replace("\n", " ")[:64],
                str(key).replace("\r", "").replace("\n", " ")[:40],
            )
            continue
        if key in _NUMERIC_CEILINGS:
            try:
                number = int(value)
            except (TypeError, ValueError) as exc:
                raise VendorReadError(f"{key} must be an integer") from exc
            clean[key] = max(1, min(number, _NUMERIC_CEILINGS[key]))
            continue
        clean[key] = value
    return clean


async def available_reads(db: AsyncSession, *, tenant_id: uuid.UUID) -> list[AvailableRead]:
    """The read verbs this tenant has a configured, enabled backend for.

    Asked of the live action registry rather than mirrored, for the reason
    ``actions_client.vendors_for_capability`` records: a second copy of the
    registry in this process would go stale the first time somebody ships a
    vendor, and the failure would read as "this tenant has no integration"
    rather than as "the list is old".

    A registry that cannot be reached yields an empty list, and the caller
    reports that as "could not determine" rather than as "no tools". The
    distinction matters here more than anywhere: an agent told it has no
    tools will confidently investigate without them.
    """
    rows = (
        (
            await db.execute(
                select(Connector)
                .where(Connector.tenant_id == tenant_id)
                .where(Connector.is_enabled.is_(True))
                .order_by(Connector.connector_type, Connector.name)
            )
        )
        .scalars()
        .all()
    )
    if not rows:
        return []

    by_type: dict[str, Connector] = {}
    for row in rows:
        by_type.setdefault(row.connector_type, row)

    out: list[AvailableRead] = []
    for capability in sorted(AGENT_READ_CAPABILITIES):
        try:
            implementers = await actions_client.vendors_for_capability(capability)
        except actions_client.ActionsServiceError as exc:
            logger.warning("agent_tools.registry_unreachable capability=%s error=%s", capability, str(exc)[:200])
            raise
        for vendor_id in sorted(implementers):
            # Through the alias map: a read executor is named for the
            # product and a connector for the integration, and three of
            # the seven never matched by string alone.
            connector = vendor_aliases.resolve(vendor_id, by_type)
            if connector is None:
                continue
            allowed = connector.allowed_capabilities
            if allowed is not None and capability not in allowed:
                # The tenant said "not this verb on this integration". An
                # agent does not outrank that, and it must not be advertised
                # a tool it would then be refused.
                continue
            out.append(AvailableRead(capability=capability, vendor_id=vendor_id, connector_name=connector.name))
    return out


async def run_read(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    capability: str,
    target: str,
    params: dict[str, Any] | None = None,
    vendor_id: str = "",
    actor: str = "aisoc-agent",
) -> StepDispatchReport:
    """Dispatch one read verb for a tenant, under governance.

    ``dry_run`` is False, which is the opposite of this repository's default
    and is deliberate: a dry run of a read returns a preview of a read, which
    is not evidence. The safety argument is the contract's rather than the
    flag's, and it is checked twice below before anything is dispatched.
    """
    if capability not in AGENT_READ_CAPABILITIES:
        raise VendorReadError(
            f"{capability!r} is not a read verb an investigation may call. Available: {', '.join(sorted(AGENT_READ_CAPABILITIES))}."
        )
    if not str(target).strip():
        raise VendorReadError("a target is required")

    # Second, independent check, against the live contract rather than the
    # list above. The allowlist stops a new verb arriving here by accident;
    # this stops an existing verb whose classification changed from carrying
    # on. Either alone would be a single point of failure on the one door in
    # this product a model can open by emitting a sentence.
    try:
        declared = await actions_client.read_only_capabilities()
    except actions_client.ActionsServiceError as exc:
        raise VendorReadError(
            f"the action registry could not confirm {capability!r} is read-only, so the read was not attempted: {exc}"
        ) from exc
    if capability not in declared:
        raise VendorReadError(
            f"the action registry does not declare {capability!r} as read-only, so an investigation may not call it. "
            f"A verb that changes a vendor's state must go through the approval path."
        )

    clean = _sanitise_params(capability, params)
    report = await dispatch_step(
        db,
        tenant_id=tenant_id,
        capability=capability,
        target=str(target),
        params=clean,
        vendor_id=vendor_id,
        # A read carries no confidence claim: the contract grades it
        # READ_ONLY and AUTOMATIC regardless, and passing a number here
        # would imply the approval matrix had an opinion it does not.
        confidence=None,
        dry_run=False,
        requested_by=actor,
    )
    logger.info(
        "agent_tools.vendor_read tenant=%s capability=%s vendor=%s status=%s executed=%s",
        tenant_id,
        str(capability).replace("\r", "").replace("\n", " ")[:64],
        str(report.vendor_id).replace("\r", "").replace("\n", " ")[:64],
        str(report.status).replace("\r", "").replace("\n", " ")[:32],
        report.executed,
    )
    return report


__all__ = [
    "AGENT_READ_CAPABILITIES",
    "ALLOWED_PARAMS",
    "AvailableRead",
    "VendorReadError",
    "available_reads",
    "run_read",
]
