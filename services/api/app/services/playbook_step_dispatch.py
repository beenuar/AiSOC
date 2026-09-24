"""Turn a playbook step that names a response verb into a governed action.

Twelve of the engine's twenty-two step types had no handler, and three more
(``block_ip``, ``isolate_host``, ``create_ticket``) returned
``{"simulated": true}`` from inside the agents service and reached no executor
at all. Meanwhile ``services/actions`` held working executors for fourteen of
those fifteen verbs behind a per-capability contract. The missing piece was
never an executor. It was this: a way from a step to governed dispatch.

Why the hop lands here
----------------------
The agents worker cannot dispatch on its own. This service holds the
credential vault, the tenant-scoped database session and the actions-service
token, and ``services/actions`` is the single place that may change a
customer's estate. A second dispatcher in the agents service would mean two
places that can isolate a host, two audit trails and two copies of the
credential handling, of which one would go stale. Same reasoning, and the
same shape, as ``siem_writeback``.

What this module decides, and what it does not
----------------------------------------------
It decides **which vendor** and **which credentials**, because those are
tenant facts and this is the only service that can read them. It decides
nothing about whether the action may run: risk, reversibility, approval and
verification are declared per capability in ``services/actions`` and applied
by ``live_actions.dispatch()``. A policy mirrored in two services is a policy
that disagrees with itself eventually.

Honesty rules, which are the point of the whole exercise
--------------------------------------------------------
``executed`` is the single field that means a vendor was touched. A dry run,
a simulation, an approval queue, a missing integration and a refusal are all
``executed=False`` and each says which one it was. Nothing here reports
``succeeded`` for work that did not happen — replacing one silent simulation
with another would leave the product exactly where it started.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.connector import Connector
from app.security.credential_vault import CredentialVaultError, get_vault
from app.services import actions_client

logger = structlog.get_logger(__name__)

#: Step outcomes that are *not* an execution, each naming its own reason.
#: Kept as a closed vocabulary so a caller can branch on it, and so a new
#: outcome has to be added deliberately rather than arriving as free text.
NOT_EXECUTED_STATES: frozenset[str] = frozenset(
    {
        "dry_run",
        "simulated",
        "pending_approval",
        "blocked",
        "no_integration",
        "failed",
        "unsupported",
    }
)


@dataclass
class StepDispatchReport:
    """What actually happened to one step.

    ``executed`` is deliberately not derived from ``status`` by the caller.
    Every construction site sets it explicitly, so adding a status cannot
    accidentally inherit "a vendor was touched".
    """

    capability: str
    status: str
    executed: bool
    summary: str
    vendor_id: str = ""
    detail: str = ""
    #: ``verified`` | ``failed`` | ``unverified``. Absent when the action did
    #: not run, because there is nothing to read back.
    verification: str = ""
    verification_reason: str = ""
    autonomy_mode: str = ""
    blast_radius: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "capability": self.capability,
            "status": self.status,
            "executed": self.executed,
            "summary": self.summary,
        }
        for key in ("vendor_id", "detail", "verification", "verification_reason", "autonomy_mode", "blast_radius"):
            value = getattr(self, key)
            if value:
                out[key] = value
        if self.details:
            out["details"] = self.details
        return out


#: Connector-instance settings a response action needs that are configuration
#: rather than secrets, so they must not be encrypted at rest as though they
#: were. Mirrors ``siem_writeback._operational_config``.
_OPERATIONAL_KEYS = ("base_url", "region", "closing_reason_id", "owner", "owner_upn", "project_key", "instance_url")


async def dispatch_step(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    capability: str,
    target: str,
    params: dict[str, Any] | None = None,
    vendor_id: str = "",
    confidence: float | None = None,
    dry_run: bool = True,
    requested_by: str = "aisoc-playbook",
    playbook_run_id: str = "",
    playbook_step_id: str = "",
) -> StepDispatchReport:
    """Resolve a vendor, resolve its credentials, and dispatch under governance."""
    log = logger.bind(
        capability=capability,
        tenant_id=str(tenant_id),
        playbook_run_id=playbook_run_id,
        playbook_step_id=playbook_step_id,
        dry_run=dry_run,
    )

    try:
        implementers = await actions_client.vendors_for_capability(capability)
    except actions_client.ActionsServiceError as exc:
        log.warning("playbook_step.registry_unreachable", error=str(exc)[:300])
        return StepDispatchReport(
            capability=capability,
            status="failed",
            executed=False,
            summary=f"Could not reach the action registry to run '{capability}'.",
            detail=exc.upstream_detail,
        )

    if not implementers:
        # Distinct from "this tenant has no integration": nothing in the
        # product can perform this verb, so no amount of configuration helps.
        return StepDispatchReport(
            capability=capability,
            status="unsupported",
            executed=False,
            summary=f"No executor is registered for '{capability}' in this deployment.",
            detail="A verb must be in both the Capability enum and KNOWN_CAPABILITIES to reach an executor.",
        )

    connector = await _pick_connector(db, tenant_id=tenant_id, capability=capability, implementers=implementers, pinned=vendor_id)
    if connector is None:
        configured = ", ".join(sorted(implementers))
        return StepDispatchReport(
            capability=capability,
            status="no_integration",
            executed=False,
            vendor_id=vendor_id,
            summary=(
                f"'{capability}' is supported, and this tenant has no enabled connector that performs it."
                if not vendor_id
                else f"'{capability}' was pinned to '{vendor_id}', which this tenant has not configured."
            ),
            detail=f"vendors that implement it: {configured}",
        )

    resolved_vendor = connector.connector_type
    log = log.bind(vendor_id=resolved_vendor)

    try:
        auth_config = get_vault().decrypt_dict(connector.auth_config or {})
    except CredentialVaultError as exc:
        # Reported, never downgraded to a simulation. A step that silently
        # became a preview because a key would not decrypt is the failure
        # this whole change exists to remove.
        log.warning("playbook_step.credentials_undecryptable")
        return StepDispatchReport(
            capability=capability,
            status="failed",
            executed=False,
            vendor_id=resolved_vendor,
            summary=f"Credentials for {resolved_vendor} could not be decrypted, so '{capability}' did not run.",
            detail=str(exc)[:500],
        )
    auth_config.update(_operational_config(connector))

    try:
        body = await actions_client.dispatch_live_action(
            capability=capability,
            vendor_id=resolved_vendor,
            target=target,
            tenant_id=str(tenant_id),
            params=dict(params or {}),
            auth_config=auth_config or None,
            dry_run=dry_run,
            requested_by=requested_by,
            confidence=confidence,
            playbook_run_id=playbook_run_id or None,
            playbook_step_id=playbook_step_id or None,
        )
    except actions_client.ActionsServiceError as exc:
        log.warning("playbook_step.dispatch_refused", status_code=exc.status_code)
        return StepDispatchReport(
            capability=capability,
            status="failed",
            executed=False,
            vendor_id=resolved_vendor,
            summary=f"The action service refused '{capability}'.",
            detail=exc.upstream_detail,
        )

    report = _interpret(capability, resolved_vendor, body, dry_run=dry_run)
    log.info("playbook_step.dispatched", status=report.status, executed=report.executed)
    return report


async def _pick_connector(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    capability: str,
    implementers: list[str],
    pinned: str,
) -> Connector | None:
    """The tenant's enabled connector for this verb, or ``None``.

    A pinned vendor is honoured only if the tenant actually has it. Honouring
    a pin without checking is how a "dry run" ends up calling somebody's
    firewall, and how an action reports against a vendor that was never
    involved.

    Where the step names no vendor and the tenant has several, the choice is
    deterministic (first by name) rather than whichever row the database
    happened to return. A non-deterministic containment target is not a
    feature.
    """
    wanted = [pinned] if pinned else implementers
    rows = (
        (
            await db.execute(
                select(Connector)
                .where(Connector.tenant_id == tenant_id)
                .where(Connector.connector_type.in_(wanted))
                .where(Connector.is_enabled.is_(True))
                .order_by(Connector.connector_type, Connector.name)
            )
        )
        .scalars()
        .all()
    )
    for connector in rows:
        if pinned and connector.connector_type != pinned:
            continue
        if connector.connector_type not in implementers:
            # The pin named a connector the tenant has and no executor can
            # drive. Not a match, and not something to substitute around.
            continue
        allowed = connector.allowed_capabilities
        if allowed is not None and capability not in allowed:
            # Per-instance downscoping is a tenant saying "not this verb on
            # this integration". A playbook does not outrank it.
            logger.info(
                "playbook_step.capability_downscoped",
                vendor_id=connector.connector_type,
                capability=capability,
            )
            continue
        return connector
    return None


def _operational_config(connector: Connector) -> dict[str, Any]:
    config = connector.connector_config or {}
    return {key: config[key] for key in _OPERATIONAL_KEYS if config.get(key) is not None}


def _interpret(capability: str, vendor_id: str, body: dict[str, Any], *, dry_run: bool) -> StepDispatchReport:
    """Translate a live-action response into an honest step outcome.

    The live-action layer already distinguishes the states that matter, and
    this function's only job is to not collapse them. In particular
    ``AWAITING_COMPLETION`` — the vendor was touched and the outcome is not
    known yet — counts as ``executed``, while ``PENDING_APPROVAL`` — nothing
    ran, a human is needed — does not. Reporting the first as pending would
    lose an action that is genuinely in flight; reporting the second as
    executed would be the fake success this replaces.
    """
    # Fetched once and then tested, rather than `x.get(k) if
    # isinstance(x.get(k), dict) else {}`: that form calls `get` twice, so
    # the value the guard inspects is not the value that gets used. It
    # happens to be safe for a plain dict and it is not a property anything
    # enforces, which is why the fourteen `union-attr` findings under it
    # were real reports about a guard that does not guard.
    raw_result = body.get("result")
    result: dict[str, Any] = raw_result if isinstance(raw_result, dict) else {}
    raw_details = result.get("details")
    details: dict[str, Any] = raw_details if isinstance(raw_details, dict) else {}
    status = str(result.get("status") or "")
    summary = str(result.get("summary") or "")

    common = {
        "capability": capability,
        "vendor_id": vendor_id,
        "autonomy_mode": str(details.get("autonomy_mode") or ""),
        "blast_radius": str(details.get("blast_radius") or ""),
    }

    if status == "failed":
        return StepDispatchReport(
            **common,
            status="failed",
            executed=False,
            summary=summary or f"'{capability}' failed on {vendor_id}.",
            detail=str(result.get("error") or "")[:2000],
            verification=str(details.get("verification") or ""),
            verification_reason=str(details.get("verification_reason") or ""),
        )

    if status == "blocked":
        return StepDispatchReport(
            **common,
            status="blocked",
            executed=False,
            summary=summary or f"'{capability}' was blocked by policy.",
            detail=str(details.get("reason") or ""),
        )

    if status == "pending_approval":
        return StepDispatchReport(
            **common,
            status="pending_approval",
            executed=False,
            summary=summary or f"'{capability}' needs an analyst before it runs.",
            detail=str(details.get("reason") or ""),
        )

    if dry_run:
        # Checked before `simulated` because a dry run *is* how the builtin
        # adapters preview: they strip the credentials and the executor takes
        # its simulation branch, so every dry run comes back SIMULATED. Saying
        # "simulated" here would suggest the credentials were missing, which
        # is a different and much more alarming fact. Never an execution,
        # whatever status came back.
        return StepDispatchReport(
            **common,
            status="dry_run",
            executed=False,
            summary=f"DRY RUN — '{capability}' was previewed against {vendor_id} and nothing was changed.",
            detail=summary,
        )

    if status == "simulated":
        return StepDispatchReport(
            **common,
            status="simulated",
            executed=False,
            summary=summary or f"'{capability}' ran in simulation — no vendor was touched.",
            detail="The executor found no usable credentials and took its safe path.",
        )

    if status == "awaiting_completion":
        return StepDispatchReport(
            **common,
            status="awaiting_completion",
            executed=True,
            summary=summary or f"'{capability}' was accepted by {vendor_id}; the outcome is not known yet.",
            verification=str(details.get("verification") or ""),
            verification_reason=str(details.get("verification_reason") or ""),
        )

    if status == "succeeded":
        return StepDispatchReport(
            **common,
            status="executed",
            executed=True,
            summary=summary or f"'{capability}' executed on {vendor_id}.",
            verification=str(details.get("verification") or "unverified"),
            verification_reason=str(details.get("verification_reason") or "no probe ran for this action"),
        )

    # An unrecognised status is not a success. The live-action layer owns this
    # vocabulary, so a new member arriving here means this function is behind
    # — and guessing "it probably worked" is how the collapse being fixed got
    # in originally.
    logger.warning("playbook_step.unrecognised_status", status=status, capability=capability)
    return StepDispatchReport(
        **common,
        status="failed",
        executed=False,
        summary=f"'{capability}' returned an unrecognised status {status!r}; treated as not executed.",
    )
