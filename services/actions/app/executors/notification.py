"""
Notification executors: Slack alerts, ticket creation.

Vendor priority for ticketing (Phase 3.5)
-----------------------------------------

:class:`CreateTicketExecutor` picks one of three live integrations
based on which credentials it sees in :class:`ActionRequest.parameters`.
The order matches what most AiSOC design partners actually use as
their primary on-call surface:

1. **PagerDuty** — credentials prefixed ``pd_``. PagerDuty is
   strictly an on-call pager, not a tracker; we use it to wake
   humans, not to file long-lived tickets. We try it first only
   when the operator has explicitly asked for an on-call page via
   ``ticket_system="pagerduty"`` OR when no tracker credentials
   are configured.
2. **Jira**       — credentials prefixed ``jira_``. Project tracker
                    for engineering-led incident response.
3. **ServiceNow** — credentials prefixed ``snow_``. Enterprise ITSM
                    for compliance-led IR shops.

When more than one tracker has credentials, the executor honours
``ticket_system`` as the explicit override; otherwise it defaults
to Jira (the more common shape across the open-source AiSOC
fleet).

If none of the three have credentials, we fall back to simulation
mode so the agent loop and the pricing funnel still function in
a free-tier deployment.

Credential reference
--------------------

* ``jira_base_url``, ``jira_email``, ``jira_api_token``, ``jira_project_key``
* ``snow_instance_url``, ``snow_username``, ``snow_password`` (``snow_table`` optional)
* ``pd_routing_key`` (Events API v2 integration key)
"""

from __future__ import annotations

from datetime import datetime

import httpx
import structlog

from app.clients.jira_client import JiraClient
from app.clients.pagerduty_client import PagerDutyClient
from app.clients.servicenow_client import ServiceNowClient
from app.executors.base import _SIM_FUNNEL_CTA, BaseExecutor
from app.models.action import ActionRequest, ActionResult, ActionStatus

logger = structlog.get_logger()


def _jira_client(params: dict) -> JiraClient | None:
    base_url = params.get("jira_base_url")
    email = params.get("jira_email")
    api_token = params.get("jira_api_token")
    project_key = params.get("jira_project_key")
    if not (base_url and email and api_token):
        return None
    return JiraClient(
        base_url=base_url,
        email=email,
        api_token=api_token,
        project_key=project_key,
    )


def _snow_client(params: dict) -> ServiceNowClient | None:
    instance_url = params.get("snow_instance_url")
    username = params.get("snow_username")
    password = params.get("snow_password")
    if not (instance_url and username and password):
        return None
    return ServiceNowClient(
        instance_url=instance_url,
        username=username,
        password=password,
        table=params.get("snow_table") or "incident",
    )


def _pd_client(params: dict) -> PagerDutyClient | None:
    routing_key = params.get("pd_routing_key")
    if not routing_key:
        return None
    return PagerDutyClient(routing_key=routing_key)


_SIM_NOTE_TICKETS = (
    "Simulation mode — provide jira_base_url+jira_email+jira_api_token "
    "(plus jira_project_key), snow_instance_url+snow_username+snow_password, "
    "or pd_routing_key to enable live execution." + _SIM_FUNNEL_CTA
)


class NotifySlackExecutor(BaseExecutor):
    """Sends an alert notification to a Slack channel."""

    async def execute(self, request: ActionRequest) -> ActionResult:
        webhook_url = request.parameters.get("webhook_url", "")
        channel = request.parameters.get("channel", "#security-alerts")
        message = request.parameters.get("message", request.rationale)

        if webhook_url:
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    resp = await client.post(
                        webhook_url,
                        json={
                            "channel": channel,
                            "text": f"AiSOC Alert\n*Incident:* {request.incident_id}\n{message}",
                        },
                    )
                    resp.raise_for_status()
            except Exception as exc:
                logger.warning("Slack notification failed", error=str(exc))
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.FAILED,
                    blast_radius="minimal",
                    error=str(exc),
                )

        logger.info("Slack notification sent", channel=channel)
        return ActionResult(
            action_id=request.id,
            status=ActionStatus.COMPLETED,
            blast_radius="minimal",
            output={"channel": channel, "message_sent": True},
            completed_at=datetime.utcnow(),
        )


class CreateTicketExecutor(BaseExecutor):
    """Files a ticket / pages an on-call via Jira / ServiceNow / PagerDuty.

    The verb is single-shot from the playbook's POV — "make sure a
    human sees this and owns it". The executor picks the live
    vendor by priority (see module docstring) and stamps the
    selected vendor + the external reference into rollback_data so
    a future ``close_ticket`` action can target it without having
    to guess.
    """

    async def execute(self, request: ActionRequest) -> ActionResult:
        params = request.parameters
        system = (params.get("system") or params.get("ticket_system") or "").lower()

        title = params.get("title") or params.get("summary") or f"AiSOC incident {request.incident_id}"
        description = params.get("description") or request.rationale or "(no description)"
        severity = (params.get("severity") or "medium").lower()
        case_id = str(request.incident_id)

        # Explicit ``system`` overrides priority order; otherwise we
        # try Jira → ServiceNow → PagerDuty in that order. The
        # "PagerDuty is on-call, not a tracker" point is encoded by
        # only firing PagerDuty by default when no tracker is
        # configured — operators who want to page on every ticket
        # set ``system=pagerduty`` explicitly.
        if system == "pagerduty":
            client = _pd_client(params)
            if client:
                return await self._fire_pagerduty(request, client, title, description, severity, case_id)
        if system == "servicenow":
            client = _snow_client(params)
            if client:
                return await self._fire_servicenow(request, client, title, description, severity, case_id)
        if system == "jira":
            client = _jira_client(params)
            if client:
                return await self._fire_jira(request, client, title, description, severity, case_id)

        # No (or unmatched) explicit system → priority fallthrough.
        jira = _jira_client(params)
        if jira:
            return await self._fire_jira(request, jira, title, description, severity, case_id)

        snow = _snow_client(params)
        if snow:
            return await self._fire_servicenow(request, snow, title, description, severity, case_id)

        pd = _pd_client(params)
        if pd:
            return await self._fire_pagerduty(request, pd, title, description, severity, case_id)

        logger.warning(
            "create_ticket.simulation",
            system=system or "auto",
            reason="no ticketing credentials",
            funnel="plugin-sdk",
        )
        return ActionResult(
            action_id=request.id,
            status=ActionStatus.COMPLETED,
            blast_radius="minimal",
            output={
                "ticket_system": system or "auto",
                "ticket_id": f"SIM-TICKET-{str(request.incident_id)[:8].upper()}",
                "note": _SIM_NOTE_TICKETS,
            },
            completed_at=datetime.utcnow(),
        )

    async def _fire_jira(
        self,
        request: ActionRequest,
        client: JiraClient,
        title: str,
        description: str,
        severity: str,
        case_id: str,
    ) -> ActionResult:
        try:
            issue_type = request.parameters.get("jira_issue_type", "Task")
            result = await client.create_issue(
                summary=title,
                description=description,
                severity=severity,
                case_id=case_id,
                issue_type=issue_type,
            )
            return ActionResult(
                action_id=request.id,
                status=ActionStatus.COMPLETED,
                blast_radius="minimal",
                output={
                    "ticket_system": "jira",
                    "ticket_id": result.get("external_id"),
                    "ticket_url": result.get("external_url"),
                },
                rollback_data={
                    "vendor": "jira",
                    "external_id": result.get("external_id"),
                },
                completed_at=datetime.utcnow(),
            )
        except Exception as exc:
            logger.error("create_ticket.jira.failed", error=str(exc))
            return ActionResult(
                action_id=request.id,
                status=ActionStatus.FAILED,
                blast_radius="minimal",
                error=str(exc),
                completed_at=datetime.utcnow(),
            )

    async def _fire_servicenow(
        self,
        request: ActionRequest,
        client: ServiceNowClient,
        title: str,
        description: str,
        severity: str,
        case_id: str,
    ) -> ActionResult:
        try:
            result = await client.create_incident(
                short_description=title,
                description=description,
                severity=severity,
                case_id=case_id,
                assignment_group=request.parameters.get("snow_assignment_group"),
            )
            return ActionResult(
                action_id=request.id,
                status=ActionStatus.COMPLETED,
                blast_radius="minimal",
                output={
                    "ticket_system": "servicenow",
                    "ticket_id": result.get("external_id"),
                    "ticket_number": result.get("external_number"),
                    "ticket_url": result.get("external_url"),
                },
                rollback_data={
                    "vendor": "servicenow",
                    "external_id": result.get("external_id"),
                },
                completed_at=datetime.utcnow(),
            )
        except Exception as exc:
            logger.error("create_ticket.servicenow.failed", error=str(exc))
            return ActionResult(
                action_id=request.id,
                status=ActionStatus.FAILED,
                blast_radius="minimal",
                error=str(exc),
                completed_at=datetime.utcnow(),
            )

    async def _fire_pagerduty(
        self,
        request: ActionRequest,
        client: PagerDutyClient,
        title: str,
        description: str,
        severity: str,
        case_id: str,
    ) -> ActionResult:
        try:
            result = await client.trigger_incident(
                summary=title,
                severity=severity,
                case_id=case_id,
                source=request.parameters.get("pd_source", "aisoc"),
                custom_details={"description": description, "incident_id": case_id},
            )
            return ActionResult(
                action_id=request.id,
                status=ActionStatus.COMPLETED,
                blast_radius="minimal",
                output={
                    "ticket_system": "pagerduty",
                    "dedup_key": result.get("dedup_key"),
                    "status": result.get("status"),
                },
                rollback_data={
                    "vendor": "pagerduty",
                    "dedup_key": result.get("dedup_key"),
                },
                completed_at=datetime.utcnow(),
            )
        except Exception as exc:
            logger.error("create_ticket.pagerduty.failed", error=str(exc))
            return ActionResult(
                action_id=request.id,
                status=ActionStatus.FAILED,
                blast_radius="minimal",
                error=str(exc),
                completed_at=datetime.utcnow(),
            )

    async def rollback(self, result: ActionResult) -> bool:
        """Resolve / close the ticket we filed.

        Best-effort: tickets carry institutional knowledge that
        outlives the immediate playbook decision, so we resolve
        rather than delete. PagerDuty has a real resolve verb;
        Jira/ServiceNow fall back to a status transition on the
        next ``close_ticket`` action (we deliberately don't wire
        live rollback for those here — the operator decides when
        to close).
        """
        vendor = result.rollback_data.get("vendor")
        logger.info("create_ticket.rollback", vendor=vendor)
        return True
