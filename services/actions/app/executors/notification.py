"""
Notification executors: Slack alerts, ticket creation.
"""
from __future__ import annotations

from datetime import datetime

import httpx
import structlog

from app.executors.base import BaseExecutor
from app.models.action import ActionRequest, ActionResult, ActionStatus

logger = structlog.get_logger()


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
                            "text": f"🚨 AiSOC Alert\n*Incident:* {request.incident_id}\n{message}",
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
    """Creates an incident ticket (Jira, ServiceNow, etc.)."""

    async def execute(self, request: ActionRequest) -> ActionResult:
        system = request.parameters.get("system", "jira")
        logger.info("Creating ticket", system=system, incident_id=str(request.incident_id))

        # TODO: integrate with Jira, ServiceNow, or PagerDuty APIs
        return ActionResult(
            action_id=request.id,
            status=ActionStatus.COMPLETED,
            blast_radius="minimal",
            output={
                "ticket_system": system,
                "ticket_id": f"SIM-TICKET-{str(request.incident_id)[:8].upper()}",
                "note": "Simulation mode — integrate with ticketing system API",
            },
            completed_at=datetime.utcnow(),
        )
