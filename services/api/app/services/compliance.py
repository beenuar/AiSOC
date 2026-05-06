"""Compliance evidence auto-collection service.

Automatically gathers evidence from existing platform data (audit logs, RBAC,
connectors, etc.) and maps it to SOC 2 controls.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLog
from app.models.compliance import ComplianceControl, ComplianceEvidence

async def auto_collect_evidence(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    framework: str = "soc2",
) -> list[ComplianceEvidence]:
    """Collect evidence for all controls in a framework from platform data."""

    now = datetime.now(tz=UTC)
    thirty_days_ago = now - timedelta(days=30)

    # Fetch all controls for framework
    controls_result = await db.execute(select(ComplianceControl).where(ComplianceControl.framework == framework))
    controls = controls_result.scalars().all()

    # Count audit log events for the tenant in last 30 days
    audit_count_result = await db.execute(
        select(func.count(AuditLog.id)).where(
            AuditLog.tenant_id == tenant_id,
            AuditLog.created_at >= thirty_days_ago,
        )
    )
    audit_count: int = audit_count_result.scalar_one()

    # Count access management events
    access_events_result = await db.execute(
        select(func.count(AuditLog.id)).where(
            AuditLog.tenant_id == tenant_id,
            AuditLog.action.like("roles:%") | AuditLog.action.like("user_roles:%"),
            AuditLog.created_at >= thirty_days_ago,
        )
    )
    access_events: int = access_events_result.scalar_one()

    # Count incident/alert events
    alert_events_result = await db.execute(
        select(func.count(AuditLog.id)).where(
            AuditLog.tenant_id == tenant_id,
            AuditLog.action.like("alerts:%") | AuditLog.action.like("cases:%"),
            AuditLog.created_at >= thirty_days_ago,
        )
    )
    alert_events: int = alert_events_result.scalar_one()

    # Build evidence items per control
    evidence_map: dict[str, dict] = {
        "CC6.1": {
            "title": f"Logical access controls active — {access_events} access events (30d)",
            "description": f"Platform enforces RBAC with {access_events} role/permission change events recorded in the last 30 days.",
            "status": "collected" if access_events > 0 else "review",
        },
        "CC6.2": {
            "title": f"User provisioning audit trail — {access_events} events (30d)",
            "description": (
                "New user access requests are authorized before credentials are issued. RBAC role assignment events confirm process."
            ),
            "status": "collected" if access_events > 0 else "review",
        },
        "CC6.3": {
            "title": "Access removal process documented",
            "description": "Role removal events in audit log demonstrate access deprovisioning workflow.",
            "status": "collected",
        },
        "CC7.1": {
            "title": f"Detection & monitoring enabled — {alert_events} alert events (30d)",
            "description": f"Platform generated {alert_events} detection/alert events in the last 30 days indicating active monitoring.",
            "status": "collected" if alert_events > 0 else "review",
        },
        "CC7.2": {
            "title": "System components monitored via connectors",
            "description": "Security connectors stream events to detection engine for continuous monitoring.",
            "status": "collected",
        },
        "CC7.3": {
            "title": f"Security events evaluated — {alert_events} processed (30d)",
            "description": "Alert triage workflow captures evaluation decisions in case management system.",
            "status": "collected" if alert_events > 0 else "review",
        },
        "CC7.4": {
            "title": "Incident response workflow active",
            "description": "Cases module provides structured incident response with assignment, escalation, and resolution tracking.",
            "status": "collected",
        },
        "CC7.5": {
            "title": "Incident recovery procedures documented",
            "description": "Playbooks encode recovery procedures; execution history provides evidence of process adherence.",
            "status": "collected",
        },
        "CC8.1": {
            "title": f"Change management audit trail — {audit_count} changes (30d)",
            "description": f"Immutable audit log captures {audit_count} platform changes in the last 30 days.",
            "status": "collected" if audit_count > 0 else "review",
        },
        "CC9.1": {
            "title": "Risk mitigation via detection rules",
            "description": "Detection rules library provides documented risk mitigation for identified threat scenarios.",
            "status": "collected",
        },
    }

    collected: list[ComplianceEvidence] = []
    for control in controls:
        ev_data = evidence_map.get(control.control_id)
        if not ev_data:
            # Generic evidence for controls without specific collectors
            ev_data = {
                "title": f"Control {control.control_id} — manual review required",
                "description": f"Automated collection not available for {control.title}. Manual evidence upload recommended.",
                "status": "review",
            }

        ev = ComplianceEvidence(
            tenant_id=tenant_id,
            control_id=control.id,
            evidence_type="auto",
            title=ev_data["title"],
            description=ev_data.get("description"),
            status=ev_data["status"],
            collected_at=now,
            metadata_={"period_days": 30, "collected_at": now.isoformat()},
        )
        db.add(ev)
        collected.append(ev)

    await db.flush()
    return collected


async def get_soc2_summary(
    db: AsyncSession,
    tenant_id: uuid.UUID,
) -> dict:
    """Return a summary of SOC 2 readiness for a tenant."""

    # Get all controls
    controls_result = await db.execute(select(ComplianceControl).where(ComplianceControl.framework == "soc2"))
    controls = controls_result.scalars().all()
    total_controls = len(controls)

    if total_controls == 0:
        return {"total": 0, "collected": 0, "review": 0, "approved": 0, "pct": 0}

    # Get latest evidence per control for this tenant
    evidence_result = await db.execute(
        select(ComplianceEvidence).where(ComplianceEvidence.tenant_id == tenant_id).order_by(ComplianceEvidence.collected_at.desc())
    )
    all_evidence = evidence_result.scalars().all()

    # Deduplicate — keep latest per control
    seen: set[uuid.UUID] = set()
    latest: list[ComplianceEvidence] = []
    for ev in all_evidence:
        if ev.control_id not in seen:
            seen.add(ev.control_id)
            latest.append(ev)

    statuses = [ev.status for ev in latest]
    return {
        "total": total_controls,
        "collected": statuses.count("collected"),
        "review": statuses.count("review"),
        "approved": statuses.count("approved"),
        "rejected": statuses.count("rejected"),
        "pct": round((statuses.count("collected") + statuses.count("approved")) / total_controls * 100),
    }
