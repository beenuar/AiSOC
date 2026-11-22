"""SIEM content: inventory, health and the governed tuning arm (WS1.2–1.6).

Read-only inventory over migration 180, health with denominators, and a
tuning-proposal arm that lands on the SAME governed detection-proposal
path native rules use — author is not approver there, and dispatch to the
vendor rides the fixed per-vendor ``sync_detection_rule`` verb with its
content read-back verification (WS1.1). Nothing here writes to a SIEM.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy import text as sa_text

from app.api.v1.deps import AuthUser, DBSession, require_permission
from app.models.connector import Connector
from app.services import siem_content as svc

router = APIRouter(prefix="/siem-content", tags=["siem-content"])


@router.get("/inventory", summary="What detection content the tenant's SIEM runs")
async def get_inventory(db: DBSession, user: AuthUser, limit: int = 500) -> dict[str, Any]:
    rows = (
        await db.execute(
            sa_text(
                """
                SELECT connector_type, vendor_rule_id, name, kind, enabled, severity,
                       attack, content_sha256, previous_hash, version, first_seen, last_seen
                FROM siem_content_rules WHERE tenant_id = :t
                ORDER BY connector_type, name LIMIT :limit
                """
            ),
            {"t": str(user.tenant_id), "limit": min(limit, 2000)},
        )
    ).fetchall()
    return {
        "rules": [
            {
                "connector_type": r[0],
                "vendor_rule_id": r[1],
                "name": r[2],
                "kind": r[3],
                "enabled": r[4],
                "severity": r[5],
                "attack": r[6] if isinstance(r[6], list) else json.loads(r[6] or "[]"),
                "content_sha256": r[7],
                "previous_hash": r[8],
                "version": r[9],
                "first_seen": r[10].isoformat() if r[10] else None,
                "last_seen": r[11].isoformat() if r[11] else None,
            }
            for r in rows
        ],
        "sources_supported": list(svc.CONTENT_SOURCES),
        "note": (
            "read-only inventory, content-hashed per rule; Sentinel and QRadar legs plug "
            "into the same /content seam and are recorded follow-ups"
        ),
    }


@router.get("/health", summary="Per SIEM rule: outcomes with denominators, or 'not measured'")
async def get_health(db: DBSession, user: AuthUser, limit: int = 200) -> dict[str, Any]:
    rules = await svc.rule_health(db, tenant_id=user.tenant_id, limit=min(limit, 500))
    return {
        "rules": rules,
        "discipline": (
            "every rate carries its denominator; zero disposed alerts reads 'not measured', "
            "never 0.0, and a vendor state the listing did not expose says could_not_check"
        ),
    }


@router.post("/refresh", summary="Refresh the inventory from the tenant's SIEMs now")
async def refresh_inventory(
    db: DBSession,
    user: Annotated[AuthUser, Depends(require_permission("rules:write"))],
) -> dict[str, Any]:
    result = await db.execute(
        select(Connector).where(
            Connector.tenant_id == user.tenant_id,
            Connector.enabled.is_(True),
            Connector.connector_type.in_(svc.CONTENT_SOURCES),
        )
    )
    connectors = list(result.scalars().all())
    if not connectors:
        return {
            "tenant_id": str(user.tenant_id),
            "sources": [],
            "note": (
                f"no enabled content-capable SIEM connector ({', '.join(svc.CONTENT_SOURCES)}); "
                "connect one under Integrations and refresh again"
            ),
        }
    report = await svc.sweep_tenant(db, tenant_id=user.tenant_id, connectors=connectors)
    await db.commit()
    return report


class TuningProposalBody(BaseModel):
    """A change to a SIEM rule, proposed — never applied from here."""

    connector_type: str = Field(..., pattern="^(splunk|elastic|sentinel|qradar)$")
    vendor_rule_id: str = Field(..., min_length=1, max_length=500)
    change: str = Field(..., pattern="^(exclusion|threshold|severity|disable|new_rule)$")
    rationale: str = Field(..., min_length=10, max_length=4000)
    proposed_content: str = Field("", max_length=20000)


@router.post(
    "/tuning-proposals",
    status_code=201,
    summary="Propose a change to a SIEM rule, on the governed proposal path",
)
async def create_tuning_proposal(
    body: TuningProposalBody,
    db: DBSession,
    user: Annotated[AuthUser, Depends(require_permission("rules:write"))],
) -> dict[str, str]:
    """WS1.6 — the tuning loop's intake. The proposal lands as a DRAFT on
    the same ``detection_rule_proposals`` path native rules use: the
    reviewer there cannot be its author (that path's own separation rule),
    and APPLYING an approved change to the vendor rides the fixed
    per-vendor ``sync_detection_rule`` capability, whose write is verified
    by content read-back (WS1.1) and rolled back from the prior content its
    rollback_data carries. Backtesting over history through federated
    search is the recorded follow-up on this arm."""
    row = (
        await db.execute(
            sa_text("SELECT name, raw FROM siem_content_rules WHERE tenant_id = :t AND connector_type = :c AND vendor_rule_id = :r"),
            {"t": str(user.tenant_id), "c": body.connector_type, "r": body.vendor_rule_id},
        )
    ).fetchone()
    if row is None and body.change != "new_rule":
        raise HTTPException(
            status_code=404,
            detail=(
                "that vendor rule is not in the inventory; refresh the inventory first so the proposal cites content that actually exists"
            ),
        )
    target_name = row[0] if row else body.vendor_rule_id
    scaffold = "\n".join(
        [
            f"# SIEM tuning proposal ({body.change}) for {body.connector_type} rule {body.vendor_rule_id!r}.",
            f"# Target: {target_name}",
            f"# Rationale: {body.rationale}",
            "# Apply path: the governed sync_detection_rule verb (content read-back verified,",
            "#   rollback from prior content). Nothing applies without review; the reviewer",
            "#   cannot be this proposal's author.",
            "",
            body.proposed_content or "# (no proposed content supplied — the reviewer drafts it)",
        ]
    )
    proposal_id = uuid.uuid4()
    await db.execute(
        sa_text(
            """
            INSERT INTO detection_rule_proposals
              (id, tenant_id, base_rule_id, name, description,
               rule_language, rule_body, category, severity, confidence,
               status, source, created_at, updated_at)
            VALUES
              (:id, :tid, NULL, :name, :desc,
               :lang, :body, 'siem-tuning', 'medium', 60,
               'draft', 'siem-tuning', :now, :now)
            """
        ).bindparams(
            id=proposal_id,
            tid=user.tenant_id,
            name=f"tune({body.change}): {target_name}"[:200],
            desc=body.rationale[:2000],
            lang={"splunk": "spl", "elastic": "eql", "sentinel": "kql", "qradar": "aql"}[body.connector_type],
            body=scaffold,
            now=datetime.now(UTC),
        )
    )
    await db.commit()
    return {"id": str(proposal_id), "status": "draft", "source": "siem-tuning"}
