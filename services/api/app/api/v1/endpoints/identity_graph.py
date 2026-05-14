"""Identity-centric correlation graph endpoints."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.endpoints.auth import get_current_user
from app.db.database import get_db
from app.models.identity_graph import AlertIdentityLink, IdentityEdge, IdentityNode
from app.models.tenant import User

router = APIRouter(prefix="/identity-graph", tags=["identity-graph"])


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class NodeCreate(BaseModel):
    node_type: str
    external_id: str
    display_name: str | None = None
    source_system: str
    risk_score: float = 0.0
    privilege_tier: int = 0
    last_activity: datetime | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)


class NodeOut(NodeCreate):
    id: uuid.UUID
    tenant_id: uuid.UUID
    is_active: bool
    created_at: str
    updated_at: str

    model_config = ConfigDict(from_attributes=True)


class EdgeCreate(BaseModel):
    source_id: uuid.UUID
    target_id: uuid.UUID
    edge_type: str
    weight: float = 1.0
    valid_until: datetime | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)


class EdgeOut(EdgeCreate):
    id: uuid.UUID
    tenant_id: uuid.UUID
    valid_from: str
    created_at: str

    model_config = ConfigDict(from_attributes=True)


class AlertLinkCreate(BaseModel):
    alert_id: uuid.UUID
    node_id: uuid.UUID
    link_reason: str
    confidence: float = 1.0


class AlertLinkOut(AlertLinkCreate):
    id: uuid.UUID
    tenant_id: uuid.UUID
    created_at: str

    model_config = ConfigDict(from_attributes=True)


# ---------------------------------------------------------------------------
# Node endpoints
# ---------------------------------------------------------------------------


@router.get("/nodes", response_model=list[NodeOut])
async def list_nodes(
    node_type: str | None = Query(None),
    source_system: str | None = Query(None),
    min_risk: float | None = Query(None),
    limit: int = Query(50, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[IdentityNode]:
    q = select(IdentityNode).where(IdentityNode.tenant_id == current_user.tenant_id)
    if node_type:
        q = q.where(IdentityNode.node_type == node_type)
    if source_system:
        q = q.where(IdentityNode.source_system == source_system)
    if min_risk is not None:
        q = q.where(IdentityNode.risk_score >= min_risk)
    q = q.order_by(IdentityNode.risk_score.desc()).offset(offset).limit(limit)
    result = await db.execute(q)
    return list(result.scalars().all())


@router.post("/nodes", response_model=NodeOut, status_code=status.HTTP_201_CREATED)
async def create_node(
    body: NodeCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> IdentityNode:
    node = IdentityNode(**body.model_dump(), tenant_id=current_user.tenant_id)
    db.add(node)
    await db.commit()
    await db.refresh(node)
    return node


@router.get("/nodes/{node_id}", response_model=NodeOut)
async def get_node(
    node_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> IdentityNode:
    node = await db.get(IdentityNode, node_id)
    if not node or node.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="Node not found")
    return node


@router.get("/nodes/{node_id}/edges", response_model=list[EdgeOut])
async def get_node_edges(
    node_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[IdentityEdge]:
    node = await db.get(IdentityNode, node_id)
    if not node or node.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="Node not found")
    result = await db.execute(
        select(IdentityEdge).where(
            IdentityEdge.tenant_id == current_user.tenant_id,
            (IdentityEdge.source_id == node_id) | (IdentityEdge.target_id == node_id),
        )
    )
    return list(result.scalars().all())


# ---------------------------------------------------------------------------
# Edge endpoints
# ---------------------------------------------------------------------------


@router.get("/edges", response_model=list[EdgeOut])
async def list_edges(
    edge_type: str | None = Query(None),
    limit: int = Query(100, le=1000),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[IdentityEdge]:
    q = select(IdentityEdge).where(IdentityEdge.tenant_id == current_user.tenant_id)
    if edge_type:
        q = q.where(IdentityEdge.edge_type == edge_type)
    q = q.order_by(IdentityEdge.created_at.desc()).offset(offset).limit(limit)
    result = await db.execute(q)
    return list(result.scalars().all())


@router.post("/edges", response_model=EdgeOut, status_code=status.HTTP_201_CREATED)
async def create_edge(
    body: EdgeCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> IdentityEdge:
    edge = IdentityEdge(**body.model_dump(), tenant_id=current_user.tenant_id)
    db.add(edge)
    await db.commit()
    await db.refresh(edge)
    return edge


# ---------------------------------------------------------------------------
# Alert-identity links
# ---------------------------------------------------------------------------


@router.post("/alert-links", response_model=AlertLinkOut, status_code=status.HTTP_201_CREATED)
async def link_alert_to_identity(
    body: AlertLinkCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AlertIdentityLink:
    link = AlertIdentityLink(**body.model_dump(), tenant_id=current_user.tenant_id)
    db.add(link)
    await db.commit()
    await db.refresh(link)
    return link


@router.get("/alert-links/{alert_id}", response_model=list[AlertLinkOut])
async def get_alert_identity_links(
    alert_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[AlertIdentityLink]:
    result = await db.execute(
        select(AlertIdentityLink).where(
            AlertIdentityLink.tenant_id == current_user.tenant_id,
            AlertIdentityLink.alert_id == alert_id,
        )
    )
    return list(result.scalars().all())
