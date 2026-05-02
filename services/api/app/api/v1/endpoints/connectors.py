"""Connector management endpoints."""
import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import and_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import AuthUser, DBSession, require_permission
from app.models.connector import Connector

router = APIRouter(prefix="/connectors", tags=["connectors"])


class ConnectorResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    name: str
    connector_type: str
    category: str
    is_enabled: bool
    health_status: str
    last_health_check: datetime | None
    last_sync: datetime | None
    events_ingested: int
    error_count: int
    tags: list
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class CreateConnectorRequest(BaseModel):
    name: str
    connector_type: str
    category: str
    auth_config: dict = {}
    connector_config: dict = {}
    tags: list[str] = []


class UpdateConnectorRequest(BaseModel):
    name: str | None = None
    is_enabled: bool | None = None
    auth_config: dict | None = None
    connector_config: dict | None = None
    tags: list[str] | None = None


@router.get("", response_model=list[ConnectorResponse])
async def list_connectors(
    current_user: Annotated[AuthUser, Depends(require_permission("connectors:read"))],
    db: DBSession,
) -> list[ConnectorResponse]:
    """List all connectors for the tenant."""
    result = await db.execute(
        select(Connector).where(Connector.tenant_id == current_user.tenant_id).order_by(Connector.created_at)
    )
    connectors = result.scalars().all()
    return [ConnectorResponse.model_validate(c) for c in connectors]


@router.post("", response_model=ConnectorResponse, status_code=status.HTTP_201_CREATED)
async def create_connector(
    request: CreateConnectorRequest,
    current_user: Annotated[AuthUser, Depends(require_permission("connectors:write"))],
    db: DBSession,
) -> ConnectorResponse:
    """Create a new connector."""
    connector = Connector(
        tenant_id=current_user.tenant_id,
        name=request.name,
        connector_type=request.connector_type,
        category=request.category,
        auth_config=request.auth_config,
        connector_config=request.connector_config,
        tags=request.tags,
    )
    db.add(connector)
    await db.commit()
    await db.refresh(connector)
    return ConnectorResponse.model_validate(connector)


@router.get("/{connector_id}", response_model=ConnectorResponse)
async def get_connector(
    connector_id: uuid.UUID,
    current_user: Annotated[AuthUser, Depends(require_permission("connectors:read"))],
    db: DBSession,
) -> ConnectorResponse:
    """Get a connector by ID."""
    result = await db.execute(
        select(Connector).where(
            Connector.id == connector_id,
            Connector.tenant_id == current_user.tenant_id,
        )
    )
    connector = result.scalar_one_or_none()
    if connector is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Connector not found")
    return ConnectorResponse.model_validate(connector)


@router.patch("/{connector_id}", response_model=ConnectorResponse)
async def update_connector(
    connector_id: uuid.UUID,
    request: UpdateConnectorRequest,
    current_user: Annotated[AuthUser, Depends(require_permission("connectors:write"))],
    db: DBSession,
) -> ConnectorResponse:
    """Update a connector's configuration or state."""
    result = await db.execute(
        select(Connector).where(
            Connector.id == connector_id, Connector.tenant_id == current_user.tenant_id
        )
    )
    connector = result.scalar_one_or_none()
    if connector is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Connector not found")

    updates: dict = {}
    for field in ["name", "is_enabled", "auth_config", "connector_config", "tags"]:
        val = getattr(request, field, None)
        if val is not None:
            updates[field] = val

    if updates:
        updates["updated_at"] = datetime.now(UTC)
        await db.execute(update(Connector).where(Connector.id == connector_id).values(**updates))
        await db.commit()
        await db.refresh(connector)

    return ConnectorResponse.model_validate(connector)


@router.delete("/{connector_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_connector(
    connector_id: uuid.UUID,
    current_user: Annotated[AuthUser, Depends(require_permission("connectors:delete"))],
    db: DBSession,
) -> None:
    """Delete a connector."""
    result = await db.execute(
        select(Connector).where(
            Connector.id == connector_id, Connector.tenant_id == current_user.tenant_id
        )
    )
    connector = result.scalar_one_or_none()
    if connector is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Connector not found")
    await db.delete(connector)
    await db.commit()


@router.post("/{connector_id}/test", status_code=status.HTTP_200_OK)
async def test_connector(
    connector_id: uuid.UUID,
    current_user: Annotated[AuthUser, Depends(require_permission("connectors:write"))],
    db: DBSession,
) -> dict:
    """Test connectivity for a connector (stub - to be implemented per connector type)."""
    result = await db.execute(
        select(Connector).where(
            Connector.id == connector_id, Connector.tenant_id == current_user.tenant_id
        )
    )
    connector = result.scalar_one_or_none()
    if connector is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Connector not found")

    # Update health check timestamp
    await db.execute(
        update(Connector).where(Connector.id == connector_id).values(
            last_health_check=datetime.now(UTC),
            health_status="healthy",
        )
    )
    await db.commit()

    return {"status": "ok", "message": f"Connector {connector.name} test initiated"}
