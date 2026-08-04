"""Customizable dashboard / report builder endpoints (Wave 7, W7.1)."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from app.api.v1.deps import AuthUser, DBSession, require_permission
from app.models.alert import Alert
from app.services.report_builder import (
    ReportError,
    parse_definition,
    render_report,
)

router = APIRouter(prefix="/report-builder", tags=["report_builder"])


class ReportDefinitionBody(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    widgets: list[dict[str, Any]] = Field(default_factory=list)


@router.post("/validate")
async def validate_report(
    body: ReportDefinitionBody,
    current_user: Annotated[AuthUser, Depends(require_permission("settings:read"))],
) -> dict[str, Any]:
    """Validate a report definition (whitelisted widget types + sources, unique
    ids, bounded size) without rendering or persisting it."""
    try:
        definition = parse_definition(body.model_dump())
    except ReportError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    return {"ok": True, "name": definition.name, "widget_count": len(definition.widgets)}


@router.post("/render")
async def render(
    body: ReportDefinitionBody,
    current_user: Annotated[AuthUser, Depends(require_permission("settings:read"))],
    db: DBSession,
) -> dict[str, Any]:
    """Render a report by resolving each widget's data server-side. Wires the
    real ``alerts_by_severity`` resolver (tenant-scoped) + ``static``; other
    sources render an honest ``error`` until their resolver is wired."""
    try:
        definition = parse_definition(body.model_dump())
    except ReportError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    async def _alerts_by_severity() -> dict[str, int]:
        rows = (
            await db.execute(select(Alert.severity, func.count()).where(Alert.tenant_id == current_user.tenant_id).group_by(Alert.severity))
        ).all()
        return {str(sev): int(count) for sev, count in rows}

    severity_counts = await _alerts_by_severity()
    resolvers = {"alerts_by_severity": lambda params: severity_counts}
    return render_report(definition, resolvers)
