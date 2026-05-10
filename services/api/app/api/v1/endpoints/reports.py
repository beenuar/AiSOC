"""Auto-generated board / executive report endpoints.

Author: Beenu <beenu@cyble.com>
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.endpoints.auth import get_current_user
from app.db.database import get_db
from app.models.report import ReportArtefact, ReportTemplate
from app.models.tenant import User
from app.services.digest_html import render_digest_html
from app.services.digest_pdf import WeasyPrintUnavailableError, render_digest_pdf
from app.services.executive_digest import ExecutiveDigest, build_weekly_digest

router = APIRouter(prefix="/reports", tags=["reports"])


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class TemplateCreate(BaseModel):
    name: str
    report_type: str
    cron_schedule: str | None = None
    timezone: str = "UTC"
    sections: list[dict[str, Any]] = Field(default_factory=list)
    recipients: list[str] | None = None
    output_format: str = "pdf"


class TemplateOut(TemplateCreate):
    id: uuid.UUID
    tenant_id: uuid.UUID
    is_enabled: bool
    last_run_at: str | None = None
    created_at: str
    updated_at: str

    class Config:
        from_attributes = True


class ArtefactOut(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    template_id: uuid.UUID | None
    report_type: str
    title: str
    period_start: str
    period_end: str
    output_format: str
    file_size_bytes: int | None
    delivered_to: list[str] | None
    delivered_at: str | None
    generated_by: str
    status: str
    error_message: str | None
    created_at: str

    class Config:
        from_attributes = True


class GenerateRequest(BaseModel):
    title: str
    report_type: str = "board_summary"
    period_start: datetime
    period_end: datetime
    output_format: str = "pdf"
    recipients: list[str] | None = None


# ---------------------------------------------------------------------------
# Template endpoints
# ---------------------------------------------------------------------------


@router.get("/templates", response_model=list[TemplateOut])
async def list_templates(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[ReportTemplate]:
    result = await db.execute(
        select(ReportTemplate).where(ReportTemplate.tenant_id == current_user.tenant_id).order_by(ReportTemplate.name)
    )
    return list(result.scalars().all())


@router.post("/templates", response_model=TemplateOut, status_code=status.HTTP_201_CREATED)
async def create_template(
    body: TemplateCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ReportTemplate:
    template = ReportTemplate(
        **body.model_dump(),
        tenant_id=current_user.tenant_id,
        created_by=current_user.id,
    )
    db.add(template)
    await db.commit()
    await db.refresh(template)
    return template


@router.get("/templates/{template_id}", response_model=TemplateOut)
async def get_template(
    template_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ReportTemplate:
    tmpl = await db.get(ReportTemplate, template_id)
    if not tmpl or tmpl.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="Template not found")
    return tmpl


@router.delete("/templates/{template_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def delete_template(
    template_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> None:
    tmpl = await db.get(ReportTemplate, template_id)
    if not tmpl or tmpl.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="Template not found")
    await db.delete(tmpl)
    await db.commit()


# ---------------------------------------------------------------------------
# Artefact endpoints
# ---------------------------------------------------------------------------


@router.get("/artefacts", response_model=list[ArtefactOut])
async def list_artefacts(
    report_type: str | None = Query(None),
    status_filter: str | None = Query(None, alias="status"),
    limit: int = Query(20, le=100),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[ReportArtefact]:
    q = select(ReportArtefact).where(ReportArtefact.tenant_id == current_user.tenant_id)
    if report_type:
        q = q.where(ReportArtefact.report_type == report_type)
    if status_filter:
        q = q.where(ReportArtefact.status == status_filter)
    q = q.order_by(ReportArtefact.created_at.desc()).offset(offset).limit(limit)
    result = await db.execute(q)
    return list(result.scalars().all())


@router.post("/generate", response_model=ArtefactOut, status_code=status.HTTP_202_ACCEPTED)
async def generate_report(
    body: GenerateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ReportArtefact:
    """Enqueue a report generation job. Returns the artefact record immediately with status='pending'."""
    artefact = ReportArtefact(
        tenant_id=current_user.tenant_id,
        report_type=body.report_type,
        title=body.title,
        period_start=body.period_start,
        period_end=body.period_end,
        output_format=body.output_format,
        delivered_to=body.recipients,
        status="pending",
        generated_by=str(current_user.id),
    )
    db.add(artefact)
    await db.commit()
    await db.refresh(artefact)
    return artefact


@router.get("/artefacts/{artefact_id}", response_model=ArtefactOut)
async def get_artefact(
    artefact_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ReportArtefact:
    art = await db.get(ReportArtefact, artefact_id)
    if not art or art.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="Artefact not found")
    return art


# ---------------------------------------------------------------------------
# Executive weekly digest (WS-G2)
# ---------------------------------------------------------------------------


@router.get(
    "/digest/weekly",
    summary="Executive weekly digest (JSON, print-ready HTML, or PDF)",
    # The endpoint returns ExecutiveDigest (JSON), HTMLResponse, or a raw PDF
    # Response depending on the ?format= query param.  FastAPI cannot synthesise
    # a response_model from that union so we opt out and let each branch
    # serialise itself.
    response_model=None,
)
async def weekly_digest(
    fmt: str = Query("json", alias="format", pattern="^(json|html|pdf)$"),
    period_start: datetime | None = Query(None, description="ISO timestamp; defaults to now-7d"),
    period_end: datetime | None = Query(None, description="ISO timestamp; defaults to now"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ExecutiveDigest | HTMLResponse | Response:
    """Build a deterministic weekly digest for the caller's tenant.

    Supported formats (``?format=``):

    * ``json``  — Pydantic model serialised as JSON *(default)*
    * ``html``  — Self-contained print-ready HTML page
    * ``pdf``   — Server-side PDF generated via WeasyPrint (requires the
                  WeasyPrint native library stack; returns 503 when unavailable)
    """
    if period_start and period_end and period_start >= period_end:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="period_start must be earlier than period_end",
        )

    digest = await build_weekly_digest(
        db,
        current_user.tenant_id,
        period_start=period_start,
        period_end=period_end,
    )

    if fmt == "html":
        return HTMLResponse(content=render_digest_html(digest))

    if fmt == "pdf":
        try:
            pdf_bytes = render_digest_pdf(digest)
        except WeasyPrintUnavailableError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=str(exc),
            ) from exc
        filename = f"aisoc-digest-{digest.period.start.date()}.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    return digest
