"""A hunt that found something, written up and exportable.

Depth plan 9.5.

* ``POST /hunt-reports/from-hunt/{saved_hunt_id}``        write one up
* ``POST /hunt-reports/from-retro-hunt/{sighting_id}``    write one up
* ``GET  /hunt-reports``                                  list this tenant's
* ``GET  /hunt-reports/{id}?format=json|html|pdf``        read or export

PDF goes through the same WeasyPrint path and the same unavailability error
as the weekly digest, deliberately. A second renderer would drift from the
first and the PDF would stop matching the page somebody approved; a second
error type would mean operators learning two messages for one missing
system library.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy import text

from app.api.v1.deps import AuthUser, require_permission
from app.db.rls import TenantDBSession
from app.services.audit import emit_audit
from app.services.digest_pdf import WeasyPrintUnavailableError
from app.services.hunt_report import (
    HuntReportError,
    attach_ledger_citations,
    build_from_hunt,
    build_from_retro_hunt,
    persist,
    render_html,
    render_pdf,
)

logger = structlog.get_logger()

router = APIRouter(prefix="/hunt-reports", tags=["hunt-reports"])


class BuildRequest(BaseModel):
    #: Attach to a case, which is also what pulls the agent's decisions into
    #: the citation list. Optional because a hunt can find something before
    #: anybody has decided it is a case — forcing the case first would mean
    #: opening one to find out whether you need it.
    case_id: uuid.UUID | None = None


class HuntReportOut(BaseModel):
    id: str
    source_kind: str
    source_id: str
    case_id: str | None
    title: str
    what: str
    how: str
    where: str
    when: str
    citations: list[dict[str, Any]] = Field(default_factory=list)
    match_count: int
    generated_by: str
    created_at: str


def _out(row: dict[str, Any]) -> HuntReportOut:
    return HuntReportOut(
        id=str(row["id"]),
        source_kind=row["source_kind"],
        source_id=str(row["source_id"]),
        case_id=str(row["case_id"]) if row.get("case_id") else None,
        title=row["title"],
        what=row["what"],
        how=row["how"],
        where=row["where"],
        when=row["when"],
        citations=list(row["citations"] or []),
        match_count=int(row["match_count"] or 0),
        generated_by=row["generated_by"],
        created_at=str(row["created_at"]),
    )


async def _build(
    db: Any,
    current_user: Any,
    request: Request,
    *,
    source_kind: str,
    source_id: uuid.UUID,
    case_id: uuid.UUID | None,
) -> HuntReportOut:
    builder = build_from_hunt if source_kind == "hunt" else build_from_retro_hunt
    kwarg = "saved_hunt_id" if source_kind == "hunt" else "sighting_id"
    try:
        report = await builder(db, tenant_id=current_user.tenant_id, **{kwarg: source_id})
        report = await attach_ledger_citations(db, report, tenant_id=current_user.tenant_id, case_id=case_id)
        row = await persist(
            db,
            report,
            tenant_id=current_user.tenant_id,
            source_kind=source_kind,
            source_id=source_id,
            case_id=case_id,
            generated_by=current_user.api_key_prefix or current_user.email,
        )
    except HuntReportError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    await emit_audit(
        db=db,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        actor_email=current_user.email,
        api_key_prefix=getattr(current_user, "api_key_prefix", None),
        action="hunt_report:create",
        resource="hunt_report",
        resource_id=str(row["id"]),
        changes={"source_kind": source_kind, "citations": len(row["citations"] or [])},
        request=request,
    )
    await db.commit()
    return _out(row)


@router.post("/from-hunt/{saved_hunt_id}", response_model=HuntReportOut, status_code=status.HTTP_201_CREATED)
async def from_hunt(
    saved_hunt_id: uuid.UUID,
    body: BuildRequest,
    request: Request,
    db: TenantDBSession,
    current_user: AuthUser,
    _: Annotated[None, Depends(require_permission("reports:write"))],
) -> HuntReportOut:
    return await _build(db, current_user, request, source_kind="hunt", source_id=saved_hunt_id, case_id=body.case_id)


@router.post("/from-retro-hunt/{sighting_id}", response_model=HuntReportOut, status_code=status.HTTP_201_CREATED)
async def from_retro_hunt(
    sighting_id: uuid.UUID,
    body: BuildRequest,
    request: Request,
    db: TenantDBSession,
    current_user: AuthUser,
    _: Annotated[None, Depends(require_permission("reports:write"))],
) -> HuntReportOut:
    return await _build(db, current_user, request, source_kind="retro_hunt", source_id=sighting_id, case_id=body.case_id)


@router.get("", response_model=list[HuntReportOut])
async def list_reports(
    db: TenantDBSession,
    current_user: AuthUser,
    _: Annotated[None, Depends(require_permission("reports:read"))],
    case_id: uuid.UUID | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
) -> list[HuntReportOut]:
    # A parameter, not a clause spliced into the statement. Both forms were
    # correct -- the only variable was one of two literals in this module --
    # and only this one stops reading as dynamic SQL to every scanner and
    # every reviewer that looks at it.
    rows = (
        (
            await db.execute(
                text(
                    "SELECT * FROM aisoc_hunt_reports "
                    "WHERE tenant_id = :tenant_id "
                    "  AND (CAST(:case_id AS uuid) IS NULL OR case_id = CAST(:case_id AS uuid)) "
                    "ORDER BY created_at DESC LIMIT :limit"
                ).bindparams(
                    tenant_id=current_user.tenant_id,
                    case_id=str(case_id) if case_id else None,
                    limit=limit,
                )
            )
        )
        .mappings()
        .all()
    )
    return [_out(dict(row)) for row in rows]


@router.get("/{report_id}", response_model=None)
async def get_report(
    report_id: uuid.UUID,
    db: TenantDBSession,
    current_user: AuthUser,
    _: Annotated[None, Depends(require_permission("reports:read"))],
    fmt: str = Query("json", alias="format", pattern="^(json|html|pdf)$"),
) -> HuntReportOut | HTMLResponse | Response:
    row = (
        (
            await db.execute(
                text("SELECT * FROM aisoc_hunt_reports WHERE id = :id AND tenant_id = :tenant_id").bindparams(
                    id=report_id, tenant_id=current_user.tenant_id
                )
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such hunt report")

    record = dict(row)
    record["created_at"] = str(record["created_at"])

    if fmt == "html":
        return HTMLResponse(content=render_html(record))
    if fmt == "pdf":
        try:
            pdf = render_pdf(record)
        except WeasyPrintUnavailableError as exc:
            # 503 with the reason, and the message names the two formats that
            # do work. A missing system library should not read as "the
            # report is gone".
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc
        return Response(
            content=pdf,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="aisoc-hunt-report-{report_id}.pdf"'},
        )
    return _out(record)
