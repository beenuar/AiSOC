"""
Pillar-1 Investigation API
==========================
Endpoints:
  POST /api/v1/cases/{case_id}/investigate     → launch async investigation
  GET  /api/v1/investigations/{run_id}         → poll status + results
  GET  /api/v1/investigations/{run_id}/report.md
  GET  /api/v1/investigations/{run_id}/report.html
  GET  /api/v1/investigations/{run_id}/report.pdf  → weasyprint PDF
  WS   /api/v1/investigations/{run_id}/stream  → SSE-style step stream
"""
from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

import httpx
import structlog
from fastapi import APIRouter, BackgroundTasks, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel

from app.investigator import InvestigatorOrchestrator, InvestigatorState

logger = structlog.get_logger()
router = APIRouter(prefix="/api/v1", tags=["investigations"])

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
_REALTIME_URL = os.environ.get("REALTIME_URL", "http://realtime:8086")
_INTERNAL_TOKEN = os.environ.get("INTERNAL_TOKEN", "")

# ---------------------------------------------------------------------------
# Simple in-memory run store (swap for Redis in production)
# ---------------------------------------------------------------------------
_runs: dict[str, dict[str, Any]] = {}
_orch = InvestigatorOrchestrator()


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------

class InvestigateRequest(BaseModel):
    alert_summary: str
    raw_alert: dict[str, Any] = {}
    tenant_id: str = "default"


class InvestigateResponse(BaseModel):
    run_id: str
    case_id: str
    status: str
    message: str


# ---------------------------------------------------------------------------
# Realtime broadcast helper
# ---------------------------------------------------------------------------

async def _emit_event(run_id: str, tenant_id: str, event: dict[str, Any]) -> None:
    """Forward an agent step event to the realtime service (best-effort)."""
    url = f"{_REALTIME_URL}/internal/agent-event"
    headers = {}
    if _INTERNAL_TOKEN:
        headers["x-internal-token"] = _INTERNAL_TOKEN
    payload = {
        "run_id": run_id,
        "tenant_id": tenant_id,
        "kind": event.get("kind", "step"),
        "agent": event.get("agent", "unknown"),
        "summary": event.get("summary", ""),
        "data": event.get("data"),
    }
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            await client.post(url, json=payload, headers=headers)
    except Exception as exc:  # noqa: BLE001
        logger.debug("realtime_emit_skipped", reason=str(exc))


# ---------------------------------------------------------------------------
# Background task: runs investigation and streams steps to realtime service
# ---------------------------------------------------------------------------

async def _run_and_store(run_id: str, case_id: str, req: InvestigateRequest) -> None:
    audit_log: list[dict[str, Any]] = []
    # Reuse the API-issued run id as the ledger row id so consumers can
    # cross-reference the realtime stream and the persisted timeline.
    try:
        run_uuid = UUID(run_id)
    except (ValueError, TypeError):
        run_uuid = uuid4()
    try:
        # Use the streaming orchestrator so we can emit events progressively
        async for event in _orch.stream(
            case_id=case_id,
            alert_summary=req.alert_summary,
            raw_alert=req.raw_alert,
            tenant_id=req.tenant_id,
            run_id=run_uuid,
        ):
            if event.get("type") == "step":
                audit_log.append(event)
                # Update the in-memory run so pollers see progress
                _runs[run_id]["audit_log"] = audit_log
                # Broadcast to realtime → WebSocket clients
                await _emit_event(run_id, req.tenant_id, event)

            elif event.get("type") == "done":
                state_data = event.get("state", {})
                _runs[run_id].update({
                    "status": "completed",
                    "report_md": state_data.get("report_md", ""),
                    "report_html": state_data.get("report_html", ""),
                    "audit_log": audit_log,
                    "recon": state_data.get("recon", {}),
                    "forensic": state_data.get("forensic", {}),
                    "responder": state_data.get("responder", {}),
                    "completed_at": datetime.utcnow().isoformat(),
                    "error": None,
                })
                await _emit_event(run_id, req.tenant_id, {
                    "kind": "completed",
                    "agent": "orchestrator",
                    "summary": "Investigation completed",
                    "data": {"status": "completed"},
                })

            elif event.get("type") == "error":
                err_msg = event.get("error", "Unknown error")
                _runs[run_id].update({"status": "failed", "error": err_msg})
                await _emit_event(run_id, req.tenant_id, {
                    "kind": "error",
                    "agent": "orchestrator",
                    "summary": err_msg,
                    "data": {"status": "failed"},
                })

    except Exception as exc:  # noqa: BLE001
        logger.error("investigation_bg_task failed", run_id=run_id, error=str(exc))
        _runs[run_id].update({"status": "failed", "error": str(exc)})


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/cases/{case_id}/investigate", response_model=InvestigateResponse)
async def launch_investigation(
    case_id: str,
    body: InvestigateRequest,
    background_tasks: BackgroundTasks,
):
    """Launch a Pillar-1 autonomous investigation for a case."""
    run_id = str(uuid4())
    _runs[run_id] = {
        "run_id": run_id,
        "case_id": case_id,
        "status": "running",
        "started_at": datetime.utcnow().isoformat(),
    }
    background_tasks.add_task(_run_and_store, run_id, case_id, body)
    logger.info("investigation.launched", run_id=run_id, case_id=case_id)
    return InvestigateResponse(
        run_id=run_id,
        case_id=case_id,
        status="running",
        message=f"Investigation started. Poll GET /api/v1/investigations/{run_id}",
    )


@router.get("/investigations/{run_id}")
async def get_investigation(run_id: str):
    """Poll investigation status and results."""
    run = _runs.get(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Investigation run not found")
    # Strip large fields from polling response — use dedicated endpoints instead
    slim = {k: v for k, v in run.items() if k not in ("report_md", "report_html")}
    return slim


@router.get("/investigations/{run_id}/report.md", response_class=PlainTextResponse)
async def get_report_md(run_id: str):
    """Download the Markdown incident report."""
    run = _runs.get(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    if run["status"] != "completed":
        raise HTTPException(status_code=409, detail=f"Investigation is {run['status']}")
    return run.get("report_md", "")


@router.get("/investigations/{run_id}/report.html", response_class=HTMLResponse)
async def get_report_html(run_id: str):
    """Download the HTML incident report."""
    run = _runs.get(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    if run["status"] != "completed":
        raise HTTPException(status_code=409, detail=f"Investigation is {run['status']}")
    return run.get("report_html", "<html><body>No report yet.</body></html>")


@router.get("/investigations/{run_id}/report.pdf")
async def get_report_pdf(run_id: str):
    """Download the PDF incident report (rendered from HTML via weasyprint)."""
    from fastapi.responses import Response as FastAPIResponse

    run = _runs.get(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    if run["status"] != "completed":
        raise HTTPException(status_code=409, detail=f"Investigation is {run['status']}")

    html_content: str = run.get("report_html", "")
    if not html_content:
        raise HTTPException(status_code=404, detail="Report not yet generated")

    try:
        import weasyprint  # type: ignore

        pdf_bytes: bytes = weasyprint.HTML(string=html_content).write_pdf()
        return FastAPIResponse(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="aisoc-report-{run_id}.pdf"'},
        )
    except ImportError:
        # weasyprint not installed — return the HTML with a PDF content-type note
        raise HTTPException(
            status_code=501,
            detail="PDF generation requires weasyprint. Install with: pip install weasyprint",
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {exc}") from exc


@router.websocket("/investigations/{run_id}/stream")
async def stream_investigation(ws: WebSocket, run_id: str):
    """
    WebSocket stream: emits per-step JSON events as the pipeline progresses.

    Two modes:
    1. If the run is already in _runs (background task is running), replay
       its current audit_log and then long-poll for completion.
    2. If query params case_id + alert_summary are supplied, run a fresh
       investigation directly on this connection (dev/test use-case).
    """
    case_id = ws.query_params.get("case_id", run_id)
    alert_summary = ws.query_params.get("alert_summary", "")
    tenant_id = ws.query_params.get("tenant_id", "default")

    await ws.accept()
    try:
        # If a background run exists, tail it via polling
        if run_id in _runs:
            seen = 0
            while True:
                run = _runs.get(run_id, {})
                audit = run.get("audit_log", [])
                # Send any new audit entries
                for entry in audit[seen:]:
                    await ws.send_text(json.dumps({"type": "step", **entry}))
                seen = len(audit)

                status = run.get("status", "running")
                if status in ("completed", "failed"):
                    await ws.send_text(json.dumps({
                        "type": "done" if status == "completed" else "error",
                        "case_id": case_id,
                        "status": status,
                        "error": run.get("error"),
                    }))
                    break
                await asyncio.sleep(0.5)
        else:
            # Direct streaming for ad-hoc calls
            async for event in _orch.stream(
                case_id=case_id,
                alert_summary=alert_summary,
                raw_alert={},
                tenant_id=tenant_id,
            ):
                await ws.send_text(json.dumps(event))
    except WebSocketDisconnect:
        logger.info("ws.disconnected", run_id=run_id)
    except Exception as exc:  # noqa: BLE001
        logger.error("ws.error", run_id=run_id, error=str(exc))
        await ws.close(code=1011)
