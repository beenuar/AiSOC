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
import hmac
import json
import os
from datetime import datetime
from typing import Annotated, Any
from uuid import UUID, uuid4

import httpx
import structlog
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel

from app.graph.runner import default_budget
from app.investigator import InvestigatorOrchestrator, ledger
from app.orchestrator.router import RouterOrchestrator
from app.security.tenant_scope import (
    TENANT_HEADER,
    TenantPrincipal,
    require_console_or_service_auth,
    resolve_console_secret,
    resolve_service_token,
    scoped_tenant_or_403,
    verify_console_token,
)

logger = structlog.get_logger()
router = APIRouter(prefix="/api/v1", tags=["investigations"])

#: The console reaches this service directly through a Next rewrite, sending
#: the first-party access token as a bearer credential. The tenant comes from
#: that verified token; a `tenant_id` on the request is only ever a filter,
#: intersected with it, so naming a foreign tenant is a 403 rather than a
#: selector for somebody else's investigation.
ScopedPrincipal = Annotated[TenantPrincipal, Depends(require_console_or_service_auth)]


async def _ws_principal(ws: WebSocket) -> TenantPrincipal | None:
    """Resolve a WebSocket caller's tenant scope, or ``None`` to refuse.

    The HTTP routes take ``ScopedPrincipal`` and a router-level dependency
    would be the obvious way to cover this one too — but a dependency that
    raises ``HTTPException`` has no defined rendering on a WebSocket scope,
    and a browser cannot set an ``Authorization`` header on a WS handshake
    regardless. So the credential is read from the header when a machine
    client sends one, and from ``?token=`` when the browser connects, which
    is the same shape ``services/realtime`` already uses for its tickets.

    Verification is the shared vendored logic, not a second implementation:
    a parallel verifier is how one side ends up accepting ``alg: none`` after
    the other stopped.
    """
    header = ws.headers.get("authorization") or ""
    token = header[len("Bearer ") :].strip() if header.startswith("Bearer ") else (ws.query_params.get("token") or "").strip()
    if not token:
        return None

    secret = resolve_console_secret()
    if secret:
        claims = verify_console_token(token, secret)
        if claims is not None:
            try:
                return TenantPrincipal(
                    tenant_ids=frozenset({UUID(str(claims["tenant_id"]))}),
                    subject=f"console:{claims.get('sub', 'unknown')}",
                )
            except (KeyError, ValueError, TypeError):
                return None

    service_token = resolve_service_token()
    if service_token and hmac.compare_digest(token, service_token):
        declared = (ws.headers.get(TENANT_HEADER.lower()) or ws.query_params.get("tenant_id") or "").strip()
        if not declared:
            # A service token identifies a service, not a tenant. Absent is
            # an empty scope, never every scope.
            return None
        try:
            return TenantPrincipal(tenant_ids=frozenset({UUID(declared)}), subject="service", delegated=True)
        except ValueError:
            return None
    return None


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
_REALTIME_URL = os.environ.get("REALTIME_URL", "http://realtime:8086")
_INTERNAL_TOKEN = os.environ.get("INTERNAL_TOKEN", "")

# ---------------------------------------------------------------------------
# Orchestrator selection
# ---------------------------------------------------------------------------
# T2.2: route /investigate through the four-agent ``RouterOrchestrator`` when
# the flag is on; otherwise keep the legacy ``InvestigatorOrchestrator`` path.
# Read at call time so operators can flip without restarting the service.
USE_ROUTER_FLAG = "AISOC_INVESTIGATE_USE_ROUTER"


def is_router_investigate_enabled() -> bool:
    """Return True if /investigate should use ``RouterOrchestrator`` (default off).

    Explicit truthy values (``1`` / ``true`` / ``yes`` / ``on`` / ``enabled``,
    case-insensitive) opt into the router path; everything else, including the
    unset case, keeps the investigator path. Mirrors the convention used by
    :func:`app.orchestrator.router.is_parallel_topology_enabled`.
    """
    raw = os.environ.get(USE_ROUTER_FLAG)
    if raw is None:
        return False
    return raw.strip().lower() in {"1", "true", "yes", "on", "enabled"}


# ---------------------------------------------------------------------------
# Simple in-memory run store (swap for Redis in production)
# ---------------------------------------------------------------------------
_runs: dict[str, dict[str, Any]] = {}
_orch = InvestigatorOrchestrator()
_router_orch = RouterOrchestrator()


def _investigate_stream(
    *,
    case_id: str,
    alert_summary: str,
    raw_alert: dict[str, Any],
    tenant_id: str,
    run_id: UUID | None = None,
):
    """Pick the orchestrator at call time based on ``AISOC_INVESTIGATE_USE_ROUTER``.

    Both orchestrators expose an investigator-compatible ``stream`` /
    ``stream_kwargs`` surface that yields the same ``step`` / ``done`` /
    ``error`` event taxonomy, so the consumer below can stay shape-agnostic.
    """
    if is_router_investigate_enabled():
        return _router_orch.stream_kwargs(
            case_id=case_id,
            alert_summary=alert_summary,
            raw_alert=raw_alert,
            tenant_id=tenant_id,
            run_id=run_id,
        )
    return _orch.stream(
        case_id=case_id,
        alert_summary=alert_summary,
        raw_alert=raw_alert,
        tenant_id=tenant_id,
        run_id=run_id,
    )


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

#: Statuses that mean this run is over. The console's ``CaseWorkspace.tsx``
#: branches on ``idle``/``starting``/``running``/``failed``/``completed`` and the
#: WebSocket tail below breaks on ``completed``/``failed``, so a run that ends in
#: any other word is a run no surface can finish rendering. A timed-out run is
#: therefore ``failed`` carrying the reason, not a fifth vocabulary entry.
_TERMINAL_STATUSES = frozenset({"completed", "failed"})


async def _fail_run(run_id: str, run_uuid: UUID, tenant_ref: str, reason: str) -> None:
    """Close a run as ``failed`` in **both** places a consumer reads it.

    The console polls ``GET /api/v1/investigations/{run_id}``, which serves the
    process dict; the Investigation Ledger renders the ``investigation_runs``
    row. Writing one and not the other swaps a spinner that never resolves for
    a ledger entry that never ends, which is the same defect wearing the other
    surface.

    Never downgrades a run that already finished: a ``done`` event followed by
    a slow generator teardown must not be relabelled a failure.
    """
    entry = _runs.get(run_id)
    if entry is not None:
        if entry.get("status") in _TERMINAL_STATUSES:
            return
        entry.update(
            {
                "status": "failed",
                "error": reason,
                "completed_at": datetime.utcnow().isoformat(),
            }
        )

    # Best-effort, exactly like every other ledger write: no database
    # configured is not an error, and a failed bookkeeping write must not
    # replace the reason the run ended with a reason it did not.
    try:
        tenant_uuid = await ledger.resolve_tenant(tenant_ref)
        if tenant_uuid is not None:
            await ledger.complete_run(
                run_id=run_uuid,
                tenant_id=tenant_uuid,
                status="failed",
                error=reason,
            )
    except Exception as exc:  # noqa: BLE001 — bookkeeping never masks the outcome
        logger.warning("investigation.ledger_close_failed", run_id=run_id, error=str(exc))


async def _run_and_store(run_id: str, case_id: str, req: InvestigateRequest) -> None:
    audit_log: list[dict[str, Any]] = []
    # Reuse the API-issued run id as the ledger row id so consumers can
    # cross-reference the realtime stream and the persisted timeline.
    try:
        run_uuid = UUID(run_id)
    except (ValueError, TypeError):
        run_uuid = uuid4()

    # The same wall-clock budget the auto-triage path runs under — read at call
    # time from ``AISOC_INVESTIGATION_MAX_SECONDS`` rather than restated here,
    # because two constants describing one deadline is how the shorter one wins
    # silently. Without it this path had none at all: `ChatOpenAI` is built with
    # no timeout, so a merely-slow model raises nothing and the run stays
    # `running` for the life of the process (issue #1242).
    max_seconds = default_budget().max_seconds
    deadline = asyncio.timeout(max_seconds)
    try:
        async with deadline:
            # Use the streaming orchestrator so we can emit events progressively.
            # ``_investigate_stream`` picks investigator vs. router at call time
            # based on ``AISOC_INVESTIGATE_USE_ROUTER``.
            async for event in _investigate_stream(
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
                    _runs[run_id].update(
                        {
                            "status": "completed",
                            "report_md": state_data.get("report_md", ""),
                            "report_html": state_data.get("report_html", ""),
                            "audit_log": audit_log,
                            "recon": state_data.get("recon", {}),
                            "forensic": state_data.get("forensic", {}),
                            "responder": state_data.get("responder", {}),
                            "completed_at": datetime.utcnow().isoformat(),
                            "error": None,
                        }
                    )
                    await _emit_event(
                        run_id,
                        req.tenant_id,
                        {
                            "kind": "completed",
                            "agent": "orchestrator",
                            "summary": "Investigation completed",
                            "data": {"status": "completed"},
                        },
                    )

                elif event.get("type") == "error":
                    err_msg = event.get("error", "Unknown error")
                    _runs[run_id].update({"status": "failed", "error": err_msg})
                    await _emit_event(
                        run_id,
                        req.tenant_id,
                        {
                            "kind": "error",
                            "agent": "orchestrator",
                            "summary": err_msg,
                            "data": {"status": "failed"},
                        },
                    )

    except TimeoutError as exc:
        # `asyncio.timeout` converts the cancellation it issued into
        # `TimeoutError`; an inner `TimeoutError` (an httpx read timeout, say)
        # arrives here too and is *not* the budget. `expired()` tells them
        # apart, so the operator-facing reason names the thing that actually
        # ran out.
        if deadline.expired():
            reason = (
                f"Investigation exceeded its wall-clock budget of {max_seconds}s and was stopped. "
                "Raise AISOC_INVESTIGATION_MAX_SECONDS if the configured model needs longer."
            )
            logger.warning("investigation.budget_timeout", run_id=run_id, max_seconds=max_seconds)
        else:
            reason = str(exc) or "Investigation timed out"
            logger.error("investigation_bg_task timed out", run_id=run_id, error=reason)
        await _fail_run(run_id, run_uuid, req.tenant_id, reason)

    except Exception as exc:  # noqa: BLE001
        logger.error("investigation_bg_task failed", run_id=run_id, error=str(exc))
        # Through the same helper as the deadline: an exception escaping the
        # stream means the orchestrator's own `except` arm did not run, so
        # nothing else is going to close the ledger row either.
        await _fail_run(run_id, run_uuid, req.tenant_id, str(exc))


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post("/cases/{case_id}/investigate", response_model=InvestigateResponse)
async def launch_investigation(
    case_id: str,
    body: InvestigateRequest,
    background_tasks: BackgroundTasks,
    principal: ScopedPrincipal,
):
    """Launch a Pillar-1 autonomous investigation for a case."""
    body.tenant_id = str(scoped_tenant_or_403(principal, body.tenant_id))
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
async def get_investigation(run_id: str, principal: ScopedPrincipal):
    """Poll investigation status and results."""
    run = _runs.get(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Investigation run not found")
    # Strip large fields from polling response — use dedicated endpoints instead
    slim = {k: v for k, v in run.items() if k not in ("report_md", "report_html")}
    return slim


@router.get("/investigations/{run_id}/report.md", response_class=PlainTextResponse)
async def get_report_md(run_id: str, principal: ScopedPrincipal):
    """Download the Markdown incident report."""
    run = _runs.get(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    if run["status"] != "completed":
        raise HTTPException(status_code=409, detail=f"Investigation is {run['status']}")
    return run.get("report_md", "")


@router.get("/investigations/{run_id}/report.html", response_class=HTMLResponse)
async def get_report_html(run_id: str, principal: ScopedPrincipal):
    """Download the HTML incident report."""
    run = _runs.get(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    if run["status"] != "completed":
        raise HTTPException(status_code=409, detail=f"Investigation is {run['status']}")
    return run.get("report_html", "<html><body>No report yet.</body></html>")


@router.get("/investigations/{run_id}/report.pdf")
async def get_report_pdf(run_id: str, principal: ScopedPrincipal):
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
    except ImportError as exc:
        # weasyprint not installed — return the HTML with a PDF content-type note
        raise HTTPException(
            status_code=501,
            detail="PDF generation requires weasyprint. Install with: pip install weasyprint",
        ) from exc
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
    principal = await _ws_principal(ws)
    if principal is None:
        # 1008 = policy violation. Refused before accept() so an anonymous
        # caller never reaches the branch below that starts a fresh
        # investigation — which spends the tenant's LLM budget.
        await ws.close(code=1008, reason="unauthenticated")
        return

    case_id = ws.query_params.get("case_id", run_id)
    alert_summary = ws.query_params.get("alert_summary", "")
    # The tenant comes from the verified credential. It used to come from a
    # query parameter defaulting to the literal "default", which names no
    # tenant anywhere in this schema.
    tenant_id = str(scoped_tenant_or_403(principal, ws.query_params.get("tenant_id")))

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
                    await ws.send_text(
                        json.dumps(
                            {
                                "type": "done" if status == "completed" else "error",
                                "case_id": case_id,
                                "status": status,
                                "error": run.get("error"),
                            }
                        )
                    )
                    break
                await asyncio.sleep(0.5)
        else:
            # Direct streaming for ad-hoc calls; orchestrator selected by flag.
            async for event in _investigate_stream(
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
