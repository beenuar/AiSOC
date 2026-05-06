"""
Action Execution Service REST API.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import structlog
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import HTMLResponse

from app.core.config import get_settings
from app.models.action import ActionRequest, ActionStatus, ActionType
from app.security.chatops_token import ChatOpsTokenError, verify_token
from app.services.blast_radius import BlastRadiusGate
from app.services.executor_registry import EXECUTOR_REGISTRY
from app.services.timeline_client import TimelineClientError, post_timeline_event

logger = structlog.get_logger()
router = APIRouter()
gate = BlastRadiusGate()

# In-memory action store (replace with DB in production)
_actions: dict[str, dict[str, Any]] = {}

# Replay-protection set: action IDs that have already received a response.
# Single-use enforcement is layered on top of HMAC + expiry. Anything more
# durable belongs in Redis once we move off the in-memory action store.
_chatops_replied: set[str] = set()


@router.post("/actions", response_model=dict)
async def submit_action(request: ActionRequest):
    """Submit an action for execution (may require approval)."""
    status, blast_radius, reason = gate.evaluate(request)

    record = {
        "id": str(request.id),
        "action_type": request.action_type,
        "target": request.target,
        "status": status,
        "blast_radius": blast_radius,
        "gate_reason": reason,
        "incident_id": str(request.incident_id),
        "tenant_id": str(request.tenant_id),
        "rationale": request.rationale,
    }
    _actions[str(request.id)] = record

    # Auto-execute if approved
    if status == ActionStatus.APPROVED:
        executor = EXECUTOR_REGISTRY.get(request.action_type)
        if executor:
            try:
                result = await executor.execute(request)
                record["status"] = result.status
                record["output"] = result.output
                record["rollback_data"] = result.rollback_data
                if result.error:
                    record["error"] = result.error
            except Exception as exc:
                logger.error("Action execution failed", error=str(exc))
                record["status"] = ActionStatus.FAILED
                record["error"] = str(exc)
        else:
            record["status"] = ActionStatus.FAILED
            record["error"] = f"No executor found for action type: {request.action_type}"

    logger.info(
        "Action submitted",
        action_id=str(request.id),
        action_type=request.action_type,
        status=record["status"],
        blast_radius=blast_radius,
    )
    return record


@router.post("/actions/{action_id}/approve")
async def approve_action(action_id: str):
    """Approve a pending action (human-in-the-loop gate)."""
    record = _actions.get(action_id)
    if not record:
        raise HTTPException(status_code=404, detail="Action not found")
    if record["status"] != ActionStatus.AWAITING_APPROVAL:
        raise HTTPException(status_code=400, detail=f"Action is not awaiting approval (current: {record['status']})")

    # Reconstruct request and execute
    request = ActionRequest(
        id=UUID(action_id),
        incident_id=UUID(record["incident_id"]),
        tenant_id=UUID(record["tenant_id"]),
        action_type=ActionType(record["action_type"]),
        target=record["target"],
        rationale=record["rationale"],
    )

    executor = EXECUTOR_REGISTRY.get(request.action_type)
    if executor:
        result = await executor.execute(request)
        record["status"] = result.status
        record["output"] = result.output
    else:
        record["status"] = ActionStatus.FAILED
        record["error"] = "No executor available"

    logger.info("Action approved and executed", action_id=action_id, status=record["status"])
    return record


@router.post("/actions/{action_id}/reject")
async def reject_action(action_id: str):
    """Reject a pending action."""
    record = _actions.get(action_id)
    if not record:
        raise HTTPException(status_code=404, detail="Action not found")
    record["status"] = ActionStatus.REJECTED
    logger.info("Action rejected", action_id=action_id)
    return record


@router.get("/actions/{action_id}")
async def get_action(action_id: str):
    """Get action status and result."""
    record = _actions.get(action_id)
    if not record:
        raise HTTPException(status_code=404, detail="Action not found")
    return record


_CHOICE_COPY: dict[str, dict[str, str]] = {
    "acknowledge": {
        "headline": "Thanks — recorded as acknowledged.",
        "body": "We've logged that you confirmed this activity. You can close this tab.",
    },
    "deny": {
        "headline": "Thanks — recorded as denied.",
        "body": (
            "We've flagged this as suspicious. A security analyst will follow up shortly. "
            "If you didn't expect this prompt, please contact your security team."
        ),
    },
    "escalate": {
        "headline": "Thanks — escalated to security.",
        "body": "We've routed this to your security team for review.",
    },
}


def _chatops_response_html(headline: str, body: str, *, ok: bool = True) -> str:
    """Tiny self-contained response page rendered to the user's browser.

    Slack/Teams open the callback URL in a normal browser tab, so we can't
    redirect into the AiSOC console (the user may not have one). A static
    HTML acknowledgement is the smallest UX that confirms the click landed
    without leaking incident details into a URL the user might forward.
    """
    color = "#0a7" if ok else "#a33"
    return (
        '<!doctype html><html lang="en"><head>'
        '<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        "<title>AiSOC verification</title>"
        "<style>"
        "body{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;"
        "background:#0b1220;color:#e6edf3;margin:0;padding:0;display:flex;min-height:100vh;"
        "align-items:center;justify-content:center}"
        ".card{max-width:480px;background:#111827;border:1px solid #1f2937;border-radius:12px;"
        "padding:32px;box-shadow:0 8px 24px rgba(0,0,0,.4)}"
        f".dot{{width:12px;height:12px;border-radius:50%;background:{color};display:inline-block;margin-right:8px}}"
        "h1{margin:0 0 12px 0;font-size:18px;display:flex;align-items:center}"
        "p{margin:0;color:#9ca3af;line-height:1.5}"
        "</style></head><body>"
        f'<div class="card"><h1><span class="dot"></span>{headline}</h1><p>{body}</p></div>'
        "</body></html>"
    )


@router.get("/chatops/callback", response_class=HTMLResponse)
async def chatops_callback(token: str = Query(..., min_length=8)):
    """Receive a user's response to a ChatOps verification prompt.

    The token is the HMAC-signed payload minted by
    :class:`app.executors.chatops.ChatOpsVerifyExecutor`. We re-verify
    the signature + expiry, dedupe against ``_chatops_replied``, write a
    ``chatops.verify.responded`` event onto the case timeline, and update
    the in-memory action record so ``GET /actions/{id}`` reflects the
    final status.

    Returns an HTML acknowledgement page so the click lands cleanly in
    Slack/Teams' default browser tab.
    """
    settings = get_settings()
    secret = settings.AISOC_CHATOPS_RESPONSE_SECRET

    try:
        claims = verify_token(token, secret)
    except ChatOpsTokenError as exc:
        reason = str(exc)
        logger.info("ChatOps callback rejected", reason=reason)
        message = {
            "expired": ("This verification link has expired. If you still need to respond, contact your security team."),
            "invalid_signature": "This verification link is invalid.",
        }.get(reason, "This verification link is invalid.")
        return HTMLResponse(
            content=_chatops_response_html("Couldn't record your response", message, ok=False),
            status_code=400,
        )

    action_id_str = str(claims.action_id)
    if action_id_str in _chatops_replied:
        return HTMLResponse(
            content=_chatops_response_html(
                "Response already recorded",
                "We've already logged a response for this prompt. No further action is needed.",
            ),
            status_code=200,
        )

    record = _actions.get(action_id_str)
    # We still record on the timeline even if the in-memory record is gone
    # (e.g. service restart). The case timeline is the durable store —
    # losing the local record shouldn't lose the user's reply.

    timeline_warning: str | None = None
    try:
        await post_timeline_event(
            case_id=claims.case_id,
            event_type="chatops.verify.responded",
            content=(f"User {claims.user_ref or 'unknown'} responded '{claims.choice}' to the ChatOps verification prompt."),
            metadata={
                "action_id": action_id_str,
                "tenant_id": str(claims.tenant_id),
                "choice": claims.choice,
                "user_ref": claims.user_ref,
                "issued_at": claims.issued_at,
                "responded_at": int(datetime.now(UTC).timestamp()),
            },
        )
    except TimelineClientError as exc:
        timeline_warning = str(exc)
        logger.warning(
            "ChatOps response timeline write failed",
            action_id=action_id_str,
            case_id=str(claims.case_id),
            error=timeline_warning,
        )

    _chatops_replied.add(action_id_str)

    if record is not None:
        record["status"] = ActionStatus.COMPLETED
        record.setdefault("output", {})
        record["output"].update(
            {
                "user_choice": claims.choice,
                "user_ref": claims.user_ref,
                "responded_at": datetime.now(UTC).isoformat(),
            }
        )
        if timeline_warning:
            record["output"]["timeline_warning"] = timeline_warning

    logger.info(
        "ChatOps response recorded",
        action_id=action_id_str,
        case_id=str(claims.case_id),
        choice=claims.choice,
    )

    copy = _CHOICE_COPY.get(claims.choice, _CHOICE_COPY["acknowledge"])
    return HTMLResponse(
        content=_chatops_response_html(copy["headline"], copy["body"]),
        status_code=200,
    )


@router.get("/health")
async def health():
    return {"status": "healthy", "service": "aisoc-actions"}
