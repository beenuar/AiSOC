"""Consume the signed email-approval links (T3.6).

`app/services/email_approval.py` shipped the issuer and the verifier and
pointed its URLs at ``/v1/actions/email-decide`` — a path that existed nowhere
in the tree. Every approve and deny button in a rendered approval email linked
to a 404, so the documented fallback for "Slack and Teams are unreachable" did
not work at the moment it was needed.

Three properties this route has to hold, none of which come for free from a
signed URL:

**The click carries an identity.** A bare signed link is a bearer credential:
whoever holds it approves, and the approval reaches the actions service with no
principal, so the permission tier and separation of duties are skipped. The
recipient address is signed into the token and forwarded as the approver, which
means an email approver must be mapped in ``AISOC_CHATOPS_APPROVERS`` under
``email`` exactly like a Slack or Teams one.

**A link works once.** Single-use falls out of the action's own state machine
rather than needing a nonce table: the actions service only accepts an approval
while the action is ``awaiting_approval``, so a replayed link gets a 400. That
is enough for approve. It is *not* enough to stop a forwarded link being
clicked by the wrong person, which is why identity is signed in rather than
inferred from the click.

**A failure says which failure.** An expired link, a tampered link and an
already-decided action are three different operator problems, and a generic
"invalid" page sends people looking at the signing key when the answer is that
somebody already approved it twenty minutes ago.
"""

from __future__ import annotations

import os

import structlog
from fastapi import APIRouter, Query
from fastapi.responses import HTMLResponse

from app.services.actions_client import ActionsServiceError, decide_action
from app.services.email_approval import EmailApprovalError, verify_token

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/actions", tags=["actions"])


def _signing_secret() -> str:
    return os.environ.get("AISOC_EMAIL_APPROVAL_SECRET", "").strip()


def _render_safe(value: str, *, limit: int) -> str:
    """One operator-readable line, HTML-escaped and length-bounded.

    Newlines are collapsed rather than escaped: a multi-line value reaching
    this page is a traceback or a wrapped transport error, and the first line
    is the only part a recipient can act on. Truncating is what stops the
    rest of it being rendered at all.
    """
    single_line = str(value).replace("\r", " ").replace("\n", " ")
    escaped = single_line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return escaped[:limit]


def _page(title: str, body: str, *, status_code: int) -> HTMLResponse:
    """Render a minimal self-contained result page.

    No external assets: this is opened from a mail client, often on a phone,
    frequently on a network that cannot reach a CDN.
    """
    # Bounded and flattened at the point of rendering, not only at the point
    # of construction.
    #
    # This route is unauthenticated by necessity — the reader is holding an
    # email, not a session — so it is the worst place in the product for a
    # transport error carrying an internal hostname or a stack frame to
    # surface. Callers already pass `ActionsServiceError.upstream_detail`
    # rather than the exception, but a sanitiser that lives at the boundary
    # holds for every future caller and is visible to a reader here, which
    # the earlier arrangement was not.
    safe_title = _render_safe(title, limit=120)
    safe_body = _render_safe(body, limit=400)
    html = (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>{safe_title}</title></head>"
        '<body style="font-family:Arial,Helvetica,sans-serif;max-width:34rem;'
        'margin:3rem auto;padding:0 1rem;line-height:1.5">'
        f"<h1 style='font-size:1.25rem'>{safe_title}</h1>"
        f"<p>{safe_body}</p>"
        "</body></html>"
    )
    return HTMLResponse(content=html, status_code=status_code)


@router.get("/email-decide", response_class=HTMLResponse)
async def email_decide(token: str = Query(..., description="Signed approval token")) -> HTMLResponse:
    """Verify a signed approval link and forward the decision.

    Unauthenticated by necessity — the recipient is reading email, not holding
    a session — so the token *is* the credential and every check that would
    otherwise come from a session has to come from the signature.
    """
    secret = _signing_secret()
    if not secret:
        # Fail closed and say so. Accepting tokens with an empty secret would
        # accept every token.
        logger.error("email_approval.no_secret_configured")
        return _page(
            "Email approvals are not configured",
            "AISOC_EMAIL_APPROVAL_SECRET is unset on the API service, so this "
            "link cannot be verified. Approve from the console or from Slack "
            "instead.",
            status_code=503,
        )

    try:
        parsed = verify_token(token, secret=secret)
    except EmailApprovalError as exc:
        # The verifier's message decides *which* fixed page to show; it is
        # never interpolated into one.
        #
        # This is the last of the stack-trace-exposure findings on this route,
        # and it is the one that was hardest to see: the page text read
        # naturally, and the value in it came from an exception. On an
        # unauthenticated page an exception message is the wrong kind of
        # string to render however harmless today's happens to look, because
        # the next one is written by whoever raises next.
        reason = str(exc)
        logger.warning("email_approval.token_rejected", reason=reason)
        expired = "expired" in reason
        if expired:
            body = "Approval links are valid for one hour. Ask for a fresh one, or approve from the console."
        else:
            body = (
                "The link could not be verified. If you received it forwarded "
                "from someone else, that is why — links are bound to their "
                "recipient."
            )
        return _page(
            "This approval link has expired" if expired else "This approval link is not valid",
            body,
            status_code=410 if expired else 400,
        )

    if not parsed.approver:
        # A token minted before approver binding, or by a caller that skipped
        # it. Refused rather than forwarded: the actions service would have to
        # authorize nobody, which is the hole this route exists to avoid.
        logger.warning("email_approval.token_without_approver", action_id=parsed.action_id)
        return _page(
            "This approval link is missing its recipient",
            "The link does not identify who it was sent to, so the decision cannot be attributed. Approve from the console instead.",
            status_code=400,
        )

    try:
        await decide_action(
            action_id=parsed.action_id,
            approve=parsed.decision == "approved",
            chatops_approver={"platform": "email", "platform_user_id": parsed.approver},
        )
    except ActionsServiceError as exc:
        status_code = exc.status_code
        if status_code is None:
            logger.warning("email_approval.upstream_unreachable", action_id=parsed.action_id, error=str(exc))
            return _page(
                "The action service could not be reached",
                "Your decision was not recorded. Try again, or use the console.",
                status_code=502,
            )
        if status_code == 400:
            return _page(
                "This action was already decided",
                "Somebody has already approved or rejected it, so this link no longer applies. Approval links work once.",
                status_code=409,
            )
        if status_code == 403:
            # The upstream detail is logged and NOT rendered.
            #
            # It was interpolated into the page, which is how a transport
            # error carrying an internal hostname — or a stack frame — ends
            # up in front of whoever holds the email. This route is
            # unauthenticated by necessity, so it is the worst surface in the
            # product for that, and truncating or escaping the string is not
            # the same as not sending it.
            #
            # Nothing is lost for the reader: an upstream authorization
            # detail is not something an email recipient can act on. The two
            # things they can act on are here, and the operator gets the
            # detail in the log with the action id beside it.
            logger.warning(
                "email_approval.not_authorized",
                action_id=parsed.action_id,
                approver=parsed.approver,
                detail=exc.upstream_detail,
            )
            return _page(
                "You are not authorised to decide this action",
                "An email approver must be mapped under 'email' in "
                "AISOC_CHATOPS_APPROVERS, and may not approve an action they "
                "requested themselves. Ask an administrator to check the "
                "API service log for this action id.",
                status_code=403,
            )
        if status_code == 404:
            return _page("Action not found", "It may have been removed since the email was sent.", status_code=404)
        logger.warning(
            "email_approval.upstream_error",
            action_id=parsed.action_id,
            status=status_code,
        )
        return _page(
            "Your decision could not be recorded",
            f"The action service returned {status_code}. Try the console instead.",
            status_code=502,
        )

    logger.info(
        "email_approval.recorded",
        action_id=parsed.action_id,
        decision=parsed.decision,
        approver=parsed.approver,
    )
    return _page(
        "Action approved" if parsed.decision == "approved" else "Action rejected",
        f"Recorded as {parsed.approver}. You can close this page.",
        status_code=200,
    )
