"""
Adaptive Card callback dispatch.

When a Teams user clicks Approve / Deny / Need-Info on an AiSOC
approval card, Teams POSTs an ``invoke`` activity carrying the card's
signed ``data`` payload. This module:

1. Verifies the HMAC signature + freshness window
   (:func:`app.services.hmac_signer.verify_card_data`).
2. Forwards the decision to ``services/actions`` (Approve / Deny) or
   records a structured audit row (Need-Info — no upstream state
   change).
3. Returns a replacement Adaptive Card so the original message reflects
   the decision and the buttons can't be clicked twice.

The dispatch is intentionally framework-agnostic. The FastAPI handler in
:mod:`app.main` extracts the payload from the Bot Framework activity
shape and hands it to :func:`handle_card_action` — the same function
can be reused under a fastapi-route, an Outlook Actionable Message
endpoint, or in a unit test.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Protocol

import structlog

from app.cards import decision_card
from app.services.hmac_signer import HmacVerificationError, verify_card_data

log = structlog.get_logger(__name__)


class _ActionsClient(Protocol):
    # Protocol method bodies use ``pass`` rather than ``...`` to silence
    # CodeQL ``py/ineffectual-statement`` (it flags ellipsis as a
    # discarded expression statement). Semantically identical for an
    # unimplemented Protocol contract.
    async def approve_action(self, action_id: str) -> dict[str, Any]:
        pass

    async def reject_action(self, action_id: str) -> dict[str, Any]:
        pass


@dataclass(slots=True, frozen=True)
class _AuditEvent:
    case_id: str
    action_id: str
    approver_id: str
    decision: str
    channel: str | None = None
    actor_ip: str | None = None
    source: str = "teams"
    error: str | None = None


class _AuditSink(Protocol):
    # See ``_ActionsClient`` — ``pass`` instead of ``...`` to keep
    # CodeQL ``py/ineffectual-statement`` quiet on Protocol stubs.
    async def record(self, event: _AuditEvent) -> None:
        pass


class CallbackResult(dict):
    """
    Typed convenience wrapper so callers can ``result["card"]`` /
    ``result["decision"]`` without inventing a parallel class. We
    subclass ``dict`` so the JSON-shape stays trivial to serialise out
    of the FastAPI handler.
    """


async def handle_card_action(
    *,
    payload: dict[str, Any],
    approver_id: str,
    secret: str,
    max_age_seconds: int,
    actions_client: _ActionsClient,
    audit_sink: _AuditSink | None = None,
    channel_id: str | None = None,
    actor_ip: str | None = None,
) -> CallbackResult:
    """
    Resolve a Teams Action.Submit click into an Adaptive Card response.

    Never raises — every failure becomes a small "could not record"
    decision card so the analyst sees actionable feedback in Teams.
    """
    try:
        verify_card_data(payload, secret=secret, max_age_seconds=max_age_seconds)
    except HmacVerificationError as exc:
        log.warning("teams_callback.hmac_failed", error=str(exc))
        return CallbackResult(
            decision="rejected_invalid_signature",
            ok=False,
            card=decision_card(
                decision="rejected",
                action_id=str(payload.get("action_id") or "?"),
                decided_by=approver_id or "?",
            ),
            error=str(exc),
        )

    verb = str(payload.get("verb") or "")
    action_id = str(payload.get("action_id") or "")
    case_id = str(payload.get("case_id") or "")
    decision_label = {"approve": "approved", "reject": "rejected", "need_info": "need_info"}.get(verb)
    if decision_label is None:
        log.warning("teams_callback.unknown_verb", verb=verb)
        return CallbackResult(
            decision="rejected_unknown_verb",
            ok=False,
            card=decision_card(decision="rejected", action_id=action_id, decided_by=approver_id),
            error=f"unknown verb {verb!r}",
        )

    if decision_label == "need_info":
        if audit_sink is not None:
            await audit_sink.record(
                _AuditEvent(
                    case_id=case_id,
                    action_id=action_id,
                    approver_id=approver_id,
                    decision="need_info",
                    channel=channel_id,
                    actor_ip=actor_ip,
                )
            )
        return CallbackResult(
            decision="need_info",
            ok=True,
            card=decision_card(decision="need_info", action_id=action_id, decided_by=approver_id),
        )

    try:
        if decision_label == "approved":
            await actions_client.approve_action(action_id)
        else:
            await actions_client.reject_action(action_id)
    except Exception as exc:  # noqa: BLE001 — surfaced as audit error
        log.warning(
            "teams_callback.upstream_failed",
            action_id=action_id,
            decision=decision_label,
            error=str(exc),
        )
        if audit_sink is not None:
            await audit_sink.record(
                _AuditEvent(
                    case_id=case_id,
                    action_id=action_id,
                    approver_id=approver_id,
                    decision=decision_label,
                    channel=channel_id,
                    actor_ip=actor_ip,
                    error=str(exc),
                )
            )
        return CallbackResult(
            decision=decision_label,
            ok=False,
            error=str(exc),
            card=decision_card(decision=decision_label, action_id=action_id, decided_by=approver_id),
        )

    if audit_sink is not None:
        await audit_sink.record(
            _AuditEvent(
                case_id=case_id,
                action_id=action_id,
                approver_id=approver_id,
                decision=decision_label,
                channel=channel_id,
                actor_ip=actor_ip,
            )
        )
    return CallbackResult(
        decision=decision_label,
        ok=True,
        card=decision_card(decision=decision_label, action_id=action_id, decided_by=approver_id),
    )


def callback_max_age_seconds() -> int:
    """Resolve the replay window. Defaults to 600s (10 minutes)."""
    raw = os.environ.get("AISOC_TEAMS_CALLBACK_MAX_AGE_SECONDS")
    if not raw:
        return 600
    try:
        value = int(raw)
        return value if value > 0 else 600
    except ValueError:
        return 600
