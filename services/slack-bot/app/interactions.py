"""
Interactive component handlers for the AiSOC Slack bot.

Slack delivers a single ``block_actions`` payload whenever the analyst
clicks a button on a message we sent. This module isolates the *logic*
side of those events — the decoding of the routing token, the call into
``services/actions``, and the construction of the reply blocks — from
the Bolt transport layer in :mod:`app.main`.

Why a pure-Python module again
==============================

Same reasoning as :mod:`app.commands`:

* the Bolt wrapper stays a 5-line shim (``ack`` → ``handle_action_decision``
  → ``respond``)
* every branch — happy path, malformed value, upstream failure — is
  covered by a fast hermetic unit test
* error messages never leak a stack trace into a public Slack channel

Action ids
----------

The approval card emits two button ids that this module knows how to
handle:

* ``aisoc_action_approve``
* ``aisoc_action_deny``

The button ``value`` is encoded by :func:`app.blocks.approval_card_blocks`
as ``"<action_id>|<case_id>"``. We decode that here so the dispatcher
can avoid a database lookup just to know which case the button belonged
to (handy for the audit-trail message we post after the decision).
"""

from __future__ import annotations

from typing import Any

from app.blocks import action_decision_blocks, error_blocks
from app.services.aisoc_clients import AisocActionsClient, AisocClientError
from app.services.approval_audit import ApprovalAuditEvent, ApprovalAuditSink, NullAuditSink

#: Action id emitted by the *Approve* button on the approval card.
APPROVE_ACTION_ID = "aisoc_action_approve"

#: Action id emitted by the *Deny* button on the approval card.
DENY_ACTION_ID = "aisoc_action_deny"

#: Action id emitted by the *Need info* button (Block Kit v2 — T3.6).
NEED_INFO_ACTION_ID = "aisoc_action_need_info"

#: Decision strings we send back to ``services/actions``. Kept in a constant
#: so a typo can't slip into the network payload.
_DECISION_APPROVE = "approved"
_DECISION_REJECT = "rejected"
_DECISION_NEED_INFO = "need_info"


def _decode_routing_value(value: str) -> tuple[str, str]:
    """
    Pull ``action_id`` and ``case_id`` out of the button ``value``.

    The encoder is :func:`app.blocks.approval_card_blocks`, which uses the
    format ``"<action_id>|<case_id>"``. We accept a missing case id (the
    case id is informational on the audit-trail line and not strictly
    required to call ``services/actions``), but a missing action id is
    fatal — the upstream call is meaningless without it.

    Raises
    ------
    ValueError
        If ``value`` is empty or does not contain a non-empty action id.
    """
    if not value:
        raise ValueError("missing routing value on action button")
    parts = value.split("|", 1)
    action_id = parts[0].strip()
    case_id = parts[1].strip() if len(parts) > 1 else ""
    if not action_id:
        raise ValueError("routing value is missing the action id")
    return action_id, case_id


def _ephemeral(blocks: list[dict[str, Any]], *, fallback: str) -> dict[str, Any]:
    """
    Private follow-up message visible only to the analyst who clicked.

    Used for parser/upstream errors so we don't pollute the channel with
    failure noise.
    """
    return {"response_type": "ephemeral", "text": fallback, "blocks": blocks}


def _replace_card(blocks: list[dict[str, Any]], *, fallback: str) -> dict[str, Any]:
    """
    Replace the original approval card in-place with the post-decision
    audit-trail line.

    ``replace_original=True`` tells Slack to swap the message we sent
    earlier rather than append a new one — that way the buttons can't be
    clicked twice (defence in depth on top of the idempotency guarantees
    in ``services/actions``).
    """
    return {
        "replace_original": True,
        "response_type": "in_channel",
        "text": fallback,
        "blocks": blocks,
    }


async def handle_action_decision(
    *,
    action_id_event: str,
    button_value: str,
    user_id: str,
    actions_client: AisocActionsClient,
    audit_sink: ApprovalAuditSink | None = None,
    channel_id: str | None = None,
    actor_ip: str | None = None,
) -> dict[str, Any]:
    """
    Resolve an approve / deny / need-info click into a Slack response payload.

    Parameters
    ----------
    action_id_event
        The Slack ``action_id`` of the button — one of
        :data:`APPROVE_ACTION_ID`, :data:`DENY_ACTION_ID`, or
        :data:`NEED_INFO_ACTION_ID`.
    button_value
        The button's ``value`` field, encoded by
        :func:`app.blocks.approval_card_blocks` as
        ``"<action_id>|<case_id>"``.
    user_id
        The Slack user id of the analyst who clicked. Recorded on the
        post-decision message so the audit trail in chat matches the
        case timeline.
    actions_client
        Client for ``services/actions``.
    audit_sink
        Optional structured audit sink. When supplied the function emits a
        :class:`ApprovalAuditEvent` for every terminal decision (including
        upstream failures so the timeline can show the attempted call).
    channel_id, actor_ip
        Forwarded onto the audit event so the trail captures *where* the
        decision was made.

    Returns
    -------
    dict
        A Slack response payload. Successful decisions use
        ``replace_original=True`` to swap the approval card with an
        audit-trail line so the buttons can't be clicked again.
    """
    sink: ApprovalAuditSink = audit_sink or NullAuditSink()
    valid = {APPROVE_ACTION_ID, DENY_ACTION_ID, NEED_INFO_ACTION_ID}
    if action_id_event not in valid:
        return _ephemeral(
            error_blocks(f"Unknown interactive action `{action_id_event}`"),
            fallback="Unknown interactive action",
        )

    try:
        action_id, case_id = _decode_routing_value(button_value)
    except ValueError as exc:
        return _ephemeral(
            error_blocks(f"Couldn't decode the approval button: {exc}"),
            fallback="Bad approval payload",
        )

    decision_map = {
        APPROVE_ACTION_ID: _DECISION_APPROVE,
        DENY_ACTION_ID: _DECISION_REJECT,
        NEED_INFO_ACTION_ID: _DECISION_NEED_INFO,
    }
    decision_label = decision_map[action_id_event]

    # Need-info is non-terminal — it doesn't change the action state, it
    # just records that the approver bounced the request back for context.
    if action_id_event == NEED_INFO_ACTION_ID:
        await sink.record(
            ApprovalAuditEvent(
                case_id=case_id,
                action_id=action_id,
                approver_id=user_id,
                decision=decision_label,
                channel=channel_id,
                actor_ip=actor_ip,
                source="slack",
            )
        )
        blocks = action_decision_blocks(
            decision=decision_label,
            action={"id": action_id},
            decided_by_slack_id=user_id,
        )
        return _ephemeral(blocks, fallback=f"Need-info recorded by <@{user_id}>")

    is_approve = action_id_event == APPROVE_ACTION_ID
    try:
        action = await actions_client.approve_action(action_id) if is_approve else await actions_client.reject_action(action_id)
    except AisocClientError as exc:
        await sink.record(
            ApprovalAuditEvent(
                case_id=case_id,
                action_id=action_id,
                approver_id=user_id,
                decision=decision_label,
                channel=channel_id,
                actor_ip=actor_ip,
                source="slack",
                error=str(exc),
            )
        )
        return _ephemeral(
            error_blocks(f"Could not record decision for action `{action_id}`: {exc}"),
            fallback="Decision failed",
        )

    if not action.get("id") and not action.get("action_id"):
        action = {**action, "id": action_id}

    await sink.record(
        ApprovalAuditEvent(
            case_id=case_id,
            action_id=action_id,
            approver_id=user_id,
            decision=decision_label,
            channel=channel_id,
            actor_ip=actor_ip,
            source="slack",
        )
    )

    blocks = action_decision_blocks(
        decision=decision_label,
        action=action,
        decided_by_slack_id=user_id,
    )
    fallback = f"Action {action_id} {decision_label} by <@{user_id}>"
    return _replace_card(blocks, fallback=fallback)
