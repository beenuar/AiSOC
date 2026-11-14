"""
Pure-Python slash-command dispatcher for ``/aisoc``.

We deliberately keep the dispatcher independent of Slack Bolt: it consumes
plain values (text, user id) and returns a Slack response payload as a dict.
This means:

* every subcommand is unit-testable without starting an ASGI app
* the Bolt wrapper in :mod:`app.main` becomes a 5-line shim around this
* failures uniformly translate to ephemeral error blocks (private to the
  user) so we never accidentally leak a stack trace into a public channel

Supported subcommands
---------------------

``list [severity]``
    List open cases. Severity is an optional filter (``low``/``medium``/
    ``high``/``critical``).

``investigate <case>``
    Kick off an investigation run for the given case id or case number.

``explain <case>``
    Render the latest AI summary for the case.

``isolate <host> <case> [reason…]``
    Request host isolation (approval required for non-low blast radius).

``block <ip|domain> <case> [reason…]``
    Request a network block.

``help``
    Render the supported subcommands.
"""

from __future__ import annotations

import shlex
from typing import Any

from app.blocks import (
    approval_card_blocks,
    case_explanation_blocks,
    case_list_blocks,
    error_blocks,
    help_blocks,
    investigation_started_blocks,
)
from app.services.aisoc_clients import (
    AisocActionsClient,
    AisocApiClient,
    AisocClientError,
)

# ────────────────────────────────────────────────────────────────────────────
# Response helpers
# ────────────────────────────────────────────────────────────────────────────


def _ephemeral(blocks: list[dict[str, Any]], *, fallback: str) -> dict[str, Any]:
    """Private response visible only to the invoking user."""
    return {"response_type": "ephemeral", "text": fallback, "blocks": blocks}


def _in_channel(blocks: list[dict[str, Any]], *, fallback: str) -> dict[str, Any]:
    """Public response visible to everyone in the channel."""
    return {"response_type": "in_channel", "text": fallback, "blocks": blocks}


def _error(message: str) -> dict[str, Any]:
    return _ephemeral(error_blocks(message), fallback=message)


def _parse_tokens(text: str) -> list[str]:
    """
    Split a slash-command argument string. We use ``shlex`` so analysts can
    pass quoted reasons that include spaces, e.g. ``isolate host-1 c-7
    "confirmed beacon to known-bad C2"``.
    """
    text = (text or "").strip()
    if not text:
        return []
    try:
        return shlex.split(text, posix=True)
    except ValueError:
        # shlex chokes on unbalanced quotes — fall back to whitespace split.
        return text.split()


# ────────────────────────────────────────────────────────────────────────────
# Subcommand implementations
# ────────────────────────────────────────────────────────────────────────────


async def _cmd_list(
    args: list[str],
    *,
    api_client: AisocApiClient,
    web_base: str,
) -> dict[str, Any]:
    severity = args[0].lower() if args else None
    if severity and severity not in {"low", "medium", "high", "critical"}:
        return _error(f"Unknown severity `{severity}`. Use low|medium|high|critical.")
    try:
        cases = await api_client.list_open_cases(limit=10, severity=severity)
    except AisocClientError as exc:
        return _error(f"Could not load cases: {exc}")

    title = "Open cases" if not severity else f"Open cases · {severity.title()}"
    blocks = case_list_blocks(cases, web_base=web_base, title=title)
    return _ephemeral(blocks, fallback=title)


async def _cmd_investigate(
    args: list[str],
    *,
    api_client: AisocApiClient,
    web_base: str,
    user_id: str,
) -> dict[str, Any]:
    if not args:
        return _error("Usage: `/aisoc investigate <case_id>`")
    case_id = args[0]
    try:
        case = await api_client.get_case(case_id)
        # Use the requesting Slack user id as a lightweight rationale source so
        # the case timeline records who fired the run from chat.
        investigation = await api_client.launch_investigation(case_id, alert_summary=f"investigation requested by Slack user {user_id}")
    except AisocClientError as exc:
        return _error(f"Investigation failed: {exc}")

    blocks = investigation_started_blocks(case, investigation, web_base=web_base)
    return _in_channel(blocks, fallback=f"Investigation launched for case {case_id}")


async def _cmd_explain(
    args: list[str],
    *,
    api_client: AisocApiClient,
    web_base: str,
) -> dict[str, Any]:
    if not args:
        return _error("Usage: `/aisoc explain <case_id>`")
    case_id = args[0]
    try:
        case = await api_client.get_case(case_id)
        summary = await api_client.get_case_summary(case_id)
    except AisocClientError as exc:
        return _error(f"Could not summarise case: {exc}")

    blocks = case_explanation_blocks(case, summary, web_base=web_base)
    return _in_channel(blocks, fallback=f"Case {case_id} summary")


async def _cmd_action(
    args: list[str],
    *,
    api_client: AisocApiClient,
    actions_client: AisocActionsClient,
    web_base: str,
    user_id: str,
    action_type: str,
    usage: str,
) -> dict[str, Any]:
    """
    Shared implementation for ``isolate`` and ``block``.

    Both commands have the same shape (``<target> <case> [reason…]``) and
    differ only in ``action_type``, so we centralise the parsing + submission
    here to keep the surface tiny.
    """
    if len(args) < 2:
        return _error(f"Usage: `{usage}`")

    target, case_ref, *reason_parts = args
    rationale = " ".join(reason_parts) if reason_parts else "Submitted via Slack"

    try:
        case = await api_client.get_case(case_ref)
        case_id = str(case.get("id") or case_ref)
        action = await actions_client.submit_action(
            action_type=action_type,
            target=target,
            case_id=case_id,
            rationale=rationale,
            requested_by=user_id,
        )
    except AisocClientError as exc:
        return _error(f"Action submission failed: {exc}")

    status = (action.get("status") or "").lower()
    if status in {"awaiting_approval", "pending_approval", "pending"}:
        blocks = approval_card_blocks(
            action=action,
            case=case,
            requested_by_slack_id=user_id,
            web_base=web_base,
        )
        return _in_channel(
            blocks,
            fallback=f"Approval required: {action_type} {target}",
        )

    # Auto-approved (low-blast actions): emit a confirmation rather than a
    # button card.
    fallback = f"{action_type} on {target} submitted (status: {status or 'unknown'})"
    return _in_channel(
        [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"✅ <@{user_id}> submitted `{action_type}` on `{target}` "
                        f"for case <{web_base.rstrip('/')}/cases/{case.get('id', '')}|"
                        f"{case.get('case_number') or case.get('id', '')}> · "
                        f"status `{status or 'unknown'}`"
                    ),
                },
            }
        ],
        fallback=fallback,
    )


# ────────────────────────────────────────────────────────────────────────────
# Top-level dispatcher
# ────────────────────────────────────────────────────────────────────────────


async def handle_aisoc_command(
    *,
    text: str,
    user_id: str,
    api_client: AisocApiClient,
    actions_client: AisocActionsClient,
    web_base: str,
) -> dict[str, Any]:
    """
    Dispatch a parsed ``/aisoc`` command to the right subcommand.

    The function never raises — every exception path is converted to an
    ephemeral error block so the user always gets useful feedback in Slack.
    """
    tokens = _parse_tokens(text)
    if not tokens:
        return _ephemeral(help_blocks(), fallback="AiSOC Slack help")

    sub, *rest = tokens
    sub = sub.lower()

    if sub in {"help", "?", "-h", "--help"}:
        return _ephemeral(help_blocks(), fallback="AiSOC Slack help")

    if sub == "list":
        return await _cmd_list(rest, api_client=api_client, web_base=web_base)

    if sub == "investigate":
        return await _cmd_investigate(rest, api_client=api_client, web_base=web_base, user_id=user_id)

    if sub == "explain":
        return await _cmd_explain(rest, api_client=api_client, web_base=web_base)

    if sub == "isolate":
        return await _cmd_action(
            rest,
            api_client=api_client,
            actions_client=actions_client,
            web_base=web_base,
            user_id=user_id,
            action_type="isolate_host",
            usage="/aisoc isolate <host> <case_id> [reason]",
        )

    if sub == "block":
        return await _cmd_action(
            rest,
            api_client=api_client,
            actions_client=actions_client,
            web_base=web_base,
            user_id=user_id,
            action_type="block_ip",
            usage="/aisoc block <ip|domain> <case_id> [reason]",
        )

    return _ephemeral(
        help_blocks(),
        fallback=f"Unknown subcommand `{sub}`. See `/aisoc help`.",
    )
