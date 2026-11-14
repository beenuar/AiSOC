"""Mailbox remediation: find a reported message, take it out, put it back.

Five verbs across Microsoft 365 and Google Workspace. Before this module the
registry held 79 builtin arms and not one could touch a mailbox, so governed
dispatch answered ``executor_not_found`` for ``purge_email`` — a phishing
response that could block the sender's domain at the firewall and could not
remove the message it arrived in.

Three properties are load-bearing, and each exists because its opposite has
already shipped in this repository.

**Off by default.** ``AISOC_FEATURE_MAILBOX_REMEDIATION`` gates every verb,
including the read. An operator upgrading AiSOC has consented to a new version
of the product, not to it acquiring the ability to delete from every mailbox
in their tenant.

**Disabled is not simulated, and absent credentials are not a clean result.**
Both return ``FAILED`` naming the cause, never ``COMPLETED``. ``executed`` is
the single field meaning a vendor was touched, and every result here sets it
explicitly. ``NotifySlackExecutor`` reporting ``message_sent: true`` for a
message it never sent is the precedent; on this surface the equivalent is
reporting a purge that never happened, across twenty-five mailboxes.

**Nothing found is not a purge.** A fan-out that reports every mailbox purged
when the message was in three of them teaches an analyst to trust a number
that means nothing, so a mailbox with no copy answers FAILED with the reason.

Why the vendor logic sits in one executor per verb
--------------------------------------------------
``ActionType`` is vendor-agnostic and the post-action verifier is keyed by it,
so each verb needs exactly one legacy executor. The per-vendor arms in
``live_actions/builtins.py`` are adapters onto these, pinning ``alert_vendor``
so ``m365/purge_email`` means Microsoft — and the pin is honoured **only when
that vendor's credentials are present**, because honouring a pin blindly is
the defect that had a "dry run" call a customer's Splunk.

Restore needs what the purge returned
--------------------------------------
Microsoft's move gives the message a **new id** in the destination folder, and
the folder it came from is only knowable before the move. Both travel back in
``rollback_data`` as ``restore_message_id`` and ``restore_folder_id``. Gmail
keeps the id across a trash and untrash restores the original labels, so its
restore needs only the id. The asymmetry is the vendors', not ours, and
collapsing it would make the Microsoft rollback guess — which on the most
disruptive verb in the product is the same as not having one.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

import structlog

from app.clients.factories import _gmail_client, _m365_mail_client
from app.clients.m365_mail_client import DEFAULT_RESTORE_FOLDER, RECOVERABLE_ITEMS, normalise_internet_message_id
from app.core.config import get_settings
from app.executors.base import BaseExecutor
from app.models.action import (
    ACTION_BLAST_RADIUS,
    ActionRequest,
    ActionResult,
    ActionStatus,
    ActionType,
    BlastRadius,
)

logger = structlog.get_logger()

M365 = "m365"
GOOGLE_WORKSPACE = "google_workspace"

#: Credential keys each vendor's factory reads, declared here so the adapters
#: in ``builtins.py`` strip exactly these on a dry run and the two cannot
#: drift. A hand-copied list on the adapter is the shape that let a "dry run"
#: reach production Splunk.
M365_CLIENT_PARAM_KEYS: tuple[str, ...] = ("azure_tenant_id", "azure_client_id", "azure_client_secret")
GMAIL_CLIENT_PARAM_KEYS: tuple[str, ...] = ("gws_service_account_key", "gws_subject_email")

_M365_PINS = frozenset({"m365", "microsoft", "microsoft365", "office365", "exchange", "outlook"})
_GMAIL_PINS = frozenset({"google_workspace", "gmail", "google", "workspace"})

#: Said verbatim whenever the feature is off, so an operator reading a failed
#: action knows it is a setting rather than a vendor outage or a bad
#: credential. Three different causes, three different next steps.
DISABLED_REASON = (
    "Mailbox remediation is disabled on this deployment. No mailbox was read or changed. "
    "Set AISOC_FEATURE_MAILBOX_REMEDIATION=true to enable it; it ships off because enabling "
    "it grants AiSOC the ability to remove mail from the tenant's mailboxes."
)

NO_CREDENTIALS_REASON = (
    "No mailbox credentials are configured. Provide the Microsoft 365 app registration "
    "(azure_tenant_id / azure_client_id / azure_client_secret) or the Google Workspace "
    "service-account key (gws_service_account_key). Nothing was read or changed."
)


def choose_vendor(params: dict[str, Any]) -> str:
    """``"m365"``, ``"google_workspace"``, or ``""`` when neither is configured.

    An explicit pin wins only when that vendor's credentials exist. A pin
    honoured without that check acts on whichever tenant's mail the ambient
    credentials happen to address.
    """
    has_m365 = _m365_mail_client(params) is not None
    has_gmail = _gmail_client(params) is not None
    pin = str(params.get("alert_vendor") or params.get("vendor") or "").strip().lower()
    if pin in _M365_PINS and has_m365:
        return M365
    if pin in _GMAIL_PINS and has_gmail:
        return GOOGLE_WORKSPACE
    if has_m365:
        return M365
    if has_gmail:
        return GOOGLE_WORKSPACE
    return ""


class _MailboxExecutor(BaseExecutor):
    """Shared preamble: feature flag, vendor choice, error shape."""

    action_type: ActionType

    def _blast(self) -> BlastRadius:
        return ACTION_BLAST_RADIUS.get(self.action_type, BlastRadius.HIGH)

    def _refused(self, request: ActionRequest, reason: str, **output: Any) -> ActionResult:
        return ActionResult(
            action_id=request.id,
            status=ActionStatus.FAILED,
            blast_radius=self._blast(),
            output={"action": self.action_type.value, "executed": False, **output},
            error=reason,
            completed_at=datetime.utcnow(),
        )

    def _failed(self, request: ActionRequest, vendor: str, exc: Exception) -> ActionResult:
        logger.warning(
            "mailbox_action.failed",
            capability=self.action_type.value,
            vendor=vendor,
            error=str(exc)[:500].replace("\r", "").replace("\n", " "),
        )
        return self._refused(request, f"{vendor} {self.action_type.value} failed: {exc}", vendor=vendor)

    def _ok(self, request: ActionRequest, vendor: str, output: dict[str, Any], rollback: dict[str, Any] | None = None) -> ActionResult:
        return ActionResult(
            action_id=request.id,
            status=ActionStatus.COMPLETED,
            blast_radius=self._blast(),
            output={"action": self.action_type.value, "executed": True, "vendor": vendor, **output},
            rollback_data={"vendor": vendor, "mailbox": request.target, **(rollback or {})},
            completed_at=datetime.utcnow(),
        )

    def _preamble(self, request: ActionRequest) -> tuple[str, Any, ActionResult | None]:
        """``(vendor, client, early_result)``. A non-None result ends the call."""
        if not get_settings().AISOC_FEATURE_MAILBOX_REMEDIATION:
            return "", None, self._refused(request, DISABLED_REASON)
        params = dict(request.parameters or {})
        vendor = choose_vendor(params)
        if not vendor:
            return "", None, self._refused(request, NO_CREDENTIALS_REASON)
        client = _m365_mail_client(params) if vendor == M365 else _gmail_client(params)
        if client is None:  # pragma: no cover - choose_vendor already proved it builds
            return vendor, None, self._refused(request, NO_CREDENTIALS_REASON, vendor=vendor)
        return vendor, client, None


class PurgeEmailExecutor(_MailboxExecutor):
    """Soft-delete one copy of a message. Reversible by ``RestoreEmailExecutor``."""

    action_type = ActionType.PURGE_EMAIL

    async def execute(self, request: ActionRequest) -> ActionResult:
        vendor, client, early = self._preamble(request)
        if early is not None:
            return early
        params = dict(request.parameters or {})
        message_id = str(params.get("message_id") or "")
        internet_id = str(params.get("internet_message_id") or "")
        source_folder = str(params.get("source_folder_id") or "")

        try:
            if not message_id:
                # A reported message carries an internet message id; the move
                # needs a per-mailbox one. Resolve it here rather than make
                # every caller run the search first.
                if not internet_id:
                    return self._refused(request, "purge_email needs either message_id or internet_message_id", vendor=vendor)
                found = await client.search_messages(request.target, internet_message_id=internet_id, limit=5)
                if not found:
                    return self._refused(
                        request,
                        "The message was not found in this mailbox, so nothing was purged.",
                        vendor=vendor,
                        mailbox=request.target,
                        match_count=0,
                    )
                message_id = str(found[0].get("id") or "")
                if vendor == M365:
                    source_folder = source_folder or str(found[0].get("parentFolderId") or "")

            if vendor == M365:
                moved = await client.soft_delete_message(request.target, message_id)
                restore_id = str(moved.get("id") or "")
                restore_folder = source_folder or DEFAULT_RESTORE_FOLDER
                summary = f"message soft-deleted from {request.target} (recoverable items)"
            else:
                await client.trash_message(request.target, message_id)
                # Gmail keeps the id across a trash and untrash restores the
                # labels the message had, which is strictly better than a
                # single destination folder.
                restore_id = message_id
                restore_folder = ""
                summary = f"message moved to Trash in {request.target}"
        except ValueError as exc:
            return self._refused(request, f"{vendor} search refused the query: {exc}", vendor=vendor)
        except Exception as exc:  # noqa: BLE001
            return self._failed(request, vendor, exc)

        return self._ok(
            request,
            vendor,
            {
                "mailbox": request.target,
                "summary": summary,
                "purged_message_id": message_id,
                "internet_message_id": normalise_internet_message_id(internet_id) if internet_id else "",
            },
            rollback={
                "restore_message_id": restore_id,
                "restore_folder_id": restore_folder,
                "internet_message_id": internet_id,
            },
        )

    async def rollback(self, result: ActionResult) -> bool:
        """Put the message back, for real. ``BaseExecutor`` defaults to ``False``.

        ``purge_email`` is the most disruptive verb this service offers and
        the one whose rollback most needs to exist rather than return a
        hopeful ``True``: ``unisolate_host`` resolving to nothing is the
        precedent, and this is the same shape with a wider blast radius.
        """
        data = dict(result.rollback_data or {})
        mailbox = str(data.get("mailbox") or "")
        if not mailbox or not data.get("restore_message_id"):
            logger.warning("purge_email.rollback_incomplete", has_mailbox=bool(mailbox))
            return False
        restored = await RestoreEmailExecutor().execute(
            ActionRequest(
                incident_id=result.action_id,
                tenant_id=result.action_id,
                action_type=ActionType.RESTORE_EMAIL,
                target=mailbox,
                parameters={**data, **(result.output.get("credentials") or {})},
            )
        )
        return restored.status == ActionStatus.COMPLETED


class RestoreEmailExecutor(_MailboxExecutor):
    """The declared reverse of ``purge_email``."""

    action_type = ActionType.RESTORE_EMAIL

    async def execute(self, request: ActionRequest) -> ActionResult:
        vendor, client, early = self._preamble(request)
        if early is not None:
            return early
        params = dict(request.parameters or {})
        message_id = str(params.get("restore_message_id") or params.get("message_id") or "")
        if not message_id:
            return self._refused(request, "restore_email needs the restore_message_id the purge returned", vendor=vendor)
        folder = str(params.get("restore_folder_id") or DEFAULT_RESTORE_FOLDER)
        try:
            if vendor == M365:
                restored = await client.restore_message(request.target, message_id, folder)
                new_id = str(restored.get("id") or message_id)
            else:
                await client.untrash_message(request.target, message_id)
                new_id = message_id
                folder = "original labels"
        except Exception as exc:  # noqa: BLE001
            return self._failed(request, vendor, exc)
        return self._ok(
            request,
            vendor,
            {
                "mailbox": request.target,
                "restored_message_id": new_id,
                "folder": folder,
                "summary": f"message restored to {folder} in {request.target}",
            },
            rollback={"message_id": new_id},
        )


class BlockSenderExecutor(_MailboxExecutor):
    """Stop future mail from one sender reaching **one** mailbox."""

    action_type = ActionType.BLOCK_SENDER

    async def execute(self, request: ActionRequest) -> ActionResult:
        vendor, client, early = self._preamble(request)
        if early is not None:
            return early
        params = dict(request.parameters or {})
        sender = str(params.get("sender") or "")
        if not sender:
            return self._refused(request, "block_sender needs a sender address", vendor=vendor)
        try:
            created = await (
                client.create_inbox_rule(request.target, sender) if vendor == M365 else client.create_filter(request.target, sender)
            )
        except Exception as exc:  # noqa: BLE001
            return self._failed(request, vendor, exc)
        mechanism = "inbox rule" if vendor == M365 else "filter"
        rule_id = str(created.get("id") or "")
        return self._ok(
            request,
            vendor,
            {
                "mailbox": request.target,
                "sender": sender,
                "rule_id": rule_id,
                "scope": "mailbox",
                # The scope is in the summary, not only in a docstring: this
                # string lands on the case timeline, and "sender blocked"
                # read without it means something the action did not do.
                "summary": (
                    f"{sender} blocked in the mailbox {request.target} only "
                    f"(per-mailbox {mechanism}; neither vendor exposes its "
                    f"organisation-wide block list through this API)"
                ),
            },
            rollback={"rule_id": rule_id, "sender": sender},
        )

    async def rollback(self, result: ActionResult) -> bool:
        data = dict(result.rollback_data or {})
        mailbox = str(data.get("mailbox") or "")
        if not mailbox or not data.get("rule_id"):
            return False
        removed = await UnblockSenderExecutor().execute(
            ActionRequest(
                incident_id=result.action_id,
                tenant_id=result.action_id,
                action_type=ActionType.UNBLOCK_SENDER,
                target=mailbox,
                parameters=data,
            )
        )
        return removed.status == ActionStatus.COMPLETED


class UnblockSenderExecutor(_MailboxExecutor):
    """The declared reverse of ``block_sender``."""

    action_type = ActionType.UNBLOCK_SENDER

    async def execute(self, request: ActionRequest) -> ActionResult:
        vendor, client, early = self._preamble(request)
        if early is not None:
            return early
        params = dict(request.parameters or {})
        rule_id = str(params.get("rule_id") or params.get("filter_id") or "")
        if not rule_id:
            return self._refused(request, "unblock_sender needs the rule_id block_sender returned", vendor=vendor)
        try:
            if vendor == M365:
                await client.delete_inbox_rule(request.target, rule_id)
            else:
                await client.delete_filter(request.target, rule_id)
        except Exception as exc:  # noqa: BLE001
            return self._failed(request, vendor, exc)
        return self._ok(
            request,
            vendor,
            {"mailbox": request.target, "rule_id": rule_id, "summary": f"sender block removed from {request.target}"},
        )


__all__ = [
    "BlockSenderExecutor",
    "DISABLED_REASON",
    "GMAIL_CLIENT_PARAM_KEYS",
    "GOOGLE_WORKSPACE",
    "M365",
    "M365_CLIENT_PARAM_KEYS",
    "NO_CREDENTIALS_REASON",
    "PurgeEmailExecutor",
    "RECOVERABLE_ITEMS",
    "RestoreEmailExecutor",
    "UnblockSenderExecutor",
    "choose_vendor",
]
