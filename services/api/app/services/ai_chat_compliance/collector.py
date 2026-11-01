"""Collect one tenant's AI-chat compliance records, and keep only labels.

The gap this closes, stated plainly: migration 146 shipped four tables, the
console shipped config CRUD and two read routes, and the client and
classifier beside this file shipped with their own tests — and **nothing
ever called them**. `aisoc_ai_chat_compliance_config` even carries
``activity_cursor``, ``last_collected_at`` and ``last_error``, three columns
that only a collector writes. A tenant could store a key, switch collection
on, and read an events page that was empty forever, which reads as "no AI
chat risk here" rather than as "nothing has ever looked".

`scripts/check_module_reachability.py` is what named it: a test that imports
a module proves the code compiles, not that it runs.

Two switches, and the narrower one is deliberately not implied by the wider.
``enabled`` turns on directory and activity collection. ``content_labels_enabled``
is a second opt-in covering anything derived from message text, and it is off
even when collection is on. Neither defaults on.

What crosses this boundary is bounded by construction rather than by
convention: :meth:`AiChatComplianceClient.classify_chat` fetches a
conversation, hands it to the classifier and lets it go out of scope, so no
caller here can reach a message. The row this writes has no column able to
hold one.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ai_chat_compliance import (
    AiChatAuditEvent,
    AiChatComplianceConfig,
    AiChatContentLabel,
    AiChatProject,
    AiChatUser,
)
from app.security.credential_vault import CredentialVaultError, get_vault

from .client import AiChatComplianceClient, ComplianceKeyTypeError

logger = structlog.get_logger(__name__)

#: How many conversations one run will classify. A tenant with ten thousand
#: chats must not turn one sync into ten thousand content reads, and the
#: cursor-less chat listing gives no way to resume, so the bound is explicit
#: and reported rather than implied by a timeout.
MAX_CHATS_PER_RUN = 200


@dataclass
class CollectionResult:
    """What one run did, in terms a caller can assert on.

    Counts are produced by the loops that write the rows, not by re-reading
    the tables afterwards: a meter asserted against a second call to the
    thing being measured measures nothing.
    """

    users: int = 0
    projects: int = 0
    events: int = 0
    content_labels: int = 0
    #: Conversations seen but not classified because the run hit
    #: :data:`MAX_CHATS_PER_RUN`. Reported so a partial pass cannot read as
    #: a complete one.
    chats_skipped: int = 0
    #: True when the key reaches the activity feed only, so content labels
    #: were not attempted. Distinct from "attempted and found nothing".
    content_unavailable: bool = False
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "users": self.users,
            "projects": self.projects,
            "events": self.events,
            "contentLabels": self.content_labels,
            "chatsSkipped": self.chats_skipped,
            "contentUnavailable": self.content_unavailable,
            "errors": list(self.errors),
        }


def _parsed(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


async def collect_for_tenant(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    *,
    client: AiChatComplianceClient | None = None,
    max_chats: int = MAX_CHATS_PER_RUN,
) -> CollectionResult:
    """Run one collection pass for ``tenant_id``.

    ``client`` is injectable so a test drives the real httpx stack through
    ``httpx.MockTransport`` rather than a hand-written double that would
    answer any URL and therefore prove nothing about the path.

    Returns a result even when a leg fails: a directory read that 403s must
    not discard the activity records already written. The failure is
    recorded on the config row and on the result, never swallowed.
    """
    result = CollectionResult()
    row = (await db.execute(select(AiChatComplianceConfig).where(AiChatComplianceConfig.tenant_id == tenant_id))).scalar_one_or_none()
    if row is None or not row.enabled:
        # Not an error. A tenant that has not opted in has nothing to collect,
        # and saying so is different from saying the provider returned nothing.
        result.errors.append("collection is not enabled for this tenant")
        return result

    if client is None:
        try:
            key = get_vault().decrypt(row.access_key_vault)
        except CredentialVaultError as exc:
            await _record_error(db, row, f"the stored key could not be decrypted: {exc}")
            result.errors.append("the stored key could not be decrypted")
            return result
        client = AiChatComplianceClient(key)

    now = datetime.now(UTC)
    org_uuid: str | None = None

    try:
        orgs = await client.list_organizations()
        org_uuid = str((orgs[0] or {}).get("uuid") or "") or None if orgs else None
    except Exception as exc:  # noqa: BLE001 — one failed leg must not lose the others
        result.errors.append(f"organisations: {type(exc).__name__}")
        logger.warning("ai_chat_compliance.orgs_failed", tenant_id=str(tenant_id), error=str(exc))

    if org_uuid:
        result.users = await _sync_users(db, row, tenant_id, client, org_uuid, result)
        result.projects = await _sync_projects(db, row, tenant_id, client, org_uuid, result)

    result.events = await _sync_activities(db, row, tenant_id, client, result)

    if row.content_labels_enabled:
        if not client.reaches_content:
            # The key type cannot read beyond the activity feed. Saying that
            # once beats recording an authorisation failure per conversation.
            result.content_unavailable = True
            result.errors.append("the stored key reaches the activity feed only; content labels need a Compliance Access Key")
        else:
            result.content_labels = await _sync_content_labels(db, row, tenant_id, client, max_chats, result)

    row.last_collected_at = now
    row.last_error = "; ".join(result.errors) if result.errors else None
    await db.commit()
    logger.info("ai_chat_compliance.collected", tenant_id=str(tenant_id), **result.as_dict())
    return result


async def _record_error(db: AsyncSession, row: AiChatComplianceConfig, message: str) -> None:
    row.last_error = message
    row.last_collected_at = datetime.now(UTC)
    await db.commit()


async def _sync_users(
    db: AsyncSession,
    row: AiChatComplianceConfig,
    tenant_id: uuid.UUID,
    client: AiChatComplianceClient,
    org_uuid: str,
    result: CollectionResult,
) -> int:
    try:
        members = await client.list_users(org_uuid)
    except Exception as exc:  # noqa: BLE001
        result.errors.append(f"users: {type(exc).__name__}")
        return 0

    existing = {
        r.external_id: r
        for r in (
            await db.execute(select(AiChatUser).where(AiChatUser.tenant_id == tenant_id, AiChatUser.provider == row.provider))
        ).scalars()
    }
    written = 0
    for member in members:
        external_id = str(member.get("id") or member.get("uuid") or "")
        if not external_id:
            continue
        user = member.get("user") if isinstance(member.get("user"), dict) else member
        email = (user or {}).get("email_address") or (user or {}).get("email")
        record = existing.get(external_id)
        if record is None:
            record = AiChatUser(
                id=uuid.uuid4(),
                tenant_id=tenant_id,
                provider=row.provider,
                external_id=external_id,
            )
            db.add(record)
        record.email = str(email) if email else None
        record.display_name = str((user or {}).get("name")) if (user or {}).get("name") else None
        written += 1
    return written


async def _sync_projects(
    db: AsyncSession,
    row: AiChatComplianceConfig,
    tenant_id: uuid.UUID,
    client: AiChatComplianceClient,
    org_uuid: str,
    result: CollectionResult,
) -> int:
    try:
        roles = await client.list_roles(org_uuid)
    except Exception as exc:  # noqa: BLE001
        result.errors.append(f"projects: {type(exc).__name__}")
        return 0

    existing = {
        r.external_id: r
        for r in (
            await db.execute(select(AiChatProject).where(AiChatProject.tenant_id == tenant_id, AiChatProject.provider == row.provider))
        ).scalars()
    }
    written = 0
    for item in roles:
        external_id = str(item.get("id") or item.get("uuid") or "")
        if not external_id:
            continue
        record = existing.get(external_id)
        if record is None:
            record = AiChatProject(
                id=uuid.uuid4(),
                tenant_id=tenant_id,
                provider=row.provider,
                external_id=external_id,
            )
            db.add(record)
        name = item.get("name")
        if name is not None and hasattr(record, "name"):
            record.name = str(name)
        written += 1
    return written


async def _sync_activities(
    db: AsyncSession,
    row: AiChatComplianceConfig,
    tenant_id: uuid.UUID,
    client: AiChatComplianceClient,
    result: CollectionResult,
) -> int:
    """Append activity records from the stored cursor.

    The cursor advances only when the page was read: a failed call leaves it
    where it was, so the next run re-reads rather than skipping a window.
    """
    try:
        records, cursor = await client.list_activities(cursor=row.activity_cursor)
    except Exception as exc:  # noqa: BLE001
        result.errors.append(f"activities: {type(exc).__name__}")
        return 0

    seen = {
        r.external_id
        for r in (
            await db.execute(
                select(AiChatAuditEvent.external_id).where(
                    AiChatAuditEvent.tenant_id == tenant_id,
                    AiChatAuditEvent.provider == row.provider,
                )
            )
        ).scalars()
    }
    written = 0
    for record in records:
        external_id = str(record.get("id") or record.get("uuid") or "")
        if not external_id or external_id in seen:
            continue
        actor = record.get("actor") if isinstance(record.get("actor"), dict) else {}
        occurred = _parsed(record.get("timestamp") or record.get("created_at")) or datetime.now(UTC)
        db.add(
            AiChatAuditEvent(
                id=uuid.uuid4(),
                tenant_id=tenant_id,
                provider=row.provider,
                external_id=external_id,
                event_type=str(record.get("type") or record.get("action") or "unknown")[:128],
                occurred_at=occurred,
                actor_email=str((actor or {}).get("email_address")) if (actor or {}).get("email_address") else None,
                actor_external_id=str((actor or {}).get("id")) if (actor or {}).get("id") else None,
                provider_org_id=str(record.get("organization_uuid")) if record.get("organization_uuid") else None,
            )
        )
        seen.add(external_id)
        written += 1

    if cursor:
        row.activity_cursor = cursor
    return written


async def _sync_content_labels(
    db: AsyncSession,
    row: AiChatComplianceConfig,
    tenant_id: uuid.UUID,
    client: AiChatComplianceClient,
    max_chats: int,
    result: CollectionResult,
) -> int:
    try:
        refs = await client.list_chats()
    except ComplianceKeyTypeError:
        result.content_unavailable = True
        result.errors.append("the stored key reaches the activity feed only; content labels need a Compliance Access Key")
        return 0
    except Exception as exc:  # noqa: BLE001
        result.errors.append(f"chats: {type(exc).__name__}")
        return 0

    if len(refs) > max_chats:
        result.chats_skipped = len(refs) - max_chats
        refs = refs[:max_chats]

    labelled = {
        r.chat_external_id
        for r in (
            await db.execute(
                select(AiChatContentLabel.chat_external_id).where(
                    AiChatContentLabel.tenant_id == tenant_id,
                    AiChatContentLabel.provider == row.provider,
                )
            )
        ).scalars()
    }
    written = 0
    for ref in refs:
        if ref.external_id in labelled:
            continue
        try:
            classification = await client.classify_chat(ref.external_id)
        except Exception as exc:  # noqa: BLE001 — one unreadable chat is not a failed run
            result.errors.append(f"chat {ref.external_id[:12]}: {type(exc).__name__}")
            continue
        if not classification.labels and not classification.shapes:
            # Nothing to record. A row asserting "this chat evidenced
            # nothing" is not evidence and would inflate the table.
            continue
        db.add(
            AiChatContentLabel(
                id=uuid.uuid4(),
                tenant_id=tenant_id,
                provider=row.provider,
                chat_external_id=ref.external_id,
                project_external_id=ref.project_external_id,
                actor_email=ref.actor_email,
                provider_org_id=ref.org_uuid,
                labels=list(classification.labels),
                secret_kinds=list(classification.secret_kinds),
                snippet=classification.snippet,
                snippet_truncated=classification.snippet_truncated,
                messages_examined=classification.messages_examined,
                messages_matched=classification.messages_matched,
                occurred_at=_parsed(ref.occurred_at) or datetime.now(UTC),
            )
        )
        written += 1
    return written


__all__ = ["MAX_CHATS_PER_RUN", "CollectionResult", "collect_for_tenant"]
