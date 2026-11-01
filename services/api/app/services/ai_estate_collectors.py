"""Run the AI-estate collectors and write what they find.

Depth plan wave 2, Phases 7.1 and 7.2.

Why this module exists at all
------------------------------
Because without it the previous commits were unreachable code.
`check_module_reachability` said so, in exactly the words this repository
has earned the hard way: *"A test that imports one of these proves the code
compiles, not that it runs."* The classifier, the compliance client, the
repository scanner and the hosted-agent client each had a suite and no
production caller, which is the "mechanism exists, nothing calls it" family
the platform keeps finding in its own tree — a passing test on an uncalled
function is indistinguishable from a working feature until somebody traces
the call graph.

So this is the call graph: three collectors, each reached from a route a
console button presses.

What is deliberately *not* here
--------------------------------
A scheduler. Every collector reaches a third party with a tenant's own
credential, and the plan's rule for anything that reaches out is off by
default and enabled per tenant. A background loop that started polling the
moment a key was saved would be a reasonable product decision and a
different one from the decision recorded in ADR-0021, so collection is
explicit: the tenant configures, and the tenant (or an operator on their
behalf) runs it.

Every write goes through the one `score_risk`
----------------------------------------------
Both asset collectors build an `attributes` blob keyed to what `score_risk`
already reads and call it directly. There is no second scorer, which the
plan forbids for Phase 7.2 by name and which this repository has paid for
twice.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.models.ai_asset import AiAsset
from app.models.ai_chat_compliance import (
    AiChatAuditEvent,
    AiChatComplianceConfig,
    AiChatContentLabel,
    AiChatProject,
    AiChatUser,
)
from app.security.credential_vault import CredentialVaultError, get_vault
from app.services.ai_chat_compliance.client import AiChatComplianceClient, ComplianceKeyTypeError
from app.services.ai_inventory import score_risk
from app.services.ai_repo_scan import RepoAiArtifact, scan_repository
from app.services.hosted_agents import HostedAgentClient

logger = structlog.get_logger()

#: How many conversations one collection pass will classify. Bounded
#: because the content path reads message bodies: an unbounded pass over a
#: large tenant would hold a lot of other people's text in memory at once,
#: and the point of this feature is to hold as little as possible.
MAX_CHATS_PER_PASS = 200


@dataclass
class CollectionResult:
    """What one pass did, per sink.

    Per sink rather than one total, because a one-sink number presented as
    the operation's result reads as total failure when the other sinks
    worked — the shape that reported `indexed: 0` beside a successful write
    of 1,739 rows on the very next line.
    """

    users: int = 0
    projects: int = 0
    events: int = 0
    content_labels: int = 0
    assets: int = 0
    #: Stated rather than inferred from a zero. "Nothing was collected"
    #: and "we could not collect" are different answers.
    errors: list[str] = field(default_factory=list)
    #: Which sinks were deliberately not attempted, with the reason.
    skipped: dict[str, str] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "users": self.users,
            "projects": self.projects,
            "events": self.events,
            "contentLabels": self.content_labels,
            "assets": self.assets,
            "errors": self.errors,
            "skipped": self.skipped,
        }


def _decrypt(ciphertext: str) -> str:
    return get_vault().decrypt(ciphertext)


async def collect_chat_compliance(db: Any, tenant_id: uuid.UUID) -> CollectionResult:
    """One pass over a tenant's AI-chat compliance API.

    Reads the directory and the activity feed; classifies conversation
    content only if the tenant opted in a second time. Returns per-sink
    counts and the reason for anything not attempted.
    """
    result = CollectionResult()
    config = (await db.execute(select(AiChatComplianceConfig).where(AiChatComplianceConfig.tenant_id == tenant_id))).scalar_one_or_none()

    if config is None:
        result.skipped["all"] = "no configuration for this tenant; collection is off by default"
        return result
    if not config.enabled:
        result.skipped["all"] = "collection is configured but disabled"
        return result

    try:
        key = _decrypt(config.access_key_vault)
    except CredentialVaultError as exc:
        # Refused rather than treated as "no key". An unreadable credential
        # is an operator problem, and reporting it as an empty estate is
        # the vacuous-zero failure in its most misleading form.
        result.errors.append(f"could not decrypt the stored key: {exc}")
        config.last_error = result.errors[-1]
        await db.commit()
        return result

    client = AiChatComplianceClient(key)
    now = datetime.now(UTC)

    try:
        activities, cursor = await client.list_activities(cursor=config.activity_cursor)
        for record in activities:
            if await _upsert_audit_event(db, tenant_id, config.provider, record, now):
                result.events += 1
        config.activity_cursor = cursor
    except Exception as exc:  # noqa: BLE001 — one sink failing must not stop the others
        result.errors.append(f"activity feed: {type(exc).__name__}: {exc}")

    if not client.reaches_content:
        # Stated, not silent. An Admin API key reaches the activity feed
        # and is answered 403 everywhere else, and an operator reading four
        # authorisation failures would reasonably conclude their key is
        # wrong when the key is fine and the *type* is not.
        result.skipped["directory"] = "the stored key is an Admin API key, which reaches the activity feed only"
        result.skipped["content"] = result.skipped["directory"]
    else:
        try:
            for org in await client.list_organizations():
                org_uuid = str(org.get("uuid") or "")
                if not org_uuid:
                    continue
                for user in await client.list_users(org_uuid):
                    if await _upsert_chat_user(db, tenant_id, config.provider, org_uuid, user, now):
                        result.users += 1
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"directory: {type(exc).__name__}: {exc}")

        if not config.content_labels_enabled:
            result.skipped["content"] = "content classification is off; it is a second, narrower opt-in"
        else:
            try:
                for ref in (await client.list_chats())[:MAX_CHATS_PER_PASS]:
                    classification = await client.classify_chat(ref.external_id)
                    if await _upsert_project(db, tenant_id, config.provider, ref, now):
                        result.projects += 1
                    # A chat that evidenced nothing is not stored. A row
                    # with an empty label set and a snippet would be a kept
                    # fragment of a conversation that showed nothing, which
                    # is precisely what this feature must not accumulate.
                    if classification.labels:
                        await _upsert_content_label(db, tenant_id, config.provider, ref, classification, now)
                        result.content_labels += 1
            except ComplianceKeyTypeError as exc:
                result.skipped["content"] = str(exc)
            except Exception as exc:  # noqa: BLE001
                result.errors.append(f"content: {type(exc).__name__}: {exc}")

    config.last_collected_at = now
    config.last_error = "; ".join(result.errors) if result.errors else None
    await db.commit()
    logger.info("ai_chat_compliance.collected", tenant_id=str(tenant_id), **result.as_dict())
    return result


async def _upsert_audit_event(db: Any, tenant_id: uuid.UUID, provider: str, record: dict, now: datetime) -> bool:
    external_id = str(record.get("id") or "")
    if not external_id:
        return False
    raw_actor = record.get("actor")
    actor: dict[str, Any] = raw_actor if isinstance(raw_actor, dict) else {}
    stmt = (
        pg_insert(AiChatAuditEvent.__table__)
        .values(
            tenant_id=tenant_id,
            provider=provider,
            external_id=external_id,
            event_type=str(record.get("type") or "unknown")[:128],
            occurred_at=_parse_time(record.get("created_at")) or now,
            actor_email=_clip(actor.get("email_address"), 320),
            actor_external_id=_clip(actor.get("user_id"), None),
            actor_ip=_clip(actor.get("ip_address"), 45),
            provider_org_id=_clip(record.get("organization_uuid"), None),
            chat_external_id=_clip(record.get("claude_chat_id"), None),
            project_external_id=_clip(record.get("claude_project_id"), None),
            collected_at=now,
        )
        .on_conflict_do_nothing(constraint="aisoc_ai_chat_audit_events_identity")
    )
    return bool((await db.execute(stmt)).rowcount)


async def _upsert_chat_user(db: Any, tenant_id: uuid.UUID, provider: str, org: str, user: dict, now: datetime) -> bool:
    external_id = str(user.get("id") or "")
    if not external_id:
        return False
    stmt = (
        pg_insert(AiChatUser.__table__)
        .values(
            tenant_id=tenant_id,
            provider=provider,
            external_id=external_id,
            email=_clip(user.get("email_address"), 320),
            display_name=_clip(user.get("name") or user.get("display_name"), 200),
            role=_clip(user.get("role"), 64),
            provider_org_id=org,
            collected_at=now,
        )
        .on_conflict_do_update(
            constraint="aisoc_ai_chat_users_identity",
            set_={"role": _clip(user.get("role"), 64), "collected_at": now},
        )
    )
    return bool((await db.execute(stmt)).rowcount)


async def _upsert_project(db: Any, tenant_id: uuid.UUID, provider: str, ref: Any, now: datetime) -> bool:
    if not ref.project_external_id:
        return False
    stmt = (
        pg_insert(AiChatProject.__table__)
        .values(
            tenant_id=tenant_id,
            provider=provider,
            external_id=ref.project_external_id,
            provider_org_id=ref.org_uuid,
            owner_email=_clip(ref.actor_email, 320),
            collected_at=now,
        )
        .on_conflict_do_nothing(constraint="aisoc_ai_chat_projects_identity")
    )
    return bool((await db.execute(stmt)).rowcount)


async def _upsert_content_label(db: Any, tenant_id: uuid.UUID, provider: str, ref: Any, result: Any, now: datetime) -> None:
    values = {
        "labels": list(result.labels),
        "secret_kinds": list(result.secret_kinds),
        # Already masked and already cut by the classifier. The column's
        # VARCHAR(280) is the backstop, not the cut.
        "snippet": result.snippet,
        "snippet_truncated": result.snippet_truncated,
        "messages_examined": result.messages_examined,
        "messages_matched": result.messages_matched,
        "collected_at": now,
    }
    stmt = (
        pg_insert(AiChatContentLabel.__table__)
        .values(
            tenant_id=tenant_id,
            provider=provider,
            chat_external_id=ref.external_id,
            project_external_id=ref.project_external_id,
            actor_email=_clip(ref.actor_email, 320),
            provider_org_id=ref.org_uuid,
            occurred_at=_parse_time(ref.occurred_at) or now,
            **values,
        )
        .on_conflict_do_update(constraint="aisoc_ai_chat_content_labels_identity", set_=values)
    )
    await db.execute(stmt)


async def collect_hosted_agents(db: Any, tenant_id: uuid.UUID, admin_key: str) -> CollectionResult:
    """Inventory a provider's hosted agents as AI assets."""
    result = CollectionResult()
    try:
        agents = await HostedAgentClient(admin_key).list_agents()
    except Exception as exc:  # noqa: BLE001
        result.errors.append(f"hosted agents: {type(exc).__name__}: {exc}")
        return result

    for agent in agents:
        await _upsert_asset(
            db,
            tenant_id=tenant_id,
            kind="hosted_agent",
            external_id=agent.external_id,
            display_name=agent.name,
            vendor="anthropic",
            discovery_source="provider_admin",
            principal=agent.owner,
            attributes=agent.attributes(),
        )
        result.assets += 1
    await db.commit()
    logger.info("ai_estate.hosted_agents_collected", tenant_id=str(tenant_id), assets=result.assets)
    return result


async def scan_repositories_for_ai_config(db: Any, tenant_id: uuid.UUID, repositories: dict[str, dict[str, str]]) -> CollectionResult:
    """Record the AI configuration a set of repositories carries.

    `repositories` is ``repo -> {path: content}``, as a code-platform
    connector returns it. The scan itself is in `ai_repo_scan`, which
    sanitises and injection-scans everything it reads before any of it
    reaches a column — see that module's header for why every byte of this
    is treated as attacker-controlled.
    """
    result = CollectionResult()
    for repository, files in repositories.items():
        for artifact in scan_repository(repository, files):
            await _upsert_repo_artifact(db, tenant_id, artifact)
            result.assets += 1
    await db.commit()
    logger.info("ai_estate.repositories_scanned", tenant_id=str(tenant_id), assets=result.assets)
    return result


async def _upsert_repo_artifact(db: Any, tenant_id: uuid.UUID, artifact: RepoAiArtifact) -> None:
    await _upsert_asset(
        db,
        tenant_id=tenant_id,
        kind="repo_ai_artifact",
        # Repository plus path: the same skill file in two repositories is
        # two assets, because the review decision is per repository.
        external_id=f"{artifact.repository}:{artifact.path}",
        display_name=artifact.name,
        vendor=None,
        discovery_source="code_platform",
        principal=None,
        attributes=artifact.attributes(),
    )


async def _upsert_asset(
    db: Any,
    *,
    tenant_id: uuid.UUID,
    kind: str,
    external_id: str,
    display_name: str | None,
    vendor: str | None,
    discovery_source: str,
    principal: str | None,
    attributes: dict[str, Any],
) -> None:
    """One asset, scored by the one `score_risk`.

    `sanctioned` is read from the existing row rather than reset, because
    a collection pass must not undo an operator's judgement — and because
    the sanction state is an *input* to the score: an asset reviewed and
    refused that is still running scores differently from one nobody has
    looked at.
    """
    existing = (
        await db.execute(
            select(AiAsset).where(
                AiAsset.tenant_id == tenant_id,
                AiAsset.kind == kind,
                AiAsset.external_id == external_id,
            )
        )
    ).scalar_one_or_none()
    sanctioned = existing.sanctioned if existing is not None else None

    score, reasons = score_risk(
        kind=kind,
        principal=principal,
        device=None,
        sanctioned=sanctioned,
        attributes=attributes,
        effective_permissions=existing.effective_permissions if existing is not None else None,
    )

    now = datetime.now(UTC)
    if existing is not None:
        existing.display_name = display_name
        existing.attributes = attributes
        existing.risk_score = score
        existing.risk_reasons = reasons
        existing.last_seen_at = now
        existing.observation_count = (existing.observation_count or 0) + 1
        return

    db.add(
        AiAsset(
            tenant_id=tenant_id,
            kind=kind,
            external_id=external_id,
            display_name=display_name,
            vendor=vendor,
            discovery_source=discovery_source,
            principal=principal,
            attributes=attributes,
            risk_score=score,
            risk_reasons=reasons,
            first_seen_at=now,
            last_seen_at=now,
            observation_count=1,
        )
    )


def _clip(value: Any, limit: int | None) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    return text[:limit] if limit else text


def _parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
