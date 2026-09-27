"""Reading the consent and writing the audit row.

Kept apart from :mod:`app.services.sandbox.policy`, which is pure and knows
nothing about a database, so every combination of the policy can be driven in a
test without one. This module is the only thing that turns a row into the
``tenant_uploads_enabled`` boolean the policy takes.

The tenant is always an argument, never a request field: every caller here
receives it from the authenticated principal, and every statement binds it.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.sandbox.policy import CONSENT_TEXT_VERSION
from app.services.sandbox.service import SandboxResult

log = structlog.get_logger(__name__)

__all__ = ["UploadConsent", "list_consent", "read_consent", "record_decision", "set_consent"]


@dataclass(frozen=True, slots=True)
class UploadConsent:
    provider: str
    uploads_enabled: bool
    consent_text_version: str | None = None
    consented_by: uuid.UUID | None = None
    consented_at: str | None = None


async def read_consent(db: AsyncSession, *, tenant_id: uuid.UUID, provider: str) -> bool:
    """Whether this tenant has consented to uploads to this provider.

    A missing row is a ``False``, not an error. Consent is the presence of an
    affirmative record, so "no row" and "row saying no" mean the same thing and
    neither needs to be created before the first refusal can be logged.
    """
    row = (
        await db.execute(
            text(
                "SELECT uploads_enabled FROM aisoc_sandbox_upload_policy WHERE tenant_id = :tenant_id AND provider = :provider"
            ).bindparams(tenant_id=tenant_id, provider=provider)
        )
    ).fetchone()
    return bool(row.uploads_enabled) if row else False


async def list_consent(db: AsyncSession, *, tenant_id: uuid.UUID) -> list[UploadConsent]:
    rows = (
        await db.execute(
            text(
                "SELECT provider, uploads_enabled, consent_text_version, consented_by, consented_at "
                "FROM aisoc_sandbox_upload_policy WHERE tenant_id = :tenant_id ORDER BY provider"
            ).bindparams(tenant_id=tenant_id)
        )
    ).fetchall()
    return [
        UploadConsent(
            provider=r.provider,
            uploads_enabled=bool(r.uploads_enabled),
            consent_text_version=r.consent_text_version,
            consented_by=r.consented_by,
            consented_at=r.consented_at.isoformat() if r.consented_at else None,
        )
        for r in rows
    ]


async def set_consent(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    provider: str,
    enabled: bool,
    actor_id: uuid.UUID | None,
) -> UploadConsent:
    """Record a consent decision, with who made it and which text they saw.

    Turning consent *off* clears the attribution, because the recorded agreement
    no longer describes the state of the row and leaving it there would suggest
    somebody agreed to the current setting.
    """
    await db.execute(
        text("""
            INSERT INTO aisoc_sandbox_upload_policy
                (tenant_id, provider, uploads_enabled, consent_text_version, consented_by, consented_at, updated_at)
            VALUES
                (:tenant_id, :provider, :enabled,
                 CASE WHEN :enabled THEN :version ELSE NULL END,
                 CASE WHEN :enabled THEN :actor ELSE NULL END,
                 CASE WHEN :enabled THEN NOW() ELSE NULL END,
                 NOW())
            ON CONFLICT (tenant_id, provider) DO UPDATE SET
                uploads_enabled      = EXCLUDED.uploads_enabled,
                consent_text_version = EXCLUDED.consent_text_version,
                consented_by         = EXCLUDED.consented_by,
                consented_at         = EXCLUDED.consented_at,
                updated_at           = NOW()
        """).bindparams(
            tenant_id=tenant_id,
            provider=provider,
            enabled=enabled,
            version=CONSENT_TEXT_VERSION,
            actor=actor_id,
        )
    )
    await db.commit()
    log.info(
        "sandbox.consent_changed",
        tenant_id=str(tenant_id),
        provider=provider,
        uploads_enabled=enabled,
        consent_text_version=CONSENT_TEXT_VERSION if enabled else None,
    )
    return UploadConsent(
        provider=provider,
        uploads_enabled=enabled,
        consent_text_version=CONSENT_TEXT_VERSION if enabled else None,
        consented_by=actor_id if enabled else None,
    )


async def record_decision(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    result: SandboxResult,
    artifact_kind: str,
    file_name: str | None = None,
    actor_id: uuid.UUID | None = None,
) -> None:
    """Append the audit row for one decision, allowed or refused.

    Fail-soft on purpose: a sandbox lookup must not 500 because the audit
    insert failed. It logs at ``warning`` with the outcome it could not store,
    so a missing row is visible in the log pipeline rather than silent.
    """
    try:
        await db.execute(
            text("""
                INSERT INTO aisoc_sandbox_submissions
                    (tenant_id, provider, artifact_kind, sha256, file_name, outcome,
                     refusal, reason, uploaded, visibility, provider_handle, requested_by)
                VALUES
                    (:tenant_id, :provider, :kind, :sha256, :file_name, :outcome,
                     :refusal, :reason, :uploaded, :visibility, :handle, :actor)
            """).bindparams(
                tenant_id=tenant_id,
                provider=result.provider,
                kind=artifact_kind,
                sha256=result.sha256,
                file_name=file_name,
                outcome=result.outcome,
                refusal=result.decision.refusal.value if result.decision and result.decision.refusal else None,
                reason=result.detail[:2000],
                uploaded=result.uploaded,
                visibility=(result.receipt.visibility if result.receipt else None) or (result.report.visibility if result.report else None),
                handle=result.receipt.handle if result.receipt else None,
                actor=actor_id,
            )
        )
        await db.commit()
    except Exception as exc:  # noqa: BLE001 - never fail a lookup over its audit row
        await db.rollback()
        log.warning(
            "sandbox.audit_write_failed",
            tenant_id=str(tenant_id),
            provider=result.provider,
            outcome=result.outcome,
            uploaded=result.uploaded,
            error=str(exc),
        )
