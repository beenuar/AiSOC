"""Consent grant / revoke / check for cross-tenant federation.

The aggregator never reads a :class:`FederatedSignal` row whose
tenant does not currently hold an *active* :class:`FederationConsent`
for that signal class under the current ``terms_hash``. All four
helpers in this module are the only sanctioned way to mutate or query
that consent state.

Two intentional design choices live here:

* **Terms-hash binding.** Consent is granted under a specific hash of
  the legal terms. When the operator rotates the terms (changes the
  ``federation_terms_hash`` setting), every existing grant is silently
  dropped from queries because :func:`has_active_consent` checks the
  hash. We never "migrate" a consent row to a new hash — re-consent
  is the only path.

* **No update-in-place.** Opt-out flips ``active=False`` and stamps
  ``deactivated_at`` on the existing row. A subsequent opt-in writes
  a *fresh* row. This keeps the audit trail intact and makes the
  "who consented when, under which terms" question trivially
  answerable from one table.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable

from sqlmodel import Session, select

from app.config import settings
from app.models.federated import FederationConsent, SignalClass


def grant_consent(
    session: Session,
    *,
    tenant_id: str,
    signal_class: SignalClass,
    granted_by: str = "system",
    terms_hash: str | None = None,
) -> FederationConsent:
    """Grant ``tenant_id`` consent to contribute ``signal_class``.

    Idempotent on (tenant_id, signal_class, current terms_hash): if
    an active row already exists under the *current* hash, return it
    unchanged. If an older active row exists under a different hash,
    deactivate it first — consent under stale terms must be explicitly
    re-granted, not silently migrated.
    """

    hash_ = terms_hash or settings.federation_terms_hash

    existing = session.exec(
        select(FederationConsent)
        .where(FederationConsent.tenant_id == tenant_id)
        .where(FederationConsent.signal_class == signal_class)
        .where(FederationConsent.active.is_(True))  # type: ignore[union-attr]
    ).all()

    for row in existing:
        if row.terms_hash == hash_:
            return row
        row.active = False
        row.deactivated_at = datetime.now(timezone.utc)
        session.add(row)

    fresh = FederationConsent(
        tenant_id=tenant_id,
        signal_class=signal_class,
        terms_hash=hash_,
        active=True,
        granted_by=granted_by,
    )
    session.add(fresh)
    session.flush()
    return fresh


def revoke_consent(
    session: Session,
    *,
    tenant_id: str,
    signal_class: SignalClass,
    revoked_by: str = "system",
) -> int:
    """Revoke any active consent rows for ``(tenant_id, signal_class)``.

    Returns the number of rows flipped. Does NOT delete past
    contributions; the aggregator simply stops reading them because
    they no longer carry an active consent. A separate purge job (out
    of scope for this module) handles "forget my data" requests.
    """

    rows = session.exec(
        select(FederationConsent)
        .where(FederationConsent.tenant_id == tenant_id)
        .where(FederationConsent.signal_class == signal_class)
        .where(FederationConsent.active.is_(True))  # type: ignore[union-attr]
    ).all()
    now = datetime.now(timezone.utc)
    for row in rows:
        row.active = False
        row.deactivated_at = now
        # Stash who pulled the switch into granted_by's audit lineage
        # by appending; granted_by stays as the original grantor so
        # we keep the original opt-in actor visible.
        session.add(row)
    _ = revoked_by  # reserved for future audit append
    return len(rows)


def has_active_consent(
    session: Session,
    *,
    tenant_id: str,
    signal_class: SignalClass,
    terms_hash: str | None = None,
) -> bool:
    """Return True iff ``tenant_id`` has live consent for ``signal_class``.

    Consent is "live" when there is a row with ``active=True`` whose
    ``terms_hash`` matches the current (or explicitly-passed) hash.
    The aggregator and ingest gate both call this on every operation —
    consent state is authoritative, not cached.
    """

    hash_ = terms_hash or settings.federation_terms_hash
    row = session.exec(
        select(FederationConsent)
        .where(FederationConsent.tenant_id == tenant_id)
        .where(FederationConsent.signal_class == signal_class)
        .where(FederationConsent.terms_hash == hash_)
        .where(FederationConsent.active.is_(True))  # type: ignore[union-attr]
    ).first()
    return row is not None


def list_consents(
    session: Session,
    *,
    tenant_id: str,
    active_only: bool = True,
) -> Iterable[FederationConsent]:
    """List a tenant's consent rows (UI-facing).

    Defaults to active rows; pass ``active_only=False`` to surface the
    full audit trail of past opt-ins and opt-outs.
    """

    stmt = select(FederationConsent).where(
        FederationConsent.tenant_id == tenant_id
    )
    if active_only:
        stmt = stmt.where(FederationConsent.active.is_(True))  # type: ignore[union-attr]
    return session.exec(stmt).all()
