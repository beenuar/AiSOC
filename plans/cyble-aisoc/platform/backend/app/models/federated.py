"""Cross-tenant federated signal aggregation models (t3b-federated).

Two append-only tables underpin opt-in, k-anonymity-gated, differentially
private signal sharing across tenants:

- :class:`FederationConsent` — per-tenant record of which **signal
  classes** the tenant has opted into. The federation aggregator
  ingests *only* the classes a tenant has live consent for; opt-out
  flips ``active=False`` and stops new ingest immediately. Past
  contributions remain in the ledger (we never silently erase the
  audit trail) but the ``deactivated_at`` timestamp gates which rows
  the aggregator may read.

- :class:`FederatedSignal` — append-only ledger of one tenant's
  contribution of a single, structured signal (e.g. "tenant T has
  observed IOC 1.2.3.4" or "tenant T has fired ATT&CK T1078 this
  week"). Tenant attribution is preserved *only* for audit and
  consent enforcement — every aggregation path scrubs ``tenant_id``
  before returning a row to a caller.

Design rules (these are the privacy guarantees we test in
``tests/test_federated_*``):

1. The aggregator NEVER returns ``tenant_id``, nor any list of
   contributors. Only ``noisy_count`` and a boolean
   ``meets_k_anonymity`` flag are exposed.

2. ``signal_class`` is a closed enum — adding a new class is a
   deliberate, reviewable code change. Free-text classes are not
   accepted.

3. ``signal_key`` is the public identifier (IOC value, ATT&CK
   technique ID). It MUST be non-PII by construction — the ingest
   step refuses values that look like emails, usernames, host
   names, or anything that could re-identify a tenant.

4. ``payload`` is bounded to a small, allow-listed shape per
   ``signal_class`` (see :mod:`app.federated.ingest`). Free-form
   JSON is not allowed in.

The aggregator's k-anonymity and differential-privacy logic lives
in :mod:`app.federated.aggregator` — these models intentionally
hold *no* policy, just the ledger.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from sqlmodel import JSON, Column, Field, SQLModel


class SignalClass(str, Enum):
    """Closed enum of signal kinds the federation will ever ingest.

    Adding a member requires (a) updating the
    :mod:`app.federated.ingest` allow-listed payload schema for the
    new class and (b) a privacy review — the test suite refuses
    classes whose payloads carry free-text or PII-shaped fields.
    """

    IOC = "ioc"
    """A single IOC (IP/domain/hash/etc.) observed by the tenant.

    ``signal_key`` is the IOC value (already non-PII by definition);
    ``payload`` is bounded to ``{"ioc_type": str, "score_bucket": str}``.
    """

    MITRE_TECHNIQUE = "mitre_technique"
    """An ATT&CK technique ID that fired on at least one open/closed
    case for the tenant in the rolling window.

    ``signal_key`` is the technique ID (e.g. ``T1078``); ``payload``
    is bounded to ``{"severity_bucket": str}``.
    """

    DETECTION_EFFICACY = "detection_efficacy"
    """Aggregate efficacy datapoint for a Sigma rule on the tenant.

    ``signal_key`` is the rule id (uuid or stable slug); ``payload``
    is bounded to ``{"verdict": str, "fired_bucket": str}``.
    """


class FederationConsent(SQLModel, table=True):
    """Per-tenant opt-in / opt-out record for a single signal class.

    There is at most one *active* row per (tenant_id, signal_class).
    Opt-out flips ``active=False`` and stamps ``deactivated_at`` — we
    keep the row so the audit log shows when consent was withdrawn.
    A subsequent opt-in writes a fresh row; we never resurrect a
    deactivated row, because the ``terms_hash`` it was granted under
    may have changed and consent is bound to that hash.
    """

    id: Optional[int] = Field(default=None, primary_key=True)
    tenant_id: str = Field(index=True)
    signal_class: SignalClass = Field(index=True)
    # SHA-256 of the consent terms the tenant accepted. If the
    # operator updates the terms and a tenant has not re-consented
    # under the new hash, the aggregator drops their contributions
    # from the next run.
    terms_hash: str
    active: bool = Field(default=True, index=True)
    granted_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        index=True,
    )
    deactivated_at: Optional[datetime] = Field(default=None, index=True)
    # Who flipped the switch (audit). For UI grant: the user subject;
    # for system opt-in (e.g. CLI bootstrap): a system identifier.
    granted_by: str = "system"


class FederatedSignal(SQLModel, table=True):
    """One tenant's contribution of a single bounded signal.

    The aggregator only reads rows whose ``(tenant_id, signal_class)``
    is currently consented (see :class:`FederationConsent`). Every
    aggregation path strips ``tenant_id`` before returning rows; this
    column exists exclusively for consent enforcement and for the
    "drop my contributions" path that opt-out triggers.
    """

    id: Optional[int] = Field(default=None, primary_key=True)
    tenant_id: str = Field(index=True)
    signal_class: SignalClass = Field(index=True)
    signal_key: str = Field(index=True)
    payload: dict = Field(default_factory=dict, sa_column=Column(JSON))
    contributed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        index=True,
    )
