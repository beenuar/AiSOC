"""k-anonymity + differential-privacy aggregator over the signal ledger.

This is the ONLY module that reads :class:`FederatedSignal` rows for
the purpose of serving a query. Two privacy primitives are layered:

* **k-anonymity gate.** If fewer than ``federation_k_anonymity``
  *distinct* tenants have contributed for a ``(signal_class,
  signal_key)`` within the ingest window AND under live consent, the
  aggregator refuses to emit a count. ``meets_k_anonymity=False`` is
  the only signal the caller gets — they don't learn how many tenants
  contributed (which would itself leak information at small N).

* **Differential privacy (Laplace).** Counts that pass the gate are
  perturbed with one fresh draw from ``Laplace(0, Δf/ε)`` per call.
  Repeated queries leak ε per call by composition; the caller is
  expected to rate-limit and budget. This module enforces neither —
  it produces honest noise per request and lets the surrounding layer
  enforce policy.

The aggregator NEVER returns ``tenant_id`` or any list of
contributors. It returns one of:

* :class:`FederatedAggregate` with ``meets_k_anonymity=True`` and a
  ``noisy_count``; or
* :class:`FederatedAggregate` with ``meets_k_anonymity=False`` and
  ``noisy_count=None``.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import func
from sqlmodel import Session, select

from app.config import settings
from app.federated.consent import has_active_consent
from app.models.federated import (
    FederatedSignal,
    FederationConsent,
    SignalClass,
)


@dataclass(frozen=True)
class FederatedAggregate:
    """Result of an aggregator query.

    ``signal_class`` and ``signal_key`` are echoed back so the caller
    can correlate; ``noisy_count`` is the DP-perturbed count of
    distinct contributing tenants when the k-gate passed, or ``None``
    when it did not. ``meets_k_anonymity`` is the boolean flag.

    The dataclass is frozen so callers can't mutate the result and
    confuse audit logs.
    """

    signal_class: SignalClass
    signal_key: str
    meets_k_anonymity: bool
    noisy_count: Optional[float]


def _laplace_noise(epsilon: float, sensitivity: float) -> float:
    """Draw one sample from Laplace(0, sensitivity / epsilon).

    Uses ``random.random()`` rather than :mod:`secrets` deliberately:
    DP noise wants a smooth distribution, not unguessable randomness.
    Tests can monkey-patch :func:`random.random` to make outputs
    deterministic. The CSPRNG matters for keys, not for noise.
    """

    if epsilon <= 0 or sensitivity <= 0:
        return 0.0
    scale = sensitivity / epsilon
    u = random.random() - 0.5
    # sign(u) * -scale * ln(1 - 2|u|)
    import math

    return -scale * math.copysign(math.log1p(-2 * abs(u)), u)


def aggregate_signal(
    session: Session,
    *,
    requester_tenant_id: str,
    signal_class: SignalClass,
    signal_key: str,
    window_days: int | None = None,
    k: int | None = None,
    epsilon: float | None = None,
    sensitivity: float | None = None,
) -> FederatedAggregate:
    """Query the count of distinct tenants contributing ``signal_key``.

    ``requester_tenant_id`` MUST itself hold active consent for the
    requested ``signal_class`` — you can only read the pool you
    contribute to. This keeps the federation reciprocal and prevents
    one-way scraping.

    The count is computed over signals within the last ``window_days``
    AND whose contributing tenants currently hold active consent. A
    tenant that opted out has its contributions excluded immediately
    on the next query, without a separate purge step.
    """

    k_threshold = k if k is not None else settings.federation_k_anonymity
    eps = epsilon if epsilon is not None else settings.federation_dp_epsilon
    sens = (
        sensitivity
        if sensitivity is not None
        else settings.federation_dp_sensitivity
    )
    window = window_days or settings.federation_window_days
    cutoff = datetime.now(timezone.utc) - timedelta(days=window)

    if not has_active_consent(
        session,
        tenant_id=requester_tenant_id,
        signal_class=signal_class,
    ):
        # Reciprocity: a non-contributor reads nothing. We return the
        # same shape as a k-fail so callers can't distinguish "no
        # consent" from "below k" — both look like "no answer for you".
        return FederatedAggregate(
            signal_class=signal_class,
            signal_key=signal_key,
            meets_k_anonymity=False,
            noisy_count=None,
        )

    # Count distinct contributing tenants for this (class, key) in
    # window, joined to active consent so opted-out tenants drop out.
    stmt = (
        select(func.count(func.distinct(FederatedSignal.tenant_id)))
        .join(
            FederationConsent,
            (FederationConsent.tenant_id == FederatedSignal.tenant_id)
            & (FederationConsent.signal_class == FederatedSignal.signal_class),
        )
        .where(FederatedSignal.signal_class == signal_class)
        .where(FederatedSignal.signal_key == signal_key)
        .where(FederatedSignal.contributed_at >= cutoff)
        .where(FederationConsent.active.is_(True))  # type: ignore[union-attr]
        .where(
            FederationConsent.terms_hash == settings.federation_terms_hash
        )
    )
    true_count = session.exec(stmt).one()
    # SQLModel/SA may return either an int or a 1-tuple depending on
    # dialect; normalize.
    if isinstance(true_count, tuple):
        true_count = true_count[0]
    true_count = int(true_count or 0)

    if true_count < k_threshold:
        return FederatedAggregate(
            signal_class=signal_class,
            signal_key=signal_key,
            meets_k_anonymity=False,
            noisy_count=None,
        )

    noisy = float(true_count) + _laplace_noise(eps, sens)
    # Clamp at zero — a negative count is never useful and would be a
    # confusing artifact of the noise mechanism for downstream UIs.
    if noisy < 0:
        noisy = 0.0
    return FederatedAggregate(
        signal_class=signal_class,
        signal_key=signal_key,
        meets_k_anonymity=True,
        noisy_count=noisy,
    )
