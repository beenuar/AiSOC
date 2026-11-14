"""Cross-tenant federated signal aggregation (t3b-federated).

The federation lets tenants opt into contributing **bounded, non-PII
signals** (IOC sightings, ATT&CK technique fires, detection efficacy)
to a shared pool that any consented tenant may query. The pool returns
*counts with Laplace noise*, gated by k-anonymity, and never the
identities of contributing tenants — the value to the customer is
"this IOC has been seen by ≥ k other defenders in the last N days",
not "tenant Acme saw it".

Privacy guarantees the test suite enforces:

* **Opt-in only.** A tenant that has not written a ``FederationConsent``
  row for a signal class contributes nothing and reads nothing for that
  class. Consent is bound to a ``terms_hash``; rotating the hash
  silently invalidates stale grants until the tenant re-consents.

* **Tenant identity is never returned.** Aggregator output exposes
  ``noisy_count`` and a boolean ``meets_k_anonymity`` flag. ``tenant_id``
  lives only in the ledger, used for consent enforcement and the
  opt-out / right-to-be-forgotten path.

* **k-anonymity gate.** If fewer than ``federation_k_anonymity``
  distinct tenants have contributed a given ``(signal_class,
  signal_key)`` in the window, the aggregator refuses to emit a count
  (``meets_k_anonymity=False``) — Laplace noise alone is not enough at
  small N.

* **Differential privacy.** Counts that pass the k gate are perturbed
  with Laplace noise calibrated to ``(ε, Δf)`` from
  :class:`app.config.Settings`. Honest queriers see the true count
  plus a draw from ``Laplace(0, Δf/ε)``; an adversary who repeats the
  query gets fresh noise each time.

* **Bounded ingest.** ``signal_key`` and ``payload`` are validated
  against an allow-listed shape per :class:`SignalClass` — free-text
  fields, emails, host names, or anything else that could re-identify
  a tenant are rejected before the row is written.

Module layout:

* :mod:`app.federated.consent` — grant / revoke / check consent.
* :mod:`app.federated.ingest` — accept a single tenant-local signal
  with strict, per-class payload validation.
* :mod:`app.federated.aggregator` — k-anonymity + differential privacy
  query path. The only place that reads from the ledger.
"""

from __future__ import annotations

from app.federated.aggregator import (
    FederatedAggregate,
    aggregate_signal,
)
from app.federated.consent import (
    grant_consent,
    has_active_consent,
    list_consents,
    revoke_consent,
)
from app.federated.ingest import (
    SignalIngestError,
    ingest_signal,
)

__all__ = [
    "FederatedAggregate",
    "SignalIngestError",
    "aggregate_signal",
    "grant_consent",
    "has_active_consent",
    "ingest_signal",
    "list_consents",
    "revoke_consent",
]
