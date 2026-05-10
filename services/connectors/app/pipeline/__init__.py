"""Pre-ingest pipeline: schema fingerprinting and event filtering.

This package owns the *connector-side* half of two related features:

* **Connector Health & Schema-Drift Sentinel** — fingerprints each batch
  of normalized events so the scheduler can detect when an upstream API
  starts returning a different field set (silent integration breakage).

* **Security Data Pipeline + Tiered Retention** — applies a list of
  declarative filter rules (drop / route) before events leave the
  connectors microservice, so noisy events never reach the hot tier.

Both helpers are pure functions that take a list of events and return
something useful. They never touch the database, the network, or the
scheduler state — that's the scheduler's job.
"""

from __future__ import annotations

from app.pipeline.filter_rules import FilterDecision, apply_filter_rules
from app.pipeline.fingerprint import compute_fingerprint, diff_fingerprints

__all__ = [
    "FilterDecision",
    "apply_filter_rules",
    "compute_fingerprint",
    "diff_fingerprints",
]
