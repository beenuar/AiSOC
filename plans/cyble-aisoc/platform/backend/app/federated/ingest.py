"""Bounded, validated ingest into the cross-tenant signal ledger.

Every write to :class:`FederatedSignal` flows through :func:`ingest_signal`.
The function is intentionally paranoid:

1. The contributing tenant MUST hold an active consent for the
   ``signal_class`` under the current ``terms_hash``. No consent → no
   ingest (and the caller gets a clear :class:`SignalIngestError`, not
   a silent drop, so misconfiguration is loud).

2. ``signal_key`` is validated against the per-class shape. The
   validators reject anything that looks like a username, email,
   hostname-with-tenant-name, etc. — the federation aggregates over
   *value-typed* keys (IP, hash, technique ID) only.

3. ``payload`` is reduced to an allow-listed dict of buckets. Free
   text, numerics outside fixed buckets, and unexpected keys are
   stripped. The aggregator MUST be able to assume a fixed schema per
   signal class — that property is enforced here once, not at every
   read site.

Anything that doesn't pass validation raises :class:`SignalIngestError`.
The caller (a connector, a scheduled job, an API route) is expected to
log and drop, not retry blindly.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from sqlmodel import Session

from app.federated.consent import has_active_consent
from app.models.federated import FederatedSignal, SignalClass


class SignalIngestError(ValueError):
    """Raised when a signal fails consent or shape validation.

    The message is safe to log — it never echoes the raw signal value
    back, only the reason for rejection.
    """


# ──────────────────────────────────────────────────────────────────────
# Key validators per signal class.
# ──────────────────────────────────────────────────────────────────────

_HASH_RE = re.compile(r"^[a-f0-9]{32,128}$")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63})+$"
)
_MITRE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
# A defensive bag of "this looks like PII" patterns. Not a complete
# PII detector — it's a tripwire for the obvious classes of mistakes
# (someone shoving an email or a username into signal_key).
_PII_LIKE = (
    re.compile(r"@"),  # email-ish
    re.compile(r"\s"),  # whitespace
    re.compile(r"^user[_-]?\d+$", re.IGNORECASE),
)


def _is_pii_shaped(value: str) -> bool:
    """Return True if ``value`` matches any obvious PII tripwire."""

    return any(p.search(value) for p in _PII_LIKE)


def _validate_ioc_key(key: str) -> None:
    """An IOC key is an IP, a domain, or a hex hash. Nothing else.

    Tenant-specific identifiers (hostnames, account IDs) leak the
    tenant — they're not IOCs in the federation sense and are rejected.
    """

    if _is_pii_shaped(key):
        raise SignalIngestError("ioc key has PII-shaped value")
    # IP?
    try:
        ipaddress.ip_address(key)
        return
    except ValueError:
        pass
    # Hash?
    if _HASH_RE.match(key):
        return
    # Domain?
    if _DOMAIN_RE.match(key.lower()):
        return
    raise SignalIngestError("ioc key must be ip, domain, or hex hash")


def _validate_mitre_key(key: str) -> None:
    if not _MITRE_RE.match(key):
        raise SignalIngestError("mitre key must look like Txxxx or Txxxx.yyy")


def _validate_detection_key(key: str) -> None:
    # Rule IDs are short, slug- or uuid-like. No spaces, no @, bounded
    # length. We deliberately don't require uuid v4 here — Sigma rules
    # often use slug ids, and we just need *not PII-shaped*.
    if _is_pii_shaped(key):
        raise SignalIngestError("detection key has PII-shaped value")
    if not (1 <= len(key) <= 128):
        raise SignalIngestError("detection key length out of bounds")
    if not re.match(r"^[A-Za-z0-9._:-]+$", key):
        raise SignalIngestError("detection key has unexpected characters")


# ──────────────────────────────────────────────────────────────────────
# Payload reducers per signal class. Each returns a *new* dict
# containing ONLY the allow-listed fields, with values normalized into
# buckets. Anything outside the allow-list is silently dropped — the
# caller can pass any shape they want; what survives into the ledger
# is bounded.
# ──────────────────────────────────────────────────────────────────────

_IOC_TYPES = {"ip", "domain", "url", "hash", "email_domain"}
_SCORE_BUCKETS = {"low", "medium", "high", "critical"}
_SEVERITY_BUCKETS = {"low", "medium", "high", "critical"}
_VERDICTS = {"true_positive", "false_positive", "benign", "unknown"}
_FIRED_BUCKETS = {"0", "1-9", "10-99", "100-999", "1000+"}


def _reduce_ioc_payload(payload: dict[str, Any]) -> dict[str, Any]:
    ioc_type = str(payload.get("ioc_type", "")).lower()
    score = str(payload.get("score_bucket", "")).lower()
    if ioc_type not in _IOC_TYPES:
        raise SignalIngestError("ioc payload.ioc_type not in allow-list")
    if score not in _SCORE_BUCKETS:
        raise SignalIngestError("ioc payload.score_bucket not in allow-list")
    return {"ioc_type": ioc_type, "score_bucket": score}


def _reduce_mitre_payload(payload: dict[str, Any]) -> dict[str, Any]:
    sev = str(payload.get("severity_bucket", "")).lower()
    if sev not in _SEVERITY_BUCKETS:
        raise SignalIngestError(
            "mitre payload.severity_bucket not in allow-list"
        )
    return {"severity_bucket": sev}


def _reduce_detection_payload(payload: dict[str, Any]) -> dict[str, Any]:
    verdict = str(payload.get("verdict", "")).lower()
    fired = str(payload.get("fired_bucket", ""))
    if verdict not in _VERDICTS:
        raise SignalIngestError(
            "detection payload.verdict not in allow-list"
        )
    if fired not in _FIRED_BUCKETS:
        raise SignalIngestError(
            "detection payload.fired_bucket not in allow-list"
        )
    return {"verdict": verdict, "fired_bucket": fired}


_KEY_VALIDATORS = {
    SignalClass.IOC: _validate_ioc_key,
    SignalClass.MITRE_TECHNIQUE: _validate_mitre_key,
    SignalClass.DETECTION_EFFICACY: _validate_detection_key,
}

_PAYLOAD_REDUCERS = {
    SignalClass.IOC: _reduce_ioc_payload,
    SignalClass.MITRE_TECHNIQUE: _reduce_mitre_payload,
    SignalClass.DETECTION_EFFICACY: _reduce_detection_payload,
}


def ingest_signal(
    session: Session,
    *,
    tenant_id: str,
    signal_class: SignalClass,
    signal_key: str,
    payload: dict[str, Any] | None = None,
) -> FederatedSignal:
    """Validate and persist a single tenant-local signal contribution.

    Raises :class:`SignalIngestError` on missing consent or shape
    violation. On success returns the newly inserted row (already
    flushed into the session — commit is the caller's job).
    """

    if not has_active_consent(
        session, tenant_id=tenant_id, signal_class=signal_class
    ):
        raise SignalIngestError(
            f"tenant has no active consent for {signal_class.value}"
        )

    key = (signal_key or "").strip()
    if not key:
        raise SignalIngestError("signal_key is empty")

    _KEY_VALIDATORS[signal_class](key)
    reduced = _PAYLOAD_REDUCERS[signal_class](payload or {})

    row = FederatedSignal(
        tenant_id=tenant_id,
        signal_class=signal_class,
        signal_key=key,
        payload=reduced,
    )
    session.add(row)
    session.flush()
    return row
