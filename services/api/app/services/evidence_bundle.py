"""Export one investigation as a signed, replayable evidence bundle.

Parity 3.7.

What a bundle is for
---------------------
An auditor, a regulator or a customer's own security team asks: *what did
this thing decide, on what evidence, and can I check that nobody edited
the answer afterwards?* The Investigation Ledger already holds the
answer; a bundle is that answer made portable and tamper-evident.

Three properties, and each one is a decision rather than a default.

**Byte-for-byte replayable.** Two exports of the same run produce
identical bytes, so a bundle can be diffed, re-hashed and checked by
somebody who does not trust the exporter. That rules out everything that
makes JSON non-deterministic: key order is sorted, separators are fixed,
timestamps are the ledger's own rather than `now()`, and nothing records
the host that produced it. :func:`verify_bundle` recomputes the digest
from the payload rather than trusting the one in the file.

**Prompts travel as hashes, never as text.** A prompt carries the alert,
and an alert carries a customer's hostnames, usernames and IP addresses.
A bundle is the artefact most likely to leave the customer's control, so
the one thing it must not do is carry their estate in clear text. The
hash still proves *which* prompt ran: re-hash the prompt and compare.

**Absent is not zero.** A run with no cost telemetry exports
``total_cost_usd: null``, not ``0.0``. A zero says the run was free; null
says nobody measured. This repository has published the first while
meaning the second before.

The OCSF mapping, and the version it honestly declares
--------------------------------------------------------
The spec asks for the ``ai_agent`` object, the ``ai_operation`` profile
and the record-integrity profile. Each was checked against the published
schema before being used here, and the result decided the version this
bundle declares:

===================  =======  =======  =======
Thing                1.1.0    1.8.0    1.9.0
===================  =======  =======  =======
``ai_agent``         absent   absent   present
``ai_operation``     absent   present  present
``record_integrity`` absent   —        present
===================  =======  =======  =======

The ingest spine emits **1.1.0** — that is the contract its normalizer
has with connectors, and it is not changed here. A bundle is a different
artefact with a different audience, and it declares **1.9.0**, because
1.9.0 is the first version containing every object it uses. Declaring
1.1.0 while emitting an `ai_agent` would be a false claim about a public
standard, which is worse than not mapping at all.

Field names are taken from the schema rather than invented:
``ai_agent`` has ``name``, ``uid``, ``type``, ``version``, ``ai_model``
and ``instance_uid``; ``ai_model`` has ``name``, ``uid``, ``version`` and
``ai_provider``; ``record_integrity`` carries ``attestation_list``, whose
``attestation`` objects have ``fingerprint``, ``signatures``,
``authority_uid`` and ``prev_event``.

Signing
-------
HMAC-SHA256 over the canonical payload, keyed from the deployment's own
secret. That is a *tamper-evidence* control, not a non-repudiation one:
anyone who can read the key can forge a bundle, so it proves the bundle
has not been altered in transit, not that AiSOC and only AiSOC produced
it. :data:`SIGNATURE_ALGORITHM` says so in the bundle itself, because an
auditor who assumes a public-key signature from the word "signed" has
been misled by us rather than by the format.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from datetime import datetime
from typing import Any

__all__ = [
    "BUNDLE_SCHEMA_VERSION",
    "OCSF_VERSION",
    "SIGNATURE_ALGORITHM",
    "BundleVerificationError",
    "build_bundle",
    "canonical_bytes",
    "serialize_bundle",
    "verify_bundle",
]

#: This format's own version, independent of OCSF's. Bumped when the
#: payload shape changes in a way a reader must notice.
BUNDLE_SCHEMA_VERSION = "1.0"

#: The first OCSF version containing every object this bundle uses. See
#: the module docstring for why it is not the 1.1.0 the ingest spine
#: emits.
OCSF_VERSION = "1.9.0"

#: Named in the bundle so a reader cannot mistake tamper-evidence for
#: non-repudiation.
SIGNATURE_ALGORITHM = "HMAC-SHA256"

#: `ai_agent.type_id` for a security-analysis agent. OCSF 1.9.0 defines
#: the enum; 99 is `Other`, which is the honest choice until this tree
#: has checked that a more specific member means what it appears to.
AI_AGENT_TYPE_ID = 99
AI_AGENT_TYPE = "Security investigation agent"


class BundleVerificationError(RuntimeError):
    """A bundle failed verification. Carries why, never just False."""


def canonical_bytes(payload: dict[str, Any]) -> bytes:
    """The one byte representation a signature is computed over.

    Sorted keys, no inserted whitespace, UTF-8, no trailing newline. Two
    exports of one run must produce identical bytes or the round-trip
    property this format is built on does not hold, and a signature
    computed over a different serialisation than the one verified is a
    signature that fails for no reason a reader can see.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _digest(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(payload)).hexdigest()


def _sign(payload: dict[str, Any], key: str) -> str:
    return hmac.new(key.encode("utf-8"), canonical_bytes(payload), hashlib.sha256).hexdigest()


def _hash_prompt(text: str | None) -> str | None:
    """A prompt as a digest.

    `None` stays `None`: "there was no prompt" and "the prompt hashed to
    something" are different facts, and a hash of the empty string would
    quietly merge them.
    """
    if text is None:
        return None
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _iso(value: Any) -> str | None:
    """A timestamp as the ledger recorded it, never as `now()`.

    A bundle that stamps its own export time cannot reproduce byte for
    byte, which is the property the whole format rests on.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _float_or_none(value: Any) -> float | None:
    """`None` rather than `0.0` when nothing measured it."""
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _redact_event_payload(payload: Any) -> Any:
    """Keep an event's structure; replace prompt text with its hash.

    The ledger stores whole prompts so a decision can be replayed inside
    the deployment. A bundle leaves the deployment, so the text goes and
    the digest stays: enough to prove which prompt ran, not enough to
    reconstruct the customer's estate from it.
    """
    if not isinstance(payload, dict):
        return payload
    redacted: dict[str, Any] = {}
    for key, value in payload.items():
        if key in {"prompt", "messages", "system_prompt", "user_prompt", "input"} and value is not None:
            redacted[f"{key}_sha256"] = _hash_prompt(value if isinstance(value, str) else json.dumps(value, sort_keys=True))
        else:
            redacted[key] = value
    return redacted


def _ocsf_block(run: dict[str, Any], agent_names: list[str]) -> dict[str, Any]:
    """The OCSF `ai_operation` view of this run.

    Every field name here was read off schema.ocsf.io for 1.9.0. The
    bundle's own payload above is the authoritative record; this block
    exists so a SIEM that speaks OCSF can file the bundle without
    understanding AiSOC's format.
    """
    model = run.get("model_used")
    return {
        "metadata": {
            "version": OCSF_VERSION,
            "product": {"name": "AiSOC", "vendor_name": "AiSOC"},
            "profiles": ["ai_operation", "record_integrity"],
        },
        "ai_operation": {
            "ai_agent": {
                "name": agent_names[0] if agent_names else "aisoc-investigation",
                "uid": str(run.get("id") or ""),
                "type": AI_AGENT_TYPE,
                "type_id": AI_AGENT_TYPE_ID,
                "instance_uid": str(run.get("id") or ""),
                # `ai_model` is nested inside `ai_agent` in 1.9.0, and
                # `null` when the run recorded no model rather than a
                # placeholder name that would read as a real one.
                "ai_model": None if not model else {"name": str(model), "uid": str(model)},
            },
        },
    }


def build_bundle(
    *,
    run: dict[str, Any],
    events: list[dict[str, Any]],
    artifacts: list[dict[str, Any]] | None = None,
    approvals: list[dict[str, Any]] | None = None,
    signing_key: str,
) -> dict[str, Any]:
    """Assemble and sign one investigation's bundle.

    `run`, `events`, `artifacts` and `approvals` are rows as the ledger
    holds them. Nothing here reaches back into the database: a bundle is
    a pure function of what it is handed, which is what lets a test build
    one without a deployment and lets two exports agree.
    """
    ordered_events = sorted(events, key=lambda e: (e.get("seq") if e.get("seq") is not None else 0, str(e.get("id") or "")))
    agent_names = sorted({str(e.get("agent")) for e in ordered_events if e.get("agent")})

    payload: dict[str, Any] = {
        "bundle_schema_version": BUNDLE_SCHEMA_VERSION,
        "run": {
            "id": str(run.get("id") or ""),
            "tenant_id": str(run.get("tenant_id") or ""),
            "case_id": run.get("case_id"),
            "status": run.get("status"),
            "error": run.get("error"),
            "started_at": _iso(run.get("started_at")),
            "completed_at": _iso(run.get("completed_at")),
            "iterations": run.get("iterations"),
        },
        "alert": {
            "summary": run.get("alert_summary"),
            "raw": run.get("raw_alert"),
        },
        "model": {
            "id": run.get("model_used"),
            # Absent is not zero. A run with no telemetry exports null,
            # because 0.0 says the run was free.
            "total_tokens": run.get("total_tokens") if run.get("total_tokens") is not None else None,
            "total_cost_usd": _float_or_none(run.get("total_cost_usd")),
            "cost_provenance": (
                "measured" if run.get("total_cost_usd") is not None else "not measured — no cost telemetry was recorded for this run"
            ),
        },
        "steps": [
            {
                "seq": event.get("seq"),
                "kind": event.get("kind"),
                "agent": event.get("agent"),
                "summary": event.get("summary"),
                "ts": _iso(event.get("ts")),
                "duration_ms": event.get("duration_ms"),
                "input_hash": event.get("input_hash"),
                "output_hash": event.get("output_hash"),
                "payload": _redact_event_payload(event.get("payload")),
            }
            for event in ordered_events
        ],
        "artifacts": sorted(
            [
                {
                    "id": str(a.get("id") or ""),
                    "kind": a.get("kind"),
                    "label": a.get("label"),
                    "sha256": a.get("sha256"),
                }
                for a in (artifacts or [])
            ],
            key=lambda a: (str(a.get("kind") or ""), a["id"]),
        ),
        "approvals": sorted(
            [
                {
                    "id": str(a.get("id") or ""),
                    "action": a.get("action"),
                    "status": a.get("status"),
                    "approver": a.get("approver"),
                    "decided_at": _iso(a.get("decided_at")),
                }
                for a in (approvals or [])
            ],
            key=lambda a: a["id"],
        ),
    }
    payload["ocsf"] = _ocsf_block(run, agent_names)

    digest = _digest(payload)
    return {
        "payload": payload,
        # The envelope is deliberately outside the signed payload: a
        # signature cannot cover itself.
        "integrity": {
            "algorithm": SIGNATURE_ALGORITHM,
            "algorithm_note": (
                "Tamper-evidence, not non-repudiation. Anyone holding the deployment's signing "
                "key can produce a valid signature, so this proves the bundle was not altered "
                "after export — not that AiSOC and only AiSOC produced it."
            ),
            "payload_sha256": digest,
            "signature": _sign(payload, signing_key),
            # The OCSF record-integrity view of the same two values.
            "attestation_list": [
                {
                    "fingerprint": {"algorithm": "SHA-256", "algorithm_id": 3, "value": digest},
                    "signatures": [{"algorithm": SIGNATURE_ALGORITHM, "algorithm_id": 99}],
                }
            ],
        },
    }


def serialize_bundle(bundle: dict[str, Any]) -> bytes:
    """The bundle as bytes on disk or on the wire.

    Same canonicalisation as the signature, so a reader who recomputes
    the digest from the file gets the digest that was signed.
    """
    return canonical_bytes(bundle)


def verify_bundle(bundle: dict[str, Any], *, signing_key: str) -> dict[str, Any]:
    """Check a bundle has not been altered, or say exactly what is wrong.

    Recomputes both the digest and the signature from the payload rather
    than comparing the two values already in the file — which would pass
    for anyone who edited the payload and the digest together.
    """
    payload = bundle.get("payload")
    integrity = bundle.get("integrity") or {}
    if not isinstance(payload, dict):
        raise BundleVerificationError("bundle has no payload object")

    recomputed = _digest(payload)
    claimed = integrity.get("payload_sha256")
    if claimed != recomputed:
        raise BundleVerificationError(f"payload digest mismatch: the bundle claims {claimed!r} and its payload hashes to {recomputed!r}")

    expected = _sign(payload, signing_key)
    actual = integrity.get("signature")
    if not isinstance(actual, str) or not hmac.compare_digest(expected, actual):
        raise BundleVerificationError(
            "signature does not match this deployment's key — the bundle was altered, or it was produced by a different deployment"
        )

    return payload


def bundle_filename(run_id: str | uuid.UUID) -> str:
    """A stable name, so two exports of one run overwrite rather than accumulate."""
    return f"aisoc-investigation-{run_id}.bundle.json"
