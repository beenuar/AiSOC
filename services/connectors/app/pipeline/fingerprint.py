"""Schema fingerprinting for the Connector Health & Schema-Drift Sentinel.

Two fingerprint flavours, both stable, both order/value independent:

* ``compute_fingerprint`` (legacy) — SHA-256 over the union of *all*
  top-level field names of a batch. Kept for compatibility and for the
  drift *evidence* snapshot; prefer the sentinel flavour below for the
  baseline.

* ``compute_dynamic_fingerprint`` — SHA-256 over the union of top-level
  field names **excluding dynamic and optional fields**. This is the
  baseline the drift sentinel stores. It answers the question the sentinel
  actually asks: "did upstream *rename or remove* a field we rely on?",
  without the false-positive storm caused by legitimate batch composition.

Why the union-of-everything baseline was wrong
-----------------------------------------------

``normalize()`` emits several fields conditionally (``src_ip``,
``object_id``, ``record_type``, ``result_status``, ...): they appear only
when the upstream record carries them. Some connectors additionally lift
event-specific key/value pairs into dynamically named fields
(``m365_audit`` turns every ``Parameters`` entry into ``param_<name>``).
On a busy tenant the *set* of dynamically named fields therefore changes
with every poll — a SharePoint file event today, an Entra ID role
assignment tomorrow — while nothing about the upstream contract changed.

Hashing the union of everything made every ordinary poll look like schema
drift (the noisy all-added, zero-removed entries the dashboard surfaced),
which trains operators to ignore the sentinel and hides the one real
failure it exists to catch.

Contract of the dynamic fingerprint
----------------------------------
* Dynamic fields (``param_*`` and friends, per ``DYNAMIC_FIELD_PREFIXES``)
  are excluded from the hash entirely.
* Optional fields (``OPTIONAL_FIELDS``) never flip the fingerprint — in
  either direction.
* Drift is reported **only** when a previously-seen core field goes
  missing from a batch (``removed`` is non-empty). Pure additions — even
  of new core fields — update the baseline silently; a new stable field
  appearing is a vendor improvement, not a breakage, and the drift details
  keep full evidence if one wants to audit it.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from typing import Any

# We do *not* recurse into nested dicts. The drift sentinel is intentionally
# scoped to top-level fields because (a) normalize() outputs are flat by
# convention in this project (``severity``, ``timestamp``, ``user``, etc.)
# and (b) hashing arbitrarily nested structures would catch too many false
# positives — every alert has different ``raw_event`` contents, but those
# differences don't represent schema drift in any meaningful sense.

_SEPARATOR = "\x1f"

#: Top-level field-name prefixes whose names are generated at normalize()
#: time from event content (Microsoft 365 ``Parameters`` pairs today; the
#: convention for other connectors lifting key/value payloads). These names
#: legitimately vary from batch to batch and must never flip a fingerprint.
DYNAMIC_FIELD_PREFIXES: tuple[str, ...] = ("param_",)

#: Normalize-output fields that are present only when the upstream record
#: carries the source attribute. They may appear or disappear between
#: batches without any upstream contract change.
OPTIONAL_FIELDS: frozenset[str] = frozenset(
    {
        "src_ip",
        "object_id",
        "record_type",
        "result_status",
        "actor_email",
        "sha256",
        "file_name",
        "parent_process",
        "command_line",
        "dns_query",
        "url",
        "destination_ip",
        "user_agent",
        "http_method",
        "http_status",
        "asset_id",
        "container_id",
        "image_id",
        "instance_id",
        "vulnerability_id",
        "cve_id",
    }
)


def _is_dynamic(name: str) -> bool:
    return name.startswith(DYNAMIC_FIELD_PREFIXES)


def batch_keys(events: Iterable[dict[str, Any]]) -> set[str]:
    """Union of top-level field names across structured events in a batch."""
    keys: set[str] = set()
    for event in events:
        if not isinstance(event, dict):
            # Defensive: we only fingerprint structured events. A connector
            # that misbehaves and yields a plain string is the scheduler's
            # problem, not the fingerprinter's.
            continue
        keys.update(event.keys())
    return keys


def stable_keys(events: Iterable[dict[str, Any]]) -> set[str]:
    """Field names that participate in the fingerprint: the batch key union
    minus dynamic (``param_*``-style) and optional fields."""
    return {k for k in batch_keys(events) if not _is_dynamic(k) and k not in OPTIONAL_FIELDS}


def compute_fingerprint(events: Iterable[dict[str, Any]]) -> str | None:
    """Legacy fingerprint: union of *all* top-level keys, hashed.

    Returns ``None`` if no events have any keys, letting the caller
    distinguish "no events this poll" from "schema became the empty set".

    Retained for evidence snapshots and existing tests. The drift baseline
    must use :func:`compute_dynamic_fingerprint` instead.
    """
    keys = batch_keys(events)
    if not keys:
        return None
    joined = _SEPARATOR.join(sorted(keys))
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


def compute_dynamic_fingerprint(events: Iterable[dict[str, Any]]) -> str | None:
    """Sentinel fingerprint: stable core field names only.

    Excludes dynamic (``param_*``-style) and optional fields so that two
    batches of *different event kinds from the same schema* produce the
    same fingerprint. Returns ``None`` for empty/keyless batches so the
    caller leaves the stored baseline untouched.
    """
    keys = stable_keys(events)
    if not keys:
        return None
    joined = _SEPARATOR.join(sorted(keys))
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


def evaluate_drift(
    baseline_keys: Iterable[str],
    current_keys: Iterable[str],
) -> dict[str, Any]:
    """Decide whether the current batch represents real schema drift.

    Takes the *stored* baseline key set (``schema_fields`` on the row;
    a connector with no persisted baseline cannot drift — the first
    non-empty batch just seeds one) and the current batch's stable key
    set.

    Returns a dict with ``drift_detected`` (bool) plus the evidence
    (``added``/``removed``/``unchanged_count``). Drift is True **only**
    when at least one baseline core field is missing from the current
    batch — the rename/removal failure mode the sentinel exists to catch.
    """
    prev = set(baseline_keys or [])
    curr = set(current_keys or [])
    removed = sorted(prev - curr)
    return {
        "drift_detected": bool(prev) and bool(removed),
        "added": sorted(curr - prev),
        "removed": removed,
        "unchanged_count": len(prev & curr),
    }


def diff_fingerprints(
    previous_keys: Iterable[str],
    current_keys: Iterable[str],
) -> dict[str, Any]:
    """Describe what changed between two field sets.

    Used by the scheduler to populate ``last_drift_details`` so the UI can
    show "added: X; removed: Y" instead of just "fingerprint changed".
    Both arguments are the raw key sets — the caller is responsible for
    pulling them from the most recent batch and the prior baseline batch.

    The mapping is not homogeneous: ``added`` and ``removed`` are sorted key
    lists and ``unchanged_count`` is an int. It was declared
    ``dict[str, list[str]]``, which the body has never returned — and because
    the scheduler assigns the result straight into a ``dict[str, Any]``
    variable, the wrong declaration narrowed that variable and made the three
    correct lines underneath it look like type errors instead. Both
    consumers, ``connector_repo`` and the API's connector model, already
    declare ``dict[str, Any]``, which is what actually reaches the JSONB
    column.
    """
    prev = set(previous_keys)
    curr = set(current_keys)
    return {
        "added": sorted(curr - prev),
        "removed": sorted(prev - curr),
        "unchanged_count": len(prev & curr),
    }


__all__ = [
    "DYNAMIC_FIELD_PREFIXES",
    "OPTIONAL_FIELDS",
    "batch_keys",
    "compute_dynamic_fingerprint",
    "compute_fingerprint",
    "diff_fingerprints",
    "evaluate_drift",
    "stable_keys",
]
