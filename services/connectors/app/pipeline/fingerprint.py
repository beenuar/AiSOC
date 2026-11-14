"""Schema fingerprinting for the Connector Health & Schema-Drift Sentinel.

We compute a stable hash of the *set of top-level field names* that appear
across a batch of normalized events. The hash is deliberately simple so that
two polls of the same upstream API produce the same fingerprint as long as
the field set is unchanged — even if values change, even if events arrive in
a different order, even if some events omit optional fields.

The intent is not to detect every possible upstream change (a value-type
change from string→int wouldn't be caught here, for example). The intent is
to catch the **single most common silent failure mode**: an upstream vendor
renames or removes a field, the connector's normalize() logic now produces
events missing critical attributes, and detections silently start firing
less frequently. Even this coarse fingerprint catches that case quickly.

Algorithm
---------

For a batch of N normalized events:

1. Union all top-level keys across all N events into a set.
2. Sort lexicographically (stable across runs, so the hash is stable).
3. Join with ``\\x1f`` (ASCII unit separator — guaranteed not to appear in
   a JSON field name).
4. SHA-256 the joined string and return the hex digest.

Two batches with identical field sets produce identical fingerprints.
A batch with one extra field (``new_field``) or one missing field produces
a different fingerprint, which the scheduler treats as drift.

Empty batches return ``None`` rather than a fingerprint of the empty set,
because we don't want a quiet hour (no events) to clobber the baseline
fingerprint we recorded the previous time the connector returned events.
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


def compute_fingerprint(events: Iterable[dict[str, Any]]) -> str | None:
    """Return a stable SHA-256 hex digest of the union of top-level field names.

    Returns ``None`` if no events have any keys (e.g. an empty list, or a
    list of empty dicts). Returning ``None`` lets the caller distinguish
    "no events this poll" from "the upstream changed schema to the empty
    set", which is essentially never what we want to flag as drift.
    """
    keys: set[str] = set()
    for event in events:
        if not isinstance(event, dict):
            # Defensive: we only fingerprint structured events. A connector
            # that misbehaves and yields a plain string is the scheduler's
            # problem, not the fingerprinter's.
            continue
        keys.update(event.keys())

    if not keys:
        return None

    joined = _SEPARATOR.join(sorted(keys))
    digest = hashlib.sha256(joined.encode("utf-8")).hexdigest()
    return digest


def diff_fingerprints(
    previous_keys: Iterable[str],
    current_keys: Iterable[str],
) -> dict[str, Any]:
    """Describe what changed between two field sets.

    Used by the scheduler to populate ``last_drift_details`` so the UI can
    show "added: X; removed: Y" instead of just "fingerprint changed".
    Both arguments are the raw key sets — the caller is responsible for
    pulling them from the most recent batch and the prior baseline batch
    (we cache the prior batch's keys in-memory in the scheduler).

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


__all__ = ["compute_fingerprint", "diff_fingerprints"]
