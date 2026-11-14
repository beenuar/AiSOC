"""Typed tool surface for the investigation agent (gap-closure Phase 4).

Three modules, split by what each owns:

``indicators``
    The closed vocabulary a model may search with, and the per-backend field
    resolution. This is the security boundary: it is why the model never
    names a field and never supplies query text.
``siem_search``
    Federated SIEM search shaped for an agent. Reuses the existing fan-out;
    adds the typed query, the projection and the caps, and the honest split
    between "nothing matched" and "could not check".
``vendor_reads``
    The read-only vendor door. Reuses the existing governed dispatch; adds a
    closed allowlist, a live contract check, per-verb parameter filtering and
    per-tenant advertisement.
"""

from __future__ import annotations
