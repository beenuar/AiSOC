"""Three-tier agent memory subsystem.

Tiers
-----
session     In-process LRU — per-run ephemeral scratchpad. Zero I/O.
working     Redis-backed — persists for the lifetime of a case/shift (~24 h).
institutional  PostgreSQL-backed — permanent institutional knowledge;
            searchable via pgvector or keyword depending on availability.

Usage::

    from app.memory import MemoryManager

    mgr = await MemoryManager.create(tenant_id="t1", run_id="r1")
    await mgr.write_session("last_tool", {"name": "mitre_lookup", "result": ...})
    await mgr.write_working("suspect_ip", "10.0.0.5")
    await mgr.write_institutional("known_fp", {"rule": "sigma-001", "reason": "..."})

    hit = await mgr.recall("suspect_ip", tiers=("session", "working"))
"""

from .manager import MemoryManager
from .models import MemoryEntry, MemoryTier

__all__ = ["MemoryManager", "MemoryEntry", "MemoryTier"]
