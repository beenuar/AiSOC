"""Pure-function translators from ``UnifiedQuery`` to backend dialects.

Each translator takes a validated ``UnifiedQuery`` and returns a string
the corresponding connector can pass straight to its SIEM. Translators
are pure: no I/O, no global state, no exceptions other than
``QueryError`` for un-translatable shapes.
"""

from __future__ import annotations

from app.federated.translators.esql import to_esql
from app.federated.translators.kql import to_kql
from app.federated.translators.spl import to_spl

__all__ = ["to_esql", "to_kql", "to_spl"]
