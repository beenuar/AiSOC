"""Federated search across SIEM backends.

The federated layer translates a single ``UnifiedQuery`` into the native
query languages of every backend SIEM AiSOC has a connector for (today:
Splunk SPL, Microsoft Sentinel KQL, Elastic ES|QL). Each connector that
opts into federated search implements ``BaseConnector.query`` against
this model.

This package owns the *shape* of a unified query and the pure-function
translators. Orchestration (fan-out, merge, ranking) lives in the API
service so it can apply tenant-scoped credential decryption and per-row
RBAC before results leave the data plane.
"""

from __future__ import annotations

from app.federated.query import (
    Indicator,
    Operator,
    QueryError,
    UnifiedQuery,
    parse_unified_query,
)

__all__ = [
    "Indicator",
    "Operator",
    "QueryError",
    "UnifiedQuery",
    "parse_unified_query",
]
