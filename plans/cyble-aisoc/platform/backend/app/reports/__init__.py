"""Multi-modal Reporter v2 (Theme 2k).

The classic ReporterAgent narrative is plain-text. This package adds a
**structured, on-demand** report surface that the analyst console (and
PDF exports, SOC2 evidence packs, executive briefings) can render as:

    * a chronological event **timeline** (alert ingest → triage → tool
      calls → HITL decisions → containment → close);
    * an **attack graph** stitched from EDR process trees, affected
      hosts/users, and IOCs;
    * an **ATT&CK heatmap** aggregating tactic→technique→count from
      every alert and case-level technique tag;
    * a **blast-radius** map enumerating which hosts, users, and
      identifiers the response actions actually touched.

By design this module computes everything *on demand* from the
existing Case / AgentTrace / Alert / HitlRequest / ToolCall tables —
nothing new is persisted to the schema, so the report stays consistent
with the canonical audit log even if a row is later edited or rolled
back.
"""
from app.reports.case_report import (
    CaseReport,
    TimelineEvent,
    AttackGraph,
    AttackGraphNode,
    AttackGraphEdge,
    AttackHeatmap,
    BlastRadius,
    build_case_report,
)

__all__ = [
    "CaseReport",
    "TimelineEvent",
    "AttackGraph",
    "AttackGraphNode",
    "AttackGraphEdge",
    "AttackHeatmap",
    "BlastRadius",
    "build_case_report",
]
