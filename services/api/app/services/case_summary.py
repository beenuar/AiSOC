"""Case auto-summary builder.

WS-D2 — buyer-value plan
========================
Produces a deterministic, analyst-ready snapshot of a single case. Designed
to be generated automatically when a case transitions to ``resolved`` or
``closed``, but the same builder also powers the on-demand
``GET /cases/{id}/summary`` endpoint so analysts can preview the artifact at
any time.

The output is consumed by:

  * The web UI via the JSON shape (interactive panel + download button).
  * The HTML renderer in :pymod:`app.services.case_summary_html`, which is
    print-ready (browser "Save as PDF" gives an archival document with no
    weasyprint dependency).
  * The case-comments stream — when the auto-trigger fires, we emit a
    system comment that links to the artifact.

Architecture mirrors :pymod:`app.services.executive_digest`:

  1. ``build_summary_from_rows`` — pure, deterministic, fully unit-tested.
  2. ``build_case_summary`` — async DB orchestrator. Only place SQL lives.

Why a separate module from ``executive_digest``? The two reports answer
different questions: the executive digest is a *tenant-wide* weekly snapshot,
while the case summary is a *single-incident* close-out artifact for the
case file / runbook archive. Sharing the renderer style keeps them visually
consistent without coupling the data shapes.
"""

from __future__ import annotations

import uuid
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

# ---------------------------------------------------------------------------
# Output schemas (Pydantic) — what the endpoint actually returns.
# ---------------------------------------------------------------------------


class CaseSummaryHeader(BaseModel):
    """Identity + lifecycle fields for the case being summarised."""

    case_id: uuid.UUID
    case_number: str | None = None
    title: str
    description: str | None = None
    severity: str
    status: str
    assignee: str | None = None
    created_by: str | None = None
    tags: dict[str, Any] = Field(default_factory=dict)


class CaseLifecycleTimings(BaseModel):
    """All of the lifecycle timestamps + derived durations (hours).

    Durations are ``None`` when the corresponding timestamp pair is missing.
    """

    opened_at: datetime
    triaged_at: datetime | None = None
    resolved_at: datetime | None = None
    closed_at: datetime | None = None
    sla_due_at: datetime | None = None

    time_to_triage_hours: float | None = None
    time_to_resolve_hours: float | None = None
    time_to_close_hours: float | None = None
    sla_breached: bool = False


class TaskBreakdown(BaseModel):
    total: int = 0
    todo: int = 0
    in_progress: int = 0
    done: int = 0
    overdue: int = 0


class CommentBreakdown(BaseModel):
    total: int = 0
    analyst: int = 0
    system: int = 0
    distinct_authors: list[str] = Field(default_factory=list)


class CoverageSummary(BaseModel):
    """ATT&CK + compliance coverage for the case."""

    mitre_techniques: list[str] = Field(default_factory=list)
    mitre_tactic_buckets: dict[str, int] = Field(default_factory=dict)
    compliance_frameworks: list[str] = Field(default_factory=list)


class ObservableSummary(BaseModel):
    total_nodes: int = 0
    total_edges: int = 0
    node_kind_counts: dict[str, int] = Field(default_factory=dict)
    distinct_kinds: list[str] = Field(default_factory=list)


class EvidenceSummary(BaseModel):
    total_items: int = 0
    distinct_kinds: list[str] = Field(default_factory=list)


class TimelineHighlight(BaseModel):
    """Compact, deterministic timeline emitted in the summary."""

    ts: datetime
    kind: str  # "case", "comment", "task"
    label: str
    detail: str | None = None


class CaseRecommendation(BaseModel):
    severity: str  # "info" | "warning" | "critical"
    title: str
    body: str


class CaseAutoSummary(BaseModel):
    """Top-level deterministic snapshot of a single case."""

    generated_at: datetime
    headline: str
    case: CaseSummaryHeader
    lifecycle: CaseLifecycleTimings
    coverage: CoverageSummary
    alerts: dict[str, Any] = Field(default_factory=dict)  # {count, ids}
    observables: ObservableSummary
    evidence: EvidenceSummary
    tasks: TaskBreakdown
    comments: CommentBreakdown
    timeline: list[TimelineHighlight] = Field(default_factory=list)
    recommendations: list[CaseRecommendation] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Pure-data input rows — what the orchestrator hands to the builder.
# Kept as plain dataclasses so tests are independent of SQLAlchemy.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SummaryCaseRow:
    """The subset of ``aisoc_cases`` we need for the summary."""

    id: uuid.UUID
    case_number: str | None
    title: str
    description: str | None
    severity: str
    status: str
    assignee: str | None
    created_by: str | None
    tags: dict[str, Any]
    mitre_techniques: list[str]
    alert_ids: list[str]
    observable_graph: dict[str, Any]
    evidence_chain: list[Any]
    compliance_frameworks: list[str]
    opened_at: datetime
    triaged_at: datetime | None
    resolved_at: datetime | None
    closed_at: datetime | None
    sla_due_at: datetime | None
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True)
class SummaryCommentRow:
    author: str | None
    body: str
    is_system: bool
    created_at: datetime


@dataclass(frozen=True)
class SummaryTaskRow:
    title: str
    status: str  # 'todo' | 'in_progress' | 'done'
    assignee: str | None
    due_at: datetime | None
    created_at: datetime
    updated_at: datetime


@dataclass
class CaseSummaryInputs:
    """Bundle of pre-fetched rows for a single case."""

    case: SummaryCaseRow
    comments: list[SummaryCommentRow] = field(default_factory=list)
    tasks: list[SummaryTaskRow] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Pure helpers (independently unit-tested).
# ---------------------------------------------------------------------------


# Best-effort technique → tactic mapping. We only group what we know about;
# unknown techniques fall into "Other" so the summary stays useful even when
# the detection content drifts ahead of this static map.
#
# Source: MITRE ATT&CK Enterprise tactics. We deliberately keep a small,
# stable set here rather than pulling in a heavy dependency — the summary
# is meant to be deterministic and cheap to render.
_TECHNIQUE_TO_TACTIC: dict[str, str] = {
    "T1078": "Initial Access",
    "T1059": "Execution",
    "T1547": "Persistence",
    "T1098": "Persistence",
    "T1068": "Privilege Escalation",
    "T1055": "Privilege Escalation",
    "T1036": "Defense Evasion",
    "T1027": "Defense Evasion",
    "T1110": "Credential Access",
    "T1003": "Credential Access",
    "T1018": "Discovery",
    "T1057": "Discovery",
    "T1082": "Discovery",
    "T1021": "Lateral Movement",
    "T1005": "Collection",
    "T1119": "Collection",
    "T1071": "Command and Control",
    "T1105": "Command and Control",
    "T1041": "Exfiltration",
    "T1486": "Impact",
    "T1490": "Impact",
}


def _hours_between(later: datetime | None, earlier: datetime | None) -> float | None:
    if later is None or earlier is None:
        return None
    delta = later - earlier
    return round(delta.total_seconds() / 3600, 2)


def _bucket_techniques(techniques: list[str]) -> dict[str, int]:
    """Group ATT&CK techniques into their parent tactics (best-effort)."""
    buckets: Counter[str] = Counter()
    for tech in techniques:
        if not isinstance(tech, str):
            continue
        # Use the parent (T1059.001 → T1059) for the lookup.
        root = tech.split(".")[0].strip().upper()
        tactic = _TECHNIQUE_TO_TACTIC.get(root, "Other")
        buckets[tactic] += 1
    return dict(buckets)


def _summarise_observables(graph: dict[str, Any]) -> ObservableSummary:
    nodes = graph.get("nodes") if isinstance(graph, dict) else None
    edges = graph.get("edges") if isinstance(graph, dict) else None
    nodes_list = nodes if isinstance(nodes, list) else []
    edges_list = edges if isinstance(edges, list) else []

    kind_counter: Counter[str] = Counter()
    for node in nodes_list:
        if not isinstance(node, dict):
            continue
        kind = node.get("kind") or node.get("type") or "unknown"
        kind_counter[str(kind)] += 1

    return ObservableSummary(
        total_nodes=len(nodes_list),
        total_edges=len(edges_list),
        node_kind_counts=dict(kind_counter),
        distinct_kinds=sorted(kind_counter.keys()),
    )


def _summarise_evidence(items: list[Any]) -> EvidenceSummary:
    if not isinstance(items, list):
        return EvidenceSummary()
    kinds: set[str] = set()
    for item in items:
        if isinstance(item, dict):
            kind = item.get("kind") or item.get("type")
            if isinstance(kind, str) and kind:
                kinds.add(kind)
    return EvidenceSummary(total_items=len(items), distinct_kinds=sorted(kinds))


def _summarise_tasks(rows: list[SummaryTaskRow], *, now: datetime) -> TaskBreakdown:
    counts: Counter[str] = Counter()
    overdue = 0
    for row in rows:
        counts[row.status] += 1
        if row.status != "done" and row.due_at is not None and row.due_at < now:
            overdue += 1
    return TaskBreakdown(
        total=len(rows),
        todo=counts.get("todo", 0),
        in_progress=counts.get("in_progress", 0),
        done=counts.get("done", 0),
        overdue=overdue,
    )


def _summarise_comments(rows: list[SummaryCommentRow]) -> CommentBreakdown:
    analyst = 0
    system = 0
    authors: set[str] = set()
    for row in rows:
        if row.is_system:
            system += 1
        else:
            analyst += 1
            if row.author:
                authors.add(row.author)
    return CommentBreakdown(
        total=len(rows),
        analyst=analyst,
        system=system,
        distinct_authors=sorted(authors),
    )


def _build_timeline(
    case: SummaryCaseRow,
    comments: list[SummaryCommentRow],
    tasks: list[SummaryTaskRow],
    *,
    limit: int = 25,
) -> list[TimelineHighlight]:
    """Merge case lifecycle events, comments, and tasks into a sorted feed.

    Sort order is strictly chronological, capped to ``limit`` items so the
    summary stays board-ready (recipients should be able to skim it).
    """
    events: list[TimelineHighlight] = []

    events.append(TimelineHighlight(ts=case.opened_at, kind="case", label="Case opened"))
    if case.triaged_at:
        events.append(TimelineHighlight(ts=case.triaged_at, kind="case", label="Triaged"))
    if case.resolved_at:
        events.append(TimelineHighlight(ts=case.resolved_at, kind="case", label="Resolved"))
    if case.closed_at:
        events.append(TimelineHighlight(ts=case.closed_at, kind="case", label="Closed"))

    for c in comments:
        body_excerpt = (c.body or "").strip().replace("\n", " ")
        if len(body_excerpt) > 140:
            body_excerpt = body_excerpt[:137] + "…"
        events.append(
            TimelineHighlight(
                ts=c.created_at,
                kind="comment",
                label=("System note" if c.is_system else "Analyst note") + (f" — {c.author}" if c.author and not c.is_system else ""),
                detail=body_excerpt or None,
            )
        )

    for t in tasks:
        events.append(
            TimelineHighlight(
                ts=t.created_at,
                kind="task",
                label=f"Task created — {t.title}",
                detail=f"status={t.status}" + (f" · assignee={t.assignee}" if t.assignee else ""),
            )
        )

    events.sort(key=lambda e: e.ts)
    if len(events) <= limit:
        return events

    # Always keep the case lifecycle events; trim comments/tasks if needed.
    lifecycle = [e for e in events if e.kind == "case"]
    other = [e for e in events if e.kind != "case"]
    keep_other = max(limit - len(lifecycle), 0)
    other = other[-keep_other:] if keep_other else []
    merged = sorted(lifecycle + other, key=lambda e: e.ts)
    return merged


def _build_headline(
    case: SummaryCaseRow,
    lifecycle: CaseLifecycleTimings,
    tasks: TaskBreakdown,
    coverage: CoverageSummary,
) -> str:
    parts: list[str] = []
    label = case.case_number or str(case.id)[:8]
    parts.append(f"{label} {case.severity.upper()}")
    parts.append(case.status)
    if lifecycle.time_to_resolve_hours is not None:
        parts.append(f"resolved in {lifecycle.time_to_resolve_hours:.1f}h")
    if tasks.total:
        parts.append(f"{tasks.done}/{tasks.total} tasks done")
    if coverage.mitre_techniques:
        parts.append(f"{len(coverage.mitre_techniques)} ATT&CK techniques")
    return " · ".join(parts)


def _build_recommendations(
    case: SummaryCaseRow,
    lifecycle: CaseLifecycleTimings,
    tasks: TaskBreakdown,
    comments: CommentBreakdown,
    coverage: CoverageSummary,
) -> list[CaseRecommendation]:
    """Heuristic, deterministic post-mortem call-to-actions.

    Designed to nudge the analyst toward the right archival hygiene without
    being prescriptive. Every threshold here is fixed and explainable.
    """
    recs: list[CaseRecommendation] = []

    if lifecycle.sla_breached:
        recs.append(
            CaseRecommendation(
                severity="warning",
                title="SLA breach on this case",
                body=(
                    "The case ran past its SLA. Capture the cause (analyst load, "
                    "missing playbook, escalation gap) so the post-mortem reaches "
                    "the on-call rotation."
                ),
            )
        )

    if tasks.overdue:
        recs.append(
            CaseRecommendation(
                severity="warning",
                title=f"{tasks.overdue} overdue task{'s' if tasks.overdue != 1 else ''}",
                body=("Tasks past their due date are still open. Close them out or reassign before archiving the case."),
            )
        )

    if case.severity in {"high", "critical"} and comments.analyst == 0:
        recs.append(
            CaseRecommendation(
                severity="warning",
                title="No analyst notes on a high-severity case",
                body=(
                    "A high or critical case is closing without any analyst "
                    "narrative. Add a closing note explaining root cause + "
                    "remediation before archival."
                ),
            )
        )

    if not coverage.mitre_techniques:
        recs.append(
            CaseRecommendation(
                severity="info",
                title="No MITRE ATT&CK coverage tagged",
                body=(
                    "Tagging at least one technique improves coverage reporting "
                    "and helps tune the detection set. Update the case before "
                    "archival if applicable."
                ),
            )
        )

    if lifecycle.time_to_resolve_hours is not None and lifecycle.time_to_resolve_hours > 24:
        recs.append(
            CaseRecommendation(
                severity="info",
                title=f"MTTR on this case was {lifecycle.time_to_resolve_hours:.1f}h",
                body=(
                    "Resolution exceeded 24h. Consider whether automation, a new "
                    "playbook, or runbook updates would compress the next "
                    "occurrence."
                ),
            )
        )

    if not recs:
        recs.append(
            CaseRecommendation(
                severity="info",
                title="Case closed cleanly",
                body=("All headline metrics look healthy. Archive this case and fold any new IOCs into your detection content."),
            )
        )

    return recs


# ---------------------------------------------------------------------------
# Pure top-level builder.
# ---------------------------------------------------------------------------


def build_summary_from_rows(
    inputs: CaseSummaryInputs,
    *,
    now: datetime | None = None,
) -> CaseAutoSummary:
    """Pure function: rows in → ``CaseAutoSummary`` out. Deterministic."""
    moment = now or datetime.now(UTC)
    case = inputs.case

    lifecycle = CaseLifecycleTimings(
        opened_at=case.opened_at,
        triaged_at=case.triaged_at,
        resolved_at=case.resolved_at,
        closed_at=case.closed_at,
        sla_due_at=case.sla_due_at,
        time_to_triage_hours=_hours_between(case.triaged_at, case.opened_at),
        time_to_resolve_hours=_hours_between(case.resolved_at, case.opened_at),
        time_to_close_hours=_hours_between(case.closed_at, case.opened_at),
        sla_breached=bool(case.sla_due_at and (case.resolved_at or case.closed_at or moment) > case.sla_due_at),
    )

    coverage = CoverageSummary(
        mitre_techniques=list(case.mitre_techniques or []),
        mitre_tactic_buckets=_bucket_techniques(list(case.mitre_techniques or [])),
        compliance_frameworks=list(case.compliance_frameworks or []),
    )

    observables = _summarise_observables(case.observable_graph or {})
    evidence = _summarise_evidence(case.evidence_chain or [])
    tasks = _summarise_tasks(inputs.tasks, now=moment)
    comments = _summarise_comments(inputs.comments)
    timeline = _build_timeline(case, inputs.comments, inputs.tasks)
    headline = _build_headline(case, lifecycle, tasks, coverage)
    recommendations = _build_recommendations(case, lifecycle, tasks, comments, coverage)

    return CaseAutoSummary(
        generated_at=moment,
        headline=headline,
        case=CaseSummaryHeader(
            case_id=case.id,
            case_number=case.case_number,
            title=case.title,
            description=case.description,
            severity=case.severity,
            status=case.status,
            assignee=case.assignee,
            created_by=case.created_by,
            tags=dict(case.tags or {}),
        ),
        lifecycle=lifecycle,
        coverage=coverage,
        alerts={
            "count": len(case.alert_ids or []),
            "ids": [str(a) for a in (case.alert_ids or [])][:25],
        },
        observables=observables,
        evidence=evidence,
        tasks=tasks,
        comments=comments,
        timeline=timeline,
        recommendations=recommendations,
    )


# ---------------------------------------------------------------------------
# DB orchestrator — the only place SQL lives.
# ---------------------------------------------------------------------------


def _row_to_summary_case(row: Any) -> SummaryCaseRow:
    """Map a raw ``aisoc_cases`` row to our pure dataclass."""
    techniques = row.mitre_techniques or []
    if isinstance(techniques, list):
        flat: list[str] = []
        for t in techniques:
            if isinstance(t, str):
                flat.append(t)
            elif isinstance(t, dict):
                tid = t.get("id") or t.get("technique_id") or t.get("name")
                if tid:
                    flat.append(str(tid))
        techniques = flat
    else:
        techniques = []

    return SummaryCaseRow(
        id=row.id,
        case_number=getattr(row, "case_number", None),
        title=row.title,
        description=row.description,
        severity=row.severity,
        status=row.status,
        assignee=row.assignee,
        created_by=row.created_by,
        tags=dict(row.tags or {}) if isinstance(row.tags, dict) else {},
        mitre_techniques=techniques,
        alert_ids=[str(a) for a in (row.alert_ids or [])],
        observable_graph=dict(row.observable_graph or {}) if isinstance(row.observable_graph, dict) else {},
        evidence_chain=list(row.evidence_chain or []) if isinstance(row.evidence_chain, list) else [],
        compliance_frameworks=list(row.compliance_frameworks or []),
        opened_at=row.opened_at,
        triaged_at=row.triaged_at,
        resolved_at=row.resolved_at,
        closed_at=row.closed_at,
        sla_due_at=getattr(row, "sla_due_at", None),
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


async def _fetch_case_for_summary(db: AsyncSession, case_id: uuid.UUID) -> SummaryCaseRow | None:
    row = (await db.execute(text("SELECT * FROM aisoc_cases WHERE id = :id").bindparams(id=case_id))).fetchone()
    return _row_to_summary_case(row) if row else None


async def _fetch_comments(db: AsyncSession, case_id: uuid.UUID) -> list[SummaryCommentRow]:
    rows = (
        await db.execute(
            text("SELECT author, body, is_system, created_at FROM aisoc_case_comments WHERE case_id = :id ORDER BY created_at").bindparams(
                id=case_id
            )
        )
    ).fetchall()
    return [
        SummaryCommentRow(
            author=r.author,
            body=r.body or "",
            is_system=bool(r.is_system),
            created_at=r.created_at,
        )
        for r in rows
    ]


async def _fetch_tasks(db: AsyncSession, case_id: uuid.UUID) -> list[SummaryTaskRow]:
    """Pull tasks; tolerate the absence of ``aisoc_case_tasks`` on older deployments."""
    try:
        rows = (
            await db.execute(
                text(
                    "SELECT title, status, assignee, due_at, created_at, updated_at "
                    "FROM aisoc_case_tasks WHERE case_id = :id ORDER BY created_at"
                ).bindparams(id=case_id)
            )
        ).fetchall()
    except Exception:  # pragma: no cover — defensive: missing table on older DBs.
        return []
    return [
        SummaryTaskRow(
            title=r.title,
            status=r.status or "todo",
            assignee=r.assignee,
            due_at=r.due_at,
            created_at=r.created_at,
            updated_at=r.updated_at,
        )
        for r in rows
    ]


async def build_case_summary(
    db: AsyncSession,
    case_id: uuid.UUID,
    *,
    now: datetime | None = None,
) -> CaseAutoSummary | None:
    """Async orchestrator: pull rows for a single case and build the summary.

    Returns ``None`` if the case isn't found, so endpoints can surface a
    clean 404 without conflating the data layer with HTTP semantics.
    """
    case = await _fetch_case_for_summary(db, case_id)
    if case is None:
        return None
    comments = await _fetch_comments(db, case_id)
    tasks = await _fetch_tasks(db, case_id)
    inputs = CaseSummaryInputs(case=case, comments=comments, tasks=tasks)
    return build_summary_from_rows(inputs, now=now)


# Dummy import to keep timedelta usage explicit & lint-clean (used in tests).
_unused = timedelta(seconds=0)


__all__ = [
    "CaseAutoSummary",
    "CaseLifecycleTimings",
    "CaseRecommendation",
    "CaseSummaryHeader",
    "CaseSummaryInputs",
    "CommentBreakdown",
    "CoverageSummary",
    "EvidenceSummary",
    "ObservableSummary",
    "SummaryCaseRow",
    "SummaryCommentRow",
    "SummaryTaskRow",
    "TaskBreakdown",
    "TimelineHighlight",
    "build_case_summary",
    "build_summary_from_rows",
]


# Internal helpers exported for tests.
_internal_helpers: dict[str, Any] = {
    "_hours_between": _hours_between,
    "_bucket_techniques": _bucket_techniques,
    "_summarise_observables": _summarise_observables,
    "_summarise_evidence": _summarise_evidence,
    "_summarise_tasks": _summarise_tasks,
    "_summarise_comments": _summarise_comments,
    "_build_timeline": _build_timeline,
    "_build_headline": _build_headline,
    "_build_recommendations": _build_recommendations,
}
