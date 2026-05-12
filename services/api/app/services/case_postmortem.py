"""Auto post-mortem builder.

Stage 3 #21 — roadmap
=====================
Drafts a *blameless retrospective* for a closed (or closing) case from the
case timeline + lifecycle metadata. Distinct from the per-case auto-summary
in :pymod:`app.services.case_summary`:

  * **Auto-summary** is a snapshot of *what the case looks like right now* —
    KPIs, observables, evidence, recommendations for archival hygiene.
  * **Post-mortem** is a retrospective: *what happened, when did we find
    out, what did we do, what did it cost, and what should we change* —
    organised around the questions an on-call retro asks.

Architecture mirrors the auto-summary intentionally so both artefacts feel
like siblings:

  1. ``build_postmortem_from_rows`` — pure, deterministic, fully unit-tested.
  2. ``build_case_postmortem`` — async DB orchestrator. Only place SQL lives.

To keep the DB layer DRY we *reuse* the input dataclasses defined in the
auto-summary module (``SummaryCaseRow`` / ``SummaryCommentRow`` /
``SummaryTaskRow``). Adding a parallel set would have meant two row mappers
for the same tables.

The post-mortem is deliberately blameless: every recommendation references
*systems* (detection content, runbooks, automation, escalation paths), not
individuals. The renderer strips author names from the timeline excerpts
that flow into the document body — they're still in the case record itself
and visible in the activity stream.
"""

from __future__ import annotations

import uuid
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

# Reuse the case-summary input rows + DB fetchers so we don't duplicate the
# row mappers. The post-mortem builder works off the same shape of inputs;
# only the *output* differs.
from .case_summary import (
    CaseSummaryInputs,
    SummaryCaseRow,
    SummaryCommentRow,
    SummaryTaskRow,
    _fetch_case_for_summary,
    _fetch_comments,
    _fetch_tasks,
)

# ---------------------------------------------------------------------------
# Output schemas (Pydantic) — what the endpoint actually returns.
# ---------------------------------------------------------------------------


class PostmortemHeader(BaseModel):
    """Identity for the case being retro-ed."""

    case_id: uuid.UUID
    case_number: str | None = None
    title: str
    severity: str
    status: str
    tags: dict[str, Any] = Field(default_factory=dict)


class IncidentOverview(BaseModel):
    """One-paragraph executive narrative + structured impact."""

    summary: str
    severity: str
    status: str
    blast_radius_hosts: int = 0
    blast_radius_identities: int = 0
    blast_radius_alerts: int = 0
    distinct_observable_kinds: list[str] = Field(default_factory=list)
    affected_domains: list[str] = Field(default_factory=list)


class DetectionTiming(BaseModel):
    """How fast did detection / triage / response happen?

    All durations in hours; ``None`` means we don't have the timestamp pair.
    """

    opened_at: datetime
    first_analyst_touch_at: datetime | None = None
    triaged_at: datetime | None = None
    resolved_at: datetime | None = None
    closed_at: datetime | None = None
    sla_due_at: datetime | None = None

    time_to_detect_hours: float | None = None  # opened → first analyst note
    time_to_triage_hours: float | None = None  # opened → triaged_at
    time_to_resolve_hours: float | None = None
    time_to_close_hours: float | None = None
    sla_breached: bool = False


class DetectionGap(BaseModel):
    """A specific gap the timeline reveals (e.g. silent for N hours)."""

    severity: str  # "info" | "warning" | "critical"
    title: str
    body: str


class ResponseAction(BaseModel):
    """One bucket of response work — derived from tasks + system actions."""

    bucket: str  # "containment" | "eradication" | "recovery" | "communication" | "investigation" | "other"
    count: int = 0
    completed: int = 0
    open: int = 0
    overdue: int = 0
    sample_titles: list[str] = Field(default_factory=list)


class ResponseEffectiveness(BaseModel):
    """Roll-up of how response went, for the executive paragraph."""

    total_actions: int = 0
    completed: int = 0
    open: int = 0
    overdue: int = 0
    automation_used: bool = False
    actions_by_bucket: list[ResponseAction] = Field(default_factory=list)


class TimelineEntry(BaseModel):
    """Compact retrospective timeline (system-side, blameless)."""

    ts: datetime
    phase: str  # "detection" | "triage" | "investigation" | "response" | "resolution" | "closure"
    label: str
    detail: str | None = None


class WentWellItem(BaseModel):
    """A positive observation surfaced from the timeline."""

    title: str
    body: str


class FellShortItem(BaseModel):
    """A blameless observation about a gap (process / coverage / runbook)."""

    title: str
    body: str


class ActionItem(BaseModel):
    """Concrete, blameless follow-up the team should consider."""

    category: str  # "detection" | "runbook" | "automation" | "process" | "training"
    severity: str  # "info" | "warning" | "critical"
    title: str
    body: str
    owner_role: str | None = None  # e.g. "detection engineering", "on-call lead"


class CasePostmortem(BaseModel):
    """Top-level deterministic blameless retrospective for one case."""

    generated_at: datetime
    headline: str
    case: PostmortemHeader
    overview: IncidentOverview
    detection: DetectionTiming
    detection_gaps: list[DetectionGap] = Field(default_factory=list)
    response: ResponseEffectiveness
    timeline: list[TimelineEntry] = Field(default_factory=list)
    went_well: list[WentWellItem] = Field(default_factory=list)
    fell_short: list[FellShortItem] = Field(default_factory=list)
    action_items: list[ActionItem] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Pure-data input bundle — wraps the reused dataclasses for clarity.
# ---------------------------------------------------------------------------


@dataclass
class PostmortemInputs:
    """Bundle of pre-fetched rows for a single case post-mortem."""

    case: SummaryCaseRow
    comments: list[SummaryCommentRow] = field(default_factory=list)
    tasks: list[SummaryTaskRow] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Pure helpers.
# ---------------------------------------------------------------------------


def _hours_between(later: datetime | None, earlier: datetime | None) -> float | None:
    if later is None or earlier is None:
        return None
    delta = later - earlier
    return round(delta.total_seconds() / 3600, 2)


# Keyword → response-action bucket. Deliberately small + stable; unknown task
# titles fall into "other" so the post-mortem stays useful even when teams
# coin new task vocabulary.
_RESPONSE_KEYWORDS: dict[str, list[str]] = {
    "containment": [
        "isolat",
        "contain",
        "quarantin",
        "block",
        "disable",
        "suspend",
        "lock",
        "kill switch",
    ],
    "eradication": [
        "remov",
        "delete",
        "wipe",
        "uninstall",
        "purge",
        "rotat",
        "revoke",
        "reset password",
        "reset secret",
    ],
    "recovery": [
        "restor",
        "recover",
        "rebuild",
        "reimage",
        "redeploy",
        "rollback",
        "reissue",
    ],
    "communication": [
        "notif",
        "inform",
        "alert team",
        "page",
        "escalat",
        "stakeholder",
        "customer",
        "comms",
        "status page",
    ],
    "investigation": [
        "investigat",
        "analyz",
        "analyse",
        "review",
        "triage",
        "collect",
        "preserve",
        "evidence",
        "forensic",
        "scope",
    ],
}


def _bucket_response_action(title: str) -> str:
    """Heuristic: classify a task into a NIST-style response bucket."""
    t = (title or "").lower()
    if not t:
        return "other"
    for bucket, keywords in _RESPONSE_KEYWORDS.items():
        for kw in keywords:
            if kw in t:
                return bucket
    return "other"


def _summarise_response(rows: list[SummaryTaskRow], *, now: datetime) -> ResponseEffectiveness:
    by_bucket: dict[str, dict[str, Any]] = {}

    for row in rows:
        bucket = _bucket_response_action(row.title)
        slot = by_bucket.setdefault(
            bucket,
            {"count": 0, "completed": 0, "open": 0, "overdue": 0, "titles": []},
        )
        slot["count"] += 1
        if row.status == "done":
            slot["completed"] += 1
        else:
            slot["open"] += 1
            if row.due_at is not None and row.due_at < now:
                slot["overdue"] += 1
        if len(slot["titles"]) < 3:
            slot["titles"].append(row.title)

    actions = [
        ResponseAction(
            bucket=bucket,
            count=info["count"],
            completed=info["completed"],
            open=info["open"],
            overdue=info["overdue"],
            sample_titles=list(info["titles"]),
        )
        for bucket, info in sorted(by_bucket.items(), key=lambda kv: (-kv[1]["count"], kv[0]))
    ]

    total = sum(a.count for a in actions)
    completed = sum(a.completed for a in actions)
    opn = sum(a.open for a in actions)
    overdue = sum(a.overdue for a in actions)

    # If any task title contains "playbook"/"workflow"/"runbook automation"
    # treat that as the team having reached for automation. Crude but useful
    # for the executive paragraph; we don't claim more than we can prove.
    automation_markers = ("playbook", "automation", "soar", "workflow run")
    automation_used = any(any(m in (t.title or "").lower() for m in automation_markers) for t in rows)

    return ResponseEffectiveness(
        total_actions=total,
        completed=completed,
        open=opn,
        overdue=overdue,
        automation_used=automation_used,
        actions_by_bucket=actions,
    )


def _first_analyst_touch(comments: list[SummaryCommentRow]) -> datetime | None:
    """First non-system comment — proxy for "an analyst saw this"."""
    for c in sorted(comments, key=lambda c: c.created_at):
        if not c.is_system:
            return c.created_at
    return None


def _build_overview(
    case: SummaryCaseRow,
    response: ResponseEffectiveness,
    detection: DetectionTiming,
) -> IncidentOverview:
    nodes = case.observable_graph.get("nodes") if isinstance(case.observable_graph, dict) else None
    nodes_list = nodes if isinstance(nodes, list) else []

    kind_counter: Counter[str] = Counter()
    hosts = identities = 0
    domains: set[str] = set()
    for node in nodes_list:
        if not isinstance(node, dict):
            continue
        kind = str(node.get("kind") or node.get("type") or "unknown").lower()
        kind_counter[kind] += 1
        if kind in {"host", "asset", "device", "endpoint"}:
            hosts += 1
        elif kind in {"user", "identity", "account"}:
            identities += 1
        elif kind == "domain":
            value = node.get("value") or node.get("label")
            if isinstance(value, str) and value:
                domains.add(value)

    parts: list[str] = []
    label = case.case_number or str(case.id)[:8]
    parts.append(f"Case {label} ({case.severity}) — {case.title}.")
    if detection.time_to_detect_hours is not None:
        parts.append(f"Detected in {detection.time_to_detect_hours:.1f}h after first signal.")
    if detection.time_to_resolve_hours is not None:
        parts.append(f"Resolved in {detection.time_to_resolve_hours:.1f}h end-to-end.")
    elif detection.time_to_triage_hours is not None:
        parts.append(f"Triage took {detection.time_to_triage_hours:.1f}h.")
    if detection.sla_breached:
        parts.append("SLA was breached.")
    if response.total_actions:
        parts.append(f"Response involved {response.total_actions} tracked actions ({response.completed} completed).")
    if response.automation_used:
        parts.append("Response leaned on automation/playbooks.")

    return IncidentOverview(
        summary=" ".join(parts),
        severity=case.severity,
        status=case.status,
        blast_radius_hosts=hosts,
        blast_radius_identities=identities,
        blast_radius_alerts=len(case.alert_ids or []),
        distinct_observable_kinds=sorted(kind_counter.keys()),
        affected_domains=sorted(domains)[:25],
    )


def _build_detection(case: SummaryCaseRow, comments: list[SummaryCommentRow], *, now: datetime) -> DetectionTiming:
    first_touch = _first_analyst_touch(comments)
    return DetectionTiming(
        opened_at=case.opened_at,
        first_analyst_touch_at=first_touch,
        triaged_at=case.triaged_at,
        resolved_at=case.resolved_at,
        closed_at=case.closed_at,
        sla_due_at=case.sla_due_at,
        time_to_detect_hours=_hours_between(first_touch, case.opened_at),
        time_to_triage_hours=_hours_between(case.triaged_at, case.opened_at),
        time_to_resolve_hours=_hours_between(case.resolved_at, case.opened_at),
        time_to_close_hours=_hours_between(case.closed_at, case.opened_at),
        sla_breached=bool(case.sla_due_at and (case.resolved_at or case.closed_at or now) > case.sla_due_at),
    )


def _build_detection_gaps(detection: DetectionTiming, case: SummaryCaseRow) -> list[DetectionGap]:
    gaps: list[DetectionGap] = []

    if detection.time_to_detect_hours is None:
        gaps.append(
            DetectionGap(
                severity="info",
                title="No analyst touched this case in the timeline",
                body=(
                    "Either the case auto-resolved without analyst review or "
                    "the activity stream wasn't captured. Consider whether "
                    "auto-resolution was appropriate for this severity."
                ),
            )
        )
    elif detection.time_to_detect_hours > 4:
        gaps.append(
            DetectionGap(
                severity="warning",
                title=f"First analyst touch took {detection.time_to_detect_hours:.1f}h",
                body=(
                    "The signal sat in the queue for over four hours before an "
                    "analyst engaged. Review on-call rotations, paging "
                    "thresholds, and whether the originating detection should "
                    "auto-page for this severity."
                ),
            )
        )

    if detection.time_to_triage_hours is not None and detection.time_to_triage_hours > 8:
        gaps.append(
            DetectionGap(
                severity="warning",
                title=f"Triage took {detection.time_to_triage_hours:.1f}h",
                body=(
                    "Triage exceeded eight hours from open. Determine whether "
                    "the originating detection had enough enrichment context "
                    "to support fast triage, or whether routing rules need "
                    "updating."
                ),
            )
        )

    if detection.sla_breached:
        gaps.append(
            DetectionGap(
                severity="critical",
                title="Case breached its SLA",
                body=(
                    "The case ran past its stated SLA. Capture the structural "
                    "cause — analyst load, missing automation, escalation gap "
                    "— so the next on-call rotation has the context to break "
                    "the pattern."
                ),
            )
        )

    if not case.mitre_techniques:
        gaps.append(
            DetectionGap(
                severity="info",
                title="No MITRE ATT&CK technique tagged",
                body=(
                    "Tagging at least one technique improves coverage "
                    "reporting and helps tune the detection set. Review the "
                    "originating detection content for this incident."
                ),
            )
        )

    return gaps


def _build_timeline(
    case: SummaryCaseRow,
    comments: list[SummaryCommentRow],
    tasks: list[SummaryTaskRow],
    *,
    limit: int = 30,
) -> list[TimelineEntry]:
    """Merge case lifecycle, system comments, and task creations into a
    blameless retrospective feed.

    Author names are deliberately *not* included — this artefact is intended
    to be shared across teams without surfacing individuals. The full
    activity stream is still available on the case itself.
    """
    events: list[TimelineEntry] = []

    events.append(TimelineEntry(ts=case.opened_at, phase="detection", label="Case opened"))
    if case.triaged_at:
        events.append(TimelineEntry(ts=case.triaged_at, phase="triage", label="Triaged"))
    if case.resolved_at:
        events.append(TimelineEntry(ts=case.resolved_at, phase="resolution", label="Resolved"))
    if case.closed_at:
        events.append(TimelineEntry(ts=case.closed_at, phase="closure", label="Closed"))

    first_analyst = _first_analyst_touch(comments)
    if first_analyst is not None:
        events.append(TimelineEntry(ts=first_analyst, phase="triage", label="First analyst engagement"))

    # Prefer system comments (they describe automated actions / playbook runs)
    # over analyst notes — analyst notes belong on the case, not in the retro.
    for c in comments:
        if not c.is_system:
            continue
        body = (c.body or "").strip().replace("\n", " ")
        if len(body) > 140:
            body = body[:137] + "…"
        events.append(
            TimelineEntry(
                ts=c.created_at,
                phase="investigation",
                label="System action",
                detail=body or None,
            )
        )

    for t in tasks:
        bucket = _bucket_response_action(t.title)
        events.append(
            TimelineEntry(
                ts=t.created_at,
                phase="response",
                label=f"Response action created: {t.title}",
                detail=f"bucket={bucket} · status={t.status}",
            )
        )

    events.sort(key=lambda e: e.ts)
    if len(events) <= limit:
        return events

    # Always keep the lifecycle/triage events; trim noise from the middle.
    lifecycle_phases = {"detection", "triage", "resolution", "closure"}
    keep = [e for e in events if e.phase in lifecycle_phases]
    other = [e for e in events if e.phase not in lifecycle_phases]
    keep_other = max(limit - len(keep), 0)
    other = other[-keep_other:] if keep_other else []
    return sorted(keep + other, key=lambda e: e.ts)


def _build_went_well(
    case: SummaryCaseRow,
    detection: DetectionTiming,
    response: ResponseEffectiveness,
) -> list[WentWellItem]:
    items: list[WentWellItem] = []

    if detection.time_to_detect_hours is not None and detection.time_to_detect_hours <= 0.5:
        items.append(
            WentWellItem(
                title="Fast first analyst engagement",
                body=(
                    f"An analyst engaged within "
                    f"{detection.time_to_detect_hours:.1f}h of the case "
                    "opening — this is what the rotation should look like. "
                    "Capture what made the page land cleanly so the pattern "
                    "is repeatable."
                ),
            )
        )

    if detection.time_to_resolve_hours is not None and detection.time_to_resolve_hours <= 4 and case.severity in {"high", "critical"}:
        items.append(
            WentWellItem(
                title="Fast resolution on a high-severity case",
                body=(
                    f"Resolved in {detection.time_to_resolve_hours:.1f}h end-"
                    "to-end. This is a strong reference incident for future "
                    "on-call training."
                ),
            )
        )

    if response.automation_used:
        items.append(
            WentWellItem(
                title="Automation engaged in response",
                body=(
                    "Response leaned on a playbook / automation. Confirm the "
                    "playbook output was reviewed before each destructive "
                    "step, then promote the playbook in the runbook index."
                ),
            )
        )

    if response.total_actions and response.completed == response.total_actions:
        items.append(
            WentWellItem(
                title="All response actions closed before archival",
                body=(
                    "Every tracked response action was completed. The case "
                    "closed cleanly with no orphan tasks — exactly the bar "
                    "to hold for future incidents."
                ),
            )
        )

    if not detection.sla_breached and detection.sla_due_at is not None:
        items.append(
            WentWellItem(
                title="SLA met",
                body=("The team resolved/closed inside the SLA window. Note what made the path linear so the rotation can replay it."),
            )
        )

    return items


def _build_fell_short(
    case: SummaryCaseRow,
    detection: DetectionTiming,
    response: ResponseEffectiveness,
    comments: list[SummaryCommentRow],
) -> list[FellShortItem]:
    items: list[FellShortItem] = []

    if detection.sla_breached:
        items.append(
            FellShortItem(
                title="SLA breached",
                body=(
                    "The case ran past its SLA. Document the single biggest "
                    "structural cause (queue backlog, missing playbook, "
                    "escalation gap) so the next rotation can target it."
                ),
            )
        )

    if response.overdue:
        items.append(
            FellShortItem(
                title=f"{response.overdue} response action{'s' if response.overdue != 1 else ''} overdue at archival",
                body=(
                    "Tasks past their due date were still open when the case "
                    "moved toward closure. Either close them out, reassign, "
                    "or document why the original deadline was unrealistic."
                ),
            )
        )

    if case.severity in {"high", "critical"} and not any(not c.is_system for c in comments):
        items.append(
            FellShortItem(
                title="No analyst narrative on a high-severity case",
                body=(
                    "A high or critical case is closing without any analyst "
                    "note explaining what was found and what was done. Add "
                    "a closing note before archival so the next on-call has "
                    "a precedent to follow."
                ),
            )
        )

    if response.total_actions == 0 and case.severity in {"high", "critical"}:
        items.append(
            FellShortItem(
                title="No tracked response actions",
                body=(
                    "A high/critical case has zero tracked response actions. "
                    "Either the work happened off-system (capture it on the "
                    "case for the next rotation) or the case was closed "
                    "without containment — both are worth surfacing."
                ),
            )
        )

    if not case.mitre_techniques:
        items.append(
            FellShortItem(
                title="MITRE ATT&CK coverage missing",
                body=(
                    "No technique was tagged on the case. Coverage reporting "
                    "and detection tuning both depend on this being filled "
                    "in — make it part of the closure checklist."
                ),
            )
        )

    return items


def _build_action_items(
    case: SummaryCaseRow,
    detection: DetectionTiming,
    response: ResponseEffectiveness,
    gaps: list[DetectionGap],
    fell_short: list[FellShortItem],
) -> list[ActionItem]:
    """Concrete, blameless follow-ups. Owners are *roles*, not people."""
    items: list[ActionItem] = []

    if detection.time_to_detect_hours is not None and detection.time_to_detect_hours > 4:
        items.append(
            ActionItem(
                category="detection",
                severity="warning",
                title="Tune the originating detection for faster paging",
                body=(
                    "First analyst touch took over four hours. Evaluate "
                    "whether the originating detection should auto-page at "
                    "this severity, or whether enrichment can shorten the "
                    "queue dwell time."
                ),
                owner_role="detection engineering",
            )
        )

    if detection.time_to_triage_hours is not None and detection.time_to_triage_hours > 8:
        items.append(
            ActionItem(
                category="runbook",
                severity="warning",
                title="Add a triage runbook for this signal class",
                body=(
                    "Triage took over eight hours. A short runbook for this "
                    "signal would let the next analyst reach a triage "
                    "decision faster."
                ),
                owner_role="on-call lead",
            )
        )

    if detection.sla_breached:
        items.append(
            ActionItem(
                category="process",
                severity="critical",
                title="Review SLA / escalation policy",
                body=(
                    "Bring the SLA breach to the next operations review. "
                    "Decide whether the SLA target is right, or whether "
                    "automation/escalation needs investment to keep it."
                ),
                owner_role="on-call lead",
            )
        )

    if response.overdue:
        items.append(
            ActionItem(
                category="process",
                severity="warning",
                title="Close out overdue response actions",
                body=(
                    "Several response actions were overdue at archival. "
                    "Either close them, reassign, or update the due dates "
                    "so the case file reflects reality."
                ),
                owner_role="case owner",
            )
        )

    if not response.automation_used and response.total_actions >= 3:
        items.append(
            ActionItem(
                category="automation",
                severity="info",
                title="Identify an automation candidate",
                body=(
                    "This case had several manual response actions. Pick "
                    "the most repetitive one and turn it into a playbook so "
                    "the next occurrence is one click."
                ),
                owner_role="security automation",
            )
        )

    if not case.mitre_techniques:
        items.append(
            ActionItem(
                category="detection",
                severity="info",
                title="Tag MITRE ATT&CK on this case",
                body=("Add at least one ATT&CK technique to the case so coverage reporting reflects this incident."),
                owner_role="case owner",
            )
        )

    # If we still have nothing, surface a neutral "no follow-ups required"
    # marker so the artefact is still complete-looking.
    if not items and not fell_short and not gaps:
        items.append(
            ActionItem(
                category="process",
                severity="info",
                title="No structural follow-ups required",
                body=(
                    "Detection, triage, and response all executed cleanly. Archive the case and roll any new IOCs into detection content."
                ),
                owner_role="case owner",
            )
        )

    return items


def _build_headline(case: SummaryCaseRow, detection: DetectionTiming, response: ResponseEffectiveness) -> str:
    parts: list[str] = []
    label = case.case_number or str(case.id)[:8]
    parts.append(f"{label} {case.severity.upper()} retrospective")
    if detection.time_to_resolve_hours is not None:
        parts.append(f"resolved in {detection.time_to_resolve_hours:.1f}h")
    if detection.sla_breached:
        parts.append("SLA breached")
    if response.total_actions:
        parts.append(f"{response.completed}/{response.total_actions} response actions closed")
    return " · ".join(parts)


# ---------------------------------------------------------------------------
# Pure top-level builder.
# ---------------------------------------------------------------------------


def build_postmortem_from_rows(
    inputs: PostmortemInputs,
    *,
    now: datetime | None = None,
) -> CasePostmortem:
    """Pure function: rows in → ``CasePostmortem`` out. Deterministic."""
    moment = now or datetime.now(UTC)
    case = inputs.case

    detection = _build_detection(case, inputs.comments, now=moment)
    response = _summarise_response(inputs.tasks, now=moment)
    overview = _build_overview(case, response, detection)
    gaps = _build_detection_gaps(detection, case)
    timeline = _build_timeline(case, inputs.comments, inputs.tasks)
    went_well = _build_went_well(case, detection, response)
    fell_short = _build_fell_short(case, detection, response, inputs.comments)
    action_items = _build_action_items(case, detection, response, gaps, fell_short)
    headline = _build_headline(case, detection, response)

    return CasePostmortem(
        generated_at=moment,
        headline=headline,
        case=PostmortemHeader(
            case_id=case.id,
            case_number=case.case_number,
            title=case.title,
            severity=case.severity,
            status=case.status,
            tags=dict(case.tags or {}),
        ),
        overview=overview,
        detection=detection,
        detection_gaps=gaps,
        response=response,
        timeline=timeline,
        went_well=went_well,
        fell_short=fell_short,
        action_items=action_items,
    )


# ---------------------------------------------------------------------------
# DB orchestrator.
# ---------------------------------------------------------------------------


async def build_case_postmortem(
    db: AsyncSession,
    case_id: uuid.UUID,
    *,
    now: datetime | None = None,
) -> CasePostmortem | None:
    """Async orchestrator: pull rows for one case and build the post-mortem.

    Returns ``None`` if the case isn't found, so the endpoint can surface a
    clean 404 without conflating the data layer with HTTP semantics.

    SQL access is delegated to the auto-summary fetchers — they already
    return the exact dataclasses we need.
    """
    case = await _fetch_case_for_summary(db, case_id)
    if case is None:
        return None
    comments = await _fetch_comments(db, case_id)
    tasks = await _fetch_tasks(db, case_id)
    inputs = PostmortemInputs(case=case, comments=comments, tasks=tasks)
    return build_postmortem_from_rows(inputs, now=now)


# Re-exported for callers who want to assemble inputs themselves (tests,
# off-line fixtures, etc.) without re-importing from case_summary directly.
__all__ = [
    "ActionItem",
    "CasePostmortem",
    "CaseSummaryInputs",
    "DetectionGap",
    "DetectionTiming",
    "FellShortItem",
    "IncidentOverview",
    "PostmortemHeader",
    "PostmortemInputs",
    "ResponseAction",
    "ResponseEffectiveness",
    "SummaryCaseRow",
    "SummaryCommentRow",
    "SummaryTaskRow",
    "TimelineEntry",
    "WentWellItem",
    "build_case_postmortem",
    "build_postmortem_from_rows",
    "_internal_helpers",
]


# Internal helpers exported for tests.
_internal_helpers: dict[str, Any] = {
    "_hours_between": _hours_between,
    "_bucket_response_action": _bucket_response_action,
    "_summarise_response": _summarise_response,
    "_first_analyst_touch": _first_analyst_touch,
    "_build_overview": _build_overview,
    "_build_detection": _build_detection,
    "_build_detection_gaps": _build_detection_gaps,
    "_build_timeline": _build_timeline,
    "_build_went_well": _build_went_well,
    "_build_fell_short": _build_fell_short,
    "_build_action_items": _build_action_items,
    "_build_headline": _build_headline,
}
