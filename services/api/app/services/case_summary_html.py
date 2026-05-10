"""HTML renderer for the per-case auto-summary.

WS-D2 — buyer-value plan
========================
Produces a self-contained, print-ready document for a ``CaseAutoSummary``.
Mirrors the design language of the executive digest renderer (WS-G2) so
operators get a consistent visual identity across reports — but the data
shape is per-case, not tenant-wide.

Design goals
------------
* Pure function: same summary in, same HTML out (deterministic).
* Inline CSS only, so the document is portable when downloaded.
* Print-friendly typography and colour-blind-safe palette.
* Defensive HTML escaping — every field touches tenant data.
"""

from __future__ import annotations

import html
from datetime import UTC, datetime

from .case_summary import (
    CaseAutoSummary,
    CaseLifecycleTimings,
    CaseRecommendation,
    CaseSummaryHeader,
    CommentBreakdown,
    CoverageSummary,
    EvidenceSummary,
    ObservableSummary,
    TaskBreakdown,
    TimelineHighlight,
)

_SEVERITY_COLOURS: dict[str, str] = {
    "critical": "#b91c1c",
    "high": "#c2410c",
    "medium": "#a16207",
    "low": "#1d4ed8",
    "info": "#475569",
}

_REC_COLOURS: dict[str, str] = {
    "critical": "#b91c1c",
    "warning": "#a16207",
    "info": "#1d4ed8",
}


def _esc(value: object) -> str:
    return html.escape("" if value is None else str(value))


def _fmt_hours(hours: float | None) -> str:
    if hours is None:
        return "—"
    if hours < 1:
        return f"{round(hours * 60)}m"
    return f"{hours:.1f}h"


def _fmt_datetime(value: datetime | None) -> str:
    if value is None:
        return "—"
    return value.strftime("%Y-%m-%d %H:%M UTC")


def _severity_chip(severity: str) -> str:
    colour = _SEVERITY_COLOURS.get(severity, "#475569")
    return (
        f'<span style="display:inline-block;padding:2px 8px;border-radius:9999px;'
        f"background:{colour};color:#fff;font-size:11px;text-transform:uppercase;"
        f'letter-spacing:0.04em;">{_esc(severity)}</span>'
    )


def _kpi(label: str, value: str, *, hint: str | None = None) -> str:
    hint_html = f'<div style="font-size:11px;color:#64748b;margin-top:2px;">{_esc(hint)}</div>' if hint else ""
    return (
        '<div style="flex:1 1 140px;background:#f8fafc;border:1px solid #e2e8f0;'
        'border-radius:8px;padding:12px 14px;min-width:140px;">'
        f'<div style="font-size:11px;color:#64748b;text-transform:uppercase;'
        f'letter-spacing:0.06em;">{_esc(label)}</div>'
        f'<div style="font-size:22px;font-weight:600;color:#0f172a;'
        f'margin-top:4px;">{_esc(value)}</div>'
        f"{hint_html}</div>"
    )


def _header_block(case: CaseSummaryHeader, lifecycle: CaseLifecycleTimings, headline: str) -> str:
    label = case.case_number or str(case.case_id)[:8]
    return (
        "<header>"
        '<div style="font-size:11px;color:#64748b;text-transform:uppercase;'
        'letter-spacing:0.08em;">AiSOC case auto-summary</div>'
        f"<h1>{_esc(label)} — {_esc(case.title)}</h1>"
        f'<div style="margin-top:6px;">{_severity_chip(case.severity)} '
        f'<span style="display:inline-block;padding:2px 8px;border-radius:9999px;'
        f'background:#e2e8f0;color:#0f172a;font-size:11px;margin-left:6px;">'
        f"{_esc(case.status)}</span></div>"
        f'<div style="color:#334155;font-size:14px;margin-top:8px;">{_esc(headline)}</div>'
        f'<div style="color:#94a3b8;font-size:11px;margin-top:6px;">'
        f"Case {_esc(case.case_id)} · "
        f"opened {_fmt_datetime(lifecycle.opened_at)} · "
        f"generated {_fmt_datetime(datetime.now(UTC))}</div>"
        "</header>"
    )


def _description_block(case: CaseSummaryHeader) -> str:
    if not case.description:
        return ""
    return (
        '<div style="background:#f8fafc;border:1px solid #e2e8f0;'
        "border-radius:8px;padding:12px 14px;margin-top:14px;color:#0f172a;"
        f'font-size:13px;line-height:1.55;">{_esc(case.description)}</div>'
    )


def _kpi_strip(summary: CaseAutoSummary) -> str:
    lifecycle = summary.lifecycle
    return (
        '<div style="display:flex;flex-wrap:wrap;gap:12px;">'
        + _kpi("Opened", _fmt_datetime(lifecycle.opened_at))
        + _kpi("Triaged", _fmt_datetime(lifecycle.triaged_at))
        + _kpi("Resolved", _fmt_datetime(lifecycle.resolved_at))
        + _kpi("Closed", _fmt_datetime(lifecycle.closed_at))
        + _kpi("Time to triage", _fmt_hours(lifecycle.time_to_triage_hours))
        + _kpi("Time to resolve", _fmt_hours(lifecycle.time_to_resolve_hours))
        + _kpi("Time to close", _fmt_hours(lifecycle.time_to_close_hours))
        + _kpi(
            "SLA",
            "Breached" if lifecycle.sla_breached else "Met",
            hint=_fmt_datetime(lifecycle.sla_due_at) if lifecycle.sla_due_at else None,
        )
        + "</div>"
    )


def _coverage_block(coverage: CoverageSummary) -> str:
    techniques = coverage.mitre_techniques
    tactic_rows = ""
    if coverage.mitre_tactic_buckets:
        tactic_rows = (
            '<table style="width:100%;border-collapse:collapse;font-size:13px;'
            'margin-top:8px;"><thead><tr style="text-align:left;color:#64748b;'
            'font-size:11px;text-transform:uppercase;letter-spacing:0.06em;">'
            '<th style="padding:6px 8px;">Tactic</th>'
            '<th style="padding:6px 8px;text-align:right;">Techniques</th></tr></thead>'
            "<tbody>"
            + "".join(
                f'<tr><td style="padding:6px 8px;">{_esc(tactic)}</td>'
                f'<td style="padding:6px 8px;text-align:right;font-weight:600;">{count}</td></tr>'
                for tactic, count in sorted(
                    coverage.mitre_tactic_buckets.items(),
                    key=lambda x: (-x[1], x[0]),
                )
            )
            + "</tbody></table>"
        )

    technique_chips = (
        '<div style="margin-top:8px;display:flex;flex-wrap:wrap;gap:6px;">'
        + "".join(
            f'<span style="padding:2px 8px;border-radius:9999px;background:#eef2ff;color:#3730a3;font-size:11px;">{_esc(t)}</span>'
            for t in techniques
        )
        + "</div>"
        if techniques
        else '<p style="color:#64748b;font-size:13px;">No MITRE techniques tagged.</p>'
    )

    frameworks = (
        '<div style="margin-top:8px;display:flex;flex-wrap:wrap;gap:6px;">'
        + "".join(
            f'<span style="padding:2px 8px;border-radius:9999px;background:#ecfdf5;color:#047857;font-size:11px;">{_esc(f)}</span>'
            for f in coverage.compliance_frameworks
        )
        + "</div>"
        if coverage.compliance_frameworks
        else '<p style="color:#64748b;font-size:13px;">No compliance frameworks tagged.</p>'
    )

    return "<h2>MITRE ATT&amp;CK techniques</h2>" + technique_chips + tactic_rows + "<h2>Compliance frameworks</h2>" + frameworks


def _evidence_block(
    observables: ObservableSummary,
    evidence: EvidenceSummary,
    alerts: dict[str, object],
) -> str:
    return (
        "<h2>Evidence &amp; observables</h2>"
        '<div style="display:flex;flex-wrap:wrap;gap:12px;">'
        + _kpi("Linked alerts", str(alerts.get("count", 0)))
        + _kpi(
            "Observables",
            f"{observables.total_nodes} nodes",
            hint=f"{observables.total_edges} edges",
        )
        + _kpi(
            "Evidence items",
            str(evidence.total_items),
            hint=", ".join(evidence.distinct_kinds) or None,
        )
        + "</div>"
    )


def _activity_block(tasks: TaskBreakdown, comments: CommentBreakdown) -> str:
    overdue_hint = f"{tasks.overdue} overdue" if tasks.overdue else None
    authors_hint = ", ".join(comments.distinct_authors[:3]) if comments.distinct_authors else None
    return (
        "<h2>Activity</h2>"
        '<div style="display:flex;flex-wrap:wrap;gap:12px;">'
        + _kpi("Tasks (total)", str(tasks.total))
        + _kpi("Tasks done", str(tasks.done), hint=overdue_hint)
        + _kpi(
            "Tasks open",
            str(tasks.todo + tasks.in_progress),
            hint=f"{tasks.todo} todo · {tasks.in_progress} in progress",
        )
        + _kpi("Analyst notes", str(comments.analyst), hint=authors_hint)
        + _kpi("System notes", str(comments.system))
        + "</div>"
    )


def _timeline_block(events: list[TimelineHighlight]) -> str:
    if not events:
        return ""
    rows = "".join(
        "<tr>"
        f'<td style="padding:6px 8px;color:#64748b;font-size:11px;'
        f'white-space:nowrap;">{_fmt_datetime(e.ts)}</td>'
        f'<td style="padding:6px 8px;color:#475569;font-size:11px;text-transform:uppercase;'
        f'letter-spacing:0.06em;">{_esc(e.kind)}</td>'
        f'<td style="padding:6px 8px;color:#0f172a;">{_esc(e.label)}</td>'
        f'<td style="padding:6px 8px;color:#475569;font-size:12px;">'
        f"{_esc(e.detail) if e.detail else '—'}</td>"
        "</tr>"
        for e in events
    )
    return (
        "<h2>Timeline</h2>"
        '<table style="width:100%;border-collapse:collapse;font-size:13px;">'
        '<thead><tr style="text-align:left;color:#64748b;font-size:11px;'
        'text-transform:uppercase;letter-spacing:0.06em;">'
        '<th style="padding:6px 8px;">When</th>'
        '<th style="padding:6px 8px;">Kind</th>'
        '<th style="padding:6px 8px;">Label</th>'
        '<th style="padding:6px 8px;">Detail</th></tr></thead>'
        f"<tbody>{rows}</tbody></table>"
    )


def _recommendation_block(recs: list[CaseRecommendation]) -> str:
    if not recs:
        return ""
    cards = "".join(
        '<div style="border-left:4px solid {colour};background:#f8fafc;'
        'padding:12px 14px;border-radius:6px;margin-bottom:10px;">'
        '<div style="font-weight:600;color:#0f172a;font-size:14px;'
        f'margin-bottom:4px;">{_esc(r.title)}</div>'
        f'<div style="color:#334155;font-size:13px;line-height:1.45;">{_esc(r.body)}</div>'
        "</div>".format(colour=_REC_COLOURS.get(r.severity, "#475569"))
        for r in recs
    )
    return "<h2>Post-mortem</h2>" + cards


def render_case_summary_html(summary: CaseAutoSummary) -> str:
    """Render a ``CaseAutoSummary`` to a self-contained HTML document."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>AiSOC Case Summary — {_esc(summary.case.case_number or summary.case.title)}</title>
<style>
  @page {{ margin: 18mm; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    color: #0f172a;
    background: #ffffff;
    margin: 0;
    padding: 24px 32px;
    line-height: 1.45;
  }}
  h1, h2, h3 {{ color: #0f172a; margin-top: 0; }}
  h1 {{ font-size: 22px; margin-bottom: 4px; }}
  h2 {{ font-size: 15px; text-transform: uppercase; letter-spacing: 0.08em;
       color: #475569; margin: 20px 0 10px; border-top: 1px solid #e2e8f0; padding-top: 14px; }}
  table th, table td {{ border-bottom: 1px solid #f1f5f9; }}
  @media print {{
    body {{ padding: 0; }}
    h2 {{ page-break-after: avoid; }}
  }}
</style>
</head>
<body>
  {_header_block(summary.case, summary.lifecycle, summary.headline)}
  {_description_block(summary.case)}

  <h2>Lifecycle</h2>
  {_kpi_strip(summary)}

  {_coverage_block(summary.coverage)}

  {_evidence_block(summary.observables, summary.evidence, summary.alerts)}

  {_activity_block(summary.tasks, summary.comments)}

  {_timeline_block(summary.timeline)}

  {_recommendation_block(summary.recommendations)}

  <footer style="margin-top:32px;color:#94a3b8;font-size:11px;text-align:center;">
    AiSOC — open-source AI Security Operations Center.
    Print this page (Ctrl/Cmd-P → Save as PDF) for case-file archival.
  </footer>
</body>
</html>"""


__all__ = ["render_case_summary_html"]
