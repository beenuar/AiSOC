"""HTML renderer for the per-case auto post-mortem (Stage 3 #21).

Sibling of :pymod:`app.services.case_summary_html`. Mirrors the same design
goals so the two artefacts feel like a matched pair when an analyst has
both open in adjacent tabs:

  * Pure function: same post-mortem in, same HTML out (deterministic).
  * Inline CSS only — the document is portable when downloaded.
  * Print-friendly typography and colour-blind-safe palette.
  * Defensive HTML escaping — every field touches tenant data.
  * Blameless: the body never names individuals; the timeline carries
    *what happened*, not *who did it*.

The two renderers share aesthetic choices on purpose (page margins, header
chip layout, KPI strip) but live in separate files so each can be tuned
independently — the post-mortem document is structured around different
questions (overview / detection / response / lessons) than the snapshot.
"""

from __future__ import annotations

from datetime import UTC, datetime
from html import escape

from .case_postmortem import (
    ActionItem,
    CasePostmortem,
    DetectionGap,
    DetectionTiming,
    FellShortItem,
    IncidentOverview,
    PostmortemHeader,
    ResponseEffectiveness,
    TimelineEntry,
    WentWellItem,
)

_SEVERITY_COLOURS: dict[str, str] = {
    "info": "#0ea5e9",
    "warning": "#f59e0b",
    "critical": "#dc2626",
}

_PHASE_COLOURS: dict[str, str] = {
    "detection": "#0ea5e9",
    "triage": "#6366f1",
    "investigation": "#8b5cf6",
    "response": "#f59e0b",
    "resolution": "#16a34a",
    "closure": "#475569",
}

_BUCKET_LABELS: dict[str, str] = {
    "containment": "Containment",
    "eradication": "Eradication",
    "recovery": "Recovery",
    "communication": "Communication",
    "investigation": "Investigation",
    "other": "Other",
}


def _esc(value: object) -> str:
    if value is None:
        return ""
    return escape(str(value))


def _fmt_hours(hours: float | None) -> str:
    if hours is None:
        return "—"
    if hours < 1:
        return f"{hours * 60:.0f}m"
    if hours < 48:
        return f"{hours:.1f}h"
    return f"{hours / 24:.1f}d"


def _fmt_datetime(value: datetime | None) -> str:
    if value is None:
        return "—"
    return value.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")


def _severity_chip(severity: str) -> str:
    colour = _SEVERITY_COLOURS.get(severity.lower(), "#475569")
    return (
        f'<span style="display:inline-block;padding:2px 8px;border-radius:9999px;'
        f"background:{colour};color:#fff;font-size:11px;font-weight:600;"
        f'text-transform:uppercase;letter-spacing:0.04em;">{_esc(severity)}</span>'
    )


def _kpi(label: str, value: str, *, hint: str | None = None) -> str:
    hint_html = f'<div style="color:#94a3b8;font-size:11px;margin-top:2px;">{_esc(hint)}</div>' if hint else ""
    return (
        '<div style="flex:1 1 140px;min-width:140px;background:#f8fafc;'
        'border:1px solid #e2e8f0;border-radius:8px;padding:10px 12px;">'
        f'<div style="color:#64748b;font-size:11px;text-transform:uppercase;'
        f'letter-spacing:0.06em;">{_esc(label)}</div>'
        f'<div style="color:#0f172a;font-size:18px;font-weight:600;'
        f'margin-top:4px;">{_esc(value)}</div>'
        f"{hint_html}</div>"
    )


def _header_block(case: PostmortemHeader, headline: str, generated_at: datetime) -> str:
    return (
        '<header style="border-bottom:2px solid #0f172a;padding-bottom:14px;">'
        f'<div style="color:#475569;font-size:11px;text-transform:uppercase;'
        f'letter-spacing:0.08em;">Blameless retrospective</div>'
        f'<h1 style="margin:6px 0 0;">{_esc(case.case_number or case.title)}</h1>'
        f'<div style="margin-top:6px;">{_severity_chip(case.severity)}'
        f'<span style="display:inline-block;padding:2px 8px;border-radius:9999px;'
        f'background:#e2e8f0;color:#0f172a;font-size:11px;margin-left:6px;">'
        f"{_esc(case.status)}</span></div>"
        f'<div style="color:#334155;font-size:14px;margin-top:8px;">{_esc(headline)}</div>'
        f'<div style="color:#94a3b8;font-size:11px;margin-top:6px;">'
        f"Case {_esc(case.case_id)} · "
        f"generated {_fmt_datetime(generated_at)} · "
        "blameless / system-focused</div>"
        "</header>"
    )


def _overview_block(overview: IncidentOverview) -> str:
    domains_html = (
        '<div style="margin-top:8px;display:flex;flex-wrap:wrap;gap:6px;">'
        + "".join(
            f'<span style="padding:2px 8px;border-radius:9999px;background:#fef3c7;color:#92400e;font-size:11px;">{_esc(d)}</span>'
            for d in overview.affected_domains
        )
        + "</div>"
        if overview.affected_domains
        else ""
    )

    kinds_html = (
        '<div style="margin-top:8px;display:flex;flex-wrap:wrap;gap:6px;">'
        + "".join(
            f'<span style="padding:2px 8px;border-radius:9999px;background:#eef2ff;color:#3730a3;font-size:11px;">{_esc(k)}</span>'
            for k in overview.distinct_observable_kinds
        )
        + "</div>"
        if overview.distinct_observable_kinds
        else ""
    )

    return (
        "<h2>Incident overview</h2>"
        '<div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;'
        f'padding:12px 14px;color:#0f172a;font-size:13px;line-height:1.55;">'
        f"{_esc(overview.summary)}</div>"
        '<div style="display:flex;flex-wrap:wrap;gap:12px;margin-top:12px;">'
        + _kpi("Hosts touched", str(overview.blast_radius_hosts))
        + _kpi("Identities touched", str(overview.blast_radius_identities))
        + _kpi("Linked alerts", str(overview.blast_radius_alerts))
        + "</div>"
        + (
            (
                '<div style="margin-top:12px;color:#64748b;font-size:11px;'
                'text-transform:uppercase;letter-spacing:0.06em;">Observable kinds</div>'
                f"{kinds_html}"
            )
            if kinds_html
            else ""
        )
        + (
            (
                '<div style="margin-top:12px;color:#64748b;font-size:11px;'
                'text-transform:uppercase;letter-spacing:0.06em;">Affected domains</div>'
                f"{domains_html}"
            )
            if domains_html
            else ""
        )
    )


def _detection_block(detection: DetectionTiming, gaps: list[DetectionGap]) -> str:
    kpi_strip = (
        '<div style="display:flex;flex-wrap:wrap;gap:12px;">'
        + _kpi("Time to detect", _fmt_hours(detection.time_to_detect_hours))
        + _kpi("Time to triage", _fmt_hours(detection.time_to_triage_hours))
        + _kpi("Time to resolve", _fmt_hours(detection.time_to_resolve_hours))
        + _kpi("Time to close", _fmt_hours(detection.time_to_close_hours))
        + _kpi(
            "SLA",
            "Breached" if detection.sla_breached else "Met",
            hint=_fmt_datetime(detection.sla_due_at) if detection.sla_due_at else None,
        )
        + "</div>"
    )

    timestamps_table = (
        '<table style="width:100%;border-collapse:collapse;font-size:13px;margin-top:10px;">'
        "<tbody>"
        f'<tr><td style="padding:6px 8px;color:#64748b;">Opened</td>'
        f'<td style="padding:6px 8px;">{_fmt_datetime(detection.opened_at)}</td></tr>'
        f'<tr><td style="padding:6px 8px;color:#64748b;">First analyst engagement</td>'
        f'<td style="padding:6px 8px;">{_fmt_datetime(detection.first_analyst_touch_at)}</td></tr>'
        f'<tr><td style="padding:6px 8px;color:#64748b;">Triaged</td>'
        f'<td style="padding:6px 8px;">{_fmt_datetime(detection.triaged_at)}</td></tr>'
        f'<tr><td style="padding:6px 8px;color:#64748b;">Resolved</td>'
        f'<td style="padding:6px 8px;">{_fmt_datetime(detection.resolved_at)}</td></tr>'
        f'<tr><td style="padding:6px 8px;color:#64748b;">Closed</td>'
        f'<td style="padding:6px 8px;">{_fmt_datetime(detection.closed_at)}</td></tr>'
        "</tbody></table>"
    )

    gaps_html = ""
    if gaps:
        cards = "".join(
            '<div style="border-left:4px solid {colour};background:#f8fafc;'
            'padding:12px 14px;border-radius:6px;margin-bottom:10px;">'
            '<div style="font-weight:600;color:#0f172a;font-size:14px;'
            f'margin-bottom:4px;">{_esc(g.title)}</div>'
            f'<div style="color:#334155;font-size:13px;line-height:1.45;">{_esc(g.body)}</div>'
            "</div>".format(colour=_SEVERITY_COLOURS.get(g.severity, "#475569"))
            for g in gaps
        )
        gaps_html = (
            '<h3 style="margin-top:18px;font-size:13px;color:#475569;text-transform:uppercase;letter-spacing:0.06em;">Detection gaps</h3>'
            + cards
        )
    else:
        gaps_html = '<p style="color:#64748b;font-size:13px;">No detection gaps surfaced from the timeline.</p>'

    return "<h2>Detection &amp; timing</h2>" + kpi_strip + timestamps_table + gaps_html


def _response_block(response: ResponseEffectiveness) -> str:
    overall = (
        '<div style="display:flex;flex-wrap:wrap;gap:12px;">'
        + _kpi("Total response actions", str(response.total_actions))
        + _kpi("Completed", str(response.completed))
        + _kpi(
            "Open",
            str(response.open),
            hint=f"{response.overdue} overdue" if response.overdue else None,
        )
        + _kpi("Automation engaged", "Yes" if response.automation_used else "No")
        + "</div>"
    )

    if not response.actions_by_bucket:
        return (
            "<h2>Response actions</h2>" + overall + '<p style="color:#64748b;font-size:13px;">No tracked response actions on this case.</p>'
        )

    rows = "".join(
        "<tr>"
        f'<td style="padding:6px 8px;font-weight:600;">{_esc(_BUCKET_LABELS.get(a.bucket, a.bucket))}</td>'
        f'<td style="padding:6px 8px;text-align:right;">{a.count}</td>'
        f'<td style="padding:6px 8px;text-align:right;">{a.completed}</td>'
        f'<td style="padding:6px 8px;text-align:right;">{a.open}</td>'
        f'<td style="padding:6px 8px;text-align:right;color:{("#dc2626" if a.overdue else "#0f172a")};">{a.overdue}</td>'
        f'<td style="padding:6px 8px;color:#475569;font-size:12px;">{_esc("; ".join(a.sample_titles))}</td>'
        "</tr>"
        for a in response.actions_by_bucket
    )
    table = (
        '<table style="width:100%;border-collapse:collapse;font-size:13px;margin-top:10px;">'
        '<thead><tr style="text-align:left;color:#64748b;font-size:11px;'
        'text-transform:uppercase;letter-spacing:0.06em;">'
        '<th style="padding:6px 8px;">Bucket</th>'
        '<th style="padding:6px 8px;text-align:right;">Total</th>'
        '<th style="padding:6px 8px;text-align:right;">Done</th>'
        '<th style="padding:6px 8px;text-align:right;">Open</th>'
        '<th style="padding:6px 8px;text-align:right;">Overdue</th>'
        '<th style="padding:6px 8px;">Examples</th>'
        "</tr></thead>"
        f"<tbody>{rows}</tbody></table>"
    )
    return "<h2>Response actions</h2>" + overall + table


def _timeline_block(events: list[TimelineEntry]) -> str:
    if not events:
        return ""
    rows = "".join(
        "<tr>"
        f'<td style="padding:6px 8px;color:#64748b;font-size:11px;'
        f'white-space:nowrap;">{_fmt_datetime(e.ts)}</td>'
        f'<td style="padding:6px 8px;font-size:11px;text-transform:uppercase;'
        f'letter-spacing:0.06em;color:{_PHASE_COLOURS.get(e.phase, "#475569")};">{_esc(e.phase)}</td>'
        f'<td style="padding:6px 8px;color:#0f172a;">{_esc(e.label)}</td>'
        f'<td style="padding:6px 8px;color:#475569;font-size:12px;">'
        f"{_esc(e.detail) if e.detail else '—'}</td>"
        "</tr>"
        for e in events
    )
    return (
        "<h2>Retrospective timeline</h2>"
        '<p style="color:#64748b;font-size:12px;margin:0 0 8px;">'
        "Author names are intentionally omitted; this artefact is meant to be shareable across teams. "
        "The full activity stream remains on the case record."
        "</p>"
        '<table style="width:100%;border-collapse:collapse;font-size:13px;">'
        '<thead><tr style="text-align:left;color:#64748b;font-size:11px;'
        'text-transform:uppercase;letter-spacing:0.06em;">'
        '<th style="padding:6px 8px;">When</th>'
        '<th style="padding:6px 8px;">Phase</th>'
        '<th style="padding:6px 8px;">Event</th>'
        '<th style="padding:6px 8px;">Detail</th></tr></thead>'
        f"<tbody>{rows}</tbody></table>"
    )


def _went_well_block(items: list[WentWellItem]) -> str:
    if not items:
        return (
            "<h2>What went well</h2>"
            '<p style="color:#64748b;font-size:13px;">'
            "Nothing structurally praiseworthy surfaced from the timeline. "
            "Capture qualitative wins in the case notes before archival."
            "</p>"
        )
    cards = "".join(
        '<div style="border-left:4px solid #16a34a;background:#f0fdf4;'
        'padding:12px 14px;border-radius:6px;margin-bottom:10px;">'
        f'<div style="font-weight:600;color:#0f172a;font-size:14px;margin-bottom:4px;">{_esc(i.title)}</div>'
        f'<div style="color:#334155;font-size:13px;line-height:1.45;">{_esc(i.body)}</div>'
        "</div>"
        for i in items
    )
    return "<h2>What went well</h2>" + cards


def _fell_short_block(items: list[FellShortItem]) -> str:
    if not items:
        return (
            '<h2>Where we fell short</h2><p style="color:#64748b;font-size:13px;">No structural shortfalls surfaced from the timeline.</p>'
        )
    cards = "".join(
        '<div style="border-left:4px solid #f59e0b;background:#fffbeb;'
        'padding:12px 14px;border-radius:6px;margin-bottom:10px;">'
        f'<div style="font-weight:600;color:#0f172a;font-size:14px;margin-bottom:4px;">{_esc(i.title)}</div>'
        f'<div style="color:#334155;font-size:13px;line-height:1.45;">{_esc(i.body)}</div>'
        "</div>"
        for i in items
    )
    return "<h2>Where we fell short</h2>" + cards


def _action_items_block(items: list[ActionItem]) -> str:
    if not items:
        return ""
    cards = "".join(
        '<div style="border-left:4px solid {colour};background:#f8fafc;'
        'padding:12px 14px;border-radius:6px;margin-bottom:10px;">'
        '<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;">'
        f'<span style="display:inline-block;padding:2px 8px;border-radius:9999px;'
        f"background:#e2e8f0;color:#0f172a;font-size:11px;text-transform:uppercase;"
        f'letter-spacing:0.04em;">{_esc(i.category)}</span>'
        f"{_severity_chip(i.severity)}"
        + (f'<span style="color:#64748b;font-size:11px;">owner: {_esc(i.owner_role)}</span>' if i.owner_role else "")
        + "</div>"
        f'<div style="font-weight:600;color:#0f172a;font-size:14px;margin-bottom:4px;">{_esc(i.title)}</div>'
        f'<div style="color:#334155;font-size:13px;line-height:1.45;">{_esc(i.body)}</div>'
        "</div>".format(colour=_SEVERITY_COLOURS.get(i.severity, "#475569"))
        for i in items
    )
    return "<h2>Action items</h2>" + cards


def render_case_postmortem_html(postmortem: CasePostmortem) -> str:
    """Render a ``CasePostmortem`` to a self-contained HTML document.

    Pure function: same input → same output. Inline styles only so the
    document is portable when downloaded; print stylesheet ensures a clean
    Save-as-PDF artefact for the runbook archive.
    """
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>AiSOC Post-mortem — {_esc(postmortem.case.case_number or postmortem.case.title)}</title>
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
       color: #475569; margin: 22px 0 10px; border-top: 1px solid #e2e8f0; padding-top: 14px; }}
  table th, table td {{ border-bottom: 1px solid #f1f5f9; }}
  @media print {{
    body {{ padding: 0; }}
    h2 {{ page-break-after: avoid; }}
  }}
</style>
</head>
<body>
  {_header_block(postmortem.case, postmortem.headline, postmortem.generated_at)}

  {_overview_block(postmortem.overview)}

  {_detection_block(postmortem.detection, postmortem.detection_gaps)}

  {_response_block(postmortem.response)}

  {_timeline_block(postmortem.timeline)}

  {_went_well_block(postmortem.went_well)}

  {_fell_short_block(postmortem.fell_short)}

  {_action_items_block(postmortem.action_items)}

  <footer style="margin-top:32px;color:#94a3b8;font-size:11px;text-align:center;">
    AiSOC — open-source AI Security Operations Center.
    Blameless retrospective · system-focused · print this page (Ctrl/Cmd-P → Save as PDF) for the runbook archive.
  </footer>
</body>
</html>"""


__all__ = ["render_case_postmortem_html"]
