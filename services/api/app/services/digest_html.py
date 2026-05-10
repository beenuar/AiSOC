"""HTML renderer for the executive weekly digest.

WS-G2 — buyer-value plan
========================
Produces a self-contained, print-ready HTML document for the
``ExecutiveDigest``. No external template engine, no PDF dependency: the
browser's own "Save as PDF" handles export.

Design goals
------------
* Pure function — same digest in, same HTML out.
* Inline CSS only, so the document remains portable when downloaded.
* Print-friendly typography and colour-blind-safe palette.
* Light theme by default (matches WS-F1 design tokens).
* Defensive HTML escaping — digest fields originate from tenant data.
"""

from __future__ import annotations

import html
from datetime import UTC, datetime

from .executive_digest import (
    AutomationSummary,
    DigestRecommendation,
    ExecutiveDigest,
    HighRiskAlertHighlight,
    SeveritySplit,
    TacticHighlight,
    TopSourceHighlight,
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
    """HTML-safe rendering for arbitrary values."""
    return html.escape("" if value is None else str(value))


def _fmt_hours(hours: float | None) -> str:
    if hours is None:
        return "—"
    if hours < 1:
        return f"{round(hours * 60)}m"
    return f"{hours:.1f}h"


def _fmt_datetime(value: datetime) -> str:
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


def _severity_table(split: SeveritySplit) -> str:
    rows: list[tuple[str, int]] = [
        ("Critical", split.critical),
        ("High", split.high),
        ("Medium", split.medium),
        ("Low", split.low),
        ("Info", split.info),
    ]
    cells = "".join(
        f'<tr><td style="padding:4px 8px;color:#0f172a;">'
        f"{_severity_chip(label.lower())}</td>"
        f'<td style="padding:4px 8px;text-align:right;font-weight:600;">{count}</td></tr>'
        for label, count in rows
    )
    return f'<table style="width:100%;border-collapse:collapse;font-size:13px;"><tbody>{cells}</tbody></table>'


def _tactic_rows(tactics: list[TacticHighlight]) -> str:
    if not tactics:
        return '<p style="color:#64748b;font-size:13px;">No MITRE-tagged alerts in this period.</p>'
    body = "".join(
        f'<tr><td style="padding:6px 8px;">{_esc(t.tactic)}</td>'
        f'<td style="padding:6px 8px;text-align:right;font-weight:600;">{t.count}</td>'
        f'<td style="padding:6px 8px;text-align:right;color:'
        f'{"#b91c1c" if t.delta_from_prior > 0 else "#15803d" if t.delta_from_prior < 0 else "#64748b"};">'
        f"{'+' if t.delta_from_prior > 0 else ''}{t.delta_from_prior}</td></tr>"
        for t in tactics
    )
    return (
        '<table style="width:100%;border-collapse:collapse;font-size:13px;">'
        '<thead><tr style="text-align:left;color:#64748b;font-size:11px;'
        'text-transform:uppercase;letter-spacing:0.06em;">'
        '<th style="padding:6px 8px;">Tactic</th>'
        '<th style="padding:6px 8px;text-align:right;">Count</th>'
        '<th style="padding:6px 8px;text-align:right;">Δ vs prior</th></tr></thead>'
        f"<tbody>{body}</tbody></table>"
    )


def _source_rows(sources: list[TopSourceHighlight]) -> str:
    if not sources:
        return '<p style="color:#64748b;font-size:13px;">No connector activity in this period.</p>'
    body = "".join(
        f'<tr><td style="padding:6px 8px;">{_esc(s.connector_type)}</td>'
        f'<td style="padding:6px 8px;text-align:right;font-weight:600;">{s.count}</td></tr>'
        for s in sources
    )
    return f'<table style="width:100%;border-collapse:collapse;font-size:13px;"><tbody>{body}</tbody></table>'


def _high_risk_table(items: list[HighRiskAlertHighlight]) -> str:
    if not items:
        return '<p style="color:#64748b;font-size:13px;">No high-risk alerts surfaced this period.</p>'
    body = "".join(
        "<tr>"
        f'<td style="padding:6px 8px;">{_severity_chip(a.severity)}</td>'
        f'<td style="padding:6px 8px;color:#0f172a;">{_esc(a.title)}</td>'
        f'<td style="padding:6px 8px;color:#475569;">{_esc(", ".join(a.mitre_tactics)) or "—"}</td>'
        f'<td style="padding:6px 8px;text-align:right;font-variant-numeric:tabular-nums;">'
        f"{a.ai_score if a.ai_score is not None else '—'}</td>"
        f'<td style="padding:6px 8px;color:#64748b;font-size:11px;'
        f'white-space:nowrap;">{_fmt_datetime(a.event_time)}</td></tr>'
        for a in items
    )
    return (
        '<table style="width:100%;border-collapse:collapse;font-size:13px;">'
        '<thead><tr style="text-align:left;color:#64748b;font-size:11px;'
        'text-transform:uppercase;letter-spacing:0.06em;">'
        '<th style="padding:6px 8px;">Severity</th>'
        '<th style="padding:6px 8px;">Title</th>'
        '<th style="padding:6px 8px;">Tactics</th>'
        '<th style="padding:6px 8px;text-align:right;">AI score</th>'
        '<th style="padding:6px 8px;">Event time</th></tr></thead>'
        f"<tbody>{body}</tbody></table>"
    )


def _automation_block(automation: AutomationSummary) -> str:
    total = max(automation.total_decisions, 1)
    auto_pct = round(automation.auto_executed / total * 100)
    review_pct = round(automation.review_pending / total * 100)
    escalate_pct = round(automation.escalated / total * 100)
    return (
        '<div style="display:flex;flex-wrap:wrap;gap:12px;">'
        + _kpi("Decisions", str(automation.total_decisions))
        + _kpi("Auto-executed", f"{automation.auto_executed}", hint=f"{auto_pct}%")
        + _kpi("Review pending", f"{automation.review_pending}", hint=f"{review_pct}%")
        + _kpi("Escalated", f"{automation.escalated}", hint=f"{escalate_pct}%")
        + "</div>"
    )


def _recommendation_cards(recs: list[DigestRecommendation]) -> str:
    if not recs:
        return ""
    cards = "".join(
        '<div style="border-left:4px solid {colour};background:{bg};'
        'padding:12px 14px;border-radius:6px;margin-bottom:10px;">'
        '<div style="font-weight:600;color:#0f172a;font-size:14px;'
        f'margin-bottom:4px;">{_esc(r.title)}</div>'
        f'<div style="color:#334155;font-size:13px;line-height:1.45;">{_esc(r.body)}</div>'
        "</div>".format(colour=_REC_COLOURS.get(r.severity, "#475569"), bg="#f8fafc")
        for r in recs
    )
    return cards


def render_digest_html(digest: ExecutiveDigest) -> str:
    """Render an ``ExecutiveDigest`` to a self-contained HTML document."""
    headline = _esc(digest.headline)
    period = digest.period

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>AiSOC Executive Digest — {_esc(period.label)}</title>
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
  <header>
    <div style="font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:0.08em;">
      AiSOC weekly executive digest
    </div>
    <h1>{_esc(period.label)}</h1>
    <div style="color:#334155;font-size:14px;margin-top:6px;">{headline}</div>
    <div style="color:#94a3b8;font-size:11px;margin-top:6px;">
      Tenant {_esc(digest.tenant_id)} · generated {_fmt_datetime(datetime.now(UTC))}
    </div>
  </header>

  <h2>Headline metrics</h2>
  <div style="display:flex;flex-wrap:wrap;gap:12px;">
    {_kpi("Alerts (total seen)", str(digest.alerts.total))}
    {_kpi("New this period", str(digest.alerts.new))}
    {_kpi("Resolved", str(digest.alerts.resolved))}
    {_kpi("Open at period end", str(digest.alerts.open_at_period_end))}
    {_kpi("Cases opened", str(digest.cases.opened))}
    {_kpi("Cases closed", str(digest.cases.closed))}
    {_kpi("SLA breaches", str(digest.cases.sla_breached))}
    {_kpi("MTTD", _fmt_hours(digest.mtt.mttd_hours))}
    {_kpi("MTTR", _fmt_hours(digest.mtt.mttr_hours))}
    {_kpi("MTTC", _fmt_hours(digest.mtt.mttc_hours))}
  </div>

  <h2>Severity distribution</h2>
  {_severity_table(digest.alerts.severity)}

  <h2>Top MITRE tactics</h2>
  {_tactic_rows(digest.top_tactics)}

  <h2>Top alert sources</h2>
  {_source_rows(digest.top_sources)}

  <h2>High-risk alerts</h2>
  {_high_risk_table(digest.high_risk_alerts)}

  <h2>Automation</h2>
  {_automation_block(digest.automation)}

  <h2>Recommendations</h2>
  {_recommendation_cards(digest.recommendations)}

  <footer style="margin-top:32px;color:#94a3b8;font-size:11px;text-align:center;">
    AiSOC — open-source AI Security Operations Center.
    Print this page (Ctrl/Cmd-P → Save as PDF) for board-ready archival.
  </footer>
</body>
</html>"""


__all__ = ["render_digest_html"]
