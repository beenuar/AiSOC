"""Audit export — deterministic CSV + print-ready HTML bundles.

WS-H3 — buyer-value plan
========================
Produces compliance-ready exports of the audit trail in two formats:

* ``csv`` — tabular for SIEM ingest, evidence binders, and spreadsheet review.
* ``html`` — self-contained, print-friendly document the browser can save
  to PDF without any server-side PDF dependency.

Design goals
------------
* Pure functions: the renderers below take an in-memory list of
  ``AuditRow`` and a ``ExportContext`` and return a ``str``. No DB, no I/O.
  This is what makes the exports reproducible and easy to unit-test.
* CSV is RFC 4180 compliant (CRLF line endings, ``QUOTE_ALL`` so JSON
  payloads in ``changes`` survive embedded commas/quotes/newlines).
* HTML mirrors the design tokens of the executive digest renderer
  (WS-G2) and case summary renderer (WS-D2) so operators get a
  consistent visual identity across all artefacts.
* Defensive HTML escaping — every field touches tenant data.
"""

from __future__ import annotations

import csv
import html
import io
import json
from dataclasses import dataclass
from datetime import UTC, datetime


@dataclass(frozen=True)
class AuditRow:
    """One row of the export. Mirrors the public ``AuditEventOut`` shape.

    ``changes`` is an arbitrary JSON-serialisable dict (or None); the
    renderers below stringify it defensively rather than trusting input.
    """

    id: str
    tenant_id: str
    actor_id: str | None
    actor_email: str | None
    actor_ip: str | None
    action: str
    resource: str | None
    resource_id: str | None
    changes: dict | None
    created_at: datetime


@dataclass(frozen=True)
class ExportContext:
    """Metadata for the export header — what filters were applied, by whom."""

    tenant_id: str
    generated_at: datetime
    generated_by_email: str | None
    filters: dict[str, str | None]
    total_rows: int


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------


_CSV_HEADERS = (
    "id",
    "tenant_id",
    "created_at",
    "actor_id",
    "actor_email",
    "actor_ip",
    "action",
    "resource",
    "resource_id",
    "changes",
)


def render_audit_csv(rows: list[AuditRow]) -> str:
    """Serialise ``rows`` to a deterministic CSV document.

    * Header row first — column order is part of the contract; downstream
      SIEM connectors and compliance scripts pin to it.
    * ``QUOTE_ALL`` so embedded commas, quotes, and newlines in JSON
      payloads (``changes``) cannot break field boundaries.
    * CRLF line endings (RFC 4180) so the file imports cleanly on Windows.
    * ``changes`` is JSON-encoded with ``sort_keys=True`` so identical
      payloads render identically across runs.
    """
    buf = io.StringIO(newline="")
    # csv writer must not insert its own newlines on top of ours — we use
    # the platform-agnostic default ("\r\n") which is RFC 4180 compliant.
    writer = csv.writer(buf, quoting=csv.QUOTE_ALL, lineterminator="\r\n")
    writer.writerow(_CSV_HEADERS)
    for row in rows:
        changes_blob = "" if row.changes is None else json.dumps(row.changes, sort_keys=True, separators=(",", ":"))
        writer.writerow(
            (
                row.id,
                row.tenant_id,
                row.created_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
                row.actor_id or "",
                row.actor_email or "",
                row.actor_ip or "",
                row.action,
                row.resource or "",
                row.resource_id or "",
                changes_blob,
            )
        )
    return buf.getvalue()


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------


def _esc(value: object) -> str:
    """HTML-safe rendering for arbitrary values."""
    return html.escape("" if value is None else str(value))


def _fmt_dt(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def _filter_chip(label: str, value: str | None) -> str:
    if value is None or value == "":
        return ""
    return (
        '<span style="display:inline-block;margin:0 6px 6px 0;padding:3px 8px;'
        "border:1px solid #cbd5e1;border-radius:9999px;background:#f1f5f9;"
        'font-size:11px;color:#1e293b;">'
        f"{_esc(label)}: <strong>{_esc(value)}</strong></span>"
    )


def _action_chip(action: str) -> str:
    # Colour-code by action prefix so a printed page is scannable even
    # when the table runs to dozens of rows.
    family = action.split(":", 1)[0] if ":" in action else action
    palette = {
        "auth": "#1d4ed8",
        "cases": "#7c3aed",
        "alerts": "#c2410c",
        "detection": "#0f766e",
        "playbooks": "#9333ea",
        "connectors": "#0891b2",
        "settings": "#475569",
        "users": "#475569",
        "audit": "#334155",
    }
    colour = palette.get(family, "#475569")
    return (
        f'<span style="display:inline-block;padding:2px 6px;border-radius:4px;'
        f"background:{colour};color:#fff;font-size:10px;font-family:ui-monospace,"
        f'SFMono-Regular,Menlo,Consolas,monospace;">{_esc(action)}</span>'
    )


def _changes_cell(changes: dict | None) -> str:
    if changes is None:
        return '<span style="color:#94a3b8;">—</span>'
    try:
        pretty = json.dumps(changes, sort_keys=True, indent=2)
    except (TypeError, ValueError):
        # If the changes payload is not JSON-serialisable for any reason,
        # fall back to repr so the report still renders without crashing.
        pretty = repr(changes)
    return (
        '<pre style="margin:0;padding:6px 8px;background:#f8fafc;'
        "border:1px solid #e2e8f0;border-radius:4px;font-size:11px;"
        "font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;"
        'white-space:pre-wrap;word-break:break-word;max-width:480px;">'
        f"{_esc(pretty)}</pre>"
    )


def _row_html(row: AuditRow) -> str:
    actor = row.actor_email or row.actor_id or "—"
    ip = row.actor_ip or "—"
    resource = (
        f'{_esc(row.resource)}<br/><span style="color:#64748b;font-size:11px;">{_esc(row.resource_id)}</span>'
        if row.resource and row.resource_id
        else _esc(row.resource or row.resource_id or "—")
    )
    return (
        '<tr style="border-bottom:1px solid #e2e8f0;vertical-align:top;">'
        f'<td style="padding:8px 12px;font-size:11px;color:#475569;white-space:nowrap;">'
        f"{_esc(_fmt_dt(row.created_at))}</td>"
        f'<td style="padding:8px 12px;">{_action_chip(row.action)}</td>'
        f'<td style="padding:8px 12px;font-size:12px;color:#1e293b;">{_esc(actor)}<br/>'
        f'<span style="color:#64748b;font-size:11px;">{_esc(ip)}</span></td>'
        f'<td style="padding:8px 12px;font-size:12px;color:#1e293b;">{resource}</td>'
        f'<td style="padding:8px 12px;">{_changes_cell(row.changes)}</td>'
        "</tr>"
    )


def render_audit_html(rows: list[AuditRow], context: ExportContext) -> str:
    """Render an audit export as a self-contained HTML document.

    The output is intentionally a single string with inline CSS so that
    the file remains portable when downloaded — no external stylesheets,
    no JavaScript, browser print-to-PDF works out of the box.
    """
    filters_html = (
        "".join(_filter_chip(label, value) for label, value in context.filters.items())
        or '<span style="color:#94a3b8;font-size:12px;">No filters applied — full audit trail.</span>'
    )

    rows_html = (
        "".join(_row_html(row) for row in rows)
        if rows
        else (
            '<tr><td colspan="5" style="padding:24px;text-align:center;'
            'color:#64748b;font-size:13px;">No audit events match the selected filters.</td></tr>'
        )
    )

    generated_by = context.generated_by_email or "system"
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>AiSOC — Audit Export</title>
<meta name="viewport" content="width=device-width,initial-scale=1" />
<style>
  /* Print-friendly page setup; no external resources. */
  @page {{ size: A4 landscape; margin: 12mm; }}
  body {{
    font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    color: #0f172a;
    background: #ffffff;
    margin: 0;
    padding: 24px;
  }}
  h1 {{ font-size: 22px; margin: 0 0 4px 0; }}
  h2 {{ font-size: 14px; margin: 16px 0 8px 0; color: #334155; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th {{
    text-align: left;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: #475569;
    padding: 8px 12px;
    border-bottom: 2px solid #cbd5e1;
    background: #f8fafc;
  }}
  .meta {{ color: #64748b; font-size: 12px; }}
  .kpis {{ display: flex; gap: 16px; margin: 12px 0 8px 0; }}
  .kpi {{
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    padding: 8px 12px;
    background: #f8fafc;
    min-width: 120px;
  }}
  .kpi .label {{ font-size: 11px; color: #64748b; text-transform: uppercase; letter-spacing: 0.04em; }}
  .kpi .value {{ font-size: 16px; font-weight: 600; color: #0f172a; }}
</style>
</head>
<body>
  <header>
    <h1>Audit Trail Export</h1>
    <div class="meta">
      Tenant <code>{_esc(context.tenant_id)}</code> &middot;
      generated {_esc(_fmt_dt(context.generated_at))} by {_esc(generated_by)}
    </div>
    <div class="kpis">
      <div class="kpi"><div class="label">Rows</div><div class="value">{context.total_rows}</div></div>
      <div class="kpi"><div class="label">Format</div><div class="value">HTML / print</div></div>
    </div>
    <h2>Filters applied</h2>
    <div>{filters_html}</div>
  </header>
  <table>
    <thead>
      <tr>
        <th style="width:160px;">Timestamp</th>
        <th style="width:160px;">Action</th>
        <th style="width:200px;">Actor</th>
        <th style="width:200px;">Resource</th>
        <th>Changes</th>
      </tr>
    </thead>
    <tbody>{rows_html}</tbody>
  </table>
  <footer style="margin-top:24px;color:#94a3b8;font-size:11px;">
    AiSOC audit export &middot; immutable, append-only event store &middot;
    column order is stable for SIEM ingestion compatibility.
  </footer>
</body>
</html>"""
