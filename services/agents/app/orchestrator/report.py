"""
Router report synthesis — T2.2 expansion (v8.0).

Renders ``(report_md, report_html)`` from the router's
:class:`app.models.state.InvestigationState` so the streaming surface and
the future ``/api/v1/cases/{case_id}/investigate`` swap can ship the same
artifact shape the legacy ``InvestigatorOrchestrator`` already emits.

The router state is flatter than ``InvestigatorState`` (no per-agent
structured outputs, no audit log), so the report is built deterministically
from the joined ``findings`` / ``mitre_mappings`` / ``proposed_actions``
slots. No LLM call is needed at this stage — the substrate already paid
for one LLM round-trip per sub-agent during fan-out and another in
auto-triage; we don't burn another one just to format the artifact.

The HTML output uses the same lightweight ``markdown`` library shell as
``app.investigator.report_writer_agent`` so reports look consistent across
both orchestrators. If ``markdown`` isn't importable for any reason we
fall back to wrapping the source in ``<pre>``; the substrate suite covers
both branches.
"""

from __future__ import annotations

import html
from datetime import datetime
from typing import Any

from app.models.state import AgentStatus, InvestigationState, ProposedAction


def _md_escape(value: Any) -> str:
    """HTML-escape a value before it is embedded in the Markdown body.

    The rendered Markdown is later piped through ``markdown.markdown``,
    which preserves raw HTML by default. Any of ``state.findings``,
    ``state.error``, ``state.confidence_basis``, ``proposed_actions``
    fields, etc. can carry adversary-influenced strings sourced from the
    underlying alert. Escaping ``<``, ``>``, ``&``, ``"``, ``'`` upstream
    means a finding like ``<script>alert(1)</script>`` reaches the
    rendered HTML as literal text rather than executable script.

    Returns the empty string for ``None`` so callers can blindly substitute.
    """
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def _fmt_confidence(value: float) -> str:
    """Render a 0.0–1.0 confidence as a two-decimal string."""
    try:
        return f"{float(value):.2f}"
    except (TypeError, ValueError):
        return "0.00"


def _proposed_actions_table(actions: list[ProposedAction]) -> list[str]:
    """Render the proposed-actions section as a Markdown table.

    Returns the section body as a list of lines (so the caller can decide
    whether to emit a heading above it). Returns an empty list when the
    state has no proposed actions, so the caller can skip the section
    entirely rather than rendering an empty table.
    """
    if not actions:
        return []

    def _cell(raw: Any) -> str:
        """Escape a cell value: HTML-escape, then escape Markdown table delimiters.

        Per security review, every table cell — not just ``rationale`` —
        needs ``|`` + newline escaping so an adversary-controlled
        ``target`` or ``action_type`` can't break the table layout.
        """
        cleaned = _md_escape(raw).replace("|", "\\|").replace("\n", " ").strip()
        return cleaned or "—"

    lines: list[str] = []
    lines.append("| # | Action | Target | Risk | Approval | Rationale |")
    lines.append("|---|--------|--------|------|----------|-----------|")
    for idx, action in enumerate(actions, start=1):
        action_type = _cell(getattr(action, "action_type", ""))
        target = _cell(getattr(action, "target", ""))
        risk_level = getattr(action, "risk_level", None)
        risk_raw = getattr(risk_level, "value", risk_level)
        risk = _cell(risk_raw)
        approval = "yes" if getattr(action, "requires_approval", False) else "no"
        rationale = _cell(getattr(action, "rationale", ""))
        lines.append(f"| {idx} | {action_type} | {target} | {risk} | {approval} | {rationale} |")
    return lines


def _bullets(items: list[str]) -> list[str]:
    """Render a list of strings as Markdown bullets.

    Newlines inside any item are flattened into spaces so the bullet stays
    on one logical line, which keeps the Markdown→HTML conversion stable.
    Each item is HTML-escaped before emission — see ``_md_escape``.
    """
    out: list[str] = []
    for item in items:
        cleaned = " ".join(_md_escape(item).splitlines()).strip()
        if cleaned:
            out.append(f"- {cleaned}")
    return out


def render_router_report_md(
    state: InvestigationState,
    *,
    info: dict[str, Any] | None = None,
) -> str:
    """Synthesise a Markdown incident report from the router's final state.

    Sections (each is skipped when its source is empty):

    1. ``# Incident Report — <case_id>``
    2. ``## Summary`` — verdict, confidence, status, topology, wall-clock
    3. ``## Triage Rationale`` — ``confidence_basis``
    4. ``## Findings`` — ``state.findings`` as bullets
    5. ``## MITRE ATT&CK Mappings`` — ``state.mitre_mappings`` as inline codes
    6. ``## Proposed Actions`` — table of ``state.proposed_actions``
    7. ``## Errors`` — ``state.error`` if set
    8. Footer — generation timestamp

    Args:
        state: the final :class:`InvestigationState` after the router
            (parallel or sequential) has run.
        info: optional substrate telemetry dict from
            :meth:`RouterOrchestrator.run` — adds topology / wall-clock /
            signals to the Summary section when provided.

    Returns:
        A Markdown string ready to ship as a ``report_md`` artifact.
    """
    info = info or {}
    case_id = str(state.incident_id)

    lines: list[str] = []
    lines.append(f"# Incident Report — {case_id}")
    lines.append("")

    # 2. Summary -----------------------------------------------------------
    lines.append("## Summary")
    lines.append("")
    summary_rows: list[tuple[str, str]] = [
        ("Verdict", _md_escape(state.verdict or "uncertain")),
        ("Confidence", _fmt_confidence(state.confidence)),
        ("Status", _md_escape(state.status.value if isinstance(state.status, AgentStatus) else str(state.status))),
    ]
    topology = info.get("topology")
    if topology:
        summary_rows.append(("Topology", _md_escape(topology)))
    signals = info.get("signals") or []
    if signals:
        summary_rows.append(("Signals", _md_escape(", ".join(str(s) for s in signals))))
    wall_clock = info.get("wall_clock_ms")
    if wall_clock is not None:
        summary_rows.append(("Wall-clock (ms)", f"{float(wall_clock):.1f}"))
    if info.get("auto_closed"):
        summary_rows.append(("Auto-closed", "yes"))

    lines.append("| Field | Value |")
    lines.append("|-------|-------|")
    for label, value in summary_rows:
        lines.append(f"| {label} | {value} |")
    lines.append("")

    # 3. Triage rationale --------------------------------------------------
    if state.confidence_basis:
        lines.append("## Triage Rationale")
        lines.append("")
        lines.extend(_bullets(state.confidence_basis))
        lines.append("")

    # 4. Findings ----------------------------------------------------------
    if state.findings:
        lines.append("## Findings")
        lines.append("")
        lines.extend(_bullets(state.findings))
        lines.append("")

    # 5. MITRE ATT&CK mappings --------------------------------------------
    if state.mitre_mappings:
        lines.append("## MITRE ATT&CK Mappings")
        lines.append("")
        for technique in state.mitre_mappings:
            cleaned = _md_escape(technique).strip()
            if cleaned:
                lines.append(f"- `{cleaned}`")
        lines.append("")

    # 6. Proposed actions --------------------------------------------------
    actions_lines = _proposed_actions_table(state.proposed_actions)
    if actions_lines:
        lines.append("## Proposed Actions")
        lines.append("")
        lines.extend(actions_lines)
        lines.append("")

    # 7. Errors ------------------------------------------------------------
    if state.error:
        lines.append("## Errors")
        lines.append("")
        lines.append(f"```\n{_md_escape(state.error)}\n```")
        lines.append("")

    # 8. Footer ------------------------------------------------------------
    generated_at = (state.completed_at or datetime.utcnow()).strftime("%Y-%m-%d %H:%M UTC")
    lines.append(f"_Generated by AiSOC router on {generated_at}_")

    return "\n".join(lines).rstrip() + "\n"


def render_router_report_html(report_md: str, *, case_id: str) -> str:
    """Convert a router-generated Markdown report into a styled HTML document.

    Uses the optional ``markdown`` package (with ``tables`` + ``fenced_code``
    extensions enabled) when available; falls back to wrapping the source
    in ``<pre>`` so the artifact still ships even if the dependency is
    missing in a minimal substrate runtime.

    The Markdown input is produced by :func:`render_router_report_md`,
    which HTML-escapes every value sourced from state before
    interpolation, so adversary-controlled finding / action / error
    text reaches the renderer as literal characters rather than tags.
    The ``<pre>``-fallback branch escapes the body for the same reason.
    The page title and case identifier are also escaped here so an
    operator-supplied case ID can never break out of the ``<title>``.
    """
    try:
        import markdown

        body = markdown.markdown(report_md, extensions=["tables", "fenced_code"])
    except ImportError:
        # Fallback: keep the report ship-able even when ``markdown`` is
        # unavailable. The unit tests exercise both branches. We escape
        # the source here because the upstream Markdown writer escapes
        # for the ``markdown.markdown`` path but a raw ``<pre>`` wrap
        # would leak HTML through unchanged.
        body = f"<pre>{html.escape(report_md)}</pre>"

    safe_case_id = html.escape(str(case_id), quote=True)
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '<meta charset="utf-8"/>\n'
        f"<title>AiSOC Incident Report \u2014 {safe_case_id}</title>\n"
        "<style>\n"
        "  body { font-family: 'Segoe UI', Arial, sans-serif; max-width: 960px; margin: 40px auto; color: #1a1a1a; }\n"
        "  h1 { color: #c0392b; }\n"
        "  h2 { color: #2c3e50; border-bottom: 1px solid #eee; padding-bottom: 4px; }\n"
        "  table { border-collapse: collapse; width: 100%; }\n"
        "  th, td { border: 1px solid #ddd; padding: 8px; }\n"
        "  th { background: #2c3e50; color: white; }\n"
        "  code { background: #f4f4f4; padding: 2px 6px; border-radius: 3px; }\n"
        "  pre { background: #f4f4f4; padding: 16px; overflow-x: auto; border-radius: 4px; }\n"
        "  .footer { color: #999; font-size: 0.8em; margin-top: 40px; }\n"
        "</style>\n"
        "</head>\n"
        "<body>\n"
        f"{body}\n"
        f'<div class="footer">Generated by AiSOC on {timestamp}</div>\n'
        "</body>\n"
        "</html>\n"
    )


def render_router_report(
    state: InvestigationState,
    *,
    info: dict[str, Any] | None = None,
) -> tuple[str, str]:
    """Convenience wrapper — render both Markdown and HTML in one call.

    Returns ``(report_md, report_html)`` for the streaming surface to
    ship as ``done`` event fields and persist as ledger artifacts.
    """
    md = render_router_report_md(state, info=info)
    html = render_router_report_html(md, case_id=str(state.incident_id))
    return md, html
