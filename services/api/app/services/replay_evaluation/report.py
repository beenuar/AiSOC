"""Export a stored replay report as JSON, Markdown or PDF.

Gap-closure Phase 1.4.

There is one renderer, and it is not here
-----------------------------------------
``format_replay_report`` in the benchmark package produces the Markdown, and
``ReplayScore.as_dict`` produces the JSON. Both shipped with Phase 1.3 and
both are reused unchanged. This module does not render a report; it serves the
one that was stored when the run completed, and turns that same Markdown into
a PDF.

That is deliberate. The phase's acceptance bar is that a report reproduces
byte for byte, and a second renderer would eventually disagree with the first
about a heading or a rounding while both still called themselves the report.

Why the Markdown to HTML step is a small hand-written pass
----------------------------------------------------------
The Markdown being converted is not arbitrary: it comes from one function in
this repository, and that function emits exactly headings, bullet lists,
pipe tables and paragraphs. A general Markdown library would be a new pinned
dependency to convert output whose full grammar is forty lines away.

The pass escapes everything it does not itself emit. The report embeds
connector-supplied values: rule ids, vendor names, and the hallucinated
indicator examples, which are by definition strings a model produced from
attacker-influenced evidence. Writing those into HTML unescaped would put
model output into a document an operator opens.
"""

from __future__ import annotations

import html
import json
import logging
import re
from typing import Any

from app._vendor.aisoc_benchmark.replay import LATENCY_FIELDS, strip_latency

logger = logging.getLogger(__name__)

__all__ = [
    "PDF_UNAVAILABLE_DETAIL",
    "PdfUnavailableError",
    "markdown_to_html",
    "render_pdf",
    "report_json",
    "report_markdown",
]

#: Said to the operator when the native stack behind WeasyPrint is missing.
#: Named as a constant so the route and the test assert the same sentence, and
#: so it says what to do rather than reporting a failed export as an empty file.
PDF_UNAVAILABLE_DETAIL = (
    "PDF export needs the WeasyPrint native libraries (Pango, Cairo, GLib), which are "
    "installed in the API container image but may be absent on a local checkout. "
    "The JSON and Markdown exports carry the same report and need nothing extra."
)

#: A table row: leading and trailing pipes with cells between.
_TABLE_ROW = re.compile(r"^\|(.+)\|$")
#: A table's separator row, which carries no data and is not rendered.
_TABLE_DIVIDER = re.compile(r"^\|[\s:|-]+\|$")


class PdfUnavailableError(RuntimeError):
    """WeasyPrint or its native stack is not installed."""


def report_json(
    *,
    evaluation_id: str,
    score: dict[str, Any] | None,
    method: dict[str, Any] | None,
    exclude_latency: bool = False,
) -> str:
    """The machine-readable export.

    ``sort_keys`` because the export is compared byte for byte across runs and
    Python's dict order would otherwise carry insertion order into the file.

    ``exclude_latency`` replaces the two wall-clock figures with ``None``
    rather than deleting the keys. A reader parsing the JSON should not have
    to tell "this run measured no latency" from "this key is missing on some
    exports", and ``None`` is already how every other unmeasured rate is
    written in this schema.
    """
    payload_score = dict(score or {})
    if exclude_latency:
        for field in LATENCY_FIELDS:
            if field in payload_score:
                payload_score[field] = None
    return json.dumps(
        {
            "evaluation_id": evaluation_id,
            "score": payload_score,
            "method": method or {},
            "latency_excluded": exclude_latency,
        },
        indent=2,
        sort_keys=True,
        default=str,
    )


def report_markdown(stored: str, *, exclude_latency: bool = False) -> str:
    """The stored report, optionally without its two wall-clock figures.

    This is a filter over the artefact, not a re-render. ``strip_latency``
    lives beside the renderer that emits the line, so the producer and the
    remover cannot drift into disagreeing about which line it is.
    """
    return strip_latency(stored) if exclude_latency else stored


def _cells(line: str) -> list[str]:
    match = _TABLE_ROW.match(line)
    if match is None:  # pragma: no cover - callers test the pattern first
        return []
    return [cell.strip() for cell in match.group(1).split("|")]


def _inline(text: str) -> str:
    """Escape, then re-apply the only inline markup the report emits.

    Order matters: escaping first means a value that happens to contain
    ``**`` or a tag is rendered as text rather than as markup. The report's
    own bold spans survive because they are re-applied to the escaped string.
    """
    escaped = html.escape(text)
    return re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", escaped)


def markdown_to_html(markdown: str) -> str:
    """Convert the replay report's Markdown subset to an HTML fragment.

    Handles the four constructs ``format_replay_report`` emits and nothing
    else. Anything unrecognised becomes a paragraph, escaped, which is the
    safe direction: an unhandled construct renders as its own source text
    rather than as markup somebody else chose.
    """
    out: list[str] = []
    table: list[list[str]] = []
    bullets: list[str] = []

    def flush_table() -> None:
        if not table:
            return
        header, *body = table
        out.append("<table>")
        out.append("<thead><tr>" + "".join(f"<th>{_inline(c)}</th>" for c in header) + "</tr></thead>")
        out.append("<tbody>")
        for row in body:
            out.append("<tr>" + "".join(f"<td>{_inline(c)}</td>" for c in row) + "</tr>")
        out.append("</tbody></table>")
        table.clear()

    def flush_bullets() -> None:
        if not bullets:
            return
        out.append("<ul>" + "".join(f"<li>{_inline(b)}</li>" for b in bullets) + "</ul>")
        bullets.clear()

    for raw_line in markdown.splitlines():
        line = raw_line.rstrip()

        if _TABLE_DIVIDER.match(line):
            continue
        if _TABLE_ROW.match(line):
            flush_bullets()
            table.append(_cells(line))
            continue
        flush_table()

        if line.startswith("- "):
            bullets.append(line[2:])
            continue
        flush_bullets()

        if not line:
            continue
        if line.startswith("### "):
            out.append(f"<h3>{_inline(line[4:])}</h3>")
        elif line.startswith("## "):
            out.append(f"<h2>{_inline(line[3:])}</h2>")
        elif line.startswith("# "):
            out.append(f"<h1>{_inline(line[2:])}</h1>")
        else:
            out.append(f"<p>{_inline(line)}</p>")

    flush_table()
    flush_bullets()
    return "\n".join(out)


def _document(body_html: str) -> str:
    """Wrap the fragment in a print-ready page.

    No generation timestamp and no host name anywhere. A report that prints
    "generated at" is a report that cannot reproduce byte for byte, which is
    this phase's acceptance bar.
    """
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>AiSOC replay evaluation</title>
<style>
  @page {{ margin: 18mm; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    color: #0f172a;
    font-size: 10.5pt;
    line-height: 1.45;
  }}
  h1 {{ font-size: 20pt; margin: 0 0 4mm; }}
  h2 {{ font-size: 13pt; margin: 7mm 0 2mm; border-bottom: 1px solid #cbd5e1; padding-bottom: 1mm; }}
  h3 {{ font-size: 11pt; margin: 5mm 0 2mm; }}
  p {{ margin: 0 0 2mm; }}
  ul {{ margin: 0 0 3mm 5mm; padding: 0; }}
  li {{ margin: 0 0 1mm; }}
  table {{ border-collapse: collapse; width: 100%; margin: 0 0 4mm; font-size: 9pt; }}
  th, td {{ border: 1px solid #cbd5e1; padding: 1.5mm 2mm; text-align: left; }}
  th {{ background: #f1f5f9; font-weight: 600; }}
</style>
</head>
<body>
{body_html}
</body>
</html>"""


def render_pdf(markdown: str) -> bytes:
    """Render the stored report as a PDF.

    Raises :class:`PdfUnavailableError` rather than returning an empty or
    partial document, because a zero-byte PDF served with a 200 reads as a
    corrupt report rather than as a missing library.
    """
    # Imported at call time, following ``app.services.digest_pdf``: WeasyPrint
    # pulls a native stack that is present in the API image and routinely
    # absent on a checkout, and a module-level import would take the whole
    # service down over an export nobody asked for.
    try:
        from weasyprint import HTML  # type: ignore[import-untyped]
    except (ImportError, OSError) as exc:
        # OSError as well as ImportError: WeasyPrint imports but fails to load
        # its native libraries on a machine without them, and that surfaces
        # here rather than as a missing module.
        logger.warning("replay report PDF export unavailable: %s", exc)
        raise PdfUnavailableError(PDF_UNAVAILABLE_DETAIL) from exc

    return HTML(string=_document(markdown_to_html(markdown))).write_pdf()
