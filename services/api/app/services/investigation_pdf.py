"""Render a saved investigation report without rerunning its investigation."""

from __future__ import annotations

import html
import logging
from typing import Any

logger = logging.getLogger(__name__)

PDF_UNAVAILABLE_DETAIL = "PDF export is unavailable on this server. Please try again later."


class InvestigationPdfUnavailable(RuntimeError):
    """The report could not be rendered as a complete PDF."""


def _deny_resource_fetch(_url: str) -> dict[str, Any]:
    # Reports include untrusted evidence. Neither Markdown images nor future
    # renderer changes may turn an export into a file read or network request.
    raise ValueError("Resource loading is disabled for investigation PDF exports")


def render_investigation_pdf(markdown: str, *, case_id: str) -> bytes:
    """Convert stored Markdown to a PDF, escaping raw HTML and denying resources."""
    try:
        import weasyprint
        from markdown import Markdown

        converter = Markdown(extensions=["tables", "fenced_code"])
        # Escape raw HTML without double-escaping the entities and code that
        # the investigation writers already put in their Markdown artifacts.
        converter.preprocessors.deregister("html_block")
        converter.inlinePatterns.deregister("html")
        body = converter.convert(markdown)
        document = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>AiSOC Incident Report — {html.escape(case_id, quote=True)}</title>
<style>
  @page {{ size: A4; margin: 18mm; }}
  body {{ font-family: 'Segoe UI', Arial, sans-serif; color: #1a1a1a; font-size: 10pt; line-height: 1.45; overflow-wrap: anywhere; }}
  h1 {{ color: #c0392b; font-size: 20pt; }}
  h2 {{ color: #2c3e50; border-bottom: 1px solid #eee; padding-bottom: 4px; font-size: 14pt; }}
  h3 {{ font-size: 11pt; }}
  table {{ border-collapse: collapse; width: 100%; font-size: 9pt; }}
  th, td {{ border: 1px solid #ddd; padding: 6px; text-align: left; overflow-wrap: anywhere; }}
  th {{ background: #2c3e50; color: white; }}
  code {{ background: #f4f4f4; font-size: 9pt; }}
  pre {{ background: #f4f4f4; padding: 12px; white-space: pre-wrap; overflow-wrap: anywhere; }}
</style>
</head>
<body>{body}</body>
</html>"""
        # WeasyPrint 70 introduced a URLFetcher class; older supported
        # versions accept a callback. Deny every protocol in either API.
        fetcher_class = getattr(weasyprint, "URLFetcher", None)
        fetcher = fetcher_class(allowed_protocols=()) if fetcher_class is not None else _deny_resource_fetch
        return weasyprint.HTML(string=document, url_fetcher=fetcher).write_pdf()
    except Exception as exc:
        # Native-library import failures and rendering failures must stay an
        # explicit error; a partial or placeholder document is not a report.
        logger.exception("investigation_pdf.render_failed")
        raise InvestigationPdfUnavailable(PDF_UNAVAILABLE_DETAIL) from exc


def render_investigation_html_pdf(document: str) -> bytes:
    """Render only case-verified Agents HTML, without fetching resources."""
    try:
        import weasyprint

        fetcher_class = getattr(weasyprint, "URLFetcher", None)
        fetcher = fetcher_class(allowed_protocols=()) if fetcher_class is not None else _deny_resource_fetch
        return weasyprint.HTML(string=document, url_fetcher=fetcher).write_pdf()
    except Exception as exc:
        logger.exception("investigation_pdf.render_html_failed")
        raise InvestigationPdfUnavailable(PDF_UNAVAILABLE_DETAIL) from exc
