"""WS-G2 — Server-side PDF generation for the Executive Weekly Digest.

Uses WeasyPrint to convert the print-ready HTML produced by
``digest_html.render_digest_html`` into a PDF byte stream.

WeasyPrint requires native libs (Pango, Cairo, GLib) that are installed in the
Docker image via ``apt-get``.  When those libs are absent (e.g. CI or a macOS
dev machine without the native stack) we fall back gracefully so that
non-PDF code paths remain functional.

Author: Beenu <beenu@cyble.com>
"""

from __future__ import annotations

import logging

from app.services.digest_html import render_digest_html
from app.services.executive_digest import ExecutiveDigest

logger = logging.getLogger(__name__)

__all__ = ["render_digest_pdf", "WeasyPrintUnavailableError"]


class WeasyPrintUnavailableError(RuntimeError):
    """Raised when the WeasyPrint native stack is not installed."""


def render_digest_pdf(digest: ExecutiveDigest) -> bytes:
    """Render *digest* as a PDF byte string.

    Converts the ``ExecutiveDigest`` model to a self-contained, print-ready
    HTML page (via :func:`render_digest_html`) and then runs it through
    WeasyPrint to produce a PDF.

    Parameters
    ----------
    digest:
        The populated executive digest model.

    Returns
    -------
    bytes
        Raw PDF bytes ready to be streamed as ``application/pdf``.

    Raises
    ------
    WeasyPrintUnavailableError
        When WeasyPrint (or its native dependencies) is not installed.
    """
    try:
        from weasyprint import HTML  # type: ignore[import-untyped]
    except (ImportError, OSError) as exc:
        raise WeasyPrintUnavailableError(
            "WeasyPrint is not available in this environment. "
            "Install it via `poetry add weasyprint` and ensure Pango/Cairo "
            "system libs are present.  See services/api/Dockerfile for the "
            "required apt packages."
        ) from exc

    html_content = render_digest_html(digest)
    logger.info(
        "rendering executive digest PDF tenant_id=%s period_start=%s",
        digest.tenant_id,
        str(digest.period.start),
    )
    pdf_bytes: bytes = HTML(string=html_content).write_pdf()
    logger.info(
        "executive digest PDF rendered tenant_id=%s size_bytes=%d",
        digest.tenant_id,
        len(pdf_bytes),
    )
    return pdf_bytes
