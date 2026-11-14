"""A scheduled hunt's report is labelled, and can be delivered.

Wave 2, Phase 5.2, and ADR-0015.

Two gaps, both of the "built but nothing connects them" family.

**No label.** ADR-0015 decides that AiSOC federates to the SIEM rather than
replacing it, and draws one consequence for this surface in particular:

    Phase 5.2's emailed hunt PDF must be labelled as hunting output in its
    own docs page. A scheduled search that emails a PDF is exactly the
    surface a reader mistakes for a compliance report.

Before this change, `rg -i "hunting output"` matched **only the ADR itself**.
The renderer emitted a `<title>` and an `<h1>` from the row's own title —
"Hunt findings: …" — with no banner, no classification and nothing saying
what the document does not claim.

**No delivery.** `render_pdf`, `build_from_hunt`, `persist` and `send_mail`
all existed and worked. Nothing called them together: hunt reports live in
`aisoc_hunt_reports` while the report scheduler delivers `ReportArtefact`
rows from `report_templates`, and the two surfaces were never connected. A
hunt report could be generated and downloaded, and could not be sent.

Against the pre-change tree the label tests fail on the missing banner and
the delivery tests fail with `AttributeError` on `HUNTING_OUTPUT_LABEL`.
"""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import MagicMock

import pytest
from app.services.hunt_report import HUNTING_OUTPUT_LABEL, render_html

_ROW: dict[str, Any] = {
    "title": "Hunt findings: Okta MFA fatigue",
    "source_kind": "saved_hunt",
    "match_count": 12,
    "created_at": "2026-11-01T09:00:00Z",
    "what": "Repeated push challenges to one account.",
    "how": "Saved hunt replayed over the last 24 hours.",
    "where": "okta.example.internal",
    "when": "2026-10-31T22:00:00Z to 2026-11-01T09:00:00Z",
    "citations": [{"kind": "saved_hunt", "id": "abc", "label": "Okta MFA fatigue"}],
}


# ── ADR-0015: the label ───────────────────────────────────────────────────


def test_the_report_is_labelled_hunting_output() -> None:
    assert HUNTING_OUTPUT_LABEL == "HUNTING OUTPUT"
    assert HUNTING_OUTPUT_LABEL in render_html(_ROW)


def test_the_label_is_in_the_title_so_it_survives_a_pdf_viewer_tab() -> None:
    """A banner is in the page; the title is what a tab and a file list show."""
    html = render_html(_ROW)
    title = html.split("<title>", 1)[1].split("</title>", 1)[0]
    assert HUNTING_OUTPUT_LABEL in title


def test_the_banner_says_what_the_document_does_not_claim() -> None:
    """A label alone names the page. This says what it is not evidence of.

    The ADR's concern is a reader mistaking a scheduled search for a
    compliance artefact, and "HUNTING OUTPUT" on its own does not address
    that — somebody who does not know the phrase learns nothing from it.
    """
    html = render_html(_ROW)
    assert "not a compliance artefact" in html
    assert "finding nothing here does not mean nothing happened" in html


def test_the_banner_is_escaped_like_every_other_interpolation() -> None:
    """The document carries attacker-influenced strings and opens in a browser."""
    hostile = dict(_ROW, title='<script>alert("x")</script>', where="<img onerror=1>")
    html = render_html(hostile)
    assert "<script>" not in html
    assert "<img onerror" not in html
    assert HUNTING_OUTPUT_LABEL in html


# ── delivery ──────────────────────────────────────────────────────────────


def _hunt() -> Any:
    hunt = MagicMock()
    hunt.id = uuid.uuid4()
    hunt.tenant_id = uuid.uuid4()
    hunt.name = "Okta MFA fatigue"
    hunt.nl_query = "repeated MFA pushes to one user"
    return hunt


@pytest.fixture()
def _report_service(monkeypatch):
    """Stand in for the report builder, recording what it was asked for."""
    from app.services import hunt_report as service

    async def _build(db, *, tenant_id, saved_hunt_id):  # noqa: ANN001, ANN202
        return MagicMock(is_citable=lambda: True)

    async def _persist(db, report, **kwargs):  # noqa: ANN001, ANN003, ANN202
        return dict(_ROW)

    monkeypatch.setattr(service, "build_from_hunt", _build)
    monkeypatch.setattr(service, "persist", _persist)
    monkeypatch.setattr(service, "render_pdf", lambda row: b"%PDF-1.7 fake")
    return service


@pytest.mark.asyncio
async def test_nobody_is_mailed_unless_a_recipient_was_configured(monkeypatch, _report_service) -> None:
    """Off by default. An unset variable means nobody asked for this."""
    from app.workers import hunt_scheduler

    monkeypatch.delenv("AISOC_HUNT_REPORT_RECIPIENTS", raising=False)
    sent: list[Any] = []
    monkeypatch.setattr("app.services.smtp_delivery.send_mail", lambda **kw: sent.append(kw))

    await hunt_scheduler._email_hunt_report(MagicMock(), _hunt(), 12)
    assert sent == []


@pytest.mark.asyncio
async def test_a_hunt_that_matched_nothing_mails_nothing(monkeypatch, _report_service) -> None:
    """A report saying a hunt found nothing is a thing nobody forwards."""
    from app.workers import hunt_scheduler

    monkeypatch.setenv("AISOC_HUNT_REPORT_RECIPIENTS", "soc@example.com")
    sent: list[Any] = []
    monkeypatch.setattr("app.services.smtp_delivery.send_mail", lambda **kw: sent.append(kw))

    await hunt_scheduler._email_hunt_report(MagicMock(), _hunt(), 0)
    assert sent == []


@pytest.mark.asyncio
async def test_the_pdf_is_mailed_with_the_hunting_output_label(monkeypatch, _report_service) -> None:
    from app.workers import hunt_scheduler

    monkeypatch.setenv("AISOC_HUNT_REPORT_RECIPIENTS", "soc@example.com, ir@example.com")
    captured: dict[str, Any] = {}

    async def _send(**kwargs):  # noqa: ANN003, ANN202
        captured.update(kwargs)
        return MagicMock(status="sent", detail="ok")

    monkeypatch.setattr("app.services.smtp_delivery.send_mail", _send)

    await hunt_scheduler._email_hunt_report(MagicMock(), _hunt(), 12)

    assert captured["recipients"] == ["soc@example.com", "ir@example.com"]
    assert captured["subject"].startswith(f"[{HUNTING_OUTPUT_LABEL}]")
    # The body carries the caveat too: a recipient who opens the mail and not
    # the attachment still learns what the document does not claim.
    assert "not a compliance artefact" in captured["text_body"]
    name, body, media_type = captured["attachment"]
    assert name.endswith(".pdf")
    assert media_type == "application/pdf"
    assert body.startswith(b"%PDF")


@pytest.mark.asyncio
async def test_a_missing_pdf_stack_sends_the_html_rather_than_nothing(monkeypatch, _report_service) -> None:
    """WeasyPrint's native stack is routinely absent outside the API image.

    The report is the deliverable; the format is not.
    """
    from app.services.digest_pdf import WeasyPrintUnavailableError
    from app.workers import hunt_scheduler

    monkeypatch.setenv("AISOC_HUNT_REPORT_RECIPIENTS", "soc@example.com")

    def _boom(row):  # noqa: ANN001, ANN202
        raise WeasyPrintUnavailableError("WeasyPrint is not installed")

    monkeypatch.setattr(_report_service, "render_pdf", _boom)
    captured: dict[str, Any] = {}

    async def _send(**kwargs):  # noqa: ANN003, ANN202
        captured.update(kwargs)
        return MagicMock(status="sent", detail="ok")

    monkeypatch.setattr("app.services.smtp_delivery.send_mail", _send)

    await hunt_scheduler._email_hunt_report(MagicMock(), _hunt(), 3)

    name, body, media_type = captured["attachment"]
    assert name.endswith(".html")
    assert media_type == "text/html"
    assert HUNTING_OUTPUT_LABEL.encode() in body


@pytest.mark.asyncio
async def test_a_failing_mail_relay_does_not_cost_the_case(monkeypatch, _report_service) -> None:
    """The case the hunt opened matters more than the mail about it."""
    from app.workers import hunt_scheduler

    monkeypatch.setenv("AISOC_HUNT_REPORT_RECIPIENTS", "soc@example.com")

    async def _boom(**kwargs):  # noqa: ANN003, ANN202
        raise ConnectionError("relay unreachable")

    monkeypatch.setattr("app.services.smtp_delivery.send_mail", _boom)

    # Returns rather than raising; the caller's `contextlib.suppress` is a
    # second belt, not the only one.
    await hunt_scheduler._email_hunt_report(MagicMock(), _hunt(), 3)
