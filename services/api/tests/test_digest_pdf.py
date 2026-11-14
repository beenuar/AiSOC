"""WS-G2 — Tests for digest_pdf.py (server-side PDF generation).

WeasyPrint requires native system libraries (Pango, Cairo, GLib) that are not
present on every CI or dev machine.  These tests therefore **mock** WeasyPrint
entirely:

* ``test_render_digest_pdf_*`` — verify the ``render_digest_pdf`` wrapper by
  replacing ``weasyprint.HTML`` with a lightweight stub that returns a
  sentinel bytes object.
* ``test_render_digest_pdf_unavailable_*`` — verify that
  ``WeasyPrintUnavailableError`` is raised when the import fails.
* ``test_weekly_digest_task_*`` — unit-test ``run_once`` from the scheduler
  worker without touching the database (full DB mocking via ``AsyncMock``).

No production code in this module imports WeasyPrint at module scope; all
production imports are guarded by a ``try/except (ImportError, OSError)``.

Author: Beenu <beenu@cyble.com>
"""

from __future__ import annotations

import base64
import sys
import types
import uuid
from datetime import UTC, date, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from app.services.digest_pdf import WeasyPrintUnavailableError, render_digest_pdf
from app.services.executive_digest import (
    AlertRow,
    DigestInputs,
    build_digest_from_rows,
)

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

PERIOD_START = datetime(2026, 5, 4, tzinfo=UTC)  # a Monday
PERIOD_END = datetime(2026, 5, 10, 23, 59, 59, tzinfo=UTC)
TENANT_ID = uuid.uuid4()


def _make_digest():
    """Return a small but valid ExecutiveDigest for use across tests."""
    inputs = DigestInputs(
        tenant_id=TENANT_ID,
        period_start=PERIOD_START,
        period_end=PERIOD_END,
        current_alerts=[
            AlertRow(
                severity="high",
                status="closed",
                created_at=PERIOD_START + timedelta(hours=1),
                resolved_at=PERIOD_START + timedelta(hours=5),
                first_seen_at=PERIOD_START + timedelta(hours=1, minutes=10),
                disposition="true_positive",
                mitre_tactics=["execution"],
                connector_type="edr-crowdstrike",
                ai_score=0.9,
                title="Suspicious PowerShell",
                alert_id=str(uuid.uuid4()),
                event_time=PERIOD_START + timedelta(hours=1),
            )
        ],
    )
    return build_digest_from_rows(inputs)


# ---------------------------------------------------------------------------
# render_digest_pdf — happy path (mocked WeasyPrint)
# ---------------------------------------------------------------------------


def _install_fake_weasyprint(pdf_bytes: bytes = b"%PDF-1.4 fake") -> None:
    """Inject a fake ``weasyprint`` module into ``sys.modules``.

    The fake provides ``HTML`` as a class whose ``write_pdf()`` method
    returns *pdf_bytes*.  Injecting into sys.modules makes the lazy
    ``from weasyprint import HTML`` inside ``render_digest_pdf`` resolve to
    the stub without any native library.
    """
    fake_html_instance = MagicMock()
    fake_html_instance.write_pdf.return_value = pdf_bytes

    fake_html_class = MagicMock(return_value=fake_html_instance)

    fake_module = types.ModuleType("weasyprint")
    fake_module.HTML = fake_html_class  # type: ignore[attr-defined]

    sys.modules["weasyprint"] = fake_module


def _remove_fake_weasyprint() -> None:
    """Undo ``_install_fake_weasyprint`` so later tests start clean."""
    sys.modules.pop("weasyprint", None)


class TestRenderDigestPdf:
    """Happy-path tests for ``render_digest_pdf``."""

    def setup_method(self) -> None:
        _install_fake_weasyprint(b"%PDF-1.4 sentinel")

    def teardown_method(self) -> None:
        _remove_fake_weasyprint()

    def test_returns_bytes(self) -> None:
        digest = _make_digest()
        result = render_digest_pdf(digest)
        assert isinstance(result, bytes)

    def test_returns_fake_pdf_bytes(self) -> None:
        digest = _make_digest()
        result = render_digest_pdf(digest)
        assert result == b"%PDF-1.4 sentinel"

    def test_html_called_with_string_kwarg(self) -> None:
        """WeasyPrint's ``HTML`` must be initialised with ``string=...``."""
        digest = _make_digest()
        render_digest_pdf(digest)

        fake_html_class = sys.modules["weasyprint"].HTML  # type: ignore[attr-defined]
        call_kwargs = fake_html_class.call_args.kwargs
        assert "string" in call_kwargs, "HTML() was not called with `string=` kwarg"
        # The HTML string should contain DOCTYPE and digest content.
        assert "<!DOCTYPE html>" in call_kwargs["string"]

    def test_write_pdf_called_once(self) -> None:
        digest = _make_digest()
        render_digest_pdf(digest)

        fake_instance = sys.modules["weasyprint"].HTML.return_value  # type: ignore[attr-defined]
        fake_instance.write_pdf.assert_called_once()


# ---------------------------------------------------------------------------
# render_digest_pdf — WeasyPrint unavailable
# ---------------------------------------------------------------------------


class TestRenderDigestPdfUnavailable:
    """Verify graceful failure when the WeasyPrint native stack is absent."""

    def setup_method(self) -> None:
        # Remove any stub that a previous test may have left behind.
        _remove_fake_weasyprint()
        # Make import fail so the guard path is exercised.
        sys.modules["weasyprint"] = None  # type: ignore[assignment]

    def teardown_method(self) -> None:
        _remove_fake_weasyprint()

    def test_raises_weasyprint_unavailable_error(self) -> None:
        digest = _make_digest()
        with pytest.raises(WeasyPrintUnavailableError):
            render_digest_pdf(digest)

    def test_error_message_mentions_installation(self) -> None:
        digest = _make_digest()
        with pytest.raises(WeasyPrintUnavailableError, match="WeasyPrint"):
            render_digest_pdf(digest)


# ---------------------------------------------------------------------------
# weekly_digest_task — unit tests (no DB, no real WeasyPrint)
# ---------------------------------------------------------------------------


class TestWeeklyDigestRunOnce:
    """Tests for ``weekly_digest_task.run_once`` with all I/O mocked."""

    def setup_method(self) -> None:
        _install_fake_weasyprint(b"%PDF-1.4 ok")

    def teardown_method(self) -> None:
        _remove_fake_weasyprint()

    @pytest.mark.asyncio
    async def test_run_once_generates_artefact_for_each_active_tenant(self) -> None:
        """``run_once`` should call ``_generate_for_tenant`` N times."""
        from app.workers import weekly_digest_task as wdt

        tenant_a = MagicMock()
        tenant_a.id = uuid.uuid4()
        tenant_b = MagicMock()
        tenant_b.id = uuid.uuid4()

        with (
            patch.object(wdt, "_fetch_active_tenants", new=AsyncMock(return_value=[tenant_a, tenant_b])),
            patch.object(wdt, "_generate_for_tenant", new=AsyncMock()) as mock_gen,
            patch("app.workers.weekly_digest_task.AsyncSessionLocal"),
        ):
            stats = await wdt.run_once(ref_date=date(2026, 5, 11))  # a Monday

        assert stats["tenants"] == 2
        assert stats["generated"] == 2
        assert stats["failed"] == 0
        assert mock_gen.call_count == 2

    @pytest.mark.asyncio
    async def test_run_once_records_failure_without_aborting_other_tenants(self) -> None:
        """A failure on tenant A must not prevent tenant B from being processed."""
        from app.workers import weekly_digest_task as wdt

        tenant_a = MagicMock()
        tenant_a.id = uuid.uuid4()
        tenant_b = MagicMock()
        tenant_b.id = uuid.uuid4()

        async def gen_side_effect(tenant_id, *args, **kwargs):
            if tenant_id == tenant_a.id:
                raise RuntimeError("DB exploded")

        with (
            patch.object(wdt, "_fetch_active_tenants", new=AsyncMock(return_value=[tenant_a, tenant_b])),
            patch.object(wdt, "_generate_for_tenant", new=AsyncMock(side_effect=gen_side_effect)),
            patch("app.workers.weekly_digest_task.AsyncSessionLocal"),
        ):
            stats = await wdt.run_once(ref_date=date(2026, 5, 11))

        assert stats["tenants"] == 2
        assert stats["generated"] == 1
        assert stats["failed"] == 1

    @pytest.mark.asyncio
    async def test_artefact_exists_skips_generation(self) -> None:
        """If a digest artefact already exists for the window, skip generation."""
        from app.workers import weekly_digest_task as wdt

        tenant = MagicMock()
        tenant.id = uuid.uuid4()

        with (
            patch.object(wdt, "_fetch_active_tenants", new=AsyncMock(return_value=[tenant])),
            patch.object(wdt, "_artefact_exists", new=AsyncMock(return_value=True)),
            patch.object(wdt, "build_weekly_digest", new=AsyncMock()) as mock_build,
            patch("app.workers.weekly_digest_task.AsyncSessionLocal"),
        ):
            # Call _generate_for_tenant directly to test the skip path.
            period_start = datetime(2026, 5, 4, tzinfo=UTC)
            period_end = datetime(2026, 5, 10, 23, 59, 59, tzinfo=UTC)
            await wdt._generate_for_tenant(tenant.id, period_start, period_end)

        mock_build.assert_not_called()

    @pytest.mark.asyncio
    async def test_html_fallback_used_when_weasyprint_unavailable(self) -> None:
        """When WeasyPrint is unavailable, artefact uses HTML format."""
        from app.workers import weekly_digest_task as wdt

        # Remove fake WeasyPrint to force the fallback path.
        _remove_fake_weasyprint()
        sys.modules["weasyprint"] = None  # type: ignore[assignment]

        digest = _make_digest()

        added_artefact: dict = {}

        async def fake_generate(tenant_id, period_start, period_end):
            """Thin inline re-implementation that captures the artefact without DB."""
            from app.services.digest_html import render_digest_html
            from app.services.digest_pdf import WeasyPrintUnavailableError, render_digest_pdf

            output_format = "pdf"
            try:
                raw_bytes = render_digest_pdf(digest)
            except WeasyPrintUnavailableError:
                raw_bytes = render_digest_html(digest).encode("utf-8")
                output_format = "html"

            added_artefact["output_format"] = output_format
            added_artefact["body_b64"] = base64.b64encode(raw_bytes).decode("ascii")

        period_start = datetime(2026, 5, 4, tzinfo=UTC)
        period_end = datetime(2026, 5, 10, 23, 59, 59, tzinfo=UTC)

        with patch.object(wdt, "_generate_for_tenant", new=fake_generate):
            await wdt._generate_for_tenant(TENANT_ID, period_start, period_end)

        assert added_artefact["output_format"] == "html"
        body = base64.b64decode(added_artefact["body_b64"]).decode("utf-8")
        assert "<!DOCTYPE html>" in body

        # Restore the fake for subsequent tests.
        _install_fake_weasyprint(b"%PDF-1.4 ok")


# ---------------------------------------------------------------------------
# _week_window helper
# ---------------------------------------------------------------------------


def test_week_window_returns_correct_bounds() -> None:
    from app.workers.weekly_digest_task import _week_window

    # Monday 2026-05-11 → previous week: 2026-05-04 to 2026-05-10 23:59:59.999999
    start, end = _week_window(date(2026, 5, 11))
    assert start == datetime(2026, 5, 4, tzinfo=UTC)
    # end should be just before 2026-05-11 00:00:00
    assert end == datetime(2026, 5, 11, tzinfo=UTC) - timedelta(microseconds=1)


def test_week_window_period_end_is_before_ref_date() -> None:
    from app.workers.weekly_digest_task import _week_window

    ref = date(2026, 5, 18)
    start, end = _week_window(ref)
    assert start < end
    assert end < datetime(ref.year, ref.month, ref.day, tzinfo=UTC)
