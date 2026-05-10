"""WS-G2 — Weekly executive digest auto-generation worker.

Runs as a single ``asyncio.Task`` started from the API's ``lifespan`` hook
(see ``app/main.py``).  Every Monday at 00:05 UTC the worker:

1. Fetches all *active* tenants.
2. Calls :func:`build_weekly_digest` to assemble the ``ExecutiveDigest`` for
   the previous ISO week (Mon 00:00 → Sun 23:59 UTC).
3. Renders the digest to PDF bytes via :func:`render_digest_pdf` when
   WeasyPrint is available, otherwise falls back to storing the HTML body.
4. Persists a :class:`ReportArtefact` row (``report_type="weekly_digest"``,
   ``output_format="pdf"|"html"``) with the base-64–encoded payload in
   ``body_b64`` and a human-readable ``storage_key``.

Failure model
-------------
* A failure for one tenant is caught, logged, and does **not** abort the
  remaining tenants — resilience over atomicity for background work.
* The outer loop retries after ``WEEKLY_DIGEST_POLL_INTERVAL_SECONDS``
  (default: 3 600 s / 1 hour) so a transient DB hiccup self-heals without
  operator intervention.
* Cancellation (ASGI shutdown) propagates cleanly through ``CancelledError``.

Configuration
-------------
``WEEKLY_DIGEST_WORKER_ENABLED``
    Set to ``false`` to disable (e.g. in unit-test environments).
``WEEKLY_DIGEST_POLL_INTERVAL_SECONDS``
    How often (seconds) the worker checks whether a digest is due.  Defaults
    to ``3600`` (1 hour).  The worker only *generates* when the current UTC
    weekday is Monday and the hour is ``00``.

Author: Beenu <beenu@cyble.com>
"""

from __future__ import annotations

import asyncio
import base64
import logging
import uuid
from datetime import UTC, date, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import AsyncSessionLocal
from app.models.report import ReportArtefact
from app.models.tenant import Tenant
from app.services.digest_pdf import WeasyPrintUnavailableError, render_digest_pdf
from app.services.executive_digest import build_weekly_digest

logger = logging.getLogger(__name__)

__all__ = ["run_once", "run_forever"]

# Weekday index for Monday in Python's datetime (0 = Monday).
_MONDAY = 0
# UTC hour at which we trigger generation (00:05 → hour == 0).
_TRIGGER_HOUR = 0


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _week_window(ref: date) -> tuple[datetime, datetime]:
    """Return the (period_start, period_end) for the ISO week ending on *ref*.

    *ref* is expected to be the current Monday.  We generate for the
    **previous** completed week: Monday-7d → the Monday just passed.

    Returns
    -------
    tuple[datetime, datetime]
        ``(prev_monday_00:00, prev_sunday_23:59:59)`` — both UTC-aware.
    """
    prev_monday = ref - timedelta(days=7)
    period_start = datetime(prev_monday.year, prev_monday.month, prev_monday.day, tzinfo=UTC)
    # End is Sunday 23:59:59 of the prev week, which is one microsecond
    # before the current Monday 00:00.
    period_end = datetime(ref.year, ref.month, ref.day, tzinfo=UTC) - timedelta(microseconds=1)
    return period_start, period_end


async def _fetch_active_tenants(db: AsyncSession) -> list[Tenant]:
    """Return all tenants with ``is_active=True``."""
    result = await db.execute(select(Tenant).where(Tenant.is_active.is_(True)))
    return list(result.scalars().all())


async def _artefact_exists(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    period_start: datetime,
) -> bool:
    """Return True if a weekly digest artefact already exists for this window.

    Prevents duplicate generation when the worker restarts within the same
    trigger window (e.g. after an API process restart on Monday morning).
    """
    result = await db.execute(
        select(ReportArtefact.id).where(
            ReportArtefact.tenant_id == tenant_id,
            ReportArtefact.report_type == "weekly_digest",
            ReportArtefact.period_start == period_start,
        )
    )
    return result.scalar_one_or_none() is not None


async def _generate_for_tenant(
    tenant_id: uuid.UUID,
    period_start: datetime,
    period_end: datetime,
) -> None:
    """Build, render, and persist one weekly digest artefact for *tenant_id*.

    Uses its own ``AsyncSession`` so that a failure here does not poison the
    caller's session.
    """
    async with AsyncSessionLocal() as db:
        if await _artefact_exists(db, tenant_id, period_start):
            logger.info(
                "weekly_digest.skip tenant_id=%s period_start=%s — artefact already exists",
                tenant_id,
                period_start.date(),
            )
            return

        digest = await build_weekly_digest(
            db,
            tenant_id,
            period_start=period_start,
            period_end=period_end,
        )

        output_format = "pdf"
        try:
            raw_bytes = render_digest_pdf(digest)
        except WeasyPrintUnavailableError:
            # Fall back to HTML when the native WeasyPrint stack is absent
            # (e.g. dev containers without Pango/Cairo).  The artefact is
            # still persisted so the digest is not silently lost.
            logger.warning(
                "weekly_digest.weasyprint_unavailable — storing HTML fallback tenant_id=%s",
                tenant_id,
            )
            from app.services.digest_html import render_digest_html  # lazy import

            raw_bytes = render_digest_html(digest).encode("utf-8")
            output_format = "html"

        body_b64 = base64.b64encode(raw_bytes).decode("ascii")
        storage_key = f"weekly_digest/{tenant_id}/{period_start.strftime('%Y-%m-%d')}_{period_end.strftime('%Y-%m-%d')}.{output_format}"
        title = f"AiSOC Weekly Executive Digest {period_start.strftime('%d %b')}–{period_end.strftime('%d %b %Y')}"

        artefact = ReportArtefact(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            report_type="weekly_digest",
            title=title,
            period_start=period_start,
            period_end=period_end,
            output_format=output_format,
            body_b64=body_b64,
            storage_key=storage_key,
            file_size_bytes=len(raw_bytes),
            data_snapshot=digest.model_dump(mode="json"),
            generated_by="weekly_digest_worker",
            status="ready",
        )
        db.add(artefact)
        await db.commit()

        logger.info(
            "weekly_digest.stored tenant_id=%s storage_key=%s size_bytes=%d fmt=%s",
            tenant_id,
            storage_key,
            len(raw_bytes),
            output_format,
        )


async def run_once(ref_date: date | None = None) -> dict[str, int]:
    """Generate weekly digests for all active tenants.

    Parameters
    ----------
    ref_date:
        The Monday that triggers generation; defaults to ``date.today()``.
        Primarily exposed for unit-test injection without mocking the clock.

    Returns
    -------
    dict[str, int]
        ``{"tenants": N, "generated": M, "failed": K}``
    """
    today = ref_date or datetime.now(UTC).date()
    period_start, period_end = _week_window(today)

    stats: dict[str, int] = {"tenants": 0, "generated": 0, "failed": 0}

    async with AsyncSessionLocal() as db:
        tenants = await _fetch_active_tenants(db)

    stats["tenants"] = len(tenants)

    for tenant in tenants:
        try:
            await _generate_for_tenant(tenant.id, period_start, period_end)
            stats["generated"] += 1
        except Exception as exc:  # noqa: BLE001
            stats["failed"] += 1
            logger.exception(
                "weekly_digest.tenant_failed tenant_id=%s err=%s",
                tenant.id,
                type(exc).__name__,
            )

    logger.info(
        "weekly_digest.run_once tenants=%d generated=%d failed=%d",
        stats["tenants"],
        stats["generated"],
        stats["failed"],
    )
    return stats


async def run_forever(*, stop_event: asyncio.Event | None = None) -> None:
    """Poll hourly and generate digests every Monday at 00:xx UTC.

    Mirrors the structure of ``workers/oauth_refresh.py`` so the two workers
    are consistent in how they integrate with the ASGI ``lifespan`` hook.

    The optional ``stop_event`` is provided so integration tests can halt the
    loop deterministically without raising ``CancelledError``.
    """
    from app.core.config import settings  # local import avoids circular deps

    interval = max(60, getattr(settings, "WEEKLY_DIGEST_POLL_INTERVAL_SECONDS", 3600))

    logger.info("weekly_digest.started poll_interval=%ds", interval)

    try:
        while True:
            if stop_event is not None and stop_event.is_set():
                break

            now_utc = datetime.now(UTC)
            if now_utc.weekday() == _MONDAY and now_utc.hour == _TRIGGER_HOUR:
                try:
                    stats = await run_once()
                    logger.info(
                        "weekly_digest.tick tenants=%d generated=%d failed=%d",
                        stats["tenants"],
                        stats["generated"],
                        stats["failed"],
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.exception("weekly_digest.tick_failed err=%s", type(exc).__name__)
            else:
                logger.debug(
                    "weekly_digest.idle weekday=%d hour=%d — not Monday 00:xx UTC",
                    now_utc.weekday(),
                    now_utc.hour,
                )

            try:
                if stop_event is not None:
                    await asyncio.wait_for(stop_event.wait(), timeout=interval)
                else:
                    await asyncio.sleep(interval)
            except TimeoutError:
                continue

    except asyncio.CancelledError:
        logger.info("weekly_digest.cancelled — shutting down cleanly")
        raise
    finally:
        logger.info("weekly_digest.stopped")
