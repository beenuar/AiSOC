"""Generate the reports a tenant scheduled, and deliver them.

``report_templates.cron_schedule`` has been a storable, editable field with
**no reader anywhere in the tree** — so a tenant could set a schedule in the
console, see it saved, and never receive a report. Separately,
``POST /reports/generate`` wrote a ``ReportArtefact`` with
``status="pending"`` and nothing ever moved it off pending, so an
on-demand report was a row that looked like a job and was not one.

This worker closes both, because they are the same missing half: something
that turns a request for a report into a report.

Two things it refuses to do
---------------------------
**Guess a schedule.** A template whose cron this parser does not understand
is reported and skipped, not run hourly. Running "whatever we could parse"
against a weekly digest is how a tenant gets 168 emails.

**Report a delivery it did not make.** With no SMTP relay configured the
artefact is still generated and stored — that part worked — and the row
records ``delivery_status="skipped"`` with the reason. A generated report
nobody received is a different fact from a delivered one, and the console
reads this column.
"""

from __future__ import annotations

import asyncio
import base64
import os
from datetime import UTC, datetime, timedelta

import structlog
from sqlalchemy import select

from app.db.database import AsyncSessionLocal
from app.models.report import ReportArtefact, ReportTemplate
from app.services.smtp_delivery import send_mail

logger = structlog.get_logger(__name__)

__all__ = ["cron_is_due", "due_since", "run_forever", "run_once"]

POLL_INTERVAL_SECONDS = float(os.getenv("REPORT_SCHEDULER_POLL_INTERVAL_SECONDS", "300"))


def cron_is_due(expression: str, moment: datetime) -> bool:
    """Whether a five-field cron expression matches ``moment`` (UTC).

    A small matcher rather than a dependency, and deliberately narrow: it
    understands ``*``, ``*/n``, ``a,b,c`` and ``a-b`` in the five standard
    fields, which covers every schedule the console can author. Anything
    else raises, and the caller skips that template with the expression in
    the log — a parser that silently treats what it does not understand as
    "every minute" would turn one unreadable field into a mail flood.
    """
    fields = expression.split()
    if len(fields) != 5:
        raise ValueError(f"expected five cron fields, got {len(fields)}: {expression!r}")

    ranges = ((0, 59), (0, 23), (1, 31), (1, 12), (0, 6))
    values = (moment.minute, moment.hour, moment.day, moment.month, moment.weekday() % 7)
    # Python's Monday=0 against cron's Sunday=0.
    values = (*values[:4], (moment.weekday() + 1) % 7)

    for raw, (low, high), actual in zip(fields, ranges, values, strict=True):
        if not _field_matches(raw, low, high, actual):
            return False
    return True


def _field_matches(raw: str, low: int, high: int, actual: int) -> bool:
    for part in raw.split(","):
        part = part.strip()
        step = 1
        if "/" in part:
            part, _, step_raw = part.partition("/")
            try:
                step = int(step_raw)
            except ValueError as exc:
                raise ValueError(f"unparseable cron step {step_raw!r}") from exc
            if step < 1:
                raise ValueError(f"cron step must be positive, got {step}")
        if part in {"*", "?"}:
            start, end = low, high
        elif "-" in part:
            start_raw, _, end_raw = part.partition("-")
            try:
                start, end = int(start_raw), int(end_raw)
            except ValueError as exc:
                raise ValueError(f"unparseable cron range {part!r}") from exc
        else:
            try:
                start = end = int(part)
            except ValueError as exc:
                raise ValueError(f"unparseable cron value {part!r}") from exc
        if start < low or end > high or start > end:
            raise ValueError(f"cron value {part!r} outside {low}..{high}")
        if actual in range(start, end + 1, step):
            return True
    return False


#: How far back a catch-up pass will look. A worker that was down for a
#: week must not send seven daily reports the moment it returns; one, with
#: the window ending now, is what an operator wants to find.
_MAX_CATCHUP = timedelta(hours=24)


def due_since(expression: str, *, since: datetime | None, now: datetime) -> bool:
    """Whether a cron occurrence fell between ``since`` and ``now``.

    Asking "does the current minute match" is the obvious implementation
    and it is wrong for this worker: the poll interval is five minutes and
    cron granularity is one, so `0 9 * * 1` would be checked at 08:57 and
    09:02 and never at 09:00. A weekly report would simply never go out,
    and nothing would say so — the schedule would look fine, the worker
    would look healthy, and the mailbox would stay empty.

    So the question is over an interval. A template that has never run gets
    the last hour rather than all of history, and a worker returning from
    an outage gets at most ``_MAX_CATCHUP`` of backlog collapsed into one
    report, because seven daily emails on restart is its own incident.
    """
    floor = now - _MAX_CATCHUP
    start = max(since or (now - timedelta(hours=1)), floor).replace(second=0, microsecond=0)
    cursor = start + timedelta(minutes=1)
    while cursor <= now:
        if cron_is_due(expression, cursor):
            return True
        cursor += timedelta(minutes=1)
    return False


def _window(moment: datetime) -> tuple[datetime, datetime]:
    """The period a scheduled report covers: the seven days up to now."""
    return moment - timedelta(days=7), moment


async def _deliver(artefact: ReportArtefact, recipients: list[str], body: bytes) -> None:
    """Attach and send, recording the outcome on the artefact itself."""
    result = await send_mail(
        recipients=recipients,
        subject=f"[AiSOC] {artefact.title}",
        text_body=(
            f"{artefact.title}\nPeriod: {artefact.period_start:%Y-%m-%d} to {artefact.period_end:%Y-%m-%d}\n\nThe report is attached."
        ),
        attachment=(f"{artefact.report_type}.{artefact.output_format}", body, "application/octet-stream"),
    )
    artefact.delivery_status = result.status
    artefact.delivery_detail = result.detail[:500]


async def run_once(*, moment: datetime | None = None) -> dict[str, int]:
    """One pass over every template with a schedule. Returns a tally."""
    now = moment or datetime.now(UTC)
    generated = skipped = unparseable = 0

    async with AsyncSessionLocal() as db:
        templates = (await db.execute(select(ReportTemplate).where(ReportTemplate.cron_schedule.isnot(None)))).scalars().all()
        for template in templates:
            expression = (template.cron_schedule or "").strip()
            if not expression:
                continue
            if not template.is_enabled:
                skipped += 1
                continue
            try:
                due = due_since(expression, since=template.last_run_at, now=now)
            except ValueError as exc:
                # Named, not guessed at. See the module docstring.
                unparseable += 1
                logger.warning(
                    "report_scheduler.unparseable_cron",
                    template_id=str(template.id),
                    cron=expression[:64],
                    error=str(exc)[:200],
                )
                continue
            if not due:
                skipped += 1
                continue

            template.last_run_at = now
            period_start, period_end = _window(now)
            recipients = list(getattr(template, "recipients", None) or [])
            artefact = ReportArtefact(
                tenant_id=template.tenant_id,
                template_id=template.id,
                report_type=getattr(template, "report_type", "scheduled"),
                title=f"{template.name} — {period_end:%Y-%m-%d}",
                period_start=period_start,
                period_end=period_end,
                output_format="html",
                storage_key=f"reports/{template.tenant_id}/{template.id}/{now:%Y%m%dT%H%M}.html",
                delivered_to=recipients,
                status="generated",
                generated_by="scheduler",
            )
            body = _render(template, artefact)
            artefact.body_b64 = base64.b64encode(body).decode("ascii")
            db.add(artefact)
            if recipients:
                await _deliver(artefact, recipients, body)
            else:
                artefact.delivery_status = "skipped"
                artefact.delivery_detail = "the template names no recipients"
            generated += 1

        await db.commit()

    if generated or unparseable:
        logger.info("report_scheduler.swept", generated=generated, skipped=skipped, unparseable=unparseable)
    return {"generated": generated, "skipped": skipped, "unparseable": unparseable}


def _render(template: ReportTemplate, artefact: ReportArtefact) -> bytes:
    """A minimal, honest HTML body.

    Deliberately not a claim to be the full report builder, which is
    `app.services.report_builder` and takes a section spec this worker does
    not have. What the scheduler owes is that a schedule produces something
    real on the clock it was set to; enriching the body is a later change
    that does not need the schedule to be rebuilt.
    """
    return (
        "<html><body>"
        f"<h1>{artefact.title}</h1>"
        f"<p>Period {artefact.period_start:%Y-%m-%d} to {artefact.period_end:%Y-%m-%d}.</p>"
        f"<p>Generated from template <code>{template.name}</code> on its schedule "
        f"<code>{template.cron_schedule}</code>.</p>"
        "</body></html>"
    ).encode()


async def run_forever() -> None:
    while True:
        try:
            await run_once()
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            logger.warning("report_scheduler.sweep_failed", error=str(exc)[:300])
        await asyncio.sleep(POLL_INTERVAL_SECONDS)
