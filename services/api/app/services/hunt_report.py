"""Turn what a hunt found into something a person can read and cite.

Depth plan 9.5. A natural-language hunt produced rows; a retro-hunt produced
a ``retro_hunt_sightings`` row. Neither produced anything a person could
read, forward or file, and the report surface and the hunt surface did not
know about each other at all — ``grep -n hunt`` across ``report_builder.py``
and ``endpoints/reports.py`` returned nothing.

Four sections, in the order a reader asks
-----------------------------------------
What, how, where, when. Each is derived from facts already recorded, and a
section that cannot be derived stays **empty**. That is the whole discipline
here: a report is a thing somebody forwards to a manager or attaches to a
ticket, and a confident sentence about nothing is worse in that context than
a blank. :func:`build_hunt_report` never writes a sentence it cannot support
from a row.

Citations are not decoration
----------------------------
"With ledger citations" is the load-bearing half of the item. Every citation
names a ``kind``, an ``id`` and a human ``label``, so a renderer can link it
and an auditor can resolve it afterwards. A report that cites nothing is
refused at build time rather than stored — an uncited report is an
assertion, and this product's position is that an assertion is not evidence.

Why the counts are stored and not recomputed
--------------------------------------------
A report is a snapshot. Re-running the hunt tomorrow gives a different
number, and the report has to keep saying what it said when it was written —
the same reasoning that makes ``aisoc_outbound_deliveries`` store its
payload rather than re-serialise it on retry.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from html import escape
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

SOURCE_KINDS: tuple[str, ...] = ("hunt", "retro_hunt")


class HuntReportError(ValueError):
    """A refusal the caller can act on. Routes render it with the text."""


@dataclass
class HuntReport:
    """The four sections, their citations, and what produced them."""

    title: str
    what: str = ""
    how: str = ""
    where: str = ""
    when: str = ""
    citations: list[dict[str, str]] = field(default_factory=list)
    match_count: int = 0

    def is_citable(self) -> bool:
        return bool(self.citations)


def _cite(kind: str, identifier: Any, label: str) -> dict[str, str]:
    return {"kind": kind, "id": str(identifier), "label": label}


# ---------------------------------------------------------------------------
# From a saved natural-language hunt
# ---------------------------------------------------------------------------


def _strings(value: Any) -> list[str]:
    """Flatten a JSONB array column into strings, tolerating any shape.

    These columns are JSONB rather than `text[]`, so a row can legitimately
    hold a list of strings, a list of objects, or a scalar somebody wrote by
    hand. Refusing any of those would make a report fail on data the rest of
    the product accepts.
    """
    if isinstance(value, list):
        return [str(v) for v in value if isinstance(v, (str, int, float))]
    if isinstance(value, str):
        return [value]
    return []


def _entity_values(rows: Any, group: str) -> set[str]:
    """Entity values of one kind out of `alerts.entities`.

    `entities` is what fusion writes; the `affected_*` columns are written
    only by the demo seed. Reading both means a report says something on a
    real deployment as well as a seeded one.
    """
    out: set[str] = set()
    for row in rows:
        for entity in row["entities"] or []:
            if not isinstance(entity, dict):
                continue
            kind = str(entity.get("kind") or entity.get("type") or "").lower()
            value = entity.get("value") or entity.get("name")
            if value and group in kind:
                out.add(str(value))
    return out


async def build_from_hunt(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    saved_hunt_id: uuid.UUID,
) -> HuntReport:
    """Write a report for what a saved hunt matched.

    Refuses when the hunt has never run or matched nothing. "A hunt that
    finds something produces a report" is the item's own wording, and a
    report saying a hunt found nothing is a thing nobody forwards — the
    saved-hunt list already shows that.
    """
    hunt = (
        (
            await db.execute(
                text(
                    "SELECT id, name, nl_query, translated_query, language, last_run_at, "
                    "       created_by, created_at "
                    "FROM aisoc_saved_hunts WHERE id = :id AND tenant_id = :tenant_id"
                ).bindparams(id=saved_hunt_id, tenant_id=tenant_id)
            )
        )
        .mappings()
        .one_or_none()
    )
    if hunt is None:
        raise HuntReportError("No such saved hunt in this tenant.")
    if hunt["last_run_at"] is None:
        raise HuntReportError(
            f"{hunt['name']!r} has never run, so there is nothing to report. "
            "Run the hunt first; a report of a hunt that has not executed would be a "
            "statement about a query rather than about the estate."
        )

    # What the hunt matched, now. Alerts carry the hunt's own id when fusion
    # raised them from it; a hunt that matched events without raising alerts
    # is reported by its run metadata alone and says so.
    matches = (
        (
            await db.execute(
                text(
                    # `affected_hosts` / `affected_users` are JSONB *arrays*, not the
                    # singular text columns a reader expects, and `entities` is what
                    # fusion actually writes -- the `affected_*` pair is written only
                    # by the demo seed. Both are read, so a report covers a demo
                    # tenant and a real one, and a `WHERE` section built from
                    # whichever is present beats one that is empty on real data.
                    "SELECT id, title, severity, created_at, "
                    "       COALESCE(affected_hosts, '[]'::jsonb) AS hosts, "
                    "       COALESCE(affected_users, '[]'::jsonb) AS actors, "
                    "       COALESCE(entities, '[]'::jsonb) AS entities "
                    "FROM alerts WHERE tenant_id = :tenant_id AND raw_event->>'saved_hunt_id' = :hunt "
                    "ORDER BY created_at DESC LIMIT 50"
                ).bindparams(tenant_id=tenant_id, hunt=str(saved_hunt_id))
            )
        )
        .mappings()
        .all()
    )

    translated = hunt["translated_query"] or {}
    query_text = translated.get("query") if isinstance(translated, dict) else None

    report = HuntReport(title=f"Hunt findings: {hunt['name']}", match_count=len(matches))
    report.what = f"The saved hunt {hunt['name']!r} matched {len(matches)} alert(s). The analyst asked: {hunt['nl_query']!r}."
    report.how = (
        f"The question was translated into {hunt['language'].upper()} and run against the event "
        f"store. The model never wrote the query text; it chose a template and its parameters, "
        f"which is why the executed query can be shown verbatim"
        + (f":\n\n{query_text}" if query_text else " but was not recorded on this hunt.")
    )
    report.citations.append(_cite("saved_hunt", hunt["id"], f"saved hunt {hunt['name']!r} ({hunt['language'].upper()})"))

    hosts = sorted({h for row in matches for h in _strings(row["hosts"]) if h} | _entity_values(matches, "host"))
    actors = sorted({a for row in matches for a in _strings(row["actors"]) if a} | _entity_values(matches, "user"))
    if hosts or actors:
        parts = []
        if hosts:
            parts.append(f"{len(hosts)} host(s): {', '.join(hosts[:10])}")
        if actors:
            parts.append(f"{len(actors)} account(s): {', '.join(actors[:10])}")
        report.where = "The matches touch " + "; ".join(parts) + "."
    # No else. An empty `where` renders as "not recorded", which is what it
    # is when every matching alert carried no host and no account.

    times = [row["created_at"] for row in matches if row["created_at"]]
    if times:
        report.when = (
            f"Earliest match {min(times).isoformat()}, latest {max(times).isoformat()}. "
            f"The hunt last ran at {hunt['last_run_at'].isoformat()}."
        )
    else:
        report.when = f"The hunt last ran at {hunt['last_run_at'].isoformat()}."

    for row in matches[:20]:
        report.citations.append(_cite("alert", row["id"], f"{row['severity']} · {row['title'][:80]}"))
    return report


# ---------------------------------------------------------------------------
# From a retro-hunt sighting
# ---------------------------------------------------------------------------


async def build_from_retro_hunt(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    sighting_id: uuid.UUID,
) -> HuntReport:
    """Write a report for an indicator a retro-hunt matched in history.

    A retro-hunt's whole point is the gap between when intelligence arrived
    and when the estate first saw the thing, so that gap is computed and
    stated rather than left for a reader to subtract two timestamps.
    """
    row = (
        (
            await db.execute(
                text(
                    "SELECT id, indicator_type, indicator_value, feed_source, intel_first_seen_at, "
                    "       first_matched_at, last_matched_at, first_sighting_at, last_sighting_at, "
                    "       sightings, matched_surfaces, alert_id, times_seen "
                    "FROM retro_hunt_sightings WHERE id = :id AND tenant_id = :tenant_id"
                ).bindparams(id=sighting_id, tenant_id=tenant_id)
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise HuntReportError("No such retro-hunt sighting in this tenant.")

    report = HuntReport(
        title=f"Retro-hunt findings: {row['indicator_type']} {row['indicator_value']}",
        match_count=int(row["sightings"] or 0),
    )
    report.what = (
        f"Threat intelligence from {row['feed_source']} named the "
        f"{row['indicator_type']} {row['indicator_value']}, and a retrospective sweep found "
        f"{row['sightings']} prior sighting(s) of it in this estate's history."
    )
    report.how = (
        "The indicator arrived on a feed and was replayed against stored events rather than "
        "only being watched for going forward, which is what surfaces activity that predates "
        "the intelligence."
    )

    surfaces = row["matched_surfaces"] or []
    if surfaces:
        report.where = "Matched on: " + ", ".join(str(s) for s in surfaces[:20]) + "."

    first_seen = row["first_sighting_at"]
    intel_at = row["intel_first_seen_at"]
    when_parts: list[str] = []
    if first_seen and row["last_sighting_at"]:
        when_parts.append(f"Seen in this estate from {first_seen.isoformat()} to {row['last_sighting_at'].isoformat()}.")
    if intel_at:
        when_parts.append(f"Intelligence first published it at {intel_at.isoformat()}.")
    if first_seen and intel_at:
        gap_days = (intel_at - first_seen).total_seconds() / 86_400.0
        if gap_days > 0:
            # The number a retro-hunt exists to produce, stated rather than
            # left as two timestamps for the reader to subtract.
            when_parts.append(f"The estate saw it **{gap_days:.1f} days before** the intelligence named it.")
    report.when = " ".join(when_parts)

    report.citations.append(
        _cite("retro_hunt_sighting", row["id"], f"{row['indicator_type']} {row['indicator_value']} via {row['feed_source']}")
    )
    if row["alert_id"]:
        report.citations.append(_cite("alert", row["alert_id"], "the alert this sighting raised"))
    return report


# ---------------------------------------------------------------------------
# Ledger citations
# ---------------------------------------------------------------------------


async def attach_ledger_citations(
    db: AsyncSession,
    report: HuntReport,
    *,
    tenant_id: uuid.UUID,
    case_id: uuid.UUID | None,
) -> HuntReport:
    """Add the agent decisions behind this case to the citation list.

    The decision ledger is the artefact that makes the rest of the report
    checkable: it is where the prompt, the response and the tools used are
    recorded. Attached as citations rather than quoted, because a report is
    a summary and the ledger is the long form a reader follows into.

    Silently adds nothing when there is no case or no ledger rows. That is
    not a swallowed failure: a hunt report written before anybody opened a
    case legitimately has no agent decisions behind it, and inventing a
    citation would be the exact defect this function exists to prevent.
    """
    if case_id is None:
        return report
    rows = (
        (
            await db.execute(
                text(
                    # `investigation_events` keys on `run_id`, not on the case:
                    # the ledger belongs to a run and a case can have several.
                    # Joining through `investigation_runs` is the only path from
                    # one to the other, and getting this wrong would have cited
                    # an empty set on every report.
                    "SELECT e.id, e.kind, e.created_at FROM investigation_events e "
                    "JOIN investigation_runs r ON r.id = e.run_id "
                    "WHERE e.tenant_id = :tenant_id AND r.case_id = :case_id "
                    "ORDER BY e.created_at ASC LIMIT 20"
                )  # `investigation_runs.case_id` is TEXT, not UUID: the ledger predates
                # the typed case id, and binding a UUID raises in asyncpg rather
                # than coercing. Stringified here rather than cast in SQL so the
                # index on that column is still usable.
                .bindparams(tenant_id=tenant_id, case_id=str(case_id))
            )
        )
        .mappings()
        .all()
    )
    for row in rows:
        report.citations.append(_cite("ledger_event", row["id"], f"{row['kind']} at {row['created_at'].isoformat()}"))
    return report


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

_SECTIONS = (("what", "What"), ("how", "How"), ("where", "Where"), ("when", "When"))

#: ADR-0015 requires this, in these words, on every rendering of a hunt report.
#:
#: The ADR's reasoning: AiSOC federates to the SIEM rather than replacing it,
#: so a scheduled search that emails a PDF is "exactly the surface a reader
#: mistakes for a compliance report". A hunt report is a record of a query
#: somebody ran over a window somebody chose. It is not evidence of coverage,
#: it is not a retention artefact, and it does not say that what it did not
#: find was not there.
#:
#: A constant rather than a literal in the template so the renderer, the
#: email subject and the gate that checks for it cannot drift apart — the
#: defect the digest path already shipped once with two renderers.
HUNTING_OUTPUT_LABEL = "HUNTING OUTPUT"

#: Why the label is there, in the document rather than only in the ADR. A
#: banner reading only "HUNTING OUTPUT" tells a reader what the page is
#: called; this tells them what it does not claim.
_CLASSIFICATION_NOTE = (
    "This is the result of a hunt query over a chosen window. It is not a compliance artefact "
    "and not a record of retention or coverage: finding nothing here does not mean nothing "
    "happened, only that this query over this window matched nothing."
)


def render_html(row: dict[str, Any], *, product_name: str = "AiSOC") -> str:
    """A self-contained, print-ready page. The same HTML the PDF is made from.

    One renderer, not two. The digest path learned this the hard way: two
    renderers drift and the PDF stops matching the page somebody approved.

    Every interpolation is escaped. A hunt report carries a hunt's own
    natural-language text, host names and indicator values, all of which are
    attacker-influenced in the general case, and this document is opened in
    a browser.
    """
    sections = []
    for key, heading in _SECTIONS:
        body = (row.get(key) or "").strip()
        sections.append(
            f"<section><h2>{escape(heading)}</h2>"
            + (
                f"<p>{escape(body)}</p>"
                if body
                # Not a blank and not a sentence: a reader has to be able to
                # tell "nothing to say" from "nobody filled this in".
                else '<p class="absent">Not recorded. Nothing in the data supported this section.</p>'
            )
            + "</section>"
        )

    citations = row.get("citations") or []
    if citations:
        items = "".join(
            f'<li><span class="kind">{escape(str(c.get("kind", "")))}</span> '
            f"<code>{escape(str(c.get('id', '')))}</code> — {escape(str(c.get('label', '')))}</li>"
            for c in citations
        )
        citation_html = f"<ol>{items}</ol>"
    else:
        citation_html = '<p class="absent">No citations.</p>'

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>{HUNTING_OUTPUT_LABEL} — {escape(str(row.get("title", "Hunt report")))}</title>
<style>
  body {{ font-family: Arial, Helvetica, sans-serif; margin: 2.5rem; color: #111; line-height: 1.5; }}
  h1 {{ font-size: 1.5rem; margin-bottom: 0.25rem; }}
  h2 {{ font-size: 1rem; text-transform: uppercase; letter-spacing: .06em; color: #555; margin: 1.5rem 0 .35rem; }}
  .meta {{ color: #666; font-size: .85rem; }}
  .absent {{ color: #888; font-style: italic; }}
  ol {{ padding-left: 1.2rem; }}
  li {{ margin-bottom: .3rem; font-size: .9rem; }}
  .kind {{ display: inline-block; min-width: 9rem; color: #555; }}
  code {{ background: #f3f3f3; padding: 0 .25rem; }}
  .classification {{ border: 1px solid #b45309; background: #fffbeb; color: #78350f;
                     padding: .6rem .8rem; border-radius: 4px; margin-bottom: 1.25rem;
                     font-size: .85rem; }}
  .classification strong {{ letter-spacing: .08em; }}
</style></head>
<body>
  <div class="classification">
    <strong>{HUNTING_OUTPUT_LABEL}</strong> — {escape(_CLASSIFICATION_NOTE)}
  </div>
  <h1>{escape(str(row.get("title", "Hunt report")))}</h1>
  <p class="meta">{escape(product_name)} · {escape(str(row.get("source_kind", "")))} ·
     {int(row.get("match_count") or 0)} match(es) ·
     generated {escape(str(row.get("created_at", "")))}</p>
  {"".join(sections)}
  <section><h2>Citations</h2>{citation_html}</section>
</body></html>"""


def render_pdf(row: dict[str, Any], *, product_name: str = "AiSOC") -> bytes:
    """The same HTML, through WeasyPrint. Raises the shared unavailability error.

    Reuses ``digest_pdf``'s error type rather than defining a second one, so
    the route's 503 branch and its message are the ones operators already
    know from the weekly digest.
    """
    from app.services.digest_pdf import WeasyPrintUnavailableError  # noqa: PLC0415 - avoids a cycle at import

    try:
        from weasyprint import HTML  # type: ignore[import-untyped]  # noqa: PLC0415
    except (ImportError, OSError) as exc:
        raise WeasyPrintUnavailableError(
            "WeasyPrint is not available in this environment, so a PDF cannot be rendered. "
            "The same report is available as HTML and JSON. See services/api/Dockerfile for "
            "the required system packages."
        ) from exc
    pdf: bytes = HTML(string=render_html(row, product_name=product_name)).write_pdf()
    return pdf


async def persist(
    db: AsyncSession,
    report: HuntReport,
    *,
    tenant_id: uuid.UUID,
    source_kind: str,
    source_id: uuid.UUID,
    case_id: uuid.UUID | None,
    generated_by: str,
) -> dict[str, Any]:
    """Store the report. Refuses an uncited one."""
    if source_kind not in SOURCE_KINDS:
        raise HuntReportError(f"source_kind must be one of {list(SOURCE_KINDS)}")
    if not report.is_citable():
        raise HuntReportError(
            "Refusing to store a report with no citations. An uncited report is an assertion, "
            "and the point of this surface is that an assertion is not evidence."
        )
    row = (
        (
            await db.execute(
                text(
                    "INSERT INTO aisoc_hunt_reports "
                    '(tenant_id, source_kind, source_id, case_id, title, what, how, "where", "when", '
                    " citations, match_count, generated_by) "
                    "VALUES (:tenant_id, :source_kind, :source_id, :case_id, :title, :what, :how, "
                    "        :where_, :when_, CAST(:citations AS jsonb), :match_count, :generated_by) "
                    "RETURNING *"
                ).bindparams(
                    tenant_id=tenant_id,
                    source_kind=source_kind,
                    source_id=source_id,
                    case_id=case_id,
                    title=report.title,
                    what=report.what,
                    how=report.how,
                    where_=report.where,
                    when_=report.when,
                    citations=json.dumps(report.citations),
                    match_count=report.match_count,
                    generated_by=generated_by,
                )
            )
        )
        .mappings()
        .one()
    )
    out = dict(row)
    out["created_at"] = (
        out["created_at"].astimezone(UTC).isoformat() if isinstance(out.get("created_at"), datetime) else out.get("created_at")
    )
    return out
