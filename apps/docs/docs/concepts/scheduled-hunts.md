---
title: Scheduled hunts and hunt reports
sidebar_position: 9
---

# Scheduled hunts and hunt reports

A saved hunt can run on a cron schedule. When it matches, AiSOC opens a case,
drafts a detection proposal, and — if you have asked it to — emails the hunt
report.

:::warning HUNTING OUTPUT, not a compliance artefact
A hunt report is the result of **one query over one window**. It is not a
record of retention, not a record of coverage, and not evidence that nothing
happened outside what it matched.

Finding nothing in a hunt report means this query over this window matched
nothing. It does not mean nothing happened.

Every rendering carries the label `HUNTING OUTPUT`: in the document banner, in
the page title, and in the subject line of the email. That is a deliberate
decision recorded in
[ADR-0015](https://github.com/beenuar/AiSOC/blob/main/docs/decisions/0015-siem-replacement-scope.md) —
AiSOC federates to your SIEM rather than replacing it, and a scheduled search
that emails a PDF is the surface a reader most easily mistakes for a
compliance report. If you need an artefact of record, use the
[evidence pack](../compliance/evidence-pack.md), which is built for that job.
:::

## Where a scheduled hunt runs

The scheduler picks one backend per hunt, and the order is deliberate.

| Order | Backend | Credentials | When it is chosen |
|---|---|---|---|
| 1 | Elasticsearch | the tenant's `elastic` connector, from the credential vault | the tenant connected Elastic and the hunt has an ES\|QL translation |
| 2 | Splunk | the tenant's `splunk` connector, from the credential vault | the tenant connected Splunk and the hunt has an SPL translation |
| 3 | The event lake | none — the lake is deployment configuration | nothing the tenant connected can answer |

**Your own SIEM always wins.** A tenant with Elastic or Splunk connected has
years of history AiSOC never ingested; answering from the lake instead would be
a narrower answer to the same question, given without anyone choosing it. The
lake is the fallback, not the default.

### Why the lake is in that list at all

Before this landed, a tenant who had connected no SIEM matched no provider, the
resolver raised, and the scheduler returned a hit count of **zero**. Zero hits
is not an error state — no case opens, nothing is logged above `INFO`, and the
hunt's `last_run_at` moves — so on every surface it was indistinguishable from
*"your hunt ran and found nothing"*.

That was the answer on every deployment whose data lives in AiSOC's own lake,
which is the default deployment, because AiSOC's own connectors put it there.

The distinction is preserved end to end: an unreachable lake raises rather than
returning zero, so the hunt retries on the next tick instead of moving its clock
and opening no case. *"We could not check"* and *"we checked and found
nothing"* are different facts, and only one of them should let anybody move on.

### Partial compilation is reported

Some hunt conditions have no column in the lake schema. When that happens the
hunt still runs, and the dropped fields are logged by name:

```
hunt_scheduler.lake_partial hunt_id=… dropped=process_name,registry_key
```

A hunt that ran with two of its four conditions missing found fewer matches
than was asked about. Publishing that count with no caveat would be a false
negative with a number on it.

## Emailing the report

**Off by default.** Set `AISOC_HUNT_REPORT_RECIPIENTS` to a comma-separated
list of addresses; leave it unset and nothing is mailed. An unset variable
means nobody asked for this — never "mail whichever account happens to be
configured".

```bash
AISOC_HUNT_REPORT_RECIPIENTS=soc@example.com,ir@example.com
```

Delivery uses the same SMTP settings as the weekly digest (`SMTP_HOST`,
`SMTP_SENDER`). With no relay configured, the send reports `skipped` naming the
setting rather than failing — the difference between *"we chose not to"* and
*"it broke"*.

Three further properties worth knowing:

- **A hunt that matched nothing mails nothing.** A report saying a hunt found
  nothing is a thing nobody forwards, and the saved-hunt list already shows it.
- **A missing PDF stack sends the HTML.** WeasyPrint's Pango, Cairo and GLib
  libraries ship in the API container image and are routinely absent on a local
  checkout. The report is the deliverable; the format is not.
- **A failing relay never costs the case.** The case the hunt opened matters
  more than the mail about it, so every delivery failure is logged and
  swallowed.

## What else a firing hunt does

- **Opens a case** (`case_type="hunt_finding"`, tagged `scheduled-hunt`), so
  the duty analyst sees it on the queue.
- **Drafts a detection proposal** into the governed flow — DRAFT only, and
  promotion still needs fixtures, a passing rule self-evaluation and a separate
  approver. Disable with `AISOC_HUNT_TO_DETECTION=false`.

## Turning the scheduler off

```bash
AISOC_HUNT_SCHEDULER_ENABLED=false
```

It is on by default and runs in-process in the API service, alongside the OAuth
refresh and weekly digest workers.
