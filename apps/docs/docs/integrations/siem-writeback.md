---
id: siem-writeback
title: SIEM disposition writeback
sidebar_label: SIEM writeback
---

# SIEM disposition writeback

AiSOC reads findings out of your SIEM, triages them, and — once you turn this
on — writes the verdict back onto the finding that produced the alert. A Splunk
notable AiSOC dismissed stops waiting for an analyst to re-read it. An Elastic
signal AiSOC confirmed is already assigned by the time somebody opens the
queue.

Until this shipped the integration ran one way only. The finding came in, the
verdict stayed in AiSOC, and the queue in the source system never changed.

## What gets written

The mapping is deliberate. Three rules govern everything:

| AiSOC verdict | What happens to the source finding |
| --- | --- |
| `false_positive` | Closed, with AiSOC's reasoning attached |
| `benign` | Closed, with AiSOC's reasoning attached |
| `benign_true_positive` | Closed, classified as a *correct* detection of authorised activity — never as a false positive |
| `true_positive` | **Left open.** Annotated, moved to in-progress, assigned |
| `escalate` | **Left open.** Annotated, moved to in-progress, assigned |
| `needs_review` | Nothing is written |
| anything else | Refused |

**A confirmed true positive is never closed.** It is the finding a human most
needs to see, and closing it because the platform is confident is how an agent
turns a real intrusion into a resolved ticket nobody read.

**An unknown verdict is refused, never guessed.** A disposition outside the
canonical taxonomy leaves the finding exactly as it was. This is stricter than
it looks: elsewhere in the platform an unrecognised verdict normalises to
`true_positive` as a fail-safe, and a writeback that normalised first would
convert "I do not recognise this string" into a confident claim and then act
on it.

**`benign_true_positive` is not a false positive.** An approved penetration
test or a sanctioned admin tool is a *correct* detection. Filing it as a false
positive corrupts the rule's own false-positive rate, so the vendor
classification reflects the distinction — `BenignPositive` on Sentinel,
`TruePositive` + `SecurityTesting` on Defender.

## Governance

Two environment variables, and the important one defaults to off.

| Variable | Default | Effect |
| --- | --- | --- |
| `AISOC_SIEM_WRITEBACK_ENABLED` | `1` (on) | Master switch. Off means nothing is attempted at either end. |
| `AISOC_SIEM_WRITEBACK_EXECUTE` | `0` (**off**) | Whether a vendor is actually called. Off means every attempt is dispatched as a dry run. |
| `AISOC_SIEM_WRITEBACK_CLOSE_CASE` | `0` (**off**) | Whether a closing verdict may resolve a linked case and project that onto its Jira / ServiceNow ticket. |

The asymmetry is the point. A writeback that did not happen costs an analyst
one duplicated triage. A writeback that happened when you did not expect it
silently closed findings in your system of record. So you opt in to writing
into your own SIEM; you do not opt out.

Anything that is not an explicit yes (`1`, `true`, `yes`, `on`) is read as a
dry run, including an unrecognised value — a typo must not be read as consent.

### Telling a dry run from a write

A dry run and a live call are both HTTP 200. One field distinguishes them
everywhere it matters:

```json
{
  "alert_id": "…",
  "disposition": "false_positive",
  "mode": "dry_run",
  "executed": false,
  "executed_count": 0,
  "outcomes": [
    {
      "vendor": "splunk",
      "external_id": "NOTABLE-42",
      "status": "dry_run",
      "executed": false,
      "writeback_action": "close",
      "detail": "DRY RUN — nothing was written to splunk. AiSOC triaged this finding as false_positive (confidence 91%). Closing it in the source system."
    }
  ]
}
```

`executed` is `true` only when a vendor call actually ran. A refusal, a dry
run, and a simulation for want of credentials all report `false`, and the
`alert_source_links.executed` column carries the same flag with no default —
a row that was never written back cannot read as one that was.

## How the join works

The source system's own identifier for a finding — a Splunk notable's rule
UID, an Elastic signal id, a Sentinel incident name, a QRadar offense id —
arrives through ingest as OCSF `finding.uid` and is stored two ways:

* `alerts.external_id`, the denormalised join key on the alert row;
* `alert_source_links`, the reconciliation record: which connector instance
  produced the finding, what was last written back to it, when, and whether
  that write executed.

Fusion writes both at promotion time, because that is the only moment the
alert id, the connector instance and the vendor finding id exist together.
A source with no writeback arm gets no link row at all — a link for a vendor
AiSOC cannot write to would read as a two-way integration that is not one.

See the links for an alert with:

```
GET /api/v1/alerts/{alert_id}/source-links
```

## Supported systems

| System | Close | Escalate | Notes |
| --- | --- | --- | --- |
| Splunk Enterprise Security | notable status → closed | notable status → in progress, owner set | Management port is **8089**, not a web port. Token or basic auth. |
| Elastic Security | signal status → `closed` | signal status → `acknowledged` | Needs `kibana_url` as well as `elastic_url`. |
| Microsoft Sentinel | incident → `Closed` + classification | incident → `Active`, owner set | App registration needs the *Sentinel Responder* role; *Reader* fails only at the PATCH. |
| IBM QRadar | offense → `CLOSED` + closing reason | note added, offense stays `OPEN` | `closing_reason_id` is per-deployment and has no safe default — set it in the connector config or a close fails loudly. |
| Microsoft Defender | alert classified + resolved | alert commented, assigned | |

TLS verification is on by default for the appliance clients. Operators running
an internal CA can opt out per instance (`qradar_verify_ssl`,
`splunk_verify_ssl`); that is an explicit opt-in to a weaker posture, never a
default.

## Ticketing

Where the alert's case has a Jira or ServiceNow ticket, a closing verdict can
carry through to it — but only by resolving the case first. The ITSM
connectors project a *status transition*, not a note, so the only truthful way
to reach the ticket is to make the transition real. Synthesising one would put
a resolution on somebody's ticket that no AiSOC record supports.

That makes it a bigger action than closing a SIEM finding — a case is a unit of
work with an owner — so it sits behind its own flag,
`AISOC_SIEM_WRITEBACK_CLOSE_CASE`, on top of the execute flag. With it off the
linked ticket is reported `skipped` with the reason rather than silently
ignored.

## Who may call it

```
POST /api/v1/alerts/{alert_id}/source-writeback
```

Two callers. A person in the console authenticates with a session and needs
`alerts:write`; their tenant comes from the session, never from the request
body. The agents worker authenticates with `AISOC_AGENTS_SERVICE_TOKEN` and
must name the tenant it is acting for.

**The service token fails closed.** When `AISOC_AGENTS_SERVICE_TOKEN` is unset
there is no service path at all — an unauthenticated caller is refused rather
than admitted, because an empty secret compared against an absent header is
how an internal route becomes a public one. If the variable is not set, the
worker logs a warning naming the reason rather than failing silently.

The worker never dispatches the vendor call itself. The API service holds the
credential vault, the tenant-scoped session and the actions-service token, and
it is the single governed path a response action takes.

## Autonomy posture

`update_alert_disposition` is declared LOW impact with `MANUAL_ONLY` reversal
in the capability contract, alongside `create_notable_event` and `push_status`
— it changes a queue item, not an estate, and a wrong one is re-opened from
the vendor console in a click.

What bounds it is not the approval tier but the disposition mapping above,
plus the execute flag. Re-opening a finding an analyst may since have actioned
would race them in their own console, so there is no automatic rollback: the
contract says `MANUAL_ONLY` and means it.
