# ADR-0015: AiSOC does not take on SIEM-replacement scope; it federates to the SIEM instead

- **Status:** proposed
- **Date:** 2026-11-01
- **Related:** ADR-0010 (entity and session context in CORE), ADR-0013 (audit retention), the event lake (`services/fusion/app/services/lake_writer.py`, ClickHouse, `full` profile), federated search (`services/connectors/app/federated/translators/`: SPL, KQL, ES|QL, AQL), `README.md`'s "Not a drop-in SIEM replacement"
- **Decides:** wave-2 depth plan Phase 0.4, which asks whether AiSOC takes on compliance search, saved and scheduled searches with export, and long-term retention SLAs, and what that would cost against the 8 GB CORE budget

## Context

The README says, under "What AiSOC is not": **"Not a drop-in SIEM
replacement. It correlates and investigates; it does not replace long-term
log retention and compliance search."** The wave-2 plan requires that line to
be decided deliberately rather than left as an accident of what was never
built, because three capabilities now sit close enough to it to blur:

1. **An event lake exists.** `lake_writer.py` writes normalised OCSF events to
   ClickHouse (`aisoc.raw_events`), queryable with tenant-scoped SQL through
   `/investigate/query`, with a per-tenant retention window up to a 400-day
   ceiling and a legal hold that outranks it.
2. **Hunting exists on top of it.** Saved hunts, a 68-hunt YAML library, a
   scheduler, retro-hunts that re-sweep history on new intelligence, and PDF
   hunt reports.
3. **Federated search exists.** Four translators compile one hunt into SPL,
   KQL, ES|QL and AQL and fan it out to Splunk, Sentinel, Elastic and QRadar
   on per-tenant credentials.

From a distance, "it stores events, searches them, schedules searches and
exports reports" is a SIEM. The question is whether to close the remaining
distance — compliance-grade search over years of retained raw logs, with the
retention SLA and the export obligations that implies.

## What the remaining distance actually costs

Measured against this tree rather than estimated in the abstract.

**The profile budget is the hard constraint.** CORE is 16 services in ~8 GB
of memory and 20 GB of disk, and ClickHouse is not in it — the lake is a
`full`-profile component. Compliance search is not a feature that can be
added to CORE; it is a second deployment tier. A tenant retaining raw logs
for a seven-year compliance window is storing two to three orders of
magnitude more bytes than the 400-day alert-and-event window the lake is
sized for today, which moves the product from "runs on one host" to "runs on
a storage cluster". That is a different product with a different first-run
story, and the first-run story is the thing this project has spent three
releases making true.

**A retention SLA is an operational promise, not a code change.** The
difference between "we keep events for the window you chose" (today, with the
purge worker and legal hold) and "we guarantee retrieval of any event from
the last seven years within N minutes, and can attest to it" is monitoring,
backup verification, restore drills and an availability commitment. This
repository ships a backup-destroy-restore gate it is proud of; it does not
ship, and should not imply, an availability commitment to a self-hoster whose
storage it does not operate.

**Compliance search has an evidential bar the lake does not meet.** A
compliance search answers "show me every access to this record, and prove
nothing was removed". The lake is a normalised OCSF projection: fields the
normaliser does not map are not in it, so it cannot answer "show me the raw
log exactly as the source emitted it" for an auditor. Making it able to would
mean storing the raw payload alongside the projection — roughly doubling the
storage of the component that is already outside CORE.

## Decision

**AiSOC does not take on SIEM-replacement scope.** The README line stays, and
stays true. Specifically:

- **Retention stays scoped to investigation**, not compliance: the window a
  tenant chooses up to the 400-day ceiling, for correlation, hunting and
  retro-hunts. No retention SLA is offered.
- **Compliance search belongs to the system of record.** Where a tenant has a
  SIEM or a log archive, AiSOC federates to it rather than duplicating it —
  the four translators already compile a hunt into that system's own query
  language, and that is the supported answer to "search the last three
  years".
- **Scheduled searches stay hunts, not reports of record.** The wave-2 plan's
  Phase 5.2 extends the hunt scheduler to the lake and the federated backends
  with an emailed PDF. That is operational hunting output. It is not a
  compliance artefact and the docs must not let it read as one.
- **Nothing in wave 2 is built from this ADR.** Phase 0.4 asks for the
  decision, not the implementation; the plan explicitly forbids building
  SIEM-replacement scope unless the maintainer accepts a decision to.

## Consequences

- `README.md`'s "Not a drop-in SIEM replacement" is now a decided position
  with a reason, and any future surface that implies otherwise — a marketing
  line, a docs page, a feature named "compliance search" — contradicts a
  published ADR rather than merely overreaching.
- Phase 5.2's emailed hunt PDF must be labelled as hunting output in its own
  docs page. A scheduled search that emails a PDF is exactly the surface a
  reader mistakes for a compliance report.
- Federated search becomes the load-bearing answer to long-horizon questions,
  which raises the cost of its gaps: per-tenant credentials, the service-token
  path and honest failure reporting when a backend cannot be searched. Wave 2
  Phase 5.2 carries that work.
- The 400-day ceiling and the legal hold stay as they are. Neither is
  presented as a compliance guarantee.

## Alternatives considered

**Take on compliance search as a third profile (`archive`).** Rejected for
now, not forever. It is a coherent product — ClickHouse with raw-payload
retention, tiered to object storage, with restore drills — but it is a
storage product with an availability promise, and this project has no
measured evidence it can keep one. Reconsider only with a design partner
operating it, and with the restore drill measured on their data volume, not
on a fixture.

**Claim it informally** — keep the lake as it is and let "search your events"
imply compliance coverage. Rejected outright: it is the published-claim
failure this repository has spent its last several releases eliminating, and
the one place a false claim costs a user an audit finding rather than a
re-run.

**Drop the lake and federate only.** Rejected. The lake is what makes
retro-hunts, the 68-hunt library and offline investigation work on a
self-hosted install with no SIEM at all, which is a real deployment shape for
this audience.
