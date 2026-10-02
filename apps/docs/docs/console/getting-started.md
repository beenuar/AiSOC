---
title: Your first ten minutes
sidebar_label: Getting started
---

# Your first ten minutes

This page covers what happens between `make up` finishing and AiSOC
triaging your own data. It is deliberately specific about what each step
proves, because several of them look similar and mean very different
things.

## Install

```bash
git clone https://github.com/beenuar/AiSOC && cd AiSOC
make up
```

That generates `.env` and its secrets, starts the stack, creates an
administrator, and prints a password **once**. Copy it.

### If a port is already in use

Nothing. AiSOC moves.

A Postgres on 5432 or an Ollama on 11434 is common — this project's
readers are exactly the people who have one — so `make up` picks a free
port instead of stopping, writes the change to `docker-compose.ports.yml`,
and tells you:

```
  2 port(s) were already in use, so AiSOC moved:
    postgres       5432 → 15432   (5432 is held by container my-postgres)
    ollama         11434 → 15434  (11434 is held by ollama)
```

Only the *published* side moves. Service-to-service traffic inside the
stack uses container ports and service names, so nothing about how AiSOC
talks to itself changes. If the console itself moves, `AISOC_CONSOLE_URL`
moves with it and the address `make up` prints is the one that answers.

That file is regenerated on each `make up` and removed once the conflict
is gone, so it never silently pins you to a port you no longer need.

### If something is wrong

```bash
make doctor
```

On a host where you have not run `make up` yet, it says so and points at
`make up` rather than listing every service as a failure.

## Prove the pipeline before you trust it

```bash
make smoke
```

This posts one real event to the ingest API and follows it through Kafka,
detection, correlation and Postgres, then reads the alert back out of the
public API. Ten stages, each PASS or FAIL. If this passes, the path your
own telemetry will take is working.

## Sign in

Open the address `make up` printed. A tenant with nothing connected lands
on the **setup wizard** rather than on an empty dashboard — a dashboard of
zeroes is accurate and tells you nothing about what to do next.

The wizard shows four things and what each one is worth:

| Step | What it proves |
|---|---|
| Administrator account | You are signed in, so this is already true |
| Connect a data source | AiSOC triages what your tools already see |
| Receive your first alert | The whole path end to end — a connector that saves but never polls looks identical until an alert arrives |
| Or try it with sample data | That triage works, before you have credentials for anything |

Its state is read from your tenant's own data every time, not from a
"finished onboarding" flag. Connect a source through the API and the
wizard knows; delete your last one and it knows that too.

## Try it before you connect anything

Press **Load sample data** in the wizard.

Five scenarios go through **the same ingest endpoint a real connector
uses** — they are not inserted into the database. That distinction is the
entire point: a console full of seeded rows looks identical whether
ingest, fusion and triage are working or completely broken. Because these
take the real path, seeing them arrive as alerts means you have watched
the product work.

They take a few seconds to appear, because they are being normalised,
correlated and triaged exactly like real telemetry.

The set is deliberately mixed — one critical, two high, one medium and one
that is genuinely routine — because a first run where everything is a
crisis teaches you nothing about how AiSOC separates signal from noise.
Watch what it says about the scanner.

### What sample data will not do

**It does not mark your setup complete.** You still have nothing
connected, and the wizard keeps saying so.

**It refuses to load into an estate that is already working.** A sample
alert sitting in a live queue is indistinguishable from a real one at a
glance, and an analyst dismissing a genuine alert because they assumed it
was sample data is a worse outcome than using a second tenant.

**It is obviously synthetic by construction.** Every address is an
[RFC 5737](https://datatracker.ietf.org/doc/html/rfc5737) documentation
range and every domain is
[RFC 2606](https://datatracker.ietf.org/doc/html/rfc2606) reserved —
neither can belong to anyone. Alerts are attributed to **AiSOC** in the
console's own source column, so a colleague who never saw this wizard can
still tell them apart.

Removing them is `DELETE FROM alerts WHERE connector_type = 'aisoc_sample'`,
which is safe precisely because the connector id is dedicated rather than
borrowed from a real vendor.

## Connect something real

From the wizard, or **Connectors → Add**. The picker leads with the
handful most teams start from — endpoint and identity — rather than making
you read an 84-row catalog first. Credentials are encrypted with the
per-tenant vault and never stored in a playbook or an export.

Once a connector is saved it polls on a schedule. The wizard's third step
flips when an alert arrives from it, which is the one that actually means
your deployment works.
