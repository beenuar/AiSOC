---
title: File and URL analysis providers
sidebar_label: File and URL analysis
---

# File and URL analysis providers

AiSOC talks to malware sandboxes and file-reputation services through one
interface, so the console, the enrichment path and the investigation agent all
read the same words whichever backend answered. A verdict, a score, signatures,
IOCs and an ATT&CK mapping are the vocabulary; each provider maps its own
payload onto them.

Three providers ship today:

| Provider | Runs | Uploads | Status |
|---|---|---|---|
| `capev2` | Your own network | Yes | Open-source reference. Written against the documented CAPEv2 REST API, **unverified against a live instance** |
| `malwareanalyzer` | Hosted, third party | Yes, **published by default** | Commercial adapter. Hash lookup and report mapping verified against the live service; authentication unverified |
| `mock` | In process | No effect | Analyses nothing. Present so the wiring is exercised on a deployment with no sandbox configured |

## The rule that matters: uploading a file is a disclosure

A SHA-256 lookup tells a provider a 32-byte digest. Uploading the file tells it
the file. Those are different acts, and AiSOC treats them differently.

**Hash lookup always runs first.** If the provider has already analysed the
file, the existing report is used and nothing is uploaded. This is the common
case and it costs nothing.

**Uploading is off by default.** It must be enabled per tenant *and* per
provider, by someone holding `settings:write`, and the decision is recorded with
who made it and which version of the disclosure text they were shown. Consent
is per provider because consenting to a sandbox in your own rack says nothing
about a hosted service.

**Air-gapped mode permits local providers only.** When `AISOC_AIRGAPPED` is on,
a hosted provider stays visible in the settings list, marked excluded with the
reason, rather than silently disappearing.

**Every decision is logged**, refusals included. `aisoc_sandbox_submissions`
holds one row per artefact with the outcome, the reason and an `uploaded`
boolean that is true only when bytes actually left the deployment. That column
is what answers "did any customer file go to a third party".

### What MalwareAnalyzer's consent text says, and why

An operator enabling uploads to `malwareanalyzer` is shown this:

> Enabling uploads lets AiSOC send files from this tenant to malwareanalyzer
> for analysis. A file may contain customer data, credentials, personal data or
> intellectual property. AiSOC cannot inspect a file to decide whether it does.
> malwareanalyzer publishes submitted samples by default: an uploaded file and
> its report become readable by anyone on the internet, not only by the vendor.
> Treat every upload as a public disclosure that cannot be recalled. AiSOC
> always looks a file's SHA-256 up first and only uploads when the provider has
> not seen it. Every upload and every refusal is recorded against this tenant.

The word *public* is there because it is literally what the service reports. A
stored report fetched from `GET /v1/reports/<sha256>` carries
`visibility: "public"` and `tlp: "clear"`. TLP:CLEAR is the Traffic Light
Protocol's unrestricted level, so this is not a vendor-internal default: the
sample is readable by anyone.

The service's own web client does send a `visibility` field on submission and
offers a `private` option, but it pins `public` and disables the control when
there is no signed-in account. So `private` appears to need an authenticated
account. AiSOC requests the visibility you configure and assumes nothing about
whether it is honoured: the consent text keeps saying *public* until an
operator sets `MALWAREANALYZER_PRIVATE_SUBMISSIONS_CONFIRMED=1`, which is a
statement that **they** confirmed private submissions work for their account.
Letting a mere API key flip that wording would be an unverified assumption
rewriting the sentence somebody agrees to before disclosing a customer file.

## Configuration

Nothing is enabled by default. A hosted provider that switched itself on
because a base URL had a default would be a deployment making outbound calls
nobody asked for.

### CAPEv2 (recommended, and the only option air-gapped)

```bash
AISOC_CAPEV2_URL=http://cape.internal:8000
AISOC_CAPEV2_TOKEN=            # optional; omit entirely on an open instance
```

Leave the token unset if your instance does not require one. AiSOC sends no
`Authorization` header at all rather than an empty one, which would turn an
open instance into a 401.

### MalwareAnalyzer

```bash
AISOC_MALWAREANALYZER_ENABLED=1
MALWAREANALYZER_BASE_URL=https://malwareanalyzer.com
MALWAREANALYZER_API_KEY=                 # optional, see below
MALWAREANALYZER_API_KEY_HEADER=Authorization
MALWAREANALYZER_API_KEY_PREFIX="Bearer "
MALWAREANALYZER_PRIVATE_SUBMISSIONS_CONFIRMED=  # only after you have verified it
```

:::caution Authentication is unverified

The service publishes "No API key required", and every call AiSOC makes works
without one. There **is** an authenticated surface, and the service's own web
client sends `Authorization: Bearer <token>`, which is why that is the default
here. But a bogus `Bearer` and a bogus `x-api-key` produce byte-identical
`401`s, and the CORS preflight reflects whatever header is asked for, so
neither confirms the scheme for a *minted API key*.

Nobody has confirmed this against a real key. `MALWAREANALYZER_API_KEY_HEADER`
and `MALWAREANALYZER_API_KEY_PREFIX` exist so you can correct it without a code
change, and the settings surface reports authentication as unverified rather
than showing a tick this project has not earned. If you hold a real key and
determine the scheme, please open an issue.

:::

## How a pending or failed analysis surfaces

A sandbox is slow and failure-prone. Two states are kept distinct from a clean
result everywhere they travel:

* **Pending.** A submitted file has no verdict yet. The report carries
  `state: pending` or `running` and its verdict field reads `unavailable`. It is
  never rendered as benign, and the agent is told the analysis is incomplete.
* **Could not check.** A provider that timed out, refused authentication or
  returned something unparseable produces `outcome: could_not_check` with the
  reason attached. It never produces a report.

To the investigation agent, both arrive as `available: false` with wording that
says plainly that the file was **not** assessed and that this is not evidence
the file is benign. That distinction is the one that matters: a model reading a
timeout as "no detections" writes a benign verdict on a file nobody analysed.

An unknown hash is handled the same way. "No provider has ever analysed this
file" is genuinely different from "a provider analysed it and found nothing",
and targeted malware is unknown to every public service by design.

## "Unavailable" is not zero

Where a provider does not publish one of the interface's fields, it reads
`unavailable`, never `0` and never `[]`, and the report says why.

The clearest example is in the test fixtures. A MalwareAnalyzer report for a
file whose type could not be identified carries `attackTechniques: []` next to
`behavior.analyzed: false`. The list is empty because no guest was ever chosen
and the behavioural stage never ran, not because the sample exhibits no
techniques. AiSOC reports that as:

```json
{
  "attack": "unavailable",
  "unavailable_reasons": {
    "attack": "behavioural analysis did not run (unidentified_file_type), so no techniques could be observed"
  }
}
```

The same payload with the behavioural stage marked as having run produces a
real empty list, which means "we looked and found none".

## The agent tool

The investigation agent gets one tool, `lookup_file_hash`. It cannot upload.

That is deliberate, not a transport limitation. An upload is a disclosure
governed by a consent an operator recorded deliberately, and a decision that
consequential does not belong behind a sentence a model chose to emit. An
injected instruction in an attachment name would otherwise be one step away
from exfiltrating the attachment.

The tool authenticates with the agent service's own API key
(`AISOC_AGENTS_API_KEY`) and passes no tenant. The API resolves the tenant from
that credential, so a prompt cannot redirect the lookup or reach another
tenant's history.

## API

| Route | Permission | Notes |
|---|---|---|
| `GET /api/v1/sandbox/providers` | `threat_intel:read` | Providers, their consent state and the current disclosure text |
| `POST /api/v1/sandbox/lookup` | `threat_intel:read` | Hash lookup. Never uploads |
| `POST /api/v1/sandbox/files` | `threat_intel:write` | Hash lookup, then upload only if consent exists **and** `confirm_upload` is set |
| `POST /api/v1/sandbox/urls` | `threat_intel:write` | URL submission. Not covered by the upload policy, still covered by air-gap |
| `GET /api/v1/sandbox/analyses/{provider}/{handle}` | `threat_intel:read` | Poll |
| `PUT /api/v1/sandbox/consent` | `settings:write` | Record or withdraw consent |

`POST /api/v1/phishing/submit` accepts `attachment_hashes`, which are looked up
through the same path. It accepts digests only: that route runs unattended on
submitted mail, and an unattended path that can upload is one misconfiguration
away from disclosing every attachment a tenant receives.

## Adding a provider

Implement `SandboxProvider` in
`services/api/app/services/sandbox/providers/`, declare `ProviderCapabilities`
including `local` and `submissions_are_public_by_default`, and register it in
`registry.py`. Nothing outside that package should learn the new provider's
name.

`scripts/check_sandbox_upload_policy.py` fails if an adapter does not declare
its locality, if a consent-shaped flag defaults to on, if the hash lookup stops
preceding the upload, or if an exception handler starts producing a report.
