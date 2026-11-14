---
title: Mailbox remediation
sidebar_label: Mailbox remediation
---

# Mailbox remediation

Reported phish goes from a report mailbox to a purge across the recipients
who received it, with the approval tier scaled by how many of them there are.

Everything on this page is **off until you turn it on**. AiSOC does not
acquire the ability to delete from your mailboxes by being upgraded.

## What is actually supported

Only verbs Microsoft Graph and the Gmail API document.

| Verb | Microsoft 365 | Google Workspace | Reverse |
|---|---|---|---|
| `search_mailboxes` | `GET /users/{id}/messages?$filter=internetMessageId eq '…'` | `users.messages.list?q=rfc822msgid:…` | n/a (read) |
| `purge_email` | move to `recoverableitemsdeletions` | `users.messages.trash` | `restore_email` |
| `restore_email` | move back to the original folder | `users.messages.untrash` | `purge_email` |
| `block_sender` | inbox `messageRules` entry | `users.settings.filters` entry | `unblock_sender` |
| `unblock_sender` | delete the rule | delete the filter | `block_sender` |

Two absences are deliberate and worth reading before you plan around them.

**There is no hard delete.** A purge is a soft delete on both vendors —
recoverable items on Microsoft, Trash on Gmail — because `restore_email` has
to be a real reverse rather than a declared one. A verb that cannot be undone
has no business being dispatched across a thousand mailboxes.

**There is no tenant-wide sender block.** Exchange Online's Tenant Allow/Block
List is reached through Exchange Online PowerShell and the Defender portal,
and Workspace's domain block list through the Admin console; neither is in the
API this platform speaks. `block_sender` is therefore **per mailbox**, and the
summary an analyst reads says so. An analyst who reads "sender blocked" and
believes the organisation is covered has been misled by the product, which is
worse than the product not offering the button.

## Enabling it

Three things, in this order.

1. **Grant the application permissions.** Microsoft 365 needs `Mail.ReadWrite`
   on the same app registration the Entra ID identity actions use —
   `azure_tenant_id`, `azure_client_id` and `azure_client_secret` are the same
   three credentials, deliberately, so you do not register a second app to
   purge a message. Google Workspace needs domain-wide delegation for
   `gmail.readonly`, `gmail.modify` and `gmail.settings.basic`.

2. **Turn the capability on** in `services/actions`:

   ```bash
   AISOC_FEATURE_MAILBOX_REMEDIATION=true
   ```

   With it unset, every mailbox verb — including the read — answers `failed`
   and names this variable. It does not simulate, and it does not report a
   purge that did not happen.

3. **Nominate a report mailbox**, if you want the poller. Set
   `phishing_report_mailbox` in the `connector_config` of an enabled
   `m365_audit`, `azure_entra` or `google_workspace` connector, and enable the
   worker:

   ```bash
   PHISHING_INTAKE_WORKER_ENABLED=true
   ```

   The worker polls every five minutes by default. It never guesses an
   address: with the flag on and no mailbox nominated it logs which half is
   missing rather than going quiet.

## The three intake doors

| Door | How it arrives | Use it when |
|---|---|---|
| Report-mailbox poller | AiSOC reads the mailbox over Graph or Gmail | Users forward phish to a shared address |
| `POST /api/v1/phishing/reports` | Your automation posts the vendor payload | You already have a bot or a webhook |
| `email_inbox` connector | IMAP poll, through the existing connector | Neither API is available to you |

All three normalise to one record, so the campaign and the purge do not know
which door a report came through.

The adapter reads **through a forward**. A user who reports phish by
forwarding it becomes the sender of the outer message, so a naive reader would
name the victim as the attacker and put your report mailbox in the recipient
list the purge then proposes to clean. The Graph adapter reads the original
sender and the original recipients out of the preserved internet headers, and
where a forward dropped them it leaves the sender empty rather than guessing.

## Campaign grouping

Reports are joined into a campaign by the strongest attribute they carry:

1. the internet message id — the same message, by definition;
2. an attachment hash — the same file reached several people;
3. the first URL — the same landing page;
4. the sender;
5. a normalised subject.

The campaign records **which** of these matched, as `grouping_basis`, and
publishes `grouping_is_factual`. The first four are facts about the message.
Subject similarity is a judgement: it strips reply prefixes and collapses
digits and long opaque tokens, so `Invoice 10452 overdue` and
`Invoice 98113 overdue` group — which is the point, and is also why it is last
and why the basis is published. You are entitled to know which kind of claim
you are about to act on across forty mailboxes.

## What the analysis says, and what it refuses to say

Every reported message is analysed on intake and again on retriage: the
headers, up to five URLs, and every attachment digest the reporter supplied.

### Sender authentication has three values, not two

| Value | Means |
|---|---|
| `pass` | A receiving boundary evaluated the check and it passed |
| `fail` | A receiving boundary evaluated the check and it failed |
| `not_evaluated` | **Nobody checked** |

The third is the one that matters. A message with no `Authentication-Results`
header has not passed SPF — it has not been evaluated, usually because it
never crossed a boundary that evaluates. AiSOC publishes that as
`not_evaluated` and never folds it into either of the other two. The RFC 8601
tokens `none`, `neutral`, `policy`, `permerror` and `temperror` are also
`not_evaluated`, because each one means the check did not reach a verdict,
and reading them as passes is how a domain with a broken SPF record comes to
look authenticated.

Every method gets an entry even when no clause mentions it, so a console
cannot show "SPF fail" and silently omit DMARC.

### The verdict is only ever raised

A malicious artefact raises the verdict to `malware`. **SPF and DMARC both
failing** raises it to `phishing` — both, not either, because a forwarded
message routinely breaks SPF and a DMARC pass on DKIM alignment is the normal
outcome; flagging one failure alone would alert on every mailing list in the
estate. `not_evaluated` raises nothing and lowers nothing.

### Counts are never summed

The analysis reports `artefacts_analysed` and `artefacts_unanalysed`
separately and the API does not add them up. Five artefacts on a deployment
with no sandbox configured is an analysis that examined nothing, and a
surface rendering "5 artefacts, 0 findings" has said the opposite of what
happened. A URL that could not be submitted appears in the output saying so;
it does not vanish from it.

Attachments are **hash lookup only** on this path, never an upload. Intake
runs unattended on whatever arrives, and an unattended path that can upload is
one misconfiguration away from disclosing every attachment a tenant receives.
To have a file analysed, post it to `/sandbox/files`, where the tenant's
upload policy is enforced.

### Where the evidence goes

Each analysis writes one investigation-ledger run and one `evidence_cited`
event per component — headers, URLs, attachments — **including** components
that found nothing. A ledger with no row for the URL check cannot be told
from one where the check passed. The run id comes back on the response as
`analysis_run_id`, and `None` means the ledger write failed, which is
reported rather than hidden.

The headers are stored on the submission (migration `111`), so a retriage
replays them instead of re-fetching the message. That ordering is not
incidental: by the time anybody asks why a message was purged, the purge has
usually removed it.

## The purge, and what it will ask of you

```bash
# Preview. Nothing is removed; every mailbox is graded and reported.
curl -X POST .../api/v1/phishing/campaigns/{id}/purge \
     -H 'Content-Type: application/json' -d '{"execute": false}'
```

The blast radius scales with the recipient count:

| Recipients | Impact | What that means |
|---|---|---|
| 1–4 | `moderate` | Analyst approval |
| 5–24 | `high` | Analyst approval, and the confidence floor rises |
| 25+ | `severe` | A human must approve, at **any** confidence and **any** autonomy tier |

The campaign is graded once and every per-mailbox dispatch underneath it is
held to the same grading, because both read the same function. The alternative
— grading each mailbox as a one-recipient purge — is the quiet way a severe
action becomes a moderate one.

Each recipient gets **its own dispatch**: its own contract check, its own
audit row, its own verification probe and its own restore handle. One approval
covering a list the approver never read is the thing the capability contract
exists to refuse.

### What counts as purged

Only a dispatch that reached the vendor. A mailbox that never held the message
is recorded as `not_found`, a preview as `simulated`, and a campaign where any
mailbox did not complete lands on `partially_purged` rather than `purged`.
Twenty of twenty-five reported as a purge teaches you to trust a number that
means nothing.

### Verification

After a purge, AiSOC re-queries the mailbox. This is the one probe in the
product whose confirming answer is an **absence**: on Microsoft the message
must no longer be findable, and on Gmail it must carry the `TRASH` label.
Absent credentials, or with the feature disabled, the result is `unverified`
— never `verified`.

### Reversing it

```bash
curl -X POST .../api/v1/phishing/campaigns/{id}/restore
```

Only mailboxes the purge executed on are restored; attempting the others would
report work that did not happen. Microsoft's move gives the message a new id
in the destination folder and the original folder is only knowable before the
move, so both were stored at purge time. Gmail keeps the id and untrash
restores the labels the message had.

## What has not been verified

**No Microsoft 365 or Google Workspace tenant has been exercised.** Every
request shape here is taken from the vendors' API reference and asserted
against a recorded mock, including the Graph filter, the move destination, the
inbox-rule body and the Gmail filter body. Nobody has watched Graph accept the
move or Gmail accept the trash. Treat the first run against your own tenant as
the first run.

The playbook pack's `Retract the message via the tenant's email gateway` step
is **not** this path and never was. It posts to `EMAIL_GATEWAY_URL`, which no
compose file or `.env.example` sets, under `on_failure: continue` — so on a
default deployment it is skipped and the message is not retracted. The
playbook engine has no `purge_email` step type, so the purge above is reached
through the route rather than from a playbook.
