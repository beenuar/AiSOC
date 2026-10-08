---
title: White-label branding
sidebar_label: White-label branding
description: Apply your own product name, logo, colours and support contacts across the console and reports.
---

# White-label branding

A managed-service provider can present AiSOC as its own product. Branding is
set once per operator organisation and applies to every tenant in that
organisation's portfolio, plus the organisation's own staff console.

## What is branded

| Surface | What changes |
|---|---|
| Console sidebar | Product name, logo, primary colour on the wordmark, accent colour on the logo frame |
| Console browser tab | The product name in the page title |
| Executive digest (HTML and PDF) | Product name, logo, primary colour, accent colour, footer, support link |
| Case close-out summary (HTML, print to PDF) | Product name, logo, primary colour, accent colour, footer, support link |
| Replay evaluation report (PDF) | Product name, logo, primary colour, accent colour, footer, support link |
| Investigation summary (PDF) | Product name, primary colour, footer, support contact |
| Email approvals | Product name in the subject and body, `sender_name` as the From display name, primary and accent colours, footer, support contact |
| Usage CSV export | The organisation named in the header block |

Branding resolves field by field. An organisation that sets a product name
and no colours renders its name against the platform palette, rather than
losing the one field it configured.

Two details are deliberate rather than oversights.

The investigation summary PDF carries no logo. It is drawn by `reportlab`
rather than rendered from HTML, so there is nowhere to place an image without
writing the asset to disk first; the product name, palette, footer and
support contact are all present.

The approve and deny buttons in an approval email stay green and red. Those
two colours say "this one contains a host" and "this one does not", and a
palette that could swap them would be a safety problem rather than a
branding feature.

## Email approvals

The signed email fallback is off until it has somewhere to send to. Set both:

```bash
AISOC_APPROVAL_EMAIL_RECIPIENTS=oncall@acme.example,duty@acme.example
AISOC_EMAIL_APPROVAL_SECRET=<a long random string>
MAILGUN_API_KEY=<key>
MAILGUN_DOMAIN=mail.acme.example
```

Every address also needs an entry in `AISOC_CHATOPS_APPROVERS` under `email`.
The recipient is signed into the approval token and forwarded as the approver,
so an address that is not mapped is refused when somebody clicks rather than
when the mail is sent.

Each recipient receives their own message with their own pair of links. One
shared link would record every click as the same identity, and separation of
duties cannot be evaluated against a distribution list.

The `From` address stays on your own Mailgun sending domain whatever
`sender_name` says. Only the display name a recipient reads is
white-labelled: a `From` address on a domain the deployment does not control
fails SPF and DKIM, which is how approval mail lands in a spam folder on the
day it matters.

## Setting it

```bash
curl -X PUT https://<your-aisoc-host>/api/v1/branding \
  -H "Authorization: Bearer $AISOC_SESSION_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
        "product_name": "Acme Shield",
        "primary_color": "#123456",
        "accent_color": "#654321",
        "support_email": "soc@acme.example",
        "support_url": "https://support.acme.example",
        "sender_name": "Acme SOC"
      }'
```

Requires `settings:write`, and applies to the organisation your tenant
belongs to. There is no field for naming a different organisation: that would
let an authenticated user of one tenant rebrand somebody else's console.

`support_url` must be `https`. It is rendered as a link in email and in PDF
reports, so a `javascript:` or `data:` value there would be a stored script
in somebody else's inbox.

If your tenant does not belong to an organisation, this returns 409. Create
an organisation and add the tenant to its portfolio first.

## Uploading a logo

```bash
curl -X POST https://<your-aisoc-host>/api/v1/branding/assets/logo \
  -H "Authorization: Bearer $AISOC_SESSION_TOKEN" \
  -F "file=@logo.svg"
```

Accepted types are `image/svg+xml`, `image/png`, `image/jpeg` and
`image/webp`, up to 256 KB.

Assets are **stored in your deployment**, never referenced by URL. A logo
fetched from a remote address would be an outbound request made by every
console that renders it and, for a PDF, by the server itself. Reports also
stay readable years later, rather than turning into a broken image when
somebody tidies up a bucket.

### SVG uploads are sanitised

SVG is XML with a scripting model. It can carry `<script>`, event handler
attributes, `<foreignObject>` containing arbitrary HTML, CSS that fetches
remote resources, and references to other documents. A logo uploaded by an
administrator is rendered inside consoles and inside reports that other
people open, so an unsanitised SVG is a stored cross-site scripting vector
with a distribution mechanism attached.

Uploads are therefore rewritten against an **allowlist**, not scrubbed
against a denylist:

- Only drawing elements survive: shapes, paths, text, gradients, clip paths,
  masks and groups. `<script>`, `<foreignObject>`, `<use>`, `<image>`,
  `<style>`, `<a>` and every animation element are dropped with their
  subtrees.
- Only geometry and presentation attributes survive. Every attribute
  beginning `on` is dropped by shape, as is anything in the `xlink`
  namespace.
- A paint reference may only point inside the same document. `fill="url(#g1)"`
  survives; `fill="url(https://…)"` does not.
- A document declaring a `DOCTYPE` or an `ENTITY` is **refused outright**,
  before parsing. Both entity-expansion denial-of-service variants need one,
  and a logo has no use for either.
- The stored file is re-serialised from the parsed document, so anything the
  parser did not understand cannot survive into it.

The response tells you what was removed:

```json
{
  "was_sanitized": true,
  "removed": { "elements": ["script"], "attributes": ["onload"] }
}
```

If your logo renders differently from your graphics program, that field is
the explanation. Exporting as a plain path-based SVG, or as PNG, usually
resolves it.

Detection is on the bytes as well as the declared content type. An SVG
announced as `image/png` still goes through the sanitiser, because the
uploader controls that header.

## Removing branding

```bash
curl -X DELETE https://<your-aisoc-host>/api/v1/branding/assets/logo \
  -H "Authorization: Bearer $AISOC_SESSION_TOKEN"
```

Clearing every field on `PUT /api/v1/branding` returns each surface to the
platform appearance.

## What is not branded

Two surfaces are not, and both are a limit rather than an omission.

**Slack and Teams messages carry the platform name.** The interactive
approval prompt is posted by `services/actions`, and the bot services are
`services/slack-bot` and `services/teams-bot`. None of the three can read the
branding store, which lives behind the API alongside the tenant session and
the credential vault. Reading it from a deployment-wide environment variable
would be worse than leaving it: branding is set per operator organisation, so
one name baked into the process would be wrong for every organisation on the
deployment except one, while looking configured.

**The sign-in page carries the platform name.** `GET /api/v1/branding`
resolves the organisation from the caller's credential, and on the sign-in
page there is no credential yet. Nothing maps a hostname to an organisation
either — `organizations` has a slug and a name and no domain — so the page
has no way to work out whose product it is about to show. Branding it needs a
hostname-to-organisation mapping first, which does not exist today.
