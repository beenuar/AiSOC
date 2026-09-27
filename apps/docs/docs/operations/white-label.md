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
| Console | Product name, logo, accent colour |
| Executive digest (HTML and PDF) | Product name, logo, accent colour, footer, support link |
| Usage CSV export | The organisation named in the header block |

Branding resolves field by field. An organisation that sets a product name
and no colours renders its name against the platform palette, rather than
losing the one field it configured.

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

## What is not branded yet

Email approvals and ChatOps messages resolve the sender name from the same
place, and the plan lists them alongside the console and reports. The console
and the report path are implemented and gated; the notification surfaces read
the resolved `sender_name` but are not yet covered by an end-to-end test, so
treat those as unverified rather than working.
