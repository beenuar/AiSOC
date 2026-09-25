---
sidebar_position: 3
title: Ingest authentication
description: POST /v1/ingest now requires a credential that carries its own tenant. What to do on upgrade, how to mint a token, and how the two credential shapes differ.
---

# Ingest authentication

`POST /v1/ingest` and `POST /v1/ingest/batch` require a credential. The
credential determines which tenant the events are written for; the
`X-Tenant-ID` header no longer does.

:::danger Upgrading an existing deployment

**This is a breaking change and it needs an action from you.** Before this
release the endpoint authenticated nothing. It read `X-Tenant-ID`, believed
it, and wrote events for whatever tenant the caller named — so any client
that could reach the port could write alerts into any tenant, including ones
it had no relationship with.

After upgrading, every existing pusher gets `401` until it presents a
credential. Jump to [What to do on upgrade](#what-to-do-on-upgrade).

:::

## The two credential shapes

Which one you want depends on whether the caller acts for one tenant or
many.

| | Tenant push token | Service token |
|---|---|---|
| Credential | `aitnb_…`, a row in `tenant_inbox_tokens` minted with the `connector-push` template | `AISOC_SERVICE_TOKEN`, a shared secret |
| Authorises | exactly the tenant the token belongs to | any tenant, but one per request and only if it exists |
| Tenant comes from | the token itself | the `X-Tenant-ID` header, checked against the tenants table |
| Use it for | curl, scripts, agents, a single customer's forwarder | AiSOC's own services — `connectors` polls on behalf of every tenant it manages |

Both are presented the same way:

```
Authorization: Bearer <credential>
```

`X-Inbox-Token: <credential>` also works, for forwarders that cannot set an
`Authorization` header. This is the same mechanism and the same header
shapes as the inbox webhooks at `/v1/inbox/*`.

### The tenant header is intersected, never trusted

`X-Tenant-ID` is still accepted, and for a service token it is required —
that is how a trusted service says which tenant it is acting for. But it is
only ever **intersected** with what the credential authorises:

* A push token naming its own tenant: allowed.
* A push token naming a different tenant: `403`. The scope narrows to
  nothing, and nothing means refuse — not "fall back to the token's own
  tenant", and certainly not "reach into the named one".
* A service token naming a tenant that does not exist or is deactivated:
  `403`.
* A service token naming no tenant at all: `403`. An absent scope is
  refused rather than widened to every tenant.
* No credential: `401`.

## Minting a push token

From a shell on the deployment:

```bash
make ingest-token
```

or directly:

```bash
docker compose run --rm api python -m app.scripts.mint_ingest_token
```

Re-running returns the **same** token rather than minting a second one, so
it is safe to call from a script; `make ingest-token ARGS=--rotate` revokes
the current one and issues a replacement. `--tenant <id-or-slug>` picks the
tenant when the deployment has more than one.

From the console, the same token is available under **Settings →
Connectors → Push (any vendor)** as **Direct ingest API**, or over the API:

```bash
curl -X POST https://<your-aisoc-host>/api/v1/inbox/tokens \
  -H "Authorization: Bearer <your console token>" \
  -H 'Content-Type: application/json' \
  -d '{"template_id":"connector-push","label":"EDR forwarder"}'
```

### Pushing with it

```bash
curl -X POST http://localhost:8081/v1/ingest/batch \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $AISOC_INGEST_TOKEN" \
  -d '{"connector_id":"edr-1","connector_type":"crowdstrike","source_format":"json",
       "events":[{"severity":"high","title":"Encoded PowerShell from Office",
                  "host":"WIN-FIN-01","process_name":"powershell.exe"}]}'
```

### Signing the body

Mint the token with an `hmac_secret` and the ingest service additionally
requires an `X-Signature: sha256=<hex>` header over the raw request body,
verified in constant time. Same contract as the inbox webhooks, so a
forwarder already signing for `/v1/inbox/*` needs no new code.

## Why `connector-push` specifically

A token minted for `pagerduty` or `cloudflare-logpush` will be refused with
`403` even though it belongs to the right tenant. That is deliberate, and it
mirrors how `/v1/inbox/cef` only accepts a `cef-syslog` token.

An inbox token is pasted into a third party's webhook configuration — once
you have minted one for PagerDuty, PagerDuty holds it. Without the pin, that
vendor could replay its own URL's token against `/v1/ingest` and write
arbitrary connector events for your tenant. Minting a `connector-push` token
is a separate, deliberate act.

## What to do on upgrade

**1. Inventory what pushes to `/v1/ingest`.** Anything that is not an AiSOC
service — a SIEM forwarder, a cron job, a homegrown agent — needs a push
token. Mint one per pusher so you can revoke them independently.

**2. Set `AISOC_SERVICE_TOKEN` if you use pull connectors.** The
`connectors` service polls vendor APIs and pushes the results to
`/v1/ingest`, so it needs the service credential. The same value must be set
on **both** services:

```bash
# .env
AISOC_SERVICE_TOKEN=$(openssl rand -base64 32)
```

`docker-compose.yml` already passes it to both. If it is unset, connector
polling is refused and both services say so: `connectors` warns at startup
that every push will be refused, and `ingest` logs which credential sources
it has. Use `AISOC_INGEST_SERVICE_TOKEN` to give this hop its own secret.

**3. Check the startup log.** The ingest service reports what it can verify:

```
ingest: /v1/ingest requires an authenticated, tenant-scoped credential
  minted_tokens=true service_token=true
```

If it instead logs at error that no credential source is configured, it will
refuse every push. That happens when `DATABASE_DSN` is unset (so minted
tokens cannot be resolved) **and** no service token is set.

**4. There is no opt-out.** `AISOC_DEV_MODE` does not reach this path and no
flag disables it. An ingest service that cannot verify a credential answers
`503` rather than accepting the write unchecked.

## Other ingest routes

| Route | Credential |
|---|---|
| `/v1/ingest`, `/v1/ingest/batch` | push token or service token, as above |
| `/v1/inbox/{token}`, `/v1/inbox/email/{token}` | the token in the URL, optional HMAC |
| `/v1/inbox/cef`, `/v1/inbox/hec` | inbox token in `Authorization`, pinned to the `cef-syslog` / `splunk-hec` template |
| `/v1/ingest/k8s-audit/{tenant_id}` | `X-AiSOC-K8s-Token` shared secret; returns `503` until `K8S_AUDIT_SHARED_SECRET` is set |

## Troubleshooting

| Response | Meaning |
|---|---|
| `401 missing ingest credential` | No `Authorization` or `X-Inbox-Token` header. |
| `401 unrecognised ingest credential` | The token does not resolve. Check for a copy/paste truncation, or mint a new one. |
| `401 this ingest token has been revoked` | Rotated or revoked. Mint a replacement. |
| `403 this token was minted for the "…" template` | Right tenant, wrong template — mint one with `connector-push`. |
| `403 requested tenant is outside the credential's authorised scope` | The `X-Tenant-ID` header names a tenant this credential does not hold. |
| `403 a service token must declare the tenant it is acting for` | Service token with no `X-Tenant-ID`. |
| `403 declared tenant is unknown or inactive` | The declared tenant is not in the tenants table, or `is_active` is false. |
| `503 ingest authentication is not configured` | Neither `DATABASE_DSN` nor `AISOC_SERVICE_TOKEN` is set on the ingest service. |
