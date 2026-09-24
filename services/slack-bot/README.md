# AiSOC Slack Bot

ChatOps surface for AiSOC: slash commands and interactive approval flows that
let an L1/L2 analyst run the SOC without leaving Slack.

This service is a thin **adapter** — it owns no security state. Every request
is forwarded to `services/api` (cases, alerts, investigations) or
`services/actions` (response actions, approvals) using a service-scoped
`aisoc_*` API key. The bot itself just translates Slack events ↔ AiSOC HTTP
calls and renders the result as Block Kit messages.

## Slash commands

All commands live under a single `/aisoc` slash command (Slack only allows
verb-based parsing inside the command text).

| Command                         | Behaviour                                                              |
| ------------------------------- | ---------------------------------------------------------------------- |
| `/aisoc list`                   | Open cases (top 10), severity-coloured cards, links into the web UI.   |
| `/aisoc investigate <case>`     | Kick off an investigation run for the case (no LLM cost in air-gap).   |
| `/aisoc explain <case>`         | Pull the per-case auto-summary (`GET /cases/{id}/summary`).            |
| `/aisoc isolate <host>`         | Submit `isolate_host` action — gated, posts an approval card.          |
| `/aisoc block <ip>`             | Submit `block_ip` action — gated, posts an approval card.              |
| `/aisoc help`                   | Inline command reference.                                              |

`isolate` and `block` always require explicit human approval; the bot posts a
"Approve / Deny" card and forwards the analyst's choice back to
`services/actions`.

## Configuration

Configured entirely via environment variables (Pydantic settings):

| Variable                              | Required | Description                                                  |
| ------------------------------------- | -------- | ------------------------------------------------------------ |
| `SLACK_BOT_TOKEN`                     | yes      | `xoxb-…` — bot user OAuth token.                             |
| `SLACK_SIGNING_SECRET`                | yes      | Used by Bolt to verify incoming Slack request signatures.    |
| `AISOC_API_BASE_URL`                  | yes      | e.g. `http://aisoc-api:8000` (in-cluster).                   |
| `AISOC_ACTIONS_BASE_URL`              | yes      | e.g. `http://aisoc-actions:8085` (in-cluster).               |
| `AISOC_API_SERVICE_TOKEN`             | yes      | `aisoc_…` API key with `cases:read,cases:write,alerts:read`. |
| `AISOC_ACTIONS_SERVICE_TOKEN`         | yes      | `aisoc_…` API key with `actions:write` (or shared key).      |
| `AISOC_WEB_BASE_URL`                  | no       | Public web URL used to deep-link case cards. Default `http://localhost:3000`. |
| `AISOC_DEFAULT_TENANT_ID`             | yes      | UUID of the tenant Slack actions belong to (single-tenant Slack workspace assumption). |
| `AISOC_SLACK_BOT_PORT`                | no       | Bolt FastAPI port. Default `8089`.                           |

Secrets must be mounted via your secret store (Doppler / Vault / k8s Secret) —
do **not** check them into the repo. `pnpm preflight` will fail if it detects
a Slack token in tracked files.

## Local dev

### Standalone (poetry)

```bash
poetry install
export SLACK_BOT_TOKEN=xoxb-…
export SLACK_SIGNING_SECRET=…
export AISOC_API_BASE_URL=http://localhost:8000
export AISOC_ACTIONS_BASE_URL=http://localhost:8002
export AISOC_API_SERVICE_TOKEN=aisoc_…
export AISOC_ACTIONS_SERVICE_TOKEN=aisoc_…
export AISOC_DEFAULT_TENANT_ID=00000000-0000-0000-0000-000000000000
poetry run uvicorn app.main:app --reload --port 8089
```

Then expose `http://localhost:8089/slack/events` to Slack via `ngrok`/`cloudflared`.

### Inside docker-compose

The service is gated behind the `chatops` profile so a default
`docker compose up` doesn't fail when no Slack app is configured. To bring
it up alongside the rest of the stack:

```bash
# in repo root .env (do not commit)
SLACK_BOT_TOKEN=xoxb-…
SLACK_SIGNING_SECRET=…
AISOC_SLACK_API_TOKEN=aisoc_…           # cases:read, cases:write, alerts:read
AISOC_SLACK_ACTIONS_TOKEN=aisoc_…       # actions:write
AISOC_DEFAULT_TENANT_ID=00000000-0000-0000-0000-000000000000

docker compose --profile chatops up slack-bot
```

The bot listens on `127.0.0.1:8009` on the host (mapped to `8089` inside the
container). Point Slack's request URL at
`https://<your-tunnel>/slack/events`.

## Slack app review checklist

Before submitting to the Slack app directory (target: end of week 12 in the
buyer-value plan), confirm every box below. The manifest under
`marketplace/slack-app/manifest.json` should match this configuration
verbatim.

### App configuration

- [ ] **OAuth scopes (bot)**: `chat:write`, `commands`, `users:read`,
      `users:read.email`, `im:write`. We do not need `channels:history` —
      v1 only reacts to slash commands and interactive payloads.
- [ ] **Slash command**: `/aisoc` registered with request URL
      `https://<deployment>/slack/events`. *(Bolt's FastAPI adapter routes
      slash commands, interactive payloads, and the URL-verification
      handshake through a single endpoint — there are no separate
      `/slack/commands` or `/slack/interactive` URLs.)*
- [ ] **Interactivity & shortcuts**: enabled, request URL
      `https://<deployment>/slack/events`.
- [ ] **Event subscriptions**: enabled, request URL
      `https://<deployment>/slack/events`. No bot events are subscribed to
      for v1; the endpoint only needs to respond to `url_verification`.
- [ ] **Tokens**: bot token rotated for production; signing secret deployed
      via your secret store, not committed.

### Listing

- [ ] **Privacy policy URL** + **support contact email** populated and
      reachable.
- [ ] **App icon (512×512)** and **app description** match the marketplace
      listing copy.
- [ ] **Long description** explains the data Slack ↔ AiSOC exchanges (case
      titles, severity, host/IP identifiers in approval prompts) and that
      AiSOC stores no Slack message content beyond the audit-trail event
      noting which user approved or denied an action.

### End-to-end verification

- [ ] **Beta workspace** has run end-to-end through every slash command:
      `list`, `investigate`, `explain`, `isolate`, `block`, `help`.
- [ ] **Approval flow** validated by a real analyst: both *Approve* and
      *Deny* paths produce the expected audit-trail entry on the underlying
      case in `services/actions`.
- [ ] **Failure modes** verified — invalid case ID, missing argument,
      backend timeout — all produce ephemeral error responses with no stack
      traces leaked to Slack.
- [ ] **Test note** in the review submission documents the demo workspace
      credentials and a reproducible scenario reviewers can run.

### Infra

- [ ] Public Slack request URL terminates TLS at the edge (`tryaisoc.com`
      ingress / Cloudflare) before reaching the bot.
- [ ] Health check at `/health` is wired into the deployment platform's
      probe (Fly.io / k8s) — review will not block on this, but production
      alerting depends on it.
- [ ] `SLACK_SIGNING_SECRET` is **set** in the deployed environment. The
      bot intentionally allows an empty secret in tests; a missing secret
      in prod logs a `slack_signing_secret_missing` warning at boot but
      does not crash, so deployment dashboards must surface that warning
      explicitly.

## Tests

```bash
poetry run pytest
```

Unit tests cover Block Kit builders, the AiSOC HTTP clients (with `respx`
mocks), command parsing, and approve/deny action handlers. They do not call
the real Slack API.
