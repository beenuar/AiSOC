---
sidebar_position: 9
title: Notifications & alerting
description: All the ways AiSOC notifies humans — Slack ChatOps, Web Push to the responder PWA, email/webhook tickets, and honeytoken first-touch alerts — and how to configure each one.
---

# Notifications and alerting

AiSOC has multiple **outbound notification surfaces**, each tuned for a
different kind of human-in-the-loop moment. This page is the one place that
explains what they are, when each fires, and what you need to set in your
environment to make them work.

## At a glance

| Surface | Who sees it | Triggered by | Service |
|---|---|---|---|
| **Web Push** (PWA) | On-call responder on a phone/desktop | P0 alerts, agent approvals, on-call hand-off | `services/realtime` |
| **Slack ChatOps** | Whole `#security-alerts` channel | Playbook `notify_slack` action, slash commands | `services/slack-bot` |
| **Slack/Teams verification prompt** | A specific user (the affected account) | `chatops.verify` action in a playbook | `services/actions` |
| **Ticketing** (Jira / ServiceNow / PagerDuty) | The ITSM queue | Playbook `create_ticket` action | `services/actions` |
| **Honeytoken webhook** | Whatever URL you point it at | A honeytoken being touched | `services/honeytokens` |
| **Connector-freshness email/webhook** | Tenant owner | A connector going stale | `services/api` |

All of these speak the same operational principle: **the system sends, the
human decides**. AiSOC never auto-resolves an incident on the back of a
notification reply unless the explicit `chatops.verify` flow has been wired
up and the user clicks **Yes, that was me**.

---

## 1. Web Push to the responder PWA

The mobile responder PWA lives at `apps/web` and is delivered by `services/realtime`. When a P0 fires, an agent needs an approval, or you snooze yourself off the on-call rotation, the realtime service fans out a [Web Push](https://www.w3.org/TR/push-api/) notification to every registered subscription for the target user / tenant / topic.

**How to enable it**

1. Generate a VAPID keypair once per environment:
   ```bash
   pnpm dlx web-push generate-vapid-keys
   ```
2. Set three environment variables on the realtime service:

   | Variable | Required | Notes |
   |---|---|---|
   | `VAPID_PUBLIC_KEY` | yes | URL-safe base64. Also exposed via `GET /api/v1/push/public-key` so the PWA can subscribe. |
   | `VAPID_PRIVATE_KEY` | yes | URL-safe base64. **Never** ship this to the browser. |
   | `VAPID_SUBJECT` | yes | Contact URL or `mailto:` — required by the Push spec. |

3. Set the gateway → realtime hop on the API service:

   | Variable | Required | Notes |
   |---|---|---|
   | `REALTIME_BASE_URL` | yes | e.g. `http://realtime:8086` in a Compose / k8s setup. |
   | `REALTIME_INTERNAL_TOKEN` | recommended | Shared secret stamped on every proxied call as `X-AiSOC-Internal-Token`. |

4. The PWA then calls four gateway endpoints (mounted under `/api/v1/push/*`):

   - `GET /public-key` — fetched once on service-worker install.
   - `POST /subscribe` — body is the browser `PushSubscription`; subject to the standard `AuthUser` dependency.
   - `POST /unsubscribe` — body `{ "endpoint": "..." }`.
   - `POST /test` — sends a single test notification to the calling user's devices, used by the PWA settings screen.

**Storage**

Subscriptions are stored in Redis with a 90-day TTL, keyed by tenant, user, and topic:

```
aisoc:push:sub:<id>                 → JSON SubscriptionRecord
aisoc:push:tenant:<tenant_id>       → SET of subscription ids
aisoc:push:user:<tenant>:<user_id>  → SET of subscription ids
aisoc:push:topic:<tenant>:<topic>   → SET of subscription ids
```

That layout is what lets a single `PushManager.sendToTarget(...)` call fan out to (a) a whole tenant on a P0 alert, (b) just the on-call user for an approval request, or (c) everyone subscribed to a topic such as `p0_alert`, `agent_approval`, or `oncall_handoff`.

**Topics shipped by default**

| Topic | Sender | Meaning |
|---|---|---|
| `p0_alert` | alert-fusion | A new P0 / high-severity alert was just produced. |
| `agent_approval` | agents | An LLM-initiated action is waiting on a human. |
| `oncall_handoff` | api (oncall endpoints) | The on-call schedule rolled over. |

If push delivery returns `404` or `410` (subscription expired or removed by the browser), the realtime service evicts the subscription from Redis automatically — the next `/subscribe` call from the PWA replaces it.

---

## 2. Slack ChatOps (`/aisoc`)

`services/slack-bot` is a thin Bolt-for-Python adapter. It owns no security state — every command is just a `httpx` call back to `services/api` or `services/actions` using a service-scoped `aisoc_*` API key.

**Slash commands**

| Command | Behaviour |
|---|---|
| `/aisoc list` | Top 10 open cases as severity-coloured Block Kit cards. |
| `/aisoc investigate <case>` | Fires an investigation run for the case. |
| `/aisoc explain <case>` | Pulls the per-case auto-summary. |
| `/aisoc isolate <host>` | Submits an `isolate_host` action — gated, posts an Approve / Deny card. |
| `/aisoc block <ip>` | Submits a `block_ip` action — gated, posts an Approve / Deny card. |
| `/aisoc help` | Inline command reference. |

**Required environment**

| Variable | Notes |
|---|---|
| `SLACK_BOT_TOKEN` | `xoxb-…` bot user OAuth token. |
| `SLACK_SIGNING_SECRET` | Used by Bolt to verify Slack request signatures. |
| `AISOC_API_BASE_URL` | e.g. `http://aisoc-api:8000`. |
| `AISOC_ACTIONS_BASE_URL` | e.g. `http://aisoc-actions:8085`. |
| `AISOC_API_SERVICE_TOKEN` | API key with `cases:read,cases:write,alerts:read`. |
| `AISOC_ACTIONS_SERVICE_TOKEN` | API key with `actions:write` (or shared key). |
| `AISOC_DEFAULT_TENANT_ID` | UUID of the tenant Slack actions belong to. |
| `AISOC_WEB_BASE_URL` | Optional. Public web URL used for deep-linked cards. Default `https://app.tryaisoc.com`. |

Slack tokens **must** come from your secret store (Doppler / Vault / k8s Secret). `pnpm preflight` fails the build if it spots a Slack token in tracked files.

---

## 3. Slack `notify_slack` from a playbook

The `notify_slack` action executor is the simplest possible Slack surface: a one-shot incoming-webhook POST. It does not require the Slack bot to be running.

```yaml
# playbooks/auto-isolate-on-p0.yaml
steps:
  - id: notify
    type: notify_slack
    parameters:
      webhook_url: "https://hooks.slack.com/services/..."
      channel: "#security-alerts"
      message: |
        AiSOC isolated host {{ context.host }} after P0 alert {{ context.alert_id }}.
```

Implementation: [`services/actions/app/executors/notification.py`](https://github.com/beenuar/AiSOC/blob/main/services/actions/app/executors/notification.py).

Failure mode is non-fatal but visible: if the webhook returns non-2xx the executor returns `ActionStatus.FAILED` with the underlying error string, the playbook step is marked failed, and the rest of the playbook runs as authored (typically with the failure path branching to `escalate_to_human`).

---

## 4. ChatOps user-verification (Slack / Teams)

`chatops.verify` is the "is this you?" prompt used by impossible-travel, compromised-account, and OAuth-grant playbooks. It is not just a notification — it is an interactive callback flow.

**Flow**

1. The executor mints **three** HMAC-signed callback tokens: `acknowledge`, `deny`, `escalate`.
2. Each token expires after `AISOC_CHATOPS_TIMEOUT_SECONDS` (default 30 minutes) and carries the action, case, tenant, user reference, and choice.
3. A Block Kit message (Slack) or Connector Card (Teams) is posted with three buttons.
4. The action returns `ActionStatus.RUNNING` — the playbook is now waiting on a human reply, it is not blocked on the request loop.
5. The user clicks a button → callback hits `services/actions` → the case timeline gets a `chatops.verify.<choice>` event → the playbook resumes on the chosen branch.

**Required environment**

| Variable | Notes |
|---|---|
| `AISOC_FEATURE_CHATOPS_VERIFY=1` | Feature flag. The executor returns `FAILED` (not silently no-ops) if it is off, so misconfiguration is loud. |
| `AISOC_ACTIONS_PUBLIC_URL` | Public URL the user's browser will be redirected to when they click a button. |
| `AISOC_CHATOPS_HMAC_SECRET` | Used to sign and verify the three per-choice tokens. |
| `AISOC_CHATOPS_TIMEOUT_SECONDS` | Optional. Default `1800`. |

The Slack/Teams transport credentials themselves are stored in the credential vault per-tenant (see [Credentials](./credentials)) — the executor reads them out at run-time, not from environment variables, so a single deployment can serve multiple tenants with different Slack workspaces.

---

## 5. Tickets (`create_ticket`)

The `create_ticket` action executor is the canonical hand-off into your ITSM tool. **As of this release the in-tree executor is intentionally simulated** — it returns a `SIM-TICKET-<id>` and a "plug in Jira / ServiceNow / PagerDuty to enable live execution" note. Two ways to make it real:

1. **Plugin path (recommended).** Ship a [Plugin SDK](../plugins/overview) plugin that registers a `LiveActionExecutor` for `(vendor_id="jira", capability="create_ticket")` (or ServiceNow / PagerDuty). The agent layer will pick it up automatically through the [live actions interface](../concepts/live-actions).
2. **In-tree path.** Replace `CreateTicketExecutor.execute` in `services/actions/app/executors/notification.py` with a real REST call. This is fine for one tenant and one ITSM tool, but every additional vendor pushes the codebase wider — the plugin path scales.

Either way, the playbook YAML is unchanged:

```yaml
- id: ticket
  type: create_ticket
  parameters:
    system: jira          # or servicenow, pagerduty, ...
    project: SEC
    priority: P1
    summary: "{{ context.alert.title }}"
    description: "{{ context.alert.summary }}"
```

---

## 6. Honeytoken first-touch webhook

When a honeytoken is touched (`honeytoken.triggered`), `services/honeytokens` posts a signed JSON payload to `settings.alert_webhook_url` *and* feeds the same event into the alert-fusion pipeline. The webhook is the **first-touch** path so you get paged even if the rest of AiSOC is degraded.

**Payload**

```json
{
  "event": "honeytoken.triggered",
  "honeytoken_id": "…",
  "tenant_id": "…",
  "token_type": "aws_iam",
  "token_name": "billing-readonly",
  "trigger_id": "…",
  "source_ip": "203.0.113.42",
  "triggered_at": "2026-05-12T18:00:00Z"
}
```

**Required environment**

| Variable | Notes |
|---|---|
| `ALERT_WEBHOOK_URL` | Where to POST the JSON payload. Empty string disables outbound alerting (the in-band timeline event is still written). |
| `ALERT_WEBHOOK_SECRET` | If set, the executor signs the body with HMAC-SHA256 and sends the digest as `X-AiSOC-Signature: sha256=<hex>`. |

Verify the signature on the receiver side with:

```python
import hmac, hashlib
expected = hmac.new(secret.encode(), request.body, hashlib.sha256).hexdigest()
assert hmac.compare_digest(expected, request.headers["X-AiSOC-Signature"].split("=", 1)[1])
```

---

## 7. Connector-freshness alerts

`services/api/app/services/connector_freshness.py` runs on a schedule and flips a connector's status to `stale` when it has not heartbeat'd within its configured window. The status change is visible in the web UI, the `/api/v1/connectors` endpoint, and (if you have the realtime service wired) is also pushed to the responder PWA on the `connector_health` topic.

There is no extra config — `connector_health` is a built-in topic that any subscribed device receives automatically.

---

## Suppression and quiet hours

You generally do **not** want to suppress notifications inside AiSOC itself — silencing is something your paging tool (PagerDuty, Opsgenie, native Slack DND, the PWA's per-user snooze) is much better at. AiSOC offers two narrow controls:

- **Per-user on-call status**. The `/api/v1/oncall` endpoint lets a responder mark themselves `available | busy | offline | snoozed`. The realtime service skips Web Push fan-out to anyone in `offline` or `snoozed`.
- **Slack channel routing**. `notify_slack` always honors the `channel` parameter — point overnight playbooks at `#security-alerts-overnight` rather than trying to suppress the daytime channel.

Anything more sophisticated (rotation logic, escalation policies, holiday calendars) belongs in the on-call tool that owns those concepts. AiSOC ships *to* PagerDuty / Opsgenie, not around them.

---

## Testing your wiring

The fastest end-to-end smoke test, in order of how much you have to set up:

1. **Web Push.** Open the PWA → Settings → Notifications → **Send test**. Hits `POST /api/v1/push/test`, which invokes `pushManager.sendToTarget(...)` on every registered device for the calling user. If you do not see a notification within ~5s, check the realtime logs for `web-push` errors — typically a stale subscription, a wrong VAPID key, or a missing `VAPID_SUBJECT`.
2. **Slack `notify_slack`.** Curl the action directly:
   ```bash
   curl -X POST "$AISOC_ACTIONS_BASE_URL/api/v1/actions" \
     -H "Authorization: Bearer $AISOC_ACTIONS_SERVICE_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "action_type": "notify_slack",
       "parameters": {
         "webhook_url": "'"$SLACK_TEST_WEBHOOK"'",
         "channel": "#aisoc-test",
         "message": "hello from AiSOC"
       },
       "rationale": "manual smoke test"
     }'
   ```
3. **ChatOps verify.** Run any playbook that includes a `chatops.verify` step against your own user, then click one of the three buttons. The case timeline should show a `chatops.verify.prompted` event followed by `chatops.verify.<choice>`.
4. **Honeytoken webhook.** `pnpm aisoc honeytokens trigger <token-id>` (or hit the trigger URL in your browser). The configured webhook should receive the JSON payload within a couple of seconds.

---

## Related

- [Live Actions](../concepts/live-actions) — how the action substrate that powers `notify_slack`, `create_ticket`, and `chatops.verify` works under the hood.
- [Playbooks](../concepts/playbooks) — the YAML grammar that wires these notification actions into a response flow.
- [Credential vault & secrets](./credentials) — where Slack / Teams / Jira credentials are stored at rest.
