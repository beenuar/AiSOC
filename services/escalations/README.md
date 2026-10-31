# escalations — ack-clock escalation bridge

Teams escalations for cases nobody has acknowledged, until the native
outbound-webhook emitters are wired (`services/api/app/services/
outbound_webhooks.py::enqueue_event` currently has no production callers).

Watches the platform's own ack clock (`aisoc_cases.acknowledged_at`):

- **CRITICAL** unacknowledged >= 30 min -> immediate card, re-nag every 4 h,
  max 3 sends per case.
- **HIGH** unacknowledged -> one digest per day (08:00 UTC) plus a pipeline
  health line (failed investigations / dead-letters, last 24 h).

Dedup + nag state persists in the `escalation-state` volume; restarts never
double-send. All thresholds are env-tunable (`ESC_*`, see docker-compose.yml).

Two semantics to know before enabling it:

- **What stops the clock:** a case counts as acknowledged only when
  `aisoc_cases.acknowledged_at` is written — today that is the console's
  acknowledge action and joining the case's war room. Editing, assigning or
  moving a case along the status ladder does **not** stop the clock; an
  actively-investigated CRITICAL that nobody acknowledged still escalates (up
  to the nag cap). That is the point of an ack clock, stated here so nobody
  expects otherwise.
- **The sweep is deployment-wide.** Every tenant's unacknowledged cases
  escalate to the one configured webhook — this is a deployment-level pager,
  not per-tenant notification (that is the native outbound-webhook
  subsystem's job, which this service bridges until its emitters are wired,
  and into which it retires). On a multi-tenant deployment, case titles from
  every tenant reach that one channel: enable this only where the channel's
  audience is cleared to see all tenants. The cross-tenant reads are recorded
  with this reasoning on `scripts/check_tenant_query_predicates.py`'s
  ratchet.

## Run

    docker compose --profile escalations up -d

The webhook target is any JSON POST endpoint that renders an Adaptive Card
(payload fields: `severity`, `title`, `summary`, `case_id`, `opened_at`,
`url`). The documented setup uses a Power Automate "Post card in a chat or
channel" flow; note that that action requires the bare Adaptive Card object,
not a `message`/`attachments` envelope.

## Tests

    python -m pytest tests/ -q
