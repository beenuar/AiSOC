# AiSOC Teams Bot

ChatOps surface for Microsoft Teams. Mirrors the Slack bot's interactive
approval flow using Adaptive Cards instead of Block Kit.

## What's here today

| Module                                      | Purpose                                                                   |
| ------------------------------------------- | ------------------------------------------------------------------------- |
| `app/cards.py`                              | Adaptive Card factories — case card, approval prompt, decision card.      |
| `app/callbacks.py`                          | HMAC-verified callback handler for Approve / Deny / Need-Info `Action.Submit`. |
| `app/main.py`                               | FastAPI entrypoint with the `/teams/messages` webhook.                    |
| `app/services/aisoc_clients.py`             | Re-exports the Slack bot's HTTP client (one source of truth).             |

The bot intentionally mirrors `services/slack-bot/` directory-for-directory
so an analyst reading one repo finds the equivalent code in the other.
Both bots share:

* `services/slack-bot/app/services/hmac_verify.py` — HMAC primitive.
* `services/slack-bot/app/services/approval_audit.py` — audit sink.
* `services/slack-bot/app/services/approval_timeout.py` — timeout scheduler.

…because the only thing Teams-specific in T3.6 is the Adaptive Card
JSON shape.

## Adaptive Card payload

Approve / Deny / Need-Info buttons are `Action.Submit` actions whose
`data` field carries:

```json
{
  "verb": "approve",
  "action_id": "<uuid>",
  "case_id": "<uuid>",
  "issued_at": 1700000000,
  "signature": "<hex hmac-sha256>"
}
```

`signature` is `HMAC-SHA256(secret, "<verb>|<action_id>|<case_id>|<issued_at>")`.
The callback handler rejects any payload whose signature is missing,
malformed, or older than `AISOC_TEAMS_CALLBACK_MAX_AGE_SECONDS` (default
600 — the human's decision window, well under Teams' own card TTL).

## Configuration

| Variable                                | Required | Description                                              |
| --------------------------------------- | -------- | -------------------------------------------------------- |
| `AISOC_TEAMS_APP_ID`                    | not read | Declared for the Bot Framework registration, but no code in this service reads it today. |
| `AISOC_TEAMS_APP_PASSWORD`              | not read | Same — the outbound Bot Framework client is not wired yet. |
| `AISOC_TEAMS_CALLBACK_SECRET`           | yes      | Shared HMAC secret used to sign + verify card payloads (`app/main.py`). |
| `AISOC_TEAMS_CALLBACK_MAX_AGE_SECONDS`  | no       | Replay window for signed payloads. Default `600` (`app/callbacks.py`). |
| `AISOC_TEAMS_HMAC_MODULE_PATH`          | no       | Test hook: redirects the HMAC signer module lookup (`app/services/hmac_signer.py`). |
| `AISOC_API_BASE_URL`                    | yes      | `services/api` base URL — same env var as the Slack bot. |
| `AISOC_ACTIONS_BASE_URL`                | yes      | `services/actions` base URL.                             |
| `AISOC_API_SERVICE_TOKEN`               | yes      | API key with `cases:read,cases:write`.                   |
| `AISOC_ACTIONS_SERVICE_TOKEN`           | yes      | API key with `actions:write`.                            |
| `AISOC_DEFAULT_TENANT_ID`               | yes      | Tenant UUID this Teams tenant maps to.                   |

## Tests

```bash
poetry run pytest tests/
```

Coverage:

* `tests/test_cards.py` — Adaptive Card factory output shape.
* `tests/test_callbacks_approver.py` — HMAC verify, replay rejection, audit
  row, upstream-failure path.
