---
title: Tenant skills
sidebar_label: Tenant skills
description: Teach the investigation agent what is normal in your estate, backtest it against your own closed findings, and activate it over the API.
---

# Tenant skills

A skill is your own investigation approach, written down. The built-in
strategies encode how an attack behaves in general. A skill encodes what is
true in *your* estate, which is knowledge a built-in cannot have.

When a skill matches an alert it supplies the investigation plan instead of
the built-in strategy, and its guidance reaches the triage prompt. When no
skill matches, nothing changes.

:::info There is no skill editor in the console yet

Skills are authored, backtested and activated over the API routes listed at
the bottom of this page. Nothing under `/settings` or anywhere else in the
console reads or writes them today, so what follows is a `curl` or SDK
workflow rather than a point-and-click one. An editor is on the roadmap
alongside the ones for agent definitions and MCP server registrations, which
are API-only for the same reason.

The API is shaped for that editor: `POST /validate` answers without saving so
a form can check a document as it is typed, and `GET /api/v1/tenant-skills`
returns the tool vocabulary alongside the skills so a picker can offer it.
Those are affordances waiting for a caller, not a description of a screen that
exists.
:::

## What a skill looks like

```yaml
id: finance-batch-powershell
name: Finance nightly reconciliation batch
owner: soc-leads@example.com
expires_at: 2027-01-31

match:
  techniques: [T1059.001]
  rule_ids: [rule-encoded-powershell]
  sources: [crowdstrike]
  keywords: ["svc_batch", "reconciliation"]

applies_when: >
  An encoded PowerShell alert names svc_batch on a FIN-APP host.

guidance: >
  Finance runs a nightly reconciliation batch on FIN-APP-01 through FIN-APP-06
  between 02:00 and 04:00 UTC. The job builds its command line from a config
  file, so the command line is different every night and is always encoded.

verdict_guidance: >
  In this organisation, encoded PowerShell launched by svc_batch on a FIN-APP
  host inside the batch window is a benign true positive: the rule fired
  correctly and the behaviour is sanctioned.

required_evidence:
  - The parent process is the scheduled task, not a browser or an Office application.
  - No account other than svc_batch authenticated to the host in the window.

escalate_when:
  - The host is not one of FIN-APP-01 through FIN-APP-06.
  - Any outbound connection leaves the finance VLAN.

plan:
  - List what executed on the host around the alert.
  - Establish the process lineage, which decides this alert on its own.
  - Check the account's authentication trail for the window.

expected_pivots: [process_activity, process_tree, authentication_events]
min_pivots: 2
```

### Fields the server owns

`version`, `status`, `enabled` and `tenant_id` are refused if you put them in
the document. The version is assigned on every content change so there is one
authority for what version 3 is, the status moves through the lifecycle routes
below, and the tenant comes from your credential.

### Fields you cannot leave out

| Field | Why it is required |
|---|---|
| `owner` | A skill that steers a verdict needs somebody to ask when the verdict is disputed. |
| `expires_at` | Organisational facts rot. A skill with no review date keeps steering after it stops being true, and nothing surfaces that. An expired skill is dropped by the resolver. |
| `match` | A skill with no match conditions applies to every alert in your tenant, which replaces the strategy library rather than adding to it. |
| `plan` | A skill with no plan cannot steer an investigation. |
| `expected_pivots` | Without it the run's depth cannot be graded, and an investigation cannot be told apart from a summary. |

### `expected_pivots` is validated against your tools

Every name must be a tool your agent can actually call:

- one of the built-in lake pivots (`process_activity`, `historical_execution`,
  `network_connections`, `authentication_events`, `fleet_ioc_hunt`,
  `entity_timeline`, `technique_activity`, `process_tree`, `mailbox_activity`,
  `oauth_grants`, `persistence_mechanisms`);
- one of the customer-product tools (`siem_indicator_search`,
  `edr_host_details`, `edr_host_detections`, `identity_user_activity`,
  `cloud_audit_lookup`, `endpoint_telemetry_sightings`), **and only if you have
  the product behind it connected**: the same check
  `GET /api/v1/agent-tools/backends` makes when the agent binds its toolset;
- or `mcp.<server>.<tool>` for a tool on an [MCP server](../operations/mcp-client.md)
  you have registered, **enabled**, and named on that server's allowlist.

`GET /api/v1/tenant-skills` returns the current list under `available_tools`,
so you can read the vocabulary rather than discovering it by being refused.

:::note When the check cannot be made

If AiSOC cannot reach its action registry it does not know which vendor verbs
you have. A known customer-tool name is then **accepted** and
`available_tools.customer_unknown` comes back true, because refusing would tell
you your EDR is not connected when the real answer is that a different service
was briefly down, and you would delete a correct line from your document. A
name that is not a tool at all is still refused: that is a typo, not an outage.
:::

## Lifecycle

```
draft ──backtest──▶ backtested ──activate──▶ active ──retire──▶ retired
  ▲                                              │
  └──────────────── any content edit ────────────┘
```

**An edit un-backtests the skill.** Saving new text bumps the version, drops
the skill back to `draft` and detaches the reports. A backtest is a statement
about specific text, and carrying it across an edit is how a report comes to
describe something nobody is running. Reformatting that does not change the
parsed body keeps the version and the backtest.

**Activation requires a backtest of the version being activated**, and both
halves of it. The route refuses with a 409 naming which of these is wrong:

- no backtest attached;
- the backtest graded a different version;
- the skill has already expired;
- the skill is already active;
- one of the two attached runs is missing, still going, or failed;
- the window those runs graded holds no alert this skill matches.

The same rule is written into a database CHECK constraint, so it holds even
against a direct fix-up, and `scripts/check_tenant_skill_contract.py` fails
the build if it disappears from either place or from this page.

The last two refusals exist because the first four can all be satisfied by a
backtest that measured nothing. Two attached ids say a report exists, not that
it says anything: both runs can have crashed, or can have graded four hundred
alerts of which none is one this skill applies to. Activation therefore opens
both runs and compares them over the alerts the skill's `match` block selects.
What it requires is that the comparison exists, never that it is favourable: a
threshold on the number would be a target to tune a skill against, and an
organisational fact that happens not to move last quarter's verdicts is still
true about your estate.

## Backtesting

`POST /api/v1/tenant-skills/{skill_id}/backtest` starts **two**
[replay evaluations](../evaluation/replay.md) over the same window, seed and
resample count:

- **baseline**: your other active skills, without this one;
- **candidate**: those plus this one.

Read them side by side at `GET /api/v1/evaluations/replay/{id}`. The only
difference between the two reports is the skill.

### Compare them over the alerts the skill matches, not over the headlines

A skill applies to a shape of alert, usually a handful out of hundreds. Both
runs cover the same window, so the difference between their two headline
figures is an average over every alert in it, most of which the skill never
touched.

Four matched alerts in twenty: a skill that corrects every one of them moves
the headline by 0.20, and a skill that breaks every one of them moves it by
-0.20. Across a few hundred findings neither is visible at all. So a headline
that barely moved is not evidence that the skill changed little; it is mostly
evidence that the window was bigger than the skill. The figure that describes
the skill is the one over the alerts it selects, and that is the comparison
activation makes.

### A skill only reaches triage on the LLM path

Guidance is read, matched and put into the prompt only when the alert takes
the LLM path. A tenant with no model configured, a deployment started with
`AISOC_DETERMINISTIC=1`, and an alert the cost governor answered from its
deduplication cache all skip it.

So a backtest run under any of those produces two identical reports, and that
result means **the skill was never applied** rather than the skill was applied
and changed nothing. Those are different facts and only one of them is about
your skill. Check that the candidate run's decisions carry a model-backed tier
before reading a flat result as a verdict on the text.

:::caution What a backtest number does and does not say

The skill is applied to a window that closed before it was written. That is
what a backtest is, and it means the author may have seen the very alerts
being graded. The replay report names the skill under `skills_under_test` in
its method section and carries the caveat there.

Read the result as a measurement against that window, not as a forecast of
accuracy on new alerts. If you want the second, activate the skill and run an
ordinary replay over a later window: skills are then frozen at the split point
like every other context source, so only guidance that was genuinely active
during the window contributes.
:::

## What gets recorded

Every investigation a skill guides records `skill_id` and `version`, on the
triage verdict's confidence basis and on the investigation's depth record.
`GET /api/v1/tenant-skills/{skill_id}/versions` turns that pair back into the
exact text that was in force, along with who authored it, the backtest that
graded it and when it was activated.

That read is why `DELETE` is the wrong way to stop using a working skill: it
removes the version history, and the history is what explains verdicts the
skill already steered. Use `POST /{skill_id}/retire`, which keeps it.

## Routes

| Route | Permission | Notes |
|---|---|---|
| `GET /api/v1/tenant-skills` | `settings:read` | With `available_tools`. |
| `GET /api/v1/tenant-skills/{skill_id}` | `settings:read` | |
| `GET /api/v1/tenant-skills/{skill_id}/versions` | `settings:read` | Resolves a recorded `skill@vN`. |
| `POST /api/v1/tenant-skills/validate` | `settings:read` | Returns `valid: false` with the message rather than a 422, so a caller can check a half-typed document without a failed request. |
| `PUT /api/v1/tenant-skills` | `settings:write` | The id is inside the document. |
| `POST /api/v1/tenant-skills/{skill_id}/backtest` | `connectors:write` | Reaches your SIEM with stored credentials, so the same bar as testing a connector. |
| `POST /api/v1/tenant-skills/{skill_id}/activate` | `settings:write` | |
| `POST /api/v1/tenant-skills/{skill_id}/retire` | `settings:write` | Keeps the history. |
| `DELETE /api/v1/tenant-skills/{skill_id}` | `settings:write` | Removes the history too. |

## Turning it off

`AISOC_TENANT_SKILLS_ENABLED=0` on the agents service stops skills being read
at all. The agent falls back to the built-in strategy library, which is the
behaviour before this feature existed.
