---
sidebar_position: 3
title: Azure Activity Logs
description: Subscription-scope control-plane events from Azure Resource Manager into AiSOC — IAM grants, policy edits, resource changes.
---

# Azure Activity Logs

The Azure Activity connector streams **subscription-scope control-plane events** from the Azure Resource Manager (ARM) Activity Log into AiSOC. This is your primary signal for cloud-plane attack patterns: privilege escalation via `roleAssignments/write`, defense evasion via policy or NSG deletes, and high-blast-radius operations like `Microsoft.Authorization/roleDefinitions/write`.

## What you get

| Source | API | Scope |
|---|---|---|
| Activity Log entries | `Microsoft.Insights/eventtypes/management/values` | One Azure subscription |

Events arrive normalized with `category: cloud` and a `resource_id` pulled from the ARM operation target.

## Prerequisites

- An **Azure AD app registration** (you can reuse the one from the [Entra connector](/docs/connectors/azure-entra) — they will live alongside each other).
- The app must have **Reader** RBAC at the **subscription** scope (so it can read the activity log). Reader is enough; do not grant Contributor.
- The tenant ID, client ID, client secret, **and** the subscription ID you want to monitor.

## Setup walkthrough

### 1. Reuse or create an app registration

If you already created one for Entra, skip to step 2. Otherwise follow the [Entra walkthrough §1-3](/docs/connectors/azure-entra#1-register-the-app) — the same app can power Entra, Activity, Defender, and M365 simultaneously.

### 2. Grant Reader on the subscription

1. Azure portal → **Subscriptions → &lt;your subscription&gt; → Access control (IAM) → Add → Add role assignment**.
2. Role: **Reader**.
3. Members: **User, group, or service principal** → search for the app registration's display name.
4. Save.

### 3. Copy the subscription ID

In the Subscription Overview blade, copy the **Subscription ID** (a GUID).

### 4. Add the connector in AiSOC

1. AiSOC console → **Connectors → Add connector → Azure Activity Logs**.
2. Fill in `tenant_id`, `client_id`, `client_secret`, and `subscription_id`.
3. **Test connection** → calls the Activity Log API and asks for at most 1 entry to validate auth and scope.
4. **Save**.

## Polling details

- Default interval: **300 seconds**.
- Each poll requests `eventTimestamp ge {since}` so we never pull more than the last interval.
- ARM endpoint: `https://management.azure.com/subscriptions/{sub}/providers/Microsoft.Insights/eventtypes/management/values?api-version=2015-04-01`.
- OAuth scope used: `https://management.azure.com/.default`. (Note: this is **not** the Microsoft Graph scope — it's the ARM resource.)

## Severity heuristics — high-blast-radius detection

`normalize()` flags operations whose **resource/verb tail** matches a high-blast-radius pattern:

| Pattern | AiSOC severity |
|---|---|
| `microsoft.authorization/roleassignments/write` | `high` (privilege grant — T1098.003 territory) |
| `microsoft.authorization/roledefinitions/write` | `high` (custom role with elevated rights) |
| `*/delete` on `policyAssignments`, `firewallRules`, `networkSecurityGroups`, `keyVaults` | `high` |
| `*/deallocate`, `*/poweroff` on a VM in active use | `medium` |
| Any `failed` write at the control plane | `medium` |
| Routine reads (`*/read`) | dropped |

The exact match list lives in `_HIGH_BLAST_RADIUS_VERBS` inside `services/connectors/app/connectors/azure_activity.py`. Add a detection rule rather than editing that tuple unless you are upstreaming the change.

## Troubleshooting

**`InvalidAuthenticationToken` / `AuthorizationFailed`** — most often the app does not have Reader at the subscription scope. Re-check the role assignment.

**`SubscriptionNotFound`** — the GUID is for a subscription this app cannot see. Make sure you copied it from the same tenant the app is registered in.

**`No Activity Log data returned`** — Activity Log only retains 90 days, but more importantly only flows from operations *attempted* during the polling window. A new connector on a quiet subscription will log polls with `events_added: 0` until something happens.

## Related

- [Microsoft Entra ID](/docs/connectors/azure-entra) — identity-plane events that pair with these control-plane events.
- [Microsoft Defender (XDR)](/docs/connectors/azure-defender) — runtime alerts that cross-reference these activity events.
