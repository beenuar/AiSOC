---
title: AI / LLM Usage Audit
description: Ingest OpenAI + Anthropic organization audit logs into AiSOC to govern AI adoption.
---

# AI / LLM Usage Audit

The **AI / LLM Usage Audit** connector (`llm_usage`, category `saas`) pulls
organization audit logs from OpenAI (`/v1/organization/audit_logs`) or Anthropic
and normalizes each into the AiSOC alert shape, mapping the event type onto the
five-tier severity ladder (`info | low | medium | high | critical`).

It is the governance surface for AI adoption — who created an API key, who was
granted owner, was audit logging or MFA turned off, was a project deleted — and
pairs with the built-in `llm-*` detection rules, which fire on the emitted
`event_type` (for example `openai.api_key.created`, `anthropic.member.added`).

## What you get

| Event family | Example `event_type` | Severity floor |
| --- | --- | --- |
| API key creation | `openai.api_key.created` | high |
| Owner/role grant | `openai.member.added` (role=owner) | high |
| Logging disabled | `openai.logging.setting.updated` (disabled) | critical |
| MFA disabled | `openai.mfa.*` (disabled) | critical |
| Project delete | `openai.project.archived` | medium |

## Setup

1. In **Connectors -> Add connector**, choose **AI / LLM Usage Audit**.
2. Pick the **provider** (OpenAI or Anthropic) and paste an **admin/audit-scoped API key** (stored in the credential vault, never in plaintext).
3. Click **Test connection**, then **Save**. The scheduler polls the audit log on the default cadence.

Events flow through ingest → Kafka → fusion, where the `llm-*` detections fire
and matching alerts are auto-triaged (copilot).
