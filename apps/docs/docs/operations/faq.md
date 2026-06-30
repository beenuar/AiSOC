---
sidebar_position: 5
title: FAQ
description: Frequently asked questions about AiSOC — what it is, how it deploys, how the agent and detection content work, and how teams actually adopt it.
---

# Frequently Asked Questions

The questions on this page are the ones that come up most often in the [adoption consultation](./adoption-questions) — both from security leaders evaluating AiSOC and from analysts running it day-to-day. Skim the section headers; jump in.

---

## What AiSOC is

### What does AiSOC actually do?

AiSOC is an open-source AI Security Operations Center. It does three things:

1. **Pulls security signal in** from your existing stack — EDR, SIEM, identity providers, cloud audit logs, SaaS, network — through a click-and-connect [connector catalog](../connectors/).
2. **Runs detection, fusion, and AI investigation** on that signal — Sigma-shaped detection rules, ML-based fusion, a LangGraph multi-agent investigation that builds a case end-to-end with full evidence and reasoning recorded to a replayable [Investigation Ledger](../concepts/cases).
3. **Drives response with explicit human boundaries** — playbooks, ChatOps approvals, blast-radius gates, and an autonomy policy you control per action class.

### How is this different from "yet another AI SIEM"?

Three things.

First, **the agent is auditable**. Every prompt, response, tool call, evidence citation, and decision is recorded step-by-step on the case. You can re-watch any investigation. AI that won't show its work is a non-starter for SOC.

Second, **the substrate is gated by a public, reproducible eval harness on every PR**. Most "AI SIEMs" claim accuracy without a way to verify it. We publish the dataset, the suites, the gates, and run them in CI on every commit. See [Benchmark](../benchmark).

Third, **everything is open source under MIT**. Self-host it, fork it, audit the code, embed it in an air-gapped network. There is no rug-pull because the only license is permissive.

### Is AiSOC a SIEM, a SOAR, or an XDR?

AiSOC is a "what comes after" — it sits on top of your existing SIEM/EDR/cloud stack and replaces the analyst's workflow, not the data lake.

That said, it carries the building blocks: an OpenSearch + ClickHouse search tier, a Kafka spine, a fusion service, a detection engine, a playbook engine, an entity graph, an audit trail, a UEBA service, honeytokens, and a purple-team feedback loop. If you want to swap your SIEM for it, you can. Most teams start by pointing AiSOC *at* their existing SIEM.

### Who is AiSOC for?

In rough order of best-fit:

- **Mid-market security teams** drowning in alerts they can't triage, with one or two analysts on rotation.
- **MSSPs** running a SOC for multiple customers — see the multi-tenant + parent-tenant console.
- **Internal SOCs at regulated enterprises** that need an auditable AI loop with hard autonomy boundaries.
- **Open-source security engineers** who want a working substrate to build their own detection tooling on.

If you have one analyst handling 50 alerts a day with no automation, AiSOC will give you back time. If you have a 30-person tier-3 SOC with mature SOAR, AiSOC is a force multiplier on your tier-1 / tier-2.

---

## Deployment & operations

### Can AiSOC run on my laptop?

Yes. `pnpm aisoc:demo` brings up a slim demo stack from prebuilt images in 3-4 minutes on a warm Docker daemon. The full development stack — every microservice plus ClickHouse, OpenSearch, Neo4j, Qdrant — needs ~12 GB RAM and a few minutes more. See [Quickstart](../quickstart).

### Can AiSOC run air-gapped?

Yes. The air-gap deployment pre-stages every container image, every dependency, every rule pack, and the bundled MITRE ATT&CK STIX file. You can run it on a network with zero outbound internet. Trade-offs (hosted OAuth flows, external threat intel, LLM API providers) are documented in [Air-gap operations](./airgap).

### What does it cost to run?

The AiSOC code is free (MIT). Real costs are:

| Component | Driver |
|---|---|
| LLM inference | The biggest variable. The autonomous investigator and copilot call OpenAI / Anthropic per case. Self-host a model (Llama, Mistral) and the cost goes to GPU time. |
| Storage | Postgres + ClickHouse + OpenSearch + Neo4j + Qdrant. ~50 GB / month / 1k EPS at default retention. |
| Compute | All services together fit in ~6-8 CPU cores and ~16-24 GB RAM under typical mid-market load. |
| Outbound API calls | Connector polling, threat-intel feeds, ChatOps webhooks. Negligible. |

Most of our public deployments spend more on LLM tokens than on infrastructure. Token costs are visible per-case in the [Investigation Cost Telemetry](../concepts/capabilities#agent-intelligence-2026-h2).

### What are the system requirements?

Minimum, single-host Docker Compose:

| Resource | Minimum |
|---|---|
| CPU | 4 cores |
| RAM | 12 GB (16 GB recommended) |
| Disk | 50 GB SSD |
| OS | Linux x86_64 (Ubuntu 22.04+, RHEL 9+) or Docker Desktop on macOS / Windows |

Production: scale `api`, `agents`, `fusion`, `realtime`, and `ingest` horizontally. Each is stateless. Postgres + Kafka + OpenSearch are the stateful tier — clustered as you'd expect. See [Kubernetes deployment](../deployment/kubernetes).

### How does AiSOC scale?

Horizontally where it matters. The hot path:

- `ingest` (Go) — 4 workers handle ~5k EPS per replica. Add replicas as event volume grows.
- `fusion` — the most CPU-bound service in steady state. Add replicas before everything else.
- `agents` — each case is one agent run. Replicas split case load across a pool.

Postgres and Kafka are the natural ceiling; both scale predictably under standard tuning.

---

## The AI agent

### Which model does the agent use?

Whichever you configure. `OPENAI_MODEL` (and per-agent overrides) is read at startup. Default is `gpt-4o`. Anthropic Claude works via the agents service's provider abstraction. Self-hosted Llama / Mistral works via OpenAI-compatible endpoints (vLLM, Ollama, llama.cpp server).

### Will the agent do things without my permission?

Only what your **autonomy policy** allows. The policy is per-action and per-tenant: every potentially impactful tool (`endpoint.isolate`, `identity.disable`, `network.block`, `email.purge`) maps to one of `auto / review / escalate / reject`. The default for every destructive action is `review` — analyst must approve in chat or in the UI before the tool runs.

You can also enforce **blast-radius gates** ("never isolate more than 5 hosts in 1 hour") and a **panic stop** that puts the agent into pure-advisory mode globally.

### Will the agent send my data to OpenAI / Anthropic / Google?

Only what you send to the LLM. Every tool call's input and output is logged in the Investigation Ledger so you can see exactly what crossed the boundary.

For regulated environments:

- Use `Azure OpenAI` instead of OpenAI for an enterprise data-handling agreement.
- Self-host an open-weights model (Llama 3, Qwen, Mistral) — the agent works against any OpenAI-compatible endpoint.
- Or run the agent in advisory-only mode (every tool call gated to `review`) so an analyst sees exactly what would have been sent before authorizing.

### Can the agent be fooled?

Yes — and we test for it. The eval harness includes an [AI-vs-AI adversary suite](../concepts/capabilities#eval-harness--benchmarking-2026-h2) where a deterministic attacker LLM mutates incidents (synonym swap, leetspeak, zero-width injection, fragmentation) to try to flip the agent's verdict. The graceful-degradation gate requires the agent to retain ≥ 0.85 accuracy under light mutation and ≤ 0.50 *false confidence* under heavy mutation. PRs that regress this gate cannot land.

This is not a guarantee against real-world prompt injection — it's a guarantee that we measure for it on every change.

### What's the "Investigation Ledger"?

A replayable record of every step the agent took on a case: each prompt, each LLM response, each tool called with its inputs and outputs, each evidence citation. You can scrub through it like a DVR, and you can hand it to compliance.

It's also what makes the analyst-override feedback loop work — a verdict overridden by a human is written back as institutional memory so future similar alerts respect that decision. See [Capabilities → Override loop](../concepts/capabilities#agent-intelligence-2026-h2).

---

## Detection content

### Where do detection rules come from?

Three tiers:

1. **Native rules** — ~800 rules authored for AiSOC, in our Sigma-shaped YAML. Tagged `tier: stable`.
2. **Imported rules** — ~6,000 rules from SigmaHQ, Splunk Security Content, Chronicle, MITRE CAR. Each carries provenance and an upstream link. Tagged `tier: imported`.
3. **Community contributions** — rules submitted via PR or installed from the marketplace. Tagged by author and license.

All run on the same engine: native YAML over OpenSearch + ClickHouse plus YARA, KQL, EQL, and SPL via federated search.

### Can I write rules in plain English?

Yes. The NL-detection-authoring API converts an English description into Sigma YAML, runs it against historical data, shows the matches and false positives, and lets you iterate. See `/api/v1/nl-detection`.

### How does detection-as-code work here?

Every rule change goes through:

1. **Propose** — PR or `POST /api/v1/detection-proposals`.
2. **Review** — comments, requested changes.
3. **Eval-gate** — the proposal carries an eval result. Candidates that regress MITRE accuracy by ≥ 1 percentage point cannot be promoted.
4. **Promote** — `POST /api/v1/detection-proposals/{id}/promote` writes the rule to `detection_rules` and starts firing it.

This is the same loop CI runs on every PR, so the rule you ship is the rule that was scored. See [Concepts: Detections](../concepts/detections).

---

## Data, privacy, retention

### Where is my data stored?

Wherever you deploy. AiSOC is self-hosted; we don't run a hosted service that holds your security data. Inside an AiSOC deployment:

| Data class | Where |
|---|---|
| Connector credentials | Postgres `connector_instances.auth_config`, encrypted by the application-layer Fernet vault |
| Cases, alerts, audit log | Postgres |
| Raw event search | OpenSearch + ClickHouse |
| Evidence files | Object storage (configurable: S3, GCS, MinIO, local FS) |
| Vector embeddings (RAG memory) | Qdrant |
| Entity graph | Neo4j |
| Real-time push subscriptions | Redis |

### How long are events / cases retained?

By default — forever, because most AiSOC users are running on disk they own. To bound retention:

- **Raw events** in OpenSearch / ClickHouse: configurable per-tenant ILM policy.
- **Cases** in Postgres: archived to cold object storage after a configurable age, soft-deleted from the main DB.
- **Investigation Ledger**: kept as long as the case is kept. It's the audit primitive.
- **Audit log**: hash-chained, append-only. Truncating the audit log breaks the chain — by design.

### Does AiSOC handle PII?

It will *see* PII (usernames, emails, IPs, device names) by virtue of being a security tool. AiSOC:

- Never logs plaintext credentials.
- Redacts secret-typed connector fields before any log line.
- Tags PII fields in the OCSF event schema so downstream consumers can filter.
- Supports tenant-scoped data residency — a tenant's data never crosses tenant boundaries even within the same deployment.

For GDPR / CCPA workflows, the audit log surfaces every read/write of identifiable fields with the requesting user and tenant.

### Can I delete a user's data on request?

Yes. `DELETE /api/v1/identity/{user_id}/data` tombstones every alert, case, and event referencing the identity within the requesting tenant, and rewrites the audit log entries to redact the identifier (the audit chain integrity is preserved; only the indexed value is replaced with a tombstone). The action itself is recorded in the audit log.

---

## Integration & ecosystem

### Does AiSOC have an MCP server?

Yes. `@aisoc/mcp` exposes 11 Investigation Ledger tools to MCP-compatible LLM clients (Claude Desktop, Cursor, Continue, Cody) so analysts can replay agent decisions, query cases, and run detection / playbook actions directly from their IDE. See [MCP integration](../integrations/mcp).

### Are there SDKs?

Three. All three ship from this monorepo today; the npm + PyPI releases land in v8.0:

- **Python** — `pip install -e packages/sdk-py` today (`pip install aisoc-sdk` once it's on PyPI in v8.0). Async first, typed against the OpenAPI spec.
- **TypeScript** — `pnpm --filter @aisoc/sdk-ts install` today (`pnpm add @aisoc/sdk-ts` once it's on npm in v8.0). Also typed against the OpenAPI spec.
- **Go** — `go get github.com/beenuar/AiSOC/packages/sdk-go` (works today; Go modules don't need a registry hop).

All three handle auth, retries, pagination, and backoff. See [Plugin SDK overview](../plugins/overview).

### Can I write a plugin?

Yes. Plugins are signed Python or Go packages that ship one or more of: a connector, an enrichment, a detection rule, a playbook, an action. Ed25519-signed publishing through the marketplace. See [Plugin SDK](../plugins/overview).

### Does AiSOC integrate with Jira / ServiceNow?

Yes. We treat ITSM as a *projection* of AiSOC, not the source of truth — the architectural model is documented in [ITSM as projection](../architecture/itsm-as-source-of-truth). In practice that means cases mirror to ITSM with two-way status sync, and ITSM can host approval workflows that gate AiSOC actions.

---

## Project & community

### Is AiSOC really free?

The agent and the platform are MIT-licensed. There are no enterprise-edition feature flags. Hosted OAuth (planned) and a managed Cloud offering may have a paid tier in future, but the self-host package will continue to be free under MIT.

### Who maintains it?

The AiSOC community. The project is hosted at [github.com/beenuar/AiSOC](https://github.com/beenuar/AiSOC). Contribution guidelines are in [contributing/guidelines](../contributing/guidelines). Security advisories are handled privately via GitHub Security Advisories.

### How do I file a bug or feature request?

GitHub Issues. For security vulnerabilities, use a private GitHub Security Advisory — never a public issue.

### How do I contribute a connector?

[Plugin SDK → Publishing](../plugins/publishing). The short version: implement `BaseConnector` in `services/connectors/app/connectors/<name>.py`, declare a `schema()`, register the class in `_CONNECTOR_CLASSES`, ship a marketplace manifest in `plugins/<name>/plugin.yaml`, run `pnpm marketplace:sync`, open a PR.

## Related

- [Adoption consultation questions](./adoption-questions) — the structured walkthrough for security leaders
- [Quickstart](../quickstart) — get a working instance in under 5 minutes
- [Architecture](../architecture)
- [Capabilities](../concepts/capabilities)
- [Glossary](../glossary)
