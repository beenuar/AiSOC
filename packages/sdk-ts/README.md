# @aisoc/sdk

[![npm version](https://img.shields.io/npm/v/@aisoc/sdk)](https://www.npmjs.com/package/@aisoc/sdk)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)

TypeScript client SDK for [AiSOC](https://github.com/beenuar/AiSOC) — auto-generated types from `docs/openapi.yaml`, hand-crafted ergonomic API.

## Installation

```bash
npm install @aisoc/sdk
# or
pnpm add @aisoc/sdk
```

## Quick start

```ts
import { AiSOCClient } from "@aisoc/sdk";

const client = new AiSOCClient({
  baseUrl: "https://your-aisoc.example.com",
  token: process.env.AISOC_API_TOKEN!, // JWT or aisoc_… API key
});

// List critical open alerts
const alerts = await client.alerts.list({
  severity: "critical",
  status: "open",
  pageSize: 50,
});
console.log(`Found ${alerts.total} critical alerts`);

// Create a case
const newCase = await client.cases.create({
  title: "Suspicious lateral movement",
  priority: "high",
});

// Trigger a playbook
const run = await client.playbooks.run("isolate-host", {
  hostId: "srv-prod-42",
  caseId: newCase.id,
});
console.log("Playbook run:", run.runId);
```

## GraphQL

```ts
const result = await client.graphql<{ alerts: { items: unknown[] } }>(`
  query {
    alerts(pageSize: 10, status: "open") {
      items { id title severity }
    }
  }
`);
```

## API reference

All resource sub-clients live on the `AiSOCClient` instance:

| Namespace | Methods |
|---|---|
| `client.alerts` | `list(filters?)`, `get(id)`, `update(id, data)` |
| `client.cases` | `list(filters?)`, `get(id)`, `create(data)`, `update(id, data)`, `delete(id)` |
| `client.detections` | `list(params?)`, `get(id)` |
| `client.connectors` | `list(params?)`, `get(id)` |
| `client.playbooks` | `list(params?)`, `get(id)`, `create(data)`, `update(id, data)`, `delete(id)`, `run(id, triggerData?)`, `getRun(runId)` |
| `client.apiKeys` | `list()`, `create(data)`, `revoke(id)` |

## Development

```bash
# Regenerate types from the OpenAPI schema
pnpm codegen

# Build
pnpm build

# Run tests
pnpm test
```
