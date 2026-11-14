# @cyble/aisoc-connector

Author Cyble AiSOC connectors in TypeScript with hot reload.

## Why TypeScript?

Most security-team automation engineers we've talked to write
TypeScript daily. The Python connector SDK is great for our shipped
vendors (Splunk, CrowdStrike, Okta, ...) but it's a high-friction
choice for someone who just wants to wrap their internal SaaS with a
working SOAR connector in an afternoon.

This SDK gives you:

- A single `defineConnector({ ... })` API, with **Zod-validated**
  input/output for every action.
- A `aisoc-connector dev <file.ts>` hot-reload server that any
  running AiSOC platform can connect to over HTTP — no rebuild loop,
  no docker-compose, no daemon to install.
- A JSON manifest output that drops straight into the marketplace
  catalog.

## Quick start

```bash
npm i -g @cyble/aisoc-connector
aisoc-connector init my-connector
cd my-connector
npm i
npm run dev
```

Then in another terminal:

```bash
curl -s http://localhost:7311/manifest | jq
curl -s -X POST http://localhost:7311/actions/ping \
  -H 'content-type: application/json' \
  -d '{"tenant_id":"local-dev","input":{},"config":{"baseUrl":"https://example.com","token":"x"}}' | jq
```

Edit `index.ts`, save, and the dev server reloads in <100ms.

## Authoring contract

```ts
import { defineConnector, ConnectorKind, RiskClass, z } from '@cyble/aisoc-connector';

export default defineConnector({
  kind: ConnectorKind.SIEM,            // bucket: SIEM, EDR, IDP, EMAIL, ...
  vendor: 'acme-siem',                 // [a-z0-9-]{2,41}, starts alpha
  version: '0.1.0',                    // semver-like
  author: 'Jane Doe (github:janedoe)', // surfaces in marketplace
  configSchema: z.object({
    baseUrl: z.string().url(),
    token: z.string().min(1),
  }),
  actions: {
    search_events: {
      description: 'Find events for an entity in the last 24h.',
      risk: RiskClass.READ,
      idempotent: true,
      input: z.object({
        entity: z.string(),
        entity_type: z.enum(['ip', 'host', 'user']),
      }),
      output: z.array(
        z.object({
          event_id: z.string(),
          timestamp: z.string(),
          title: z.string(),
        }),
      ),
      handler: async ({ input, ctx }) => {
        const r = await ctx.http.get<{ events: any[] }>(
          `/search?q=${encodeURIComponent(input.entity)}`,
        );
        return r.events;
      },
    },
  },
});
```

Hard rules enforced at `defineConnector(...)` time:

| Rule                                                                           |
| ------------------------------------------------------------------------------ |
| `vendor` matches `^[a-z0-9][a-z0-9-]{1,40}$`                                    |
| `version` is semver-like                                                       |
| `configSchema` is a Zod schema                                                 |
| Every action name is snake_case (`^[a-z][a-z0-9_]{1,40}$`)                     |
| Every action has Zod `input` and `output` schemas                              |
| Every action has a `handler`                                                   |

The handler context supplies:

- `ctx.config` — your validated, typed config object.
- `ctx.http` — `get/post/put/delete/fetch` preconfigured with
  `baseUrl` from your config and `Authorization: Bearer <token>` (or
  `x-api-key: <apiKey>`) auth headers.
- `ctx.tenantId` — the tenant making the call.
- `ctx.idempotencyKey` — pass this through to the upstream when
  available so retries are safe.
- `ctx.invocationId` — unique per call, for log correlation.
- `ctx.log(level, msg, extra?)` — structured logger that lands in
  the platform's audit log.
- `ctx.signal` — `AbortSignal`. Always pass to upstream `fetch()`.

## Wiring into a running AiSOC

Run `aisoc-connector dev index.ts` and the platform's connector
registry will discover it via `http://localhost:$PORT/manifest`.

When you change a file, the server reloads and emits a `reload`
event over `GET /events` (Server-Sent Events); the platform
auto-re-registers without you having to restart anything.

## Publishing to the marketplace

```bash
aisoc-connector manifest index.ts > manifest.json
# Submit manifest.json + your code via PR to
# github.com/beenuar/AiSOC/community-connectors/
```

Marketplace policy lives in
[`CONTRIBUTING-CONNECTORS.md`](../../CONTRIBUTING-CONNECTORS.md).
