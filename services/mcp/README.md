# @aisoc/mcp

The [Model Context Protocol](https://modelcontextprotocol.io) server for **AiSOC** — connects Claude Desktop, Cursor, Continue.dev, Cody, and any MCP-aware assistant to your alerts, cases, detections, event lake, and the agent decision ledger.

[![license](https://img.shields.io/badge/license-MIT-22c55e.svg)](https://github.com/beenuar/AiSOC/blob/main/LICENSE)
[![install](https://img.shields.io/badge/install-monorepo%20source%20build-blue)](#install)
[![npm](https://img.shields.io/badge/npm-ready%2C%20unpublished-f59e0b)](#packaging-status)

AiSOC is an open-source AI SOC in which every agent decision is recorded in an investigation ledger. This package lets an assistant query that data — "which P0 cases are open", "replay the agent's reasoning on this run" — over stdio JSON-RPC, without the assistant ever holding your credentials.

## Packaging status

**`@aisoc/mcp` is ready, unpublished.** `release.yml` builds and packs it on every tag, but the upload is blocked on registry credentials, which is an account action rather than a code change. `npx -y @aisoc/mcp` therefore does **not** resolve today.

Everything below uses the monorepo source build, which does work. Where a command would differ once the package is published, that is noted inline rather than shown as a second copy of every command.

## Install

```bash
git clone https://github.com/beenuar/AiSOC.git
cd AiSOC/services/mcp
pnpm install
pnpm build           # writes dist/index.js — the executable entry point
```

Then point a host at it:

```bash
node dist/index.js install --host cursor \
  --aisoc-url https://aisoc.your-company.com \
  --api-key  aisoc_pat_xxxxxxxxxxxx
```

Hosts are `claude`, `cursor`, `continue`, and `cody`. Restart the assistant afterwards and `aisoc` appears in its tool picker.

The installer is idempotent — re-running with the same arguments is a no-op, and re-running with a new URL or key updates the entry in place. It refuses to overwrite a config file it cannot parse rather than clobbering hand-edits.

> **Where does `--api-key` come from?** AiSOC console → Settings → API Keys → "New personal access token". Grant `alerts:read`, `cases:read` and `rules:read` for the core read tools, and `cases:write` only if you want the agent to be able to start investigations from chat. The token is tenant-scoped and revocable.

The scope each tool needs, as the API enforces it:

| Tools | Scope |
|---|---|
| `aisoc_list_alerts`, `aisoc_get_alert`, `aisoc_get_triage_verdict` | `alerts:read` |
| `aisoc_list_cases`, `aisoc_get_case`, `aisoc_list_investigations`, `aisoc_get_investigation`, `aisoc_replay_decision`, `aisoc_explain_step` | `cases:read` |
| `aisoc_query_detections`, `aisoc_get_detection_rule` | `rules:read` |
| `aisoc_list_replay_reports`, `aisoc_get_replay_report` | `reports:read` |
| `aisoc_list_actions` | `actions:read` |
| `aisoc_preview_action` | `actions:execute` (dry-run only) |
| `aisoc_lake_query` | `lake:query` |
| `aisoc_lake_schema` | `lake:read_schema` |
| `aisoc_run_investigation` | `cases:write` |

### Which launcher gets written

`install` has to decide how the host should start the server, and the two answers are not interchangeable:

| `--launcher` | Config entry | When it works |
|---|---|---|
| `auto` *(default)* | picks `node` or `npx` by detecting where this copy was resolved from | always correct |
| `node` | `node /abs/path/to/dist/index.js serve` | today, from a source build |
| `npx` | `npx -y @aisoc/mcp serve` | only once the package is published |

From a clone, `auto` resolves to `node` with an absolute path to the build you just made. Forcing `--launcher npx` today writes an entry that the host cannot start; the installer prints a warning to stderr when you do.

### Manual setup

`--dry-run` prints exactly what would be written, without touching disk:

```bash
node dist/index.js install --host claude --dry-run \
  --aisoc-url https://aisoc.your-company.com --api-key aisoc_xxx
```

Paste the result under `mcpServers` in your host's config:

```json
{
  "mcpServers": {
    "aisoc": {
      "command": "node",
      "args": ["/absolute/path/to/AiSOC/services/mcp/dist/index.js", "serve"],
      "env": {
        "AISOC_URL": "https://aisoc.your-company.com",
        "AISOC_API_KEY": "aisoc_pat_xxxxxxxxxxxx"
      }
    }
  }
}
```

Per-host config locations:

| Host | Config file |
|---|---|
| Claude Desktop (macOS) | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Claude Desktop (Windows) | `%APPDATA%\Claude\claude_desktop_config.json` |
| Cursor | `~/.cursor/mcp.json` |
| Continue.dev | `~/.continue/config.json` |
| Cody | VS Code User Settings (JSON) → `cody.mcp.servers` |

Print the resolved paths for your own machine with `node dist/index.js install --list-paths`. Cody reports `null` because it reads MCP config from VS Code settings, where there is no single safe file to merge into — that host prints a snippet to paste instead.

## Tools exposed

The server advertises **19 tools**. Discovery tools list things, deep-dive tools fetch one thing, the lake pair runs governed SELECTs over the warm tier, and the replay tools expose the agent's own reasoning.

Every tool carries MCP behaviour annotations (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`), so a client that takes them seriously can decide what it may call without an operator vouching for each tool by name. **Seventeen of the eighteen are read-only.** The exception is `aisoc_run_investigation`, which starts an agent run, and it is annotated as such rather than being quietly marked read-only. No tool is annotated destructive, because none is.

| Tool | Required arguments | Purpose |
|---|---|---|
| `aisoc_list_alerts` | — | Page through alerts with filters (severity, status, time range). |
| `aisoc_list_cases` | — | Page through cases with filters (status, owner, priority). |
| `aisoc_query_detections` | — | Search detection rules by name, MITRE technique, or tag. |
| `aisoc_list_investigations` | — | Page through agent investigation runs. |
| `aisoc_list_replay_reports` | — | Replay evaluations: runs that graded AiSOC triage against this tenant's own analysts' past decisions. |
| `aisoc_list_actions` | — | Response actions this deployment can perform, and the vendor behind each. Listing one neither performs nor schedules it. |
| `aisoc_lake_schema` | — | Discover allowlisted tables and columns in the warm tier. Call this *before* `aisoc_lake_query` so the agent does not guess column names. |
| `aisoc_get_alert` | `alert_id` | Full alert detail including enrichments and matched detections. |
| `aisoc_get_case` | `case_id` | Full case detail including timeline and linked alerts. |
| `aisoc_get_detection_rule` | `rule_id` | Inspect a single rule (logic, fixtures, false-positive notes). |
| `aisoc_get_investigation` | `run_id` | Run summary (status, duration, agents involved, cost). |
| `aisoc_get_triage_verdict` | `alert_id` | What the agent decided about one alert: verdict, recommended actions, confidence with its rationale, and the analyst disposition. Says so explicitly when nothing has triaged it yet. |
| `aisoc_get_replay_report` | `evaluation_id` | One replay report, served as stored rather than re-rendered. A withheld headline stays withheld. |
| `aisoc_lake_query` | `sql` | Read-only SELECT against the warm tier. Per-tenant RLS, row caps, and the `lake:query` permission are enforced server-side. |
| `aisoc_run_investigation` | `case_id` | Start the agent on a case and stream events back. The one tool here that is not read-only. |
| `aisoc_preview_action` | `capability` | Preview a response action: blast radius, reversibility, verification probe, approval tier. **Dry run only.** |
| `aisoc_replay_decision` | `run_id` | Walk the agent ledger step by step (recon, forensic, responder, reporter). |
| `aisoc_explain_step` | `run_id`, `step` | Prompt, response, and tool I/O for a single step. |

Tools are advertised in that order deliberately: an agent reading the listing top-to-bottom meets the cheap discovery surface before the expensive one.

### Actions are previewed, never performed

`aisoc_preview_action` is the only tool that touches the response surface, and it cannot perform an action. The path it requests is a module constant naming `/api/v1/live-actions/dry-run`; the sibling `/dispatch`, which performs an action against a live vendor, appears nowhere in `src/`, and `tests/actions.test.ts` asserts that by reading the source rather than by driving the handler, so a second action tool added later is caught too. The API route behind it also forces `dry_run: true` server-side whatever the body says.

That boundary is deliberate. An MCP key is read-scoped credential material that ends up in an editor's configuration file, and the distance between "preview" and "perform" should not be one careless string. Performing an action needs the AiSOC console or API with an approval.

## Configuration

Every flag has an environment-variable equivalent. The CLI flag wins when both are set.

| Flag | Env var | Default | Notes |
|---|---|---|---|
| `--aisoc-url` | `AISOC_URL` | `http://localhost:8000` | Base URL of the AiSOC API. |
| `--api-key` | `AISOC_API_KEY` | _(none)_ | API key (`aisoc_pat_…`) or JWT. Required for non-public endpoints. |
| `--timeout` | `AISOC_TIMEOUT_MS` | `20000` | Per-request timeout in ms. |
| `--verbose` | `AISOC_MCP_VERBOSE=1` | off | Lifecycle logs to stderr. Stdout stays JSON-RPC clean. |
| `--http` | `AISOC_MCP_HTTP=1` | off | Serve streamable HTTP instead of stdio. See below. |
| — | `AISOC_MCP_HTTP_HOST` | `127.0.0.1` | Bind address for the HTTP transport. |
| — | `AISOC_MCP_HTTP_PORT` | `8096` | Port for the HTTP transport. |
| — | `AISOC_MCP_MAX_BODY_BYTES` | `1048576` | Largest JSON-RPC frame accepted over HTTP. |

Two further env vars control telemetry, described under [Security notes](#security-notes): `AISOC_MCP_TELEMETRY_URL` and `AISOC_MCP_AGENT_ID`.

## Over the network (streamable HTTP)

`--http` serves the same tools over MCP's streamable HTTP transport at
`POST /mcp`, with an unauthenticated liveness probe at `GET /healthz`.
`docker compose --profile mcp up` runs it; the Helm chart has an `mcp`
component, off by default.

Three things are different over HTTP, and they are differences in who decides
what rather than in plumbing:

- **The credential comes from the request.** Send
  `Authorization: Bearer aisoc_…` (or a JWT) on every call. `--api-key` /
  `AISOC_API_KEY` configure the *stdio* server and are not consulted here, so a
  request without a credential is `401` rather than being answered with the
  operator's own access. The tenant is derived from the credential; there is no
  tenant parameter anywhere in the protocol or the authorize request.
- **Every call is authorized by AiSOC before it runs.** The server posts to
  `POST /api/v1/mcp/tool-calls/authorize` and does what it is told. It fails
  **closed**: if the API cannot be reached, no tool runs.
- **A tool that is not read-only needs a human.** `aisoc_run_investigation` is
  the only one today. The first call creates an approval bound to those exact
  arguments and answers with its id; somebody other than the requester decides
  it at `POST /api/v1/mcp/approvals/{id}/decide`, and the approval is spent by
  the call it authorised.

A tenant administrator can switch any individual tool off for the whole tenant
at `PUT /api/v1/mcp/tools/{tool_name}`, independently of what scopes a key
carries. `GET /api/v1/mcp/tools` lists the effective state and says whether it
came from a tenant decision or from the tool's default.

Sessions are deliberately not implemented: the transport is stateless and a
fresh server is built per request, so revoking a key ends every conversation
it had opened rather than leaving a session id that outlives it.

## Verify before you fly

```bash
AISOC_URL=https://aisoc.your-company.com \
AISOC_API_KEY=aisoc_pat_xxx \
node dist/index.js doctor
```

`doctor` checks DNS, TLS, the AiSOC `/health` endpoint, and that your API key is accepted. It exits non-zero on failure, so it can be wired into a pre-flight script.

## How it talks to AiSOC

```
┌──────────────┐        stdio JSON-RPC        ┌──────────────┐    HTTPS     ┌──────────────┐
│ Claude /     │ ───────────────────────────► │ @aisoc/mcp   │ ───────────► │ AiSOC API    │
│ Cursor / IDE │ ◄─────────────────────────── │ (this pkg)   │ ◄─────────── │ + agents     │
└──────────────┘                              └──────────────┘              └──────────────┘
                                                                                   │
                                                                                   ▼
                                                                         investigation_events
                                                                         (decision ledger)
```

The host launches us over stdio. Stdout carries JSON-RPC frames only; logs go to stderr. We translate MCP `tools/call` into AiSOC REST calls. `aisoc_run_investigation` emits progressive content blocks so the assistant can show intermediate steps.

With `--http` the left-hand arrow is streamable HTTP rather than stdio, the
host supplies its own bearer credential per request, and one extra hop sits in
front of every dispatch:

```
┌──────────────┐   HTTP POST /mcp   ┌──────────────┐  authorize   ┌──────────────┐
│ any MCP      │ ─────────────────► │ @aisoc/mcp   │ ───────────► │ AiSOC API    │
│ client       │   Authorization:   │ --http       │ ◄─────────── │ decides +    │
│              │   Bearer aisoc_…   │              │   allow /    │ writes audit │
└──────────────┘                    └──────┬───────┘   deny /     └──────────────┘
                                           │           approval
                                           ▼  (only if allowed)
                                      the tool's own AiSOC REST call
```

## Security notes

- **Your API key never leaves the machine** running this server, on the stdio transport. It is read from the environment or from the host's local config file (written mode `0600`) and used to sign requests to your own AiSOC instance. Over HTTP there is no stored key at all: the credential arrives with each request, is used for that request, and is not retained.
- **Read-only unless the key says otherwise.** `aisoc_run_investigation` requires `cases:write`; `aisoc_preview_action` requires `actions:execute` but only ever calls the dry-run; every other tool needs only read scopes.
- **Audit trail — and it differs by transport, so read which one you run.**
  - **Over HTTP:** AiSOC writes an `mcp:tool_call` row to the tenant's
    append-only, hash-chained `audit_log` for **every** call including the
    reads, before the tool runs, carrying the tool name, the argument *names*
    (never the values), the decision and the calling key's prefix. A second
    `mcp:tool_result` row carries the outcome and latency — a second row
    rather than an update because those rows are immutable by trigger. Revoke
    the key and the history survives the revocation.
  - **Over stdio:** that path does not exist, and the old caveat still holds.
    The API's `audit_middleware` records only mutating methods carrying a
    valid JWT, so the read tools (`aisoc_list_*`, `aisoc_get_*`,
    `aisoc_lake_query`) produce **no server-side audit row**, and what it does
    record is an HTTP path rather than a tool name. Attribution then comes
    only from this server's own telemetry, below.
  - Either way, `AISOC_MCP_TELEMETRY_URL` collects this server's own
    `mcp.tool_call` records into an AiSOC inbox token using the `ai-runtime`
    template. Unset, nothing is emitted. `AISOC_MCP_AGENT_ID` names this
    server in the AI-estate inventory. That is a self-report, which is a
    weaker artefact than the audit row above and is not a substitute for it.
- **Outbound destinations** are your `AISOC_URL`, plus `AISOC_MCP_TELEMETRY_URL` when you configure one, plus the npm registry on `npx` cold-start if you launch that way.

## Troubleshooting

**The server does not appear in my assistant.** Restart the host fully — Claude Desktop needs `Cmd+Q`, not just closing the window. Then run `install --list-paths` and confirm the file at the printed path really contains an `aisoc` entry under `mcpServers`.

**The host says the server failed to start.** Check whether the config entry runs `npx -y @aisoc/mcp`. That cannot resolve until the package is published; re-run the installer with `--launcher node`.

**Tools fail with 401 / 403.** Re-mint the API key with the right scopes and re-run the installer — it updates the entry in place. Confirm with `node dist/index.js doctor`.

**Tools fail with "fetch failed" or time out.** The host cannot reach `AISOC_URL`. Check reachability from the same machine (`curl $AISOC_URL/health`) and raise `--timeout 60000` on a slow link.

## Development

```bash
pnpm install
pnpm test          # config, installers, tool registry, lake, telemetry, registry manifest
pnpm typecheck
pnpm build         # produces dist/index.js
pnpm dev           # tsx watch, stdio serve mode
```

Adding a tool? Each one is a `ToolDefinition<ZodSchema>` exported from a domain file in [`src/tools/`](./src/tools) and registered in [`src/tools/index.ts`](./src/tools/index.ts). The contract tests in `tests/tools.test.ts` fail loudly on missing metadata, wrong ordering, or off-convention naming.

### Registry manifest

[`server.json`](./server.json) is the [MCP registry](https://registry.modelcontextprotocol.io) manifest, written against the published `2025-12-11` schema. It carries the server's identity and points at this subfolder for source inspection.

It deliberately declares **no `packages` entry**. That field is optional in the schema, and omitting it is the accurate state: a directory listing sends a reader to the source rather than to an install command that would 404. When the npm upload is unblocked, add the entry and drop the "ready, unpublished" line above together — `tests/registry.test.ts` asserts the two stay consistent.

## License

MIT — see [LICENSE](https://github.com/beenuar/AiSOC/blob/main/LICENSE). Bug reports and PRs welcome at [github.com/beenuar/AiSOC](https://github.com/beenuar/AiSOC).
