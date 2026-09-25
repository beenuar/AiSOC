---
sidebar_position: 1
title: MCP server (Claude / Cursor / Cody)
description: Connect AiSOC to Claude Desktop, Cursor, Cody, and Continue.dev via the Model Context Protocol.
---

# MCP server

The `@aisoc/mcp` server is the official [Model Context Protocol](https://modelcontextprotocol.io) bridge between AiSOC and modern AI assistants. Once installed, your assistant can list alerts, pull cases, run agent investigations, and **replay every step the agent took** — without leaving the chat or the IDE.

:::info Packaging status — ready, unpublished
The MCP server ships from [`services/mcp/`](https://github.com/beenuar/AiSOC/tree/main/services/mcp) and works today from a source build. It is **not on npm**: `release.yml` builds and packs it on every tag, but the upload is blocked on registry credentials, which is an account action rather than a code change. `npx -y @aisoc/mcp` does not resolve — use the source-build path below.
:::

MCP is the interface Claude Desktop, Cursor, Cody, Continue.dev and Zed use to reach external tools, so an analyst working in any of them can query AiSOC without switching windows.

## Build from source

```bash
git clone https://github.com/beenuar/AiSOC.git
cd AiSOC/services/mcp
pnpm install
pnpm build               # writes services/mcp/dist/index.js
```

`dist/index.js` is an executable Node entry point. Every command below assumes you run it from the `services/mcp` directory.

## Supported hosts

| Host | Install command | Config file |
|---|---|---|
| **Claude Desktop** | `node dist/index.js install --host claude --aisoc-url … --api-key …` | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| **Cursor** | `node dist/index.js install --host cursor --aisoc-url … --api-key …` | `~/.cursor/mcp.json` |
| **Continue.dev** | `node dist/index.js install --host continue --aisoc-url … --api-key …` | `~/.continue/config.json` |
| **Cody** | `node dist/index.js install --host cody --aisoc-url … --api-key …` (prints a snippet) | VS Code User Settings → `cody.mcp.servers` |

Print the canonical config paths for your machine any time:

```bash
node dist/index.js install --list-paths
```

### Which launcher gets written

The installer has to decide how the host should start the server, and `--launcher` controls it:

| Value | Config entry | When it works |
|---|---|---|
| `auto` *(default)* | detects where this copy was resolved from and picks one of the two below | always correct |
| `node` | `node /abs/path/to/dist/index.js serve` | today, from a source build |
| `npx` | `npx -y @aisoc/mcp serve` | only once the package is published |

From a clone, `auto` resolves to `node` with an absolute path. Forcing `--launcher npx` today writes an entry the host cannot start, and the installer warns on stderr when you do.

## 60-second quickstart

### 1. Mint an API key

In the AiSOC console: **Settings → API Keys → New personal access token**. Give it `cases:read`, `alerts:read`, `detections:read`, and (if you want the agent to investigate from chat) `cases:investigate`. Copy the token — it's shown once.

### 2. Run the installer

```bash
node dist/index.js install --host claude \
  --aisoc-url https://aisoc.your-company.com \
  --api-key  aisoc_pat_xxxxxxxxxxxx
```

The installer is **idempotent**. Re-running it with the same arguments is a no-op; re-running it with a new URL or key updates the entry in place.

### 3. Restart your assistant

- **Claude Desktop**: `Cmd+Q` then reopen.
- **Cursor**: open Settings → MCP and confirm the `aisoc` server shows green.
- **Continue.dev**: `Cmd/Ctrl+Shift+P` → _Continue: Reload Window_.

### 4. Try it

Ask your assistant:

> _"Show me the open P0 cases in AiSOC."_
>
> _"Replay the agent's reasoning on case INC-0421 step by step."_
>
> _"Why did the agent decide that 10.0.42.7 was malicious in run 7c1f…?"_

If the assistant asks for permission to call `aisoc_*` tools, that's expected — every host requires explicit approval the first time.

## Tools exposed

The server advertises **13 tools** to your assistant. Discovery tools list things, deep-dive tools fetch one thing, the lake-query pair lets agents run governed SELECTs over the warm tier, and the replay tools expose the agent's own reasoning:

```mermaid
graph LR
  subgraph Discovery
    A1[aisoc_list_alerts]
    A2[aisoc_list_cases]
    A3[aisoc_query_detections]
    A4[aisoc_list_investigations]
    A5[aisoc_lake_schema]
  end
  subgraph Deep-dive
    B1[aisoc_get_alert]
    B2[aisoc_get_case]
    B3[aisoc_get_detection_rule]
    B4[aisoc_get_investigation]
  end
  subgraph Lake query
    D1[aisoc_lake_query]
  end
  subgraph Action / replay
    C1[aisoc_run_investigation]
    C2[aisoc_replay_decision]
    C3[aisoc_explain_step]
  end
  A2 --> B2 --> C1 --> C2 --> C3
  A5 --> D1
```

| Tool | What it does |
|---|---|
| `aisoc_list_alerts` | Page through alerts with filters (severity, status, time range). |
| `aisoc_get_alert` | Full alert detail including enrichments and matched detections. |
| `aisoc_list_cases` | Page through cases with filters (status, owner, priority). |
| `aisoc_get_case` | Full case detail including timeline and linked alerts. |
| `aisoc_query_detections` | Search detection rules by name, MITRE technique, or tag. |
| `aisoc_get_detection_rule` | Inspect a single rule (logic, fixtures, FP notes). |
| `aisoc_list_investigations` | Page through agent investigation runs. |
| `aisoc_get_investigation` | Run summary (status, duration, agents involved, cost). |
| `aisoc_lake_schema` | Discover allowlisted tables and column names in the warm tier — call this *before* `aisoc_lake_query` so the agent doesn't guess column names. |
| `aisoc_lake_query` | Run a read-only SELECT against the warm tier (lake). Per-tenant RLS, row caps, and the `lake:query` permission are enforced server-side. |
| **`aisoc_run_investigation`** | Kick off the agent on a case and stream events back. |
| **`aisoc_replay_decision`** | Walk the agent ledger step-by-step (recon, forensic, responder, reporter). |
| **`aisoc_explain_step`** | Why-did-the-agent-do-this for a single step: prompt, response, tool I/O. |

`aisoc_replay_decision` and `aisoc_explain_step` read the investigation ledger, so the prompt, the response and the tool I/O behind any single agent step are retrievable from chat rather than only from the console.

## Configuration

All flags can be set via env vars; the CLI flag wins if both are present.

| Flag | Env var | Default | Notes |
|---|---|---|---|
| `--aisoc-url` | `AISOC_URL` | `http://localhost:8081` | Base URL of the AiSOC API. |
| `--api-key` | `AISOC_API_KEY` | _(none)_ | API key (`aisoc_pat_…`) or JWT. Required for non-public endpoints. |
| `--timeout` | `AISOC_TIMEOUT_MS` | `20000` | Per-request timeout in ms. |
| `--verbose` | `AISOC_MCP_VERBOSE=1` | off | Lifecycle logs to stderr (stdout stays JSON-RPC clean). |

## Manual (no-installer) setup

If you'd rather edit JSON yourself, `install --dry-run` prints exactly what the installer would write:

```bash
node dist/index.js install --host claude --dry-run \
  --aisoc-url https://aisoc.your-company.com --api-key aisoc_xxx
```

Paste the snippet under `mcpServers` in your host's config:

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

Once the package is published, the equivalent entry becomes `"command": "npx"` with `"args": ["-y", "@aisoc/mcp", "serve"]` and no absolute path. Until then that form will not start.

## Verify before you fly

Before pointing your assistant at it, smoke-test the connection:

```bash
AISOC_URL=https://aisoc.your-company.com \
AISOC_API_KEY=aisoc_pat_xxx \
node dist/index.js doctor
```

`doctor` checks DNS, TLS, the AiSOC `/health` endpoint, and that your API key is accepted. It exits non-zero on failure, so it's safe to wire into a pre-flight script.

## Security model

- **Your API key never leaves the machine** running the server. It's read from env or the host's local config file (mode `0600`) and used to sign requests to your AiSOC instance.
- **Read-only by default** unless your API key has write scopes. `aisoc_run_investigation` requires `cases:investigate`; everything else only needs `cases:read` / `alerts:read`.
- **Audit trail — read this before relying on it.** The API's `audit_middleware` records only mutating methods carrying a valid JWT, so the ten read tools (`aisoc_list_*`, `aisoc_get_*`, `aisoc_lake_query`) produce **no server-side audit row**, and what it does record is an HTTP path rather than a tool name. Per-tool attribution comes instead from this server's own `mcp.tool_call` records: tool name, calling key's subject, argument *keys* (never values), latency, and outcome. Set `AISOC_MCP_TELEMETRY_URL` to an AiSOC inbox token using the `ai-runtime` template to collect them; unset, nothing is emitted. `AISOC_MCP_AGENT_ID` names this server in the AI-estate inventory.
- **Outbound destinations** are your `AISOC_URL`, plus `AISOC_MCP_TELEMETRY_URL` when you configure one, plus the npm registry on `npx` cold-start if you launch that way.

## Troubleshooting

**The server doesn't appear in my assistant.** Restart the host fully (Claude Desktop: `Cmd+Q`, not just close the window). Then re-run `install --list-paths` and confirm the config file at the printed path actually contains an `aisoc` entry under `mcpServers`.

**Tools fail with 401 / 403.** Re-mint the API key with the right scopes and re-run the installer; it will update the entry in place. Confirm with `node dist/index.js doctor`.

**Tools fail with "fetch failed" / timeouts.** Your assistant's host can't reach `AISOC_URL`. Check that the URL is reachable from the same machine (`curl $AISOC_URL/health`) and bump `--timeout 60000` if you're on a slow link.

**The config file is malformed.** The installer refuses to overwrite a config it can't parse, to avoid clobbering hand-edits. Fix or back up the file, then re-run.

## Source & contributions

The package source lives in [`services/mcp`](https://github.com/beenuar/AiSOC/tree/main/services/mcp). Tests, tool definitions, and the installer are all there. PRs welcome — the contract tests in [`tests/tools.test.ts`](https://github.com/beenuar/AiSOC/blob/main/services/mcp/tests/tools.test.ts) will tell you immediately if you forget metadata, ordering, or naming conventions on a new tool.
