# @aisoc/mcp

> The official [Model Context Protocol](https://modelcontextprotocol.io) server for **AiSOC** — connect Claude Desktop, Cursor, Cody, Continue, and any MCP-aware assistant to your alerts, cases, detections, and the agent decision ledger.

[![license](https://img.shields.io/badge/license-MIT-22c55e.svg)](https://github.com/beenuar/AiSOC/blob/main/LICENSE)
[![status](https://img.shields.io/badge/status-monorepo--source--build-blue)](#install-from-source-today)
[![npm release](https://img.shields.io/badge/npm-coming%20in%20v8.0-f59e0b)](https://github.com/beenuar/AiSOC/blob/main/CHANGELOG.md)
[![tests](https://img.shields.io/badge/tests-50%20passing-brightgreen)](#development)

> **Status — monorepo source build today; npm publish in v8.0.** Every command in this README that shows `npx -y @aisoc/mcp …` works once the package lands on npm. Until then, use the **source-build equivalents** shown right below each one — they call the same binary, take the same arguments, and write the same config files.

AiSOC is the open-source AI SOC where every agent decision is auditable. This package is the bridge that lets your assistant ask AiSOC questions like "show me the open P0 cases" or "replay the agent's reasoning on INC-0421" without leaving the chat.

---

## Install from source (today)

```bash
git clone https://github.com/beenuar/AiSOC.git
cd AiSOC/services/mcp
pnpm install
pnpm build           # writes dist/index.js (the executable bin)
```

`dist/index.js` is the binary. Every command below shows the **today** invocation (`node dist/index.js …`) and the **v8.0 npm** invocation (`npx -y @aisoc/mcp …`) side by side — they accept identical flags.

## Configure your assistant

The recommended path is the one-liner installer. It writes the right snippet into the right config file for your host, and it's idempotent:

```bash
# Claude Desktop — today:
node dist/index.js install --host claude \
  --aisoc-url https://aisoc.your-company.com \
  --api-key  aisoc_pat_xxxxxxxxxxxx
# Claude Desktop — v8.0+:
npx -y @aisoc/mcp install --host claude \
  --aisoc-url https://aisoc.your-company.com \
  --api-key  aisoc_pat_xxxxxxxxxxxx

# Cursor — today:
node dist/index.js install --host cursor --aisoc-url ... --api-key ...
# Cursor — v8.0+:
npx -y @aisoc/mcp install --host cursor --aisoc-url ... --api-key ...

# Continue.dev — today:
node dist/index.js install --host continue --aisoc-url ... --api-key ...
# Continue.dev — v8.0+:
npx -y @aisoc/mcp install --host continue --aisoc-url ... --api-key ...

# Cody — today (prints a snippet to paste; the extension reads VS Code settings):
node dist/index.js install --host cody --aisoc-url ... --api-key ...
# Cody — v8.0+:
npx -y @aisoc/mcp install --host cody --aisoc-url ... --api-key ...
```

Restart your assistant and the `aisoc` server will appear in its tool picker.

> **Where does `--api-key` come from?** AiSOC console → Settings → API Keys → "New personal access token". The token is scoped to your tenant; revoke it any time.

### Manual install

If you'd rather edit the JSON yourself, `install --dry-run` prints exactly what the installer would write:

```bash
# Today:
node dist/index.js install --host claude --dry-run \
  --aisoc-url https://aisoc.your-company.com --api-key aisoc_xxx
# v8.0+:
npx -y @aisoc/mcp install --host claude --dry-run \
  --aisoc-url https://aisoc.your-company.com --api-key aisoc_xxx
```

Paste the snippet the installer prints under `mcpServers` in your host's config. The today vs v8.0 shapes are:

```json
// Today (monorepo source build — note the absolute path)
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

// v8.0+ (once @aisoc/mcp is on npm)
{
  "mcpServers": {
    "aisoc": {
      "command": "npx",
      "args": ["-y", "@aisoc/mcp", "serve"],
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

Print these as JSON any time with `npx @aisoc/mcp install --list-paths`.

---

## Tools exposed

The server advertises **13 tools**. Discovery tools list things, deep-dive tools fetch one thing, the lake-query pair lets agents run governed SELECTs over the warm tier, and the action / replay tools are what make AiSOC interesting:

| Tool | Purpose |
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

The replay/explain pair is the moat — closed-source AI SOC vendors can't show you their agent's prompts and tool calls. AiSOC will.

---

## Configuration

All flags can be set via env vars. The CLI flag wins if both are present.

| Flag | Env var | Default | Notes |
|---|---|---|---|
| `--aisoc-url` | `AISOC_URL` | `http://localhost:8081` | Base URL of the AiSOC API. |
| `--api-key` | `AISOC_API_KEY` | _(none)_ | API key (`aisoc_pat_…`) or JWT. Required for non-public endpoints. |
| `--timeout` | `AISOC_TIMEOUT_MS` | `20000` | Per-request timeout in ms. |
| `--verbose` | `AISOC_VERBOSE=1` | off | Lifecycle logs to stderr (stdout stays JSON-RPC clean). |

---

## Verify before you fly

Before pointing your assistant at it, smoke-test the connection:

```bash
# Today (monorepo source build):
AISOC_URL=https://aisoc.your-company.com \
AISOC_API_KEY=aisoc_pat_xxx \
node dist/index.js doctor

# v8.0+ (once @aisoc/mcp lands on npm):
AISOC_URL=https://aisoc.your-company.com \
AISOC_API_KEY=aisoc_pat_xxx \
npx -y @aisoc/mcp doctor
```

`doctor` checks DNS, TLS, the AiSOC `/health` endpoint, and that your API key is accepted. It exits non-zero on failure so you can wire it into a pre-flight script.

---

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

- The host launches us via stdio. Stdout is reserved for JSON-RPC frames; logs go to stderr.
- We translate MCP `tools/call` into the AiSOC REST API.
- Streaming tools (`aisoc_run_investigation`) emit progressive content blocks so the assistant can show intermediate steps.

---

## Security notes

- **Your API key never leaves the machine** running this server. It's read from env or the host's local config file (mode `0600`) and used to sign requests to your AiSOC instance.
- **Read-only by default** unless your API key has write scopes. `aisoc_run_investigation` requires `cases:investigate`; everything else only needs `cases:read` / `alerts:read`.
- **Audit trail.** Every tool call logged through this server lands in the AiSOC audit log with the calling user and the tool name. You can revoke the key and replay every action it took.

---

## Development

```bash
git clone https://github.com/beenuar/AiSOC.git
cd AiSOC/services/mcp
pnpm install
pnpm test          # 50 unit tests covering config, installers, tool registry
pnpm typecheck
pnpm build         # produces dist/index.js (the bin)
pnpm dev           # tsx watch — runs in stdio serve mode
```

Adding a tool? See [`src/tools/`](./src/tools) — each tool is a `ToolDefinition<ZodSchema>` exported from a domain file and registered in [`src/tools/index.ts`](./src/tools/index.ts). The contract tests in `tests/tools.test.ts` will fail loudly if you forget metadata, ordering, or naming conventions.

---

## License

MIT — see [LICENSE](https://github.com/beenuar/AiSOC/blob/main/LICENSE).

Bug reports and PRs welcome at [github.com/beenuar/AiSOC](https://github.com/beenuar/AiSOC).
