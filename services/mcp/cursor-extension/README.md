# AiSOC IDE Extension

> Run triage, replay investigation steps, and ask "why did the agent do this?" from inside your editor — without leaving your IDE.

This extension is the analyst-facing companion to [`@aisoc/mcp`](../README.md). It registers four commands that call the AiSOC MCP gateway over HTTP and renders the response in a side-panel webview. It targets any VSCode-compatible IDE (engines `^1.80.0`), so it runs on every editor that supports the VSCode extension API.

<!-- TODO: demo video link -->

---

## Commands

| Command palette | What it does |
|---|---|
| `AiSOC: Run Triage on Case…` | Kicks off the multi-agent investigator on a case UUID. Returns the `run_id` you can feed back into the next two commands. |
| `AiSOC: Replay Investigation Step…` | Walks the agent decision ledger for a run — recon → forensic → responder → reporter steps, with optional `since_seq` cursor for tail-mode polling. |
| `AiSOC: Explain Why the Agent Did This` | Deep-dive on one step: prompt, response, tool I/O, surrounding context. The trust-vector view that closed-source agents don't expose. |
| `AiSOC: Find Detections for This Technique` | Search the detection-rule library. Pastes a MITRE technique id (`T1059.003`) or free text. If you have text selected in the editor, it pre-seeds the query. |

Plus two key-management helpers:

| Command palette | What it does |
|---|---|
| `AiSOC: Set API Key…` | Prompts for your AiSOC API key (`aisoc_pat_…`) with a masked input box and stores it in the IDE's secret storage. |
| `AiSOC: Clear Stored API Key` | Forgets the stored key. |

All output is logged to the **AiSOC** output channel for an audit trail you can grep.

---

## Settings

| Setting | Default | What it controls |
|---|---|---|
| `aisoc.mcpEndpoint` | `http://localhost:8765/mcp` | HTTP URL the extension posts JSON-RPC `tools/call` requests to. Point this at your AiSOC MCP gateway (see below). |
| `aisoc.requestTimeoutMs` | `30000` | Per-request timeout. Investigations stream back asynchronously via `replayDecision`; this is the timeout on the kick-off call. |
| `aisoc.apiKey` | _(empty, do not use)_ | Decoy setting. **Do not paste your API key here** — it's stored as plain text. Use the `AiSOC: Set API Key…` command instead. |

---

## Architecture (short)

```
┌──────────────┐   tools/call (HTTP)   ┌──────────────────┐   stdio MCP   ┌──────────────┐
│ IDE          │ ────────────────────► │ MCP HTTP gateway │ ────────────► │ @aisoc/mcp   │
│ (extension)  │ ◄──────────────────── │ (your choice)    │ ◄──────────── │ (stdio bin)  │
└──────────────┘                       └──────────────────┘               └──────────────┘
                                                                                  │
                                                                                  ▼
                                                                          AiSOC REST API
                                                                          + decision ledger
```

- The extension only knows about HTTP JSON-RPC. It sends `{ jsonrpc, id, method: "tools/call", params: { name, arguments } }` and reads the standard MCP `CallToolResult` envelope back.
- The MCP HTTP gateway is your choice — it can be a thin wrapper that spawns `npx @aisoc/mcp serve` and bridges stdio↔HTTP, the AiSOC API itself once an MCP-over-HTTP endpoint lands, or any reverse proxy you already run.
- The API key never appears on the wire to the underlying AiSOC API directly; it's sent to the gateway as `Authorization: Bearer …` and forwarded from there.

---

## Install locally (developer)

```bash
cd services/mcp/cursor-extension
npm install
npm run compile           # produces out/extension.js
```

Then load the extension in a development host:

1. Open this folder in VSCode-compatible IDE.
2. Press `F5` (or "Run → Start Debugging"). A second IDE window opens with the extension loaded.
3. Open the command palette (`Ctrl/Cmd+Shift+P`) and type `AiSOC:` to see the four commands.

Or package and side-load a `.vsix`:

```bash
npm install -g @vscode/vsce
vsce package --no-dependencies     # writes aisoc-extension-0.1.0.vsix
code --install-extension aisoc-extension-0.1.0.vsix
```

(`--no-dependencies` is correct here: the extension ships only its compiled output and has no runtime npm dependencies.)

---

## First-run configuration

After installing, configure the extension from the command palette:

1. **`AiSOC: Set API Key…`** — paste your `aisoc_pat_…` token. It's stored in the OS keychain via the IDE's secret-storage API; nothing lands in `settings.json`.
2. **Open settings → search "AiSOC"** and set `aisoc.mcpEndpoint` if your gateway isn't on `http://localhost:8765/mcp`.

You're done. Run `AiSOC: Find Detections for This Technique`, type `T1059.003`, and you should see a list come back.

---

## Tests

```bash
npm test                  # vitest run — covers URL construction, JSON-RPC shape, error mapping
```

The smoke tests stub `fetch` and assert each public method (`runInvestigation`, `replayDecision`, `explainStep`, `queryDetections`) constructs the right URL, headers, and payload. They are intentionally lightweight — full end-to-end coverage lives in `services/mcp/tests/`.

---

## Publishing

This package is publish-ready but **not** published yet. The launch flow is:

1. Bump `version` in `package.json`.
2. Update the `CHANGELOG.md` (TODO when first published) with the user-visible delta.
3. From this directory:
   ```bash
   npm install
   npm run compile
   npm test
   npx @vscode/vsce package --no-dependencies
   ```
4. Inspect the `.vsix` (`unzip -l aisoc-extension-*.vsix`) and confirm it does **not** contain `src/`, `tests/`, `node_modules/`, or any `.env` / `.secret` files. The `.vscodeignore` is what enforces that — review it before publishing.
5. Authenticate with the marketplace publisher (separate one-time step):
   ```bash
   npx @vscode/vsce login aisoc
   ```
6. Publish:
   ```bash
   npx @vscode/vsce publish --no-dependencies
   ```
   (Or `vsce publish minor` / `patch` to bump and publish in one step.)
7. Optionally publish to the Open VSX registry as well for non-marketplace IDEs:
   ```bash
   npx ovsx publish aisoc-extension-*.vsix --pat <OVSX_PAT>
   ```

> **Secrets:** the publisher PAT and the OVSX PAT must come from the publisher's secret manager — they are never committed to the repo.

---

## Roadmap

- Live "tail mode" for in-progress investigations (poll `replayDecision` with `since_seq` and stream new steps into the webview).
- Detection-rule "open in editor" — when `queryDetections` returns a hit, offer to fetch the rule body and open it in a buffer.
- A command-palette quick-pick that lists recent investigations (uses `aisoc_list_investigations`) so users don't have to paste UUIDs.

---

## License

MIT — same as the rest of AiSOC. See [`LICENSE`](../../../LICENSE) at the repo root.
