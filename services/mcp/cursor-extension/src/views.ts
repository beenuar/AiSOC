/**
 * Output and webview helpers for the AiSOC extension.
 *
 * Two surfaces:
 *
 *   1. `AisocOutput` — a singleton `vscode.OutputChannel` we log every
 *      command invocation, MCP request, and error into. This gives the
 *      analyst a persistent audit trail without having to dig into
 *      developer tools.
 *
 *   2. `showToolResultWebview()` — renders an `McpToolResult` in a
 *      side-panel webview with the human-readable markdown stacked above
 *      the structured JSON payload. The MCP server formats its content
 *      blocks as fenced JSON / markdown text already; we just escape and
 *      inline them.
 *
 * The webview HTML is deliberately self-contained (no asset URIs, no
 * third-party libs) so the extension passes the marketplace's
 * "trustworthiness" review with the minimum content-security-policy
 * footprint.
 */
import * as vscode from "vscode";

import type { McpContentBlock, McpToolResult } from "./mcpClient";

let output: vscode.OutputChannel | undefined;

/** Return a process-wide output channel, lazily created on first use. */
export function getOutputChannel(): vscode.OutputChannel {
  if (!output) {
    output = vscode.window.createOutputChannel("AiSOC");
  }
  return output;
}

/**
 * Append a timestamped line to the AiSOC output channel. Multi-line
 * payloads are indented for readability.
 */
export function logLine(message: string, payload?: unknown): void {
  const channel = getOutputChannel();
  const ts = new Date().toISOString();
  channel.appendLine(`[${ts}] ${message}`);
  if (payload !== undefined) {
    const rendered =
      typeof payload === "string" ? payload : safeJsonStringify(payload);
    for (const line of rendered.split("\n")) {
      channel.appendLine(`    ${line}`);
    }
  }
}

/**
 * Open (or reveal) the AiSOC results webview and render `result`.
 *
 * `title` is the command name (e.g. "Run Triage") shown in the tab.
 * `subtitle` is the user-supplied context (e.g. the case id) so the user
 * can keep multiple invocations straight at a glance.
 */
export function showToolResultWebview(opts: {
  title: string;
  subtitle: string;
  result: McpToolResult;
}): void {
  const panel = vscode.window.createWebviewPanel(
    "aisocResult",
    `AiSOC: ${opts.title}`,
    { viewColumn: vscode.ViewColumn.Beside, preserveFocus: false },
    { enableScripts: false, retainContextWhenHidden: true },
  );
  panel.webview.html = renderHtml(opts.title, opts.subtitle, opts.result);
}

/**
 * Render an `McpToolResult` as a stand-alone HTML document. We avoid
 * scripts entirely so the default webview CSP (`default-src 'none';
 * style-src 'unsafe-inline'`) accepts the document without explicit
 * relaxation.
 */
function renderHtml(
  title: string,
  subtitle: string,
  result: McpToolResult,
): string {
  const textBlocks = result.content
    .map((c) => renderContentBlock(c))
    .filter(Boolean)
    .join("\n<hr/>\n");
  const structured = result.structuredContent;
  const structuredHtml =
    structured !== undefined
      ? `<section>
          <h2>Structured payload</h2>
          <pre><code>${escapeHtml(safeJsonStringify(structured))}</code></pre>
         </section>`
      : "";

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta http-equiv="Content-Security-Policy"
          content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; font-src data:;" />
    <title>AiSOC: ${escapeHtml(title)}</title>
    <style>
      :root {
        color-scheme: light dark;
        --bg: var(--vscode-editor-background, #1e1e1e);
        --fg: var(--vscode-editor-foreground, #d4d4d4);
        --border: var(--vscode-panel-border, #444);
        --accent: var(--vscode-textLink-foreground, #4ea3ff);
        --pre-bg: var(--vscode-textCodeBlock-background, rgba(255, 255, 255, 0.04));
      }
      body {
        margin: 0;
        padding: 1.5rem;
        font-family: var(--vscode-font-family, -apple-system, "Segoe UI", sans-serif);
        font-size: var(--vscode-font-size, 13px);
        color: var(--fg);
        background: var(--bg);
        line-height: 1.5;
      }
      header { margin-bottom: 1.25rem; }
      header h1 {
        font-size: 1.4rem;
        margin: 0 0 0.25rem 0;
      }
      header .subtitle {
        font-size: 0.95rem;
        opacity: 0.75;
      }
      section { margin: 1.25rem 0; }
      section h2 {
        font-size: 1rem;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        opacity: 0.8;
        margin: 0 0 0.5rem 0;
      }
      pre {
        background: var(--pre-bg);
        border: 1px solid var(--border);
        border-radius: 4px;
        padding: 0.75rem 1rem;
        overflow-x: auto;
        font-family: var(--vscode-editor-font-family, "SF Mono", Menlo, monospace);
        font-size: 0.85rem;
        white-space: pre-wrap;
        word-break: break-word;
      }
      hr {
        border: 0;
        border-top: 1px dashed var(--border);
        margin: 1rem 0;
      }
      .empty {
        opacity: 0.6;
        font-style: italic;
      }
    </style>
  </head>
  <body>
    <header>
      <h1>${escapeHtml(title)}</h1>
      <div class="subtitle">${escapeHtml(subtitle)}</div>
    </header>
    <section>
      <h2>Response</h2>
      ${textBlocks || '<div class="empty">No textual content returned.</div>'}
    </section>
    ${structuredHtml}
  </body>
</html>`;
}

/**
 * Convert a single MCP content block into HTML. We render text blocks as
 * `<pre>` to preserve the fenced-JSON formatting the server emits. Any
 * other block type (image, audio) falls back to a structured dump so the
 * data isn't silently dropped.
 */
function renderContentBlock(block: McpContentBlock): string {
  if (block.type === "text" && typeof block.text === "string") {
    return `<pre><code>${escapeHtml(block.text)}</code></pre>`;
  }
  return `<pre><code>${escapeHtml(safeJsonStringify(block))}</code></pre>`;
}

function escapeHtml(input: string): string {
  return input
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function safeJsonStringify(value: unknown): string {
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}
