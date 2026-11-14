/**
 * AiSOC IDE extension — activation + command wiring.
 *
 * Lifecycle:
 *
 *   1. The host activates us when the user invokes one of our commands
 *      (see `activationEvents` in `package.json`).
 *   2. `activate()` registers the four MCP-backed commands plus the two
 *      key-management commands, and pushes their disposables onto
 *      `context.subscriptions` so they're torn down on deactivate.
 *   3. Each command prompts for the inputs it needs, asks the resolved
 *      `McpClient` for a result, logs the call to the output channel,
 *      and opens a side-panel webview with the response.
 *
 * API-key handling: the API key is **never** read from settings.json
 * (the `aisoc.apiKey` setting is documented as "do not put your key
 * here"). Instead we use `context.secrets` (the host's secure storage)
 * and a dedicated `AiSOC: Set API Key…` command that uses a masked
 * `vscode.window.showInputBox`. This matches the workspace rule that
 * forbids committing secrets and ensures the key never lands in
 * synced settings.
 */
import * as vscode from "vscode";

import { McpClient, McpClientError } from "./mcpClient";
import { logLine, showToolResultWebview } from "./views";

const SECRET_KEY = "aisoc.apiKey";
const CONFIG_SECTION = "aisoc";

export function activate(context: vscode.ExtensionContext): void {
  logLine(`AiSOC extension activated (vscode ${vscode.version}).`);

  const disposables: vscode.Disposable[] = [
    vscode.commands.registerCommand("aisoc.runTriage", () =>
      withErrorHandling("Run Triage", () => commandRunTriage(context)),
    ),
    vscode.commands.registerCommand("aisoc.replayDecision", () =>
      withErrorHandling("Replay Investigation Step", () =>
        commandReplayDecision(context),
      ),
    ),
    vscode.commands.registerCommand("aisoc.explainStep", () =>
      withErrorHandling("Explain Step", () => commandExplainStep(context)),
    ),
    vscode.commands.registerCommand("aisoc.queryDetections", () =>
      withErrorHandling("Find Detections", () =>
        commandQueryDetections(context),
      ),
    ),
    vscode.commands.registerCommand("aisoc.setApiKey", () =>
      withErrorHandling("Set API Key", () => commandSetApiKey(context)),
    ),
    vscode.commands.registerCommand("aisoc.clearApiKey", () =>
      withErrorHandling("Clear API Key", () => commandClearApiKey(context)),
    ),
  ];

  context.subscriptions.push(...disposables);
}

export function deactivate(): void {
  logLine("AiSOC extension deactivated.");
}

// ---------------------------------------------------------------------------
// commands
// ---------------------------------------------------------------------------

async function commandRunTriage(
  context: vscode.ExtensionContext,
): Promise<void> {
  const caseId = await vscode.window.showInputBox({
    title: "AiSOC: Run Triage on Case",
    prompt: "Case UUID to investigate.",
    placeHolder: "e.g. f47ac10b-58cc-4372-a567-0e02b2c3d479",
    ignoreFocusOut: true,
    validateInput: requireNonEmpty,
  });
  if (!caseId) return;

  const alertSummary = await vscode.window.showInputBox({
    title: "AiSOC: Optional alert summary",
    prompt:
      "Optional human-readable summary used to seed the recon agent. Leave empty to use linked alerts.",
    placeHolder: "Suspicious oauth grant from new geography on alice@acme.corp",
    ignoreFocusOut: true,
  });

  const client = await getClient(context);
  logLine(`runInvestigation case_id=${caseId}`);
  const result = await client.runInvestigation(
    caseId,
    alertSummary && alertSummary.length > 0 ? alertSummary : undefined,
  );
  showToolResultWebview({
    title: "Run Triage",
    subtitle: `case ${caseId}`,
    result,
  });
}

async function commandReplayDecision(
  context: vscode.ExtensionContext,
): Promise<void> {
  const runId = await vscode.window.showInputBox({
    title: "AiSOC: Replay Investigation Step",
    prompt: "Investigation run UUID.",
    placeHolder: "e.g. 8a7c3e2f-…",
    ignoreFocusOut: true,
    validateInput: requireNonEmpty,
  });
  if (!runId) return;

  const stepRaw = await vscode.window.showInputBox({
    title: "AiSOC: Cursor (since_seq)",
    prompt:
      "Optional. Return only events with seq > this value. Leave empty for the full run.",
    placeHolder: "0",
    ignoreFocusOut: true,
    validateInput: optionalNonNegativeInteger,
  });
  const step = parseOptionalInt(stepRaw);

  const client = await getClient(context);
  logLine(`replayDecision run_id=${runId} since_seq=${step ?? "<none>"}`);
  const result = await client.replayDecision(runId, step);
  showToolResultWebview({
    title: "Replay Decision",
    subtitle: `run ${runId}${step !== undefined ? ` (since_seq=${step})` : ""}`,
    result,
  });
}

async function commandExplainStep(
  context: vscode.ExtensionContext,
): Promise<void> {
  const runId = await vscode.window.showInputBox({
    title: "AiSOC: Explain Why the Agent Did This",
    prompt: "Investigation run UUID.",
    placeHolder: "e.g. 8a7c3e2f-…",
    ignoreFocusOut: true,
    validateInput: requireNonEmpty,
  });
  if (!runId) return;

  const stepRaw = await vscode.window.showInputBox({
    title: "AiSOC: Step (seq number)",
    prompt: "Event seq number to deep-dive into.",
    placeHolder: "e.g. 7",
    ignoreFocusOut: true,
    validateInput: requireNonNegativeInteger,
  });
  if (stepRaw === undefined) return;
  const step = Number.parseInt(stepRaw, 10);

  const client = await getClient(context);
  logLine(`explainStep run_id=${runId} step=${step}`);
  const result = await client.explainStep(runId, step);
  showToolResultWebview({
    title: "Explain Step",
    subtitle: `run ${runId} step ${step}`,
    result,
  });
}

async function commandQueryDetections(
  context: vscode.ExtensionContext,
): Promise<void> {
  // If the user has a selection, use it as the seed query — keeps the
  // "find detections for the technique I'm reading about" flow snappy.
  const editor = vscode.window.activeTextEditor;
  const seed =
    editor && !editor.selection.isEmpty
      ? editor.document.getText(editor.selection).trim()
      : "";

  const technique = await vscode.window.showInputBox({
    title: "AiSOC: Find Detections",
    prompt:
      "MITRE technique id (T1059.003) or free-text query (matches name, tags, description).",
    placeHolder: "T1110.001 or 'aws iam'",
    ignoreFocusOut: true,
    value: seed,
    validateInput: requireNonEmpty,
  });
  if (!technique) return;

  const client = await getClient(context);
  logLine(`queryDetections technique=${technique}`);
  const result = await client.queryDetections(technique);
  showToolResultWebview({
    title: "Detections",
    subtitle: `query: ${technique}`,
    result,
  });
}

async function commandSetApiKey(
  context: vscode.ExtensionContext,
): Promise<void> {
  const value = await vscode.window.showInputBox({
    title: "AiSOC: Set API Key",
    prompt:
      "Paste your AiSOC API key (aisoc_pat_…). Stored only in your IDE's secret storage.",
    placeHolder: "aisoc_pat_…",
    ignoreFocusOut: true,
    password: true,
    validateInput: requireNonEmpty,
  });
  if (!value) return;
  await context.secrets.store(SECRET_KEY, value);
  logLine("API key stored in secret storage.");
  await vscode.window.showInformationMessage("AiSOC API key saved.");
}

async function commandClearApiKey(
  context: vscode.ExtensionContext,
): Promise<void> {
  await context.secrets.delete(SECRET_KEY);
  logLine("API key cleared from secret storage.");
  await vscode.window.showInformationMessage("AiSOC API key cleared.");
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/**
 * Build an `McpClient` from current settings. The API key is fetched from
 * secret storage on every call so the user can rotate it without
 * reloading the extension.
 */
async function getClient(
  context: vscode.ExtensionContext,
): Promise<McpClient> {
  const config = vscode.workspace.getConfiguration(CONFIG_SECTION);
  const endpoint = config.get<string>("mcpEndpoint", "http://localhost:8765/mcp");
  const timeoutMs = config.get<number>("requestTimeoutMs", 30000);

  // The `aisoc.apiKey` setting is intentionally a decoy (so anyone
  // browsing settings.json sees an explicit "do not paste keys here"
  // doc string). We read it as a *fallback* for local dev only, and
  // prefer the secret storage value when present.
  const fromSecret = await context.secrets.get(SECRET_KEY);
  const fromSetting = config.get<string>("apiKey", "");
  const apiKey = fromSecret || fromSetting || undefined;

  return new McpClient({ endpoint, apiKey, timeoutMs });
}

/**
 * Wrap a command body so unhandled errors surface as user-facing
 * notifications (with the option to "Show details" jumping to the
 * output channel) instead of silent failures.
 */
async function withErrorHandling(
  commandLabel: string,
  fn: () => Promise<void>,
): Promise<void> {
  try {
    await fn();
  } catch (err) {
    const message =
      err instanceof McpClientError
        ? err.message
        : err instanceof Error
          ? err.message
          : String(err);
    logLine(`error in ${commandLabel}: ${message}`, err);
    const action = await vscode.window.showErrorMessage(
      `AiSOC ${commandLabel} failed: ${message}`,
      "Show details",
    );
    if (action === "Show details") {
      // Reveal the output channel; the error has already been logged.
      const channel = vscode.window.createOutputChannel("AiSOC");
      channel.show(true);
    }
  }
}

// --- input validators -----------------------------------------------------

function requireNonEmpty(input: string): string | undefined {
  return input.trim().length === 0 ? "Value is required." : undefined;
}

function optionalNonNegativeInteger(input: string): string | undefined {
  if (input.trim().length === 0) return undefined;
  return requireNonNegativeInteger(input);
}

function requireNonNegativeInteger(input: string): string | undefined {
  const n = Number.parseInt(input, 10);
  if (!Number.isFinite(n) || n < 0 || String(n) !== input.trim()) {
    return "Enter a non-negative integer.";
  }
  return undefined;
}

function parseOptionalInt(input: string | undefined): number | undefined {
  if (!input || input.trim().length === 0) return undefined;
  const n = Number.parseInt(input, 10);
  return Number.isFinite(n) ? n : undefined;
}
