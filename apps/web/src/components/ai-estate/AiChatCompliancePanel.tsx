"use client";

/**
 * Enable and read enterprise AI-chat compliance collection (wave 2, 7.1).
 *
 * This panel is the reason the feature is "enabled per tenant through a real
 * console surface" rather than through a configuration file. Everything it
 * does is a real call: there is no toast-only control here, and no sample
 * data anywhere in it.
 *
 * Three rendering decisions carry weight:
 *
 * 1. **Two switches, and the stricter one is separate.** Turning on
 *    collection does not turn on anything derived from message text. The
 *    second switch is disabled until the first is on, and its help text says
 *    plainly what it reads and what it stores.
 * 2. **Never-run and found-nothing are different states.** An unconfigured
 *    tenant, a configured tenant that has not polled yet, and a tenant whose
 *    feed is genuinely empty render as three distinct things. Showing a
 *    confident zero for the first two is the failure this page exists to
 *    avoid.
 * 3. **A read failure says so.** It never renders as "no AI chat activity",
 *    because that is the one false statement a compliance surface must not
 *    make.
 *
 * The key is write-only by design: the API returns `hasKey`, never the value
 * and never a masked form of it, because a mask still tells you the length.
 */

import { useEffect, useState } from "react";
import useSWR, { mutate } from "swr";
import { apiHeaders } from "@/lib/api";

const CONFIG_URL = "/api/v1/ai-chat-compliance/config";
const LABELS_URL = "/api/v1/ai-chat-compliance/content-labels";

interface Config {
  configured: boolean;
  provider: string | null;
  enabled: boolean;
  contentLabels: boolean;
  hasKey: boolean;
  lastCollectedAt: string | null;
  lastError: string | null;
}

interface ContentLabel {
  id: string;
  chatExternalId: string;
  actorEmail: string | null;
  labels: string[];
  secretKinds: string[];
  snippet: string | null;
  snippetTruncated: boolean;
  messagesExamined: number;
  messagesMatched: number;
  occurredAt: string;
}

interface LabelList {
  items: ContentLabel[];
  total: number;
  contentLabelsEnabled: boolean;
}

const LABEL_COPY: Record<string, string> = {
  secrets: "Credential material",
  personal_data: "Personal data",
  regulated: "Regulated identifier",
  financial: "Financial data",
};

async function getJson<T>(url: string): Promise<T> {
  const res = await fetch(url, { headers: apiHeaders() });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return (await res.json()) as T;
}

export function AiChatCompliancePanel() {
  const config = useSWR<Config>(CONFIG_URL, getJson);
  const labels = useSWR<LabelList>(LABELS_URL, getJson);

  const [provider, setProvider] = useState("anthropic");
  const [accessKey, setAccessKey] = useState("");
  const [enabled, setEnabled] = useState(false);
  const [contentLabels, setContentLabels] = useState(false);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);

  // Seed the switches from the server once it has answered, so the form
  // shows the tenant's real state rather than defaults that would silently
  // turn something off on the next save.
  useEffect(() => {
    if (config.data?.configured) {
      setProvider(config.data.provider ?? "anthropic");
      setEnabled(config.data.enabled);
      setContentLabels(config.data.contentLabels);
    }
  }, [config.data]);

  async function save() {
    setSaving(true);
    setSaveError(null);
    try {
      const res = await fetch(CONFIG_URL, {
        method: "PUT",
        headers: { ...apiHeaders(), "Content-Type": "application/json" },
        body: JSON.stringify({ provider, accessKey, enabled, contentLabels }),
      });
      if (!res.ok) {
        const detail = await res.text();
        throw new Error(detail || `${res.status} ${res.statusText}`);
      }
      setAccessKey("");
      await mutate(CONFIG_URL);
      await mutate(LABELS_URL);
    } catch (err) {
      setSaveError(err instanceof Error ? err.message : "Could not save the configuration.");
    } finally {
      setSaving(false);
    }
  }

  if (config.error) {
    return (
      <section className="rounded border border-red-700 bg-red-950/40 p-4">
        <h2 className="font-semibold text-red-200">AI chat compliance: could not read the configuration</h2>
        <p className="mt-1 text-sm text-red-300">
          {String(config.error)}. This is a failure to read, not an empty result — nothing below should be
          taken as a statement about your AI chat activity.
        </p>
      </section>
    );
  }

  const data = config.data;

  return (
    <section className="space-y-4 rounded border border-neutral-700 p-4">
      <header>
        <h2 className="font-semibold">Enterprise AI chat compliance</h2>
        <p className="mt-1 text-sm text-neutral-400">
          Reads your AI provider&apos;s compliance API for the directory, projects and activity feed. Off
          until you add a key here. AiSOC stores classification labels and one 280-character masked
          snippet per conversation, never the conversation.
        </p>
      </header>

      <div className="space-y-3">
        <label className="block text-sm">
          <span className="text-neutral-300">Provider</span>
          <select
            className="mt-1 w-full rounded border border-neutral-700 bg-neutral-900 p-2"
            value={provider}
            onChange={(e) => setProvider(e.target.value)}
          >
            <option value="anthropic">Anthropic (Claude Enterprise / Console)</option>
          </select>
        </label>

        <label className="block text-sm">
          <span className="text-neutral-300">
            Compliance Access Key{data?.hasKey ? " (one is stored; type a new one to replace it)" : ""}
          </span>
          <input
            type="password"
            autoComplete="off"
            className="mt-1 w-full rounded border border-neutral-700 bg-neutral-900 p-2 font-mono"
            placeholder="sk-ant-api01-…"
            value={accessKey}
            onChange={(e) => setAccessKey(e.target.value)}
          />
          <span className="mt-1 block text-xs text-neutral-500">
            Encrypted by the credential vault before it is written, and never returned by the API. An
            Admin API key reaches the activity feed only.
          </span>
        </label>

        <label className="flex items-start gap-2 text-sm">
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
          <span>
            <span className="text-neutral-200">Collect the directory, projects and activity feed</span>
            <span className="mt-0.5 block text-xs text-neutral-500">
              Users, roles, projects, and who did what and when. No message content is read.
            </span>
          </span>
        </label>

        <label className="flex items-start gap-2 text-sm">
          <input
            type="checkbox"
            checked={contentLabels}
            disabled={!enabled}
            onChange={(e) => setContentLabels(e.target.checked)}
          />
          <span>
            <span className="text-neutral-200">Also classify message content</span>
            <span className="mt-0.5 block text-xs text-neutral-500">
              Reads messages in memory to label a conversation as containing credentials, personal data,
              regulated identifiers or financial data. Stores the labels, the shape names and one masked
              snippet of at most 280 characters. The conversation is not stored and is not sent anywhere.
            </span>
          </span>
        </label>

        <button
          type="button"
          onClick={save}
          disabled={saving || (!accessKey && !data?.hasKey)}
          className="rounded bg-blue-700 px-3 py-1.5 text-sm font-medium disabled:opacity-50"
        >
          {saving ? "Saving…" : "Save"}
        </button>
        {saveError ? <p className="text-sm text-red-400">{saveError}</p> : null}
      </div>

      {data ? (
        <p className="text-xs text-neutral-500">
          {!data.configured
            ? "Not configured. Nothing is collected for this tenant."
            : data.lastError
              ? `Last collection failed: ${data.lastError}`
              : data.lastCollectedAt
                ? `Last collected ${new Date(data.lastCollectedAt).toLocaleString()}.`
                : "Configured, but collection has not run yet. This is not the same as finding nothing."}
        </p>
      ) : null}

      <div>
        <h3 className="text-sm font-semibold">Classified conversations</h3>
        {labels.error ? (
          <p className="mt-1 text-sm text-red-400">
            Could not read the classification results: {String(labels.error)}. This is a read failure, not
            an empty result.
          </p>
        ) : !labels.data ? (
          <p className="mt-1 text-sm text-neutral-500">Loading…</p>
        ) : !labels.data.contentLabelsEnabled ? (
          <p className="mt-1 text-sm text-neutral-500">
            Content classification is off, so there is nothing to show. That is a setting, not a result.
          </p>
        ) : labels.data.items.length === 0 ? (
          <p className="mt-1 text-sm text-neutral-500">
            No conversation has matched a classifier yet.
          </p>
        ) : (
          <ul className="mt-2 space-y-2">
            {labels.data.items.map((row) => (
              <li key={row.id} className="rounded border border-neutral-800 p-2 text-sm">
                <div className="flex flex-wrap items-center gap-2">
                  {row.labels.map((label) => (
                    <span key={label} className="rounded bg-amber-900/60 px-1.5 py-0.5 text-xs">
                      {LABEL_COPY[label] ?? label}
                    </span>
                  ))}
                  <span className="text-neutral-400">{row.actorEmail ?? "actor not learned"}</span>
                  <span className="text-neutral-600">{new Date(row.occurredAt).toLocaleString()}</span>
                </div>
                {row.snippet ? (
                  <pre className="mt-1 overflow-x-auto whitespace-pre-wrap break-all rounded bg-neutral-900 p-2 font-mono text-xs text-neutral-300">
                    {row.snippet}
                    {row.snippetTruncated ? "…" : ""}
                  </pre>
                ) : null}
                <p className="mt-1 text-xs text-neutral-500">
                  {row.messagesMatched} of {row.messagesExamined} messages matched
                  {row.secretKinds.length > 0 ? ` · ${row.secretKinds.join(", ")}` : ""}
                </p>
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}
