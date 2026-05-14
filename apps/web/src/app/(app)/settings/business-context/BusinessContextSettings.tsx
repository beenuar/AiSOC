"use client";

/**
 * Business Context settings — composed view.
 *
 * Owns the Monaco YAML editor + rule-builder side-panel + live preview.
 * Talks to the API directly via ``fetch`` (rather than a typed client
 * helper) so this whole feature lives in one directory and we can ship
 * the explicit-paths-only commit cleanly.
 */
import dynamic from "next/dynamic";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import {
  type PreviewResponse,
  type PreviewRow,
  type RulesEnvelope,
  loadRules,
  previewRules,
  saveRules,
} from "./client";
import { RuleBuilder } from "./RuleBuilder";
import { PreviewTable } from "./PreviewTable";

const MonacoEditor = dynamic(() => import("@monaco-editor/react"), {
  ssr: false,
  loading: () => (
    <div className="flex h-full items-center justify-center text-sm text-slate-500">
      Loading editor...
    </div>
  ),
});

const STARTER_YAML = `# Business context rules — YAML.
# Each rule mutates a fused alert before it reaches the triage agent.
# Supported actions: set_severity, route_to, tag, suppress.
#
# Hit "Save" to apply; the live preview re-runs automatically on every
# keystroke (debounced) so you can see the impact on your last 50
# alerts before committing.
rules:
  - id: prod-iam-during-business-hours
    description: Wake tier-2 for any prod IAM touch during business hours.
    priority: 10
    when:
      all:
        - field: alert.target.tag
          op: eq
          value: prod
        - field: alert.time.is_business_hours
          op: eq
          value: true
    then:
      set_severity: critical
      route_to: tier2
      tag: business-hours-prod
`;

export function BusinessContextSettings() {
  const [yaml, setYaml] = useState<string>(STARTER_YAML);
  const [envelope, setEnvelope] = useState<RulesEnvelope | null>(null);
  const [preview, setPreview] = useState<PreviewResponse | null>(null);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [previewing, setPreviewing] = useState(false);
  const [dirty, setDirty] = useState(false);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Initial load — pull whatever the tenant currently has saved.
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const env = await loadRules();
        if (cancelled) return;
        setEnvelope(env);
        if (env.yaml.trim().length > 0) {
          setYaml(env.yaml);
        }
      } catch (err) {
        if (cancelled) return;
        setSaveError((err as Error).message);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  // Debounced preview — fires 300ms after the editor stops changing.
  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => {
      void runPreview(yaml);
    }, 300);
    return () => {
      if (debounceRef.current) clearTimeout(debounceRef.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [yaml]);

  const runPreview = useCallback(async (currentYaml: string) => {
    setPreviewing(true);
    setPreviewError(null);
    try {
      const resp = await previewRules(currentYaml);
      setPreview(resp);
    } catch (err) {
      setPreviewError((err as Error).message);
      setPreview(null);
    } finally {
      setPreviewing(false);
    }
  }, []);

  const handleSave = useCallback(async () => {
    setSaving(true);
    setSaveError(null);
    try {
      const env = await saveRules(yaml);
      setEnvelope(env);
      setDirty(false);
    } catch (err) {
      setSaveError((err as Error).message);
    } finally {
      setSaving(false);
    }
  }, [yaml]);

  const handleAppendRule = useCallback((snippet: string) => {
    setYaml((prev) => {
      const trimmed = prev.replace(/\s+$/, "");
      // If the document already has a `rules:` list, append under it;
      // otherwise wrap the snippet in a `rules:` list of its own so the
      // resulting YAML stays a single document the parser accepts.
      if (/^\s*rules:/m.test(trimmed)) {
        return `${trimmed}\n${snippet}\n`;
      }
      return `rules:\n${snippet}\n`;
    });
    setDirty(true);
  }, []);

  const summaryLine = useMemo(() => {
    if (!preview) return null;
    const { sample_size, changed_count, suppressed_count, elapsed_ms } = preview;
    if (sample_size === 0) {
      return "No alerts available for the dry-run preview yet.";
    }
    return (
      `${changed_count} of ${sample_size} sample alerts would be mutated` +
      (suppressed_count > 0 ? ` (${suppressed_count} suppressed)` : "") +
      ` — preview ran in ${elapsed_ms.toFixed(1)} ms.`
    );
  }, [preview]);

  return (
    <div className="flex h-full flex-col gap-4 p-6">
      <header className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold text-slate-100">
            Business Context Rules
          </h1>
          <p className="max-w-2xl text-sm text-slate-400">
            Encode your operational reality between fusion and the triage
            agent — bump severity for prod, route AWS alerts to the cloud
            team, suppress alerts during a known maintenance window. Rules
            run in priority order; the last matching action wins.
          </p>
        </div>
        <div className="flex items-center gap-3">
          {envelope ? (
            <span className="text-xs text-slate-500">
              version {envelope.version} · saved{" "}
              {new Date(envelope.updated_at).toLocaleTimeString()}
            </span>
          ) : null}
          <button
            type="button"
            onClick={handleSave}
            disabled={saving}
            className="rounded-md bg-indigo-600 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-indigo-500 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {saving ? "Saving..." : dirty ? "Save changes" : "Save"}
          </button>
        </div>
      </header>

      {saveError ? (
        <div
          role="alert"
          className="rounded-md border border-rose-500/40 bg-rose-950/40 p-3 text-sm text-rose-200"
        >
          {saveError}
        </div>
      ) : null}

      <div className="grid flex-1 grid-cols-1 gap-4 lg:grid-cols-3">
        <section className="col-span-2 flex min-h-[420px] flex-col rounded-md border border-slate-700 bg-slate-950">
          <div className="border-b border-slate-800 px-3 py-2 text-xs font-medium uppercase tracking-wide text-slate-500">
            YAML editor
          </div>
          <div className="flex-1">
            <MonacoEditor
              language="yaml"
              theme="vs-dark"
              value={yaml}
              options={{
                fontSize: 13,
                minimap: { enabled: false },
                automaticLayout: true,
                tabSize: 2,
              }}
              onChange={(value) => {
                setYaml(value ?? "");
                setDirty(true);
              }}
            />
          </div>
        </section>

        <section className="flex min-h-[420px] flex-col rounded-md border border-slate-700 bg-slate-950">
          <div className="border-b border-slate-800 px-3 py-2 text-xs font-medium uppercase tracking-wide text-slate-500">
            Rule builder
          </div>
          <div className="flex-1 overflow-auto p-3">
            <RuleBuilder onAppend={handleAppendRule} />
          </div>
        </section>
      </div>

      <section className="rounded-md border border-slate-700 bg-slate-950">
        <header className="flex items-center justify-between border-b border-slate-800 px-3 py-2">
          <div className="text-xs font-medium uppercase tracking-wide text-slate-500">
            Live preview
          </div>
          <div className="flex items-center gap-2 text-xs text-slate-400">
            {previewing ? "Recomputing..." : summaryLine}
          </div>
        </header>
        <div className="max-h-[360px] overflow-auto">
          {previewError ? (
            <div className="p-3 text-sm text-rose-300">{previewError}</div>
          ) : preview ? (
            <PreviewTable rows={preview.rows} />
          ) : (
            <div className="p-3 text-sm text-slate-500">
              Edit the YAML above to see a before/after diff against your last
              50 alerts.
            </div>
          )}
        </div>
      </section>
    </div>
  );
}

export type { PreviewRow };
