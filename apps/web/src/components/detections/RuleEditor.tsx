'use client';

import { useEffect, useMemo, useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import dynamic from 'next/dynamic';
import useSWR from 'swr';
import { clsx } from 'clsx';
import toast from 'react-hot-toast';
import {
  detectionApi,
  type DetectionLanguage,
  type DetectionRule,
  type HuntResult,
} from '@/lib/api';
import type { AlertSeverity } from '@/lib/api';
import { Skeleton } from '@/components/ui/Skeleton';
import { ErrorState } from '@/components/ui/ErrorState';
import { ContextualActions } from '@/components/copilot/ContextualActions';

const MonacoEditor = dynamic(() => import('@monaco-editor/react'), {
  ssr: false,
  loading: () => <Skeleton className="h-full w-full" />,
});

// ─── Constants ────────────────────────────────────────────────────────────────

const LANGS: { id: DetectionLanguage; label: string; monaco: string }[] = [
  { id: 'sigma', label: 'Sigma', monaco: 'yaml' },
  { id: 'yara', label: 'YARA', monaco: 'plaintext' },
  { id: 'kql', label: 'KQL', monaco: 'sql' },
  { id: 'eql', label: 'EQL', monaco: 'sql' },
  { id: 'lucene', label: 'Lucene', monaco: 'plaintext' },
  { id: 'regex', label: 'Regex', monaco: 'plaintext' },
];

const SEVERITIES: AlertSeverity[] = ['low', 'medium', 'high', 'critical'];

const SAMPLE_BODIES: Record<DetectionLanguage, string> = {
  sigma: `title: My new detection
id: aisoc-rule-new
status: experimental
description: Describe what this rule catches
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains: '-EncodedCommand'
  condition: selection
level: medium
tags:
  - attack.execution
`,
  yara: `rule MySuspiciousBinary
{
    meta:
        author = "AiSOC"
        description = "Detects an embedded marker"
    strings:
        $a = "evil_marker"
    condition:
        $a
}
`,
  kql: `// Author your KQL here
SecurityEvent
| where EventID == 4625
| summarize FailedLogons = count() by Account, IpAddress, bin(TimeGenerated, 5m)
| where FailedLogons > 5
`,
  eql: `process where process.name == "powershell.exe" and
  process.command_line : "*EncodedCommand*"
`,
  lucene: `event.category:"process" AND process.name:"powershell.exe" AND process.command_line:*EncodedCommand*`,
  regex: `(?i)powershell\\.exe.*-encodedcommand\\s+[A-Za-z0-9+/=]{40,}`,
};

const SAMPLE_EVENT = JSON.stringify(
  {
    '@timestamp': new Date().toISOString(),
    host: { name: 'WIN-DC-01', os: { family: 'windows' } },
    process: {
      name: 'powershell.exe',
      command_line:
        'powershell.exe -NoProfile -EncodedCommand JABzAD0AJwBoAGUAbABsAG8AJwA=',
      pid: 4321,
    },
    user: { name: 'svc_backup' },
    event: { category: 'process', action: 'process_started' },
  },
  null,
  2,
);

// ─── Component ────────────────────────────────────────────────────────────────

interface RuleEditorProps {
  mode: 'create' | 'edit';
  ruleId?: string;
}

export function RuleEditor({ mode, ruleId }: RuleEditorProps) {
  const router = useRouter();

  // Load existing rule when editing
  const { data, error, isLoading, mutate } = useSWR(
    mode === 'edit' && ruleId ? `detection:rule:${ruleId}` : null,
    () => (ruleId ? detectionApi.get(ruleId) : null),
    { revalidateOnFocus: false, shouldRetryOnError: false },
  );

  // Form state
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [language, setLanguage] = useState<DetectionLanguage>('sigma');
  const [body, setBody] = useState(SAMPLE_BODIES.sigma);
  const [severity, setSeverity] = useState<AlertSeverity>('medium');
  const [enabled, setEnabled] = useState(true);
  const [tags, setTags] = useState<string[]>([]);
  const [mitre, setMitre] = useState<string[]>([]);
  const [tagInput, setTagInput] = useState('');
  const [mitreInput, setMitreInput] = useState('');

  // Test runner state
  const [sampleEvent, setSampleEvent] = useState(SAMPLE_EVENT);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{
    matches: number;
    preview: HuntResult[];
  } | null>(null);
  const [saving, setSaving] = useState(false);

  // Hydrate form when data arrives
  useEffect(() => {
    if (data) {
      setName(data.name);
      setDescription(data.description ?? '');
      setLanguage(data.language);
      setBody(data.body);
      setSeverity(data.severity ?? 'medium');
      setEnabled(data.enabled);
      setTags(data.tags ?? []);
      setMitre(data.mitre ?? []);
    }
  }, [data]);

  const monacoLang = useMemo(
    () => LANGS.find((l) => l.id === language)?.monaco ?? 'plaintext',
    [language],
  );

  // Loading state for edit
  if (mode === 'edit' && isLoading) {
    return (
      <div className="space-y-3">
        <Skeleton className="h-10 w-2/3" />
        <Skeleton className="h-96 w-full" />
      </div>
    );
  }

  if (mode === 'edit' && error) {
    return (
      <ErrorState
        title="Couldn't load this detection rule"
        description="The detection service is unreachable or the rule no longer exists."
        error={error}
        action={
          <Link
            href="/detection"
            className="rounded-md border border-gray-700 px-4 py-2 text-sm text-gray-300 hover:bg-gray-800"
          >
            Back to rules
          </Link>
        }
      />
    );
  }

  // ─── Handlers ──────────────────────────────────────────────────────────────

  const handleLanguageChange = (next: DetectionLanguage) => {
    // If body still matches the previous sample, swap to new sample
    if (Object.values(SAMPLE_BODIES).includes(body)) {
      setBody(SAMPLE_BODIES[next]);
    }
    setLanguage(next);
    setTestResult(null);
  };

  const addChip = (
    raw: string,
    list: string[],
    set: (next: string[]) => void,
    clear: () => void,
  ) => {
    const v = raw.trim().replace(/^#/, '');
    if (!v) return;
    if (list.includes(v)) {
      clear();
      return;
    }
    set([...list, v]);
    clear();
  };

  const handleTest = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      const result = await detectionApi.test({
        language,
        body,
        sample: sampleEvent,
      });
      setTestResult(result);
      if (result.matches > 0) {
        toast.success(`Match — ${result.matches} event(s)`);
      } else {
        toast(`No match against the sample`, { icon: '🔍' });
      }
    } catch (err) {
      console.warn('Test failed, using demo evaluator', err);
      const demo = evaluateDemo(language, body, sampleEvent);
      setTestResult(demo);
      if (demo.matches > 0) {
        toast.success(
          `Demo evaluator: matched ${demo.matches} event(s) (offline mode)`,
        );
      } else {
        toast('Demo evaluator: no match (offline mode)', { icon: '🧪' });
      }
    } finally {
      setTesting(false);
    }
  };

  const handleSave = async () => {
    if (!name.trim()) {
      toast.error('Rule name is required');
      return;
    }
    if (!body.trim()) {
      toast.error('Rule body is empty');
      return;
    }
    setSaving(true);
    const payload: Partial<DetectionRule> = {
      name: name.trim(),
      description: description.trim() || undefined,
      language,
      body,
      enabled,
      severity,
      tags: tags.length ? tags : undefined,
      mitre: mitre.length ? mitre : undefined,
    };

    try {
      if (mode === 'create') {
        const created = await detectionApi.create(payload);
        toast.success('Rule created');
        router.push(`/detection/${created.id}`);
      } else if (ruleId) {
        await detectionApi.update(ruleId, payload);
        toast.success('Rule saved');
        mutate();
      }
    } catch (err) {
      console.error('Save failed', err);
      toast.error('Backend unavailable — your changes were not persisted.');
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async () => {
    if (!ruleId) return;
    if (!confirm('Delete this rule? This cannot be undone.')) return;
    try {
      await detectionApi.delete(ruleId);
      toast.success('Rule deleted');
      router.push('/detection');
    } catch (err) {
      console.error('Delete failed', err);
      toast.error('Could not delete rule');
    }
  };

  // ─── Render ────────────────────────────────────────────────────────────────

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
        <div className="flex items-center gap-3">
          <Link
            href="/detection"
            className="text-sm text-gray-500 hover:text-gray-300"
          >
            ← Detection rules
          </Link>
          <span className="text-gray-700">/</span>
          <h1 className="truncate text-xl font-semibold text-gray-100">
            {mode === 'create' ? 'New rule' : (data?.name ?? 'Editing…')}
          </h1>
        </div>

        <div className="flex items-center gap-2">
          {mode === 'edit' && (
            <button
              onClick={handleDelete}
              className="rounded-md border border-red-500/30 bg-red-500/5 px-3 py-1.5 text-sm text-red-300 transition-colors hover:bg-red-500/10"
            >
              Delete
            </button>
          )}
          <button
            onClick={handleSave}
            disabled={saving}
            className={clsx(
              'inline-flex items-center gap-2 rounded-md bg-blue-500 px-4 py-2 text-sm font-medium text-white shadow-sm transition-colors',
              saving ? 'opacity-60' : 'hover:bg-blue-600',
            )}
          >
            {saving ? 'Saving…' : mode === 'create' ? 'Create rule' : 'Save'}
          </button>
        </div>
      </div>

      {/*
        Ambient Copilot — rule-scoped contextual AI. Only shown in edit mode where
        the rule has a stable id + body to reason about; new-rule drafts have no
        runtime stats so "why is this noisy?" doesn't apply yet. We pass the
        live form state (not just the persisted snapshot) so the LLM sees what
        the analyst is currently editing. Backed by `services/agents`
        `/api/v1/contextual` endpoints.
      */}
      {mode === 'edit' && data ? (
        <ContextualActions
          page="detections"
          entityId={data.id}
          entity={{
            id: data.id,
            name: name || data.name,
            description: description || data.description,
            language,
            body,
            severity: severity ?? data.severity,
            tags: tags.length ? tags : data.tags,
            mitre: mitre.length ? mitre : data.mitre,
            enabled: data.enabled,
            hit_count: data.hitCount,
            last_triggered_at: data.lastTriggeredAt,
          }}
          eyebrow="Ask AiSOC about this rule"
        />
      ) : null}

      {/* Body — two-column on lg+ */}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-[1fr_360px]">
        {/* Left: editor + test runner */}
        <div className="space-y-4">
          {/* Language pills */}
          <div className="flex flex-wrap items-center gap-2">
            {LANGS.map((l) => (
              <button
                key={l.id}
                type="button"
                onClick={() => handleLanguageChange(l.id)}
                className={clsx(
                  'rounded-md border px-3 py-1.5 text-xs font-medium transition-colors',
                  language === l.id
                    ? 'border-blue-500/60 bg-blue-500/10 text-blue-300'
                    : 'border-gray-800 bg-gray-900/40 text-gray-400 hover:bg-gray-800',
                )}
              >
                {l.label}
              </button>
            ))}
          </div>

          {/* Editor */}
          <div className="overflow-hidden rounded-lg border border-gray-800 bg-[#0d1117]">
            <div className="flex items-center justify-between border-b border-gray-800 px-3 py-2 text-xs text-gray-500">
              <span>
                {LANGS.find((l) => l.id === language)?.label} • detection logic
              </span>
              <span>{body.split('\n').length} lines</span>
            </div>
            <div className="h-[520px]">
              <MonacoEditor
                language={monacoLang}
                value={body}
                onChange={(val) => setBody(val ?? '')}
                theme="vs-dark"
                options={{
                  minimap: { enabled: false },
                  fontSize: 13,
                  fontFamily:
                    'JetBrains Mono, ui-monospace, SFMono-Regular, Menlo, monospace',
                  scrollBeyondLastLine: false,
                  wordWrap: 'on',
                  smoothScrolling: true,
                  padding: { top: 12, bottom: 12 },
                }}
              />
            </div>
          </div>

          {/* Test runner */}
          <div className="rounded-lg border border-gray-800 bg-gray-900/40">
            <div className="flex items-center justify-between border-b border-gray-800 px-4 py-2.5">
              <div>
                <h3 className="text-sm font-semibold text-gray-200">
                  Test against a sample event
                </h3>
                <p className="text-xs text-gray-500">
                  Paste a JSON event and evaluate this rule before going live.
                </p>
              </div>
              <button
                onClick={handleTest}
                disabled={testing}
                className={clsx(
                  'rounded-md bg-emerald-500/90 px-3 py-1.5 text-xs font-medium text-white transition-colors',
                  testing ? 'opacity-60' : 'hover:bg-emerald-500',
                )}
              >
                {testing ? 'Evaluating…' : 'Run test'}
              </button>
            </div>
            <div className="grid grid-cols-1 lg:grid-cols-2">
              <div className="border-b border-gray-800 lg:border-b-0 lg:border-r">
                <div className="px-3 py-1.5 text-[11px] uppercase tracking-wider text-gray-500">
                  Sample event (JSON)
                </div>
                <div className="h-56">
                  <MonacoEditor
                    language="json"
                    value={sampleEvent}
                    onChange={(val) => setSampleEvent(val ?? '')}
                    theme="vs-dark"
                    options={{
                      minimap: { enabled: false },
                      fontSize: 12,
                      scrollBeyondLastLine: false,
                      wordWrap: 'on',
                    }}
                  />
                </div>
              </div>
              <div>
                <div className="px-3 py-1.5 text-[11px] uppercase tracking-wider text-gray-500">
                  Result
                </div>
                <div className="h-56 overflow-y-auto px-4 py-3 text-sm">
                  {!testResult ? (
                    <div className="flex h-full items-center justify-center text-xs text-gray-600">
                      Click "Run test" to evaluate the rule.
                    </div>
                  ) : testResult.matches > 0 ? (
                    <div className="space-y-2">
                      <div className="inline-flex items-center gap-2 rounded-md bg-emerald-500/10 px-2 py-1 text-xs text-emerald-300 ring-1 ring-emerald-500/30">
                        <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
                        Matched {testResult.matches} event
                        {testResult.matches > 1 ? 's' : ''}
                      </div>
                      <pre className="max-h-40 overflow-auto rounded-md bg-gray-950 px-3 py-2 font-mono text-[11px] text-gray-300">
                        {JSON.stringify(testResult.preview[0] ?? {}, null, 2)}
                      </pre>
                    </div>
                  ) : (
                    <div className="inline-flex items-center gap-2 rounded-md bg-gray-800 px-2 py-1 text-xs text-gray-300 ring-1 ring-gray-700">
                      <span className="h-1.5 w-1.5 rounded-full bg-gray-500" />
                      No match — rule did not fire on this sample.
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Right: metadata sidebar */}
        <aside className="space-y-4">
          <FormSection label="Name" required>
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Suspicious PowerShell Encoded Command"
              className="w-full rounded-md border border-gray-800 bg-gray-950 px-3 py-2 text-sm text-gray-200 outline-none focus:border-blue-500/60"
            />
          </FormSection>

          <FormSection label="Description">
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              rows={3}
              placeholder="What does this rule catch? Why does it matter? Link to threat intel if useful."
              className="w-full resize-none rounded-md border border-gray-800 bg-gray-950 px-3 py-2 text-sm text-gray-200 outline-none focus:border-blue-500/60"
            />
          </FormSection>

          <FormSection label="Severity">
            <div className="grid grid-cols-4 gap-1.5">
              {SEVERITIES.map((sev) => (
                <button
                  key={sev}
                  type="button"
                  onClick={() => setSeverity(sev)}
                  className={clsx(
                    'rounded-md px-2 py-1.5 text-xs font-medium capitalize ring-1 transition-colors',
                    severity === sev
                      ? severityActive(sev)
                      : 'bg-gray-900/40 text-gray-400 ring-gray-800 hover:bg-gray-800',
                  )}
                >
                  {sev}
                </button>
              ))}
            </div>
          </FormSection>

          <FormSection label="Status">
            <button
              type="button"
              onClick={() => setEnabled((v) => !v)}
              className={clsx(
                'flex w-full items-center justify-between rounded-md border px-3 py-2 text-sm transition-colors',
                enabled
                  ? 'border-emerald-500/40 bg-emerald-500/5 text-emerald-300'
                  : 'border-gray-800 bg-gray-900/40 text-gray-400',
              )}
            >
              <span>
                {enabled ? 'Enabled — running live' : 'Disabled — not running'}
              </span>
              <span
                className={clsx(
                  'relative inline-flex h-5 w-9 items-center rounded-full transition-colors',
                  enabled ? 'bg-emerald-500/70' : 'bg-gray-700',
                )}
              >
                <span
                  className={clsx(
                    'inline-block h-4 w-4 transform rounded-full bg-white transition-transform',
                    enabled ? 'translate-x-4' : 'translate-x-0.5',
                  )}
                />
              </span>
            </button>
          </FormSection>

          <FormSection
            label="MITRE ATT&CK"
            hint="Tag the techniques (e.g. T1059.001) this rule covers."
          >
            <ChipInput
              value={mitreInput}
              onChange={setMitreInput}
              onCommit={() =>
                addChip(mitreInput, mitre, setMitre, () => setMitreInput(''))
              }
              placeholder="T1059.001"
              chips={mitre}
              onRemove={(t) => setMitre(mitre.filter((x) => x !== t))}
              chipClassName="bg-blue-500/10 text-blue-300 ring-blue-500/30"
            />
          </FormSection>

          <FormSection label="Tags">
            <ChipInput
              value={tagInput}
              onChange={setTagInput}
              onCommit={() =>
                addChip(tagInput, tags, setTags, () => setTagInput(''))
              }
              placeholder="windows, lolbin, cloud"
              chips={tags}
              onRemove={(t) => setTags(tags.filter((x) => x !== t))}
              chipClassName="bg-gray-800 text-gray-300 ring-gray-700"
            />
          </FormSection>

          {mode === 'edit' && data && (
            <div className="rounded-md border border-gray-800 bg-gray-900/40 p-3 text-xs text-gray-500">
              <div>
                Created{' '}
                <span className="text-gray-400">
                  {new Date(data.createdAt).toLocaleString()}
                </span>
              </div>
              <div className="mt-0.5">
                Updated{' '}
                <span className="text-gray-400">
                  {new Date(data.updatedAt).toLocaleString()}
                </span>
              </div>
              {data.hitCount != null && (
                <div className="mt-0.5">
                  <span className="font-mono text-gray-300">
                    {data.hitCount}
                  </span>{' '}
                  total hits
                </div>
              )}
            </div>
          )}
        </aside>
      </div>
    </div>
  );
}

// ─── Form helpers ─────────────────────────────────────────────────────────────

function FormSection({
  label,
  hint,
  required,
  children,
}: {
  label: string;
  hint?: string;
  required?: boolean;
  children: React.ReactNode;
}) {
  return (
    <div>
      <label className="flex items-baseline gap-1 text-xs font-medium uppercase tracking-wider text-gray-500">
        <span>{label}</span>
        {required && <span className="text-red-400">*</span>}
      </label>
      <div className="mt-1.5">{children}</div>
      {hint && <p className="mt-1 text-[11px] text-gray-600">{hint}</p>}
    </div>
  );
}

interface ChipInputProps {
  value: string;
  onChange: (v: string) => void;
  onCommit: () => void;
  chips: string[];
  onRemove: (chip: string) => void;
  placeholder: string;
  chipClassName?: string;
}

function ChipInput({
  value,
  onChange,
  onCommit,
  chips,
  onRemove,
  placeholder,
  chipClassName,
}: ChipInputProps) {
  return (
    <div className="space-y-2">
      <input
        value={value}
        onChange={(e) => onChange(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ',') {
            e.preventDefault();
            onCommit();
          }
        }}
        onBlur={() => value.trim() && onCommit()}
        placeholder={placeholder}
        className="w-full rounded-md border border-gray-800 bg-gray-950 px-3 py-2 text-sm text-gray-200 outline-none focus:border-blue-500/60"
      />
      {chips.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {chips.map((chip) => (
            <button
              key={chip}
              type="button"
              onClick={() => onRemove(chip)}
              className={clsx(
                'group inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-[11px] font-mono ring-1',
                chipClassName ?? 'bg-gray-800 text-gray-300 ring-gray-700',
              )}
            >
              {chip}
              <span className="text-gray-500 opacity-0 transition-opacity group-hover:opacity-100">
                ×
              </span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

function severityActive(sev: AlertSeverity): string {
  switch (sev) {
    case 'critical':
      return 'bg-red-500/15 text-red-300 ring-red-500/40';
    case 'high':
      return 'bg-orange-500/15 text-orange-300 ring-orange-500/40';
    case 'medium':
      return 'bg-yellow-500/15 text-yellow-300 ring-yellow-500/40';
    case 'low':
      return 'bg-blue-500/15 text-blue-300 ring-blue-500/40';
  }
}

// ─── Demo evaluator ───────────────────────────────────────────────────────────
// Used when the detection backend is unreachable. Light-touch heuristics so the
// UI feels responsive in offline / demo mode.

function evaluateDemo(
  language: DetectionLanguage,
  body: string,
  sampleRaw: string,
): { matches: number; preview: HuntResult[] } {
  let sample: Record<string, unknown> = {};
  try {
    sample = JSON.parse(sampleRaw);
  } catch {
    return { matches: 0, preview: [] };
  }

  const flat = flatten(sample);
  const lower = (s: string) => s.toLowerCase();

  let isMatch = false;

  if (language === 'sigma') {
    // Look for `contains:` and `endswith:` operands inside `detection:` block.
    const operands: string[] = [];
    const re = /(?:contains|endswith)\s*:\s*'([^']+)'|(?:contains|endswith)\s*:\s*"([^"]+)"/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(body))) {
      operands.push(m[1] ?? m[2] ?? '');
    }
    if (operands.length > 0) {
      isMatch = operands.every((needle) =>
        Object.values(flat).some((v) =>
          typeof v === 'string' && lower(v).includes(lower(needle)),
        ),
      );
    }
  } else if (language === 'regex') {
    try {
      const re = new RegExp(body, 'm');
      isMatch = Object.values(flat).some(
        (v) => typeof v === 'string' && re.test(v),
      );
    } catch {
      isMatch = false;
    }
  } else if (language === 'kql' || language === 'eql' || language === 'lucene') {
    // Pull bare-word literals out of the query and require any to be present.
    const tokens = body
      .split(/[\s,()='":\[\]<>!]+/)
      .filter(
        (t) =>
          t.length > 3 &&
          !/^(where|and|or|not|by|in|like|count|summarize|project|process|true|false|null|sequence|maxspan|with|extend|order|asc|desc)$/i.test(
            t,
          ),
      )
      .slice(0, 6);
    if (tokens.length > 0) {
      isMatch = tokens.some((tok) =>
        Object.values(flat).some(
          (v) => typeof v === 'string' && lower(v).includes(lower(tok)),
        ),
      );
    }
  } else if (language === 'yara') {
    const stringMatches = [...body.matchAll(/\$[a-zA-Z0-9_]+\s*=\s*"([^"]+)"/g)].map(
      (m) => m[1],
    );
    if (stringMatches.length > 0) {
      isMatch = stringMatches.some((needle) =>
        Object.values(flat).some(
          (v) => typeof v === 'string' && v.includes(needle),
        ),
      );
    }
  }

  if (!isMatch) return { matches: 0, preview: [] };

  const previewRow: HuntResult = {
    id: 'demo-match-1',
    timestamp:
      typeof sample['@timestamp'] === 'string'
        ? (sample['@timestamp'] as string)
        : new Date().toISOString(),
    source: 'sample-event',
    fields: flat,
  };
  return { matches: 1, preview: [previewRow] };
}

function flatten(
  obj: unknown,
  prefix = '',
  out: Record<string, unknown> = {},
): Record<string, unknown> {
  if (obj === null || typeof obj !== 'object') {
    out[prefix || 'value'] = obj as unknown;
    return out;
  }
  for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
    const next = prefix ? `${prefix}.${k}` : k;
    if (v && typeof v === 'object' && !Array.isArray(v)) {
      flatten(v, next, out);
    } else {
      out[next] = v;
    }
  }
  return out;
}
