'use client';

/**
 * PlaybookEditor
 * ==============
 * Full-page playbook editor. Shows:
 *  - Left: metadata panel (name, description, trigger)
 *  - Centre: React Flow canvas
 *  - Right: step inspector (when step selected)
 *  - Bottom toolbar: save, run, add step, undo/redo
 *
 * WS-F4 polish: every mutation that flows through `setPlaybook` is now
 * captured in a `useHistoryState` undo/redo stack. Remote loads sync via
 * `controls.replace(...)` so they don't pollute history. Cmd/Ctrl-Z and
 * Cmd/Ctrl-Shift-Z (or Ctrl-Y on Windows-style keyboards) trigger undo/redo
 * globally while the editor is mounted, except when focus is in a text
 * input — that lets the browser's native input undo keep working.
 */

import React, { useState, useCallback, useEffect, useMemo } from 'react';
import { useRouter } from 'next/navigation';
import useSWR, { mutate } from 'swr';
import { PlaybookFlowCanvas } from './PlaybookFlowCanvas';
import { StepInspector } from './StepInspector';
import type { Playbook, PlaybookStep, StepType } from './types';
import { STEP_TYPE_META } from './stepColors';
import { defaultParamsFor } from './stepSchemas';
import { ContextualActions } from '@/components/copilot/ContextualActions';
import { useHistoryState } from '@/hooks/useHistoryState';

const STEP_TYPES: StepType[] = [
  'enrich',
  'investigate',
  'notify',
  'block_ip',
  'isolate_host',
  'create_ticket',
  'close_case',
  'http',
  'condition',
];

function generateId(): string {
  return Math.random().toString(36).slice(2, 10);
}

function makeNewStep(type: StepType): PlaybookStep {
  return {
    id: generateId(),
    name: `New ${STEP_TYPE_META[type].label} step`,
    type,
    // Honour each step kind's default param shape so the new step is
    // immediately valid for the schema-driven inspector form.
    params: defaultParamsFor(type),
    on_failure: 'abort',
    retry_max: 0,
    timeout_seconds: 30,
  };
}

const fetcher = (url: string) =>
  fetch(url).then((r) => {
    if (!r.ok) throw new Error('Failed to fetch');
    return r.json();
  });

/* ───────────────────────────── Trigger editor ───────────────────────────── */

function TriggerBadge({
  on,
  severity,
}: {
  on: string;
  severity?: string[];
}) {
  const colorMap: Record<string, string> = {
    alert: 'bg-red-900/50 text-red-300 border-red-800',
    case: 'bg-blue-900/50 text-blue-300 border-blue-800',
    manual: 'bg-gray-800 text-gray-300 border-gray-700',
    schedule: 'bg-purple-900/50 text-purple-300 border-purple-800',
  };
  return (
    <div
      className={`inline-flex items-center gap-1.5 text-xs px-2 py-1 rounded border ${colorMap[on] ?? 'bg-gray-800 text-gray-400 border-gray-700'}`}
    >
      <span className="font-medium">on:{on}</span>
      {severity && severity.length > 0 && (
        <span className="opacity-70">[{severity.join(', ')}]</span>
      )}
    </div>
  );
}

/* ─────────────────────────────── Main ─────────────────────────────── */

interface PlaybookEditorProps {
  playbookId: string;
}

const EMPTY_PLAYBOOK: Playbook = {
  id: '',
  name: 'Untitled Playbook',
  description: '',
  version: '1.0.0',
  tags: [],
  trigger: { on: 'manual' },
  steps: [],
  author: 'AiSOC',
  enabled: true,
  created_at: '',
  updated_at: '',
};

export function PlaybookEditor({ playbookId }: PlaybookEditorProps) {
  const router = useRouter();
  const isNew = playbookId === 'new';

  const { data: remote, isLoading } = useSWR<Playbook>(
    !isNew ? `/api/v1/playbooks/${playbookId}` : null,
    fetcher,
  );

  const [playbook, history] = useHistoryState<Playbook>(EMPTY_PLAYBOOK);
  const setPlaybook = history.set;

  // Sync remote data once loaded — use replace() so the load doesn't push
  // an extra entry onto the history stack.
  const [synced, setSynced] = useState(false);
  useEffect(() => {
    if (remote && !synced) {
      history.reset(remote);
      setSynced(true);
    }
  }, [remote, synced, history]);

  // T3.7 — NL drafter seed. When the new-playbook route is entered via
  // the "Draft from prompt" flow, the drafted Playbook is parked in
  // sessionStorage under "aisoc:nl-draft" by /playbooks/new. Pick it up
  // ONCE, hydrate the editor, then immediately wipe the key so reload
  // doesn't re-seed the same draft. Use history.reset() so the seed
  // doesn't push an empty playbook onto the undo stack.
  useEffect(() => {
    if (!isNew || synced) return;
    if (typeof window === 'undefined') return;
    try {
      const raw = sessionStorage.getItem('aisoc:nl-draft');
      if (!raw) return;
      sessionStorage.removeItem('aisoc:nl-draft');
      const draft = JSON.parse(raw) as Playbook;
      if (draft && typeof draft === 'object' && Array.isArray(draft.steps)) {
        history.reset(draft);
        setSynced(true);
      }
    } catch {
      // Malformed sessionStorage payload — fall back to the empty playbook.
    }
  }, [isNew, synced, history]);

  const [selectedStepId, setSelectedStepId] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [running, setRunning] = useState(false);
  const [runResult, setRunResult] = useState<string | null>(null);
  const [showAddStep, setShowAddStep] = useState(false);
  const [editMeta, setEditMeta] = useState(false);

  const selectedStep = useMemo(
    () => playbook.steps.find((s) => s.id === selectedStepId) ?? null,
    [playbook.steps, selectedStepId],
  );

  /* ── Callbacks ── */

  const updateStep = useCallback(
    (updated: PlaybookStep) => {
      setPlaybook((pb) => ({
        ...pb,
        steps: pb.steps.map((s) => (s.id === updated.id ? updated : s)),
      }));
    },
    [setPlaybook],
  );

  const deleteStep = useCallback(
    (id: string) => {
      setPlaybook((pb) => ({
        ...pb,
        steps: pb.steps.filter((s) => s.id !== id),
      }));
      setSelectedStepId(null);
    },
    [setPlaybook],
  );

  const addStep = useCallback(
    (type: StepType) => {
      const step = makeNewStep(type);
      setPlaybook((pb) => ({ ...pb, steps: [...pb.steps, step] }));
      setSelectedStepId(step.id);
      setShowAddStep(false);
    },
    [setPlaybook],
  );

  const handleStepsChange = useCallback(
    (steps: PlaybookStep[]) => {
      setPlaybook((p) => ({ ...p, steps }));
    },
    [setPlaybook],
  );

  /* ── Undo / redo keyboard shortcuts ── */

  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      const target = e.target as HTMLElement | null;
      if (target) {
        // Don't swallow native input undo while the user is typing.
        const tag = target.tagName;
        if (tag === 'INPUT' || tag === 'TEXTAREA' || target.isContentEditable) {
          return;
        }
      }
      const mod = e.metaKey || e.ctrlKey;
      if (!mod) return;
      const key = e.key.toLowerCase();
      // Cmd/Ctrl + Z = undo (no Shift)
      if (key === 'z' && !e.shiftKey) {
        e.preventDefault();
        history.undo();
        return;
      }
      // Cmd/Ctrl + Shift + Z = redo, or Cmd/Ctrl + Y = redo
      if ((key === 'z' && e.shiftKey) || key === 'y') {
        e.preventDefault();
        history.redo();
      }
    }
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [history]);

  const handleSave = async () => {
    setSaving(true);
    setRunResult(null);
    try {
      const url = isNew
        ? '/api/v1/playbooks'
        : `/api/v1/playbooks/${playbook.id}`;
      const method = isNew ? 'POST' : 'PUT';
      const body = isNew ? playbook : { ...playbook };
      const res = await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (!res.ok) throw new Error(await res.text());
      const saved: Playbook = await res.json();
      // Save reset: post-save state is the new "clean" baseline, so wipe
      // any historical drafts that no longer match the persisted record.
      history.reset(saved);
      setSynced(true);
      await mutate('/api/v1/playbooks');
      if (isNew) router.replace(`/playbooks/${saved.id}`);
      setRunResult('Saved');
    } catch (err) {
      setRunResult(
        `Save failed: ${err instanceof Error ? err.message : String(err)}`,
      );
    } finally {
      setSaving(false);
    }
  };

  const handleRun = async () => {
    if (!playbook.id) {
      setRunResult('Save the playbook first');
      return;
    }
    setRunning(true);
    setRunResult(null);
    try {
      const res = await fetch(`/api/v1/playbooks/${playbook.id}/run`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ context: {}, dry_run: true }),
      });
      if (!res.ok) throw new Error(await res.text());
      const data = await res.json();
      setRunResult(`Dry run started — run_id: ${data.run_id}`);
    } catch (err) {
      setRunResult(
        `Run failed: ${err instanceof Error ? err.message : String(err)}`,
      );
    } finally {
      setRunning(false);
    }
  };

  if (!isNew && isLoading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="text-gray-500">Loading playbook…</div>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full bg-gray-950 text-white">
      {/* ── Top bar ── */}
      <div className="flex items-center gap-4 px-5 h-14 border-b border-gray-800/60 bg-gray-900/80 flex-shrink-0">
        <button
          onClick={() => router.back()}
          className="text-gray-500 hover:text-gray-300 transition-colors"
        >
          Back
        </button>

        <div className="flex-1 flex items-center gap-3 overflow-hidden">
          {editMeta ? (
            <input
              autoFocus
              value={playbook.name}
              onChange={(e) =>
                setPlaybook((p) => ({ ...p, name: e.target.value }))
              }
              onBlur={() => setEditMeta(false)}
              className="bg-transparent border-b border-blue-500 text-white text-lg font-semibold focus:outline-none w-64"
            />
          ) : (
            <button
              onClick={() => setEditMeta(true)}
              className="text-white text-lg font-semibold truncate hover:text-blue-300 transition-colors"
              title="Click to rename"
            >
              {playbook.name}
            </button>
          )}
          <TriggerBadge
            on={playbook.trigger.on}
            severity={playbook.trigger.severity}
          />
          <span className="text-xs text-gray-600">v{playbook.version}</span>
          <span
            className={`text-xs px-2 py-0.5 rounded-full border ${playbook.enabled ? 'border-green-800 text-green-400 bg-green-950/50' : 'border-gray-700 text-gray-500'}`}
          >
            {playbook.enabled ? 'enabled' : 'disabled'}
          </span>
        </div>

        <div className="flex items-center gap-2">
          {/* Undo / redo buttons */}
          <button
            onClick={() => history.undo()}
            disabled={!history.canUndo}
            title="Undo (⌘Z)"
            aria-label="Undo"
            className="text-xs px-2.5 py-1.5 rounded border border-gray-700 text-gray-400 hover:bg-gray-800 transition-colors disabled:opacity-30 disabled:cursor-not-allowed"
          >
            ↶
          </button>
          <button
            onClick={() => history.redo()}
            disabled={!history.canRedo}
            title="Redo (⌘⇧Z)"
            aria-label="Redo"
            className="text-xs px-2.5 py-1.5 rounded border border-gray-700 text-gray-400 hover:bg-gray-800 transition-colors disabled:opacity-30 disabled:cursor-not-allowed"
          >
            ↷
          </button>
          <div className="h-5 w-px bg-gray-800" />
          <button
            onClick={() => setShowAddStep(true)}
            className="text-xs px-3 py-1.5 rounded border border-blue-700 text-blue-400 hover:bg-blue-900/30 transition-colors"
          >
            + Add Step
          </button>
          <button
            onClick={handleRun}
            disabled={running || isNew}
            className="text-xs px-3 py-1.5 rounded border border-green-800 text-green-400 hover:bg-green-900/30 transition-colors disabled:opacity-40"
            title={isNew ? 'Save first' : 'Dry run'}
          >
            {running ? 'Running…' : 'Dry run'}
          </button>
          <button
            onClick={handleSave}
            disabled={saving}
            className="text-xs px-4 py-1.5 rounded bg-blue-600 hover:bg-blue-500 text-white font-medium transition-colors disabled:opacity-50"
          >
            {saving ? 'Saving…' : 'Save'}
          </button>
        </div>
      </div>

      {/* ── Result banner ── */}
      {runResult && (
        <div className="px-5 py-2 bg-gray-900/60 text-sm border-b border-gray-800/60 flex items-center justify-between">
          <span className="text-gray-300">{runResult}</span>
          <button
            onClick={() => setRunResult(null)}
            className="text-gray-600 hover:text-gray-400 text-xs"
          >
            Dismiss
          </button>
        </div>
      )}

      {/*
        Ambient Copilot — playbook-scoped contextual AI. Only rendered for saved
        playbooks (`!isNew && playbook.id`); brand-new drafts have no real
        steps to reason about yet. We pass a compact snapshot of the live form
        state (not just the persisted record) so "explain this playbook" /
        "suggest improvements" reflect the user's in-flight edits. Backed by
        `services/agents` `/api/v1/contextual` endpoints.
      */}
      {!isNew && playbook.id ? (
        <div className="px-5 py-3 border-b border-gray-800/60 bg-gray-900/30">
          <ContextualActions
            page="playbooks"
            entityId={playbook.id}
            entity={{
              id: playbook.id,
              name: playbook.name,
              description: playbook.description,
              version: playbook.version,
              tags: playbook.tags,
              trigger: playbook.trigger,
              enabled: playbook.enabled,
              step_count: playbook.steps.length,
              steps: playbook.steps.map((s) => ({
                id: s.id,
                type: s.type,
                name: s.name,
              })),
            }}
            eyebrow="Ask AiSOC about this playbook"
          />
        </div>
      ) : null}

      {/* ── Body ── */}
      <div className="flex flex-1 min-h-0">
        {/* Left meta panel */}
        <div className="w-56 flex-shrink-0 border-r border-gray-800/60 bg-gray-900/40 p-4 overflow-y-auto space-y-4 text-sm">
          <div>
            <div className="text-gray-500 text-xs font-medium uppercase tracking-wider mb-2">
              Metadata
            </div>
            <div className="space-y-2">
              <div>
                <label className="text-gray-600 text-xs block mb-1">
                  Description
                </label>
                <textarea
                  rows={3}
                  value={playbook.description}
                  onChange={(e) =>
                    setPlaybook((p) => ({ ...p, description: e.target.value }))
                  }
                  className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-300 focus:outline-none focus:border-blue-500 resize-none"
                />
              </div>
              <div>
                <label className="text-gray-600 text-xs block mb-1">
                  Trigger
                </label>
                <select
                  value={playbook.trigger.on}
                  onChange={(e) =>
                    setPlaybook((p) => ({
                      ...p,
                      trigger: {
                        ...p.trigger,
                        on: e.target.value as
                          | 'alert'
                          | 'case'
                          | 'manual'
                          | 'schedule',
                      },
                    }))
                  }
                  className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-300 focus:outline-none focus:border-blue-500"
                >
                  <option value="manual">Manual</option>
                  <option value="alert">Alert</option>
                  <option value="case">Case</option>
                  <option value="schedule">Schedule</option>
                </select>
              </div>
              <div>
                <label className="text-gray-600 text-xs block mb-1">
                  Tags (comma sep)
                </label>
                <input
                  value={playbook.tags.join(', ')}
                  onChange={(e) =>
                    setPlaybook((p) => ({
                      ...p,
                      tags: e.target.value
                        .split(',')
                        .map((t) => t.trim())
                        .filter(Boolean),
                    }))
                  }
                  className="w-full bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-300 focus:outline-none focus:border-blue-500"
                />
              </div>
              <div className="flex items-center gap-2">
                <label className="text-gray-600 text-xs">Enabled</label>
                <input
                  type="checkbox"
                  checked={playbook.enabled}
                  onChange={(e) =>
                    setPlaybook((p) => ({ ...p, enabled: e.target.checked }))
                  }
                  className="accent-blue-500"
                />
              </div>
            </div>
          </div>

          {/* Steps list */}
          <div>
            <div className="text-gray-500 text-xs font-medium uppercase tracking-wider mb-2">
              Steps ({playbook.steps.length})
            </div>
            <div className="space-y-1">
              {playbook.steps.map((step, idx) => {
                const m = STEP_TYPE_META[step.type];
                return (
                  <button
                    key={step.id}
                    onClick={() =>
                      setSelectedStepId(
                        step.id === selectedStepId ? null : step.id,
                      )
                    }
                    className={`w-full text-left px-2 py-1.5 rounded text-xs flex items-center gap-2 transition-colors ${
                      step.id === selectedStepId
                        ? 'bg-blue-900/40 text-blue-300'
                        : 'text-gray-400 hover:bg-gray-800'
                    }`}
                  >
                    <span className="text-gray-600 w-4 text-right flex-shrink-0">
                      {idx + 1}.
                    </span>
                    <span>{m.icon}</span>
                    <span className="truncate">{step.name}</span>
                  </button>
                );
              })}
              {playbook.steps.length === 0 && (
                <div className="text-gray-700 text-xs italic">No steps yet</div>
              )}
            </div>
          </div>
        </div>

        {/* Canvas */}
        <div className="flex-1 min-w-0 relative">
          {playbook.steps.length === 0 ? (
            <div className="absolute inset-0 flex flex-col items-center justify-center text-gray-700">
              <div className="text-lg font-medium text-gray-500">
                Empty playbook
              </div>
              <div className="text-sm mt-1 mb-6">
                Add your first step to get started
              </div>
              <button
                onClick={() => setShowAddStep(true)}
                className="px-4 py-2 rounded bg-blue-600 hover:bg-blue-500 text-white text-sm transition-colors"
              >
                + Add Step
              </button>
            </div>
          ) : (
            <PlaybookFlowCanvas
              steps={playbook.steps}
              selectedId={selectedStepId}
              onSelectStep={setSelectedStepId}
              onStepsChange={handleStepsChange}
            />
          )}
        </div>

        {/* Right: inspector */}
        {selectedStep && (
          <div className="w-72 flex-shrink-0 border-l border-gray-800/60 bg-gray-900/40">
            <div className="px-4 py-3 border-b border-gray-800/60 flex items-center justify-between">
              <span className="text-xs font-semibold text-gray-400 uppercase tracking-wider">
                Step Inspector
              </span>
              <button
                onClick={() => setSelectedStepId(null)}
                className="text-gray-600 hover:text-gray-400 text-sm"
              >
                ✕
              </button>
            </div>
            <StepInspector
              step={selectedStep}
              onUpdate={updateStep}
              onDelete={deleteStep}
            />
          </div>
        )}
      </div>

      {/* ── Add Step Modal ── */}
      {showAddStep && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm"
          onClick={() => setShowAddStep(false)}
        >
          <div
            className="bg-gray-900 border border-gray-700 rounded-xl p-5 w-80 shadow-2xl"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="text-sm font-semibold text-white mb-4">
              Choose Step Type
            </div>
            <div className="grid grid-cols-3 gap-2">
              {STEP_TYPES.map((type) => {
                const m = STEP_TYPE_META[type];
                return (
                  <button
                    key={type}
                    onClick={() => addStep(type)}
                    className="flex flex-col items-center gap-1 p-3 rounded-lg border border-gray-700 hover:border-gray-500 bg-gray-800 hover:bg-gray-750 transition-colors"
                  >
                    <span style={{ color: m.color, fontSize: 20 }}>
                      {m.icon}
                    </span>
                    <span className="text-xs text-gray-400 text-center leading-tight">
                      {m.label}
                    </span>
                  </button>
                );
              })}
            </div>
            <button
              onClick={() => setShowAddStep(false)}
              className="mt-4 w-full text-xs text-gray-500 hover:text-gray-300 transition-colors"
            >
              Cancel
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
