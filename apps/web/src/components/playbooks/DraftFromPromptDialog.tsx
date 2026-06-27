'use client';

/**
 * DraftFromPromptDialog — T3.7 NL → playbook generator UI.
 * ========================================================
 *
 * Modal launched from /playbooks. The analyst types a free-text
 * description ("when a high-severity exfil alert fires on a prod
 * S3 bucket, isolate the IAM role, snapshot the bucket policy and
 * page on-call"), the dialog POSTs to ``/api/v1/playbooks/draft-from-nl``
 * and routes to /playbooks/new with the draft parked in sessionStorage
 * under ``aisoc:nl-draft`` for the editor to pick up.
 *
 * Drafts are NEVER auto-saved or auto-run. The editor is the gate —
 * the drafted playbook arrives with ``enabled=false`` and the analyst
 * reviews each node before saving.
 *
 * Design choices:
 *   • The modal is purely controlled (open / onClose) so the parent
 *     owns its visibility; tests can mount the body component
 *     directly without a portal.
 *   • Network failures surface inline (red banner). The submit button
 *     is disabled while the request is in flight to prevent dupes.
 *   • A small "suggestions" footer offers two canned prompts the
 *     analyst can click to populate the textarea — helps first-time
 *     users discover what the drafter understands.
 *   • The dialog returns *real* HTTP errors verbatim. We don't try to
 *     pretty-print the backend's message because the backend already
 *     emits short, actionable text ("prompt is required",
 *     "prompt is too long (max 4000 chars)").
 */

import React, { useCallback, useEffect, useRef, useState } from 'react';
import { useRouter } from 'next/navigation';
import type { Playbook } from './types';

const SUGGESTIONS: { label: string; prompt: string }[] = [
  {
    label: 'High-sev exfil → isolate + notify',
    prompt:
      'When a high-severity exfil alert fires on a prod S3 bucket, ' +
      'isolate the IAM role, snapshot the bucket policy and page on-call.',
  },
  {
    label: 'Account takeover → disable + reset',
    prompt:
      'On a critical account-takeover case, disable the user, ' +
      'reset the password, revoke sessions and notify the SOC.',
  },
];

const MAX_PROMPT_LEN = 4000;

interface DraftResponse {
  playbook: Playbook;
  rationale: string;
  used_llm: boolean;
  schema_validated: boolean;
}

export interface DraftFromPromptDialogProps {
  open: boolean;
  onClose: () => void;
}

export function DraftFromPromptDialog({ open, onClose }: DraftFromPromptDialogProps) {
  const router = useRouter();
  const textareaRef = useRef<HTMLTextAreaElement | null>(null);

  const [prompt, setPrompt] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (open) {
      setError(null);
      setBusy(false);
      // Defer focus so the dialog has actually mounted in the DOM.
      const t = setTimeout(() => textareaRef.current?.focus(), 0);
      return () => clearTimeout(t);
    }
    return undefined;
  }, [open]);

  const handleSubmit = useCallback(async () => {
    const trimmed = prompt.trim();
    if (!trimmed) {
      setError('Add a description of the playbook you want.');
      return;
    }
    if (trimmed.length > MAX_PROMPT_LEN) {
      setError(`Prompt is too long (max ${MAX_PROMPT_LEN} chars).`);
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const resp = await fetch('/api/v1/playbooks/draft-from-nl', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ prompt: trimmed, allow_llm: true }),
      });
      if (!resp.ok) {
        const txt = await resp.text();
        setError(txt || `Drafter returned HTTP ${resp.status}`);
        setBusy(false);
        return;
      }
      const data = (await resp.json()) as DraftResponse;
      if (!data?.playbook || !Array.isArray(data.playbook.steps)) {
        setError('Drafter returned an unexpected payload — try again.');
        setBusy(false);
        return;
      }
      // Park the draft for the editor to pick up. sessionStorage is the
      // simplest pipe — survives the navigation, doesn't leak across tabs.
      sessionStorage.setItem('aisoc:nl-draft', JSON.stringify(data.playbook));
      onClose();
      router.push('/playbooks/new?nl=true');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Network error');
      setBusy(false);
    }
  }, [prompt, router, onClose]);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
      if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        void handleSubmit();
      }
      if (e.key === 'Escape' && !busy) {
        onClose();
      }
    },
    [handleSubmit, busy, onClose],
  );

  if (!open) return null;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="nl-draft-title"
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
      onClick={(e) => {
        if (e.target === e.currentTarget && !busy) onClose();
      }}
    >
      <div className="w-full max-w-2xl rounded-xl border border-gray-800 bg-gray-950 p-6 shadow-2xl">
        <div className="flex items-start justify-between">
          <div>
            <h2 id="nl-draft-title" className="text-base font-semibold text-white">
              Draft a playbook from a prompt
            </h2>
            <p className="mt-0.5 text-xs text-gray-500">
              Describe what should happen — AiSOC drafts the DAG, you review and save.
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            disabled={busy}
            className="rounded-md p-1 text-gray-500 hover:bg-gray-800 hover:text-gray-300 disabled:opacity-40"
            aria-label="Close"
          >
            ✕
          </button>
        </div>

        <textarea
          ref={textareaRef}
          value={prompt}
          onChange={(e) => setPrompt(e.target.value)}
          onKeyDown={handleKeyDown}
          rows={6}
          maxLength={MAX_PROMPT_LEN}
          placeholder={
            'e.g. "When a high-severity exfil alert fires on a prod S3 bucket, ' +
            'isolate the IAM role, snapshot the bucket policy, and page on-call."'
          }
          className="mt-4 w-full resize-y rounded-lg border border-gray-800 bg-gray-900 px-3 py-2 text-sm text-gray-200 placeholder:text-gray-600 focus:border-blue-600 focus:outline-none focus:ring-1 focus:ring-blue-600"
          disabled={busy}
        />

        <div className="mt-1 flex items-center justify-between text-[11px] text-gray-500">
          <span>
            {prompt.trim().length}/{MAX_PROMPT_LEN} chars · Press Cmd/Ctrl-Enter to draft
          </span>
        </div>

        {error && (
          <div
            role="alert"
            className="mt-3 rounded-lg border border-red-900/60 bg-red-950/40 px-3 py-2 text-xs text-red-300"
          >
            {error}
          </div>
        )}

        <div className="mt-4 border-t border-gray-800 pt-3">
          <p className="text-[11px] uppercase tracking-wide text-gray-500">Try one of:</p>
          <div className="mt-2 flex flex-wrap gap-2">
            {SUGGESTIONS.map((s) => (
              <button
                key={s.label}
                type="button"
                disabled={busy}
                onClick={() => setPrompt(s.prompt)}
                className="rounded-md border border-gray-800 bg-gray-900 px-2 py-1 text-[11px] text-gray-400 hover:border-gray-700 hover:bg-gray-800 hover:text-gray-200 disabled:opacity-50"
              >
                {s.label}
              </button>
            ))}
          </div>
        </div>

        <div className="mt-5 flex items-center justify-end gap-2">
          <button
            type="button"
            onClick={onClose}
            disabled={busy}
            className="rounded-lg border border-gray-800 px-4 py-2 text-sm text-gray-400 hover:bg-gray-800 hover:text-gray-200 disabled:opacity-50"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={() => void handleSubmit()}
            disabled={busy || !prompt.trim()}
            className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {busy ? 'Drafting…' : 'Draft playbook'}
          </button>
        </div>
      </div>
    </div>
  );
}
