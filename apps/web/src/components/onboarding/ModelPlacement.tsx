'use client';

/**
 * Where AI triage is running, and the ways to change it.
 *
 * Shown inside the setup checklist's "Choose where the AI runs" step. It
 * reports rather than configures, for the two local options, because it has to:
 * switching the bundled Ollama onto a GPU means restarting that container with
 * different compose arguments, and a web service that could do that would need
 * the Docker socket -- which is a container-escape path, not a feature.
 *
 * The hosted-provider option *is* configurable from here, because that is a
 * database row rather than a container restart. It links to the existing BYOK
 * form rather than duplicating it.
 */

import Link from 'next/link';
import useSWR from 'swr';

import { llmApi, type LlmRuntime } from '@/lib/api';

/** How each placement reads to someone deciding what to do about it. */
const TONE: Record<string, { label: string; className: string }> = {
  gpu: { label: 'On a GPU', className: 'border-emerald-700/60 bg-emerald-950/30 text-emerald-200' },
  partial: { label: 'Partly on a GPU', className: 'border-amber-700/60 bg-amber-950/30 text-amber-200' },
  cpu: { label: 'On the CPU', className: 'border-slate-600 bg-slate-800/40 text-slate-200' },
  unknown: { label: 'Not loaded right now', className: 'border-slate-600 bg-slate-800/40 text-slate-300' },
  unreachable: { label: 'No local model', className: 'border-slate-600 bg-slate-800/40 text-slate-300' },
};

export function ModelPlacement() {
  const { data, error, isLoading } = useSWR<LlmRuntime>(
    'onboarding:llm-runtime',
    () => llmApi.runtime(),
    // No `fallbackData`: supplying one disables revalidation, so a placeholder
    // would be what this panel *shows* rather than a first paint. There is no
    // invented placement better than saying the probe failed.
    { revalidateOnFocus: false, shouldRetryOnError: false },
  );

  if (isLoading) {
    return <p className="mt-2 text-sm text-slate-500">Asking the model where it is running…</p>;
  }

  if (error || !data) {
    return (
      <p className="mt-2 text-sm text-slate-400">
        Could not determine where the model is running. Triage is unaffected; this panel is
        informational.{' '}
        <Link href="/settings" className="underline hover:text-slate-200">
          Configure a provider
        </Link>
      </p>
    );
  }

  const tone = TONE[data.placement] ?? TONE.unknown;

  return (
    <div className="mt-2 space-y-2">
      <div className={`inline-flex items-center gap-2 rounded-md border px-2.5 py-1 text-xs ${tone.className}`}>
        <span className="font-medium">{tone.label}</span>
        {typeof data.vram_bytes === 'number' && data.vram_bytes > 0 && (
          <span className="opacity-80">{(data.vram_bytes / 1024 ** 3).toFixed(1)} GB in VRAM</span>
        )}
      </div>

      <p className="text-sm text-slate-400">{data.detail}</p>

      {data.options.length > 0 && (
        <ul className="space-y-1 text-sm text-slate-400">
          {data.options.map((option) => (
            <li key={option} className="flex gap-2">
              <span aria-hidden className="text-slate-600">
                ·
              </span>
              <span>{option}</span>
            </li>
          ))}
        </ul>
      )}

      <Link
        href="/settings?tab=deployment"
        className="mt-1 inline-block rounded-md border border-slate-600 px-3 py-1.5 text-sm text-slate-200 transition hover:border-slate-400 hover:bg-slate-800"
      >
        Use my own provider
      </Link>
    </div>
  );
}

export default ModelPlacement;
