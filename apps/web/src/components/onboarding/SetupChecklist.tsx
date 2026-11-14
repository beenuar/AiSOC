'use client';

import { useState } from 'react';
import Link from 'next/link';
import useSWR from 'swr';
import toast from 'react-hot-toast';

import { onboardingApi, type OnboardingStatus, type SampleDataResult } from '@/lib/api';
import { ModelPlacement } from './ModelPlacement';
import { clsx } from 'clsx';

/**
 * What a new tenant still has to do, and a way to see the product work
 * before they have credentials for anything.
 *
 * The gap this fills
 * ------------------
 * A brand-new operator signed in and landed on `/dashboard`: every tile
 * zero, every panel an honest empty state, and nothing saying what to do
 * next. The empty states were right — "0 connected sources" is true — but
 * true and *useful* are different things, and none of them is a button.
 *
 * Two paths, deliberately
 * -----------------------
 * **Connect something real** is the primary one and is listed first,
 * because that is what the product is for.
 *
 * **Load sample data** is the escape hatch for the evaluator who is three
 * approvals away from an API key for their EDR and wants to know whether
 * this is worth pursuing. It pushes five scenarios through the same
 * ingest endpoint a real connector uses, so what they end up looking at
 * has genuinely been normalised, correlated and triaged — a console full
 * of inserted rows would look identical whether the pipeline works or is
 * completely broken.
 *
 * What it will not do
 * -------------------
 * Sample data does not mark setup complete. Somebody who has only looked
 * at samples still has nothing connected, and telling them otherwise
 * would be exactly the kind of flattering fiction this product spends
 * most of its effort avoiding.
 */
export function SetupChecklist({ compact = false }: { compact?: boolean }) {
  const { data, error, isLoading, mutate } = useSWR<OnboardingStatus>(
    'onboarding-status',
    onboardingApi.status,
    { refreshInterval: 15_000 },
  );
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<SampleDataResult | null>(null);

  const loadSamples = async () => {
    setLoading(true);
    try {
      const outcome = await onboardingApi.loadSampleData();
      setResult(outcome);
      toast.success(
        `${outcome.accepted} sample events accepted. They become alerts in a few seconds.`,
      );
      // Revalidate rather than optimistically marking the step done: the
      // events are in the pipeline, not yet alerts, and claiming
      // otherwise is the exact shape of dishonesty this avoids.
      void mutate();
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      // Surfaced verbatim. A first run is the worst possible moment to
      // replace a specific cause with "something went wrong".
      toast.error(message, { duration: 10_000 });
    } finally {
      setLoading(false);
    }
  };

  if (error) {
    return (
      <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-4 text-sm">
        <p className="font-medium text-amber-200">Setup status unavailable</p>
        <p className="mt-1 text-slate-400">
          The console could not read what is set up. Treat this as unknown rather than as a
          tenant with nothing configured.
        </p>
      </div>
    );
  }

  if (isLoading || !data) {
    return <div className="h-32 animate-pulse rounded-lg bg-slate-800/40" />;
  }

  // `try` and `model` are both optional: sample data is an alternative to a real
  // connector, and the model step is informational because a local model ships
  // and works. Counting either would show a tenant that is genuinely finished as
  // having work left.
  const remaining = data.steps.filter(
    (s) => !s.done && s.key !== 'try' && s.key !== 'model',
  ).length;

  return (
    <section
      aria-labelledby="setup-checklist-heading"
      className="rounded-xl border border-slate-700/60 bg-slate-900/40 p-5"
    >
      <div className="flex items-start justify-between gap-4">
        <div>
          <h2 id="setup-checklist-heading" className="text-lg font-semibold text-slate-100">
            {remaining === 0 ? 'Setup complete' : 'Finish setting up'}
          </h2>
          <p className="mt-1 text-sm text-slate-400">
            {remaining === 0
              ? 'A source is connected and alerts are arriving from it.'
              : `${remaining} step${remaining === 1 ? '' : 's'} left before AiSOC is working on your own data.`}
          </p>
        </div>
      </div>

      <ol className="mt-5 space-y-3">
        {data.steps.map((step) => (
          <li
            key={step.key}
            className={clsx(
              'flex gap-3 rounded-lg border p-3',
              step.done
                ? 'border-emerald-500/25 bg-emerald-500/5'
                : 'border-slate-700/60 bg-slate-800/30',
            )}
          >
            <span
              aria-hidden
              className={clsx(
                'mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full text-xs font-bold',
                step.done ? 'bg-emerald-500/20 text-emerald-300' : 'bg-slate-700 text-slate-400',
              )}
            >
              {step.done ? '✓' : '·'}
            </span>
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-medium text-slate-100">{step.label}</span>
                <span className="sr-only">{step.done ? 'done' : 'not done yet'}</span>
                {step.detail && (
                  <span className="text-xs text-slate-500">{step.detail}</span>
                )}
              </div>
              {!compact && <p className="mt-1 text-sm text-slate-400">{step.why}</p>}

              {step.key === 'model' && <ModelPlacement />}

              {step.key === 'try' && !step.done && (
                <button
                  type="button"
                  onClick={loadSamples}
                  disabled={loading}
                  className="mt-2 rounded-md border border-slate-600 px-3 py-1.5 text-sm text-slate-200 transition hover:border-slate-400 hover:bg-slate-800 disabled:opacity-50"
                >
                  {loading ? 'Pushing events through the pipeline…' : 'Load sample data'}
                </button>
              )}

              {step.href && !step.done && step.key !== 'try' && (
                <Link
                  href={step.href}
                  className="mt-2 inline-block rounded-md bg-indigo-600 px-3 py-1.5 text-sm font-medium text-white transition hover:bg-indigo-500"
                >
                  {step.key === 'connector' ? 'Connect a source' : 'Open'}
                </Link>
              )}
            </div>
          </li>
        ))}
      </ol>

      {result && (
        <div className="mt-4 rounded-lg border border-slate-700/60 bg-slate-800/30 p-4">
          <p className="text-sm text-slate-300">{result.note}</p>
          <ul className="mt-3 space-y-1.5">
            {result.scenarios.map((scenario) => (
              <li key={scenario.key} className="text-sm">
                <span className="text-slate-200">{scenario.title}</span>
                <span className="ml-2 text-xs uppercase tracking-wide text-slate-500">
                  {scenario.severity}
                </span>
                <p className="text-xs text-slate-500">{scenario.why}</p>
              </li>
            ))}
          </ul>
          <Link
            href="/alerts"
            className="mt-3 inline-block text-sm text-indigo-400 hover:text-indigo-300"
          >
            Watch them arrive in Alerts →
          </Link>
        </div>
      )}

      {data.sample_data_loaded && (
        <p className="mt-4 text-xs text-slate-500">
          Sample alerts are attributed to &quot;AiSOC&quot; in the source column, so you can tell
          them from real telemetry anywhere in the console. Connecting a real source is still
          the next step.
        </p>
      )}
    </section>
  );
}
