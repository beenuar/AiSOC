'use client';

/**
 * Opt this tenant into retro-hunt sweeps.
 *
 * `retro_hunt_settings.enabled` has defaulted to FALSE since migration 070
 * under a comment reading "Off until a tenant asks", and until this panel
 * existed there was nowhere to ask: no route and no console surface touched
 * the table, so opting in meant an UPDATE issued against the database by hand.
 *
 * Two switches have to be on. This is the tenant's. The operator's is
 * `RETRO_HUNT_ENABLED`, which decides whether the consumer runs at all, and
 * the panel says so rather than letting someone toggle this and conclude the
 * feature is broken when nothing sweeps.
 */

import { useCallback, useState } from 'react';
import useSWR from 'swr';

import { retroHuntsApi, type RetroHuntSettings as Settings } from '@/lib/api';

const MIN_LOOKBACK = 1;
const MAX_LOOKBACK = 365;

export function RetroHuntSettingsPanel() {
  const { data, error, isLoading, mutate } = useSWR<Settings>(
    'settings:retro-hunts',
    () => retroHuntsApi.getSettings(),
    // No `fallbackData`: supplying one disables revalidation, so a mock would
    // be what this panel *shows* rather than a first paint. There is no shape
    // of invented settings better than saying the read failed -- a fabricated
    // "off" reads as an answer.
    { revalidateOnFocus: false, shouldRetryOnError: false },
  );

  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);

  const save = useCallback(
    async (patch: Partial<Pick<Settings, 'enabled' | 'lookback_days' | 'include_federated'>>) => {
      if (!data) return;
      const next = { ...data, ...patch };
      setSaving(true);
      setSaveError(null);
      try {
        const written = await retroHuntsApi.putSettings({
          enabled: next.enabled,
          lookback_days: next.lookback_days,
          include_federated: next.include_federated,
        });
        await mutate(written, { revalidate: false });
      } catch (err) {
        // Do not leave the optimistic value on screen: a toggle that looks
        // saved and is not is worse than one that visibly refused.
        setSaveError(err instanceof Error ? err.message : 'Could not save.');
        await mutate();
      } finally {
        setSaving(false);
      }
    },
    [data, mutate],
  );

  if (isLoading) {
    return <p className="text-sm text-muted-foreground">Reading retro-hunt settings…</p>;
  }

  if (error || !data) {
    return (
      <div className="rounded-md border border-destructive/40 bg-destructive/5 p-4">
        <p className="text-sm font-medium">Could not read retro-hunt settings</p>
        <p className="mt-1 text-sm text-muted-foreground">
          {error instanceof Error ? error.message : 'The settings endpoint did not answer.'}
        </p>
        <button
          type="button"
          onClick={() => void mutate()}
          className="mt-3 rounded-md border px-3 py-1.5 text-sm hover:bg-muted"
        >
          Try again
        </button>
      </div>
    );
  }

  const s = data;

  return (
    <section className="space-y-6">
      <header>
        <h3 className="text-base font-semibold">Retro-hunt sweeps</h3>
        <p className="mt-1 text-sm text-muted-foreground">
          When a new indicator arrives, look back over your history for anything that already
          matched it. Off until you ask, because a sweep reads your past events.
        </p>
      </header>

      <label className="flex items-start gap-3">
        <input
          type="checkbox"
          checked={s.enabled}
          disabled={saving}
          onChange={(e) => void save({ enabled: e.target.checked })}
          className="mt-1"
        />
        <span>
          <span className="text-sm font-medium">Sweep my history when new intel arrives</span>
          <span className="mt-0.5 block text-sm text-muted-foreground">
            Your operator must also have started the retro-hunt consumer
            (<code>RETRO_HUNT_ENABLED</code>). Both switches have to be on before anything is
            swept.
          </span>
        </span>
      </label>

      <label className="flex items-start gap-3">
        <input
          type="checkbox"
          checked={s.include_federated}
          disabled={saving || !s.enabled}
          onChange={(e) => void save({ include_federated: e.target.checked })}
          className="mt-1"
        />
        <span>
          <span className="text-sm font-medium">Also sweep my connected SIEMs</span>
          <span className="mt-0.5 block text-sm text-muted-foreground">
            Separate from the switch above because it is a separate cost: sweeping the AiSOC lake
            is free to you, and sweeping a connected SIEM may bill you per query.
          </span>
        </span>
      </label>

      <label className="block">
        <span className="text-sm font-medium">Look back</span>
        <span className="mt-1 flex items-center gap-2">
          <input
            type="number"
            min={MIN_LOOKBACK}
            max={MAX_LOOKBACK}
            value={s.lookback_days}
            disabled={saving || !s.enabled}
            onChange={(e) => {
              const days = Number(e.target.value);
              if (days >= MIN_LOOKBACK && days <= MAX_LOOKBACK) void save({ lookback_days: days });
            }}
            className="w-24 rounded-md border px-2 py-1 text-sm"
          />
          <span className="text-sm text-muted-foreground">
            days (1–{MAX_LOOKBACK}; the column enforces the same bound)
          </span>
        </span>
      </label>

      <div className="rounded-md border p-4">
        <p className="text-sm font-medium">Your sweep budget</p>
        <p className="mt-1 text-sm text-muted-foreground">
          Set by your operator, not here: it is the ceiling on what one tenant can cost the
          deployment.
        </p>
        <dl className="mt-3 grid grid-cols-2 gap-x-6 gap-y-1 text-sm">
          <dt className="text-muted-foreground">This hour</dt>
          <dd>
            {s.sweeps_this_hour} of {s.max_sweeps_per_hour}
          </dd>
          <dt className="text-muted-foreground">Today</dt>
          <dd>
            {s.sweeps_today} of {s.max_sweeps_per_day}
          </dd>
          <dt className="text-muted-foreground">Declined for budget</dt>
          <dd>{s.sweeps_skipped_budget}</dd>
        </dl>
        {s.sweeps_skipped_budget > 0 && (
          <p className="mt-3 text-sm">
            {s.sweeps_skipped_budget} sweep{s.sweeps_skipped_budget === 1 ? ' has' : 's have'} been
            declined because a budget was exhausted. Surfaced because the symptom otherwise is
            silence, which looks identical to a feed with nothing to report.
          </p>
        )}
      </div>

      {saveError && (
        <p className="text-sm text-destructive" role="alert">
          {saveError}
        </p>
      )}
    </section>
  );
}

export default RetroHuntSettingsPanel;
