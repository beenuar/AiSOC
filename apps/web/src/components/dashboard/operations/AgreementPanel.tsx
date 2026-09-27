'use client';

/**
 * How often the agent and this tenant's own analysts reached the same verdict.
 *
 * Gap-closure Phase 2.2.
 *
 * The rest of this dashboard answers "is the pipeline working". This panel
 * answers the question that decides whether any of it gets trusted with a
 * decision: on the alerts your analysts have closed, how often was the agent
 * right, and how often did it catch the ones that mattered.
 *
 * Three rules this panel follows, each because the obvious alternative
 * misleads in the direction that sells.
 *
 * **A rate with no denominator reads "not measured", never 0.** A zero in the
 * agreement column says the agent was wrong every time. "It has not been
 * asked yet" is a different fact calling for a different response, and on a
 * new deployment it is always the true one.
 *
 * **Every rate is printed with the count behind it.** 100% over four answers
 * is not the claim 100% over four hundred is, and a tile showing only the
 * percentage has thrown that distinction away.
 *
 * **The recent slice is shown beside the window, not instead of it.** A
 * thirty-day average is where a gradual decline hides: an agent that agreed
 * 99% of the time for three weeks and 70% this week still posts about 95%.
 * Showing only the window would make this panel the thing that conceals the
 * problem it exists to reveal.
 */

import useSWR from 'swr';
import { clsx } from 'clsx';
import { autonomyPolicyApi, type AgreementScope, type AgreementWindow } from '@/lib/api';
import { EmptyState } from '@/components/ui/EmptyState';
import { ErrorState } from '@/components/ui/ErrorState';

/** A rate as a percentage, or the words that mean there was no denominator. */
export function formatRate(value: number | null | undefined): string {
  return value === null || value === undefined ? 'not measured' : `${(value * 100).toFixed(1)}%`;
}

/**
 * Progress toward a sample floor, as a fraction a reader can act on.
 *
 * "47 of 100" tells an operator to keep measuring. "47%" invites them to read
 * it as an accuracy figure, on a panel where every other percentage is one.
 */
export function formatProgress(have: number, need: number): string {
  return `${have} of ${need}`;
}

export function AgreementPanel() {
  const { data, error, isLoading } = useSWR(
    'ops-shadow-agreement',
    () => autonomyPolicyApi.agreement(),
    { refreshInterval: 60_000, revalidateOnFocus: false },
  );

  if (error) {
    return (
      <Shell>
        <ErrorState
          title="Agreement unavailable"
          description="The autonomy policy endpoint did not answer, so no figures are shown. An agreement rate that is silently stale is worse than none."
          error={error}
        />
      </Shell>
    );
  }

  if (isLoading || !data) {
    return (
      <Shell>
        <p className="text-sm text-gray-500">Loading agreement…</p>
      </Shell>
    );
  }

  const { window: w, recent, thresholds } = data;

  if (w.resolved === 0) {
    return (
      <Shell>
        <EmptyState
          title="No graded decisions yet"
          description={
            'Agreement is measured on alerts the agent triaged in shadow mode and an analyst later closed. ' +
            'Enable shadow mode for an alert class in Settings, then close some alerts as usual.'
          }
        />
      </Shell>
    );
  }

  return (
    <Shell>
      <dl className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Metric
          label="Agreement"
          value={formatRate(w.agreement_rate)}
          detail={`${w.agreed} of ${w.answered} answered`}
          meets={meets(w.agreement_rate, thresholds.min_agreement)}
        />
        <Metric
          label="Recall on malicious"
          value={formatRate(w.malicious_recall)}
          detail={`${w.malicious_caught} of ${w.malicious_support} true positives`}
          meets={meets(w.malicious_recall, thresholds.min_malicious_recall)}
        />
        <Metric
          label="Abstained"
          value={formatRate(w.abstention_rate)}
          detail={`${w.abstained} of ${w.labelled} labelled`}
          /* The only metric here where lower is better: an agent can lift its
             agreement rate by declining the hard cases, and this is the column
             where that shows up. */
          meets={w.abstention_rate === null ? null : w.abstention_rate <= thresholds.max_abstention_rate}
        />
        <Metric
          label="Sample"
          value={formatProgress(w.labelled, thresholds.min_decisions)}
          detail={`${formatProgress(w.malicious_support, thresholds.min_malicious)} malicious`}
          meets={w.labelled >= thresholds.min_decisions && w.malicious_support >= thresholds.min_malicious}
        />
      </dl>

      <p className="mt-3 text-xs text-gray-500">
        Last {thresholds.window_days} days. {w.unlabeled} closure
        {w.unlabeled === 1 ? '' : 's'} carried no disposition this platform can name and
        {w.unlabeled === 1 ? ' is' : ' are'} excluded from every rate above.
      </p>

      <div className="mt-4 rounded-md border border-gray-800 bg-gray-950/60 p-3">
        <p className="text-[11px] uppercase tracking-wide text-gray-500">
          Most recent {recent.labelled} decision{recent.labelled === 1 ? '' : 's'}
        </p>
        <p className="mt-1 text-sm text-gray-300">
          Agreement {formatRate(recent.agreement_rate)} ({recent.agreed} of {recent.answered}), recall{' '}
          {formatRate(recent.malicious_recall)} ({recent.malicious_caught} of {recent.malicious_support}).
        </p>
        <p className="mt-1 text-xs text-gray-500">
          Scored apart from the window, because a decline that started this week is still
          absorbed by a month of earlier agreement.
        </p>
      </div>

      <Breakdown title="By alert class" rows={data.by_alert_class} />
      <Breakdown title="By source" rows={data.by_source} />
    </Shell>
  );
}

function meets(value: number | null, floor: number): boolean | null {
  return value === null ? null : value >= floor;
}

function Shell({ children }: { children: React.ReactNode }) {
  return (
    <section
      className="rounded-lg border border-gray-800 bg-gray-950/40 p-4"
      aria-label="Agreement with analysts"
    >
      <header className="mb-3">
        <h2 className="text-sm font-semibold text-gray-100">Agreement with analysts</h2>
        <p className="mt-0.5 text-xs text-gray-500">
          Measured on shadow decisions your analysts have since closed, here or in the source SIEM.
        </p>
      </header>
      {children}
    </section>
  );
}

function Metric({
  label,
  value,
  detail,
  meets: met,
}: {
  label: string;
  value: string;
  detail: string;
  meets: boolean | null;
}) {
  return (
    <div>
      <dt className="text-[11px] uppercase tracking-wide text-gray-500">{label}</dt>
      <dd
        className={clsx(
          'font-mono text-lg tabular-nums',
          // No colour at all when there is nothing to judge. Painting an
          // unmeasured figure red would read as a failing one.
          met === null ? 'text-gray-400' : met ? 'text-emerald-300' : 'text-amber-300',
        )}
      >
        {value}
      </dd>
      <p className="text-[11px] text-gray-500">{detail}</p>
    </div>
  );
}

function Breakdown({ title, rows }: { title: string; rows: AgreementScope[] }) {
  if (rows.length === 0) return null;
  return (
    <div className="mt-4">
      <p className="text-[11px] uppercase tracking-wide text-gray-500">{title}</p>
      <ul className="mt-1 divide-y divide-gray-800/70">
        {rows.slice(0, 6).map((row) => (
          <li key={row.key} className="flex items-baseline justify-between gap-3 py-1.5 text-sm">
            <span className="truncate text-gray-300">{row.key}</span>
            <span className="shrink-0 font-mono text-xs tabular-nums text-gray-400">
              {formatRate(row.window.agreement_rate)} · {sampleOf(row.window)}
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function sampleOf(window: AgreementWindow): string {
  return `${window.answered} answered`;
}

export default AgreementPanel;
