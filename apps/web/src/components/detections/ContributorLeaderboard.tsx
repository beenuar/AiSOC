'use client';

import { useMemo, useState } from 'react';

const CONTRIBUTE_URL =
  'https://github.com/beenuar/AiSOC/blob/main/.github/PULL_REQUEST_TEMPLATE/detection_rule.md';
const DETECTIONS_URL =
  'https://github.com/beenuar/AiSOC/tree/main/detections';

interface Contributor {
  name: string;
  rules: number;
  categories: string[];
  badge: 'platinum' | 'gold' | 'silver' | 'bronze';
}

function badgeFor(count: number): Contributor['badge'] {
  if (count >= 50) return 'platinum';
  if (count >= 20) return 'gold';
  if (count >= 10) return 'silver';
  return 'bronze';
}

const BADGE_STYLES: Record<Contributor['badge'], { bg: string; text: string; border: string; label: string }> = {
  platinum: { bg: 'bg-violet-500/10', text: 'text-violet-300', border: 'border-violet-500/30', label: 'Platinum' },
  gold:     { bg: 'bg-amber-500/10',  text: 'text-amber-300',  border: 'border-amber-500/30',  label: 'Gold' },
  silver:   { bg: 'bg-gray-400/10',   text: 'text-gray-300',   border: 'border-gray-400/30',   label: 'Silver' },
  bronze:   { bg: 'bg-orange-500/10',  text: 'text-orange-300', border: 'border-orange-500/30', label: 'Bronze' },
};

const CORE_CONTRIBUTORS: Contributor[] = [
  { name: 'AiSOC', rules: 218, categories: ['cloud', 'endpoint', 'identity', 'network', 'application'], badge: 'platinum' },
];

const BADGE_THRESHOLDS: { tier: Contributor['badge']; min: number; label: string }[] = [
  { tier: 'platinum', min: 50, label: '50+ rules' },
  { tier: 'gold',     min: 20, label: '20+ rules' },
  { tier: 'silver',   min: 10, label: '10+ rules' },
  { tier: 'bronze',   min: 1,  label: '1+ rules' },
];

type SortKey = 'rules' | 'name';

export function ContributorLeaderboard() {
  const [sortBy, setSortBy] = useState<SortKey>('rules');

  const sorted = useMemo(() => {
    const list = [...CORE_CONTRIBUTORS];
    if (sortBy === 'rules') {
      list.sort((a, b) => b.rules - a.rules);
    } else {
      list.sort((a, b) => a.name.localeCompare(b.name));
    }
    return list;
  }, [sortBy]);

  return (
    <div className="rounded-2xl border border-white/10 bg-white/[0.02] p-8">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h3 className="text-xl font-semibold tracking-tight text-white">
            Detection rule contributors
          </h3>
          <p className="mt-2 max-w-2xl text-sm text-gray-400">
            Community members and teams that contribute Sigma rules,
            platform-native detections, and cross-platform translations to
            the open-source detection corpus.
          </p>
        </div>
        <a
          href={CONTRIBUTE_URL}
          target="_blank"
          rel="noreferrer"
          className="inline-flex items-center gap-2 rounded-md bg-brand-500 px-4 py-2 text-sm font-semibold text-white transition hover:bg-brand-400"
        >
          Contribute a rule
          <svg
            viewBox="0 0 20 20"
            className="h-3.5 w-3.5"
            fill="currentColor"
            aria-hidden="true"
          >
            <path d="M5.22 14.78a.75.75 0 001.06 0l7.22-7.22v3.69a.75.75 0 001.5 0v-5.5a.75.75 0 00-.75-.75h-5.5a.75.75 0 000 1.5h3.69L5.22 13.72a.75.75 0 000 1.06z" />
          </svg>
        </a>
      </div>

      <div className="mt-6 grid gap-4 sm:grid-cols-4">
        {BADGE_THRESHOLDS.map((t) => {
          const s = BADGE_STYLES[t.tier];
          return (
            <div
              key={t.tier}
              className={`rounded-lg border ${s.border} ${s.bg} p-3 text-center`}
            >
              <div className={`text-xs font-bold uppercase tracking-wider ${s.text}`}>
                {s.label}
              </div>
              <div className="mt-1 text-[10px] text-gray-400">{t.label}</div>
            </div>
          );
        })}
      </div>

      <div className="mt-6">
        <div className="flex items-center gap-3 border-b border-white/5 pb-3">
          <span className="text-xs font-medium text-gray-500 uppercase tracking-wider">
            Sort by
          </span>
          {(['rules', 'name'] as SortKey[]).map((key) => (
            <button
              key={key}
              onClick={() => setSortBy(key)}
              className={`rounded-md px-2.5 py-1 text-xs font-medium transition ${
                sortBy === key
                  ? 'bg-white/10 text-white'
                  : 'text-gray-500 hover:text-gray-300'
              }`}
            >
              {key === 'rules' ? 'Rule count' : 'Name'}
            </button>
          ))}
        </div>

        <div className="mt-4 space-y-3">
          {sorted.map((c, i) => {
            const s = BADGE_STYLES[c.badge];
            return (
              <div
                key={c.name}
                className="flex items-center gap-4 rounded-lg border border-white/5 bg-black/20 p-4"
              >
                <span className="w-6 text-right text-sm font-bold text-gray-500">
                  {i + 1}
                </span>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-semibold text-white truncate">
                      {c.name}
                    </span>
                    <span
                      className={`rounded-full border ${s.border} ${s.bg} px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider ${s.text}`}
                    >
                      {s.label}
                    </span>
                  </div>
                  <div className="mt-1 flex flex-wrap gap-1.5">
                    {c.categories.map((cat) => (
                      <span
                        key={cat}
                        className="rounded bg-white/5 px-1.5 py-0.5 text-[10px] text-gray-400"
                      >
                        {cat}
                      </span>
                    ))}
                  </div>
                </div>
                <div className="text-right">
                  <span className="text-lg font-bold text-white">{c.rules}</span>
                  <span className="ml-1 text-xs text-gray-500">rules</span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {sorted.length <= 1 && (
        <div className="mt-6 rounded-lg border border-dashed border-white/10 bg-black/20 p-6 text-center">
          <p className="text-sm text-gray-400">
            The community leaderboard grows as detection rule PRs are merged.
          </p>
          <p className="mt-1 text-xs text-gray-500">
            Submit your first rule using the{' '}
            <a
              href={CONTRIBUTE_URL}
              target="_blank"
              rel="noreferrer"
              className="underline decoration-dotted hover:text-gray-300"
            >
              detection rule PR template
            </a>{' '}
            and earn your first badge.
          </p>
        </div>
      )}

      <div className="mt-6 flex items-center justify-between border-t border-white/5 pt-4">
        <p className="text-xs text-gray-500">
          Corpus:{' '}
          <a
            href={DETECTIONS_URL}
            target="_blank"
            rel="noreferrer"
            className="underline decoration-dotted hover:text-gray-300"
          >
            {sorted.reduce((sum, c) => sum + c.rules, 0).toLocaleString()}+ rules across{' '}
            {[...new Set(sorted.flatMap((c) => c.categories))].length} categories
          </a>
        </p>
        <p className="text-xs text-gray-500">
          Badge tiers update as PRs are merged.
        </p>
      </div>
    </div>
  );
}
