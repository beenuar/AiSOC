'use client';

import { useState } from 'react';
import { clsx } from 'clsx';
import { EmptyState, EmptyStateIcons } from '@/components/ui/EmptyState';

interface Analyst {
  id: string;
  name: string;
  initials: string;
  avatarColor: string;
  casesClosed: number;
  avgResolutionMin: number;
  accuracy: number;
  score: number;
  badges: string[];
}

interface Achievement {
  text: string;
  timeAgo: string;
  icon: 'badge' | 'streak' | 'record' | 'rank';
}

const BADGE_COLORS: Record<string, { bg: string; text: string; border: string }> = {
  'MITRE Master':     { bg: 'bg-purple-500/15', text: 'text-purple-300', border: 'border-purple-500/30' },
  'Speed Demon':      { bg: 'bg-blue-500/15',   text: 'text-blue-300',   border: 'border-blue-500/30' },
  'Zero FP':          { bg: 'bg-green-500/15',  text: 'text-green-300',  border: 'border-green-500/30' },
  'Night Owl':        { bg: 'bg-indigo-500/15', text: 'text-indigo-300', border: 'border-indigo-500/30' },
  'Precision Strike': { bg: 'bg-amber-500/15',  text: 'text-amber-300',  border: 'border-amber-500/30' },
  'Mentor':           { bg: 'bg-teal-500/15',   text: 'text-teal-300',   border: 'border-teal-500/30' },
  'Newcomer Rising':  { bg: 'bg-rose-500/15',   text: 'text-rose-300',   border: 'border-rose-500/30' },
};

const ANALYSTS: Analyst[] = [
  { id: 'sc', name: 'Sarah Chen',     initials: 'SC', avatarColor: 'bg-violet-500', casesClosed: 47, avgResolutionMin: 18, accuracy: 96.2, score: 945, badges: ['MITRE Master', 'Speed Demon'] },
  { id: 'mr', name: 'Marcus Rivera',  initials: 'MR', avatarColor: 'bg-sky-500',    casesClosed: 42, avgResolutionMin: 22, accuracy: 94.8, score: 892, badges: ['Zero FP', 'Night Owl'] },
  { id: 'ap', name: 'Aisha Patel',    initials: 'AP', avatarColor: 'bg-emerald-500',casesClosed: 39, avgResolutionMin: 15, accuracy: 97.1, score: 878, badges: ['Precision Strike', 'MITRE Master'] },
  { id: 'jw', name: 'James Wong',     initials: 'JW', avatarColor: 'bg-amber-500',  casesClosed: 35, avgResolutionMin: 25, accuracy: 91.5, score: 812, badges: ['Speed Demon'] },
  { id: 'ev', name: 'Elena Vasquez',  initials: 'EV', avatarColor: 'bg-pink-500',   casesClosed: 31, avgResolutionMin: 20, accuracy: 95.3, score: 785, badges: ['Mentor', 'Zero FP'] },
  { id: 'dk', name: 'David Kim',      initials: 'DK', avatarColor: 'bg-orange-500', casesClosed: 28, avgResolutionMin: 28, accuracy: 89.7, score: 721, badges: ['Newcomer Rising'] },
];

const ACHIEVEMENTS: Achievement[] = [
  { text: 'Sarah Chen earned MITRE Master badge',            timeAgo: '2 hours ago', icon: 'badge' },
  { text: 'Marcus Rivera achieved Zero FP streak (30 days)', timeAgo: '5 hours ago', icon: 'streak' },
  { text: 'Team closed 50 cases this week — new record!',    timeAgo: '1 day ago',   icon: 'record' },
  { text: 'Aisha Patel reached #1 accuracy rating',          timeAgo: '2 days ago',  icon: 'rank' },
];

const RANK_ACCENTS: Record<number, { ring: string; text: string; label: string }> = {
  1: { ring: 'ring-2 ring-amber-400/60',  text: 'text-amber-400',  label: '🥇' },
  2: { ring: 'ring-2 ring-gray-300/40',   text: 'text-gray-300',   label: '🥈' },
  3: { ring: 'ring-2 ring-orange-400/40', text: 'text-orange-400', label: '🥉' },
};

type SortKey = 'score' | 'cases' | 'accuracy' | 'speed';

function achievementIcon(icon: Achievement['icon']) {
  switch (icon) {
    case 'badge':
      return (
        <svg className="h-4 w-4 text-purple-400" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12c0 1.268-.63 2.39-1.593 3.068a3.745 3.745 0 01-1.043 3.296 3.745 3.745 0 01-3.296 1.043A3.745 3.745 0 0112 21c-1.268 0-2.39-.63-3.068-1.593a3.746 3.746 0 01-3.296-1.043 3.746 3.746 0 01-1.043-3.296A3.745 3.745 0 013 12c0-1.268.63-2.39 1.593-3.068a3.746 3.746 0 011.043-3.296 3.746 3.746 0 013.296-1.043A3.745 3.745 0 0112 3c1.268 0 2.39.63 3.068 1.593a3.746 3.746 0 013.296 1.043 3.746 3.746 0 011.043 3.296A3.745 3.745 0 0121 12z" />
        </svg>
      );
    case 'streak':
      return (
        <svg className="h-4 w-4 text-green-400" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" d="M15.362 5.214A8.252 8.252 0 0112 21 8.25 8.25 0 016.038 7.048 8.287 8.287 0 009 9.6a8.983 8.983 0 013.361-6.867 8.21 8.21 0 003 2.48z" />
          <path strokeLinecap="round" strokeLinejoin="round" d="M12 18a3.75 3.75 0 00.495-7.467 5.99 5.99 0 00-1.925 3.546 5.974 5.974 0 01-2.133-1.001A3.75 3.75 0 0012 18z" />
        </svg>
      );
    case 'record':
      return (
        <svg className="h-4 w-4 text-amber-400" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" d="M16.5 18.75h-9m9 0a3 3 0 013 3h-15a3 3 0 013-3m9 0v-3.375c0-.621-.503-1.125-1.125-1.125h-.871M7.5 18.75v-3.375c0-.621.504-1.125 1.125-1.125h.872m5.007 0H9.497m5.007 0a7.454 7.454 0 01-.982-3.172M9.497 14.25a7.454 7.454 0 00.981-3.172M5.25 4.236c-.982.143-1.954.317-2.916.52A6.003 6.003 0 007.73 9.728M5.25 4.236V4.5c0 2.108.966 3.99 2.48 5.228M5.25 4.236V2.721C7.456 2.41 9.71 2.25 12 2.25c2.291 0 4.545.16 6.75.47v1.516M18.75 4.236c.982.143 1.954.317 2.916.52A6.003 6.003 0 0016.27 9.728M18.75 4.236V4.5c0 2.108-.966 3.99-2.48 5.228m0 0a6.003 6.003 0 01-4.52 1.522 6.003 6.003 0 01-4.52-1.522" />
        </svg>
      );
    case 'rank':
      return (
        <svg className="h-4 w-4 text-blue-400" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" d="M2.25 18L9 11.25l4.306 4.307a11.95 11.95 0 015.814-5.519l2.74-1.22m0 0l-5.94-2.28m5.94 2.28l-2.28 5.941" />
        </svg>
      );
  }
}

export function TeamAnalyticsView() {
  const [sortBy, setSortBy] = useState<SortKey>('score');
  const [search, setSearch] = useState('');

  const totalCases = ANALYSTS.reduce((s, a) => s + a.casesClosed, 0);
  const avgResolution = Math.round(ANALYSTS.reduce((s, a) => s + a.avgResolutionMin, 0) / ANALYSTS.length);
  const teamAccuracy = (ANALYSTS.reduce((s, a) => s + a.accuracy, 0) / ANALYSTS.length).toFixed(1);
  const totalBadges = ANALYSTS.reduce((s, a) => s + a.badges.length, 0);

  const sorted = [...ANALYSTS]
    .filter((a) => !search.trim() || a.name.toLowerCase().includes(search.toLowerCase()))
    .sort((a, b) => {
      switch (sortBy) {
        case 'score':    return b.score - a.score;
        case 'cases':    return b.casesClosed - a.casesClosed;
        case 'accuracy': return b.accuracy - a.accuracy;
        case 'speed':    return a.avgResolutionMin - b.avgResolutionMin;
      }
    });

  const SORT_OPTIONS: { key: SortKey; label: string }[] = [
    { key: 'score',    label: 'Score' },
    { key: 'cases',    label: 'Cases' },
    { key: 'accuracy', label: 'Accuracy' },
    { key: 'speed',    label: 'Speed' },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-white">Team Analytics</h1>
        <p className="mt-1 text-sm text-gray-400">Analyst performance and gamification leaderboard</p>
      </div>

      {/* Aggregate stats */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {[
          { label: 'Cases Closed This Month', value: totalCases.toString(), accent: 'text-emerald-400' },
          { label: 'Avg Resolution Time',     value: `${avgResolution} min`,     accent: 'text-sky-400' },
          { label: 'Team Accuracy Rate',       value: `${teamAccuracy}%`,         accent: 'text-violet-400' },
          { label: 'Total Badges Earned',      value: totalBadges.toString(),      accent: 'text-amber-400' },
        ].map((stat) => (
          <div key={stat.label} className="rounded-xl border border-gray-800/60 bg-gray-900/40 p-5 space-y-4">
            <p className="text-xs font-medium uppercase tracking-wider text-gray-400">{stat.label}</p>
            <p className={clsx('text-3xl font-bold', stat.accent)}>{stat.value}</p>
          </div>
        ))}
      </div>

      {/* Leaderboard */}
      <div className="rounded-xl border border-gray-800/60 bg-gray-900/40 p-5 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h2 className="text-lg font-semibold text-white">Analyst Leaderboard</h2>
          <div className="flex items-center gap-3">
            <input
              type="search"
              placeholder="Search analyst…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="rounded-lg border border-gray-700/60 bg-gray-900 px-3 py-1.5 text-xs text-gray-200 placeholder-gray-600 focus:outline-none focus:ring-1 focus:ring-indigo-500/60 w-44"
            />
            <span className="text-xs font-medium uppercase tracking-wider text-gray-500">Sort</span>
            {SORT_OPTIONS.map((opt) => (
              <button
                key={opt.key}
                onClick={() => setSortBy(opt.key)}
                className={clsx(
                  'rounded-md px-2.5 py-1 text-xs font-medium transition',
                  sortBy === opt.key
                    ? 'bg-white/10 text-white'
                    : 'text-gray-500 hover:text-gray-300',
                )}
              >
                {opt.label}
              </button>
            ))}
          </div>
        </div>

        {sorted.length === 0 ? (
          <EmptyState
            icon={EmptyStateIcons.search}
            title="No analysts match your search"
            description="Try a different name or clear the search to see all analysts."
            action={
              <button
                type="button"
                onClick={() => setSearch('')}
                className="rounded-lg bg-gray-800 px-4 py-2 text-sm text-gray-200 hover:bg-gray-700 transition-colors"
              >
                Clear search
              </button>
            }
          />
        ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-gray-800/60 text-xs uppercase tracking-wider text-gray-500">
                <th className="pb-3 pr-3 font-medium w-12">Rank</th>
                <th className="pb-3 pr-3 font-medium">Analyst</th>
                <th className="pb-3 pr-3 font-medium text-right">Cases</th>
                <th className="pb-3 pr-3 font-medium text-right">Avg Time</th>
                <th className="pb-3 pr-3 font-medium text-right">Accuracy</th>
                <th className="pb-3 pr-3 font-medium text-right">Score</th>
                <th className="pb-3 font-medium">Badges</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800/40">
              {sorted.map((analyst, i) => {
                const rank = i + 1;
                const accent = RANK_ACCENTS[rank];
                return (
                  <tr key={analyst.id} className="group transition hover:bg-white/[0.02]">
                    <td className="py-3 pr-3">
                      <span className={clsx('text-sm font-bold', accent?.text ?? 'text-gray-500')}>
                        {accent?.label ?? `#${rank}`}
                      </span>
                    </td>
                    <td className="py-3 pr-3">
                      <div className="flex items-center gap-3">
                        <div
                          className={clsx(
                            'flex h-8 w-8 items-center justify-center rounded-full text-xs font-bold text-white',
                            analyst.avatarColor,
                            accent?.ring,
                          )}
                        >
                          {analyst.initials}
                        </div>
                        <span className="font-medium text-white">{analyst.name}</span>
                      </div>
                    </td>
                    <td className="py-3 pr-3 text-right tabular-nums text-gray-300">
                      {analyst.casesClosed}
                    </td>
                    <td className="py-3 pr-3 text-right tabular-nums text-gray-300">
                      {analyst.avgResolutionMin} min
                    </td>
                    <td className="py-3 pr-3 text-right tabular-nums text-gray-300">
                      {analyst.accuracy.toFixed(1)}%
                    </td>
                    <td className="py-3 pr-3 text-right">
                      <span className={clsx('tabular-nums font-bold', accent?.text ?? 'text-white')}>
                        {analyst.score}
                      </span>
                    </td>
                    <td className="py-3">
                      <div className="flex flex-wrap gap-1.5">
                        {analyst.badges.map((badge) => {
                          const bc = BADGE_COLORS[badge] ?? { bg: 'bg-gray-500/15', text: 'text-gray-300', border: 'border-gray-500/30' };
                          return (
                            <span
                              key={badge}
                              className={clsx(
                                'inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-semibold',
                                bc.bg, bc.text, bc.border,
                              )}
                            >
                              {badge}
                            </span>
                          );
                        })}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        )}
      </div>

      {/* Team Highlights */}
      <div className="rounded-xl border border-gray-800/60 bg-gray-900/40 p-5 space-y-4">
        <h2 className="text-lg font-semibold text-white">Team Highlights</h2>
        <div className="space-y-3">
          {ACHIEVEMENTS.map((ach, i) => (
            <div
              key={i}
              className="flex items-start gap-3 rounded-lg border border-gray-800/40 bg-black/20 p-3.5"
            >
              <div className="mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-white/5">
                {achievementIcon(ach.icon)}
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium text-gray-200">{ach.text}</p>
                <p className="mt-0.5 text-xs text-gray-500">{ach.timeAgo}</p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
