import type { Meta, StoryObj } from '@storybook/react-vite';
import React from 'react';

/**
 * Foundations / Typography — pins the type ramp the AiSOC console
 * uses. Each row is a real Tailwind class so designers can copy the
 * declaration into Figma without translating tokens.
 */

const RAMP = [
  { name: 'Display / 4xl', cls: 'text-4xl font-bold', sample: 'Cyble AiSOC' },
  { name: 'Page title / 2xl', cls: 'text-2xl font-bold', sample: 'Playbooks' },
  { name: 'Section title / xl', cls: 'text-xl font-semibold', sample: 'Recent runs' },
  { name: 'Heading / lg', cls: 'text-lg font-semibold', sample: 'High-severity alerts (last 24h)' },
  { name: 'Body / base', cls: 'text-base', sample: 'Investigations are routed through the deterministic substrate first.' },
  { name: 'Body small / sm', cls: 'text-sm', sample: 'Drafted playbooks ship disabled — review each node before saving.' },
  { name: 'Caption / xs', cls: 'text-xs text-gray-500', sample: 'Updated 2 minutes ago' },
  { name: 'Mono caption / xs font-mono', cls: 'text-xs font-mono text-gray-400', sample: 'aisoc.playbook.nl_drafter' },
];

const meta: Meta = {
  title: 'Foundations/Typography',
  parameters: {
    docs: {
      description: {
        component:
          'Type ramp used throughout the console. Use the Tailwind class shown alongside each sample; do NOT introduce new sizes without bumping this story first.',
      },
    },
  },
};

export default meta;

type Story = StoryObj;

export const Ramp: Story = {
  render: () => (
    <div className="space-y-5">
      {RAMP.map((row) => (
        <div key={row.name} className="grid grid-cols-[180px_1fr] gap-4 border-b border-gray-800/60 pb-4">
          <div>
            <div className="text-[11px] font-mono uppercase tracking-wide text-gray-500">{row.name}</div>
            <div className="mt-1 text-[10px] font-mono text-gray-600">{row.cls}</div>
          </div>
          <div className={row.cls}>{row.sample}</div>
        </div>
      ))}
    </div>
  ),
};

export const LineHeightLadder: Story = {
  render: () => (
    <div className="space-y-4">
      {(['leading-tight', 'leading-normal', 'leading-relaxed', 'leading-loose'] as const).map((cls) => (
        <div key={cls} className="rounded-lg border border-gray-800/60 p-4">
          <div className="text-[10px] font-mono uppercase text-gray-500">{cls}</div>
          <p className={`mt-2 text-sm ${cls}`}>
            Each playbook step is bounded by a hard timeout and an explicit retry budget so the
            engine cannot get stuck in a backpressured loop while the analyst is asleep. Reasonable
            defaults: 30s timeout, 0 retries, abort on failure.
          </p>
        </div>
      ))}
    </div>
  ),
};
