import type { Meta, StoryObj } from '@storybook/react-vite';
import React from 'react';

/**
 * Foundations / Spacing — surfaces the 4 px-grid the console uses for
 * padding, gap and stack rhythm. Use these tokens (and only these) so
 * dense screens like the alert queue stay visually predictable.
 */

const STEPS = [1, 2, 3, 4, 5, 6, 8, 10, 12, 16, 20, 24];

const meta: Meta = {
  title: 'Foundations/Spacing',
  parameters: {
    docs: {
      description: {
        component:
          'Tailwind v4 spacing scale (each step = 4 px). The console keeps padding decisions to the values shown; ad-hoc pixel values are discouraged.',
      },
    },
  },
};

export default meta;

type Story = StoryObj;

export const Scale: Story = {
  render: () => (
    <div className="space-y-2 text-xs">
      {STEPS.map((s) => (
        <div key={s} className="flex items-center gap-3">
          <span className="w-16 font-mono text-gray-500">space-{s} = {s * 4}px</span>
          <div className="h-3 rounded bg-blue-500/60" style={{ width: `${s * 4}px` }} />
        </div>
      ))}
    </div>
  ),
};

export const StackRhythm: Story = {
  render: () => (
    <div className="grid grid-cols-3 gap-6 text-xs">
      {(['space-y-2', 'space-y-4', 'space-y-6'] as const).map((cls) => (
        <div key={cls} className="rounded-lg border border-gray-800/60 p-4">
          <div className="mb-3 font-mono text-[10px] text-gray-500">{cls}</div>
          <div className={cls}>
            <div className="h-3 rounded bg-blue-800/40" />
            <div className="h-3 rounded bg-blue-800/40" />
            <div className="h-3 rounded bg-blue-800/40" />
          </div>
        </div>
      ))}
    </div>
  ),
};
