import type { Meta, StoryObj } from '@storybook/react-vite';
import React from 'react';

/**
 * Foundations / Colors — surfaces the CSS variables declared in
 * apps/web/src/app/globals.css so the design team can audit token
 * coverage at a glance. The swatches are pure presentation so no
 * Args / play() function needed.
 */

const SURFACE_TOKENS = [
  { name: 'surface-base', desc: 'Page background' },
  { name: 'surface-raised', desc: 'Top bars, sticky headers' },
  { name: 'surface-card', desc: 'Card and panel bodies' },
  { name: 'surface-hover', desc: 'Hover state of any surface' },
  { name: 'surface-subtle', desc: 'Sidebar, secondary nav' },
];

const FG_TOKENS = [
  { name: 'fg-primary', desc: 'Headlines, table headers' },
  { name: 'fg-secondary', desc: 'Body copy, descriptions' },
  { name: 'fg-muted', desc: 'Help text, captions' },
  { name: 'fg-disabled', desc: 'Disabled inputs' },
];

const ACCENT_TOKENS = [
  { name: 'brand-500', value: '#3b82f6', desc: 'Primary CTA' },
  { name: 'brand-600', value: '#2563eb', desc: 'Hover CTA' },
  { name: 'brand-700', value: '#1d4ed8', desc: 'Pressed CTA' },
  { name: 'danger-500', value: '#ef4444', desc: 'Destructive action' },
  { name: 'warning-500', value: '#f59e0b', desc: 'Warning badge' },
  { name: 'success-500', value: '#22c55e', desc: 'Completed status' },
];

function Swatch({ label, sample, description }: { label: string; sample: React.ReactNode; description: string }) {
  return (
    <div className="rounded-lg border border-gray-800/60 bg-gray-900/40 p-4">
      <div className="h-16 w-full rounded-md border border-gray-800/40" aria-hidden="true">
        {sample}
      </div>
      <div className="mt-3 font-mono text-xs text-gray-200">{label}</div>
      <div className="mt-0.5 text-[11px] text-gray-500">{description}</div>
    </div>
  );
}

const meta: Meta = {
  title: 'Foundations/Colors',
  parameters: {
    docs: {
      description: {
        component:
          'Surface, foreground and accent tokens used by the AiSOC console. The token names map 1:1 to CSS variables in globals.css; the values come from tailwind.config.ts.',
      },
    },
  },
};

export default meta;

type Story = StoryObj;

export const Surfaces: Story = {
  render: () => (
    <div className="grid grid-cols-3 gap-4">
      {SURFACE_TOKENS.map((t) => (
        <Swatch
          key={t.name}
          label={`--${t.name}`}
          description={t.desc}
          sample={<div className="h-full w-full" style={{ background: `var(--${t.name})` }} />}
        />
      ))}
    </div>
  ),
};

export const Foregrounds: Story = {
  render: () => (
    <div className="grid grid-cols-2 gap-4">
      {FG_TOKENS.map((t) => (
        <Swatch
          key={t.name}
          label={`--${t.name}`}
          description={t.desc}
          sample={
            <div
              className="flex h-full w-full items-center justify-center text-sm"
              style={{ color: `var(--${t.name})` }}
            >
              The quick brown fox
            </div>
          }
        />
      ))}
    </div>
  ),
};

export const Accents: Story = {
  render: () => (
    <div className="grid grid-cols-3 gap-4">
      {ACCENT_TOKENS.map((t) => (
        <Swatch
          key={t.name}
          label={t.name}
          description={`${t.desc} — ${t.value}`}
          sample={<div className="h-full w-full" style={{ background: t.value }} />}
        />
      ))}
    </div>
  ),
};
