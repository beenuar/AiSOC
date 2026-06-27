import type { Meta, StoryObj } from '@storybook/react-vite';
import React from 'react';

/**
 * Foundations / Theme — quick visual A/B between dark (default) and
 * light. Toolbar offers the toggle via @storybook/addon-themes; this
 * story shows the same surfaces across themes so a design reviewer
 * can scan for token coverage gaps.
 */

const meta: Meta = {
  title: 'Foundations/Theme',
  parameters: {
    docs: {
      description: {
        component:
          'Dark is the default. Light is opt-in via the user preference toggle in TopBar. Use the toolbar in the canvas to verify your component renders correctly on both.',
      },
    },
  },
};

export default meta;

type Story = StoryObj;

function Sample() {
  return (
    <div className="grid grid-cols-3 gap-4">
      <div className="rounded-xl border border-gray-800/60 bg-[var(--surface-card)] p-4">
        <div className="text-sm font-semibold" style={{ color: 'var(--fg-primary)' }}>
          Surface card
        </div>
        <p className="mt-2 text-xs" style={{ color: 'var(--fg-muted)' }}>
          Body copy lives here.
        </p>
      </div>
      <div className="rounded-xl border border-gray-800/60 bg-[var(--surface-raised)] p-4">
        <div className="text-sm font-semibold" style={{ color: 'var(--fg-primary)' }}>
          Surface raised
        </div>
        <p className="mt-2 text-xs" style={{ color: 'var(--fg-muted)' }}>
          Top bars and sticky headers.
        </p>
      </div>
      <div className="rounded-xl border border-gray-800/60 bg-[var(--surface-subtle)] p-4">
        <div className="text-sm font-semibold" style={{ color: 'var(--fg-primary)' }}>
          Surface subtle
        </div>
        <p className="mt-2 text-xs" style={{ color: 'var(--fg-muted)' }}>
          Sidebars, secondary nav.
        </p>
      </div>
    </div>
  );
}

export const DarkAndLight: Story = {
  render: () => <Sample />,
};
