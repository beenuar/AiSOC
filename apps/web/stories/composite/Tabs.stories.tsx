import type { Meta, StoryObj } from '@storybook/react-vite';
import React, { useState } from 'react';

/**
 * Composite / Tabs — the underlined-tab pattern used on /playbooks,
 * /alerts, /investigations etc. Kept as a story until the team agrees
 * on the final ui/Tabs API.
 */

const meta: Meta = {
  title: 'Composite/Tabs',
};

export default meta;

type Story = StoryObj;

const TABS = [
  { id: 'playbooks', label: 'Playbooks (12)' },
  { id: 'runs', label: 'Run History' },
  { id: 'community', label: 'Community' },
];

export const UnderlinedTabs: Story = {
  render: () => {
    const Demo = () => {
      const [active, setActive] = useState('playbooks');
      return (
        <div>
          <div className="flex gap-1 border-b border-gray-800/60">
            {TABS.map((t) => (
              <button
                key={t.id}
                onClick={() => setActive(t.id)}
                className={`px-4 py-2 text-sm font-medium transition-colors border-b-2 -mb-px ${
                  active === t.id
                    ? 'border-blue-500 text-blue-300'
                    : 'border-transparent text-gray-500 hover:text-gray-300'
                }`}
              >
                {t.label}
              </button>
            ))}
          </div>
          <div className="mt-4 text-sm text-gray-400">
            Active tab: <span className="text-gray-200">{active}</span>
          </div>
        </div>
      );
    };
    return <Demo />;
  },
};

export const SegmentedControl: Story = {
  render: () => {
    const Demo = () => {
      const [active, setActive] = useState('substrate');
      const options = [
        { id: 'substrate', label: 'Substrate' },
        { id: 'llm', label: 'LLM-assisted' },
      ];
      return (
        <div className="inline-flex rounded-lg border border-gray-800 bg-gray-900 p-1 text-xs">
          {options.map((o) => (
            <button
              key={o.id}
              onClick={() => setActive(o.id)}
              className={`px-3 py-1 rounded-md transition-colors ${
                active === o.id ? 'bg-blue-600 text-white' : 'text-gray-400 hover:text-gray-200'
              }`}
            >
              {o.label}
            </button>
          ))}
        </div>
      );
    };
    return <Demo />;
  },
};
